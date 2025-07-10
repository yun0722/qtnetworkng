#include <QtCore/qwaitcondition.h>
#include <QtCore/qmutex.h>
#include <QtCore/qpointer.h>
#include <QtCore/qelapsedtimer.h>
#include "../include/private/eventloop_p.h"
#include "../include/locks.h"
#include "debugger.h"

QTNG_LOGGER("qtng.locks");

QTNETWORKNG_NAMESPACE_BEGIN

class SemaphorePrivate
{
public:
    SemaphorePrivate(int value);
    virtual ~SemaphorePrivate();
public:
    bool acquire(QSharedPointer<SemaphorePrivate> self, int value, quint32 msecs);
    void release(QSharedPointer<SemaphorePrivate> self, int value);
    void scheduleDelete(QSharedPointer<SemaphorePrivate> self);
public:
    QList<QPointer<BaseCoroutine>> waiters;
    const int init_value;
    volatile int counter;
    int notified;
};

SemaphorePrivate::SemaphorePrivate(int value)
    : init_value(qMax(1, value))
    , counter(value)
    , notified(0)
{
    if (value < 1) {
        qtng_warning << "Semaphore got init value less than 1:" << value << ", we treat it as 1.";
    }
}

SemaphorePrivate::~SemaphorePrivate()
{
    Q_ASSERT(waiters.isEmpty());
}

bool SemaphorePrivate::acquire(QSharedPointer<SemaphorePrivate> self, int value, quint32 msecs)
{
    if (counter >= value) {
        counter -= value;
        return true;
    }
    if (msecs == 0) {
        return false;
    }
    // UINT_MAX: means wait until success
    int callbackId = 0;
    if (msecs != (UINT_MAX)) {
        callbackId = EventLoopCoroutine::get()->callLater(msecs, new YieldCurrentFunctor());
    }

    Q_ASSERT_X(EventLoopCoroutine::get() != BaseCoroutine::current(), "SemaphorePrivate",
               "coroutine locks should not be called from eventloop coroutine.");
    Q_ASSERT_X(value <= init_value, "SemaphorePrivate", "the value to acquire must not large than init_value.");

    int gotNum = counter;
    int remain = value - counter;
    counter = 0;

    while (remain > 0) {
        waiters.append(BaseCoroutine::current());

        try {
            EventLoopCoroutine::get()->yield();
        } catch (...) {
            // if we caught an exception, the release() must not touch me.
            // the waiter should be remove.
            bool found = waiters.removeOne(BaseCoroutine::current());
            Q_ASSERT(found);
            if (callbackId) {
                EventLoopCoroutine::get()->cancelCall(callbackId);
            }
            release(self, gotNum);
            throw;
        }

        bool found = waiters.removeOne(BaseCoroutine::current());
        if (found) {  // timeout
            release(self, gotNum);  // release what has been acquired
            return false;
        }

        Q_ASSERT_X(notified != 0, "SemaphorePrivate",
                   "if there are something other reason cause yield, it means the acquire action is failed");
        Q_ASSERT(counter > 0);
        if (counter >= remain) {
            counter -= remain;
            break;
        } else {
            gotNum += counter;
            remain -= counter;
            counter = 0;
        }
    }
    if (callbackId) {
        EventLoopCoroutine::get()->cancelCall(callbackId);
    }
    return true;
}

class SemaphoreNotifyWaitersFunctor : public Functor
{
public:
    SemaphoreNotifyWaitersFunctor(QSharedPointer<SemaphorePrivate> sp, bool doDelete)
        : sp(sp)
        , doDelete(doDelete)
    {
    }
    QSharedPointer<SemaphorePrivate> sp;
    bool doDelete;
    virtual bool operator()() override
    {
        while ((doDelete || (sp->notified != 0 && sp->counter > 0)) && !sp->waiters.isEmpty()) {
            QPointer<BaseCoroutine> waiter = sp->waiters.takeFirst();
            if (waiter.isNull()) {
                qtng_debug << "waiter was deleted.";
                continue;
            }
            waiter->yield();
        }
        // do not move this line above the loop, see the Q_ASSERT_X(notified != 0) in SemaphorePrivate::acquire()
        sp->notified = 0;
        return true;
    }
};

void SemaphorePrivate::release(QSharedPointer<SemaphorePrivate> self, int value)
{
    if (value <= 0) {
        return;
    }
    if (counter > INT_MAX - value) {
        counter = INT_MAX;
    } else {
        counter += value;
    }
    counter = qMin(static_cast<int>(counter), init_value);
    if (!notified && !waiters.isEmpty()) {
        notified = EventLoopCoroutine::get()->callLater(0, new SemaphoreNotifyWaitersFunctor(self, false));
    }
}

void SemaphorePrivate::scheduleDelete(QSharedPointer<SemaphorePrivate> self)
{
    if (notified) {
        EventLoopCoroutine::get()->cancelCall(notified);
        notified = 0;
    }
    counter = init_value;
    EventLoopCoroutine::get()->callLater(0, new SemaphoreNotifyWaitersFunctor(self, true));
}

Semaphore::Semaphore(int value)
    : d(new SemaphorePrivate(value))
{
}

Semaphore::~Semaphore()
{
    d->scheduleDelete(d);
    d.clear();
}

bool Semaphore::acquireMany(int value, quint32 msecs)
{
    if (!d) {
        return false;
    }
    QSharedPointer<SemaphorePrivate> d(this->d);
    if (value > d->init_value) {
        return false;
    }
    return d->acquire(d, value, msecs);
}

bool Semaphore::tryAcquire(quint32 msecs /*= (UINT_MAX)*/)
{
    if (!d) {
        return false;
    }
    QSharedPointer<SemaphorePrivate> d(this->d);
    if (1 > d->init_value) {
        return false;
    }
    return d->acquire(d, 1, msecs);
}

void Semaphore::release(int value)
{
    if (!d) {
        return;
    }
    d->release(d, value);
}

bool Semaphore::isLocked() const
{
    if (!d) {
        return false;
    }
    return d->counter <= 0;
}

bool Semaphore::isUsed() const
{
    if (!d) {
        return false;
    }
    return d->counter < d->init_value;
}

quint32 Semaphore::getting() const
{
    if (!d) {
        return 0;
    }
    return d->waiters.size();
}

Lock::Lock()
    : Semaphore(1)
{
}

struct RLockState
{
    quintptr holder;
    int counter;
};

class RLockPrivate
{
public:
    RLockPrivate(RLock *q);
    ~RLockPrivate();
public:
    bool acquire(quint32 msecs);
    void release();
    RLockState reset();
    void set(const RLockState &state);
private:
    RLock * const q_ptr;
    Lock lock;
    quintptr holder;
    int counter;
    Q_DECLARE_PUBLIC(RLock)
};

RLockPrivate::RLockPrivate(RLock *q)
    : q_ptr(q)
    , holder(0)
    , counter(0)
{
}

RLockPrivate::~RLockPrivate() { }

bool RLockPrivate::acquire(quint32 msecs)
{
    if (holder == BaseCoroutine::current()->id()) {
        counter += 1;
        return true;
    }
    if (lock.tryAcquire(msecs)) {
        counter = 1;
        holder = BaseCoroutine::current()->id();
        return true;
    }
    return false;  // XXX lock is deleted.
}

void RLockPrivate::release()
{
    if (holder != BaseCoroutine::current()->id()) {
        qtng_warning << "do not release other coroutine's rlock.";
        return;
    }
    counter -= 1;
    if (counter == 0) {
        holder = 0;
        lock.release();
    }
}

RLockState RLockPrivate::reset()
{
    RLockState state;
    state.counter = counter;
    counter = 0;
    state.holder = holder;
    holder = 0;
    if (state.counter > 0) {
        lock.release();
    }
    return state;
}

void RLockPrivate::set(const RLockState &state)
{
    counter = state.counter;
    holder = state.holder;
    if (counter > 0) {
        lock.tryAcquire();
    }
}

RLock::RLock()
    : d_ptr(new RLockPrivate(this))
{
}

RLock::~RLock()
{
    delete d_ptr;
}

bool RLock::tryAcquire(quint32 msecs)
{
    Q_D(RLock);
    return d->acquire(msecs);
}

void RLock::release()
{
    Q_D(RLock);
    d->release();
}

bool RLock::isLocked() const
{
    Q_D(const RLock);
    return d->lock.isLocked();
}

bool RLock::isOwned() const
{
    Q_D(const RLock);
    return d->holder == BaseCoroutine::current()->id();
}

class ConditionPrivate
{
public:
    QList<QSharedPointer<Lock>> waiters;
};

Condition::Condition()
    : d_ptr(new ConditionPrivate())
{
}

Condition::~Condition()
{
    notify(d_ptr->waiters.size());
    delete d_ptr;
}

bool Condition::wait(quint32 msecs)
{
    Q_D(Condition);
    QSharedPointer<Lock> waiter(new Lock());
    if (!waiter->tryAcquire())
        return false;
    d->waiters.append(waiter);

    bool ok = false;
    try {
        ok = waiter->tryAcquire(msecs);
    } catch (...) {
        waiter->release();
        d->waiters.removeOne(waiter);
        throw;
    }

    if (ok) {
        waiter->release();
    }
    d->waiters.removeOne(waiter);
    return ok;
}

void Condition::notify(int value)
{
    Q_D(Condition);
    for (int i = 0; i < value && !d->waiters.isEmpty(); ++i) {
        QSharedPointer<Lock> waiter = d->waiters.takeFirst();
        waiter->release();
    }
}

void Condition::notifyAll()
{
    Q_D(Condition);
    notify(d->waiters.size());
}

quint32 Condition::getting() const
{
    Q_D(const Condition);
    return static_cast<quint32>(d->waiters.size());
}

class EventPrivate
{
public:
    EventPrivate(Event *q);
    ~EventPrivate();
public:
    void set();
    void clear();
    bool wait(quint32 msecs);
private:
    Event * const q_ptr;
    Condition condition;
    volatile bool flag;
    QList<Event *> linkTo;
    QList<Event *> linkFrom;
    Q_DECLARE_PUBLIC(Event)
};

EventPrivate::EventPrivate(Event *q)
    : q_ptr(q)
    , flag(false)
{
}

EventPrivate::~EventPrivate()
{
    if (!flag && condition.getting() > 0) {
        condition.notifyAll();
    }
    for (Event *event : linkFrom) {
        event->d_ptr->linkTo.removeOne(q_ptr);
    }
    for (Event *event : linkTo) {
        event->d_ptr->linkFrom.removeOne(q_ptr);
    }
}

void EventPrivate::set()
{
    if (!flag) {
        flag = true;
        condition.notifyAll();
        for (Event *other : linkTo) {
            other->set();
        }
    }
}

void EventPrivate::clear()
{
    flag = false;
}

bool EventPrivate::wait(quint32 msecs)
{
    if (msecs == 0 || flag) {
        return flag;
    }

    if (msecs == UINT_MAX) {
        do {
            try {
                if (!condition.wait(UINT_MAX)) {
                    return false;
                }
            } catch (...) {
                throw;
            }
        } while (!flag);
    } else {
        QElapsedTimer timer;
        timer.start();

        quint32 elapsed = 0;
        while (true) {
            try {
                if (!condition.wait(msecs - elapsed)) {
                    return false;
                }
            } catch (...) {
                throw;
            }
            if (flag) {
                break;
            }
            elapsed = timer.elapsed();
            if (msecs >= elapsed) {
                return false;
            }
        }
    }
    return flag;
}

Event::Event()
    : d_ptr(new EventPrivate(this))
{
}

Event::~Event()
{
    delete d_ptr;
}

bool Event::tryWait(quint32 msecs)
{
    Q_D(Event);
    return d->wait(msecs);
}

void Event::set()
{
    Q_D(Event);
    d->set();
}

bool Event::isSet() const
{
    Q_D(const Event);
    return d->flag;
}

void Event::clear()
{
    Q_D(Event);
    d->clear();
}

quint32 Event::getting() const
{
    Q_D(const Event);
    return d->condition.getting();
}

void Event::link(Event &other)
{
    Q_D(Event);
    d->linkTo.append(&other);
    other.d_func()->linkFrom.append(this);
}

void Event::unlink(Event &other)
{
    Q_D(Event);
    d->linkTo.removeOne(&other);
    other.d_ptr->linkFrom.removeOne(this);
}

struct Behold
{
    QPointer<EventLoopCoroutine> eventloop;
    QSharedPointer<Condition> condition;
};

class ThreadEventPrivate
{
public:
    ThreadEventPrivate();
    void notify();
    bool wait(quint32 msecs);
    quint32 getting();
    inline void incref();
    inline bool decref();
public:
    QWaitCondition condition;
    QMutex mutex;
    QList<Behold> holds;
    QList<ThreadEvent *> linkTo;
    QList<ThreadEvent *> linkFrom;
    QAtomicInteger<int> flag;
    QAtomicInteger<int> count;  // only for condition
    QAtomicInteger<quint32> ref;
};

class NotifiyCondition : public Functor
{
public:
    NotifiyCondition(QSharedPointer<Condition> condition)
        : condition(condition)
    {
    }
    virtual bool operator()()
    {
        condition->notifyAll();
        return true;
    }
    QSharedPointer<Condition> condition;
};

ThreadEventPrivate::ThreadEventPrivate()
    : flag(false)
    , count(0)
    , ref(1)
{
}

void ThreadEventPrivate::notify()
{
    incref();
    mutex.lock();
    QSharedPointer<EventLoopCoroutine> current = currentLoop()->get();
    QMutableListIterator<Behold> itor(holds);
    // XXX the flag can be false.
    while (itor.hasNext() && ref.loadAcquire() > 1) {
        const Behold &hold = itor.next();
        QSharedPointer<Condition> holdCondition = hold.condition;
        EventLoopCoroutine *holdEventloop = hold.eventloop.data();
        if (holdEventloop) {
            if (holdEventloop == current) {
                holdCondition->notifyAll();
            } else {
                holdEventloop->callLaterThreadSafe(0, new NotifiyCondition(holdCondition));
            }
        } else {
            itor.remove();
        }
    }
    mutex.unlock();
    // XXX the flag can be false.
    if (count.loadAcquire() > 0) {
        condition.wakeAll();
    }
    decref();
}

bool ThreadEventPrivate::wait(quint32 msecs)
{
    bool f = flag.loadAcquire();
    if (msecs == 0 || f) {
        return f;
    }

    QSharedPointer<QElapsedTimer> timer;
    if (msecs != UINT_MAX) {
        timer.reset(new QElapsedTimer());
        timer->start();
    }

    incref();
    mutex.lock();
    EventLoopCoroutine *current = currentLoop()->get().data();
    Q_ASSERT(!f);
    if (!current) {
        if (msecs != UINT_MAX) {
            qtng_warning << "useless arg:msecs when call ThreadEvent::wait";
        }

        ++count;
        while (!(f = flag.loadAcquire()) && ref.loadAcquire() > 1) {
            this->condition.wait(&mutex);
        }
        --count;
        mutex.unlock();
    } else {
        QSharedPointer<Condition> condition;
        // should we use QMap<EventLoopCoroutine *, Hold> to accelerate?
        for (const Behold &hold : holds) {
            if (hold.eventloop.data() == current) {
                condition = hold.condition;
                break;
            }
        }
        if (condition.isNull()) {
            condition.reset(new Condition());
            Behold hold;
            hold.condition = condition;
            hold.eventloop = current;
            holds.append(hold);
        }
        mutex.unlock();
        bool ok = false;

        while (!(f = flag.loadAcquire()) && ref.loadAcquire() > 1) {
            try {
                if (msecs == UINT_MAX) {
                    ok = condition->wait();
                } else {
                    quint32 elapsed = timer->elapsed();
                    if (msecs <= elapsed) {
                        return false;
                    }
                    ok = condition->wait(msecs - elapsed);
                }
            } catch (...) {
                decref();
                throw;
            }
            if (!ok) {
                decref();
                return false;
            }
        }
    }
    decref();
    return f;
}

quint32 ThreadEventPrivate::getting()
{
    incref();
    mutex.lock();
    quint32 count = this->count.loadAcquire();
    for (const Behold &hold : holds) {
        if (!hold.condition.isNull()) {
            count += hold.condition->getting();
        }
    }
    mutex.unlock();
    decref();
    return count;
}

void ThreadEventPrivate::incref()
{
    ref.ref();
}

bool ThreadEventPrivate::decref()
{
    if (!ref.deref()) {
        delete this;
        return false;
    }
    return true;
}

ThreadEvent::ThreadEvent()
    : d(new ThreadEventPrivate())
{
}

ThreadEvent::~ThreadEvent()
{
    if (d->decref()) {
        d->notify();
    }
    d = nullptr;
}

bool ThreadEvent::tryWait(quint32 msecs)
{
    if (d) {
        return d->wait(msecs);
    } else {
        return false;
    }
}


void ThreadEvent::set()
{
    if (!d) {
        return;
    }

    if (d->flag.fetchAndStoreRelease(true)) {
        return;
    }
    d->notify();
}

void ThreadEvent::clear()
{
    if (!d) {
        return;
    }
    d->flag.storeRelease(false);
    // d->flag.testAndSetAcquire(true, false);
}

bool ThreadEvent::isSet() const
{
    if (!d) {
        return false;
    }
    return d->flag.loadAcquire();
}

quint32 ThreadEvent::getting() const
{
    if (!d) {
        return 0;
    }
    return d->getting();
}

void ThreadEvent::link(ThreadEvent &other)
{
    if (!d) {
        return;
    }
    d->mutex.lock();
    d->linkTo.append(&other);
    d->mutex.unlock();
    other.d->mutex.lock();
    other.d->linkFrom.append(this);
    other.d->mutex.unlock();
}

void ThreadEvent::unlink(ThreadEvent &other)
{
    if (!d) {
        return;
    }
    d->mutex.lock();
    d->linkTo.removeOne(&other);
    d->mutex.unlock();
    other.d->mutex.lock();
    other.d->linkFrom.removeOne(this);
    other.d->mutex.unlock();
}

class GatePrivate
{
public:
    Lock lock;
};

bool Gate::tryWait(quint32 msecs /*= (UINT_MAX)*/)
{
    if (!lock.isLocked()) {
        return true;
    } else {
        bool success = lock.tryAcquire(msecs);
        if (!success) {
            return false;
        } else {
            lock.release();
            return true;
        }
    }
}
class RingBufferPrivate{
public:
    explicit RingBufferPrivate(quint32 capacity = 1024);
    ~RingBufferPrivate();
    void setCapacity(quint32 capacity);
    bool put(const char &c);
    quint32 put(const QByteArray &c);
    bool putForcedly(const char &c);
    bool putForcedly(const QByteArray &c);
    char get();
    quint32 get(QByteArray &bytes,quint32 size = 0);
    char peek();
    quint32 peek(QByteArray &res, quint32 size);
    void clear();
public:
    inline bool isEmpty();
    inline bool isFull();
    inline quint32 capacity();
    inline quint32 size();
    inline bool contains(const char &c);
private:
    QVector<char> buffers;
    QAtomicInteger<quint32> readPtr = 0;
    QAtomicInteger<quint32> writePtr = 0;
    quint32 mCapacity;
    quint32 mSize;
};

RingBufferPrivate::RingBufferPrivate(quint32 capacity)
    : readPtr (0)
    , writePtr (0)
    , mCapacity (capacity)
    , mSize (0)
{
    buffers.resize(mCapacity);
}

RingBufferPrivate::~RingBufferPrivate()
{

}

void RingBufferPrivate::setCapacity(quint32 capacity)
{
    mCapacity = capacity;
    buffers.resize(mCapacity);
}

bool RingBufferPrivate::put(const char &c)
{
    if (isFull()) {
        return false;
    }
    buffers[writePtr] = c;
    writePtr = (writePtr + 1) & (mCapacity - 1);
    ++mSize;
    return true;
}

quint32 RingBufferPrivate::put(const QByteArray &bytes)
{
    quint32 nums = 0;
    for(auto c : bytes){
        if(put(c)){
            ++nums;
            continue;
        }
        break;
    }
    return nums;
}

bool RingBufferPrivate::putForcedly(const char &c)
{
    buffers[writePtr] = c;
    writePtr = (writePtr + 1) & (mCapacity -1);
    mSize = mSize < mCapacity ? ++mSize : mSize;
    return true;
}

bool RingBufferPrivate::putForcedly(const QByteArray &bytes)
{
    quint32 nums = 0;
    for(auto c : bytes){
        if(putForcedly(c)){
            ++nums;
            continue;
        }
        break;
    }
    return nums;
}

char RingBufferPrivate::get()
{
    if (isEmpty()){
        return char();
    }
    char res = buffers.at(readPtr);
    readPtr = (readPtr + 1) & (mCapacity - 1);
    mSize--;
    return res;
}

quint32 RingBufferPrivate::get(QByteArray &bytes, quint32 size)
{
    if (isEmpty()){
        return 0;
    }
    quint32 nums = 0;
    quint32 min = qMin(size, mSize);
    QByteArray res;
    for(;nums < min; nums++){
        res += get();
    }
    bytes = res;
    return nums;
}

char RingBufferPrivate::peek()
{
    if (isEmpty()){
        return char();
    }
    return buffers[readPtr];
}

quint32 RingBufferPrivate::peek(QByteArray &res, quint32 size)
{
    if (isEmpty()){
        return 0;
    }
    QByteArray b;
    quint32 nums = 0;
    quint32 read = readPtr;
    quint32 min = qMin(mSize,size);
    while (true){
        if (nums < min){
            b += buffers[read];
            read = (read + 1) & (mCapacity - 1);
            ++nums;
            continue;
        }
        break;
    }
    res = b;
    return nums;
}

void RingBufferPrivate::clear()
{
    readPtr = 0;
    writePtr = 0;
    mSize = 0;
}

bool RingBufferPrivate::isEmpty()
{
    return mSize == 0;
}

bool RingBufferPrivate::isFull()
{
    return mSize == mCapacity;
}

quint32 RingBufferPrivate::capacity()
{
    return this->mCapacity;
}

quint32 RingBufferPrivate::size()
{
    return mSize;
}

bool RingBufferPrivate::contains(const char &c)
{
    return buffers.contains(c);
}

RingBuffer::RingBuffer(quint32 capacity)
    : d (new RingBufferPrivate(capacity))
{

}

void RingBuffer::setCapacity(quint32 capacity)
{
    d->setCapacity(capacity);
}

bool RingBuffer::put(const char &c)
{
    return d->put(c);
}

quint32 RingBuffer::put(const QByteArray &c)
{
    return d->put(c);
}

bool RingBuffer::putForcedly(const char &c)
{
    return d->putForcedly(c);
}

bool RingBuffer::putForcedly(const QByteArray &c)
{
    return d->putForcedly(c);
}

char RingBuffer::get()
{
    return d->get();
}

quint32 RingBuffer::get(QByteArray &bytes, quint32 size)
{
    return d->get(bytes,size);
}

char RingBuffer::peek()
{
    return d->peek();
}

quint32 RingBuffer::peek(QByteArray &res, quint32 size)
{
    return d->peek(res,size);
}

void RingBuffer::clear()
{
    d->clear();
}

bool RingBuffer::isEmpty()
{
    return d->isEmpty();
}

bool RingBuffer::isFull()
{
    return d->isFull();
}

quint32 RingBuffer::capacity()
{
    return d->capacity();
}

quint32 RingBuffer::size()
{
    return d->size();
}

bool RingBuffer::contains(const char &c)
{
    return d->contains(c);
}

ThreadRingBuffer::ThreadRingBuffer(quint32 capacity)
    : mCapacity(capacity)
{
    Q_ASSERT((capacity & (capacity - 1)) == 0);
    buffers.setCapacity(mCapacity);
    notEmpty.clear();
    notFull.set();
}

void ThreadRingBuffer::setCapacity(quint32 capacity)
{
    lock.lockForWrite();
    this->mCapacity = capacity;
    if (static_cast<quint32>(buffers.size()) >= mCapacity) {
        notFull.clear();
    } else {
        notFull.set();
    }
    lock.unlock();
}

bool ThreadRingBuffer::put(const char &c)
{
    lock.lockForWrite();
    if (buffers.size() < mCapacity) {
        buffers.put(c);
        notEmpty.set();
        if (buffers.size() >= mCapacity) {
            notFull.clear();
        }
        lock.unlock();
        return true;
    }
    lock.unlock();
    notFull.wait();
    return put(c);
}

quint32 ThreadRingBuffer::put(const QByteArray &bytes)
{
    quint32 total = 0;
    for (int i = 0; i < bytes.size(); ++i) {
        if (put(bytes[i])) {
            ++total;
        } else {
            break;
        }
    }
    return total;
}

bool ThreadRingBuffer::putForcedly(const char &c)
{
    lock.lockForWrite();
    buffers.putForcedly(c);
    notEmpty.set();
    if (static_cast<quint32>(buffers.size()) >= mCapacity) {
        notFull.clear();
    }
    lock.unlock();
    return true;
}

bool ThreadRingBuffer::putForcedly(const QByteArray &c)
{
    lock.lockForWrite();
    buffers.putForcedly(c);;
    notEmpty.set();
    if (static_cast<quint32>(buffers.size()) >= mCapacity) {
        notFull.clear();
    }
    lock.unlock();
    return true;
}

char ThreadRingBuffer::get()
{
    char result;
    while (true) {
        lock.lockForWrite();
        if (!buffers.isEmpty()) {
            result = buffers.get();
            if (buffers.isEmpty()) {
                notEmpty.clear();
            }
            notFull.set();
            lock.unlock();
            return result;
        }
        lock.unlock();
        notEmpty.wait();
    }
}

quint32 ThreadRingBuffer::get(QByteArray &bytes, quint32 size)
{
    do {
        if (!notEmpty.tryWait()){
            return 0;
        }
        lock.lockForWrite();
        if (!this->buffers.isEmpty()){
            break;
        }
        lock.unlock();
    } while(true);

    const quint32 &res = buffers.get(bytes,size);
    if (this->buffers.isEmpty()){
        notEmpty.clear();
    }
    if (static_cast<quint32>(buffers.size()) < mCapacity){
        notFull.set();
    }
    lock.unlock();
    return res;
}

char ThreadRingBuffer::peek()
{
    lock.lockForRead();
    if (this->buffers.isEmpty()){
        lock.unlock();
        return char();
    }
    const char &c = buffers.peek();
    lock.unlock();
    return c;
}

quint32 ThreadRingBuffer::peek(QByteArray &bytes, quint32 size)
{
    lock.lockForRead();
    if (this->buffers.isEmpty()){
        lock.unlock();
        return 0;
    }
    const quint32 &res = buffers.peek(bytes, size);
    lock.unlock();
    return res;
}

void ThreadRingBuffer::clear()
{
    lock.lockForWrite();
    this->buffers.clear();
    notFull.set();
    notEmpty.clear();
    lock.unlock();
}

bool ThreadRingBuffer::isEmpty()
{
    lock.lockForRead();
    bool t = buffers.isEmpty();
    lock.unlock();
    return t;
}

bool ThreadRingBuffer::isFull()
{
    lock.lockForRead();
    bool t = static_cast<quint32>(buffers.size()) >= mCapacity;
    lock.unlock();
    return t;
}

quint32 ThreadRingBuffer::capacity()
{
    const_cast<ThreadRingBuffer *>(this)->lock.lockForRead();
    quint32 c =mCapacity;
    const_cast<ThreadRingBuffer *>(this)->lock.unlock();
    return c;
}

quint32 ThreadRingBuffer::size()
{
    const_cast<ThreadRingBuffer *>(this)->lock.lockForRead();
    quint32 res = buffers.size();
    const_cast<ThreadRingBuffer *>(this)->lock.unlock();
    return res;
}

bool ThreadRingBuffer::contains(const char &c)
{
    const_cast<ThreadRingBuffer *>(this)->lock.lockForRead();
    bool t = buffers.contains(c);
    const_cast<ThreadRingBuffer *>(this)->lock.unlock();
    return t;
}

quint32 ThreadRingBuffer::getting()
{
    const_cast<ThreadRingBuffer *>(this)->lock.lockForRead();
    int g = notEmpty.getting();
    const_cast<ThreadRingBuffer *>(this)->lock.unlock();
    return g;
}

void LockFreeRingBuffer::put(const QByteArray &data)
{
    while (isFull()) {
        notFull.tryWait();
    }
    bool state = isEmpty();
    const quint32 writeIndex = this->writePtr.loadRelaxed();
    const quint32 nextWriteIndex = writeIndex + 1;
    if (nextWriteIndex - this->readPtr.loadAcquire() > static_cast<quint32>(buffers.size())) {
        this->readPtr.store(writeIndex);
    }

    buffers[writeIndex & this->mask] = std::move(data);;
    this->writePtr.store(nextWriteIndex);

    if (isFull()) {
        notFull.clear();
    }
    if (state){
        notEmpty.set();
    }
}
void LockFreeRingBuffer::putForcedly(const QByteArray &data)
{
    const quint32 writeIndex = this->writePtr.loadRelaxed();
    const quint32 nextWriteIndex = writeIndex + 1;

    if (nextWriteIndex - this->readPtr.loadAcquire() > static_cast<quint32>(buffers.size())) {
        this->readPtr.store(writeIndex);
    }

    buffers[writeIndex & this->mask] = std::move(data);;
    this->writePtr.store(nextWriteIndex);
    notEmpty.set();
}
QByteArray LockFreeRingBuffer::get()
{
    while (isEmpty()) {
        notEmpty.tryWait();
    }

    const quint32 readIndex = this->readPtr.loadAcquire();
    QByteArray data = std::move(buffers[readIndex & this->mask]);
    this->readPtr.store(readIndex + 1);

    if (isEmpty()) {
        notEmpty.clear();
    }
    notFull.set();
    return data;
}
QByteArray LockFreeRingBuffer::peek()
{
    if (isEmpty()) {
        return QByteArray();
    }
    const quint32 readIndex = this->readPtr.loadAcquire();
    return buffers[readIndex & this->mask];
}
size_t LockFreeRingBuffer::size() const
{
    return this->writePtr.loadRelaxed() - this->readPtr.loadAcquire();
}
void LockFreeRingBuffer::clear()
{
    this->readPtr.store(0);
    this->writePtr.store(0);
}
LockFreeRingBuffer::LockFreeRingBuffer(size_t capacity)
    : mCapacity(capacity)
{
    // 确保容量为2的幂
    size_t size = 1;
    while (size < capacity) {
        size *= 2;
    }
    buffers.resize(size);
    this->mask = size - 1;
    this->notEmpty.clear();
    this->notFull.set();
}

QTNETWORKNG_NAMESPACE_END
