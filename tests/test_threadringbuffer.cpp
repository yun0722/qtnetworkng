#include <QtCore/qcoreapplication.h>
#include "qtnetworkng.h"
#include <QDebug>
#include <QThread>
#include <QSemaphore>
#include <QtTest/QTest>
#include <QThread>
#include <QElapsedTimer>
#include <QMutex>
#include <QWaitCondition>
#include <QSharedPointer>
using namespace qtng;
class ThreadRingBufferTest : public QObject
{
    Q_OBJECT

public:
    ThreadRingBufferTest();
    ~ThreadRingBufferTest();

private slots:
    // 基础功能测试
    void testBasicOperations();
    void testEmptyFullConditions();
    void testForcedOperations();
    void testPeek();
    void testClear();

            // 多线程安全测试
    void testConcurrentProducers();
    void testConcurrentConsumers();
    void testMixedProducersConsumers();

private:
    static constexpr quint32 BUFFER_CAPACITY = 4096;

    void producerWorker(ThreadRingBuffer* buffer, int id, int count, QSemaphore* ready);
    void consumerWorker(ThreadRingBuffer* buffer, QVector<char>* output, QReadWriteLock* lock, QSemaphore* ready);
};

ThreadRingBufferTest::ThreadRingBufferTest() {}
ThreadRingBufferTest::~ThreadRingBufferTest() {}

// 基础测试 1: 单字符读写
void ThreadRingBufferTest::testBasicOperations()
{
    ThreadRingBuffer buffer(BUFFER_CAPACITY);

    // 测试单字符写入
    char testChar = 'A';
    QVERIFY(buffer.put(testChar));
    QCOMPARE(buffer.size(), 1u);
    QVERIFY(!buffer.isEmpty());
    QVERIFY(!buffer.isFull());

    // 测试单字符读取
    char result = buffer.get();
    QCOMPARE(result, testChar);
    QCOMPARE(buffer.size(), 0u);
    QVERIFY(buffer.isEmpty());
}

// 基础测试 2: 空/满状态
void ThreadRingBufferTest::testEmptyFullConditions()
{
    ThreadRingBuffer buffer(BUFFER_CAPACITY);

    // 初始状态应为空
    QVERIFY(buffer.isEmpty());
    QVERIFY(!buffer.isFull());

    // 填满缓冲区
    for (quint32 i = 0; i < BUFFER_CAPACITY; ++i) {
        QVERIFY(buffer.put('x'));
    }

    QVERIFY(buffer.isFull());
    QCOMPARE(buffer.size(), BUFFER_CAPACITY);

    // 清空缓冲区
    for (quint32 i = 0; i < BUFFER_CAPACITY; ++i) {
        QVERIFY(buffer.get() == 'x');
    }

    QVERIFY(buffer.isEmpty());
}

// 基础测试 3: 强制操作
void ThreadRingBufferTest::testForcedOperations()
{
    ThreadRingBuffer buffer(4); // 小容量便于测试
    // 强制写入超出容量
    QByteArray data("ABCDEF");
    buffer.putForcedly(data);
    QCOMPARE(buffer.size(), 4); // 超过容量
    QVERIFY(buffer.isFull());    // 强制写入后应为满

    // 读取验证
    QByteArray result;
    buffer.get(result, 6);
    QCOMPARE(result, QByteArray("EFCD")); // 最早的数据被覆盖
}

// 基础测试 4: 查看功能
void ThreadRingBufferTest::testPeek()
{
    ThreadRingBuffer buffer(BUFFER_CAPACITY);

    buffer.put('A');
    buffer.put('B');

    // 查看首字符
    QCOMPARE(buffer.peek(), 'A');

    // 查看多字符
    QByteArray peekResult;
    quint32 peeked = buffer.peek(peekResult, 2);
    QCOMPARE(peeked, 2u);
    QCOMPARE(peekResult, QByteArray("AB"));

    // 查看后缓冲区应不变
    QCOMPARE(buffer.size(), 2u);
}

// 基础测试 5: 清空操作
void ThreadRingBufferTest::testClear()
{
    ThreadRingBuffer buffer(BUFFER_CAPACITY);

    // 填充部分数据
    for (int i = 0; i < 10; ++i) {
        buffer.put('x');
    }

    QCOMPARE(buffer.size(), 10u);
    buffer.clear();
    QVERIFY(buffer.isEmpty());
}

// 线程安全测试 1: 多个生产者
void ThreadRingBufferTest::testConcurrentProducers()
{
    ThreadRingBuffer buffer(BUFFER_CAPACITY);
    const int THREAD_COUNT = 4;
    const int ITEMS_PER_THREAD = 1000;
    QVector<QThread*> threads;
    QSemaphore ready;

    // 创建生产者线程
    for (int i = 0; i < THREAD_COUNT; ++i) {
        QThread* thread = QThread::create([&, i]() {
            producerWorker(&buffer, i, ITEMS_PER_THREAD, &ready);
        });
        threads.append(thread);
        thread->start();
    }

    // 等待所有生产者完成
    ready.acquire(THREAD_COUNT);
    for (auto thread : threads) {
        thread->wait();
        delete thread;
    }

    // 验证总数
    QCOMPARE(buffer.size(), THREAD_COUNT * ITEMS_PER_THREAD);
}

// 生产者工作函数
void ThreadRingBufferTest::producerWorker(
        ThreadRingBuffer* buffer, int id, int count, QSemaphore* ready)
{
    char baseChar = 'A' + id;

    for (int i = 0; i < count; ++i) {
        buffer->put(baseChar);
    }

    ready->release();
}

// 线程安全测试 2: 多个消费者
void ThreadRingBufferTest::testConcurrentConsumers()
{
    ThreadRingBuffer buffer(BUFFER_CAPACITY);
    const int TOTAL_ITEMS = 4000;
    const int THREAD_COUNT = 4;

    // 预先填充数据
    for (int i = 0; i < TOTAL_ITEMS; ++i) {
        buffer.put('X');
    }

    QVector<char> output;
    QReadWriteLock outputLock;
    QSemaphore ready;

    QVector<QThread*> threads;
    for (int i = 0; i < THREAD_COUNT; ++i) {
        QThread* thread = QThread::create([&]() {
            consumerWorker(&buffer, &output, &outputLock, &ready);
        });
        threads.append(thread);
        thread->start();
    }

    // 等待消费者完成
    ready.acquire(THREAD_COUNT);
    for (auto thread : threads) {
        thread->wait();
        delete thread;
    }

    // 验证所有数据都被消费
    QCOMPARE(buffer.size(), 0u);
    QCOMPARE(output.size(), TOTAL_ITEMS);
}

// 消费者工作函数
void ThreadRingBufferTest::consumerWorker(
        ThreadRingBuffer* buffer, QVector<char>* output,
        QReadWriteLock* lock, QSemaphore* ready)
{
    for (int i = 0; i < 1000; ++i) {
        char c = buffer->get();

        QWriteLocker locker(lock);
        output->append(c);
    }

    ready->release();
}

// 线程安全测试 3: 混合生产者和消费者
void ThreadRingBufferTest::testMixedProducersConsumers()
{
    ThreadRingBuffer buffer(BUFFER_CAPACITY);
    const int THREAD_COUNT = 8;
    const int OPERATIONS = 5000;

    QAtomicInt totalProduced(0);
    QAtomicInt totalConsumed(0);
    QSemaphore startSemaphore;

    QVector<QThread*> threads;

    // 创建混合线程
    for (int i = 0; i < THREAD_COUNT; ++i) {
        QThread* thread = QThread::create([&]() {
            startSemaphore.acquire();

            for (int j = 0; j < OPERATIONS; ++j) {
                if (QRandomGenerator::global()->bounded(2)) {
                    buffer.put('X');
                    totalProduced.fetchAndAddRelaxed(1);
                } else {
                    if (!buffer.isEmpty()) {
                        buffer.get();
                        totalConsumed.fetchAndAddRelaxed(1);
                    }
                }
            }
        });
        threads.append(thread);
        thread->start();
    }

    // 同时启动所有线程
    startSemaphore.release(THREAD_COUNT);

    // 等待完成
    for (auto thread : threads) {
        thread->wait();
        delete thread;
    }

    // 验证状态一致性
    int finalSize = totalProduced.load() - totalConsumed.load();
    QCOMPARE(buffer.size(), static_cast<quint32>(finalSize));
}
QTEST_APPLESS_MAIN(ThreadRingBufferTest)
#include "test_threadringbuffer.moc"

