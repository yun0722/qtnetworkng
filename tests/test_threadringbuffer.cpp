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
#include <qtestcase.h>
using namespace qtng;
class TestThreadRingBuffer : public QObject
{
    Q_OBJECT

private slots:
    void testbasicOptions(){
        ThreadRingBuffer buffers(4);
        QVERIFY(buffers.put("a"));
        buffers.put("b");
        buffers.put("c");
        QCOMPARE(buffers.size(),3);
        buffers.put("d");
        QVERIFY(buffers.isFull());
        QCOMPARE(buffers.peek(),"abcd");
        QCOMPARE(buffers.get(),"abcd");
        QVERIFY(buffers.isEmpty());
        buffers.put("abcd");
        QCOMPARE(buffers.size(),4);
        buffers.clear();
        QCOMPARE(buffers.size(),0);
    }
    void testputforcely(){
        ThreadRingBuffer buffers(4);;
        buffers.put("abcd");
        QCOMPARE(buffers.size(),4);
        QVERIFY(buffers.isFull());
        buffers.putForcedly("hello");
        QCOMPARE(buffers.size(),4);
        QCOMPARE(buffers.get(),"ello");
        QVERIFY(buffers.isEmpty());
    }
    void testThreadOptions(){
        ThreadRingBuffer buffers(4);
        QAtomicInteger<bool> finished = false;
        QSharedPointer<QThread>wThread(QThread::create([&](){
            buffers.put("hello world");
            finished=true;
        }));
        QByteArray res;
        QSharedPointer<QThread>rThread(QThread::create([&](){
            while (!finished){
                res += buffers.get();
            }
        }));
        wThread->start();
        rThread->start();
        wThread->wait();
        rThread->wait();
        QCOMPARE(res,"hello world");
    }
};

QTEST_APPLESS_MAIN(TestThreadRingBuffer)
#include "test_threadringbuffer.moc"
