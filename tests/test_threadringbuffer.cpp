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
#include <QtConcurrent/QtConcurrent>
#include <qtestcase.h>
using namespace qtng;
class TestLockFreeRingBufferBasicBlock : public QObject
{
    Q_OBJECT

private slots:
    void testCapacityAdjustment();
    void testBasicOperations();
    void testFullBehavior();
    void testEmptyBehavior();
    void testConcurrentAccess();
    void testClearOperation();
};

void TestLockFreeRingBufferBasicBlock::testCapacityAdjustment()
{
    // 测试非2^n容量的调整
    LockFreeRingBufferBasicBlock buffer(3); // 3不是2的幂

    // 验证实际分配的容量是4 (2^2)
    QCOMPARE(buffer.buffers.size(), 4);
    QCOMPARE(buffer.mask, 3); // mask = size - 1 = 3

    // 验证能存储超过原始容量的数据
    buffer.putForcedly("1234");
    QVERIFY(!buffer.isEmpty());
    QCOMPARE(buffer.get(), QByteArray("1234"));
}

void TestLockFreeRingBufferBasicBlock::testBasicOperations()
{
    LockFreeRingBufferBasicBlock buffer(2); // 容量调整为4

    // 基础读写测试
    QVERIFY(buffer.put("AB"));
    QVERIFY(buffer.put("CD"));

    QCOMPARE(buffer.peek(), QByteArray("AB"));
    QCOMPARE(buffer.get(), QByteArray("AB"));
    QCOMPARE(buffer.get(), QByteArray("CD"));

    // 验证空状态
    QVERIFY(buffer.isEmpty());
}

void TestLockFreeRingBufferBasicBlock::testFullBehavior()
{
    LockFreeRingBufferBasicBlock buffer(2); // 实际容量4

    // 填充缓冲区
    buffer.put("A");
    buffer.put("B");
    QVERIFY(buffer.isFull());

    // 测试阻塞写入
    bool putCompleted = false;
    auto future = QtConcurrent::run([&]() {
        buffer.put("E"); // 应该阻塞
        putCompleted = true;
    });

    // 验证阻塞
    QTest::qWait(100);
    QVERIFY(!putCompleted);

    // 释放空间
    buffer.get();
    QTest::qWait(100);
    QVERIFY(putCompleted);
}

void TestLockFreeRingBufferBasicBlock::testEmptyBehavior()
{
    LockFreeRingBufferBasicBlock buffer(2);

    // 测试阻塞读取
    bool getCompleted = false;
    QByteArray result;
    auto future = QtConcurrent::run([&]() {
        result = buffer.get(); // 应该阻塞
        getCompleted = true;
    });

    // 验证阻塞
    QTest::qWait(100);
    QVERIFY(!getCompleted);

    // 写入数据
    buffer.put("Test");
    future.waitForFinished();
    QVERIFY(getCompleted);
    QCOMPARE(result, QByteArray("Test"));
}

void TestLockFreeRingBufferBasicBlock::testConcurrentAccess()
{
    LockFreeRingBufferBasicBlock buffer(4); // 实际容量8

    const int itemCount = 100;
    QAtomicInt producerCount(0);
    QAtomicInt consumerCount(0);

    // 生产者线程
    auto producer = QtConcurrent::run([&]() {
        for (int i = 0; i < itemCount; ++i) {
            buffer.put(QByteArray::number(i));
            producerCount.fetchAndAddRelaxed(1);
        }
    });

    // 消费者线程
    auto consumer = QtConcurrent::run([&]() {
        for (int i = 0; i < itemCount; ++i) {
            QByteArray data = buffer.get();
            bool ok;
            int value = data.toInt(&ok);
            if (ok) consumerCount.fetchAndAddRelaxed(1);
        }
    });

    // 等待完成
    producer.waitForFinished();
    consumer.waitForFinished();

    // 验证数据完整性
    QCOMPARE(producerCount.load(), itemCount);
    QCOMPARE(consumerCount.load(), itemCount);
    QVERIFY(buffer.isEmpty());
}

void TestLockFreeRingBufferBasicBlock::testClearOperation()
{
    LockFreeRingBufferBasicBlock buffer(2); // 实际容量4

    buffer.put("Data1");
    buffer.put("Data2");

    QCOMPARE(buffer.size(), 2);
    buffer.clear();

    // 验证清除后状态
    QVERIFY(buffer.isEmpty());
    QCOMPARE(buffer.size(), 0);

    // 验证清除后可用
    QVERIFY(buffer.put("NewData"));
    QCOMPARE(buffer.get(), QByteArray("NewData"));
}

QTEST_MAIN(TestLockFreeRingBufferBasicBlock)
#include "test_threadringbuffer.moc"
