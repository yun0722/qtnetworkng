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

class TestRingBuffer : public QObject
{
    Q_OBJECT

private:
    const quint32 TEST_CAPACITY = 1024; // 2^10 幂次方容量
    RingBuffer* buffer;

private slots:
    // 测试初始化与清理
    void initTestCase() {
        buffer = new RingBuffer(TEST_CAPACITY);
    }
    void cleanupTestCase() {
        delete buffer;
    }
    void init() {
        buffer->clear();
    }

            // 核心功能测试
    void testEmptyBuffer();
    void testSingleChar();
    void testBoundaryConditions();
    void testFullCapacity();
    void testPeekFunction();
    void testForcedOverwrite();
    void testDataContains();
    void testBufferClear();
    void testCapacityChange();
};

// === 测试用例实现 ===
void TestRingBuffer::testEmptyBuffer() {
    QVERIFY(buffer->isEmpty());
    QVERIFY(!buffer->isFull());
    QCOMPARE(buffer->size(), 0u);
    QCOMPARE(buffer->capacity(), TEST_CAPACITY);

            // 空缓冲区读取应返回空值
    QCOMPARE(buffer->get(), char());
    QByteArray data;
    QCOMPARE(buffer->get(data, 10), 0u);
}

void TestRingBuffer::testSingleChar() {
    // 验证单字符写入/读取
    char testChar = 'A';
    QVERIFY(buffer->put(testChar));
    QCOMPARE(buffer->size(), 1u);
    QVERIFY(!buffer->isEmpty());

            // Peek验证不改变指针
    QCOMPARE(buffer->peek(), testChar);
    QCOMPARE(buffer->size(), 1u);

            // 读取验证
    QCOMPARE(buffer->get(), testChar);
    QVERIFY(buffer->isEmpty());
}

void TestRingBuffer::testBoundaryConditions() {
    // 边界循环测试（写指针回绕）
    QByteArray data(TEST_CAPACITY / 2, 'B');
    quint32 written = buffer->put(data);
    QCOMPARE(written, TEST_CAPACITY / 2);

            // 读取部分数据触发回绕条件
    QByteArray output;
    quint32 read = buffer->get(output, TEST_CAPACITY / 4);
    QCOMPARE(read, TEST_CAPACITY / 4);

            // 继续写入直到超过容量
    QByteArray newData(TEST_CAPACITY, 'C');
    written = buffer->put(newData);
    QCOMPARE(written, TEST_CAPACITY - (TEST_CAPACITY / 4)); // 剩余空间
}

void TestRingBuffer::testFullCapacity() {
    // 填满缓冲区
    QByteArray data(TEST_CAPACITY, 'D');
    quint32 written = buffer->put(data);
    QCOMPARE(written, TEST_CAPACITY);
    QVERIFY(buffer->isFull());
    QCOMPARE(buffer->size(), TEST_CAPACITY);

            // 满时写入失败
    QVERIFY(!buffer->put('X'));

            // 读取所有数据
    QByteArray output;
    quint32 read = buffer->get(output, TEST_CAPACITY + 100);
    QCOMPARE(read, TEST_CAPACITY);
    QVERIFY(buffer->isEmpty());
}

void TestRingBuffer::testPeekFunction() {
    // 多字符peek测试
    QByteArray input = "TestPeek";
    qDebug()<<"size:"<<buffer->put(input);
            // Peek不改变缓冲区状态
    QByteArray peekResult;
    quint32 peekSize = buffer->peek(peekResult, 4);
    QCOMPARE(peekSize, 4u);
    QCOMPARE(peekResult.constData(), "Test");
    QCOMPARE(buffer->size(), input.size());

            // 完整读取验证
    QByteArray fullRead;
    buffer->get(fullRead, input.size());
    QCOMPARE(fullRead, input);
}

void TestRingBuffer::testForcedOverwrite() {
    // 填满缓冲区
    buffer->clear();
    buffer->setCapacity(TEST_CAPACITY);
    QByteArray initialData(TEST_CAPACITY, 'A');
    buffer->put(initialData);

            // 强制写入覆盖旧数据
    QByteArray overwriteData = "Forced";
    buffer->putForcedly(overwriteData);
    QByteArray bytes;
            // 验证新数据存在且长度不变
    QVERIFY(buffer->contains('F'));
    QCOMPARE(buffer->size(), TEST_CAPACITY);

            // 读取数据验证覆盖顺序
    QByteArray readData;
    buffer->get(readData, TEST_CAPACITY);
    QVERIFY(readData.startsWith("Forced")); // 原始数据被覆盖
    QVERIFY(readData.endsWith("A"));        // 未覆盖部分保留
}

void TestRingBuffer::testDataContains() {
    // 填充测试数据
    QByteArray data = "SearchTest";
    buffer->put(data);

            // 存在性验证
    QVERIFY(buffer->contains('S'));
    QVERIFY(buffer->contains('T'));
    QVERIFY(!buffer->contains('X')); // 不存在字符

}

void TestRingBuffer::testBufferClear() {
    // 填充后清除
    buffer->put(QByteArray(100, 'G'));
    buffer->clear();

    QVERIFY(buffer->isEmpty());
    QCOMPARE(buffer->size(), 0u);
    QCOMPARE(buffer->capacity(), TEST_CAPACITY); // 容量不变
}

void TestRingBuffer::testCapacityChange() {
    // 动态调整容量
    const quint32 newCapacity = 2048; // 2^11
    buffer->setCapacity(newCapacity);
    QCOMPARE(buffer->capacity(), newCapacity);
    QVERIFY(buffer->isEmpty());

            // 验证新容量可用性
    QByteArray largeData(newCapacity, 'H');
    quint32 written = buffer->put(largeData);
    QCOMPARE(written, newCapacity);
    QVERIFY(buffer->isFull());
}

QTEST_APPLESS_MAIN(TestRingBuffer)
#include "test_ringbuffer.moc"

