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
#include <QtTest>
#include <QByteArray>
#include <QtMath>

using namespace qtng;
class TestRingBuffer : public QObject
{
    Q_OBJECT

private slots:
    // 基础功能测试
    void testInitialization();
    void testBasicPutGet();
    void testIsEmpty();
    void testIsFull();
    void testSizeCalculation();
    void testClear();

            // 边界条件测试
    void testFullBuffer();
    void testFullBufferPutForcedly();
    void testEmptyBufferGet();
    void testPeekBehavior();

            // 特殊操作测试
    void testPutForcedlyOverCapacity();
    void testCircularWrapAround();
};

// 辅助函数：检查是否为2的幂次方
bool isPowerOfTwo(size_t n) {
    return (n != 0) && ((n & (n - 1)) == 0);
}

void TestRingBuffer::testInitialization()
{
    // 测试非2的幂次方容量
    const size_t requestedCapacity = 5;
    const size_t expectedCapacity = 8;  // 大于5的最小2的幂次方

    RingBuffer buffer(requestedCapacity);

    QVERIFY(buffer.isEmpty());
    QVERIFY(!buffer.isFull());
    QCOMPARE(buffer.size(), 0);
    QVERIFY(buffer.peek().isEmpty());

    // 验证实际容量是2的幂次方
    QVERIFY(isPowerOfTwo(expectedCapacity));
    QVERIFY(buffer.isFull() == false);
}

void TestRingBuffer::testBasicPutGet()
{
    // 使用2的幂次方容量
    const size_t capacity = 4;  // 2^2
    RingBuffer buffer(capacity);

    // 测试基本写入和读取
    QVERIFY(buffer.put('a'));
    QVERIFY(buffer.put('b'));
    QVERIFY(buffer.put('c'));
    QVERIFY(buffer.put('d'));  // 刚好填满

    QCOMPARE(buffer.get(), 'a');
    QCOMPARE(buffer.get(), 'b');
    QCOMPARE(buffer.get(), 'c');
    QCOMPARE(buffer.get(), 'd');
}

void TestRingBuffer::testIsEmpty()
{
    const size_t capacity = 4;  // 2^2
    RingBuffer buffer(capacity);

    QVERIFY(buffer.isEmpty());
    buffer.put('x');
    QVERIFY(!buffer.isEmpty());
    buffer.get();
    QVERIFY(buffer.isEmpty());
}

void TestRingBuffer::testIsFull()
{
    const size_t capacity = 4;  // 2^2
    RingBuffer buffer(capacity);

    QVERIFY(!buffer.isFull());
    buffer.put('a');
    QVERIFY(!buffer.isFull());
    buffer.put('b');
    QVERIFY(!buffer.isFull());
    buffer.put('c');
    QVERIFY(!buffer.isFull());
    buffer.put('d');
    QVERIFY(buffer.isFull());
    buffer.get();
    QVERIFY(!buffer.isFull());
}

void TestRingBuffer::testSizeCalculation()
{
    const size_t capacity = 8;  // 2^3
    RingBuffer buffer(capacity);

    QCOMPARE(buffer.size(), 0);
    buffer.put('a');
    QCOMPARE(buffer.size(), 1);
    buffer.put('b');
    QCOMPARE(buffer.size(), 2);
    buffer.get();
    QCOMPARE(buffer.size(), 1);
    buffer.get();
    QCOMPARE(buffer.size(), 0);
}

void TestRingBuffer::testClear()
{
    const size_t capacity = 4;  // 2^2
    RingBuffer buffer(capacity);

    buffer.put('a');
    buffer.put('b');
    buffer.clear();

    QVERIFY(buffer.isEmpty());
    QCOMPARE(buffer.size(), 0);
    QVERIFY(buffer.peek().isEmpty());
}

void TestRingBuffer::testFullBuffer()
{
    const size_t capacity = 4;  // 2^2
    RingBuffer buffer(capacity);

    QVERIFY(buffer.put('a'));
    QVERIFY(buffer.put('b'));
    QVERIFY(buffer.put('c'));
    QVERIFY(buffer.put('d'));  // 填满

    // 尝试在满时添加新元素应失败
    QVERIFY(!buffer.put('e'));

    QCOMPARE(buffer.get(), 'a');  // 取出一个元素
    QVERIFY(buffer.put('e'));    // 现在应该成功添加
    QCOMPARE(buffer.get(), 'b');
    QCOMPARE(buffer.get(), 'c');
    QCOMPARE(buffer.get(), 'd');
    QCOMPARE(buffer.get(), 'e');
}

void TestRingBuffer::testFullBufferPutForcedly()
{
    const size_t capacity = 4;  // 2^2
    RingBuffer buffer(capacity);

    // 填满缓冲区
    buffer.put('a');
    buffer.put('b');
    buffer.put('c');
    buffer.put('d');

    QVERIFY(buffer.isFull());

    // 使用putForcedly添加更多数据
    QByteArray extraData = "efg";
    buffer.putForcedly(extraData);

    // 验证数据被覆盖（环形行为）
    QCOMPARE(buffer.get(), 'd');
    QCOMPARE(buffer.get(), 'e');  // 最旧的数据被覆盖
    QCOMPARE(buffer.get(), 'f');
    QCOMPARE(buffer.get(), 'g');

}

void TestRingBuffer::testEmptyBufferGet()
{
    const size_t capacity = 4;  // 2^2
    RingBuffer buffer(capacity);

    // 空缓冲区读取应该返回空字符
    QCOMPARE(buffer.get(), '\0');
}

void TestRingBuffer::testPeekBehavior()
{
    const size_t capacity = 4;  // 2^2
    RingBuffer buffer(capacity);

    buffer.put('a');
    buffer.put('b');

    QByteArray peekResult = buffer.peek();
    QCOMPARE(peekResult, QByteArray("ab"));

    // 确保peek不改变状态
    QCOMPARE(buffer.get(), 'a');
    QCOMPARE(buffer.get(), 'b');
}

void TestRingBuffer::testPutForcedlyOverCapacity()
{
    const size_t capacity = 4;  // 2^2
    RingBuffer buffer(capacity);

    QByteArray largeData = "abcdefgh";  // 8个字符，两倍于容量
    buffer.putForcedly(largeData);

    // 验证只保留了最后4个字符（环形覆盖）
    QCOMPARE(buffer.get(), 'e');
    QCOMPARE(buffer.get(), 'f');
    QCOMPARE(buffer.get(), 'g');
    QCOMPARE(buffer.get(), 'h');

    // 现在缓冲区应该为空
    QVERIFY(buffer.isEmpty());
    QCOMPARE(buffer.size(), 0);

    // 再次读取应该得到空字符
    QCOMPARE(buffer.get(), '\0');
    // 并且仍然为空
    QVERIFY(buffer.isEmpty());
}

void TestRingBuffer::testCircularWrapAround()
{
    const size_t capacity = 4;  // 2^2
    RingBuffer buffer(capacity);

    // 填充缓冲区
    buffer.put('a');
    buffer.put('b');
    buffer.put('c');
    buffer.put('d');

    // 读取部分数据
    QCOMPARE(buffer.get(), 'a');
    QCOMPARE(buffer.get(), 'b');

    // 添加新数据（应该循环使用空间）
    buffer.put('e');
    buffer.put('f');

    QCOMPARE(buffer.size(), 4);
    QVERIFY(buffer.isFull());

    // 验证顺序和内容
    QCOMPARE(buffer.get(), 'c');
    QCOMPARE(buffer.get(), 'd');
    QCOMPARE(buffer.get(), 'e');
    QCOMPARE(buffer.get(), 'f');

    // 缓冲区应为空
    QVERIFY(buffer.isEmpty());
}

QTEST_APPLESS_MAIN(TestRingBuffer)
#include "test_ringbuffer.moc"

