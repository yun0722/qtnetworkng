#include <QCoreApplication>
#include <QThread>
#include <QDebug>
#include <atomic>
#include "qtnetworkng.h"

using namespace qtng;

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    const int bufferSize = 256;
    ThreadRingBuffer ringbuffer(bufferSize);

            // 使用原子变量确保线程安全
    std::atomic<bool> productionComplete(false);
    std::atomic<int> itemsToConsume(0);

            // 创建生产者线程
    QSharedPointer<QThread> producer1(QThread::create([&](){
        for(int i = 0; i < bufferSize; i++) {
            QByteArray value = "thread1:" + QString::number(i).toLatin1();
            if (ringbuffer.put(value)) {
                qDebug() << "Producer1 put:" << value;
                itemsToConsume++; // 增加待消费计数
            }
            QThread::msleep(1); // 减少延迟以便更快完成
        }
        productionComplete = true; // 标记生产完成
        qDebug() << "Producer1 finished";
    }));

    QSharedPointer<QThread> consumer(QThread::create([&](){
        while (true) {
            QByteArray value;

            bool success = ringbuffer.get(value, ringbuffer.size());

            if (success) {
                qDebug() << "Consumer got:" << value;
                itemsToConsume--; // 减少待消费计数
            }

            if (productionComplete && itemsToConsume <= 0) {
                qDebug() << "Consumer exiting: production complete and no items left";
                break;
            }

            if (productionComplete && ringbuffer.isEmpty()) {
                qDebug() << "Consumer exiting: production complete and buffer empty";
                break;
            }
        }
        qDebug() << "Consumer finished";
    }));

            // 启动所有线程
    producer1->start();
    consumer->start();

    // 等待所有线程完成
    producer1->wait();
    consumer->wait();

    qDebug() << "All threads completed. Remaining items:" << itemsToConsume;
    return 0;
}
