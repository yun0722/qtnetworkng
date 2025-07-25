#include <QtCore/qcoreapplication.h>
#include "qtnetworkng.h"
#include <QDebug>
#include <QThread>
using namespace qtng;

int main(int argc, char **argv)
{
    QQueue<QByteArray> q;
    for(int i=0;i<8;i++){
        q.enqueue("test"+QString::number(i).toLatin1());
    }
    LockFreeRingBuffer buffers(4);
    QSharedPointer<QThread> wPtr(QThread::create([&](){
        while(!q.isEmpty()){
            buffers.put(q.dequeue());
        }
    }));
    QSharedPointer<QThread> rPtr(QThread::create([&](){
        for(int i = 0; i<8; i++){
            qDebug()<<buffers.get();
        }
    }));
    wPtr->start();
    rPtr->start();
    wPtr->wait();
    rPtr->wait();
    return 0;
}
