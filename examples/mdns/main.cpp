#include "include/private/dns_p.h"
#include "include/qtnetworkng.h"
#include <QApplication>
using namespace qtng;
int main(int argc, char* argv[])
{
    QApplication a(argc, argv);
    DnsServer server;
    HostName hostname(&server);
    Provider provider(&server, &hostname);
    Service service;
    service.setType("_http._tcp.local.");
    service.setName("AAAAAAAAAAAAAAAAAAAAAAAAA");
    service.setPort(1235);

    Coroutine::spawn([&provider, &service]() {
        while (1) {
                provider.update(service);
                Coroutine::msleep(10 * 1000);
        }
        });
    Browser browser(&server, MdnsBrowseType);
    QObject::connect(&browser, &Browser::serviceAdded, [&](const Service& service) {
        qDebug() << "Add: " << "Type:" << service.type() << " Name: " << service.name() << " HostName:" << service.hostname() << " Port: " << service.port() << " IP: " << service.address();
    });
    return a.exec();
}
