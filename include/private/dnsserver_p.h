#ifndef DNSSERVER_P_H
#define DNSSERVER_P_H

#include "include/coroutine_utils.h"
#include "include/dns.h"
#include "include/dnsserver.h"
#include "qtimer.h"
#include "qobject.h"
#include "qdatetime.h"
#include "include/coroutine.h"
#include "include/socket.h"
QTNETWORKNG_NAMESPACE_BEGIN
class Cache;
class CachePrivate : public QObject {
	Q_OBJECT
public:
	struct  Entry
	{
		Record record;
		QList<QDateTime> triggers;
	};

	CachePrivate(Cache* cache);
	~CachePrivate();
	QList<Entry> entries;
	QDateTime nextTrigger;
	QTimer timer;
private Q_SLOTS:

	void onTimeout();

private:
	Cache* const q;
};
class AbstractServer;
class HostName;
class Message;
class Record;
class HostNamePrivate : public QObject {
	Q_OBJECT
public:
	HostNamePrivate(HostName* hostname, AbstractServer* server);
	~HostNamePrivate();
	void assertHostname();
        bool generateRecord(const HostAddress& srcAddress, quint16 type, Record& record);
	AbstractServer* server;

	QByteArray hostnamePrev;
	QByteArray hostname;
	bool hostnameRegistered;
	int hostnameSuffix;
	QTimer registrationTimer;
	QTimer rebroadcastTimer;
private Q_SLOTS:
	void onMessageReceived(const Message& message);
	void onRegistrationTimeout();
	void onRebroadcastTimeout();
private:
	HostName* const q;
};
class Prober;
class ProberPrivate : public QObject
{
	Q_OBJECT
public:
	ProberPrivate(Prober* prober, AbstractServer* server, const Record& record);
	~ProberPrivate();
	void assertRecord();

	AbstractServer* server;
	bool confirmed;
	Record proposedRecord;
	QByteArray name;
	QByteArray type;
	int suffix;
	QTimer timer;
private Q_SLOTS:
	void onMessageReceived(const Message& message);
	void onTimeout();
private:
	Prober* const q;
};
class Provider;
class ProviderPrivate : public QObject {
	Q_OBJECT
public:
        ProviderPrivate(QObject* parent, AbstractServer* server,HostName* hostname);
	virtual ~ProviderPrivate();

	void announce();
	void confirm();
	void farewell();
	void publish();

	AbstractServer* server;
	HostName* hostname;
	Prober* prober;

	Service service;
	bool initialized;
	bool confirmed;

	Record browsePtrRecord;
	Record ptrRecord;
	Record srvRecord;
	Record txtRecord;

	Record browsePtrProposed;
	Record ptrProposed;
	Record srvProposed;
	Record txtProposed;

private Q_SLOTS:

	void onMessageReceived(const Message& message);
	void onHostnameChanged(const QByteArray& hostname);
};
class ServicePrivate
{
public:
	ServicePrivate();
	~ServicePrivate();
	HostAddress address;
	QByteArray type;
	QByteArray name;
	QByteArray hostname;
	quint16 port;
	QMap<QByteArray, QByteArray> attributes;
private:
};
class ResolverPrivate : public QObject
{
	Q_OBJECT
public:
	explicit ResolverPrivate(Resolver* resolver, AbstractServer* server, const QByteArray& name, Cache* cache);
	~ResolverPrivate();
	QList<Record> existing() const;
	void query() const;

	AbstractServer* server;
	Cache* cache;
	QByteArray name;
	QSet<HostAddress> addresses;
	QTimer timer;
private Q_SLOTS:
	void onMessageReceived(const Message& message);
	void onTimeout();
private:
	Resolver* const q;
};
class DnsServerPrivate : public QObject
{
	Q_OBJECT
public:
	explicit DnsServerPrivate(DnsServer* server);
	~DnsServerPrivate();
	bool bindSocket(QSharedPointer<Socket>& socket, const HostAddress& address);

	void onReadyRead(QSharedPointer<Socket>& socket);

	QSharedPointer<Socket> ipv4Socket;
	QSharedPointer<Socket> ipv6Socket;
	QTimer timer;
private Q_SLOTS:

	void onTimeout();

private:
	DnsServer* const q;
	CoroutineGroup* operations;
};
class BrowserPrivate : public QObject
{
	Q_OBJECT
public:
	explicit BrowserPrivate(Browser* browser, AbstractServer* server, const QByteArray& type, Cache* existingCache);
	~BrowserPrivate();
	bool updateService(const QByteArray& fqName);
	void sendQueryAll();

	AbstractServer* server;
	QByteArray type;
	Cache* cache;
	QSet<QByteArray> ptrTargets;
	QMap<QByteArray, Service> services;
	QSet<QByteArray> hostnames;

	QTimer queryTimer;
	QTimer serviceTimer;
private Q_SLOTS:
	void onMessageReceived(const Message& message);
	void onShouldQuery(const Record& record);
	void onRecordExpired(const Record& record);

	void onQueryTimeout();
	void onServiceTimeout();
private:
	void updateHostnames();
	CoroutineGroup* operations;
	Browser* const q;
	Message mes;
};
QTNETWORKNG_NAMESPACE_END
#endif // DNSSERVER_P_H
