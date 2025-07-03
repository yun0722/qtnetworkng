#ifndef DNSSERVER_H
#define DNSSERVER_H
#include <QObject>
#include "dns.h"
QTNETWORKNG_NAMESPACE_BEGIN
class AbstractServer : public QObject {
	Q_OBJECT
public:
	explicit AbstractServer(QObject* parent = 0);
	virtual void sendMessage(const Message& message) = 0;
	virtual void sendMessageToAll(const Message& message) = 0;
Q_SIGNALS:
	void messageReceived(const Message& message);
	void error(const QString& message);
};
class CachePrivate;
class Cache : public QObject {
	Q_OBJECT
public:
	explicit Cache(QObject* parent = 0);
	void addRecord(const Record& record);
	bool lookupRecord(const QByteArray& name, quint16 type, Record& record) const;
	bool lookupRecords(const QByteArray& name, quint16 type, QList<Record>& records) const;
Q_SIGNALS:
	void shouldQuery(const Record& record);
	void recordExpired(const Record& record);
private:
	CachePrivate* const d;
};
class HostNamePrivate;
class HostName : public QObject {
	Q_OBJECT
public:
	HostName(AbstractServer* server, QObject* parent = 0);
	~HostName();
	bool isRegistered() const;
	QByteArray hostname() const;
        static QString getLocalHostName();
Q_SIGNALS:
	void hostnameChanged(const QByteArray& hostname);
private:
	HostNamePrivate* const d;
};
class ServicePrivate;
class Service
{
public:
	Service();
	Service(const Service& other);
	Service& operator=(const Service& other);
	bool operator==(const Service& other) const;
	bool operator!=(const Service& other) const;
	virtual ~Service();
	void setAddress(const HostAddress& address);
	HostAddress address() const;
	QByteArray type() const;
	void setType(const QByteArray& type);
	QByteArray name() const;
	void setName(const QByteArray& name);
	QByteArray hostname()const;
	void setHostname(const QByteArray& hostname);
	quint16 port() const;
	void setPort(quint16 port);
	QMap<QByteArray, QByteArray> attributes() const;
	void setAttributes(const QMap<QByteArray, QByteArray>& attributes);
	void addAttribute(const QByteArray& key, const QByteArray& value);
private:
	ServicePrivate* const d;
};

class ProberPrivate;
class Prober : public QObject
{
	Q_OBJECT
public:
	Prober(AbstractServer* server, const Record& record, QObject* parent = 0);
Q_SIGNALS:
	void nameConfirmed(const QByteArray& name);
private:
	ProberPrivate* const d;
};
class ProviderPrivate;
class Provider :public QObject {
	Q_OBJECT
public:
	Provider(AbstractServer* server, HostName* hostname, QObject* parent = 0);
	void update(const Service& service);
private:
	ProviderPrivate* const d;
};
class ResolverPrivate;
class Resolver : public QObject
{
	Q_OBJECT
public:
	Resolver(AbstractServer* server, const QByteArray& name, Cache* cache = 0, QObject* parent = 0);

Q_SIGNALS:
	void resolved(const HostAddress& address);
private:
	ResolverPrivate* const d;
};
class DnsServerPrivate;
class DnsServer : public AbstractServer
{
	Q_OBJECT
public:
	explicit DnsServer(QObject* parent = 0);
	virtual void sendMessage(const Message& message);
	virtual void sendMessageToAll(const Message& message);
private:
	DnsServerPrivate* const d;
};
class BrowserPrivate;
class Browser : public QObject
{
	Q_OBJECT
public:
	Browser(AbstractServer* server, const QByteArray& type, Cache* cache = 0, QObject* parent = 0);
	QMap<QByteArray, Service> getServices();
	void sendQueryAll();
Q_SIGNALS:
	void serviceAdded(const Service& service);
	void serviceUpdated(const Service& service);
	void serviceRemoved(const Service& service);
private:
	BrowserPrivate* const d;
};
QTNETWORKNG_NAMESPACE_END
#endif // DNSSERVER_H
