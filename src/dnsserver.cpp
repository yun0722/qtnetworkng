#include "include/dnsserver.h"
#include "include/private/dnsserver_p.h"
#include "include/dns.h"
#include "include/private/dns_p.h"
#if defined(_WIN32)
#include <Windows.h>
#else
#include <unistd.h>
#endif
QTNETWORKNG_NAMESPACE_BEGIN
AbstractServer::AbstractServer(QObject* parent)
	: QObject(parent)
{
}



CachePrivate::CachePrivate(Cache* cache)
	: QObject(cache)
	, q(cache)
{
	connect(&timer, &QTimer::timeout, this, &CachePrivate::onTimeout);

	timer.setSingleShot(true);
}

CachePrivate::~CachePrivate()
{
}

void Cache::addRecord(const Record& record)
{
	// If a record exists that matches, remove it from the cache; if the TTL
	// is nonzero, it will be added back to the cache with updated times
	for (auto i = d->entries.begin(); i != d->entries.end();) {
		if ((record.flushCache() &&
			(*i).record.name() == record.name() &&
			(*i).record.type() == record.type()) ||
			(*i).record == record) {

			// If the TTL is set to 0, indicate that the record was removed
			if (record.ttl() == 0) {
				emit recordExpired((*i).record);
			}

			i = d->entries.erase(i);

			// No need to continue further if the TTL was set to 0
			if (record.ttl() == 0) {
				return;
			}
		}
		else {
			++i;
		}
	}

	// Use the current time to calculate the triggers and add a random offset
	QDateTime now = QDateTime::currentDateTime();
#ifdef USE_QRANDOMGENERATOR
	qint64 random = QRandomGenerator::global()->bounded(20);
#else
	qint64 random = qrand() % 20;
#endif

	QList<QDateTime> triggers{
		now.addMSecs(record.ttl() * 500 + random),  // 50%
		now.addMSecs(record.ttl() * 850 + random),  // 85%
		now.addMSecs(record.ttl() * 900 + random),  // 90%
		now.addMSecs(record.ttl() * 950 + random),  // 95%
		now.addSecs(record.ttl())
	};

	// Append the record and its triggers
	d->entries.append({ record, triggers });

	// Check if the new record's first trigger is earlier than the next
	// scheduled trigger; if so, restart the timer
	if (d->nextTrigger.isNull() || triggers.at(0) < d->nextTrigger) {
		d->nextTrigger = triggers.at(0);
		d->timer.start(now.msecsTo(d->nextTrigger));
	}
}

bool Cache::lookupRecord(const QByteArray& name, quint16 type, Record& record) const
{
	QList<Record> records;
	if (lookupRecords(name, type, records)) {
		record = records.at(0);
		return true;
	}
	return false;
}

bool Cache::lookupRecords(const QByteArray& name, quint16 type, QList<Record>& records) const
{
	bool recordsAdded = false;
	for (const CachePrivate::Entry& entry : d->entries) {
		if ((name.isNull() || entry.record.name() == name) &&
			(type == ANY || entry.record.type() == type)) {
			records.append(entry.record);
			recordsAdded = true;
		}
	}
	return recordsAdded;
}



HostName::HostName(AbstractServer* server, QObject* parent)
	:QObject(parent)
	, d(new HostNamePrivate(this, server))
{

}

HostName::~HostName()
{
	delete d;
}

bool HostName::isRegistered() const
{
	return d->hostnameRegistered;
}

QByteArray HostName::hostname() const
{
	return d->hostname;
}

QString HostName::getLocalHostName()
{
#if defined(_WIN32)
    DWORD size = 0;
    if (!GetComputerNameExA(ComputerNameDnsHostname, nullptr, &size) &&
        GetLastError() == ERROR_MORE_DATA) {
        std::string buffer(size, '\0');
        if (GetComputerNameExA(ComputerNameDnsHostname, &buffer[0], &size)) {
            buffer.resize(size);
            return QString::fromStdString(buffer);
        }
    }
    throw std::runtime_error("Failed to get Windows computer name");
#else
    // POSIX实现（Linux/macOS/BSD等）
    char buffer[256];
    if (gethostname(buffer, sizeof(buffer)) == 0) {
        buffer[sizeof(buffer)-1] = '\0'; // 确保终止
            return QString::fromStdString(buffer);
    }
    throw std::runtime_error("Failed to get POSIX hostname");
#endif
}

HostNamePrivate::HostNamePrivate(HostName* hostname, AbstractServer* server)
	: QObject(hostname)
	, server(server)
	, q(hostname)
{
	connect(server, &AbstractServer::messageReceived, this, &HostNamePrivate::onMessageReceived);
	connect(&registrationTimer, &QTimer::timeout, this, &HostNamePrivate::onRegistrationTimeout);
	connect(&rebroadcastTimer, &QTimer::timeout, this, &HostNamePrivate::onRebroadcastTimeout);

	registrationTimer.setInterval(2 * 1000);
	registrationTimer.setSingleShot(true);

	rebroadcastTimer.setInterval(30 * 60 * 1000);
	rebroadcastTimer.setSingleShot(true);

	// Immediately assert the hostname
	onRebroadcastTimeout();
}

HostNamePrivate::~HostNamePrivate()
{
}

void HostNamePrivate::assertHostname()
{
	// Begin with the local hostname and replace any "." with "-" (I'm looking
	// at you, macOS)
        QByteArray localHostname = HostName::getLocalHostName().toUtf8();
	localHostname = localHostname.replace('.', '-');

	// If the suffix > 1, then append a "-2", "-3", etc. to the hostname to
	// aid in finding one that is unique and not in use
	hostname = (hostnameSuffix == 1 ? localHostname :
		localHostname + "-" + QByteArray::number(hostnameSuffix)) + ".local.";

	// Compose a query for A and AAAA records matching the hostname
	Query ipv4Query;
	ipv4Query.setName(hostname);
	ipv4Query.setType(A);
	Query ipv6Query;
	ipv6Query.setName(hostname);
	ipv6Query.setType(AAAA);
	Message message;
	message.addQuery(ipv4Query);
	message.addQuery(ipv6Query);

	server->sendMessageToAll(message);

	// If no reply is received after two seconds, the hostname is available
	registrationTimer.start();
}

bool HostNamePrivate::generateRecord(const HostAddress &srcAddress, quint16 type, Record& record)
{

	const auto interfaces = NetworkInterface::allInterfaces();
	for (const NetworkInterface& networkInterface : interfaces) {
		const auto entries = networkInterface.addressEntries();
		for (const NetworkAddressEntry& entry : entries) {
			if (srcAddress.isInSubnet(entry.ip(), entry.prefixLength())) {
				for (const NetworkAddressEntry& newEntry : entries) {
                                        HostAddress address = newEntry.ip();
                                        if ((address.protocol() == HostAddress::IPv4Protocol && type == A) ||
                                                (address.protocol() == HostAddress::IPv6Protocol && type == AAAA)) {
						record.setName(hostname);
						record.setType(type);
						record.setAddress(address);
						return true;
					}
				}
			}
		}
	}
	return false;
}

void HostNamePrivate::onMessageReceived(const Message& message)
{
	if (message.isResponse()) {
		if (hostnameRegistered) {
			return;
		}
		const auto records = message.records();
		for (const Record& record : records) {
			if ((record.type() == A || record.type() == AAAA) && record.name() == hostname) {
				++hostnameSuffix;
				assertHostname();
			}
		}
	}
	else {
		if (!hostnameRegistered) {
			return;
		}
		Message reply;
		reply.reply(message);
		const auto queries = message.queries();
		for (const Query& query : queries) {
			if ((query.type() == A || query.type() == AAAA) && query.name() == hostname) {
				Record record;
				if (generateRecord(message.address(), query.type(), record)) {
					reply.addRecord(record);
				}
			}
		}
		if (reply.records().count()) {
			server->sendMessage(reply);
		}
	}
}

void HostNamePrivate::onRegistrationTimeout()
{
	hostnameRegistered = true;
	if (hostname != hostnamePrev) {
		emit q->hostnameChanged(hostname);
	}

	// Re-assert the hostname in half an hour
	rebroadcastTimer.start();
}

void HostNamePrivate::onRebroadcastTimeout()
{
	hostnamePrev = hostname;
	hostnameRegistered = false;
	hostnameSuffix = 1;

	assertHostname();
}


ProberPrivate::ProberPrivate(Prober* prober, AbstractServer* server, const Record& record)
	: QObject(prober),
	server(server),
	confirmed(false),
	proposedRecord(record),
	suffix(1),
	q(prober)
{
	// All records should contain at least one "."
	int index = record.name().indexOf('.');
	name = record.name().left(index);
	type = record.name().mid(index);

	connect(server, &AbstractServer::messageReceived, this, &ProberPrivate::onMessageReceived);
	connect(&timer, &QTimer::timeout, this, &ProberPrivate::onTimeout);

	timer.setSingleShot(true);

	assertRecord();
}

ProberPrivate::~ProberPrivate()
{

}


void ProberPrivate::assertRecord()
{
	QString tmpName = suffix == 1
		? QString("%1%2").arg(name, type.constData())
		: QString("%1-%2%3").arg(name.constData(), QByteArray::number(suffix), type);

	proposedRecord.setName(tmpName.toUtf8());

	// Broadcast a query for the proposed name (using an ANY query) and
	// include the proposed record in the query
	Query query;
	query.setName(proposedRecord.name());
	query.setType(ANY);
	Message message;
	message.addQuery(query);
	message.addRecord(proposedRecord);
	server->sendMessageToAll(message);

	// Wait two seconds to confirm it is unique
	timer.stop();
	timer.start(2 * 1000);
}



void ProberPrivate::onMessageReceived(const Message& message)
{
	// If the response matches the proposed record, increment the suffix and
	// try with the new name

	if (confirmed || !message.isResponse()) {
		return;
	}
	const auto records = message.records();
	for (const Record& record : records) {
		if (record.name() == proposedRecord.name() && record.type() == proposedRecord.type()) {
			++suffix;
			assertRecord();
		}
	}
}



Prober::Prober(AbstractServer* server, const Record& record, QObject* parent)
	: QObject(parent),
	d(new ProberPrivate(this, server, record))
{
}



ServicePrivate::ServicePrivate()
{
}

ServicePrivate::~ServicePrivate()
{
}



Service::Service()
	:d(new ServicePrivate)
{

}



Service::Service(const Service& other)
	: d(new ServicePrivate)
{
	*this = other;
}



Service& Service::operator=(const Service& other)
{
	*d = *other.d;
	return *this;
}



bool Service::operator==(const Service& other) const
{
	return d->type == other.d->type &&
		d->name == other.d->name &&
		d->port == other.d->port &&
		d->attributes == other.d->attributes;
}



bool Service::operator!=(const Service& other) const
{
	return !(*this == other);
}



Service::~Service()
{
	delete d;
}

void Service::setAddress(const HostAddress& address)
{
	d->address = address;
}

HostAddress Service::address() const
{
	return d->address;
}

QByteArray Service::type() const
{
	return d->type;
}

void Service::setType(const QByteArray& type)
{
	d->type = type;
}

QByteArray Service::name() const
{
	return d->name;
}

void Service::setName(const QByteArray& name)
{
	d->name = name;
}

QByteArray Service::hostname() const
{
	return d->hostname;
}

void Service::setHostname(const QByteArray& hostname)
{
	d->hostname = hostname;
}

quint16 Service::port() const
{
	return d->port;
}

void Service::setPort(quint16 port)
{
	d->port = port;
}

QMap<QByteArray, QByteArray> Service::attributes() const
{
	return d->attributes;
}

void Service::setAttributes(const QMap<QByteArray, QByteArray>& attributes)
{
	d->attributes = attributes;
}

void Service::addAttribute(const QByteArray& key, const QByteArray& value)
{
	d->attributes.insert(key, value);
}

ProviderPrivate::ProviderPrivate(QObject* parent, AbstractServer* server, HostName* hostname)
	: QObject(parent),
	server(server),
	hostname(hostname),
	prober(nullptr),
	initialized(false),
	confirmed(false)
{
	connect(server, &AbstractServer::messageReceived, this, &ProviderPrivate::onMessageReceived);
	connect(hostname, &HostName::hostnameChanged, this, &ProviderPrivate::onHostnameChanged);

	browsePtrProposed.setName(MdnsBrowseType);
	browsePtrProposed.setType(PTR);
	ptrProposed.setType(PTR);
	srvProposed.setType(SRV);
	txtProposed.setType(TXT);
}


ProviderPrivate::~ProviderPrivate()
{
	if (confirmed) {
		farewell();
	}
}
void ProviderPrivate::announce()
{
	// Broadcast a message with each of the records

	Message message;
	message.setResponse(true);
	message.addRecord(ptrRecord);
	message.addRecord(srvRecord);
	message.addRecord(txtRecord);
	server->sendMessageToAll(message);
}

void ProviderPrivate::confirm()
{
	// Confirm that the desired name is unique through probing

	if (prober) {
		delete prober;
	}
	prober = new Prober(server, srvProposed, this);
	connect(prober, &Prober::nameConfirmed, [this](const QByteArray& name) {

		// If existing records were confirmed, indicate that they are no
		// longer valid
		if (confirmed) {
			farewell();
		}
		else {
			confirmed = true;
		}

		// Update the proposed records
		ptrProposed.setTarget(name);
		srvProposed.setName(name);
		txtProposed.setName(name);

		// Publish the proposed records and announce them
		publish();

		delete prober;
		prober = nullptr;
		});
}

void ProviderPrivate::farewell()
{
	// Send a message indicating that the existing records are no longer valid
	// by setting their TTL to 0

	ptrRecord.setTtl(0);
	srvRecord.setTtl(0);
	txtRecord.setTtl(0);
	announce();
}

void ProviderPrivate::publish()
{
	// Copy the proposed records over and announce them

	browsePtrRecord = browsePtrProposed;
	ptrRecord = ptrProposed;
	srvRecord = srvProposed;
	txtRecord = txtProposed;
	announce();
}

void ProviderPrivate::onMessageReceived(const Message& message)
{
	if (!confirmed || message.isResponse()) {
		return;
	}

	bool sendBrowsePtr = false;
	bool sendPtr = false;
	bool sendSrv = false;
	bool sendTxt = false;

	// Determine which records to send based on the queries
	const QList<Query> queries = message.queries();
	for (const Query& query : queries) {
		if (query.type() == PTR && query.name() == MdnsBrowseType) {
			sendBrowsePtr = true;
		}
		else if (query.type() == PTR && query.name() == ptrRecord.name()) {
			sendPtr = true;
		}
		else if (query.type() == SRV && query.name() == srvRecord.name()) {
			sendSrv = true;
		}
		else if (query.type() == TXT && query.name() == txtRecord.name()) {
			sendTxt = true;
		}
	}

	// Remove records to send if they are already known
	const QList<Record> records = message.records();
	for (const Record& record : records) {
		if (record == ptrRecord) {
			sendPtr = false;
		}
		else if (record == srvRecord) {
			sendSrv = false;
		}
		else if (record == txtRecord) {
			sendTxt = false;
		}
	}

	// Include the SRV and TXT if the PTR is being sent
	if (sendPtr) {
		sendSrv = sendTxt = true;
	}

	// If any records should be sent, compose a message reply
	if (sendBrowsePtr || sendPtr || sendSrv || sendTxt) {
		Message reply;
		reply.reply(message);
		if (sendBrowsePtr) {
			reply.addRecord(browsePtrRecord);
		}
		if (sendPtr) {
			reply.addRecord(ptrRecord);
		}
		if (sendSrv) {
			reply.addRecord(srvRecord);
		}
		if (sendTxt) {
			reply.addRecord(txtRecord);
		}
		server->sendMessage(reply);
	}
}

void ProviderPrivate::onHostnameChanged(const QByteArray& newHostname)
{
	// Update the proposed SRV record
	srvProposed.setTarget(newHostname);

	// If initialized, confirm the record
	if (initialized) {
		confirm();
	}
}

Provider::Provider(AbstractServer* server, HostName* hostname, QObject* parent)
	: QObject(parent),
	d(new ProviderPrivate(this, server, hostname))
{
}

void Provider::update(const Service& service)
{
	d->initialized = true;

	// Clean the service name
	QByteArray serviceName = service.name();
	serviceName = serviceName.replace('.', '-');
	// Update the proposed records
	QByteArray fqName = serviceName + "." + service.type();
	d->browsePtrProposed.setTarget(service.type());
	d->ptrProposed.setName(service.type());
	d->ptrProposed.setTarget(fqName);
	d->srvProposed.setName(fqName);
	d->srvProposed.setPort(service.port());
	d->srvProposed.setTarget(d->hostname->hostname());
	d->txtProposed.setName(fqName);
	d->txtProposed.setAttributes(service.attributes());
	// Assuming a valid hostname exists, check to see if the new service uses
	// a different name - if so, it must first be confirmed
	if (d->hostname->isRegistered()) {
		if (!d->confirmed || fqName != d->srvRecord.name()) {
			d->confirm();
		}
		else {
			d->publish();
		}
	}
}




ResolverPrivate::ResolverPrivate(Resolver* resolver, AbstractServer* server, const QByteArray& name, Cache* cache)
	: QObject(resolver)
	, server(server)
	, name(name)
	, cache(cache ? cache : new Cache(this))
	, q(resolver)
{
	connect(server, &AbstractServer::messageReceived, this, &ResolverPrivate::onMessageReceived);
	connect(&timer, &QTimer::timeout, this, &ResolverPrivate::onTimeout);

	// Query for new records
	query();

	// Pull the existing records from the cache
	timer.setSingleShot(true);
	timer.start(0);
}

ResolverPrivate::~ResolverPrivate()
{
}

QList<Record> ResolverPrivate::existing() const
{
	QList<Record> records;
	cache->lookupRecords(name, A, records);
	cache->lookupRecords(name, AAAA, records);
	return records;
}



void ResolverPrivate::query() const
{
	Message message;

	// Add a query for A and AAAA records
	Query query;
	query.setName(name);
	query.setType(A);
	message.addQuery(query);
	query.setType(AAAA);
	message.addQuery(query);

	// Add existing (known) records to the query
	const auto records = existing();
	for (const Record& record : records) {
		message.addRecord(record);
	}

	// Send the query
	server->sendMessageToAll(message);
}



void ResolverPrivate::onMessageReceived(const Message& message)
{
	if (!message.isResponse()) {
		return;
	}
	const auto records = message.records();
	for (const Record& record : records) {
		if (record.name() == name && (record.type() == A || record.type() == AAAA)) {
			cache->addRecord(record);
			if (!addresses.contains(record.address())) {
				emit q->resolved(record.address());
				addresses.insert(record.address());
			}
		}
	}
}



Cache::Cache(QObject* parent)
	:d(new CachePrivate(this))
{

}



Resolver::Resolver(AbstractServer* server, const QByteArray& name, Cache* cache, QObject* parent)
	: QObject(parent),
	d(new ResolverPrivate(this, server, name, cache))
{

}


DnsServerPrivate::DnsServerPrivate(DnsServer* server)
	: QObject(server)
	, q(server)
	, operations(new CoroutineGroup)
{
	connect(&timer, &QTimer::timeout, this, &DnsServerPrivate::onTimeout);
	ipv4Socket.reset(new Socket(HostAddress::IPv4Protocol, Socket::UdpSocket));
	ipv6Socket.reset(new Socket(HostAddress::IPv6Protocol, Socket::UdpSocket));

	timer.setInterval(5 * 1000);
	timer.setSingleShot(true);
	onTimeout();
}

DnsServerPrivate::~DnsServerPrivate()
{
	delete operations;
}

bool DnsServerPrivate::bindSocket(QSharedPointer<Socket>& socket, const HostAddress& address)
{
	socket->setOption(Socket::AddressReusable, 2);
	socket->setOption(Socket::MulticastTtlOption, 255);
	if (socket->state() == Socket::BoundState) {
		return  true;
	}
	if (!socket->bind(address, MdnsPort, Socket::ReuseAddressHint)) {
		qDebug() << socket->errorString();
		emit q->error(socket->errorString());
		return false;
	}
	operations->spawn([this, &socket]() {
		onReadyRead(socket);
		});
	return true;
}

void DnsServerPrivate::onTimeout()
{
	// A timer is used to run a set of operations once per minute; first, the
	// two sockets are bound - if this fails, another attempt is made once per
	// timeout; secondly, all network interfaces are enumerated; if the
	// interface supports multicast, the socket will join the mDNS multicast
	// groups

        bool ipv4Bound = bindSocket(ipv4Socket, HostAddress::AnyIPv4);
        bool ipv6Bound = bindSocket(ipv6Socket, HostAddress::AnyIPv6);

	if (ipv4Bound || ipv6Bound) {
		const auto interfaces = NetworkInterface::allInterfaces();
		for (const NetworkInterface& networkInterface : interfaces) {
			if (networkInterface.flags() & NetworkInterface::CanMulticast) {
				if (ipv4Bound) {
					ipv4Socket->joinMulticastGroup(MdnsIpv4Address, networkInterface);
				}
				if (ipv6Bound) {
					ipv6Socket->joinMulticastGroup(MdnsIpv6Address, networkInterface);
				}
			}
		}
	}
	timer.start();
}


void DnsServerPrivate::onReadyRead(QSharedPointer<Socket>& socket)
{
	while (1) {
		HostAddress addr;
		quint16 port;
		QByteArray packet = socket->recvfrom(1024 * 10, &addr, &port);
		Message message;
		if (fromPacket(packet, message)) {
			message.setAddress(addr);
			message.setPort(port);
			emit q->messageReceived(message);
		}
	}
}

DnsServer::DnsServer(QObject* parent)
	: AbstractServer(parent)
	, d(new DnsServerPrivate(this))
{

}

void DnsServer::sendMessage(const Message& message)
{
	QByteArray packet;
	toPacket(message, packet);
        if (message.address().protocol() == HostAddress::IPv4Protocol) {
		d->ipv4Socket->sendto(packet, message.address(), message.port());
	}
	else {
		d->ipv6Socket->sendto(packet, message.address(), message.port());
	}
}

void DnsServer::sendMessageToAll(const Message& message)
{
	QByteArray packet;
	toPacket(message, packet);
	d->ipv4Socket->sendto(packet, MdnsIpv4Address, MdnsPort);
	d->ipv6Socket->sendto(packet, MdnsIpv6Address, MdnsPort);
}


BrowserPrivate::BrowserPrivate(Browser* browser, AbstractServer* server, const QByteArray& type, Cache* existingCache)
	: QObject(browser)
	, server(server)
	, type(type)
	, cache(existingCache ? existingCache : new Cache(this))
	, q(browser)
	, operations(new CoroutineGroup)
{
	connect(server, &AbstractServer::messageReceived, this, &BrowserPrivate::onMessageReceived);
	connect(cache, &Cache::shouldQuery, this, &BrowserPrivate::onShouldQuery);
	connect(cache, &Cache::recordExpired, this, &BrowserPrivate::onRecordExpired);
	connect(&queryTimer, &QTimer::timeout, this, &BrowserPrivate::onQueryTimeout);
	connect(&serviceTimer, &QTimer::timeout, this, &BrowserPrivate::onServiceTimeout);

	queryTimer.setInterval(60 * 1000);
	queryTimer.setSingleShot(true);

	serviceTimer.setInterval(100);
	serviceTimer.setSingleShot(true);

	// Immediately begin browsing for services
	onQueryTimeout();
}

BrowserPrivate::~BrowserPrivate()
{
	delete operations;
}

void BrowserPrivate::onMessageReceived(const Message& message)
{
	if (!message.isResponse()) {
		return;
	}
	mes = message;
	const bool any = type == MdnsBrowseType;

	// Use a set to track all services that are updated in the message to
	// prevent unnecessary queries for SRV and TXT records
	QSet<QByteArray> updateNames;
	const auto records = message.records();
	for (const Record& record : records) {
		bool cacheRecord = false;

		switch (record.type()) {
		case PTR:
			if (any && record.name() == MdnsBrowseType) {
				ptrTargets.insert(record.target());
				serviceTimer.start();
				cacheRecord = true;
			}
			else if (any || record.name() == type) {
				updateNames.insert(record.target());
				cacheRecord = true;
			}
			break;
		case SRV:
		case TXT:
			if (any || record.name().endsWith("." + type)) {
				updateNames.insert(record.name());
				cacheRecord = true;
			}
			break;
		}
		if (cacheRecord) {
			cache->addRecord(record);
		}
	}

	// For each of the services marked to be updated, perform the update and
	// make a list of all missing SRV records
	QSet<QByteArray> queryNames;
#if (QT_VERSION >= QT_VERSION_CHECK(6, 6, 0))
	for (const QByteArray& name : std::as_const(updateNames)) {
#else
	for (const QByteArray& name : qAsConst(updateNames)) {
#endif
		if (updateService(name)) {
			queryNames.insert(name);
		}
	}

	// Cache A / AAAA records after services are processed to ensure hostnames are known
	for (const Record& record : records) {
		bool cacheRecord = false;

		switch (record.type()) {
		case A:
		case AAAA:
			cacheRecord = hostnames.contains(record.name());
			break;
		}
		if (cacheRecord) {
			cache->addRecord(record);
		}
	}

	// Build and send a query for all of the SRV and TXT records
	if (queryNames.count()) {
		Message queryMessage;
#if (QT_VERSION >= QT_VERSION_CHECK(6, 6, 0))
		for (const QByteArray& name : std::as_const(queryNames)) {
#else
		for (const QByteArray& name : qAsConst(queryNames)) {
#endif
			Query query;
			query.setName(name);
			query.setType(SRV);
			queryMessage.addQuery(query);
			query.setType(TXT);
			queryMessage.addQuery(query);
		}
		server->sendMessageToAll(queryMessage);
	}
}



void BrowserPrivate::onShouldQuery(const Record & record)
{
	Query query;
	query.setName(record.name());
	query.setType(record.type());
	Message message;
	message.addQuery(query);
	server->sendMessageToAll(message);
}



void BrowserPrivate::onRecordExpired(const Record & record)
{
	QByteArray serviceName;
	switch (record.type()) {
	case SRV:
		serviceName = record.name();
		break;
	case TXT:
		updateService(record.name());
		return;
	default:
		return;
	}
	Service service = services.value(serviceName);
	if (!service.name().isNull()) {
		emit q->serviceRemoved(service);
		services.remove(serviceName);
		updateHostnames();
	}
}


bool BrowserPrivate::updateService(const QByteArray & fqName)
{
	int index = fqName.indexOf('.');
	QByteArray serviceName = fqName.left(index);
	QByteArray serviceType = fqName.mid(index + 1);
	Record ptrRecord;
	if (!cache->lookupRecord(serviceType, PTR, ptrRecord)) {
		return false;
	}
	Record srvRecord;
	if (!cache->lookupRecord(fqName, SRV, srvRecord)) {
		return true;
	}
	Service service;
	service.setName(serviceName);
	service.setType(serviceType);
	service.setHostname(srvRecord.target());
	service.setPort(srvRecord.port());
	service.setAddress(mes.address());
	QList<Record> txtRecords;
	if (cache->lookupRecords(fqName, TXT, txtRecords)) {
		QMap<QByteArray, QByteArray> attributes;
		for (const Record& record : qAsConst(txtRecords)) {
			for (auto i = record.attributes().constBegin();
				i != record.attributes().constEnd();++i) {
				attributes.insert(i.key(), i.value());
			}
		}
		service.setAttributes(attributes);
	}
	if (!services.contains(fqName)) {
		emit q->serviceAdded(service);
	}
	else if (services.value(fqName) != service) {
		emit q->serviceUpdated(service);
	}
	services.insert(fqName, service);
	hostnames.insert(service.hostname());
	return false;
}

void BrowserPrivate::sendQueryAll()
{
	Query query;
	query.setName(type);
	query.setType(PTR);
	Message message;
	message.addQuery(query);

	// TODO: including too many records could cause problems

	// Include PTR records for the target that are already known
	QList<Record> records;
	if (cache->lookupRecords(query.name(), PTR, records)) {
#if (QT_VERSION >= QT_VERSION_CHECK(6, 6, 0))
		for (const Record& record : std::as_const(records)) {
#else
		for (const Record& record : qAsConst(records)) {
#endif
			message.addRecord(record);
		}
	}

	server->sendMessageToAll(message);
}

void BrowserPrivate::updateHostnames()
{
	hostnames.clear();
	for (const auto& service : services) {
		hostnames.insert(service.hostname());
	}
}

Browser::Browser(AbstractServer * server, const QByteArray & type, Cache * cache, QObject * parent)
	: QObject(parent)
	, d(new BrowserPrivate(this, server, type, cache))
{

}

QMap<QByteArray, Service> Browser::getServices()
{
	return d->services;
}

void Browser::sendQueryAll()
{
	d->sendQueryAll();
}

void CachePrivate::onTimeout()
{
	QDateTime now = QDateTime::currentDateTime();
	QDateTime newNextTrigger;

	for (auto i = entries.begin(); i != entries.end();) {

		// Loop through the triggers and remove ones that have already
		// passed
		bool shouldQuery = false;
		for (auto j = i->triggers.begin(); j != i->triggers.end();) {
			if ((*j) <= now) {
				shouldQuery = true;
				j = i->triggers.erase(j);
			}
			else {
				break;
			}
		}

		// If triggers remain, determine the next earliest one; if none
		// remain, the record has expired and should be removed
		if (i->triggers.length()) {
			if (newNextTrigger.isNull() || i->triggers.at(0) < newNextTrigger) {
				newNextTrigger = i->triggers.at(0);
			}
			if (shouldQuery) {
				emit q->shouldQuery(i->record);
			}
			++i;
		}
		else {
			emit q->recordExpired(i->record);
			i = entries.erase(i);
		}
	}

	// If newNextTrigger contains a value, it will be the time for the next
	// trigger and the timer should be started again
	nextTrigger = newNextTrigger;
	if (!nextTrigger.isNull()) {
		timer.start(now.msecsTo(nextTrigger));
	}
}



void ProberPrivate::onTimeout()
{
	confirmed = true;
	emit q->nameConfirmed(proposedRecord.name());
}



void ResolverPrivate::onTimeout()
{
	const auto records = existing();
	for (const Record& record : records) {
		emit q->resolved(record.address());
	}
}



void BrowserPrivate::onQueryTimeout()
{
	sendQueryAll();
	queryTimer.start();
}



void BrowserPrivate::onServiceTimeout()
{
	if (ptrTargets.count()) {
		Message message;
#if (QT_VERSION >= QT_VERSION_CHECK(6, 6, 0))
		for (const QByteArray& target : std::as_const(ptrTargets)) {
#else
		for (const QByteArray& target : qAsConst(ptrTargets)) {
#endif \
    // Add a query for PTR records
			Query query;
			query.setName(target);
			query.setType(PTR);
			message.addQuery(query);

			// Include PTR records for the target that are already known
			QList<Record> records;
			if (cache->lookupRecords(target, PTR, records)) {
#if (QT_VERSION >= QT_VERSION_CHECK(6, 6, 0))
				for (const Record& record : std::as_const(records)) {
#else
				for (const Record& record : qAsConst(records)) {
#endif
					message.addRecord(record);
				}
			}
		}

		server->sendMessageToAll(message);
		ptrTargets.clear();
	}
}
QTNETWORKNG_NAMESPACE_END
