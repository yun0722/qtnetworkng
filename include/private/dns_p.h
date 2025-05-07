#ifndef DNS_P_H
#define DNS_P_H
#include "include/dns.h"

QTNETWORKNG_NAMESPACE_BEGIN
const quint16 MdnsPort = 5353;
const HostAddress MdnsIpv4Address("224.0.0.251");
const HostAddress MdnsIpv6Address("ff02::fb");
const QByteArray MdnsBrowseType("_services._dns-sd._udp.local.");
class BitMapPrivate {
public:
	BitMapPrivate();
	virtual ~BitMapPrivate();

	void free();
	void fromData(quint8 newLength, const quint8* newData);

	quint8 length;
	quint8* data;
};

class QueryPrivate {
public:
	QueryPrivate();
	virtual ~QueryPrivate();
	QByteArray name;
	quint16 type;
	bool unicastResponse;
};
class RecordPrivate {
public:
	RecordPrivate();
	virtual ~RecordPrivate();
	QByteArray name;
	quint16 type;
	bool flushCache;
	quint32 ttl;

	HostAddress address;
	QByteArray target;
	QByteArray nextDomainName;
	quint16 priority;
	quint16 weight;
	quint16 port;
	QMap<QByteArray, QByteArray> attributes;
	BitMap bitmap;
};


class MessagePrivate
{
public:

	MessagePrivate();
	~MessagePrivate();
	void reply(const Message& other);
	HostAddress address;
	quint16 port;
	quint16 transactionId;
	bool isResponse;
	bool isTruncated;
	QList<Query> queries;
	QList<Record> records;
};
QTNETWORKNG_NAMESPACE_END
#endif // DNS_P_H
