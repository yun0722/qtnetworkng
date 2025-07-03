#ifndef DNS_H
#define DNS_H
#include <QtCore>
#include "hostaddress.h"
QTNETWORKNG_NAMESPACE_BEGIN
class BitMapPrivate;
class BitMap {
public:
	BitMap();
	BitMap(const BitMap& other);
	BitMap& operator=(const BitMap& other);
	bool operator==(const BitMap& other);
	virtual ~BitMap();
	quint8 length() const;
	const quint8* data() const;
	void setData(quint8 length, const quint8* data);
private:
	BitMapPrivate* d;
};

class QueryPrivate;
class Query {
public:
	Query();
	Query(const Query& other);
	Query& operator =(const Query& other);
	virtual ~Query();
	QByteArray name() const;
	void setName(const QByteArray& name);
	quint16 type() const;
	void setType(quint16 type);
	bool uincastRespone() const;
	void setUnicastRespone(bool unicastResponse);
private:
	QueryPrivate* const d;
};
class RecordPrivate;
class  Record
{
public:
	Record();
	Record(const Record& other);
	Record& operator=(const Record& other);
	bool operator==(const Record& other) const;
	bool operator!=(const Record& other) const;
	virtual ~Record();
	QByteArray name() const;
	void setName(const QByteArray& name);
	quint16 type() const;
	void setType(quint16 type);
	bool flushCache() const;
	void setFlushCache(bool flushCache);
	quint32 ttl() const;
	void setTtl(quint32 ttl);
	HostAddress address() const;
	void setAddress(const HostAddress& address);
	QByteArray target() const;
	void setTarget(const QByteArray& target);
	QByteArray nextDomainName() const;
	void setNextDomainName(const QByteArray& nextDomainName);
	quint16 priority() const;
	void setPriority(quint16 priority);
	quint16 weight() const;
	void setWeight(quint16 weight);
	quint16 port() const;
	void setPort(quint16 port);
	QMap<QByteArray, QByteArray> attributes() const;
	void setAttributes(const QMap<QByteArray, QByteArray>& attributes);
	void addAttribute(const QByteArray& key, const QByteArray& value);
	BitMap bitmap() const;
	void setBitmap(const BitMap& bitmap);
private:
	RecordPrivate* const d;
};
class MessagePrivate;
class Message {
public:
	Message();
	Message(const Message& other);
	Message& operator=(const Message& other);
        virtual ~Message();
        HostAddress address() const;
        void setAddress(const HostAddress& address);
	quint16 port() const;
	void setPort(quint16 port);
	quint16 transactionId() const;
	void setTransactionId(quint16 transactionId);
	bool isResponse() const;
	void setResponse(bool isResponse);
	bool isTruncated() const;
	void setTruncated(bool isTruncated);
	QList<Query> queries() const;
	void addQuery(const Query& query);
	QList<Record> records() const;
	void addRecord(const Record& record);
	void reply(const Message& other);

private:

	MessagePrivate* const d;
};
enum {
	/// IPv4 address record
	A = 1,
	/// IPv6 address record
	AAAA = 28,
	/// Wildcard for cache lookups
	ANY = 255,
	/// List of records
	NSEC = 47,
	/// Pointer to hostname
	PTR = 12,
	/// %Service information
	SRV = 33,
	/// Arbitrary metadata
	TXT = 16
};
QDebug operator<<(QDebug dbg, const Query& query);
QDebug operator<<(QDebug dbg, const Record& record);
bool parseName(const QByteArray& packet, quint16& offset, QByteArray& name);
void writeName(QByteArray& packet, quint16& offset, const QByteArray& name, QMap<QByteArray, quint16>& nameMap);
bool parseRecord(const QByteArray& packet, quint16& offset, Record& record);
void writeRecord(QByteArray& packet, quint16& offset, Record& record, QMap<QByteArray, quint16>& nameMap);
bool fromPacket(const QByteArray& packet, Message& message);
void toPacket(const Message& message, QByteArray& packet);
QString typeName(quint16 type);
QTNETWORKNG_NAMESPACE_END
#endif // DNS_H
