#include "include/dns.h"
#include "include/private/dns_p.h"
QTNETWORKNG_NAMESPACE_BEGIN
QueryPrivate::QueryPrivate()
	:type(0)
	, unicastResponse(false)
{

}

QueryPrivate::~QueryPrivate()
{

}
Query::Query()
	:d(new QueryPrivate)
{

}

Query::Query(const Query& other)
	: d(new QueryPrivate)
{
	*this = other;
}

Query& Query::operator =(const Query& other)
{
	*d = *other.d;
	return *this;
}



Query::~Query()
{
	delete d;
}



QByteArray Query::name() const
{
	return d->name;
}



void Query::setName(const QByteArray& name)
{
	d->name = name;
}



quint16 Query::type() const
{
	return d->type;
}



void Query::setType(quint16 type)
{
	d->type = type;
}

bool Query::uincastRespone() const
{
	return d->unicastResponse;
}

void Query::setUnicastRespone(bool unicastResponse)
{
	d->unicastResponse = unicastResponse;
}



BitMap::BitMap()
	:d(new BitMapPrivate)
{

}

BitMap::BitMap(const BitMap& other)
	: d(new BitMapPrivate)
{
	d->fromData(other.d->length, other.d->data);
}

BitMap& BitMap::operator=(const BitMap& other)
{
	d->free();
	d->fromData(other.d->length, other.d->data);
	return *this;
}

bool BitMap::operator==(const BitMap& other)
{
	if (d->length != other.d->length) {
		return false;
	}
	for (int i = 0; i < d->length; ++i) {
		if (d->data[i] != other.d->data[i]) {
			return false;
		}
	}
	return true;
}

BitMap::~BitMap()
{
	delete d;
}

quint8 BitMap::length() const
{
	return d->length;
}

const quint8* BitMap::data() const
{
	return d->data;
}

void BitMap::setData(quint8 length, const quint8* data)
{
	d->fromData(length, data);
}

BitMapPrivate::BitMapPrivate()
	: length(0),
	data(nullptr)
{

}

BitMapPrivate::~BitMapPrivate()
{
	free();
}

void BitMapPrivate::free()
{
	if (data) {
		delete[] data;
	}
}

void BitMapPrivate::fromData(quint8 newLength, const quint8* newData)
{
	data = new quint8[newLength];
	for (int i = 0; i < newLength; ++i) {
		data[i] = newData[i];
	}
	length = newLength;
}


RecordPrivate::RecordPrivate()
	: type(0),
	flushCache(false),
	ttl(3600),
	priority(0),
	weight(0),
	port(0)
{

}

RecordPrivate::~RecordPrivate()
{

}



Record::Record()
	: d(new RecordPrivate)
{

}



Record::~Record()
{
	delete d;
}



Record::Record(const Record& other)
	: d(new RecordPrivate)
{
	*this = other;
}



Record& Record::operator=(const Record& other)
{
	*d = *other.d;
	return *this;
}



bool Record::operator==(const Record& other) const
{
	return d->name == other.d->name &&
		d->type == other.d->type &&
		d->address == other.d->address &&
		d->target == other.d->target &&
		d->nextDomainName == other.d->nextDomainName &&
		d->priority == other.d->priority &&
		d->weight == other.d->weight &&
		d->port == other.d->port &&
		d->attributes == other.d->attributes &&
		d->bitmap == other.d->bitmap;
}

QByteArray Record::name() const
{
	return d->name;
}

void Record::setName(const QByteArray& name)
{
	d->name = name;
}

quint16 Record::type() const
{
	return d->type;
}

void Record::setType(quint16 type)
{
	d->type = type;
}

bool Record::flushCache() const
{
	return d->flushCache;
}

void Record::setFlushCache(bool flushCache)
{
	d->flushCache = flushCache;
}

quint32 Record::ttl() const
{
	return d->ttl;
}

void Record::setTtl(quint32 ttl)
{
	d->ttl = ttl;
}

HostAddress Record::address() const
{
	return d->address;
}

void Record::setAddress(const HostAddress& address)
{
	d->address = address;
}

QByteArray Record::target() const
{
	return d->target;
}

void Record::setTarget(const QByteArray& target)
{
	d->target = target;
}

QByteArray Record::nextDomainName() const
{
	return d->nextDomainName;
}

void Record::setNextDomainName(const QByteArray& nextDomainName)
{
	d->nextDomainName = nextDomainName;
}

quint16 Record::priority() const
{
	return d->priority;
}

void Record::setPriority(quint16 priority)
{
	d->priority = priority;
}

quint16 Record::weight() const
{
	return d->weight;
}

void Record::setWeight(quint16 weight)
{
	d->weight = weight;
}

quint16 Record::port() const
{
	return d->port;
}

void Record::setPort(quint16 port)
{
	d->port = port;
}

QMap<QByteArray, QByteArray> Record::attributes() const
{
	return d->attributes;
}

void Record::setAttributes(const QMap<QByteArray, QByteArray>& attributes)
{
	d->attributes = attributes;
}

void Record::addAttribute(const QByteArray& key, const QByteArray& value)
{
	d->attributes.insert(key, value);
}

BitMap Record::bitmap() const
{
	return d->bitmap;
}

void Record::setBitmap(const BitMap& bitmap)
{
	d->bitmap = bitmap;
}


bool Record::operator!=(const Record& other) const
{
	return !(operator==(other));
}



MessagePrivate::MessagePrivate()
	: port(0),
	transactionId(0),
	isResponse(false),
	isTruncated(false)
{
}


MessagePrivate::~MessagePrivate()
{

}

void MessagePrivate::reply(const Message& other)
{
	if (other.port() == MdnsPort) {
                if (other.address().protocol() == HostAddress::IPv4Protocol) {
			address = MdnsIpv4Address;
		}
		else {
			address = MdnsIpv6Address;
		}
	}
	else {
		address = other.address();
	}
	port = other.port();
	transactionId = other.transactionId();
	isResponse = true;
}

Message::Message()
	: d(new MessagePrivate)
{
}

Message::Message(const Message& other)
	: d(new MessagePrivate)
{
	*this = other;
}

Message& Message::operator=(const Message& other)
{
	*d = *other.d;
	return *this;
}

Message::~Message()
{
	delete d;
}

HostAddress Message::address() const
{
	return d->address;
}

void Message::setAddress(const HostAddress &address)
{
	d->address = address;
}

quint16 Message::port() const
{
	return d->port;
}

void Message::setPort(quint16 port)
{
	d->port = port;
}

quint16 Message::transactionId() const
{
	return d->transactionId;
}

void Message::setTransactionId(quint16 transactionId)
{
	d->transactionId = transactionId;
}

bool Message::isResponse() const
{
	return d->isResponse;
}

void Message::setResponse(bool isResponse)
{
	d->isResponse = isResponse;
}

bool Message::isTruncated() const
{
	return d->isTruncated;
}

void Message::setTruncated(bool isTruncated)
{
	d->isTruncated = isTruncated;
}

QList<Query> Message::queries() const
{
	return d->queries;
}

void Message::addQuery(const Query& query)
{
	d->queries.append(query);
}

QList<Record> Message::records() const
{
	return d->records;
}

void Message::addRecord(const Record& record)
{
	d->records.append(record);
}

void Message::reply(const Message& other)
{
	d->reply(other);
}

template<class T>
bool parseInteger(const QByteArray& packet, quint16& offset, T& value)
{
	if (offset + sizeof(T) > static_cast<unsigned int>(packet.length())) {
		return false;  // out-of-bounds
	}
	value = qFromBigEndian<T>(reinterpret_cast<const uchar*>(packet.constData() + offset));
	offset += sizeof(T);
	return true;
}

template<class T>
void writeInteger(QByteArray& packet, quint16& offset, T value)
{
	value = qToBigEndian<T>(value);
	packet.append(reinterpret_cast<const char*>(&value), sizeof(T));
	offset += sizeof(T);
}

bool parseName(const QByteArray& packet, quint16& offset, QByteArray& name)
{
	quint16 offsetEnd = 0;
	quint16 offsetPtr = offset;
	forever{
		quint8 nBytes;
		if (!parseInteger<quint8>(packet, offset, nBytes)) {
			return false;
		}
		if (!nBytes) {
			break;
		}
		switch (nBytes & 0xc0) {
		case 0x00:
			if (offset + nBytes > packet.length()) {
				return false;  // length exceeds message
			}
			name.append(packet.mid(offset, nBytes));
			name.append('.');
			offset += nBytes;
			break;
		case 0xc0:
		{
			quint8 nBytes2;
			quint16 newOffset;
			if (!parseInteger<quint8>(packet, offset, nBytes2)) {
				return false;
			}
			newOffset = ((nBytes & ~0xc0) << 8) | nBytes2;
			if (newOffset >= offsetPtr) {
				return false;  // prevent infinite loop
			}
			offsetPtr = newOffset;
			if (!offsetEnd) {
				offsetEnd = offset;
			}
			offset = newOffset;
			break;
		}
		default:
			return false;  // no other types supported
		}
	}
		if (offsetEnd) {
			offset = offsetEnd;
		}
	return true;
}

void writeName(QByteArray& packet, quint16& offset, const QByteArray& name, QMap<QByteArray, quint16>& nameMap)
{
	QByteArray fragment = name;
	if (fragment.endsWith('.')) {
		fragment.chop(1);
	}
	while (fragment.length()) {
		if (nameMap.contains(fragment)) {
			writeInteger<quint16>(packet, offset, nameMap.value(fragment) | 0xc000);
			return;
		}
		nameMap.insert(fragment, offset);
		int index = fragment.indexOf('.');
		if (index == -1) {
			index = fragment.length();
		}
		writeInteger<quint8>(packet, offset, index);
		packet.append(fragment.left(index));
		offset += index;
		fragment.remove(0, index + 1);
	}
	writeInteger<quint8>(packet, offset, 0);
}

bool parseRecord(const QByteArray& packet, quint16& offset, Record& record)
{
	QByteArray name;
	quint16 type, class_, dataLen;
	quint32 ttl;
	if (!parseName(packet, offset, name) ||
		!parseInteger<quint16>(packet, offset, type) ||
		!parseInteger<quint16>(packet, offset, class_) ||
		!parseInteger<quint32>(packet, offset, ttl) ||
		!parseInteger<quint16>(packet, offset, dataLen)) {
		return false;
	}
	record.setName(name);
	record.setType(type);
	record.setFlushCache(class_ & 0x8000);
	record.setTtl(ttl);
	switch (type) {
	case A:
	{
		quint32 ipv4Addr;
		if (!parseInteger<quint32>(packet, offset, ipv4Addr)) {
			return false;
		}
                record.setAddress(HostAddress(ipv4Addr));
		break;
	}
	case AAAA:
	{
		if (offset + 16 > packet.length()) {
			return false;
		}
                record.setAddress(HostAddress(
			reinterpret_cast<const quint8*>(packet.constData() + offset)
		));
		offset += 16;
		break;
	}
	case NSEC:
	{
		QByteArray nextDomainName;
		quint8 number;
		quint8 length;
		if (!parseName(packet, offset, nextDomainName) ||
			!parseInteger<quint8>(packet, offset, number) ||
			!parseInteger<quint8>(packet, offset, length) ||
			number != 0 ||
			offset + length > packet.length()) {
			return false;
		}
		BitMap bitmap;
		bitmap.setData(length, reinterpret_cast<const quint8*>(packet.constData() + offset));
		record.setNextDomainName(nextDomainName);
		record.setBitmap(bitmap);
		offset += length;
		break;
	}
	case PTR:
	{
		QByteArray target;
		if (!parseName(packet, offset, target)) {
			return false;
		}
		record.setTarget(target);
		break;
	}
	case SRV:
	{
		quint16 priority, weight, port;
		QByteArray target;
		if (!parseInteger<quint16>(packet, offset, priority) ||
			!parseInteger<quint16>(packet, offset, weight) ||
			!parseInteger<quint16>(packet, offset, port) ||
			!parseName(packet, offset, target)) {
			return false;
		}
		record.setPriority(priority);
		record.setWeight(weight);
		record.setPort(port);
		record.setTarget(target);
		break;
	}
	case TXT:
	{
		quint16 start = offset;
		while (offset < start + dataLen) {
			quint8 nBytes;
			if (!parseInteger<quint8>(packet, offset, nBytes) ||
				offset + nBytes > packet.length()) {
				return false;
			}
			if (nBytes == 0) {
				break;
			}
			QByteArray attr(packet.constData() + offset, nBytes);
			offset += nBytes;
			int splitIndex = attr.indexOf('=');
			if (splitIndex == -1) {
				record.addAttribute(attr, QByteArray());
			}
			else {
				record.addAttribute(attr.left(splitIndex), attr.mid(splitIndex + 1));
			}
		}
		break;
	}
	default:
		offset += dataLen;
		break;
	}
	return true;
}

void writeRecord(QByteArray& packet, quint16& offset, Record& record, QMap<QByteArray, quint16>& nameMap)
{
    // 写入记录头部
    writeName(packet, offset, record.name(), nameMap);
    writeInteger<quint16>(packet, offset, record.type());
    writeInteger<quint16>(packet, offset, record.flushCache() ? 0x8001 : 1);
    writeInteger<quint32>(packet, offset, record.ttl());

            // 记录长度字段位置，并写入两字节占位（0）
    quint16 lengthPos = offset;
    writeInteger<quint16>(packet, offset, 0); // 占位，增加 offset 和 packet 大小

            // 构造 RDATA 部分到临时缓冲区
    QByteArray data;
    quint16 dataOffset = 0;

    switch (record.type()) {
    case A: {
        quint32 ipv4 = record.address().toIPv4Address();
        writeInteger<quint32>(data, dataOffset, ipv4);
        break;
    }
    case AAAA: {
        IPv6Address ipv6 = record.address().toIPv6Address();  // 假设返回 Q_IPV6ADDR
        // 如果 toIPv6Address 返回主机字节序，需要转换
        for (int i = 0; i < 16; ++i) {
            data.append(ipv6[i]);  // 直接追加，假设已经是网络序
        }
        break;
    }
    case NSEC: {
        QByteArray nextNameData;
        quint16 nextNameOffset = 0;
        writeName(nextNameData, nextNameOffset, record.nextDomainName(), nameMap);
        data.append(nextNameData);
        data.append(char(0)); // 窗口块，固定0
        data.append(char(record.bitmap().length()));
        data.append(reinterpret_cast<const char*>(record.bitmap().data()), record.bitmap().length());
        break;
    }
    case PTR: {
        QByteArray targetData;
        quint16 targetOffset = 0;
        writeName(targetData, targetOffset, record.target(), nameMap);
        data.append(targetData);
        break;
    }
    case SRV: {
        quint16 priority = qToBigEndian(record.priority());
        quint16 weight = qToBigEndian(record.weight());
        quint16 port = qToBigEndian(record.port());
        data.append(reinterpret_cast<const char*>(&priority), 2);
        data.append(reinterpret_cast<const char*>(&weight), 2);
        data.append(reinterpret_cast<const char*>(&port), 2);
        QByteArray targetData;
        quint16 targetOffset = 0;
        writeName(targetData, targetOffset, record.target(), nameMap);
        data.append(targetData);
        break;
    }
    case TXT: {
        const auto& attrs = record.attributes();
        for (auto it = attrs.begin(); it != attrs.end(); ++it) {
            QByteArray entry = it.key();
            if (!it.value().isNull())
                entry += "=" + it.value();
            data.append(char(entry.size()));
            data.append(entry);
        }
        if (attrs.isEmpty()) {
            data.append(char(0)); // 空 TXT 记录
        }
        break;
    }
    default:
        // 未知类型，无数据
        break;
    }

            // 将实际 RDATA 长度写回之前占位的长度字段（大端序）—— 直接修改 packet 中对应位置
    quint16 dataLen = data.size();
    quint16 dataLenNet = qToBigEndian<quint16>(dataLen);
    memcpy(packet.data() + lengthPos, &dataLenNet, 2);

            // 追加 RDATA 到报文末尾
    packet.append(data);
    // 更新外部偏移量到报文末尾
    offset = packet.size();
}

bool fromPacket(const QByteArray& packet, Message& message)
{
	quint16 offset = 0;
	quint16 transactionId, flags, nQuestion, nAnswer, nAuthority, nAdditional;
	if (!parseInteger<quint16>(packet, offset, transactionId) ||
		!parseInteger<quint16>(packet, offset, flags) ||
		!parseInteger<quint16>(packet, offset, nQuestion) ||
		!parseInteger<quint16>(packet, offset, nAnswer) ||
		!parseInteger<quint16>(packet, offset, nAuthority) ||
		!parseInteger<quint16>(packet, offset, nAdditional)) {
		return false;
	}
	message.setTransactionId(transactionId);
	message.setResponse(flags & 0x8400);
	message.setTruncated(flags & 0x0200);
	for (int i = 0; i < nQuestion; ++i) {
		QByteArray name;
		quint16 type, class_;
		if (!parseName(packet, offset, name) ||
			!parseInteger<quint16>(packet, offset, type) ||
			!parseInteger<quint16>(packet, offset, class_)) {
			return false;
		}
		Query query;
		query.setName(name);
		query.setType(type);
		query.setUnicastRespone(class_ & 0x8000);
		message.addQuery(query);
	}
	quint16 nRecord = nAnswer + nAuthority + nAdditional;
	for (int i = 0; i < nRecord; ++i) {
		Record record;
		if (!parseRecord(packet, offset, record)) {
			return false;
		}
		message.addRecord(record);
	}
	return true;
}
void toPacket(const Message& message, QByteArray& packet)
{
	quint16 offset = 0;
	quint16 flags = (message.isResponse() ? 0x8400 : 0) |
		(message.isTruncated() ? 0x200 : 0);
	writeInteger<quint16>(packet, offset, message.transactionId());
	writeInteger<quint16>(packet, offset, flags);
	writeInteger<quint16>(packet, offset, message.queries().length());
	writeInteger<quint16>(packet, offset, message.records().length());
	writeInteger<quint16>(packet, offset, 0);
	writeInteger<quint16>(packet, offset, 0);
	QMap<QByteArray, quint16> nameMap;
	const auto queries = message.queries();
	for (const Query& query : queries) {
		writeName(packet, offset, query.name(), nameMap);
		writeInteger<quint16>(packet, offset, query.type());
		writeInteger<quint16>(packet, offset, query.uincastRespone() ? 0x8001 : 1);
	}
	const auto records = message.records();
	for (Record record : records) {
		writeRecord(packet, offset, record, nameMap);
	}
}

QString typeName(quint16 type)
{
	switch (type) {
	case A:    return "A";
	case AAAA: return "AAAA";
	case ANY:  return "ANY";
	case NSEC: return "NSEC";
	case PTR:  return "PTR";
	case SRV:  return "SRV";
	case TXT:  return "TXT";
	default:   return "?";
	}
}

QDebug operator<<(QDebug dbg, const Query& query)
{
	QDebugStateSaver saver(dbg);
	Q_UNUSED(saver);

	dbg.noquote().nospace() << "Query(" << typeName(query.type()) << " " << query.name() << ")";

	return dbg;
}
QDebug operator<<(QDebug dbg, const Record& record) {
	QDebugStateSaver saver(dbg);
	Q_UNUSED(saver);

	dbg.noquote().nospace() << "Record(" << typeName(record.type()) << " " << record.name() << ")";

	return dbg;
};
QTNETWORKNG_NAMESPACE_END
