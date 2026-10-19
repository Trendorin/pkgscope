// SPDX-License-Identifier: MIT
#include "RpmHeader.h"

namespace ps {

namespace {
quint32 be32(const QByteArray &d, qint64 o)
{
    if (o < 0 || o + 4 > d.size()) return 0;
    const auto *p = reinterpret_cast<const uchar *>(d.constData() + o);
    return (quint32(p[0]) << 24) | (quint32(p[1]) << 16) | (quint32(p[2]) << 8) | p[3];
}
constexpr quint32 kMaxIndex = 100000;
constexpr quint32 kMaxStore = 256u * 1024 * 1024;
} // namespace

bool RpmHeader::parse(const QByteArray &d, QString *error)
{
    const auto fail = [error](const char *m) { if (error) *error = QString::fromLatin1(m); return false; };
    if (d.size() < 96 || !d.startsWith("\xed\xab\xee\xdb")) return fail("not an RPM file");

    qint64 off = 96;
    // Signature header
    if (!d.mid(off, 3).startsWith("\x8e\xad\xe8")) return fail("bad signature header magic");
    quint32 nindex = be32(d, off + 8), hsize = be32(d, off + 12);
    if (nindex > kMaxIndex || hsize > kMaxStore) return fail("signature header too large");
    m_sigEntries = static_cast<int>(nindex);
    off += 16 + qint64(nindex) * 16 + hsize;
    off = (off + 7) & ~qint64(7);

    // Main header
    if (off + 16 > d.size() || !d.mid(off, 3).startsWith("\x8e\xad\xe8")) return fail("bad main header magic (header truncated?)");
    nindex = be32(d, off + 8);
    hsize = be32(d, off + 12);
    if (nindex > kMaxIndex || hsize > kMaxStore) return fail("main header too large");
    const qint64 indexStart = off + 16;
    const qint64 storeStart = indexStart + qint64(nindex) * 16;
    if (storeStart + hsize > d.size()) return fail("main header truncated");
    m_store = d.mid(storeStart, hsize);
    for (quint32 i = 0; i < nindex; ++i) {
        const qint64 e = indexStart + qint64(i) * 16;
        Entry en{be32(d, e + 4), be32(d, e + 8), be32(d, e + 12)};
        if (en.offset >= hsize || en.count > kMaxStore) continue;
        m_entries.insert(be32(d, e), en);
    }
    m_headerEnd = storeStart + hsize;
    return true;
}

QString RpmHeader::string(quint32 tag) const
{
    auto it = m_entries.constFind(tag);
    if (it == m_entries.constEnd()) return {};
    if (it->type != 6 && it->type != 8 && it->type != 9) return {};
    const qint64 start = it->offset;
    const qint64 end = m_store.indexOf('\0', start);
    return QString::fromUtf8(m_store.mid(start, (end < 0 ? m_store.size() : end) - start));
}

QStringList RpmHeader::stringArray(quint32 tag) const
{
    QStringList out;
    auto it = m_entries.constFind(tag);
    if (it == m_entries.constEnd() || (it->type != 8 && it->type != 9 && it->type != 6)) return out;
    qint64 pos = it->offset;
    const quint32 n = it->type == 6 ? 1 : it->count;
    for (quint32 i = 0; i < n && pos < m_store.size(); ++i) {
        qint64 end = m_store.indexOf('\0', pos);
        if (end < 0) end = m_store.size();
        out << QString::fromUtf8(m_store.mid(pos, end - pos));
        pos = end + 1;
    }
    return out;
}

QVector<qint64> RpmHeader::intArray(quint32 tag) const
{
    QVector<qint64> out;
    auto it = m_entries.constFind(tag);
    if (it == m_entries.constEnd()) return out;
    int width = 0;
    switch (it->type) {
    case 2: width = 1; break;
    case 3: width = 2; break;
    case 4: width = 4; break;
    case 5: width = 8; break;
    default: return out;
    }
    const qint64 need = qint64(it->count) * width;
    if (qint64(it->offset) + need > m_store.size()) return out;
    out.reserve(it->count);
    const auto *p = reinterpret_cast<const uchar *>(m_store.constData() + it->offset);
    for (quint32 i = 0; i < it->count; ++i) {
        quint64 v = 0;
        for (int b = 0; b < width; ++b) v = (v << 8) | p[i * width + b];
        out << static_cast<qint64>(v);
    }
    return out;
}

QStringList RpmHeader::filePaths() const
{
    const QStringList base = stringArray(BaseNames);
    const QStringList dirs = stringArray(DirNames);
    const QVector<qint64> idx = intArray(DirIndexes);
    QStringList out;
    for (int i = 0; i < base.size(); ++i) {
        const qint64 di = i < idx.size() ? idx[i] : -1;
        out << ((di >= 0 && di < dirs.size()) ? dirs[di] : QString()) + base[i];
    }
    return out;
}

} // namespace ps
