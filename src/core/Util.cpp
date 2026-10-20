// SPDX-License-Identifier: MIT
#include "Util.h"

#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>

#include <array>
#include <cmath>
#include <sys/stat.h>
#include <unistd.h>

namespace ps::util {

QString humanSize(quint64 bytes)
{
    static const char *units[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    double v = static_cast<double>(bytes);
    int u = 0;
    while (v >= 1024.0 && u < 4) {
        v /= 1024.0;
        ++u;
    }
    return u == 0 ? QStringLiteral("%1 B").arg(bytes)
                  : QStringLiteral("%1 %2").arg(v, 0, 'f', v < 10 ? 2 : 1).arg(QLatin1String(units[u]));
}

QString modeString(quint32 mode)
{
    QString s(10, QLatin1Char('-'));
    switch (mode & S_IFMT) {
    case S_IFDIR: s[0] = QLatin1Char('d'); break;
    case S_IFLNK: s[0] = QLatin1Char('l'); break;
    case S_IFCHR: s[0] = QLatin1Char('c'); break;
    case S_IFBLK: s[0] = QLatin1Char('b'); break;
    case S_IFIFO: s[0] = QLatin1Char('p'); break;
    case S_IFSOCK: s[0] = QLatin1Char('s'); break;
    default: break;
    }
    const char rwx[] = "rwxrwxrwx";
    for (int i = 0; i < 9; ++i)
        if (mode & (1u << (8 - i))) s[i + 1] = QLatin1Char(rwx[i]);
    if (mode & S_ISUID) s[3] = QLatin1Char((mode & S_IXUSR) ? 's' : 'S');
    if (mode & S_ISGID) s[6] = QLatin1Char((mode & S_IXGRP) ? 's' : 'S');
    if (mode & S_ISVTX) s[9] = QLatin1Char((mode & S_IXOTH) ? 't' : 'T');
    return s;
}

double shannonEntropy(const char *data, qsizetype len)
{
    if (len <= 0) return 0.0;
    std::array<quint64, 256> freq{};
    for (qsizetype i = 0; i < len; ++i) ++freq[static_cast<unsigned char>(data[i])];
    double e = 0.0;
    const double n = static_cast<double>(len);
    for (quint64 c : freq) {
        if (!c) continue;
        const double p = static_cast<double>(c) / n;
        e -= p * std::log2(p);
    }
    return e;
}

double shannonEntropy(const QByteArray &data) { return shannonEntropy(data.constData(), data.size()); }

bool looksLikeText(const QByteArray &head)
{
    if (head.isEmpty()) return true;
    const qsizetype n = std::min<qsizetype>(head.size(), 8192);
    int bad = 0;
    for (qsizetype i = 0; i < n; ++i) {
        const auto c = static_cast<unsigned char>(head[i]);
        if (c == 0) return false;
        if (c < 0x09 || (c > 0x0d && c < 0x20 && c != 0x1b)) ++bad;
    }
    return bad * 100 / n < 3;
}

QString hexDigest(const QByteArray &raw) { return QString::fromLatin1(raw.toHex()); }

static int hexVal(QChar c)
{
    const ushort u = c.unicode();
    if (u >= '0' && u <= '9') return u - '0';
    if (u >= 'a' && u <= 'f') return u - 'a' + 10;
    if (u >= 'A' && u <= 'F') return u - 'A' + 10;
    return -1;
}

QByteArray unescapeC(QStringView s)
{
    QByteArray out;
    out.reserve(s.size());
    for (qsizetype i = 0; i < s.size(); ++i) {
        const QChar c = s[i];
        if (c != QLatin1Char('\\') || i + 1 >= s.size()) {
            out.append(QString(c).toUtf8());
            continue;
        }
        const QChar n = s[++i];
        switch (n.unicode()) {
        case 'n': out.append('\n'); break;
        case 't': out.append('\t'); break;
        case 'r': out.append('\r'); break;
        case 'v': out.append('\v'); break;
        case 'f': out.append('\f'); break;
        case 'a': out.append('\a'); break;
        case 'b': out.append('\b'); break;
        case '\\': out.append('\\'); break;
        case '"': out.append('"'); break;
        case '\'': out.append('\''); break;
        case 'x': {
            int v = 0, k = 0;
            while (k < 2 && i + 1 < s.size() && hexVal(s[i + 1]) >= 0) {
                v = v * 16 + hexVal(s[++i]);
                ++k;
            }
            out.append(static_cast<char>(v));
            break;
        }
        default:
            if (n >= QLatin1Char('0') && n <= QLatin1Char('7')) {
                int v = n.unicode() - '0', k = 1;
                while (k < 3 && i + 1 < s.size() && s[i + 1] >= QLatin1Char('0') && s[i + 1] <= QLatin1Char('7')) {
                    v = v * 8 + (s[++i].unicode() - '0');
                    ++k;
                }
                out.append(static_cast<char>(v & 0xff));
            } else {
                out.append(QString(n).toUtf8());
            }
        }
    }
    return out;
}

static bool parseIpv4(const QString &s, quint32 *out)
{
    const QStringList parts = s.split(QLatin1Char('.'));
    if (parts.size() != 4) return false;
    quint32 v = 0;
    for (const QString &p : parts) {
        bool ok = false;
        const uint n = p.toUInt(&ok);
        if (!ok || n > 255 || p.isEmpty() || p.size() > 3) return false;
        v = (v << 8) | n;
    }
    if (out) *out = v;
    return true;
}

bool isIpv4(const QString &s) { return parseIpv4(s, nullptr); }

bool isNonRoutableIp(const QString &ipIn)
{
    QString ip = ipIn.trimmed().toLower();
    if (ip.startsWith(QLatin1String("::ffff:")) && ip.count(QLatin1Char('.')) == 3) ip = ip.mid(7);
    quint32 v = 0;
    if (parseIpv4(ip, &v)) {
        const auto in = [v](quint32 net, int bits) {
            const quint32 mask = bits == 0 ? 0 : ~((1u << (32 - bits)) - 1);
            return (v & mask) == (net & mask);
        };
        return in(0x00000000, 8) || in(0x0A000000, 8) || in(0xAC100000, 12) || in(0xC0A80000, 16)
            || in(0x64400000, 10) || in(0xA9FE0000, 16) || in(0x7F000000, 8) || in(0xC0000200, 24)
            || in(0xC6336400, 24) || in(0xCB007100, 24) || in(0xE0000000, 4) || in(0xF0000000, 4);
    }
    if (!ip.contains(QLatin1Char(':'))) return true; // not an IP at all
    if (ip == QLatin1String("::") || ip == QLatin1String("::1")) return true;
    if (ip.startsWith(QLatin1String("fe8")) || ip.startsWith(QLatin1String("fe9")) || ip.startsWith(QLatin1String("fea"))
        || ip.startsWith(QLatin1String("feb")) || ip.startsWith(QLatin1String("fc")) || ip.startsWith(QLatin1String("fd"))
        || ip.startsWith(QLatin1String("ff")) || ip.startsWith(QLatin1String("2001:db8")))
        return true;
    return false;
}

QString shellQuote(const QString &s)
{
    if (s.isEmpty()) return QStringLiteral("''");
    static const QString safe = QStringLiteral("@%+=:,./-_");
    bool ok = true;
    for (QChar c : s)
        if (!c.isLetterOrNumber() && !safe.contains(c)) { ok = false; break; }
    if (ok) return s;
    QString r = s;
    r.replace(QLatin1Char('\''), QLatin1String("'\\''"));
    return QLatin1Char('\'') + r + QLatin1Char('\'');
}

QString sanitizeOneLine(const QString &s, int maxLen)
{
    QString out;
    out.reserve(std::min<qsizetype>(s.size(), maxLen + 1));
    for (QChar c : s) {
        if (out.size() >= maxLen) {
            out += QChar(0x2026);
            break;
        }
        if (c == QLatin1Char('\n') || c == QLatin1Char('\r') || c == QLatin1Char('\t')) out += QLatin1Char(' ');
        else if (c.isPrint() || c == QLatin1Char(' ')) out += c;
        else out += QChar(0xFFFD);
    }
    return out.trimmed();
}

QString elide(const QString &s, int maxLen)
{
    return s.size() <= maxLen ? s : s.left(maxLen - 1) + QChar(0x2026);
}

QString lowerExt(const QString &name)
{
    const qsizetype dot = name.lastIndexOf(QLatin1Char('.'));
    return dot < 0 ? QString() : name.mid(dot + 1).toLower();
}

QString findInPath(const QString &name)
{
    const QByteArray path = qgetenv("PATH");
    const QStringList dirs = QString::fromLocal8Bit(path.isEmpty() ? QByteArray("/usr/bin:/bin") : path)
                                 .split(QLatin1Char(':'), Qt::SkipEmptyParts);
    for (const QString &d : dirs) {
        const QString p = d + QLatin1Char('/') + name;
        if (::access(QFile::encodeName(p).constData(), X_OK) == 0 && QFileInfo(p).isFile()) return p;
    }
    for (const char *d : {"/usr/bin", "/usr/sbin", "/bin", "/sbin"}) {
        const QString p = QLatin1String(d) + QLatin1Char('/') + name;
        if (::access(QFile::encodeName(p).constData(), X_OK) == 0) return p;
    }
    return {};
}

QString findHelper(const QString &name)
{
    const QString appDir = QCoreApplication::applicationDirPath();
    const QStringList candidates = {
        appDir + QLatin1Char('/') + name,
        QStringLiteral(PKGSCOPE_HELPER_DIR "/") + name,
        appDir + QStringLiteral("/../lib/pkgscope/") + name,
        appDir + QStringLiteral("/../libexec/pkgscope/") + name,
        appDir + QStringLiteral("/../libexec/") + name,
    };
    for (const QString &c : candidates) {
        const QString p = QDir::cleanPath(c);
        if (::access(QFile::encodeName(p).constData(), X_OK) == 0 && QFileInfo(p).isFile()) return p;
    }
    return findInPath(name);
}

} // namespace ps::util
