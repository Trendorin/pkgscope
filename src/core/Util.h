// SPDX-License-Identifier: MIT
#pragma once

#include <QByteArray>
#include <QString>
#include <QStringList>

namespace ps::util {

QString humanSize(quint64 bytes);
QString modeString(quint32 mode);          // -rwsr-xr-x
double shannonEntropy(const QByteArray &data);
double shannonEntropy(const char *data, qsizetype len);
bool looksLikeText(const QByteArray &head);
QString hexDigest(const QByteArray &raw);

// Decodes a C-style escaped string as produced by strace (\xNN, \n, \t, \", \\, octal).
QByteArray unescapeC(QStringView s);

// Returns true for loopback, RFC1918, link-local, CGNAT, ULA, multicast, unspecified.
bool isNonRoutableIp(const QString &ip);
bool isIpv4(const QString &s);

QString shellQuote(const QString &s);
QString sanitizeOneLine(const QString &s, int maxLen = 300); // printable, single line, truncated
QString elide(const QString &s, int maxLen);

QString lowerExt(const QString &name);

// Locate a helper executable: next to our binary, in ../lib/pkgscope, ../libexec, then PATH.
QString findHelper(const QString &name);
QString findInPath(const QString &name);

} // namespace ps::util
