// SPDX-License-Identifier: MIT
#pragma once

#include "Types.h"

#include <QByteArray>
#include <QString>
#include <QStringList>

#include <atomic>
#include <functional>

namespace ps {

struct ExtractLimits {
    quint64 maxTotalBytes = 4ull * 1024 * 1024 * 1024;
    quint64 maxEntries = 300000;
};

struct ExtractStats {
    QVector<FileEntry> entries;     // path = "/" + sanitized relative path
    QStringList unsafeEntries;      // names rejected (traversal, symlink write-through, absolute device ...)
    quint64 totalBytes = 0;
    bool truncated = false;
    QString error;
};

enum class ArchiveKind { Tar, Ar, RpmCpio, Generic };

class ArchiveReader
{
public:
    // Extracts an archive file into destDir (created if needed).
    static bool extractFile(const QString &archivePath, ArchiveKind kind, const QString &destDir,
                            const ExtractLimits &lim, ExtractStats *stats, const std::atomic<bool> *cancel);

    // Debian-style container (ar or tar outer) with control.tar.* and data.tar.* members.
    struct DebParts { QString debianBinary; QString controlMember; QString dataMember; };
    static bool extractDeb(const QString &path, bool outerIsTar, const QString &controlDir, const QString &payloadDir,
                           const ExtractLimits &lim, ExtractStats *control, ExtractStats *payload, DebParts *parts,
                           const std::atomic<bool> *cancel);

    // Lists the first `max` entry names (for format sniffing). Empty on failure.
    static QStringList listEntries(const QString &path, ArchiveKind kind, int max);

    // Decompresses a (possibly compressed) raw byte stream, e.g. Arch .MTREE (gzip).
    static QByteArray decompressRaw(const QByteArray &data, qint64 maxOut = 64ll * 1024 * 1024);

    static QString libarchiveVersion();
};

} // namespace ps
