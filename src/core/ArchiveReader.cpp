// SPDX-License-Identifier: MIT
#include "ArchiveReader.h"
#include "SecureFs.h"

#include <QDir>
#include <QFile>
#include <QScopeGuard>

#include <archive.h>
#include <archive_entry.h>
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace ps {

namespace {

struct ArchivePtr {
    archive *a = nullptr;
    explicit ArchivePtr(archive *p) : a(p) {}
    ~ArchivePtr() { if (a) archive_read_free(a); }
    ArchivePtr(const ArchivePtr &) = delete;
    ArchivePtr &operator=(const ArchivePtr &) = delete;
};

void configure(archive *a, ArchiveKind kind)
{
    archive_read_support_filter_all(a);
    switch (kind) {
    case ArchiveKind::Tar:
        archive_read_support_format_tar(a);
        archive_read_support_format_gnutar(a);
        archive_read_set_options(a, "tar:read_concatenated_archives");
        break;
    case ArchiveKind::Ar:
        archive_read_support_format_ar(a);
        break;
    case ArchiveKind::RpmCpio:
        archive_read_support_format_cpio(a);
        break;
    case ArchiveKind::Generic:
        archive_read_support_format_tar(a);
        archive_read_support_format_gnutar(a);
        archive_read_support_format_cpio(a);
        archive_read_support_format_zip(a);
        archive_read_support_format_7zip(a);
        archive_read_support_format_iso9660(a);
        archive_read_support_format_ar(a);
        archive_read_support_format_xar(a);
        archive_read_support_format_cab(a);
        archive_read_support_format_lha(a);
        archive_read_support_format_rar(a);
        archive_read_support_format_rar5(a);
        break;
    }
}

QString entryName(archive_entry *e)
{
    if (const char *u = archive_entry_pathname_utf8(e)) return QString::fromUtf8(u);
    if (const char *p = archive_entry_pathname(e)) return QFile::decodeName(p);
    return {};
}

QString dirName(const QString &rel)
{
    const qsizetype s = rel.lastIndexOf(QLatin1Char('/'));
    return s < 0 ? QString() : rel.left(s);
}
QString baseName(const QString &rel)
{
    const qsizetype s = rel.lastIndexOf(QLatin1Char('/'));
    return s < 0 ? rel : rel.mid(s + 1);
}

struct Writer {
    int rootFd = -1;
    QString root;
    const ExtractLimits &lim;
    ExtractStats &st;
    const std::atomic<bool> *cancel;

    bool cancelled() const { return cancel && cancel->load(); }

    bool copyData(archive *a, int fd)
    {
        char buf[1 << 16];
        for (;;) {
            const la_ssize_t r = archive_read_data(a, buf, sizeof buf);
            if (r == 0) return true;
            if (r < 0) return r == ARCHIVE_WARN;
            if (st.totalBytes + static_cast<quint64>(r) > lim.maxTotalBytes) {
                st.truncated = true;
                return false;
            }
            st.totalBytes += static_cast<quint64>(r);
            if (fd >= 0) {
                la_ssize_t off = 0;
                while (off < r) {
                    const ssize_t w = ::write(fd, buf + off, static_cast<size_t>(r - off));
                    if (w < 0 && errno == EINTR) continue;
                    if (w <= 0) return false;
                    off += w;
                }
            }
            if (cancelled()) return false;
        }
    }

    // Returns false to abort extraction.
    bool handle(archive *a, archive_entry *e)
    {
        const QString raw = entryName(e);
        bool trav = false;
        const QString rel = securefs::sanitizeRelative(raw, &trav);
        if (rel.isEmpty()) {
            if (trav) st.unsafeEntries << QStringLiteral("path traversal: ") + raw;
            archive_read_data_skip(a);
            return true;
        }
        if (static_cast<quint64>(st.entries.size()) >= lim.maxEntries) {
            st.truncated = true;
            return false;
        }

        FileEntry fe;
        fe.path = QLatin1Char('/') + rel;
        fe.mode = archive_entry_mode(e);
        fe.size = static_cast<quint64>(std::max<la_int64_t>(0, archive_entry_size(e)));
        const char *un = archive_entry_uname(e);
        const char *gn = archive_entry_gname(e);
        fe.owner = (un ? QString::fromUtf8(un) : QString::number(archive_entry_uid(e))) + QLatin1Char(':')
                 + (gn ? QString::fromUtf8(gn) : QString::number(archive_entry_gid(e)));

        const char *hl = archive_entry_hardlink(e);
        const mode_t ft = archive_entry_filetype(e);
        const QString parent = dirName(rel);
        const QByteArray base = QFile::encodeName(baseName(rel));

        int pfd = -1;
        const bool needsWrite = !(ft == AE_IFCHR || ft == AE_IFBLK || ft == AE_IFIFO || ft == AE_IFSOCK);
        if (needsWrite) {
            pfd = securefs::mkdirsBeneath(rootFd, parent);
            if (pfd < 0) {
                st.unsafeEntries << QStringLiteral("blocked (parent is a symlink or file): ") + raw;
                archive_read_data_skip(a);
                return true;
            }
        }
        const auto closeP = qScopeGuard([&] { if (pfd >= 0) ::close(pfd); });

        if (hl) {
            fe.type = QStringLiteral("hardlink");
            bool t2 = false;
            const QString target = securefs::sanitizeRelative(QString::fromUtf8(hl), &t2);
            fe.linkTarget = QLatin1Char('/') + target;
            if (target.isEmpty()) {
                st.unsafeEntries << QStringLiteral("hardlink traversal: ") + raw;
            } else {
                // Materialise as a copy: never call linkat() with attacker-controlled paths.
                const int src = securefs::openBeneath(root, target, O_RDONLY | O_NONBLOCK);
                if (src >= 0) {
                    ::unlinkat(pfd, base.constData(), 0);
                    const int dst = ::openat(pfd, base.constData(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
                    struct stat sst{};
                    if (dst >= 0 && ::fstat(src, &sst) == 0 && S_ISREG(sst.st_mode)) {
                        char buf[1 << 16];
                        ssize_t r;
                        // A copy costs as much as the original: thousands of hardlinks to one file
                        // must not get around the extraction limit.
                        while ((r = ::read(src, buf, sizeof buf)) > 0) {
                            if (st.totalBytes + static_cast<quint64>(r) > lim.maxTotalBytes) {
                                st.truncated = true;
                                break;
                            }
                            st.totalBytes += static_cast<quint64>(r);
                            if (::write(dst, buf, static_cast<size_t>(r)) != r) break;
                        }
                        ::fchmod(dst, (sst.st_mode & 0755) | 0600);
                        fe.size = static_cast<quint64>(sst.st_size);
                    }
                    if (dst >= 0) ::close(dst);
                    ::close(src);
                }
            }
            archive_read_data_skip(a);
        } else if (ft == AE_IFDIR) {
            fe.type = QStringLiteral("dir");
            fe.size = 0;
            struct stat cur{};
            if (::fstatat(pfd, base.constData(), &cur, AT_SYMLINK_NOFOLLOW) == 0 && !S_ISDIR(cur.st_mode))
                ::unlinkat(pfd, base.constData(), 0);
            ::mkdirat(pfd, base.constData(), 0755);
            archive_read_data_skip(a);
        } else if (ft == AE_IFLNK) {
            fe.type = QStringLiteral("symlink");
            const char *t = archive_entry_symlink_utf8(e);
            if (!t) t = archive_entry_symlink(e);
            fe.linkTarget = t ? QString::fromUtf8(t) : QString();
            fe.size = 0;
            struct stat cur{};
            if (::fstatat(pfd, base.constData(), &cur, AT_SYMLINK_NOFOLLOW) == 0) {
                if (S_ISDIR(cur.st_mode)) securefs::removeTree(root + QLatin1Char('/') + rel);
                else ::unlinkat(pfd, base.constData(), 0);
            }
            if (t && ::symlinkat(t, pfd, base.constData()) != 0) st.unsafeEntries << QStringLiteral("could not create symlink: ") + raw;
            archive_read_data_skip(a);
        } else if (ft == AE_IFREG || ft == 0) {
            fe.type = QStringLiteral("file");
            struct stat cur{};
            if (::fstatat(pfd, base.constData(), &cur, AT_SYMLINK_NOFOLLOW) == 0) {
                if (S_ISDIR(cur.st_mode)) {
                    st.unsafeEntries << QStringLiteral("file replaces directory: ") + raw;
                    archive_read_data_skip(a);
                    st.entries << fe;
                    return true;
                }
                ::unlinkat(pfd, base.constData(), 0);
            }
            const int fd = ::openat(pfd, base.constData(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
            const bool ok = copyData(a, fd);
            if (fd >= 0) {
                ::fchmod(fd, (fe.mode & 0755) | 0600);
                ::close(fd);
            }
            if (!ok && (st.truncated || cancelled())) {
                st.entries << fe;
                return false;
            }
        } else {
            switch (ft) {
            case AE_IFCHR: fe.type = QStringLiteral("char"); break;
            case AE_IFBLK: fe.type = QStringLiteral("block"); break;
            case AE_IFIFO: fe.type = QStringLiteral("fifo"); break;
            case AE_IFSOCK: fe.type = QStringLiteral("socket"); break;
            default: fe.type = QStringLiteral("other");
            }
            archive_read_data_skip(a);
        }
        st.entries << fe;
        return !cancelled();
    }
};

bool runExtraction(archive *a, const QString &destDir, const ExtractLimits &lim, ExtractStats *stats,
                   const std::atomic<bool> *cancel)
{
    QDir().mkpath(destDir);
    const int rootFd = ::open(QFile::encodeName(destDir).constData(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (rootFd < 0) {
        stats->error = QStringLiteral("cannot open extraction directory");
        return false;
    }
    Writer w{rootFd, destDir, lim, *stats, cancel};
    archive_entry *e = nullptr;
    bool ok = true;
    for (;;) {
        const int r = archive_read_next_header(a, &e);
        if (r == ARCHIVE_EOF) break;
        if (r == ARCHIVE_FATAL) {
            stats->error = QString::fromUtf8(archive_error_string(a) ? archive_error_string(a) : "fatal archive error");
            ok = stats->entries.size() > 0;
            break;
        }
        if (r == ARCHIVE_RETRY) continue;
        if (!w.handle(a, e)) break;
    }
    ::close(rootFd);
    return ok;
}

struct NestedCtx {
    archive *outer;
    char buf[1 << 16];
};

la_ssize_t nestedRead(archive *, void *client, const void **out)
{
    auto *ctx = static_cast<NestedCtx *>(client);
    const la_ssize_t r = archive_read_data(ctx->outer, ctx->buf, sizeof ctx->buf);
    *out = ctx->buf;
    return r < 0 ? ARCHIVE_FATAL : r;
}

} // namespace

bool ArchiveReader::extractFile(const QString &archivePath, ArchiveKind kind, const QString &destDir,
                                const ExtractLimits &lim, ExtractStats *stats, const std::atomic<bool> *cancel)
{
    ArchivePtr a(archive_read_new());
    configure(a.a, kind);
    if (archive_read_open_filename(a.a, QFile::encodeName(archivePath).constData(), 1 << 16) != ARCHIVE_OK) {
        stats->error = QString::fromUtf8(archive_error_string(a.a) ? archive_error_string(a.a) : "cannot open archive");
        return false;
    }
    return runExtraction(a.a, destDir, lim, stats, cancel);
}

bool ArchiveReader::extractDeb(const QString &path, bool outerIsTar, const QString &controlDir, const QString &payloadDir,
                               const ExtractLimits &lim, ExtractStats *control, ExtractStats *payload, DebParts *parts,
                               const std::atomic<bool> *cancel)
{
    ArchivePtr outer(archive_read_new());
    configure(outer.a, outerIsTar ? ArchiveKind::Tar : ArchiveKind::Ar);
    if (archive_read_open_filename(outer.a, QFile::encodeName(path).constData(), 1 << 16) != ARCHIVE_OK) {
        payload->error = QString::fromUtf8(archive_error_string(outer.a) ? archive_error_string(outer.a) : "cannot open package");
        return false;
    }
    archive_entry *e = nullptr;
    bool sawData = false;
    while (archive_read_next_header(outer.a, &e) == ARCHIVE_OK) {
        QString name = entryName(e);
        if (name.startsWith(QLatin1String("./"))) name = name.mid(2);
        if (name.endsWith(QLatin1Char('/'))) name.chop(1);
        if (name == QLatin1String("debian-binary")) {
            char buf[64] = {};
            const la_ssize_t r = archive_read_data(outer.a, buf, sizeof buf - 1);
            if (r > 0) parts->debianBinary = QString::fromLatin1(buf, static_cast<qsizetype>(r)).trimmed();
            continue;
        }
        const bool isControl = name.startsWith(QLatin1String("control.tar"));
        const bool isData = name.startsWith(QLatin1String("data.tar"));
        if (!isControl && !isData) {
            archive_read_data_skip(outer.a);
            continue;
        }
        (isControl ? parts->controlMember : parts->dataMember) = name;
        NestedCtx ctx{outer.a, {}};
        ArchivePtr inner(archive_read_new());
        configure(inner.a, ArchiveKind::Tar);
        if (archive_read_open(inner.a, &ctx, nullptr, nestedRead, nullptr) != ARCHIVE_OK) {
            (isControl ? control : payload)->error = QStringLiteral("cannot open %1").arg(name);
            continue;
        }
        runExtraction(inner.a, isControl ? controlDir : payloadDir, lim, isControl ? control : payload, cancel);
        if (isData) sawData = true;
        if (cancel && cancel->load()) break;
    }
    if (!sawData && payload->error.isEmpty()) payload->error = QStringLiteral("package has no data.tar member");
    return sawData || !parts->controlMember.isEmpty();
}

QStringList ArchiveReader::listEntries(const QString &path, ArchiveKind kind, int max)
{
    QStringList out;
    ArchivePtr a(archive_read_new());
    configure(a.a, kind);
    if (archive_read_open_filename(a.a, QFile::encodeName(path).constData(), 1 << 16) != ARCHIVE_OK) return out;
    archive_entry *e = nullptr;
    while (out.size() < max && archive_read_next_header(a.a, &e) == ARCHIVE_OK) {
        QString n = entryName(e);
        if (n.startsWith(QLatin1String("./"))) n = n.mid(2);
        out << n;
        archive_read_data_skip(a.a);
    }
    return out;
}

QByteArray ArchiveReader::decompressRaw(const QByteArray &data, qint64 maxOut)
{
    ArchivePtr a(archive_read_new());
    archive_read_support_filter_all(a.a);
    archive_read_support_format_raw(a.a);
    if (archive_read_open_memory(a.a, data.constData(), static_cast<size_t>(data.size())) != ARCHIVE_OK) return data;
    archive_entry *e = nullptr;
    if (archive_read_next_header(a.a, &e) != ARCHIVE_OK) return data;
    QByteArray out;
    char buf[1 << 16];
    la_ssize_t r;
    while ((r = archive_read_data(a.a, buf, sizeof buf)) > 0) {
        out.append(buf, static_cast<qsizetype>(r));
        if (out.size() > maxOut) break;
    }
    return out;
}

QString ArchiveReader::libarchiveVersion() { return QString::fromLatin1(archive_version_details()); }

} // namespace ps
