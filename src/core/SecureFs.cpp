// SPDX-License-Identifier: MIT
#include "SecureFs.h"

#include <QCryptographicHash>
#include <QFile>
#include <QStringList>
#include <QVector>

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

namespace ps::securefs {

namespace {

struct Fd {
    int fd = -1;
    Fd() = default;
    explicit Fd(int f) : fd(f) {}
    ~Fd() { if (fd >= 0) ::close(fd); }
    Fd(const Fd &) = delete;
    Fd &operator=(const Fd &) = delete;
    Fd(Fd &&o) noexcept : fd(o.fd) { o.fd = -1; }
    Fd &operator=(Fd &&o) noexcept { if (this != &o) { if (fd >= 0) ::close(fd); fd = o.fd; o.fd = -1; } return *this; }
    int release() { int f = fd; fd = -1; return f; }
};

QByteArray enc(const QString &s) { return QFile::encodeName(s); }

constexpr int kDirFlags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;

} // namespace

QString sanitizeRelative(const QString &name, bool *hadTraversal)
{
    if (hadTraversal) *hadTraversal = false;
    if (name.contains(QChar(0))) return {};
    QStringList out;
    for (const QString &part : name.split(QLatin1Char('/'), Qt::SkipEmptyParts)) {
        if (part == QLatin1String(".")) continue;
        if (part == QLatin1String("..")) {
            if (hadTraversal) *hadTraversal = true;
            return {};
        }
        out << part;
    }
    return out.join(QLatin1Char('/'));
}

int openBeneath(const QString &root, const QString &rel, int flags)
{
    Fd dir(::open(enc(root).constData(), kDirFlags));
    if (dir.fd < 0) return -1;
    const QStringList parts = rel.split(QLatin1Char('/'), Qt::SkipEmptyParts);
    if (parts.isEmpty()) return ::fcntl(dir.fd, F_DUPFD_CLOEXEC, 0);
    for (int i = 0; i < parts.size() - 1; ++i) {
        if (parts[i] == QLatin1String("..")) { errno = EPERM; return -1; }
        Fd next(::openat(dir.fd, enc(parts[i]).constData(), kDirFlags));
        if (next.fd < 0) return -1;
        dir = std::move(next);
    }
    if (parts.last() == QLatin1String("..")) { errno = EPERM; return -1; }
    return ::openat(dir.fd, enc(parts.last()).constData(), flags | O_NOFOLLOW | O_CLOEXEC);
}

QByteArray readBeneath(const QString &root, const QString &rel, qint64 maxBytes, bool *truncated)
{
    if (truncated) *truncated = false;
    Fd f(openBeneath(root, rel, O_RDONLY | O_NONBLOCK));
    if (f.fd < 0) return {};
    struct stat st{};
    if (::fstat(f.fd, &st) != 0 || !S_ISREG(st.st_mode)) return {};
    const qint64 want = std::min<qint64>(st.st_size, maxBytes);
    if (truncated && st.st_size > maxBytes) *truncated = true;
    QByteArray buf;
    buf.resize(want);
    qint64 got = 0;
    while (got < want) {
        const ssize_t r = ::read(f.fd, buf.data() + got, static_cast<size_t>(want - got));
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        got += r;
    }
    buf.resize(got);
    return buf;
}

bool hashBeneath(const QString &root, const QString &rel, QByteArray *sha256, QByteArray *md5)
{
    Fd f(openBeneath(root, rel, O_RDONLY | O_NONBLOCK));
    if (f.fd < 0) return false;
    struct stat st{};
    if (::fstat(f.fd, &st) != 0 || !S_ISREG(st.st_mode)) return false;
    QCryptographicHash hs(QCryptographicHash::Sha256), hm(QCryptographicHash::Md5);
    char buf[1 << 16];
    for (;;) {
        const ssize_t r = ::read(f.fd, buf, sizeof buf);
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) return false;
        if (r == 0) break;
        if (sha256) hs.addData(QByteArrayView(buf, r));
        if (md5) hm.addData(QByteArrayView(buf, r));
    }
    if (sha256) *sha256 = hs.result();
    if (md5) *md5 = hm.result();
    return true;
}

int mkdirsBeneath(int rootFd, const QString &relDir)
{
    Fd cur(::fcntl(rootFd, F_DUPFD_CLOEXEC, 0));
    if (cur.fd < 0) return -1;
    for (const QString &part : relDir.split(QLatin1Char('/'), Qt::SkipEmptyParts)) {
        if (part == QLatin1String("..") || part == QLatin1String(".")) { errno = EPERM; return -1; }
        const QByteArray p = enc(part);
        Fd next(::openat(cur.fd, p.constData(), kDirFlags));
        if (next.fd < 0) {
            if (errno != ENOENT) return -1; // ELOOP/ENOTDIR => symlink or file in the way
            if (::mkdirat(cur.fd, p.constData(), 0755) != 0 && errno != EEXIST) return -1;
            next = Fd(::openat(cur.fd, p.constData(), kDirFlags));
            if (next.fd < 0) return -1;
        }
        cur = std::move(next);
    }
    return cur.release();
}

static bool walkFd(int dirFd, const QString &prefix, const WalkFn &fn, int depth, int maxDepth, bool &stop)
{
    if (depth > maxDepth) return true;
    const int dupFd = ::fcntl(dirFd, F_DUPFD_CLOEXEC, 0);
    if (dupFd < 0) return false;
    DIR *d = ::fdopendir(dupFd);
    if (!d) { ::close(dupFd); return false; }
    QVector<QByteArray> names;
    while (dirent *e = ::readdir(d)) {
        if (!std::strcmp(e->d_name, ".") || !std::strcmp(e->d_name, "..")) continue;
        names << QByteArray(e->d_name);
    }
    ::closedir(d);
    std::sort(names.begin(), names.end());
    for (const QByteArray &n : names) {
        if (stop) return true;
        struct stat st{};
        if (::fstatat(dirFd, n.constData(), &st, AT_SYMLINK_NOFOLLOW) != 0) continue;
        const QString rel = prefix.isEmpty() ? QFile::decodeName(n) : prefix + QLatin1Char('/') + QFile::decodeName(n);
        if (!fn(rel, st)) { stop = true; return true; }
        if (S_ISDIR(st.st_mode)) {
            Fd sub(::openat(dirFd, n.constData(), kDirFlags));
            if (sub.fd >= 0) walkFd(sub.fd, rel, fn, depth + 1, maxDepth, stop);
        }
    }
    return true;
}

bool walk(const QString &root, const WalkFn &fn, int maxDepth)
{
    Fd r(::open(enc(root).constData(), kDirFlags));
    if (r.fd < 0) return false;
    bool stop = false;
    return walkFd(r.fd, QString(), fn, 0, maxDepth, stop);
}

static void removeContents(int dirFd, int depth)
{
    if (depth > 256) return;
    ::fchmod(dirFd, 0700);
    const int dupFd = ::fcntl(dirFd, F_DUPFD_CLOEXEC, 0);
    if (dupFd < 0) return;
    DIR *d = ::fdopendir(dupFd);
    if (!d) { ::close(dupFd); return; }
    QVector<QByteArray> names;
    while (dirent *e = ::readdir(d)) {
        if (!std::strcmp(e->d_name, ".") || !std::strcmp(e->d_name, "..")) continue;
        names << QByteArray(e->d_name);
    }
    ::closedir(d);
    for (const QByteArray &n : names) {
        struct stat st{};
        if (::fstatat(dirFd, n.constData(), &st, AT_SYMLINK_NOFOLLOW) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            if (::fchmodat(dirFd, n.constData(), 0700, 0) != 0) { /* best effort */ }
            Fd sub(::openat(dirFd, n.constData(), kDirFlags));
            if (sub.fd >= 0) removeContents(sub.fd, depth + 1);
            ::unlinkat(dirFd, n.constData(), AT_REMOVEDIR);
        } else {
            ::unlinkat(dirFd, n.constData(), 0);
        }
    }
}

bool removeTree(const QString &path)
{
    if (path.isEmpty() || path == QLatin1String("/")) return false;
    const QByteArray p = enc(path);
    struct stat st{};
    if (::lstat(p.constData(), &st) != 0) return errno == ENOENT;
    if (!S_ISDIR(st.st_mode)) return ::unlink(p.constData()) == 0;
    {
        ::chmod(p.constData(), 0700);
        Fd d(::open(p.constData(), kDirFlags));
        if (d.fd < 0) return false;
        removeContents(d.fd, 0);
    }
    return ::rmdir(p.constData()) == 0;
}

static qint64 copyDir(int srcFd, int dstFd, int depth, QString *error)
{
    if (depth > 128) return 0;
    const int dupFd = ::fcntl(srcFd, F_DUPFD_CLOEXEC, 0);
    if (dupFd < 0) return -1;
    DIR *d = ::fdopendir(dupFd);
    if (!d) { ::close(dupFd); return -1; }
    QVector<QByteArray> names;
    while (dirent *e = ::readdir(d)) {
        if (!std::strcmp(e->d_name, ".") || !std::strcmp(e->d_name, "..")) continue;
        names << QByteArray(e->d_name);
    }
    ::closedir(d);
    qint64 count = 0;
    for (const QByteArray &n : names) {
        struct stat st{};
        if (::fstatat(srcFd, n.constData(), &st, AT_SYMLINK_NOFOLLOW) != 0) continue;
        const mode_t perm = st.st_mode & 0777;
        if (S_ISDIR(st.st_mode)) {
            if (::mkdirat(dstFd, n.constData(), perm | 0700) != 0 && errno != EEXIST) continue;
            Fd s(::openat(srcFd, n.constData(), kDirFlags));
            Fd t(::openat(dstFd, n.constData(), kDirFlags));
            if (s.fd < 0 || t.fd < 0) continue;
            const qint64 c = copyDir(s.fd, t.fd, depth + 1, error);
            if (c > 0) count += c;
            ++count;
        } else if (S_ISLNK(st.st_mode)) {
            QByteArray target(PATH_MAX, '\0');
            const ssize_t len = ::readlinkat(srcFd, n.constData(), target.data(), target.size());
            if (len < 0) continue;
            target.resize(len);
            ::unlinkat(dstFd, n.constData(), 0);
            if (::symlinkat(target.constData(), dstFd, n.constData()) == 0) ++count;
        } else if (S_ISREG(st.st_mode)) {
            Fd s(::openat(srcFd, n.constData(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC));
            if (s.fd < 0) continue;
            ::unlinkat(dstFd, n.constData(), 0);
            Fd t(::openat(dstFd, n.constData(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, perm | 0600));
            if (t.fd < 0) {
                if (error) *error = QString::fromLocal8Bit(std::strerror(errno));
                continue;
            }
            char buf[1 << 16];
            for (;;) {
                const ssize_t r = ::read(s.fd, buf, sizeof buf);
                if (r < 0 && errno == EINTR) continue;
                if (r <= 0) break;
                ssize_t off = 0;
                while (off < r) {
                    const ssize_t w = ::write(t.fd, buf + off, static_cast<size_t>(r - off));
                    if (w < 0 && errno == EINTR) continue;
                    if (w <= 0) { off = r; break; }
                    off += w;
                }
            }
            ::fchmod(t.fd, perm);
            ++count;
        }
    }
    return count;
}

qint64 copyTree(const QString &src, const QString &dst, QString *error)
{
    Fd s(::open(enc(src).constData(), kDirFlags));
    if (s.fd < 0) { if (error) *error = QStringLiteral("cannot open source"); return -1; }
    ::mkdir(enc(dst).constData(), 0755);
    Fd t(::open(enc(dst).constData(), kDirFlags));
    if (t.fd < 0) { if (error) *error = QStringLiteral("cannot open destination"); return -1; }
    return copyDir(s.fd, t.fd, 0, error);
}

static void sanitizeFd(int dirFd, int depth)
{
    if (depth > 128) return;
    const int dupFd = ::fcntl(dirFd, F_DUPFD_CLOEXEC, 0);
    if (dupFd < 0) return;
    DIR *d = ::fdopendir(dupFd);
    if (!d) { ::close(dupFd); return; }
    QVector<QByteArray> names;
    while (dirent *e = ::readdir(d)) {
        if (!std::strcmp(e->d_name, ".") || !std::strcmp(e->d_name, "..")) continue;
        names << QByteArray(e->d_name);
    }
    ::closedir(d);
    for (const QByteArray &n : names) {
        struct stat st{};
        if (::fstatat(dirFd, n.constData(), &st, AT_SYMLINK_NOFOLLOW) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            if (::fchmodat(dirFd, n.constData(), (st.st_mode & 0755) | 0700, 0) != 0) { /* best effort */ }
            Fd sub(::openat(dirFd, n.constData(), kDirFlags));
            if (sub.fd >= 0) sanitizeFd(sub.fd, depth + 1);
        } else if (S_ISREG(st.st_mode)) {
            if (st.st_mode & (S_ISUID | S_ISGID | S_ISVTX | 0022))
                if (::fchmodat(dirFd, n.constData(), (st.st_mode & 0755) | 0600, 0) != 0) { /* best effort */ }
        } else if (!S_ISLNK(st.st_mode)) {
            ::unlinkat(dirFd, n.constData(), 0); // devices, fifos, sockets
        }
    }
}

void sanitizeTree(const QString &root)
{
    Fd r(::open(enc(root).constData(), kDirFlags));
    if (r.fd >= 0) sanitizeFd(r.fd, 0);
}

} // namespace ps::securefs
