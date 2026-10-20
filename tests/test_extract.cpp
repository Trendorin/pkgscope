// SPDX-License-Identifier: MIT
//
// Hostile archives must never write outside the extraction directory, must not
// write through symlinks or hardlinks, and must not leave privileged modes or
// device nodes behind.

#include "core/ArchiveReader.h"
#include "core/SecureFs.h"

#include <QDir>
#include <QFile>
#include <QTemporaryDir>

#include <archive.h>
#include <archive_entry.h>
#include <cstdio>
#include <cstring>
#include <sys/sysmacros.h>
#include <sys/stat.h>

using namespace ps;

namespace {

int g_failed = 0;

void check(bool ok, const char *what)
{
    std::printf("%s  %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) ++g_failed;
}

struct Entry {
    const char *name;
    mode_t type;
    mode_t perm = 0644;
    const char *data = "";
    const char *link = nullptr; // symlink target or hardlink source
    bool hardlink = false;
};

QString writeTar(const QString &path, std::initializer_list<Entry> entries)
{
    archive *a = archive_write_new();
    archive_write_set_format_pax_restricted(a);
    archive_write_open_filename(a, QFile::encodeName(path).constData());
    for (const Entry &e : entries) {
        archive_entry *en = archive_entry_new();
        archive_entry_set_pathname(en, e.name);
        archive_entry_set_filetype(en, e.type);
        archive_entry_set_perm(en, e.perm);
        if (e.link && e.hardlink) archive_entry_set_hardlink(en, e.link);
        else if (e.link) archive_entry_set_symlink(en, e.link);
        const size_t len = std::strlen(e.data);
        archive_entry_set_size(en, e.type == AE_IFREG && !e.hardlink ? static_cast<la_int64_t>(len) : 0);
        if (e.type == AE_IFCHR) archive_entry_set_rdev(en, makedev(1, 3));
        archive_write_header(a, en);
        if (e.type == AE_IFREG && len && !e.hardlink) archive_write_data(a, e.data, len);
        archive_entry_free(en);
    }
    archive_write_close(a);
    archive_write_free(a);
    return path;
}

bool emptyDir(const QString &dir)
{
    return QDir(dir).entryList(QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System).isEmpty();
}

} // namespace

int main()
{
    QTemporaryDir tmp;
    if (!tmp.isValid()) return 2;
    const QString outside = tmp.filePath(QStringLiteral("outside"));
    const QString dest = tmp.filePath(QStringLiteral("work/dest"));
    QDir().mkpath(outside);
    QDir().mkpath(dest);
    QFile secret(tmp.filePath(QStringLiteral("outside-secret")));
    if (!secret.open(QIODevice::WriteOnly)) return 2;
    secret.write("do not touch");
    secret.close();

    const QByteArray outsideAbs = QFile::encodeName(outside);
    const QByteArray secretAbs = QFile::encodeName(secret.fileName());
    const QString tar = writeTar(tmp.filePath(QStringLiteral("evil.tar")), {
        {"../outside/escaped", AE_IFREG, 0644, "x"},
        {"../../work-escaped", AE_IFREG, 0644, "x"},
        {"/abs-file", AE_IFREG, 0644, "abs"},
        {"lnk", AE_IFLNK, 0777, "", outsideAbs.constData()},
        {"lnk/through-symlink", AE_IFREG, 0644, "x"},
        {"up", AE_IFLNK, 0777, "", "../.."},
        {"up/work/through-relative-symlink", AE_IFREG, 0644, "x"},
        {"hard", AE_IFREG, 0644, "", secretAbs.constData(), true},
        {"hard-rel", AE_IFREG, 0644, "", "../../outside-secret", true},
        {"suid", AE_IFREG, 04755, "#!/bin/sh\n"},
        {"dev-null", AE_IFCHR, 0666},
        {"ok/normal.txt", AE_IFREG, 0644, "hello"},
    });

    ExtractStats st;
    const bool ok = ArchiveReader::extractFile(tar, ArchiveKind::Tar, dest, ExtractLimits{}, &st, nullptr);
    check(ok, "archive with hostile entries is still processed");
    check(emptyDir(outside), "nothing was written into the sibling directory");
    check(!QFileInfo::exists(tmp.filePath(QStringLiteral("work-escaped"))), "../../ traversal did not escape");
    check(!QFileInfo::exists(QStringLiteral("/abs-file")), "absolute path did not land in /");
    {
        QFile s(secret.fileName());
        check(s.open(QIODevice::ReadOnly), "the file outside is still readable");
        check(s.readAll() == "do not touch", "the file outside was not modified through a hardlink");
    }
    check(!QFileInfo(dest + QStringLiteral("/hard")).exists() || QFileInfo(dest + QStringLiteral("/hard")).size() == 0,
          "absolute hardlink did not copy outside content");
    check(securefs::readBeneath(dest, QStringLiteral("lnk/through-symlink"), 16).isEmpty(), "no write through an absolute symlink");
    check(QFile(dest + QStringLiteral("/ok/normal.txt")).exists(), "normal file extracted");
    struct stat sb{};
    if (::lstat(QFile::encodeName(dest + QStringLiteral("/suid")).constData(), &sb) == 0)
        check((sb.st_mode & (S_ISUID | S_ISGID)) == 0, "setuid bit stripped");
    check(::lstat(QFile::encodeName(dest + QStringLiteral("/dev-null")).constData(), &sb) != 0 || !S_ISCHR(sb.st_mode),
          "device node not created");
    check(!st.unsafeEntries.isEmpty(), "unsafe entries are reported");

    // Size limit (zip bomb guard).
    const QString big = writeTar(tmp.filePath(QStringLiteral("big.tar")), {
        {"a", AE_IFREG, 0644, "0123456789012345678901234567890123456789"},
        {"b", AE_IFREG, 0644, "0123456789012345678901234567890123456789"},
    });
    ExtractStats st2;
    ExtractLimits lim;
    lim.maxTotalBytes = 50;
    ArchiveReader::extractFile(big, ArchiveKind::Tar, tmp.filePath(QStringLiteral("dest2")), lim, &st2, nullptr);
    check(st2.truncated || !st2.error.isEmpty(), "size limit stops extraction");

    // Hardlinks are copies: each one counts against the limit.
    const QString links = writeTar(tmp.filePath(QStringLiteral("links.tar")), {
        {"a", AE_IFREG, 0644, "0123456789012345678901234567890123456789"},
        {"b", AE_IFREG, 0644, "", "a", true},
        {"c", AE_IFREG, 0644, "", "a", true},
        {"d", AE_IFREG, 0644, "", "a", true},
    });
    ExtractStats st3;
    ExtractLimits lim3;
    lim3.maxTotalBytes = 100;
    ArchiveReader::extractFile(links, ArchiveKind::Tar, tmp.filePath(QStringLiteral("dest3")), lim3, &st3, nullptr);
    check(st3.totalBytes <= 100 && st3.truncated, "hardlink copies count against the size limit");

    // Name sanitizer.
    bool trav = false;
    check(securefs::sanitizeRelative(QStringLiteral("a/../../b"), &trav).isEmpty() || !securefs::sanitizeRelative(QStringLiteral("a/../../b")).contains(QLatin1String("..")),
          "sanitizeRelative removes ..");
    check(securefs::sanitizeRelative(QStringLiteral("./usr//bin/x")) == QLatin1String("usr/bin/x"), "sanitizeRelative normalises");

    std::printf("%s\n", g_failed ? "FAILED" : "all passed");
    return g_failed ? 1 : 0;
}
