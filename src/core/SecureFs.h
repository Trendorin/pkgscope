// SPDX-License-Identifier: MIT
#pragma once

#include <QByteArray>
#include <QString>

#include <functional>
#include <sys/stat.h>

namespace ps::securefs {

// Normalises an archive member name into a safe relative path.
// Returns empty string if the name is unsafe (contains "..", NUL, or is empty).
// `hadTraversal` is set when the original name tried to escape.
QString sanitizeRelative(const QString &name, bool *hadTraversal = nullptr);

// Opens `rel` beneath `root` without following any symlink in any component.
// Returns -1 on failure (errno set). Flags are passed to the final openat().
int openBeneath(const QString &root, const QString &rel, int flags);

// Reads at most `maxBytes` from a regular file beneath root (no symlink following).
QByteArray readBeneath(const QString &root, const QString &rel, qint64 maxBytes, bool *truncated = nullptr);

// SHA-256 (and optionally MD5) of a regular file beneath root.
bool hashBeneath(const QString &root, const QString &rel, QByteArray *sha256, QByteArray *md5 = nullptr);

// Creates directories (mode 0700/0755) for rel's parent chain beneath root.
// Fails if any component exists and is not a real directory.
int mkdirsBeneath(int rootFd, const QString &relDir);

// Recursively walks a tree without following symlinks. Callback gets the
// relative path (no leading slash) and lstat info; return false to stop.
using WalkFn = std::function<bool(const QString &rel, const struct stat &st)>;
bool walk(const QString &root, const WalkFn &fn, int maxDepth = 64);

// Robust recursive delete: fixes permissions on the fly, never follows symlinks.
bool removeTree(const QString &path);

// Copies a tree (files, dirs, symlinks only) from src to dst, merging into dst.
// Modes are sanitised (no suid/sgid/sticky). Returns number of entries copied, -1 on error.
qint64 copyTree(const QString &src, const QString &dst, QString *error = nullptr);

// Strips setuid/setgid/sticky bits and device nodes inside an extracted tree.
void sanitizeTree(const QString &root);

} // namespace ps::securefs
