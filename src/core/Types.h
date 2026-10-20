// SPDX-License-Identifier: MIT
#pragma once

#include <QDateTime>
#include <QMap>
#include <QString>
#include <QStringList>
#include <QVector>

namespace ps {

enum class Severity { Info = 0, Low, Medium, High, Critical };

QString severityName(Severity s);
Severity severityFromName(const QString &s);
int severityWeight(Severity s);
Severity downgrade(Severity s);

struct Finding {
    Severity severity = Severity::Info;
    QString ruleId;     // stable identifier, e.g. "persist.cron"
    QString category;   // Persistence, Network, Privilege, ...
    QString title;      // one-line human summary
    QString detail;     // why it matters
    QString location;   // path inside package / sandbox
    int line = 0;       // 1-based line for text files
    QString evidence;   // matched snippet (untrusted text!)
    QString origin;     // "static" | "dynamic"
};

struct FileEntry {
    QString path;        // absolute install path, e.g. /usr/bin/foo
    QString type;        // file, dir, symlink, hardlink, char, block, fifo, socket
    QString linkTarget;
    quint64 size = 0;
    quint32 mode = 0;    // original mode from the package (incl. suid bits)
    QString owner;       // user:group as recorded in the package
    QString sha256;
    QString kind;        // ELF, Script, Text, Data, Kernel module, ...
    QStringList flags;   // setuid, setgid, world-writable, conffile, hidden, ...
    bool conffile = false;
};

struct ElfInfo {
    QString path;
    QString elfClass;    // ELF32 / ELF64
    QString machine;
    QString elfType;     // Executable, PIE executable, Shared object, Relocatable, Core
    QString interpreter;
    QString soname;
    QString language;    // C/C++, Go, Rust, ...
    QString relro;       // Full / Partial / None
    QStringList needed, rpath, runpath;
    QStringList notableImports;
    QStringList libcOverrides;
    QMap<QString, QString> modinfo; // kernel modules
    double entropy = 0.0;
    bool pie = false, nx = true, canary = false, fortify = false;
    bool stripped = true, staticLinked = false, rwxSegment = false;
    bool noSectionHeaders = false, upx = false;
};

struct ScriptEntry {
    QString name;        // postinst, .INSTALL, %post ...
    QString stage;       // Pre-install, Post-install, ...
    QString interpreter;
    QString content;     // untrusted text
    QVector<int> flaggedLines;
};

struct Indicator {
    QString type;        // url, ip, domain, email, onion
    QString value;
    QString source;
    int count = 1;
    bool likelyBenign = false;
};

struct PackageMeta {
    QString name, version, arch, maintainer, description, homepage, license;
    QStringList depends;
    QMap<QString, QString> extra;
};

// ---- Behaviour (dynamic) ----------------------------------------------------

struct ProcessInfo {
    int pid = 0;
    int ppid = 0;
    QString stage;
    QString exe;
    QStringList argv;
    QString cwd;
    double start = 0;     // seconds since run start
    int exitCode = -1;
    QString exitSignal;
    bool execFailed = false;
};

struct FsEvent {
    double t = 0;
    int pid = 0;
    QString stage;
    QString op;           // write, create, delete, rename, mkdir, chmod, chown, symlink, link, read-sensitive, exec
    QString path;
    QString path2;
    QString detail;
    bool ok = true;
    QString error;
};

struct NetEvent {
    double t = 0;
    int pid = 0;
    QString stage;
    QString op;           // connect, sendto, bind, listen, socket
    QString family;       // inet, inet6, unix, netlink, packet
    QString proto;        // tcp, udp, raw
    QString address;
    int port = 0;
    QString domain;       // from DNS query / SNI / Host header
    bool ok = true;
    QString error;
};

struct FsChange {
    QString path;
    QString change;       // installed, created, modified, metadata, deleted
    QString type;         // file, dir, symlink
    quint64 size = 0;
    quint32 mode = 0;
    QString sha256;
    QString linkTarget;
};

struct StageResult {
    QString name;
    QString command;
    int exitCode = -1;
    QString exitSignal;
    bool timedOut = false;
    double duration = 0;
    QString output;       // captured stdout/stderr tail (untrusted)
};

struct BehaviorReport {
    bool ran = false;
    bool networkAllowed = false;
    bool displayAllowed = false;
    QString sandboxNotes;
    QVector<StageResult> stages;
    QVector<ProcessInfo> processes;
    QVector<FsEvent> fsEvents;
    QVector<NetEvent> netEvents;
    QStringList dnsQueries;
    QVector<FsChange> changes;
    QVector<ElfInfo> droppedBinaries;
    QVector<Finding> findings;
    double duration = 0;
};

struct AnalysisResult {
    QString inputPath;
    QString fileName;
    quint64 fileSize = 0;
    QString sha256;
    QString sha1;
    QString formatId;     // deb, rpm, arch, alpine, xbps, slackware, ipk, appimage, snap, elf, script, tarball, zip, unknown
    QString formatName;   // human readable
    PackageMeta meta;
    QVector<FileEntry> files;
    QVector<ElfInfo> binaries;
    QVector<ScriptEntry> scripts;
    QVector<Indicator> indicators;
    QVector<Finding> findings;
    QStringList log;
    QDateTime analyzedAt;
    qint64 durationMs = 0;
    bool truncated = false;
    BehaviorReport behavior;

    QVector<Finding> allFindings() const;
    int riskScore() const;
    QString verdict() const;
    int countAtLeast(Severity s) const;
};

} // namespace ps
