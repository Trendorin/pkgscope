// SPDX-License-Identifier: MIT
#include "DynamicTracer.h"
#include "ContentScanner.h"
#include "SecureFs.h"
#include "StaticAnalyzer.h"
#include "StraceParser.h"
#include "Util.h"

#include <QCryptographicHash>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QRandomGenerator>
#include <QRegularExpression>
#include <QSet>
#include <QThread>

#include <csignal>
#include <fcntl.h>
#include <sys/stat.h>
#include <climits>
#include <unistd.h>

namespace ps {

namespace {

const QStringList kOverlayTops = {QStringLiteral("usr"), QStringLiteral("etc"), QStringLiteral("opt"), QStringLiteral("var"),
                                  QStringLiteral("bin"), QStringLiteral("sbin"), QStringLiteral("lib"), QStringLiteral("lib32"),
                                  QStringLiteral("lib64"), QStringLiteral("libx32"), QStringLiteral("home"), QStringLiteral("root"),
                                  QStringLiteral("tmp")};

// Root-owned copy of the helper that the AppArmor profile of source and AppImage installs names.
constexpr char kSystemHelper[] = "/usr/local/libexec/pkgscope/pkgscope-sandbox";

const char *kTraceSet =
    "?open,openat,?openat2,?creat,?mkdir,mkdirat,?unlink,unlinkat,?rmdir,?rename,renameat,?renameat2,?link,linkat,"
    "?symlink,symlinkat,?chmod,fchmod,fchmodat,?fchmodat2,?chown,?lchown,fchown,fchownat,truncate,execve,execveat,"
    "clone,?clone3,?fork,?vfork,chdir,fchdir,socket,connect,bind,listen,sendto,sendmsg,?sendmmsg,ptrace,init_module,"
    "finit_module,delete_module,mount,umount2,pivot_root,unshare,setns,memfd_create,bpf,keyctl,add_key,perf_event_open,"
    "?io_uring_setup,setuid,setgid,setresuid,setresgid,setreuid,capset";

QString readSmall(const QString &path, qint64 max = 1 << 20)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return {};
    return QString::fromUtf8(f.read(max));
}

QString readTail(const QString &path, qint64 max)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return {};
    if (f.size() > max) f.seek(f.size() - max);
    QString s = QString::fromUtf8(f.readAll());
    if (f.size() > max) s.prepend(QStringLiteral("[… output truncated …]\n"));
    return s;
}

QByteArray hostSha256(const QString &path, quint32 *mode = nullptr, bool *readable = nullptr)
{
    if (readable) *readable = false;
    const int fd = ::open(QFile::encodeName(path).constData(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return {};
    struct stat st{};
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) { ::close(fd); return {}; }
    if (mode) *mode = st.st_mode;
    QCryptographicHash h(QCryptographicHash::Sha256);
    char buf[1 << 16];
    ssize_t r;
    while ((r = ::read(fd, buf, sizeof buf)) > 0) h.addData(QByteArrayView(buf, r));
    ::close(fd);
    if (readable) *readable = r == 0;
    return h.result();
}

} // namespace

DynamicTracer::DynamicTracer(Settings s, const StaticAnalyzer *analyzer) : m_s(std::move(s)), m_analyzer(analyzer) {}

DynamicTracer::Environment DynamicTracer::probe(const Settings &s)
{
    Environment env;
    env.helper = util::findHelper(QStringLiteral("pkgscope-sandbox"));
    if (env.helper.isEmpty()) env.problems << QStringLiteral("The sandbox helper 'pkgscope-sandbox' was not found next to the application.");
    env.strace = (!s.straceOverride.isEmpty() && QFileInfo(s.straceOverride).isExecutable()) ? s.straceOverride : util::findHelper(QStringLiteral("strace"));
    if (env.strace.isEmpty()) {
        env.problems << QStringLiteral("strace is not installed (Arch: sudo pacman -S strace · Debian/Ubuntu: sudo apt install strace · Fedora: sudo dnf install strace).");
    } else {
        QProcess p;
        p.start(env.strace, {QStringLiteral("-V")});
        if (p.waitForFinished(3000)) env.straceVersion = QString::fromUtf8(p.readAllStandardOutput()).section(QLatin1Char('\n'), 0, 0).trimmed();
    }
    const auto sysctl = [](const char *path) -> int {
        QFile f(QString::fromLatin1(path));
        if (!f.open(QIODevice::ReadOnly)) return -1;
        return f.readAll().trimmed().toInt();
    };
    if (sysctl("/proc/sys/kernel/unprivileged_userns_clone") == 0)
        env.problems << QStringLiteral("Unprivileged user namespaces are disabled (kernel.unprivileged_userns_clone=0).");
    if (sysctl("/proc/sys/user/max_user_namespaces") == 0)
        env.problems << QStringLiteral("User namespaces are disabled (user.max_user_namespaces=0).");
    const int yama = sysctl("/proc/sys/kernel/yama/ptrace_scope");
    if (yama >= 2)
        env.problems << QStringLiteral("ptrace is restricted (kernel.yama.ptrace_scope=%1); strace cannot trace processes.").arg(yama);
    {
        QFile fs(QStringLiteral("/proc/filesystems"));
        if (fs.open(QIODevice::ReadOnly) && !fs.readAll().contains("\toverlay\n"))
            env.notes << QStringLiteral("overlayfs is not loaded, so system directories can only be mounted read-only and installers cannot write there. "
                                        "Load it with: sudo modprobe overlay (the PkgScope packages load it at boot).");
    }
    if (sysctl("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") == 1) {
        // AppArmor lets only a profiled helper create user namespaces. The profile must name a
        // root-owned file: one under ~/.local (source install) or inside an AppImage could be
        // swapped by any program of the user. "install.sh --setup" and "PkgScope.AppImage
        // --setup-sandbox" put such a copy here; packages install theirs under /usr already.
        const QString system = QString::fromLatin1(kSystemHelper);
        struct stat st{};
        if (!env.helper.startsWith(QLatin1String("/usr/")) && ::stat(kSystemHelper, &st) == 0 && st.st_uid == 0 &&
            ::access(kSystemHelper, X_OK) == 0)
            env.helper = system;
        if (!env.helper.startsWith(QLatin1String("/usr/")))
            env.notes << (qEnvironmentVariableIsSet("APPIMAGE")
                              ? QStringLiteral("AppArmor restricts unprivileged user namespaces. To trace from the AppImage, run it once with "
                                               "--setup-sandbox (asks for your password), or install the distribution package.")
                              : QStringLiteral("AppArmor restricts unprivileged user namespaces. Run ./install.sh --setup once "
                                               "(asks for your password), or install the distribution package."));
    }
    return env;
}

bool DynamicTracer::run(AnalysisResult &r, Workspace &ws, const Progress &progress, const std::atomic<bool> *cancel)
{
    BehaviorReport &out = r.behavior;
    out = BehaviorReport();
    out.networkAllowed = m_s.allowNetwork;
    out.displayAllowed = m_s.allowDisplay;
    const Environment env = probe(m_s);
    if (!env.ready()) {
        out.sandboxNotes = env.problems.join(QLatin1Char('\n'));
        return false;
    }
    if (!ws.plan.supported || ws.plan.stages.isEmpty()) {
        out.sandboxNotes = ws.plan.reason.isEmpty() ? QStringLiteral("Nothing to execute for this file type.") : ws.plan.reason;
        return false;
    }

    // Fresh run directory
    int n = 0;
    QString runDir;
    do {
        runDir = ws.runsDir() + QStringLiteral("/run-%1").arg(++n);
    } while (QFileInfo::exists(runDir));
    for (const QString &d : {QStringLiteral(""), QStringLiteral("/root"), QStringLiteral("/upper"), QStringLiteral("/work"), QStringLiteral("/logs")})
        ::mkdir(QFile::encodeName(runDir + d).constData(), 0700);
    ::chmod(QFile::encodeName(runDir + QStringLiteral("/root")).constData(), 0755);
    if (ws.plan.bindPayloadAsSource) {
        QString err;
        securefs::copyTree(ws.payloadDir(), runDir + QStringLiteral("/src"), &err);
    }

    QStringList notes = env.notes;
    notes << QStringLiteral("Tracer: %1").arg(env.straceVersion.isEmpty() ? env.strace : env.straceVersion);
    notes << QStringLiteral("Network: %1").arg(m_s.allowNetwork ? QStringLiteral("shared with host (allowed in Settings)")
                                                              : QStringLiteral("isolated — connection attempts are recorded but fail"));
    if (m_s.allowDisplay) notes << QStringLiteral("Display access: Wayland/X11 socket passed into the sandbox (reduced isolation).");
    if (r.formatId == QLatin1String("deb") && !QFileInfo::exists(QStringLiteral("/usr/bin/dpkg")))
        notes << QStringLiteral("Maintainer scripts run against this system's userland; Debian-specific helpers (dpkg, debconf, deb-systemd-helper) may be missing, so some commands fail.");
    if (r.formatId == QLatin1String("rpm") && !QFileInfo::exists(QStringLiteral("/usr/bin/rpm")))
        notes << QStringLiteral("RPM scriptlets run against this system's userland; RPM-specific helpers may be missing.");

    QElapsedTimer total;
    total.start();
    QStringList mountpoints;
    double offset = 0;
    bool ok = true;
    bool payloadPlaced = false;
    for (int i = 0; i < ws.plan.stages.size(); ++i) {
        if (cancel && cancel->load()) { ok = false; break; }
        const TraceStage &st = ws.plan.stages[i];
        if (st.installPayloadBefore && !payloadPlaced && ws.payloadIsInstallTree) {
            if (progress) progress(5 + 80 * i / ws.plan.stages.size(), QStringLiteral("Placing package files into the sandbox"));
            placePayload(ws, runDir, out);
            payloadPlaced = true;
        }
        if (!runStage(st, i, ws, runDir, r, env, out, progress, cancel, mountpoints, offset)) {
            ok = false;
            break;
        }
    }
    if (!payloadPlaced && ws.payloadIsInstallTree && ok) placePayload(ws, runDir, out);

    if (progress) progress(88, QStringLiteral("Comparing filesystem changes"));
    if (!out.stages.isEmpty()) diff(ws, runDir, mountpoints, out);
    out.duration = total.elapsed() / 1000.0;
    out.ran = !out.stages.isEmpty();
    if (!out.sandboxNotes.isEmpty()) notes.prepend(out.sandboxNotes);
    out.sandboxNotes = notes.join(QLatin1Char('\n'));

    if (progress) progress(94, QStringLiteral("Evaluating behaviour"));
    deriveFindings(r, ws, runDir);

    if (progress) progress(98, QStringLiteral("Cleaning up sandbox"));
    if (!m_s.keepRunDir) securefs::removeTree(runDir);
    else out.sandboxNotes += QStringLiteral("\nRun directory kept for inspection: %1").arg(runDir);
    return ok && out.ran;
}

bool DynamicTracer::runStage(const TraceStage &stage, int index, Workspace &ws, const QString &runDir, const AnalysisResult &r,
                             const Environment &env, BehaviorReport &out, const Progress &progress, const std::atomic<bool> *cancel,
                             QStringList &mountpoints, double &timeOffset)
{
    const QString logs = runDir + QStringLiteral("/logs");
    const QString traceLog = logs + QStringLiteral("/trace-%1.log").arg(index);
    const QString statusFile = logs + QStringLiteral("/status-%1").arg(index);
    const QString outputFile = logs + QStringLiteral("/output-%1").arg(index);
    const QByteArray marker = "/.pkgscope-marker-" + QByteArray::number(QRandomGenerator::system()->generate64(), 16);

    QStringList helperArgs = {
        QStringLiteral("--root-dir"), runDir + QStringLiteral("/root"),
        QStringLiteral("--upper"), runDir + QStringLiteral("/upper"),
        QStringLiteral("--work"), runDir + QStringLiteral("/work"),
        QStringLiteral("--status-file"), statusFile,
        QStringLiteral("--output-file"), outputFile,
        QStringLiteral("--marker"), QString::fromLatin1(marker),
        QStringLiteral("--timeout"), QString::number(m_s.traceTimeoutSec),
        QStringLiteral("--grace"), QString::number(m_s.graceSec),
        QStringLiteral("--fsize"), QString::number(qint64(m_s.maxFileSizeMiB) * 1024 * 1024),
        QStringLiteral("--ro-bind"), ws.inputDir(), QStringLiteral("/sandbox/input"),
        QStringLiteral("--ro-bind"), ws.scriptsDir(), QStringLiteral("/sandbox/scripts"),
        QStringLiteral("--chdir"), stage.cwd,
    };
    if (m_s.allowNetwork) helperArgs << QStringLiteral("--net");
    if (ws.plan.bindPayloadAsAppDir) {
        helperArgs << QStringLiteral("--ro-bind") << ws.payloadDir() << QStringLiteral("/sandbox/appdir");
        helperArgs << QStringLiteral("--ro-bind") << r.inputPath << QStringLiteral("/sandbox/input-image");
    }
    if (ws.plan.bindPayloadAsSource) helperArgs << QStringLiteral("--rw-bind") << runDir + QStringLiteral("/src") << QStringLiteral("/sandbox/src");
    QStringList env2 = stage.env;
    for (QString &e : env2)
        if (e.startsWith(QLatin1String("APPIMAGE="))) e = QStringLiteral("APPIMAGE=/sandbox/input-image");
    if (m_s.allowDisplay) {
        const QString xdg = qEnvironmentVariable("XDG_RUNTIME_DIR");
        const QString wl = qEnvironmentVariable("WAYLAND_DISPLAY", QStringLiteral("wayland-0"));
        if (!xdg.isEmpty() && QFileInfo::exists(xdg + QLatin1Char('/') + wl) && !wl.contains(QLatin1Char('/'))) {
            helperArgs << QStringLiteral("--ro-bind") << xdg + QLatin1Char('/') + wl << QStringLiteral("/run/user/0/") + wl;
            env2 << QStringLiteral("WAYLAND_DISPLAY=") + wl << QStringLiteral("QT_QPA_PLATFORM=wayland;xcb")
                 << QStringLiteral("GDK_BACKEND=wayland,x11");
        }
        const QString disp = qEnvironmentVariable("DISPLAY");
        static const QRegularExpression dre(QStringLiteral(R"(^:(\d+)(\.\d+)?$)"));
        const auto m = dre.match(disp);
        if (m.hasMatch() && QFileInfo::exists(QStringLiteral("/tmp/.X11-unix/X") + m.captured(1))) {
            helperArgs << QStringLiteral("--ro-bind") << QStringLiteral("/tmp/.X11-unix/X") + m.captured(1) << QStringLiteral("/tmp/.X11-unix/X") + m.captured(1);
            env2 << QStringLiteral("DISPLAY=") + disp;
            QString xauth = qEnvironmentVariable("XAUTHORITY");
            if (xauth.isEmpty()) xauth = QDir::homePath() + QStringLiteral("/.Xauthority");
            if (QFileInfo(xauth).isFile()) {
                helperArgs << QStringLiteral("--ro-bind") << xauth << QStringLiteral("/sandbox/xauthority");
                env2 << QStringLiteral("XAUTHORITY=/sandbox/xauthority");
            }
        }
    }
    for (const QString &e : env2) helperArgs << QStringLiteral("--setenv") << e;
    helperArgs << QStringLiteral("--") << stage.argv;

    const QStringList straceArgs = QStringList{QStringLiteral("-f"), QStringLiteral("-q"), QStringLiteral("-tt"), QStringLiteral("-xx"),
                                               QStringLiteral("-s"), QStringLiteral("1024"), QStringLiteral("-e"), QStringLiteral("signal=none"),
                                               QStringLiteral("-e"), QStringLiteral("trace=") + QString::fromLatin1(kTraceSet),
                                               QStringLiteral("-o"), traceLog, QStringLiteral("--"), env.helper}
                                 + helperArgs;

    StageResult sr;
    sr.name = stage.name;
    QStringList shown;
    for (const QString &a : stage.argv) shown << util::shellQuote(a);
    sr.command = shown.join(QLatin1Char(' '));

    QProcess proc;
    proc.setProgram(env.strace);
    proc.setArguments(straceArgs);
    proc.setProcessChannelMode(QProcess::MergedChannels);
    proc.setStandardInputFile(QProcess::nullDevice());
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    proc.setChildProcessModifier([] { ::setsid(); });
#endif
    QElapsedTimer t;
    t.start();
    proc.start();
    if (!proc.waitForStarted(10000)) {
        out.sandboxNotes = QStringLiteral("Could not start strace: %1").arg(proc.errorString());
        return false;
    }
    const qint64 pgid = proc.processId();
    const qint64 hardLimitMs = (qint64(m_s.traceTimeoutSec) + m_s.graceSec + 30) * 1000;
    bool killed = false;
    while (!proc.waitForFinished(250)) {
        const qint64 el = t.elapsed();
        if (progress) {
            const int base = 5 + 80 * index / std::max<qsizetype>(1, ws.plan.stages.size());
            progress(base, QStringLiteral("Tracing “%1” — %2 s").arg(stage.name).arg(el / 1000));
        }
        bool stop = (cancel && cancel->load()) || el > hardLimitMs;
        if (QFileInfo(traceLog).size() > 3ll * 1024 * 1024 * 1024) stop = true;
        if (stop) {
            ::kill(-static_cast<pid_t>(pgid), SIGKILL);
            proc.kill();
            proc.waitForFinished(5000);
            killed = true;
            break;
        }
    }
    sr.duration = t.elapsed() / 1000.0;
    const QString straceOut = QString::fromUtf8(proc.readAll()).trimmed();

    // Status from the helper
    const QString status = readSmall(statusFile);
    QString helperError;
    for (const QString &line : status.split(QLatin1Char('\n'), Qt::SkipEmptyParts)) {
        const QString k = line.section(QLatin1Char('='), 0, 0), v = line.section(QLatin1Char('='), 1);
        if (k == QLatin1String("exit")) sr.exitCode = v.toInt();
        else if (k == QLatin1String("signal")) sr.exitSignal = QStringLiteral("signal %1").arg(v);
        else if (k == QLatin1String("timeout")) sr.timedOut = true;
        else if (k == QLatin1String("mountpoint")) mountpoints << v;
        else if (k == QLatin1String("error")) helperError = v;
        else if (k == QLatin1String("background_killed")) sr.output += QStringLiteral("[sandbox] %1 background process(es) were still running and were killed.\n").arg(v);
        else if (k == QLatin1String("overlay") && v != QLatin1String("ok") && index == 0)
            out.sandboxNotes += QStringLiteral("Overlay: %1 — some system directories were mounted read-only; writes there failed but were still recorded.\n").arg(v);
        else if (k == QLatin1String("proc") && v != QLatin1String("ok") && index == 0)
            out.sandboxNotes += QStringLiteral("/proc could not be mounted inside the sandbox.\n");
    }
    if (killed && !sr.timedOut) sr.timedOut = !(cancel && cancel->load());
    sr.output += readTail(outputFile, 64 * 1024);
    if (!straceOut.isEmpty() && sr.exitCode < 0) sr.output += QStringLiteral("\n[strace] ") + straceOut.right(2000);

    StraceParser parser(stage.name, marker, stage.cwd, timeOffset);
    StraceParser::Output po;
    parser.parseFile(traceLog, po);
    out.processes += po.processes;
    out.fsEvents += po.fs;
    out.netEvents += po.net;
    for (const QString &d : po.dns)
        if (!out.dnsQueries.contains(d, Qt::CaseInsensitive)) out.dnsQueries << d;
    if (po.dropped) sr.output += QStringLiteral("\n[pkgscope] %1 events dropped (limit reached).").arg(po.dropped);
    timeOffset += sr.duration;
    out.stages << sr;
    if (!m_s.keepRunDir) QFile::remove(traceLog);

    if (!helperError.isEmpty()) {
        out.sandboxNotes += QStringLiteral("Sandbox setup failed: %1\n").arg(helperError);
        if (helperError.contains(QLatin1String("unshare")) || helperError.contains(QLatin1String("uid_map")) || helperError.contains(QLatin1String("mount")))
            out.sandboxNotes += QStringLiteral("Your system blocks unprivileged user namespaces for this program. On Ubuntu 24.04+ the helper "
                                               "needs its AppArmor profile: install the package, run ./install.sh --setup, or start the "
                                               "AppImage once with --setup-sandbox.\n");
        return false;
    }
    if (!po.markerSeen) {
        out.sandboxNotes += QStringLiteral("The traced program never started (no trace marker). strace said: %1\n").arg(util::elide(straceOut, 400));
        return false;
    }
    return !(cancel && cancel->load());
}

void DynamicTracer::placePayload(Workspace &ws, const QString &runDir, BehaviorReport &out)
{
    QDir pd(ws.payloadDir());
    for (const QString &name : pd.entryList(QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System)) {
        QString destRel = name;
        const QFileInfo host(QLatin1Char('/') + name);
        if (host.isSymLink()) {
            const QString target = QFile::symLinkTarget(QLatin1Char('/') + name);
            // e.g. /bin -> /usr/bin (usr-merge): place files where they will really be visible
            if (target.startsWith(QLatin1String("/usr/"))) destRel = target.mid(1);
        }
        const QString top = destRel.section(QLatin1Char('/'), 0, 0);
        const QString base = kOverlayTops.contains(top) ? runDir + QStringLiteral("/upper/") : runDir + QStringLiteral("/root/");
        const QString src = ws.payloadDir() + QLatin1Char('/') + name;
        const QString dst = base + destRel;
        QDir().mkpath(QFileInfo(dst).path());
        struct stat st{};
        if (::lstat(QFile::encodeName(src).constData(), &st) != 0) continue;
        QString err;
        if (S_ISDIR(st.st_mode)) {
            if (securefs::copyTree(src, dst, &err) < 0)
                out.sandboxNotes += QStringLiteral("Could not stage %1: %2\n").arg(name, err);
        } else if (S_ISLNK(st.st_mode)) {
            // Recreate the link itself. QFile::copy would follow it and put the host file it
            // points to (say ~/.ssh/id_rsa) into the sandbox as a regular file.
            char target[PATH_MAX];
            const ssize_t n = ::readlink(QFile::encodeName(src).constData(), target, sizeof target - 1);
            if (n > 0) {
                target[n] = '\0';
                QFile::remove(dst);
                if (::symlink(target, QFile::encodeName(dst).constData()) != 0)
                    out.sandboxNotes += QStringLiteral("Could not stage the link %1\n").arg(name);
            }
        } else if (S_ISREG(st.st_mode)) {
            QFile::remove(dst);
            QFile::copy(src, dst);
        }
    }
}

void DynamicTracer::diff(Workspace &ws, const QString &runDir, const QStringList &mountpoints, BehaviorReport &out)
{
    QSet<QString> payloadPaths;
    for (auto it = ws.payloadSha256.constBegin(); it != ws.payloadSha256.constEnd(); ++it) payloadPaths.insert(it.key());
    // usr-merge aliases (/bin/x installed into /usr/bin/x)
    QHash<QString, QString> alias;
    for (const QString &p : std::as_const(payloadPaths)) {
        const QString top = p.section(QLatin1Char('/'), 1, 1);
        const QFileInfo host(QLatin1Char('/') + top);
        if (host.isSymLink()) {
            const QString t = QFile::symLinkTarget(QLatin1Char('/') + top);
            if (t.startsWith(QLatin1String("/usr/"))) alias.insert(t + p.mid(top.size() + 1), p);
        }
    }
    const QSet<QString> mp(mountpoints.begin(), mountpoints.end());
    const auto isPrivate = [](const QString &rel) {
        return rel == QLatin1String("home") || rel == QLatin1String("root") || rel == QLatin1String("tmp")
            || rel.startsWith(QLatin1String("home/")) || rel.startsWith(QLatin1String("root/")) || rel.startsWith(QLatin1String("tmp/"));
    };
    const int maxChanges = 100000;

    const auto addChange = [&](const QString &root, const QString &rel, const struct stat &st, const QString &change) {
        if (out.changes.size() >= maxChanges) return;
        FsChange c;
        c.path = QLatin1Char('/') + rel;
        c.change = change;
        c.mode = st.st_mode;
        if (S_ISDIR(st.st_mode)) c.type = QStringLiteral("dir");
        else if (S_ISLNK(st.st_mode)) {
            c.type = QStringLiteral("symlink");
            c.linkTarget = QFile::symLinkTarget(root + QLatin1Char('/') + rel);
            QByteArray buf(4096, '\0');
            const ssize_t n = ::readlink(QFile::encodeName(root + QLatin1Char('/') + rel).constData(), buf.data(), buf.size());
            if (n > 0) c.linkTarget = QFile::decodeName(buf.left(n));
        } else if (S_ISCHR(st.st_mode)) c.type = QStringLiteral("whiteout");
        else c.type = QStringLiteral("file");
        c.size = S_ISREG(st.st_mode) ? static_cast<quint64>(st.st_size) : 0;
        if (S_ISREG(st.st_mode)) {
            QByteArray sha;
            if (securefs::hashBeneath(root, rel, &sha)) c.sha256 = util::hexDigest(sha);
        }
        out.changes << c;
    };

    const QString upper = runDir + QStringLiteral("/upper");
    securefs::walk(upper, [&](const QString &rel, const struct stat &st) {
        if (out.changes.size() >= maxChanges) return false;
        const QString abs = QLatin1Char('/') + rel;
        if (rel.startsWith(QLatin1String("tmp/.X11-unix"))) return true;
        const bool priv = isPrivate(rel);
        if (rel == QLatin1String("home") || rel == QLatin1String("root") || rel == QLatin1String("tmp")) return true;
        const QString payloadKey = alias.value(abs, abs);
        if (S_ISCHR(st.st_mode) && st.st_rdev == 0) {
            addChange(upper, rel, st, QStringLiteral("deleted"));
            return true;
        }
        if (S_ISDIR(st.st_mode)) {
            if (priv) {
                addChange(upper, rel, st, QStringLiteral("created"));
                return true;
            }
            struct stat hs{};
            if (::lstat(QFile::encodeName(abs).constData(), &hs) == 0 && S_ISDIR(hs.st_mode)) return true;
            bool payloadDir = false;
            for (const QString &p : std::as_const(payloadPaths))
                if (p.startsWith(abs + QLatin1Char('/'))) { payloadDir = true; break; }
            if (!payloadDir) addChange(upper, rel, st, QStringLiteral("created"));
            return true;
        }
        if (payloadPaths.contains(payloadKey)) {
            if (S_ISREG(st.st_mode)) {
                QByteArray sha;
                securefs::hashBeneath(upper, rel, &sha);
                addChange(upper, rel, st, util::hexDigest(sha) == ws.payloadSha256.value(payloadKey) || ws.payloadSha256.value(payloadKey).isEmpty()
                                              ? QStringLiteral("installed") : QStringLiteral("modified"));
            } else {
                addChange(upper, rel, st, QStringLiteral("installed"));
            }
            return true;
        }
        if (priv) {
            addChange(upper, rel, st, QStringLiteral("created"));
            return true;
        }
        struct stat hs{};
        if (::lstat(QFile::encodeName(abs).constData(), &hs) != 0) {
            addChange(upper, rel, st, QStringLiteral("created"));
            return true;
        }
        if (S_ISLNK(st.st_mode)) {
            if (S_ISLNK(hs.st_mode) && QFile::symLinkTarget(abs) == QFile::symLinkTarget(upper + abs)) return true;
            addChange(upper, rel, st, QStringLiteral("modified"));
            return true;
        }
        if (S_ISREG(st.st_mode)) {
            quint32 hostMode = 0;
            bool readable = false;
            const QByteArray hostSha = hostSha256(abs, &hostMode, &readable);
            QByteArray sha;
            securefs::hashBeneath(upper, rel, &sha);
            if (readable && hostSha == sha) {
                if ((hostMode & 07777) != (st.st_mode & 07777)) addChange(upper, rel, st, QStringLiteral("metadata"));
                return true;
            }
            addChange(upper, rel, st, QStringLiteral("modified"));
        }
        return true;
    });

    const QString root = runDir + QStringLiteral("/root");
    static const QSet<QString> fixed = {QStringLiteral("dev"), QStringLiteral("proc"), QStringLiteral("sys"), QStringLiteral("run"), QStringLiteral("sandbox")};
    securefs::walk(root, [&](const QString &rel, const struct stat &st) {
        const QString top = rel.section(QLatin1Char('/'), 0, 0);
        if (fixed.contains(top) || mp.contains(rel)) return true;
        if (kOverlayTops.contains(top) && !rel.contains(QLatin1Char('/'))) return true;
        // anything under a mountpoint dir that is itself not a mountpoint was written in "split" mode
        addChange(root, rel, st, payloadPaths.contains(QLatin1Char('/') + rel) ? QStringLiteral("installed") : QStringLiteral("created"));
        return out.changes.size() < maxChanges;
    });
    if (ws.plan.bindPayloadAsSource) {
        // writes inside the extracted source tree are expected; they are not reported
    }

    // Static analysis of dropped / modified files
    if (!m_analyzer) return;
    IndicatorCollector ioc;
    int analysed = 0;
    for (const FsChange &c : std::as_const(out.changes)) {
        if (analysed >= 400) break;
        if (c.type != QLatin1String("file") || (c.change != QLatin1String("created") && c.change != QLatin1String("modified"))) continue;
        const QString rel = c.path.mid(1);
        const QString base = QFileInfo::exists(upper + c.path) ? upper : root;
        m_analyzer->analyzeDroppedFile(base, rel, c.path, out.findings, out.droppedBinaries, ioc);
        ++analysed;
    }
}

void DynamicTracer::deriveFindings(AnalysisResult &r, Workspace &ws, const QString &runDir)
{
    Q_UNUSED(runDir);
    Q_UNUSED(ws);
    BehaviorReport &b = r.behavior;
    QSet<QString> seen;
    const auto add = [&](const QString &id, Severity sev, const QString &cat, const QString &title, const QString &detail,
                         const QString &loc = {}, const QString &ev = {}) {
        const QString key = id + QLatin1Char('|') + loc + QLatin1Char('|') + title;
        if (seen.contains(key)) return;
        seen.insert(key);
        Finding f;
        f.ruleId = id;
        f.severity = sev;
        f.category = cat;
        f.title = title;
        f.detail = detail;
        f.location = loc;
        f.evidence = util::sanitizeOneLine(ev, 300);
        f.origin = QStringLiteral("dynamic");
        b.findings << f;
    };

    QSet<QString> createdPaths;
    int deletedHost = 0, modifiedSystem = 0;
    QStringList deletedList, modifiedList;
    for (const FsChange &c : std::as_const(b.changes)) {
        if (c.change == QLatin1String("installed")) continue;
        if (c.change == QLatin1String("created")) createdPaths.insert(c.path);
        if (c.change == QLatin1String("deleted")) { ++deletedHost; if (deletedList.size() < 10) deletedList << c.path; }
        if (c.change == QLatin1String("modified") && (c.path.startsWith(QLatin1String("/etc/")) || c.path.startsWith(QLatin1String("/usr/")))) {
            ++modifiedSystem;
            if (modifiedList.size() < 10) modifiedList << c.path;
        }
        for (const auto &rule : ContentScanner::persistencePathRules()) {
            if (!rule.re.match(c.path).hasMatch()) continue;
            Severity sev = rule.sev;
            if (rule.id == QLatin1String("path.home")) {
                if (c.path.startsWith(QLatin1String("/root/.cache/")) || c.path.startsWith(QLatin1String("/root/.local/share/"))) break;
                sev = Severity::Low;
            }
            if (rule.id == QLatin1String("path.tmp-exec") && !(c.mode & 0111)) break;
            if (c.type == QLatin1String("dir")) break;
            const QString verb = c.change == QLatin1String("deleted") ? QStringLiteral("Deleted: ") : QString();
            add(QStringLiteral("dyn.") + rule.id, sev, rule.category, verb + rule.title,
                QStringLiteral("Observed at runtime (%1).").arg(c.change), c.path);
            break;
        }
    }
    if (deletedHost > 0)
        add(QStringLiteral("dyn.delete-system"), deletedHost > 20 ? Severity::High : Severity::Medium, QStringLiteral("Filesystem"),
            QStringLiteral("Deleted %1 existing system file(s)").arg(deletedHost),
            QStringLiteral("Packages should only remove their own files. Deletions happened in the sandbox overlay, not on your system."),
            QString(), deletedList.join(QStringLiteral(", ")));
    if (modifiedSystem > 0)
        add(QStringLiteral("dyn.modify-system"), Severity::Low, QStringLiteral("Filesystem"),
            QStringLiteral("Modified %1 existing file(s) in /etc or /usr").arg(modifiedSystem),
            QStringLiteral("Common for configuration updates (e.g. ld.so.cache, mime caches); review the list in the Behaviour tab."),
            QString(), modifiedList.join(QStringLiteral(", ")));

    // File-system activity (includes attempts that failed)
    static const QHash<QString, QPair<Severity, QString>> tools = {
        {QStringLiteral("curl"), {Severity::Low, QStringLiteral("Runs curl (downloads)")}},
        {QStringLiteral("wget"), {Severity::Low, QStringLiteral("Runs wget (downloads)")}},
        {QStringLiteral("nc"), {Severity::Medium, QStringLiteral("Runs netcat")}},
        {QStringLiteral("ncat"), {Severity::Medium, QStringLiteral("Runs ncat")}},
        {QStringLiteral("netcat"), {Severity::Medium, QStringLiteral("Runs netcat")}},
        {QStringLiteral("socat"), {Severity::Medium, QStringLiteral("Runs socat")}},
        {QStringLiteral("telnet"), {Severity::Medium, QStringLiteral("Runs telnet")}},
        {QStringLiteral("chattr"), {Severity::Medium, QStringLiteral("Changes file attributes (chattr)")}},
        {QStringLiteral("insmod"), {Severity::High, QStringLiteral("Loads a kernel module (insmod)")}},
        {QStringLiteral("modprobe"), {Severity::Medium, QStringLiteral("Runs modprobe")}},
        {QStringLiteral("iptables"), {Severity::Medium, QStringLiteral("Changes firewall rules (iptables)")}},
        {QStringLiteral("nft"), {Severity::Medium, QStringLiteral("Changes firewall rules (nft)")}},
        {QStringLiteral("ufw"), {Severity::Medium, QStringLiteral("Changes firewall rules (ufw)")}},
        {QStringLiteral("crontab"), {Severity::Medium, QStringLiteral("Edits cron jobs (crontab)")}},
        {QStringLiteral("setenforce"), {Severity::High, QStringLiteral("Changes SELinux mode")}},
        {QStringLiteral("useradd"), {Severity::Low, QStringLiteral("Creates a user account")}},
        {QStringLiteral("adduser"), {Severity::Low, QStringLiteral("Creates a user account")}},
        {QStringLiteral("usermod"), {Severity::Low, QStringLiteral("Modifies a user account")}},
        {QStringLiteral("chpasswd"), {Severity::Medium, QStringLiteral("Sets passwords (chpasswd)")}},
        {QStringLiteral("passwd"), {Severity::Medium, QStringLiteral("Runs passwd")}},
        {QStringLiteral("visudo"), {Severity::Medium, QStringLiteral("Edits sudoers")}},
        {QStringLiteral("ssh-keygen"), {Severity::Low, QStringLiteral("Generates SSH keys")}},
        {QStringLiteral("base64"), {Severity::Low, QStringLiteral("Decodes/encodes base64 at runtime")}},
        {QStringLiteral("xxd"), {Severity::Low, QStringLiteral("Runs xxd (hex decoding)")}},
        {QStringLiteral("openssl"), {Severity::Low, QStringLiteral("Runs openssl")}},
        {QStringLiteral("gpg"), {Severity::Info, QStringLiteral("Runs gpg")}},
        {QStringLiteral("apt-key"), {Severity::Low, QStringLiteral("Adds an APT signing key")}},
        {QStringLiteral("sudo"), {Severity::Low, QStringLiteral("Calls sudo")}},
        {QStringLiteral("pkexec"), {Severity::Medium, QStringLiteral("Calls pkexec")}},
        {QStringLiteral("systemctl"), {Severity::Info, QStringLiteral("Calls systemctl")}},
        {QStringLiteral("shred"), {Severity::Medium, QStringLiteral("Securely deletes files (shred)")}},
        {QStringLiteral("dd"), {Severity::Info, QStringLiteral("Runs dd")}},
    };
    QHash<QString, int> blockedWrites;
    for (const FsEvent &e : std::as_const(b.fsEvents)) {
        if (e.op == QLatin1String("exec")) {
            const QString base = e.path.section(QLatin1Char('/'), -1);
            const bool tmp = e.path.startsWith(QLatin1String("/tmp/")) || e.path.startsWith(QLatin1String("/var/tmp/")) || e.path.startsWith(QLatin1String("/dev/shm/"));
            if (createdPaths.contains(e.path) || tmp)
                add(QStringLiteral("dyn.exec-dropped"), Severity::High, QStringLiteral("Execution"),
                    QStringLiteral("Executes a file created during the run"),
                    QStringLiteral("Code that is written and then executed at install time is invisible to static analysis (dropper pattern)."), e.path, e.detail);
            if (e.path.startsWith(QLatin1String("/proc/self/fd/")) || e.path.startsWith(QLatin1String("/memfd:")))
                add(QStringLiteral("dyn.fileless"), Severity::High, QStringLiteral("Execution"), QStringLiteral("Fileless execution from memory"),
                    QStringLiteral("Executes code from an anonymous memory file."), e.path, e.detail);
            auto it = tools.constFind(base);
            if (it != tools.constEnd() && it->first > Severity::Info) {
                Severity sev = it->first;
                QString title = it->second;
                if (base == QLatin1String("systemctl") && e.detail.contains(QLatin1String(" enable"))) { sev = Severity::Low; title = QStringLiteral("Enables a systemd service"); }
                if (base == QLatin1String("dd") && e.detail.contains(QLatin1String("of=/dev/"))) { sev = Severity::High; title = QStringLiteral("Writes to a raw device with dd"); }
                add(QStringLiteral("dyn.tool.") + base, sev, QStringLiteral("Execution"), title,
                    QStringLiteral("Command executed during the run."), e.path, e.detail);
            }
            if ((base == QLatin1String("bash") || base == QLatin1String("sh")) && e.detail.contains(QLatin1String(" -i")))
                add(QStringLiteral("dyn.interactive-shell"), Severity::High, QStringLiteral("Backdoor"), QStringLiteral("Spawns an interactive shell"),
                    QStringLiteral("Interactive shells during installation are typical for reverse shells."), e.path, e.detail);
            if ((base.startsWith(QLatin1String("python")) || base.startsWith(QLatin1String("perl"))) && (e.detail.contains(QLatin1String(" -c ")) || e.detail.contains(QLatin1String(" -e "))))
                add(QStringLiteral("dyn.inline-code"), Severity::Low, QStringLiteral("Execution"), QStringLiteral("Runs inline interpreter code"),
                    QStringLiteral("python -c / perl -e is often used to hide logic."), e.path, e.detail);
        } else if (e.op == QLatin1String("read-sensitive")) {
            for (const auto &rule : ContentScanner::sensitiveReadRules())
                if (rule.title == e.detail) {
                    add(QStringLiteral("dyn.") + rule.id, rule.sev, rule.category, rule.title + (e.ok ? QString() : QStringLiteral(" (attempt blocked)")),
                        QStringLiteral("Observed at runtime."), e.path);
                    break;
                }
        } else if (e.op == QLatin1String("ptrace")) {
            add(QStringLiteral("dyn.ptrace"), Severity::High, QStringLiteral("Execution"), QStringLiteral("Attaches to another process (ptrace)"),
                QStringLiteral("Used for debugging, but also for code injection and credential theft."), QString(), e.detail);
        } else if (e.op == QLatin1String("kernel-module")) {
            add(QStringLiteral("dyn.kmod"), Severity::Critical, QStringLiteral("Kernel"), QStringLiteral("Tries to load/unload a kernel module"),
                QStringLiteral("Blocked by the sandbox. Kernel code has full control over the machine."), e.path, e.detail);
        } else if (e.op == QLatin1String("mount") || e.op == QLatin1String("namespace") || e.op == QLatin1String("clone-denied")) {
            add(QStringLiteral("dyn.ns"), Severity::Medium, QStringLiteral("Privilege"), QStringLiteral("Tries to mount filesystems or create namespaces"),
                QStringLiteral("Blocked by the sandbox. Unusual for installers; can be container tooling or an escape attempt."), e.path, e.detail);
        } else if (e.op == QLatin1String("memfd")) {
            add(QStringLiteral("dyn.memfd"), Severity::Medium, QStringLiteral("Execution"), QStringLiteral("Creates an anonymous in-memory file"),
                QStringLiteral("memfd_create is used by JITs, but also by fileless malware."), e.path, e.detail);
        } else if (e.op == QLatin1String("restricted-syscall")) {
            add(QStringLiteral("dyn.restricted"), Severity::Medium, QStringLiteral("Privilege"), QStringLiteral("Uses a restricted kernel interface (%1)").arg(e.detail),
                QStringLiteral("Blocked by the sandbox seccomp policy."), QString(), e.detail);
        } else if (!e.ok && (e.op == QLatin1String("create") || e.op == QLatin1String("write") || e.op == QLatin1String("mkdir"))
                   && (e.error == QLatin1String("EACCES") || e.error == QLatin1String("EROFS") || e.error == QLatin1String("EPERM"))) {
            for (const auto &rule : ContentScanner::persistencePathRules())
                if (rule.re.match(e.path).hasMatch() && rule.id != QLatin1String("path.home") && rule.id != QLatin1String("path.tmp-exec")) {
                    add(QStringLiteral("dyn.") + rule.id, rule.sev, rule.category, rule.title + QStringLiteral(" (attempt blocked)"),
                        QStringLiteral("The write failed inside the sandbox, but the intent was recorded."), e.path);
                    break;
                }
            ++blockedWrites[e.path.section(QLatin1Char('/'), 0, 2)];
        }
    }

    // Network
    QMap<QString, QPair<NetEvent, int>> dest;
    for (const NetEvent &n : std::as_const(b.netEvents)) {
        if (n.op == QLatin1String("socket") && (n.proto == QLatin1String("raw") || n.family == QLatin1String("packet"))) {
            add(QStringLiteral("dyn.raw-socket"), Severity::High, QStringLiteral("Network"), QStringLiteral("Opens a raw/packet socket"),
                QStringLiteral("Raw sockets allow sniffing and crafting packets."), QString(), n.family + QLatin1Char('/') + n.proto);
            continue;
        }
        if (n.op == QLatin1String("listen") || (n.op == QLatin1String("bind") && n.port > 0 && n.family != QLatin1String("unix"))) {
            add(QStringLiteral("dyn.listen"), Severity::Medium, QStringLiteral("Network"), QStringLiteral("Opens a listening port %1/%2").arg(n.port).arg(n.proto),
                QStringLiteral("Listening services accept connections from others; a backdoor would do the same."), QString(), n.address);
            continue;
        }
        if (n.family == QLatin1String("unix")) {
            if (n.address.contains(QLatin1String("docker.sock")))
                add(QStringLiteral("dyn.docker"), Severity::High, QStringLiteral("Privilege"), QStringLiteral("Connects to the Docker socket"),
                    QStringLiteral("Docker access is equivalent to root."), n.address);
            continue;
        }
        if (n.family != QLatin1String("inet") && n.family != QLatin1String("inet6")) continue;
        if (n.address.isEmpty() || util::isNonRoutableIp(n.address)) continue;
        const QString key = n.address + QLatin1Char(':') + QString::number(n.port);
        auto &slot = dest[key];
        if (slot.second == 0) slot.first = n;
        else if (!n.domain.isEmpty() && !slot.first.domain.contains(n.domain)) slot.first.domain += QStringLiteral(", ") + n.domain;
        ++slot.second;
    }
    int destCount = 0;
    for (auto it = dest.constBegin(); it != dest.constEnd(); ++it) {
        const NetEvent &n = it->first;
        if (++destCount > 40) break;
        const QString what = n.domain.isEmpty() ? it.key() : QStringLiteral("%1 (%2)").arg(it.key(), n.domain);
        add(QStringLiteral("dyn.net-connect"), n.port == 53 ? Severity::Low : Severity::Medium, QStringLiteral("Network"),
            (b.networkAllowed ? QStringLiteral("Network connection to %1") : QStringLiteral("Attempted network connection to %1")).arg(what),
            QStringLiteral("Installers and first runs should not need to contact servers unless they download components. %1 event(s), process %2.")
                .arg(it->second).arg(n.pid),
            it.key());
        r.indicators << Indicator{QStringLiteral("ip"), n.address, QStringLiteral("[runtime]"), it->second, false};
    }
    static const QRegularExpression exfil(QStringLiteral(R"(pastebin\.com|transfer\.sh|ngrok|discord(app)?\.com|telegram\.org|hastebin|0x0\.st|webhook\.site|requestbin|pipedream|\.onion$|duckdns\.org|no-ip\.|ddns\.net)"),
                                          QRegularExpression::CaseInsensitiveOption);
    for (const QString &d : std::as_const(b.dnsQueries)) {
        r.indicators << Indicator{QStringLiteral("domain"), d, QStringLiteral("[runtime DNS]"), 1, false};
        if (exfil.match(d).hasMatch())
            add(QStringLiteral("dyn.dns-exfil"), Severity::High, QStringLiteral("Exfiltration"), QStringLiteral("Resolves a paste/tunnel/dynamic-DNS service: %1").arg(d),
                QStringLiteral("These services are commonly abused for command-and-control."), d);
    }
    if (!b.dnsQueries.isEmpty())
        add(QStringLiteral("dyn.dns"), Severity::Low, QStringLiteral("Network"), QStringLiteral("Resolves %1 domain name(s)").arg(b.dnsQueries.size()),
            QStringLiteral("DNS lookups performed during the run."), QString(), b.dnsQueries.mid(0, 12).join(QStringLiteral(", ")));

    // Stage outcomes
    for (const StageResult &s : std::as_const(b.stages)) {
        if (s.timedOut)
            add(QStringLiteral("dyn.timeout"), Severity::Info, QStringLiteral("Analysis"), QStringLiteral("Stage “%1” reached the time limit").arg(s.name),
                QStringLiteral("The program was still running and was stopped. GUI apps usually keep running until closed."));
        if (s.output.contains(QLatin1String("background process(es) were still running")))
            add(QStringLiteral("dyn.background"), Severity::Medium, QStringLiteral("Persistence"), QStringLiteral("Leaves processes running in the background"),
                QStringLiteral("Stage “%1” started processes that outlived it (daemonizing). Installers normally finish cleanly.").arg(s.name));
    }
    std::stable_sort(b.findings.begin(), b.findings.end(), [](const Finding &x, const Finding &y) { return x.severity > y.severity; });
}

} // namespace ps
