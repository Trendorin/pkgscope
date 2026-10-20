// SPDX-License-Identifier: MIT
#include "StraceParser.h"
#include "ContentScanner.h"
#include "Util.h"

#include <QDir>
#include <QFile>
#include <QRegularExpression>

namespace ps {

namespace {

int hexv(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Decodes the first quoted strace string in `s` (handles \xNN, \n, octal ...).
QByteArray unq(QByteArray s, qsizetype *endPos = nullptr)
{
    QByteArray out;
    const qsizetype q = s.indexOf('"');
    if (q < 0) return out;
    qsizetype i = q + 1;
    for (; i < s.size(); ++i) {
        const char c = s[i];
        if (c == '"') break;
        if (c != '\\' || i + 1 >= s.size()) { out.append(c); continue; }
        const char n = s[++i];
        switch (n) {
        case 'x': {
            int v = 0, k = 0;
            while (k < 2 && i + 1 < s.size() && hexv(s[i + 1]) >= 0) { v = v * 16 + hexv(s[++i]); ++k; }
            out.append(static_cast<char>(v));
            break;
        }
        case 'n': out.append('\n'); break;
        case 't': out.append('\t'); break;
        case 'r': out.append('\r'); break;
        case 'v': out.append('\v'); break;
        case 'f': out.append('\f'); break;
        default:
            if (n >= '0' && n <= '7') {
                int v = n - '0', k = 1;
                while (k < 3 && i + 1 < s.size() && s[i + 1] >= '0' && s[i + 1] <= '7') { v = v * 8 + (s[++i] - '0'); ++k; }
                out.append(static_cast<char>(v));
            } else {
                out.append(n);
            }
        }
    }
    if (endPos) *endPos = i + 1;
    return out;
}

QString unqs(QByteArray s) { return QString::fromUtf8(unq(s)); }

// Splits top-level comma separated arguments.
QList<QByteArray> splitArgs(QByteArray s)
{
    QList<QByteArray> out;
    int depth = 0;
    bool inStr = false;
    qsizetype start = 0;
    for (qsizetype i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (inStr) {
            if (c == '\\') ++i;
            else if (c == '"') inStr = false;
            continue;
        }
        if (c == '"') inStr = true;
        else if (c == '(' || c == '[' || c == '{') ++depth;
        else if (c == ')' || c == ']' || c == '}') --depth;
        else if (c == ',' && depth == 0) {
            out << s.mid(start, i - start).trimmed();
            start = i + 1;
        }
    }
    const QByteArray last = s.mid(start).trimmed();
    if (!last.isEmpty() || !out.isEmpty()) out << last;
    return out;
}

double parseTime(QByteArray t)
{
    // HH:MM:SS.ffffff
    if (t.size() < 8) return 0;
    const int h = (t[0] - '0') * 10 + (t[1] - '0');
    const int m = (t[3] - '0') * 10 + (t[4] - '0');
    const double s = t.mid(6).toDouble();
    return h * 3600 + m * 60 + s;
}

QStringList parseArgv(QByteArray arr)
{
    QStringList out;
    if (!arr.startsWith('[')) return out;
    qsizetype pos = 0;
    while (out.size() < 256) {
        const qsizetype q = arr.indexOf('"', pos);
        if (q < 0) break;
        qsizetype end = 0;
        out << QString::fromUtf8(unq(arr.mid(q), &end));
        pos = q + end;
    }
    if (arr.contains("...")) out << QStringLiteral("…");
    return out;
}

const QRegularExpression &reFamily() { static const QRegularExpression r(QStringLiteral(R"(sa_family=(AF_\w+))")); return r; }
const QRegularExpression &rePort() { static const QRegularExpression r(QStringLiteral(R"(sin6?_port=htons\((\d+)\))")); return r; }

struct SockAddr {
    QString family;
    QString addr;
    int port = 0;
    bool valid = false;
};

SockAddr parseSockaddr(const QByteArray &a)
{
    SockAddr s;
    const QString txt = QString::fromLatin1(a);
    const auto fm = reFamily().match(txt);
    if (!fm.hasMatch()) return s;
    s.valid = true;
    const QString fam = fm.captured(1);
    s.family = fam == QLatin1String("AF_INET") ? QStringLiteral("inet") : fam == QLatin1String("AF_INET6") ? QStringLiteral("inet6")
             : fam == QLatin1String("AF_UNIX") ? QStringLiteral("unix") : fam == QLatin1String("AF_NETLINK") ? QStringLiteral("netlink")
             : fam == QLatin1String("AF_PACKET") ? QStringLiteral("packet") : fam.mid(3).toLower();
    const auto pm = rePort().match(txt);
    if (pm.hasMatch()) s.port = pm.captured(1).toInt();
    qsizetype i = a.indexOf("inet_addr(");
    if (i >= 0) s.addr = unqs(QByteArray(a).mid(i));
    i = a.indexOf("inet_pton(AF_INET6,");
    if (i >= 0) s.addr = unqs(QByteArray(a).mid(i + 19));
    i = a.indexOf("sun_path=");
    if (i >= 0) {
        const bool abstract = a.size() > i + 9 && a[i + 9] == '@';
        s.addr = (abstract ? QStringLiteral("@") : QString()) + unqs(QByteArray(a).mid(i));
    }
    return s;
}

QString protoFromType(const QByteArray &type)
{
    if (type.contains("SOCK_STREAM")) return QStringLiteral("tcp");
    if (type.contains("SOCK_DGRAM")) return QStringLiteral("udp");
    if (type.contains("SOCK_RAW")) return QStringLiteral("raw");
    if (type.contains("SOCK_SEQPACKET")) return QStringLiteral("seqpacket");
    return QString::fromLatin1(type).toLower();
}

int argInt(const QList<QByteArray> &a, int i)
{
    if (i >= a.size()) return -1;
    bool ok = false;
    const int v = a[i].toInt(&ok, 0);
    return ok ? v : -1;
}

bool isWriteOpen(const QByteArray &flags)
{
    return flags.contains("O_WRONLY") || flags.contains("O_RDWR") || flags.contains("O_CREAT") || flags.contains("O_TRUNC")
        || flags.contains("O_APPEND");
}

QList<QByteArray> quotedAfter(QByteArray text, QByteArray key)
{
    QList<QByteArray> out;
    qsizetype pos = 0;
    while (out.size() < 64) {
        const qsizetype i = text.indexOf(key, pos);
        if (i < 0) break;
        qsizetype end = 0;
        out << unq(text.mid(i + key.size()), &end);
        pos = i + key.size() + std::max<qsizetype>(end, 1);
    }
    return out;
}

} // namespace

StraceParser::StraceParser(QString stage, QByteArray marker, QString initialCwd, double timeOffset)
    : m_stage(std::move(stage)), m_marker(std::move(marker)), m_initialCwd(std::move(initialCwd)), m_offset(timeOffset)
{
}

bool StraceParser::parseFile(const QString &path, Output &out, qint64 maxEvents)
{
    m_maxEvents = maxEvents;
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return false;
    while (!f.atEnd()) {
        QByteArray line = f.readLine(1 << 20);
        if (line.endsWith('\n')) line.chop(1);
        if (!line.isEmpty()) parseLine(line, out);
    }
    return true;
}

void StraceParser::parseLine(QByteArray line, Output &out)
{
    ++out.lines;
    // "PID HH:MM:SS.ffffff rest"
    const qsizetype sp1 = line.indexOf(' ');
    if (sp1 <= 0) return;
    bool ok = false;
    const int pid = line.left(sp1).toInt(&ok);
    if (!ok) return;
    qsizetype p = sp1;
    while (p < line.size() && line[p] == ' ') ++p;
    const qsizetype sp2 = line.indexOf(' ', p);
    if (sp2 < 0) return;
    const double tAbs = parseTime(line.mid(p, sp2 - p));
    if (m_t0 < 0) m_t0 = tAbs;
    const double t = tAbs - m_t0 + m_offset;
    QByteArray rest = line.mid(sp2 + 1);

    if (rest.startsWith("+++ ")) {
        if (!m_started || m_preMarker.contains(pid)) return;
        const int tg = tgid(pid);
        if (tg != pid) return;
        const int idx = procIndex(tg, out, t);
        if (rest.startsWith("+++ exited with ")) out.processes[idx].exitCode = rest.mid(16).split(' ').value(0).toInt();
        else if (rest.startsWith("+++ killed by ")) out.processes[idx].exitSignal = QString::fromLatin1(rest.mid(14).split(' ').value(0));
        return;
    }
    if (rest.startsWith("--- ")) return; // signals

    QByteArray full;
    if (rest.startsWith("<... ")) {
        const qsizetype r = rest.indexOf("resumed>");
        if (r < 0) return;
        full = m_pending.take(pid) + rest.mid(r + 8);
    } else if (rest.endsWith("<unfinished ...>")) {
        m_pending.insert(pid, rest.left(rest.size() - 16).trimmed());
        return;
    } else {
        full = rest;
    }

    const qsizetype lp = full.indexOf('(');
    if (lp <= 0) return;
    Call c;
    c.pid = pid;
    c.t = t;
    c.name = full.left(lp);
    // find matching ')'
    int depth = 0;
    bool inStr = false;
    qsizetype rp = -1;
    for (qsizetype i = lp; i < full.size(); ++i) {
        const char ch = full[i];
        if (inStr) {
            if (ch == '\\') ++i;
            else if (ch == '"') inStr = false;
            continue;
        }
        if (ch == '"') inStr = true;
        else if (ch == '(' || ch == '[' || ch == '{') ++depth;
        else if (ch == ')' || ch == ']' || ch == '}') {
            if (--depth == 0 && ch == ')') { rp = i; break; }
        }
    }
    if (rp < 0) return;
    c.args = splitArgs(QByteArray(full).mid(lp + 1, rp - lp - 1));
    const qsizetype eq = full.indexOf(" = ", rp);
    if (eq < 0) {
        c.unknownRet = true;
    } else {
        const QByteArray retTok = full.mid(eq + 3).split(' ').value(0);
        if (retTok == "?") c.unknownRet = true;
        c.ret = retTok.toLongLong(&ok, 0);
        if (retTok.startsWith("-1")) {
            c.failed = true;
            c.errnoName = full.mid(eq + 3).split(' ').value(1);
        }
    }

    // Marker detection
    if (!m_started) {
        if (c.name == "execve" && !c.args.isEmpty() && unq(c.args[0]) == m_marker) {
            m_started = true;
            out.markerSeen = true;
            m_rootPid = pid;
            m_preMarker.remove(pid); // the helper's own setup calls came before the marker, from this very pid
            const int idx = procIndex(pid, out, t);
            out.processes[idx].ppid = 0;
            out.processes[idx].cwd = m_initialCwd;
            m_cwd.insert(pid, m_initialCwd);
        } else {
            m_preMarker.insert(pid);
        }
        return;
    }
    if (m_preMarker.contains(pid)) return;
    if (c.name == "execve" && !c.args.isEmpty() && unq(c.args[0]) == m_marker) return;
    handle(c, out);
}

int StraceParser::procIndex(int tg, Output &out, double t)
{
    auto it = m_procIdx.constFind(tg);
    if (it != m_procIdx.constEnd()) return it.value();
    ProcessInfo p;
    p.pid = tg;
    p.stage = m_stage;
    p.start = t;
    out.processes << p;
    m_procIdx.insert(tg, static_cast<int>(out.processes.size() - 1));
    return static_cast<int>(out.processes.size() - 1);
}

QString StraceParser::resolve(int tg, const QByteArray &dirfd, const QString &path) const
{
    if (path.startsWith(QLatin1Char('/'))) return QDir::cleanPath(path);
    QString base;
    if (dirfd.isEmpty() || dirfd == "AT_FDCWD") base = m_cwd.value(tg, m_initialCwd);
    else base = m_fdPath.value(tg).value(dirfd.toInt(), QString());
    if (base.isEmpty()) return path.isEmpty() ? QStringLiteral("?") : QStringLiteral("…/") + path;
    if (path.isEmpty()) return base;
    return QDir::cleanPath(base + QLatin1Char('/') + path);
}

void StraceParser::fsEvent(Output &out, const Call &c, const QString &op, const QString &path, const QString &path2, const QString &detail)
{
    if (out.fs.size() >= m_maxEvents) { ++out.dropped; return; }
    FsEvent e;
    e.t = c.t;
    e.pid = tgid(c.pid);
    e.stage = m_stage;
    e.op = op;
    e.path = path;
    e.path2 = path2;
    e.detail = detail;
    e.ok = !c.failed;
    if (c.failed) e.error = QString::fromLatin1(c.errnoName);
    out.fs << e;
}

void StraceParser::inspectPayloads(Output &out, const QString &peer, int port, const QString &proto, const QList<QByteArray> &payloads, int netIndex)
{
    for (const QByteArray &pl : payloads) {
        QString domain;
        if (port == 53 || proto == QLatin1String("udp")) {
            int qt = 0;
            domain = parseDnsQuery(pl, &qt);
            if (!domain.isEmpty()) {
                const QString key = domain.toLower();
                if (!m_dnsSeen.contains(key)) {
                    m_dnsSeen.insert(key);
                    out.dns << domain;
                }
            }
        }
        if (domain.isEmpty()) domain = parseTlsSni(pl);
        if (domain.isEmpty()) domain = parseHttpHost(pl);
        if (!domain.isEmpty() && netIndex >= 0 && netIndex < out.net.size()) {
            NetEvent &n = out.net[netIndex];
            if (n.domain.isEmpty()) n.domain = domain;
            else if (!n.domain.contains(domain)) n.domain += QStringLiteral(", ") + domain;
        }
        Q_UNUSED(peer);
    }
}

void StraceParser::netFromSockaddr(Output &out, const Call &c, int fd, const QByteArray &sockaddr, const QString &op,
                                   const QList<QByteArray> &payloads)
{
    const int tg = tgid(c.pid);
    Sock &s = m_socks[tg][fd];
    const SockAddr sa = parseSockaddr(sockaddr);
    QString peer = s.peer;
    int port = s.port;
    if (sa.valid) {
        peer = sa.addr;
        port = sa.port;
        if (s.family.isEmpty()) s.family = sa.family;
    }
    if (op == QLatin1String("connect")) {
        s.peer = peer;
        s.port = port;
    }
    if (sa.family == QLatin1String("netlink") || s.family == QLatin1String("netlink")) return;
    int idx = -1;
    // Merge repeated sends on the same connected socket into the connect event.
    if (op == QLatin1String("sendto") && !sa.valid && s.netIndex >= 0) {
        idx = s.netIndex;
    } else if (out.net.size() < m_maxEvents) {
        NetEvent n;
        n.t = c.t;
        n.pid = tg;
        n.stage = m_stage;
        n.op = op;
        n.family = sa.valid ? sa.family : s.family;
        n.proto = s.proto.isEmpty() ? (n.family == QLatin1String("unix") ? QStringLiteral("unix") : QString()) : s.proto;
        n.address = peer;
        n.port = port;
        n.ok = !c.failed || c.errnoName == "EINPROGRESS";
        if (c.failed) n.error = QString::fromLatin1(c.errnoName);
        out.net << n;
        idx = static_cast<int>(out.net.size() - 1);
        if (op == QLatin1String("connect")) s.netIndex = idx;
    }
    inspectPayloads(out, peer, port, s.proto, payloads, idx);
}

void StraceParser::handle(const Call &c, Output &out)
{
    const int tg = tgid(c.pid);
    const int idx = procIndex(tg, out, c.t);
    const QByteArray &n = c.name;
    const auto a = [&](int i) -> QByteArray { return i < c.args.size() ? c.args[i] : QByteArray(); };
    const auto s = [&](int i) { return unqs(a(i)); };

    if (n == "clone" || n == "clone3" || n == "fork" || n == "vfork") {
        if (c.failed || c.unknownRet || c.ret <= 0) {
            // clone3 returning ENOSYS is glibc's routine probe before falling back to clone; not a namespace attempt.
            static const QRegularExpression nsFlag(QStringLiteral("CLONE_NEW(NS|USER|NET|PID|UTS|IPC|CGROUP)"));
            const QString flags = QString::fromLatin1(c.args.join(' '));
            if (c.failed && c.errnoName != "ENOSYS" && nsFlag.match(flags).hasMatch())
                fsEvent(out, c, QStringLiteral("namespace"), QString(), QString(), QStringLiteral("clone ") + flags.left(140));
            return;
        }
        const int child = static_cast<int>(c.ret);
        bool thread = false;
        for (const QByteArray &x : c.args) thread = thread || x.contains("CLONE_THREAD");
        if (thread) {
            m_tgid.insert(child, tg);
            return;
        }
        const int ci = procIndex(child, out, c.t);
        ProcessInfo &cp = out.processes[ci];
        const ProcessInfo &pp = out.processes[idx];
        cp.ppid = tg;
        if (cp.exe.isEmpty()) {
            cp.exe = pp.exe;
            cp.argv = pp.argv;
        }
        cp.cwd = m_cwd.value(tg, m_initialCwd);
        m_cwd.insert(child, cp.cwd);
        m_fdPath.insert(child, m_fdPath.value(tg));
        m_socks.insert(child, m_socks.value(tg));
        return;
    }
    if (n == "execve" || n == "execveat") {
        const int off = n == "execveat" ? 1 : 0;
        const QString path = resolve(tg, n == "execveat" ? a(0) : QByteArray(), s(off));
        const QStringList argv = parseArgv(a(off + 1));
        if (c.failed) {
            if (c.errnoName == "ENOENT" || c.errnoName == "ENOTDIR") return; // PATH search noise
            fsEvent(out, c, QStringLiteral("exec"), path, QString(), argv.join(QLatin1Char(' ')).left(400));
            return;
        }
        ProcessInfo &p = out.processes[idx];
        if (!p.exe.isEmpty() && p.exe != path && p.pid != m_rootPid) {
            // exec replaces the image; keep the original command visible in argv history
        }
        p.exe = path;
        p.argv = argv;
        p.execFailed = false;
        fsEvent(out, c, QStringLiteral("exec"), path, QString(), argv.join(QLatin1Char(' ')).left(400));
        return;
    }
    if (n == "chdir") {
        if (!c.failed) m_cwd.insert(tg, resolve(tg, QByteArray(), s(0)));
        return;
    }
    if (n == "fchdir") {
        if (!c.failed) {
            const QString p = m_fdPath.value(tg).value(argInt(c.args, 0));
            if (!p.isEmpty()) m_cwd.insert(tg, p);
        }
        return;
    }
    if (n == "open" || n == "openat" || n == "openat2" || n == "creat") {
        QString path;
        QByteArray flags;
        if (n == "open") { path = resolve(tg, {}, s(0)); flags = a(1); }
        else if (n == "creat") { path = resolve(tg, {}, s(0)); flags = "O_CREAT|O_WRONLY|O_TRUNC"; }
        else { path = resolve(tg, a(0), s(1)); flags = a(2); }
        if (!c.failed && c.ret >= 0 && (flags.contains("O_DIRECTORY") || isWriteOpen(flags)))
            m_fdPath[tg].insert(static_cast<int>(c.ret), path);
        if (isWriteOpen(flags)) {
            if (path == QLatin1String("/dev/null") || path == QLatin1String("/dev/tty") || path.startsWith(QLatin1String("/proc/self/fd"))
                || path.startsWith(QLatin1String("/dev/pts/")))
                return;
            fsEvent(out, c, flags.contains("O_CREAT") ? QStringLiteral("create") : QStringLiteral("write"), path, QString(),
                    QString::fromLatin1(flags.left(120)));
        } else if (!c.failed || c.errnoName == "EACCES" || c.errnoName == "EPERM") {
            // Plain reads are far too noisy; keep only sensitive locations.
            for (const auto &r : ContentScanner::sensitiveReadRules())
                if (r.re.match(path).hasMatch()) {
                    fsEvent(out, c, QStringLiteral("read-sensitive"), path, QString(), r.title);
                    break;
                }
        }
        return;
    }
    if (n == "mkdir" || n == "mkdirat") {
        const QString path = n == "mkdir" ? resolve(tg, {}, s(0)) : resolve(tg, a(0), s(1));
        if (c.errnoName == "EEXIST") return;
        fsEvent(out, c, QStringLiteral("mkdir"), path);
        return;
    }
    if (n == "unlink" || n == "unlinkat" || n == "rmdir") {
        const QString path = n == "unlinkat" ? resolve(tg, a(0), s(1)) : resolve(tg, {}, s(0));
        if (c.errnoName == "ENOENT") return;
        fsEvent(out, c, QStringLiteral("delete"), path);
        return;
    }
    if (n == "rename" || n == "renameat" || n == "renameat2") {
        if (n == "rename") fsEvent(out, c, QStringLiteral("rename"), resolve(tg, {}, s(0)), resolve(tg, {}, s(1)));
        else fsEvent(out, c, QStringLiteral("rename"), resolve(tg, a(0), s(1)), resolve(tg, a(2), s(3)));
        return;
    }
    if (n == "link" || n == "linkat") {
        if (n == "link") fsEvent(out, c, QStringLiteral("link"), resolve(tg, {}, s(1)), resolve(tg, {}, s(0)));
        else fsEvent(out, c, QStringLiteral("link"), resolve(tg, a(2), s(3)), resolve(tg, a(0), s(1)));
        return;
    }
    if (n == "symlink" || n == "symlinkat") {
        if (n == "symlink") fsEvent(out, c, QStringLiteral("symlink"), resolve(tg, {}, s(1)), s(0));
        else fsEvent(out, c, QStringLiteral("symlink"), resolve(tg, a(1), s(2)), s(0));
        return;
    }
    if (n == "chmod" || n == "fchmodat" || n == "fchmodat2" || n == "fchmod") {
        QString path;
        QByteArray mode;
        if (n == "chmod") { path = resolve(tg, {}, s(0)); mode = a(1); }
        else if (n == "fchmod") { path = m_fdPath.value(tg).value(argInt(c.args, 0)); mode = a(1); if (path.isEmpty()) return; }
        else { path = resolve(tg, a(0), s(1)); mode = a(2); }
        fsEvent(out, c, QStringLiteral("chmod"), path, QString(), QString::fromLatin1(mode));
        return;
    }
    if (n == "chown" || n == "lchown" || n == "fchownat" || n == "fchown") {
        QString path;
        QString who;
        if (n == "fchownat") { path = resolve(tg, a(0), s(1)); who = QString::fromLatin1(a(2) + ':' + a(3)); }
        else if (n == "fchown") { path = m_fdPath.value(tg).value(argInt(c.args, 0)); who = QString::fromLatin1(a(1) + ':' + a(2)); if (path.isEmpty()) return; }
        else { path = resolve(tg, {}, s(0)); who = QString::fromLatin1(a(1) + ':' + a(2)); }
        fsEvent(out, c, QStringLiteral("chown"), path, QString(), who);
        return;
    }
    if (n == "truncate") {
        fsEvent(out, c, QStringLiteral("write"), resolve(tg, {}, s(0)), QString(), QStringLiteral("truncate"));
        return;
    }
    if (n == "socket") {
        if (c.failed) {
            fsEvent(out, c, QStringLiteral("socket"), QString(), QString(), QString::fromLatin1(a(0) + ", " + a(1)));
            if (a(1).contains("SOCK_RAW") || a(0) == "AF_PACKET") {
                NetEvent ne;
                ne.t = c.t; ne.pid = tg; ne.stage = m_stage; ne.op = QStringLiteral("socket");
                ne.family = QString::fromLatin1(a(0)).mid(3).toLower();
                ne.proto = protoFromType(a(1)); ne.ok = false; ne.error = QString::fromLatin1(c.errnoName);
                out.net << ne;
            }
            return;
        }
        Sock sk;
        const QByteArray fam = a(0);
        sk.family = fam == "AF_INET" ? QStringLiteral("inet") : fam == "AF_INET6" ? QStringLiteral("inet6") : fam == "AF_UNIX" ? QStringLiteral("unix")
                  : fam == "AF_NETLINK" ? QStringLiteral("netlink") : QString::fromLatin1(fam).mid(3).toLower();
        sk.proto = protoFromType(a(1));
        m_socks[tg].insert(static_cast<int>(c.ret), sk);
        if (a(1).contains("SOCK_RAW") || fam == "AF_PACKET") {
            NetEvent ne;
            ne.t = c.t; ne.pid = tg; ne.stage = m_stage; ne.op = QStringLiteral("socket");
            ne.family = sk.family; ne.proto = sk.proto; ne.ok = true;
            out.net << ne;
        }
        return;
    }
    if (n == "connect") {
        netFromSockaddr(out, c, argInt(c.args, 0), a(1), QStringLiteral("connect"), {});
        return;
    }
    if (n == "bind" || n == "listen") {
        const int fd = argInt(c.args, 0);
        if (n == "bind") {
            const SockAddr sa = parseSockaddr(a(1));
            Sock &sk = m_socks[tg][fd];
            sk.peer = sa.addr;
            sk.port = sa.port;
            if (sa.family == QLatin1String("netlink") || sk.family == QLatin1String("netlink")) return;
            if (sa.family == QLatin1String("unix") || sa.port == 0) return; // ephemeral/local binds are noise
        }
        const Sock sk = m_socks.value(tg).value(fd);
        if (sk.family == QLatin1String("netlink") || (n == "listen" && sk.family == QLatin1String("unix"))) return;
        NetEvent ne;
        ne.t = c.t; ne.pid = tg; ne.stage = m_stage; ne.op = QString::fromLatin1(n);
        ne.family = sk.family; ne.proto = sk.proto; ne.address = sk.peer; ne.port = sk.port;
        ne.ok = !c.failed; ne.error = QString::fromLatin1(c.errnoName);
        out.net << ne;
        return;
    }
    if (n == "sendto") {
        netFromSockaddr(out, c, argInt(c.args, 0), a(4), QStringLiteral("sendto"), {unq(a(1))});
        return;
    }
    if (n == "sendmsg" || n == "sendmmsg") {
        const QByteArray body = a(1);
        netFromSockaddr(out, c, argInt(c.args, 0), body.contains("msg_name={") ? body : QByteArray(), QStringLiteral("sendto"),
                        quotedAfter(body, "iov_base="));
        return;
    }
    if (n == "ptrace") {
        if (a(0) == "PTRACE_TRACEME") return;
        fsEvent(out, c, QStringLiteral("ptrace"), QString(), QString(), QString::fromLatin1(a(0) + " pid " + a(1)));
        return;
    }
    if (n == "init_module" || n == "finit_module" || n == "delete_module") {
        fsEvent(out, c, QStringLiteral("kernel-module"), n == "delete_module" ? s(0) : QString(), QString(), QString::fromLatin1(n));
        return;
    }
    if (n == "mount" || n == "umount2" || n == "pivot_root") {
        fsEvent(out, c, QStringLiteral("mount"), n == "mount" ? s(1) : s(0), QString(), QString::fromLatin1(n + ' ' + a(2).left(40)));
        return;
    }
    if (n == "unshare" || n == "setns") {
        fsEvent(out, c, QStringLiteral("namespace"), QString(), QString(), QString::fromLatin1(n + ' ' + a(0).left(120)));
        return;
    }
    if (n == "memfd_create") {
        fsEvent(out, c, QStringLiteral("memfd"), s(0), QString(), QString::fromLatin1(a(1)));
        return;
    }
    if (n == "bpf" || n == "keyctl" || n == "add_key" || n == "perf_event_open" || n == "io_uring_setup") {
        fsEvent(out, c, QStringLiteral("restricted-syscall"), QString(), QString(), QString::fromLatin1(n));
        return;
    }
    if (n == "setuid" || n == "setgid" || n == "setresuid" || n == "setresgid" || n == "setreuid" || n == "capset") {
        fsEvent(out, c, QStringLiteral("credentials"), QString(), QString(), QString::fromLatin1(n + '(' + c.args.join(", ").left(80) + ')'));
        return;
    }
}

// ---------------------------------------------------------------- protocol helpers

QString StraceParser::parseDnsQuery(const QByteArray &pkt, int *qtype)
{
    if (pkt.size() < 17) return {};
    const auto *d = reinterpret_cast<const uchar *>(pkt.constData());
    if (d[2] & 0x80) return {};                      // response, not a query
    const int qd = (d[4] << 8) | d[5];
    if (qd < 1 || qd > 4) return {};
    qsizetype i = 12;
    QStringList labels;
    while (i < pkt.size()) {
        const int len = d[i];
        if (len == 0) { ++i; break; }
        if (len > 63 || i + 1 + len > pkt.size()) return {};
        QString lab = QString::fromLatin1(pkt.mid(i + 1, len));
        for (QChar ch : lab)
            if (!(ch.isLetterOrNumber() || ch == QLatin1Char('-') || ch == QLatin1Char('_'))) return {};
        labels << lab;
        i += 1 + len;
        if (labels.size() > 40) return {};
    }
    if (labels.isEmpty()) return {};
    if (qtype && i + 2 <= pkt.size()) *qtype = (d[i] << 8) | d[i + 1];
    return labels.join(QLatin1Char('.'));
}

QString StraceParser::parseTlsSni(const QByteArray &b)
{
    const auto *d = reinterpret_cast<const uchar *>(b.constData());
    const qsizetype n = b.size();
    if (n < 50 || d[0] != 0x16 || d[1] != 0x03 || d[5] != 0x01) return {};
    qsizetype p = 5 + 4 + 2 + 32;
    if (p >= n) return {};
    p += 1 + d[p];                                   // session id
    if (p + 2 > n) return {};
    p += 2 + ((d[p] << 8) | d[p + 1]);               // cipher suites
    if (p >= n) return {};
    p += 1 + d[p];                                   // compression
    if (p + 2 > n) return {};
    const qsizetype extEnd = std::min<qsizetype>(n, p + 2 + ((d[p] << 8) | d[p + 1]));
    p += 2;
    while (p + 4 <= extEnd) {
        const int type = (d[p] << 8) | d[p + 1];
        const int len = (d[p + 2] << 8) | d[p + 3];
        p += 4;
        if (type == 0 && p + 5 <= extEnd) {
            const int nameLen = (d[p + 3] << 8) | d[p + 4];
            if (p + 5 + nameLen <= n) return QString::fromLatin1(b.mid(p + 5, nameLen));
            return {};
        }
        p += len;
    }
    return {};
}

QString StraceParser::parseHttpHost(const QByteArray &b)
{
    static const char *methods[] = {"GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "PATCH ", "OPTIONS ", "CONNECT "};
    bool http = false;
    for (const char *m : methods) http = http || b.startsWith(m);
    if (!http) return {};
    const qsizetype h = b.indexOf("\r\nHost:");
    if (h < 0) {
        if (b.startsWith("CONNECT ")) return QString::fromLatin1(b.mid(8, b.indexOf(' ', 8) - 8));
        return {};
    }
    const qsizetype e = b.indexOf("\r\n", h + 7);
    return QString::fromLatin1(b.mid(h + 7, (e < 0 ? b.size() : e) - h - 7)).trimmed().left(253);
}

} // namespace ps
