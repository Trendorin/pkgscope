// SPDX-License-Identifier: MIT
#include "ContentScanner.h"
#include "Util.h"

#include <QSet>
#include <QUrl>
#include <sys/stat.h>

namespace ps {

namespace {

QRegularExpression rx(const QString &p, bool ci = false)
{
    QRegularExpression::PatternOptions o = QRegularExpression::UseUnicodePropertiesOption;
    if (ci) o |= QRegularExpression::CaseInsensitiveOption;
    QRegularExpression r(p, o);
    r.optimize();
    return r;
}

bool benignHost(const QString &host)
{
    static const QStringList suffixes = {
        QStringLiteral("w3.org"), QStringLiteral("purl.org"), QStringLiteral("ns.adobe.com"), QStringLiteral("gnu.org"),
        QStringLiteral("fsf.org"), QStringLiteral("opensource.org"), QStringLiteral("xml.org"), QStringLiteral("freedesktop.org"),
        QStringLiteral("apache.org"), QStringLiteral("creativecommons.org"), QStringLiteral("json-schema.org"),
        QStringLiteral("example.com"), QStringLiteral("example.org"), QStringLiteral("example.net"), QStringLiteral("localhost"),
        QStringLiteral("xmlsoap.org"), QStringLiteral("openxmlformats.org"), QStringLiteral("schemas.microsoft.com"),
        QStringLiteral("mozilla.org"), QStringLiteral("kde.org"), QStringLiteral("gnome.org"), QStringLiteral("debian.org"),
        QStringLiteral("ubuntu.com"), QStringLiteral("archlinux.org"), QStringLiteral("fedoraproject.org"),
        QStringLiteral("qt.io"), QStringLiteral("qt-project.org"), QStringLiteral("unicode.org"), QStringLiteral("ietf.org"),
        QStringLiteral("iana.org"), QStringLiteral("oasis-open.org"), QStringLiteral("xmlpull.org"), QStringLiteral("sun.com"),
        QStringLiteral("openssl.org"), QStringLiteral("python.org"), QStringLiteral("kernel.org"), QStringLiteral("x.org"),
        QStringLiteral("gtk.org"), QStringLiteral("libsdl.org"), QStringLiteral("opengl.org"), QStringLiteral("khronos.org"),
        QStringLiteral("dublincore.org"), QStringLiteral("openoffice.org"), QStringLiteral("docbook.org"), QStringLiteral("ecma-international.org"),
    };
    const QString h = host.toLower();
    for (const QString &s : suffixes)
        if (h == s || h.endsWith(QLatin1Char('.') + s)) return true;
    return false;
}

} // namespace

// ---------------------------------------------------------------- Indicators

void IndicatorCollector::add(const QString &type, const QString &value, const QString &source)
{
    const QString key = type + QLatin1Char('|') + value;
    auto it = m_items.find(key);
    if (it != m_items.end()) {
        ++it->count;
        return;
    }
    if (m_items.size() >= 5000) return;
    Indicator ind;
    ind.type = type;
    ind.value = value;
    ind.source = source;
    if (type == QLatin1String("url")) ind.likelyBenign = benignHost(QUrl(value).host());
    else if (type == QLatin1String("domain")) ind.likelyBenign = benignHost(value);
    m_items.insert(key, ind);
    m_order << key;
}

QVector<Indicator> IndicatorCollector::result() const
{
    QVector<Indicator> out;
    out.reserve(m_order.size());
    for (const QString &k : m_order) out << m_items.value(k);
    return out;
}

// ---------------------------------------------------------------- Scanner

ContentScanner::ContentScanner()
{
    using S = Severity;
    const auto add = [this](const char *id, S sev, const char *cat, const char *title, const char *detail,
                            const QString &pattern, bool ci = false, bool scriptsOnly = false, bool keepInBinary = false) {
        m_rules.push_back(Rule{QString::fromLatin1(id), sev, QString::fromLatin1(cat), QString::fromLatin1(title),
                               QString::fromLatin1(detail), rx(pattern, ci), scriptsOnly, keepInBinary});
    };

    // Execution / download
    add("exec.download-pipe-shell", S::High, "Execution", "Downloads and pipes code straight into a shell",
        "Remote content is executed without any integrity check. Whoever controls the URL (or the network path) controls this machine.",
        QStringLiteral(R"(\b(curl|wget|fetch)\b[^\n|;]*\|\s*(sudo\s+)?(ba|da|z|k)?sh\b)"));
    add("exec.download-to-tmp", S::Medium, "Execution", "Downloads a file into a temporary directory",
        "Payload staging in /tmp, /var/tmp or /dev/shm is a common malware dropper pattern.",
        QStringLiteral(R"(\b(curl|wget)\b[^\n]*\s(-o|-O|--output|>)\s*["']?(/tmp/|/dev/shm/|/var/tmp/))"));
    add("exec.chmod-tmp", S::Medium, "Execution", "Makes a file in a temporary directory executable",
        "Executing binaries from world-writable temp locations is typical for droppers.",
        QStringLiteral(R"(chmod\s+(\S+\s+)*\+?[0-7]*x?\s*["']?(/tmp|/dev/shm|/var/tmp)/)"));
    add("obf.base64-exec", S::High, "Obfuscation", "Decodes base64 and executes the result",
        "Hiding executable code behind encoding is rarely legitimate in packaging scripts.",
        QStringLiteral(R"(base64\s+(-d|--decode|-D)\b[^\n]*\|\s*(sudo\s+)?(ba|da|z)?sh\b|eval[^\n]*base64\s+(-d|--decode))"));
    add("obf.eval-subshell", S::Medium, "Obfuscation", "Evaluates dynamically generated shell code",
        "eval on the output of echo/printf is used to hide the real commands being executed.",
        QStringLiteral(R"(\beval\s+["']?\$\(\s*(echo|printf|rev|xxd|openssl)\b)"), false, true);
    add("obf.python-exec", S::High, "Obfuscation", "Python executes decoded/decompressed code",
        "exec() of base64/zlib/marshal data is a classic obfuscation technique.",
        QStringLiteral(R"(exec\s*\(\s*(base64\.b64decode|zlib\.decompress|marshal\.loads|codecs\.decode|bytes\.fromhex))"));
    add("obf.perl-eval", S::High, "Obfuscation", "Perl evaluates packed/encoded code",
        "eval of unpack/decode_base64 output hides the executed code.",
        QStringLiteral(R"(\beval\s*\(?\s*(unpack|pack|decode_base64|MIME::Base64))"));
    add("obf.base64-blob", S::Medium, "Obfuscation", "Large base64 blob embedded in a script",
        "Long encoded payloads inside install scripts often carry hidden binaries or second stages.",
        QStringLiteral(R"([A-Za-z0-9+/]{600,}={0,2})"), false, true);
    add("obf.hex-blob", S::Medium, "Obfuscation", "Long hex-escaped byte string in a script",
        "Shellcode and hidden commands are frequently stored as \\xNN sequences.",
        QStringLiteral(R"((\\x[0-9a-fA-F]{2}){48,})"), false, true);

    // Reverse shells / backdoors
    add("backdoor.dev-tcp", S::Critical, "Backdoor", "Bash /dev/tcp network redirection (reverse shell pattern)",
        "Redirecting a shell to /dev/tcp/HOST/PORT gives a remote party an interactive shell.",
        QStringLiteral(R"(/dev/(tcp|udp)/[A-Za-z0-9.\-\$\{\}_]+/[0-9\$\{])"));
    add("backdoor.netcat-exec", S::High, "Backdoor", "Netcat/socat spawning a program (bind/reverse shell)",
        "nc -e / socat EXEC attach a shell to a network socket.",
        QStringLiteral(R"(\b(nc|ncat|netcat)\b[^\n]*\s-[a-zA-Z]*[ec]\s|\bsocat\b[^\n]*\b(exec|system):|\bmkfifo\b[^\n]*\b(nc|ncat|telnet|openssl\s+s_client)\b)"));
    add("backdoor.interactive-shell", S::High, "Backdoor", "Interactive shell redirected to a socket",
        "bash -i with file descriptor redirection is a reverse-shell idiom.",
        QStringLiteral(R"(\b(ba|z)?sh\s+-i\s*[<>]&|python[0-9.]*\s+-c\s+["'][^"']*\b(socket|pty)\.)"));
    add("backdoor.ssh-keys", S::High, "Persistence", "Touches SSH authorized_keys",
        "Adding keys to authorized_keys grants persistent remote login.",
        QStringLiteral(R"(authorized_keys2?\b)"));

    // Mining
    add("mining.pool", S::Critical, "Cryptomining", "Cryptocurrency mining pool / miner reference",
        "Stratum URLs and miner names indicate an embedded coin miner.",
        QStringLiteral(R"(stratum\+(tcp|ssl|tls)://|\bxmrig\b|--donate-level|\bcpuminer\b|\bminerd\b|\bnicehash\b|\bcryptonight\b|\bxmr-stak\b|pool\.(minexmr|supportxmr|hashvault)\b)"),
        true, false, true);

    // Privilege / persistence
    // Titles name the file without its full path: PkgScope's own binaries must not match their rules.
    add("persist.ld-preload-file", S::Critical, "Rootkit", "References the global preload list (ld.so.preload in /etc)",
        "Libraries listed there are injected into every process – a classic userland rootkit technique.",
        QStringLiteral(R"(/etc/ld\.so\.preload)"), false, false, true);
    add("priv.ld-preload", S::Medium, "Rootkit", "Sets LD_PRELOAD",
        "Forcing a preload library changes behaviour of every launched program.",
        QStringLiteral(R"(\bLD_PRELOAD\s*=)"), false, true);
    add("priv.sudoers", S::High, "Privilege", "Modifies sudo configuration",
        "Changes to sudoers can grant password-less root to arbitrary users.",
        QStringLiteral(R"(/etc/sudoers|NOPASSWD\s*:)"));
    add("cred.shadow", S::High, "Credential access", "Accesses /etc/shadow",
        "Password hashes are stored there; packages have no reason to read or edit it directly.",
        QStringLiteral(R"(/etc/(g)?shadow\b)"));
    add("priv.passwd-append", S::High, "Privilege", "Appends directly to /etc/passwd",
        "Writing accounts directly (instead of useradd) is how backdoor root users are created.",
        QStringLiteral(R"(>>\s*/etc/passwd\b)"));
    add("priv.user-management", S::Low, "Privilege", "Creates or modifies user accounts",
        "Common for daemons that need a system user, but worth confirming.",
        QStringLiteral(R"(\b(useradd|adduser|usermod|groupadd|chpasswd)\b)"), false, true);
    add("priv.setuid", S::Medium, "Privilege", "Sets setuid/setgid permission bits",
        "setuid binaries run with the owner's privileges and widen the attack surface.",
        QStringLiteral(R"(chmod\s+(-\S+\s+)*([ugoa]*[+=][rwxXt]*s|0?[2-7][0-7]{3})\b)"), false, true);
    add("persist.cron", S::Medium, "Persistence", "Installs or edits cron jobs",
        "Scheduled tasks are a common persistence mechanism.",
        QStringLiteral(R"(\bcrontab\b|/etc/cron(\.d|tab|\.daily|\.hourly|\.weekly|\.monthly)|/var/spool/cron)"), false, true);
    add("persist.systemd-enable", S::Low, "Persistence", "Enables a systemd unit",
        "Normal for services, but it means code will start automatically on boot.",
        QStringLiteral(R"(systemctl\s+(--\S+\s+)*enable\b)"), false, true);
    add("persist.autostart", S::Medium, "Persistence", "Uses desktop autostart",
        "Entries in autostart directories run on every graphical login.",
        QStringLiteral(R"(/etc/xdg/autostart|\.config/autostart)"), false, true);
    add("persist.shell-rc", S::Medium, "Persistence", "Appends to shell startup files",
        "Code added to .bashrc/.profile runs every time a shell starts.",
        QStringLiteral(R"(>>?\s*["']?\S*\.(bashrc|bash_profile|zshrc|profile|zprofile)\b)"));
    add("persist.profile-d", S::Medium, "Persistence", "Writes global shell environment files",
        "/etc/profile.d and /etc/environment affect every user session.",
        QStringLiteral(R"(>>?\s*["']?(/etc/profile\.d/|/etc/environment|/etc/bash\.bashrc))"));
    add("persist.pam", S::High, "Credential access", "Touches PAM configuration or modules",
        "Malicious PAM modules can log or bypass passwords.",
        QStringLiteral(R"(/etc/pam\.d/|\bpam_exec\.so\b)"), false, true);
    add("persist.sshd", S::Medium, "Persistence", "References SSH server configuration",
        "Enabling root login or changing sshd settings weakens remote access security.",
        QStringLiteral(R"(/etc/ssh/sshd_config|PermitRootLogin\s+yes)"), false, true);
    add("kernel.module-load", S::Medium, "Kernel", "Loads or unloads kernel modules",
        "Kernel code runs with full privileges; expected for drivers/DKMS, suspicious otherwise.",
        QStringLiteral(R"(\b(insmod|modprobe|rmmod)\b)"), false, true);
    add("kernel.sysctl-write", S::Medium, "Defense evasion", "Writes kernel parameters under /proc/sys",
        "Changing kernel settings (e.g. ptrace_scope, kptr_restrict) can weaken system hardening.",
        QStringLiteral(R"(>\s*/proc/sys/|sysctl\s+-w\b)"), false, true);

    // Defense evasion / anti-forensics
    add("evasion.immutable", S::High, "Defense evasion", "Changes immutable file attributes",
        "chattr +i is used to make malware files undeletable.",
        QStringLiteral(R"(chattr\s+[+-][aiAI]*i)"), false, true);
    add("evasion.selinux", S::High, "Defense evasion", "Disables SELinux",
        "Turning off mandatory access control removes a security layer.",
        QStringLiteral(R"(setenforce\s+0|SELINUX\s*=\s*disabled)"));
    add("evasion.firewall", S::Medium, "Defense evasion", "Flushes or disables the firewall",
        "Firewall changes can expose services to the network.",
        QStringLiteral(R"(iptables\s+(-F|--flush|-P\s+INPUT\s+ACCEPT)|ufw\s+disable|nft\s+flush\s+ruleset|systemctl\s+(stop|disable|mask)\s+(firewalld|ufw|nftables))"));
    add("evasion.history", S::High, "Anti-forensics", "Clears or disables shell history",
        "Erasing history hides attacker activity.",
        QStringLiteral(R"(history\s+-c\b|unset\s+HISTFILE|HISTFILE=/dev/null|HISTSIZE=0\b)"));
    add("evasion.log-wipe", S::High, "Anti-forensics", "Deletes or truncates system logs",
        "Removing logs hides evidence of compromise.",
        QStringLiteral(R"((\brm|\bshred|\btruncate)\b[^\n]*\s/var/log\b|>\s*/var/log/(wtmp|btmp|lastlog|auth\.log|secure|syslog)\b)"));
    add("evasion.kill-security", S::High, "Defense evasion", "Stops security / monitoring tools",
        "Killing audit and AV daemons is a strong malicious signal.",
        QStringLiteral(R"(\b(pkill|killall|kill\s+-9|systemctl\s+stop)\b[^\n]*\b(auditd|clamd|clamav|rkhunter|chkrootkit|osqueryd|falco|wazuh|falcon-sensor|apparmor|sysdig)\b)"), true);

    // Network / exfiltration
    add("net.exfil-service", S::High, "Exfiltration", "Uses a paste/webhook/tunnel service",
        "These services are frequently abused for command-and-control and data exfiltration.",
        QStringLiteral(R"(pastebin\.com/raw|transfer\.sh|ngrok\.(io|app)|discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|hastebin\.com|0x0\.st|webhook\.site|requestbin|anonfiles\.com|file\.io/|pipedream\.net)"), true, false, true);
    add("net.tor", S::High, "Network", "References a Tor hidden service (.onion)",
        "Tor addresses are used to hide C2 infrastructure.",
        QStringLiteral(R"(\b[a-z2-7]{16}(?:[a-z2-7]{40})?\.onion\b)"), true, false, true);
    add("net.insecure-tls", S::Low, "Integrity", "Downloads with TLS verification disabled",
        "curl -k / wget --no-check-certificate allows trivial man-in-the-middle replacement of downloads.",
        QStringLiteral(R"(\bcurl\b[^\n]*\s(-k|--insecure)\b|--no-check-certificate)"));
    add("net.hosts-file", S::High, "Network", "Writes /etc/hosts or resolver configuration",
        "Redirecting name resolution can hijack updates, banking or login sites.",
        QStringLiteral(R"(>>?\s*["']?/etc/(hosts|resolv\.conf)\b)"));
    add("integrity.repo-add", S::Low, "Integrity", "Adds a third-party package repository or signing key",
        "Common for vendor packages (Chrome, VS Code …) but grants the vendor future root-level updates.",
        QStringLiteral(R"(/etc/apt/sources\.list\.d|apt-key\s+add|/etc/apt/trusted\.gpg|/etc/yum\.repos\.d|zypper\s+(ar|addrepo)\b|>>?\s*/etc/pacman\.conf)"), false, true);
    add("misc.docker-socket", S::Medium, "Privilege", "Accesses the Docker socket",
        "Access to docker.sock is equivalent to root.",
        QStringLiteral(R"(/var/run/docker\.sock|/run/docker\.sock)"), false, true);

    // Credential theft
    add("cred.browser-wallet", S::High, "Credential access", "References browser profiles, wallets or SSH/cloud credentials",
        "Info-stealers target these locations. Browsers themselves legitimately reference their own profile.",
        QStringLiteral(R"(\.mozilla/firefox|\.config/(google-chrome|chromium|BraveSoftware)|logins\.json|key4\.db|\.ssh/id_(rsa|ed25519|ecdsa)|\.aws/credentials|\.kube/config|wallet\.dat|\.electrum/|Local Storage/leveldb|\.gnupg/)"), false, true);
    add("cred.input-capture", S::Medium, "Collection", "Captures keyboard/input events",
        "Reading /dev/input or xinput test output can be used for keylogging.",
        QStringLiteral(R"(/dev/input/event|xinput\s+(--)?test\b|\blogkeys\b)"), false, true);

    // Destructive
    add("destroy.rm-root", S::Critical, "Destructive", "Recursive deletion of the root filesystem",
        "This wipes the system.",
        QStringLiteral(R"(\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*|-rf|-fr)\s+(--no-preserve-root\s+)?["']?/(\*|["']?\s|["']?$))"), false, true);
    add("destroy.disk-wipe", S::Critical, "Destructive", "Overwrites a raw disk device",
        "Writing zeros/random data to /dev/sdX or nvme destroys data.",
        QStringLiteral(R"(\bdd\b[^\n]*of=/dev/(sd[a-z]|nvme\d|vd[a-z]|mmcblk\d)|\bmkfs(\.\w+)?\s+[^\n]*/dev/(sd[a-z]|nvme\d|vd[a-z]))"), false, true);
    add("destroy.forkbomb", S::Critical, "Destructive", "Fork bomb",
        "Exhausts process table and freezes the system.",
        QStringLiteral(R"(:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:)"), false, true);

    m_url = rx(QStringLiteral(R"(\b(?:https?|ftp|wss?)://[A-Za-z0-9\-._~%]+(?::\d{1,5})?(?:/[^\s"'<>`\\)\]}|^]*)?)"));
    m_ipv4 = rx(QStringLiteral(R"((?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.]))"));
    m_onion = rx(QStringLiteral(R"(\b[a-z2-7]{16}(?:[a-z2-7]{40})?\.onion\b)"));
}

void ContentScanner::collectIndicators(const QString &line, const QString &location, IndicatorCollector &ioc) const
{
    auto it = m_url.globalMatch(line);
    int n = 0;
    while (it.hasNext() && n++ < 50) {
        QString u = it.next().captured(0);
        while (u.endsWith(QLatin1Char('.')) || u.endsWith(QLatin1Char(',')) || u.endsWith(QLatin1Char(';'))) u.chop(1);
        if (u.size() > 12) ioc.add(QStringLiteral("url"), u.left(300), location);
    }
    auto ip = m_ipv4.globalMatch(line);
    n = 0;
    while (ip.hasNext() && n++ < 50) {
        const auto m = ip.next();
        const QString v = m.captured(0);
        if (util::isNonRoutableIp(v)) continue;
        // Skip things that look like version strings ("version 1.2.3.4", "v1.2.3.4").
        const qsizetype s = m.capturedStart(0);
        const QString before = line.mid(std::max<qsizetype>(0, s - 10), std::min<qsizetype>(s, 10)).toLower();
        if (before.contains(QLatin1String("version")) || before.endsWith(QLatin1Char('v'))) continue;
        ioc.add(QStringLiteral("ip"), v, location);
    }
    auto on = m_onion.globalMatch(line);
    while (on.hasNext()) ioc.add(QStringLiteral("onion"), on.next().captured(0), location);
}

void ContentScanner::scanText(const QByteArray &data, const QString &location, ContentKind kind,
                              QVector<Finding> &out, IndicatorCollector &ioc, QVector<int> *flagged) const
{
    const bool isScript = kind == ContentKind::MaintainerScript || kind == ContentKind::Script
                       || kind == ContentKind::Desktop || kind == ContentKind::Config;
    const bool hasPem = data.contains("-----BEGIN ");
    const QString text = QString::fromUtf8(data);
    QHash<QString, int> perRule;
    int lineNo = 0;
    qsizetype pos = 0;
    while (pos <= text.size()) {
        qsizetype nl = text.indexOf(QLatin1Char('\n'), pos);
        if (nl < 0) nl = text.size();
        const QStringView full = QStringView(text).mid(pos, nl - pos);
        pos = nl + 1;
        ++lineNo;
        if (full.trimmed().isEmpty()) continue;
        const QString line = full.size() > 8192 ? full.left(8192).toString() : full.toString();
        const QStringView trimmed = QStringView(line).trimmed();
        const bool isComment = isScript && trimmed.startsWith(QLatin1Char('#')) && !trimmed.startsWith(QLatin1String("#!"));

        collectIndicators(line, location, ioc);
        if (isComment) continue;

        bool lineFlagged = false;
        for (const Rule &r : m_rules) {
            if (r.scriptsOnly && !isScript) continue;
            if (r.id.startsWith(QLatin1String("obf.")) && r.scriptsOnly && kind != ContentKind::Script && kind != ContentKind::MaintainerScript) continue;
            if (r.id == QLatin1String("obf.base64-blob") && hasPem) continue;
            const QString &subject = (r.id.startsWith(QLatin1String("obf.")) && full.size() > 8192) ? text.mid(pos - full.size() - 1, full.size()) : line;
            const auto m = r.re.match(subject);
            if (!m.hasMatch()) continue;
            if (r.id == QLatin1String("obf.base64-blob")) {
                static const QRegularExpression nonHex(QStringLiteral("[g-zG-Z+/]"));
                if (!nonHex.match(m.captured(0)).hasMatch()) continue; // long hex (e.g. DH moduli) is not base64
            }
            lineFlagged = true;
            int &count = perRule[r.id];
            ++count;
            if (count > 1) {
                // Aggregate repeated hits into the first finding of this rule for this file.
                for (Finding &f : out)
                    if (f.ruleId == r.id && f.location == location) {
                        f.title = r.title + QStringLiteral(" (%1 occurrences)").arg(count);
                        break;
                    }
                continue;
            }
            Finding f;
            f.ruleId = r.id;
            f.severity = r.sev;
            if (kind == ContentKind::Text && !r.keepInBinary) {
                f.severity = downgrade(downgrade(r.sev));
                if (f.severity == Severity::Info) { --count; continue; }
            }
            if (kind == ContentKind::MaintainerScript && r.sev >= Severity::Low && r.sev < Severity::Critical
                && (r.id.startsWith(QLatin1String("exec.")) || r.id.startsWith(QLatin1String("backdoor.")) || r.id.startsWith(QLatin1String("obf."))))
                f.severity = static_cast<Severity>(static_cast<int>(r.sev) + 1);
            f.category = r.category;
            f.title = r.title;
            f.detail = r.detail;
            if (kind == ContentKind::MaintainerScript) f.detail += QStringLiteral(" This runs as root during installation.");
            f.location = location;
            f.line = lineNo;
            f.evidence = util::sanitizeOneLine(m.capturedStart(0) > 60 ? line.mid(m.capturedStart(0) - 40) : line, 220);
            f.origin = QStringLiteral("static");
            out << f;
        }
        if (lineFlagged && flagged) flagged->append(lineNo);
    }
}

QByteArray ContentScanner::extractStrings(const QByteArray &data, int minLen, qsizetype maxOut)
{
    QByteArray out;
    out.reserve(std::min<qsizetype>(data.size() / 4, maxOut));
    qsizetype start = -1;
    const char *d = data.constData();
    for (qsizetype i = 0; i <= data.size(); ++i) {
        const bool printable = i < data.size() && ((d[i] >= 0x20 && d[i] < 0x7f) || d[i] == '\t');
        if (printable) {
            if (start < 0) start = i;
        } else if (start >= 0) {
            if (i - start >= minLen) {
                out.append(d + start, std::min<qsizetype>(i - start, 4096));
                out.append('\n');
                if (out.size() > maxOut) break;
            }
            start = -1;
        }
    }
    return out;
}

void ContentScanner::scanBinary(const QByteArray &data, const QString &location, QVector<Finding> &out,
                                IndicatorCollector &ioc) const
{
    const QByteArray strings = extractStrings(data);
    const QString text = QString::fromLatin1(strings);
    QSet<QString> seen;
    qsizetype pos = 0;
    int iocLines = 0;
    while (pos < text.size()) {
        qsizetype nl = text.indexOf(QLatin1Char('\n'), pos);
        if (nl < 0) nl = text.size();
        const QString line = text.mid(pos, nl - pos);
        pos = nl + 1;
        if (iocLines < 20000) {
            collectIndicators(line, location, ioc);
            ++iocLines;
        }
        for (const Rule &r : m_rules) {
            if (r.scriptsOnly || seen.contains(r.id)) continue;
            const auto m = r.re.match(line);
            if (!m.hasMatch()) continue;
            seen.insert(r.id);
            Finding f;
            f.ruleId = r.id;
            f.severity = r.keepInBinary ? r.sev : downgrade(downgrade(r.sev));
            if (f.severity == Severity::Info) continue; // too weak to report from a string table
            f.category = r.category;
            f.title = r.title + QStringLiteral(" (string in binary)");
            f.detail = r.detail + QStringLiteral(" Found as an embedded string, which is weaker evidence than a script.");
            f.location = location;
            f.evidence = util::sanitizeOneLine(line, 220);
            f.origin = QStringLiteral("static");
            out << f;
        }
    }
}

// ---------------------------------------------------------------- Path rules

const QVector<ContentScanner::PathRule> &ContentScanner::persistencePathRules()
{
    using S = Severity;
    static const QVector<PathRule> rules = {
        {QStringLiteral("path.ld-preload"), S::Critical, QStringLiteral("Rootkit"), QStringLiteral("Writes ld.so.preload in /etc (global library injection)"), rx(QStringLiteral(R"(^/etc/ld\.so\.preload$)"))},
        {QStringLiteral("path.sudoers"), S::High, QStringLiteral("Privilege"), QStringLiteral("Installs sudo rules"), rx(QStringLiteral(R"(^/etc/sudoers(\.d/.*)?$)"))},
        {QStringLiteral("path.pam-module"), S::High, QStringLiteral("Credential access"), QStringLiteral("Installs a PAM authentication module"), rx(QStringLiteral(R"(/security/pam_[^/]+\.so$)"))},
        {QStringLiteral("path.pam"), S::Medium, QStringLiteral("Credential access"), QStringLiteral("Installs PAM configuration"), rx(QStringLiteral(R"(^/etc/pam\.d/)"))},
        {QStringLiteral("path.ssh-keys"), S::High, QStringLiteral("Persistence"), QStringLiteral("Writes SSH authorized_keys"), rx(QStringLiteral(R"(authorized_keys2?$)"))},
        {QStringLiteral("path.ssh"), S::Low, QStringLiteral("Persistence"), QStringLiteral("Ships SSH client/server configuration"), rx(QStringLiteral(R"(^/etc/ssh/)"))},
        {QStringLiteral("path.kernel-module"), S::High, QStringLiteral("Kernel"), QStringLiteral("Installs a kernel module"), rx(QStringLiteral(R"(^/(usr/)?lib/modules/.*\.ko(\.(xz|zst|gz))?$)"))},
        {QStringLiteral("path.modules-load"), S::Medium, QStringLiteral("Kernel"), QStringLiteral("Configures modules to load at boot"), rx(QStringLiteral(R"(^/(etc|usr/lib)/modules-load\.d/|^/etc/modules$)"))},
        {QStringLiteral("path.cron"), S::Medium, QStringLiteral("Persistence"), QStringLiteral("Installs a cron job"), rx(QStringLiteral(R"(^/etc/cron|^/var/spool/cron)"))},
        {QStringLiteral("path.systemd-system"), S::Low, QStringLiteral("Persistence"), QStringLiteral("Installs a system service/timer"), rx(QStringLiteral(R"(^/(etc|usr/lib|lib)/systemd/system/[^/]+\.(service|timer|socket|path)$)"))},
        {QStringLiteral("path.systemd-user"), S::Low, QStringLiteral("Persistence"), QStringLiteral("Installs a per-user service"), rx(QStringLiteral(R"(^/(etc|usr/lib)/systemd/user/[^/]+\.(service|timer|socket)$)"))},
        {QStringLiteral("path.systemd-generator"), S::Medium, QStringLiteral("Persistence"), QStringLiteral("Installs a systemd generator (runs at every boot)"), rx(QStringLiteral(R"(^/(etc|usr/lib|lib)/systemd/(system|user)-generators/)"))},
        {QStringLiteral("path.autostart"), S::Low, QStringLiteral("Persistence"), QStringLiteral("Adds a desktop autostart entry"), rx(QStringLiteral(R"(^/etc/xdg/autostart/|/\.config/autostart/)"))},
        {QStringLiteral("path.profile"), S::Medium, QStringLiteral("Persistence"), QStringLiteral("Adds a global login-shell script"), rx(QStringLiteral(R"(^/etc/(profile\.d/|profile$|bash\.bashrc$|environment$|zsh/))"))},
        {QStringLiteral("path.shell-rc"), S::High, QStringLiteral("Persistence"), QStringLiteral("Writes a user shell startup file"), rx(QStringLiteral(R"(/\.(bashrc|bash_profile|profile|zshrc|zprofile)$)"))},
        {QStringLiteral("path.udev"), S::Low, QStringLiteral("Persistence"), QStringLiteral("Installs udev rules"), rx(QStringLiteral(R"(^/(etc|usr/lib|lib)/udev/rules\.d/)"))},
        {QStringLiteral("path.polkit"), S::Medium, QStringLiteral("Privilege"), QStringLiteral("Installs polkit rules"), rx(QStringLiteral(R"(^/(etc|usr/share)/polkit-1/rules\.d/)"))},
        {QStringLiteral("path.nm-dispatcher"), S::Medium, QStringLiteral("Persistence"), QStringLiteral("Installs a NetworkManager dispatcher script"), rx(QStringLiteral(R"(^/etc/NetworkManager/dispatcher\.d/)"))},
        {QStringLiteral("path.hosts"), S::High, QStringLiteral("Network"), QStringLiteral("Overwrites name-resolution configuration"), rx(QStringLiteral(R"(^/etc/(hosts|resolv\.conf|nsswitch\.conf)$)"))},
        {QStringLiteral("path.repo"), S::Low, QStringLiteral("Integrity"), QStringLiteral("Adds a package repository or trusted key"), rx(QStringLiteral(R"(^/etc/apt/(sources\.list\.d/|trusted\.gpg)|^/etc/yum\.repos\.d/|^/etc/zypp/repos\.d/|^/etc/pacman\.(conf|d/))"))},
        {QStringLiteral("path.ld-conf"), S::Low, QStringLiteral("Integrity"), QStringLiteral("Adds a dynamic linker search path"), rx(QStringLiteral(R"(^/etc/ld\.so\.conf(\.d/.*)?$)"))},
        {QStringLiteral("path.binfmt"), S::Medium, QStringLiteral("Persistence"), QStringLiteral("Registers a binfmt_misc handler"), rx(QStringLiteral(R"(^/(etc|usr/lib)/binfmt\.d/)"))},
        {QStringLiteral("path.home"), S::High, QStringLiteral("Filesystem"), QStringLiteral("Writes into a home directory"), rx(QStringLiteral(R"(^/(home/[^/]+|root)/)"))},
        {QStringLiteral("path.tmp-exec"), S::Medium, QStringLiteral("Filesystem"), QStringLiteral("Places files in a temporary directory"), rx(QStringLiteral(R"(^/(tmp|var/tmp|dev/shm)/)"))},
        {QStringLiteral("path.boot"), S::High, QStringLiteral("Kernel"), QStringLiteral("Writes into /boot (bootloader/kernel)"), rx(QStringLiteral(R"(^/boot/)"))},
        {QStringLiteral("path.log"), S::Medium, QStringLiteral("Anti-forensics"), QStringLiteral("Modifies log files"), rx(QStringLiteral(R"(^/var/log/(wtmp|btmp|lastlog|auth\.log|secure|syslog|messages))"))},
    };
    return rules;
}

const QVector<ContentScanner::PathRule> &ContentScanner::sensitiveReadRules()
{
    using S = Severity;
    static const QVector<PathRule> rules = {
        {QStringLiteral("read.shadow"), S::High, QStringLiteral("Credential access"), QStringLiteral("Reads password hashes"), rx(QStringLiteral(R"(^/etc/(g)?shadow-?$)"))},
        {QStringLiteral("read.ssh-keys"), S::High, QStringLiteral("Credential access"), QStringLiteral("Reads SSH private keys"), rx(QStringLiteral(R"(/\.ssh/(id_|identity)|^/etc/ssh/ssh_host_.*_key$)"))},
        {QStringLiteral("read.browser"), S::High, QStringLiteral("Credential access"), QStringLiteral("Reads browser profile / credential stores"), rx(QStringLiteral(R"(/\.mozilla/firefox/|/\.config/(google-chrome|chromium|BraveSoftware|vivaldi|opera)/)"))},
        {QStringLiteral("read.cloud-creds"), S::High, QStringLiteral("Credential access"), QStringLiteral("Reads cloud/developer credentials"), rx(QStringLiteral(R"(/\.(aws|kube|docker|gnupg|password-store)/|/\.netrc$|/\.git-credentials$|/\.config/gh/)"))},
        {QStringLiteral("read.wallet"), S::High, QStringLiteral("Credential access"), QStringLiteral("Reads cryptocurrency wallets"), rx(QStringLiteral(R"(wallet\.dat$|/\.electrum/|/\.bitcoin/|/\.ethereum/keystore|/Exodus/)"))},
        {QStringLiteral("read.proc-mem"), S::High, QStringLiteral("Credential access"), QStringLiteral("Reads another process' memory or environment"), rx(QStringLiteral(R"(^/proc/(\d+)/(mem|environ|maps)$)"))},
        {QStringLiteral("read.input"), S::Medium, QStringLiteral("Collection"), QStringLiteral("Opens raw input devices"), rx(QStringLiteral(R"(^/dev/input/)"))},
        {QStringLiteral("read.history"), S::Medium, QStringLiteral("Collection"), QStringLiteral("Reads shell history"), rx(QStringLiteral(R"(/\.(bash|zsh|python)_history$|/\.histfile$)"))},
    };
    return rules;
}

void ContentScanner::checkInstallPath(const FileEntry &fe, QVector<Finding> &out, bool locationRules)
{
    const auto make = [&](const QString &id, Severity sev, const QString &cat, const QString &title, const QString &detail) {
        Finding f;
        f.ruleId = id;
        f.severity = sev;
        f.category = cat;
        f.title = title;
        f.detail = detail;
        f.location = fe.path;
        f.origin = QStringLiteral("static");
        out << f;
    };

    if (locationRules && (fe.type == QLatin1String("file") || fe.type == QLatin1String("symlink") || fe.type == QLatin1String("hardlink"))) {
        for (const PathRule &r : persistencePathRules()) {
            if (r.id == QLatin1String("path.tmp-exec") || r.id == QLatin1String("path.log")) continue;
            if (r.re.match(fe.path).hasMatch()) {
                make(r.id, r.sev, r.category, r.title, QStringLiteral("The package installs %1.").arg(fe.path));
                break;
            }
        }
    }
    if (fe.type == QLatin1String("file") && (fe.mode & S_ISUID))
        make(QStringLiteral("perm.setuid"), fe.owner.startsWith(QLatin1String("root")) || fe.owner.startsWith(QLatin1String("0:")) ? Severity::High : Severity::Medium,
             QStringLiteral("Privilege"), QStringLiteral("setuid executable"),
             QStringLiteral("Runs with the privileges of its owner (%1) regardless of who starts it.").arg(fe.owner));
    else if (fe.type == QLatin1String("file") && (fe.mode & S_ISGID))
        make(QStringLiteral("perm.setgid"), Severity::Medium, QStringLiteral("Privilege"), QStringLiteral("setgid executable"),
             QStringLiteral("Runs with the group privileges of %1.").arg(fe.owner));
    if (fe.type == QLatin1String("file") && (fe.mode & S_IWOTH))
        make(QStringLiteral("perm.world-writable"), Severity::Medium, QStringLiteral("Privilege"), QStringLiteral("World-writable file"),
             QStringLiteral("Any local user can modify this file; if it is executed by root this is a privilege escalation."));
    if (fe.type == QLatin1String("dir") && (fe.mode & S_IWOTH) && !(fe.mode & S_ISVTX))
        make(QStringLiteral("perm.world-writable-dir"), Severity::Medium, QStringLiteral("Privilege"), QStringLiteral("World-writable directory without sticky bit"),
             QStringLiteral("Any user can replace files inside it."));
    if (fe.type == QLatin1String("char") || fe.type == QLatin1String("block"))
        make(QStringLiteral("perm.device-node"), Severity::High, QStringLiteral("Privilege"), QStringLiteral("Package ships a device node"),
             QStringLiteral("Device files can expose raw memory or disks. Packages normally rely on udev instead."));

    const QString name = fe.path.section(QLatin1Char('/'), -1);
    static const QRegularExpression sysDir(QStringLiteral(R"(^/(usr/)?(s?bin|lib(32|64)?|libexec)/|^/etc/)"));
    if (locationRules && name.startsWith(QLatin1Char('.')) && name.size() > 1 && sysDir.match(fe.path).hasMatch() && fe.type != QLatin1String("dir")
        && !name.startsWith(QLatin1String(".build-id")) && name != QLatin1String(".keep") && !name.endsWith(QLatin1String(".hmac")))
        make(QStringLiteral("path.hidden-system"), Severity::Medium, QStringLiteral("Defense evasion"), QStringLiteral("Hidden file in a system directory"),
             QStringLiteral("Dot-files inside system directories are a common hiding spot for implants."));
    for (QChar c : name) {
        if (!c.isPrint() || c == QChar(0x202E)) {
            make(QStringLiteral("path.weird-name"), Severity::Medium, QStringLiteral("Defense evasion"), QStringLiteral("File name contains control or bidi characters"),
                 QStringLiteral("Non-printable characters are used to disguise file names."));
            break;
        }
    }
    if (fe.type == QLatin1String("symlink")) {
        static const QRegularExpression sens(QStringLiteral(R"(^/etc/(shadow|sudoers|passwd)$|^/root|/\.ssh/|^/proc/|^/dev/(mem|kmem|sd|nvme))"));
        if (sens.match(fe.linkTarget).hasMatch())
            make(QStringLiteral("path.symlink-sensitive"), Severity::High, QStringLiteral("Privilege"), QStringLiteral("Symlink pointing at a sensitive location"),
                 QStringLiteral("%1 -> %2").arg(fe.path, fe.linkTarget));
    }
}

} // namespace ps
