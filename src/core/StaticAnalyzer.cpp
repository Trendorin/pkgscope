// SPDX-License-Identifier: MIT
#include "StaticAnalyzer.h"
#include "ArchiveReader.h"
#include "ElfParser.h"
#include "RpmHeader.h"
#include "SecureFs.h"
#include "Util.h"

#include <QCryptographicHash>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QRegularExpression>
#include <QSet>
#include <QThread>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace ps {

namespace {

const QStringList kDocPrefixes = {
    QStringLiteral("/usr/share/doc/"), QStringLiteral("/usr/share/man/"), QStringLiteral("/usr/share/info/"),
    QStringLiteral("/usr/share/licenses/"), QStringLiteral("/usr/share/locale/"), QStringLiteral("/usr/share/help/"),
    QStringLiteral("/usr/share/gtk-doc/"), QStringLiteral("/usr/include/"), QStringLiteral("/usr/share/icons/"),
    QStringLiteral("/usr/share/i18n/"), QStringLiteral("/usr/share/mime/"),
};

bool isDocPath(const QString &p)
{
    for (const QString &d : kDocPrefixes)
        if (p.startsWith(d) || p.contains(QLatin1String("/usr/share/doc/"))) return true;
    return false;
}

const QSet<QString> kScriptExt = {QStringLiteral("sh"), QStringLiteral("bash"), QStringLiteral("zsh"), QStringLiteral("ksh"),
                                  QStringLiteral("py"), QStringLiteral("pl"), QStringLiteral("rb"), QStringLiteral("lua"),
                                  QStringLiteral("fish"), QStringLiteral("csh"), QStringLiteral("tcl")};
const QSet<QString> kConfigExt = {QStringLiteral("service"), QStringLiteral("timer"), QStringLiteral("socket"),
                                  QStringLiteral("path"), QStringLiteral("rules"), QStringLiteral("conf"),
                                  QStringLiteral("cron"), QStringLiteral("hook"), QStringLiteral("target"),
                                  QStringLiteral("mount"), QStringLiteral("automount")};

QString shebangInterpreter(const QByteArray &content)
{
    if (!content.startsWith("#!")) return {};
    const qsizetype nl = content.indexOf('\n');
    return QString::fromUtf8(content.mid(2, (nl < 0 ? content.size() : nl) - 2)).trimmed().left(200);
}

QMap<QString, QString> parseRfc822(const QByteArray &data)
{
    QMap<QString, QString> m;
    QString key;
    for (const QByteArray &raw : data.split('\n')) {
        const QString line = QString::fromUtf8(raw);
        if (line.startsWith(QLatin1Char(' ')) || line.startsWith(QLatin1Char('\t'))) {
            if (!key.isEmpty()) m[key] += QLatin1Char('\n') + line.trimmed();
            continue;
        }
        const qsizetype c = line.indexOf(QLatin1Char(':'));
        if (c <= 0) continue;
        key = line.left(c).trimmed();
        m[key] = line.mid(c + 1).trimmed();
    }
    return m;
}

QMap<QString, QStringList> parseKeyEq(const QByteArray &data) // .PKGINFO style
{
    QMap<QString, QStringList> m;
    for (const QByteArray &raw : data.split('\n')) {
        const QString line = QString::fromUtf8(raw).trimmed();
        if (line.isEmpty() || line.startsWith(QLatin1Char('#'))) continue;
        const qsizetype eq = line.indexOf(QLatin1Char('='));
        if (eq <= 0) continue;
        m[line.left(eq).trimmed()] << line.mid(eq + 1).trimmed();
    }
    return m;
}

QMap<QString, QString> parseDesktop(const QByteArray &data)
{
    QMap<QString, QString> m;
    bool inMain = false;
    for (const QByteArray &raw : data.split('\n')) {
        const QString line = QString::fromUtf8(raw).trimmed();
        if (line.startsWith(QLatin1Char('['))) { inMain = line == QLatin1String("[Desktop Entry]"); continue; }
        if (!inMain) continue;
        const qsizetype eq = line.indexOf(QLatin1Char('='));
        if (eq > 0) m.insert(line.left(eq).trimmed(), line.mid(eq + 1).trimmed());
    }
    return m;
}

QString mtreeUnescape(const QString &s)
{
    QString out;
    for (qsizetype i = 0; i < s.size(); ++i) {
        if (s[i] == QLatin1Char('\\') && i + 3 < s.size() && s[i + 1].isDigit() && s[i + 2].isDigit() && s[i + 3].isDigit()) {
            out += QChar(s.mid(i + 1, 3).toInt(nullptr, 8));
            i += 3;
        } else {
            out += s[i];
        }
    }
    return out;
}

quint32 parseModeString(const QString &s)
{
    if (s.size() < 10) return 0;
    quint32 m = 0;
    switch (s[0].unicode()) {
    case 'd': m = S_IFDIR; break;
    case 'l': m = S_IFLNK; break;
    case 'c': m = S_IFCHR; break;
    case 'b': m = S_IFBLK; break;
    case 'p': m = S_IFIFO; break;
    case 's': m = S_IFSOCK; break;
    default: m = S_IFREG;
    }
    const quint32 bits[9] = {S_IRUSR, S_IWUSR, S_IXUSR, S_IRGRP, S_IWGRP, S_IXGRP, S_IROTH, S_IWOTH, S_IXOTH};
    for (int i = 0; i < 9; ++i) {
        const QChar c = s[i + 1];
        if (c != QLatin1Char('-') && c != QLatin1Char('S') && c != QLatin1Char('T')) m |= bits[i];
    }
    if (s[3] == QLatin1Char('s') || s[3] == QLatin1Char('S')) m |= S_ISUID;
    if (s[6] == QLatin1Char('s') || s[6] == QLatin1Char('S')) m |= S_ISGID;
    if (s[9] == QLatin1Char('t') || s[9] == QLatin1Char('T')) m |= S_ISVTX;
    return m;
}

bool writeFile(const QString &path, const QByteArray &content, mode_t mode)
{
    const int fd = ::open(QFile::encodeName(path).constData(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    qsizetype off = 0;
    while (off < content.size()) {
        const ssize_t w = ::write(fd, content.constData() + off, static_cast<size_t>(content.size() - off));
        if (w <= 0) break;
        off += w;
    }
    ::fchmod(fd, mode);
    ::close(fd);
    return off == content.size();
}

QString safeFileName(const QString &name)
{
    QString s;
    for (QChar c : name) s += (c.isLetterOrNumber() || c == QLatin1Char('.') || c == QLatin1Char('_') || c == QLatin1Char('-')) ? c : QLatin1Char('_');
    if (s.isEmpty() || s.startsWith(QLatin1Char('.'))) s.prepend(QLatin1String("input"));
    return s.left(120);
}

QString shellBinary()
{
    for (const char *p : {"/bin/bash", "/usr/bin/bash"})
        if (::access(p, X_OK) == 0) return QString::fromLatin1(p);
    return QStringLiteral("/bin/sh");
}

} // namespace

struct StaticAnalyzer::Ctx {
    QString path;
    QString name;
    AnalysisResult &r;
    Workspace &ws;
    const Progress &progress;
    const std::atomic<bool> *cancel;
    QByteArray head;
    ExtractStats payload, control;
    IndicatorCollector ioc;
    QHash<QString, QByteArray> expectedMd5, expectedSha256; // raw digests
    QSet<QString> conffiles;
    QSet<QString> scannedPaths;
    QString integritySource;
    int hashed = 0;

    bool cancelled() const { return cancel && cancel->load(); }
    void log(const QString &m) { r.log << m; }
    void step(int pct, const QString &m) { if (progress) progress(pct, m); }
    void finding(const QString &id, Severity sev, const QString &cat, const QString &title, const QString &detail,
                 const QString &loc = {}, const QString &evidence = {})
    {
        Finding f;
        f.ruleId = id;
        f.severity = sev;
        f.category = cat;
        f.title = title;
        f.detail = detail;
        f.location = loc;
        f.evidence = evidence;
        f.origin = QStringLiteral("static");
        r.findings << f;
    }
};

StaticAnalyzer::StaticAnalyzer(Settings s) : m_s(std::move(s)) {}

QString StaticAnalyzer::unsquashfsPath(const Settings &s)
{
    if (!s.unsquashfsOverride.isEmpty() && QFileInfo(s.unsquashfsOverride).isExecutable()) return s.unsquashfsOverride;
    return util::findHelper(QStringLiteral("unsquashfs"));
}

bool StaticAnalyzer::analyze(const QString &inputPath, AnalysisResult &r, std::shared_ptr<Workspace> &ws,
                             const Progress &progress, const std::atomic<bool> *cancel)
{
    QElapsedTimer timer;
    timer.start();
    r = AnalysisResult();
    r.analyzedAt = QDateTime::currentDateTime();
    const QFileInfo fi(inputPath);
    r.inputPath = fi.absoluteFilePath();
    r.fileName = fi.fileName();

    struct stat st{};
    if (::stat(QFile::encodeName(r.inputPath).constData(), &st) != 0 || !S_ISREG(st.st_mode)) {
        r.log << QStringLiteral("Input is not a regular file.");
        return false;
    }
    r.fileSize = static_cast<quint64>(st.st_size);

    QString err;
    ws = Workspace::create(&err);
    if (!ws) {
        r.log << err;
        return false;
    }

    Ctx c{r.inputPath, r.fileName, r, *ws, progress, cancel, {}, {}, {}, {}, {}, {}, {}, {}, {}, 0};
    c.step(1, QStringLiteral("Hashing input"));

    // Hash + head
    {
        QFile f(r.inputPath);
        if (!f.open(QIODevice::ReadOnly)) {
            r.log << QStringLiteral("Cannot open input: %1").arg(f.errorString());
            return false;
        }
        QCryptographicHash h256(QCryptographicHash::Sha256), h1(QCryptographicHash::Sha1);
        QByteArray buf;
        while (!(buf = f.read(1 << 20)).isEmpty()) {
            if (c.head.size() < 4 * 1024 * 1024) c.head.append(buf.left(4 * 1024 * 1024 - c.head.size()));
            h256.addData(buf);
            h1.addData(buf);
            if (c.cancelled()) return false;
        }
        r.sha256 = util::hexDigest(h256.result());
        r.sha1 = util::hexDigest(h1.result());
    }

    c.step(4, QStringLiteral("Detecting format"));
    detect(c);
    c.log(QStringLiteral("Detected format: %1").arg(r.formatName));

    bool ok = false;
    c.step(6, QStringLiteral("Unpacking"));
    if (r.formatId == QLatin1String("deb")) ok = doDeb(c, false);
    else if (r.formatId == QLatin1String("ipk")) ok = doDeb(c, true);
    else if (r.formatId == QLatin1String("rpm")) ok = doRpm(c);
    else if (r.formatId == QLatin1String("arch") || r.formatId == QLatin1String("alpine") || r.formatId == QLatin1String("xbps")
             || r.formatId == QLatin1String("slackware")) ok = doTarPackage(c);
    else if (r.formatId == QLatin1String("appimage2")) ok = doAppImage(c, 2);
    else if (r.formatId == QLatin1String("appimage1")) ok = doAppImage(c, 1);
    else if (r.formatId == QLatin1String("snap") || r.formatId == QLatin1String("squashfs")) ok = doSnap(c);
    else if (r.formatId == QLatin1String("tarball") || r.formatId == QLatin1String("archive")) ok = doGenericArchive(c);
    else ok = doSingleFile(c);

    if (c.cancelled()) {
        r.log << QStringLiteral("Cancelled.");
        return false;
    }

    for (const QString &u : c.payload.unsafeEntries + c.control.unsafeEntries)
        c.finding(QStringLiteral("archive.unsafe-entry"), Severity::High, QStringLiteral("Integrity"),
                  QStringLiteral("Archive contains an unsafe entry"),
                  QStringLiteral("Entries that try to escape the extraction directory are a sign of a crafted/malicious archive. The entry was blocked."),
                  QString(), util::sanitizeOneLine(u));
    if (c.payload.truncated) {
        r.truncated = true;
        c.finding(QStringLiteral("archive.truncated"), Severity::Info, QStringLiteral("Analysis"),
                  QStringLiteral("Extraction stopped at the configured size limit"),
                  QStringLiteral("Increase 'Maximum extracted size' in Settings for a complete scan. Huge expansion ratios can also indicate a decompression bomb."));
    }
    if (!c.payload.error.isEmpty()) c.log(QStringLiteral("Payload: %1").arg(c.payload.error));
    if (!c.control.error.isEmpty()) c.log(QStringLiteral("Control: %1").arg(c.control.error));

    c.step(40, QStringLiteral("Scanning files"));
    scanPayload(c);
    if (m_s.verifyChecksums) verifyIntegrity(c);

    QVector<Indicator> inds = c.ioc.result();
    r.indicators = inds;

    // De-duplicate findings (same rule+location+line).
    QSet<QString> seen;
    QVector<Finding> unique;
    for (const Finding &f : std::as_const(r.findings)) {
        const QString k = f.ruleId + QLatin1Char('|') + f.location + QLatin1Char('|') + QString::number(f.line);
        if (seen.contains(k)) continue;
        seen.insert(k);
        unique << f;
    }
    r.findings = unique;
    std::stable_sort(r.findings.begin(), r.findings.end(),
                     [](const Finding &a, const Finding &b) { return a.severity > b.severity; });
    r.durationMs = timer.elapsed();
    c.step(100, QStringLiteral("Done"));
    c.log(QStringLiteral("Static analysis finished in %1 ms (%2 entries, %3 binaries, %4 scripts).")
              .arg(r.durationMs).arg(r.files.size()).arg(r.binaries.size()).arg(r.scripts.size()));
    return ok || !r.files.isEmpty();
}

// ------------------------------------------------------------------ detection

void StaticAnalyzer::detect(Ctx &c)
{
    AnalysisResult &r = c.r;
    const QByteArray &h = c.head;
    const QString lname = c.name.toLower();
    const auto set = [&](const char *id, const char *name) {
        r.formatId = QString::fromLatin1(id);
        r.formatName = QString::fromLatin1(name);
    };

    if (ElfParser::isElf(h)) {
        const int ai = ElfParser::appImageType(h);
        if (ai == 2) return set("appimage2", "AppImage (type 2, SquashFS)");
        if (ai == 1) return set("appimage1", "AppImage (type 1, ISO 9660)");
        // Some AppImages lack the magic: look for a squashfs right after the ELF image.
        const quint64 end = ElfParser::elfImageEnd(h);
        if (end > 0 && end + 4 <= static_cast<quint64>(h.size()) && h.mid(static_cast<qsizetype>(end), 4) == "hsqs"
            && lname.endsWith(QLatin1String(".appimage")))
            return set("appimage2", "AppImage (type 2, SquashFS)");
        const quint16 et = static_cast<quint16>(static_cast<uchar>(h[16]) | (static_cast<uchar>(h[17]) << 8));
        if (et == 1 && (lname.endsWith(QLatin1String(".ko")) || lname.contains(QLatin1String(".ko."))))
            return set("elf", "ELF kernel module");
        return set("elf", "ELF binary");
    }
    if (h.startsWith("!<arch>\n")) {
        if (h.mid(8, 13) == "debian-binary") return set("deb", "Debian package (.deb)");
        return set("archive", "ar archive");
    }
    if (h.startsWith("\xed\xab\xee\xdb")) return set("rpm", "RPM package");
    if (h.startsWith("hsqs")) {
        if (lname.endsWith(QLatin1String(".snap"))) return set("snap", "Snap package (SquashFS)");
        return set("squashfs", "SquashFS image");
    }
    if (h.startsWith("#!")) return set("script", "Script");

    const bool compressed = h.startsWith("\x1f\x8b") || h.startsWith("\xfd" "7zXZ") || h.startsWith("\x28\xb5\x2f\xfd")
                         || h.startsWith("BZh") || h.startsWith("\x5d\x00\x00") || h.startsWith("\x04\x22\x4d\x18")
                         || h.startsWith("\x89LZO") || (h.size() > 262 && h.mid(257, 5) == "ustar");
    if (compressed) {
        const QStringList e = ArchiveReader::listEntries(c.path, ArchiveKind::Tar, 64);
        if (!e.isEmpty()) {
            const auto any = [&](const auto &pred) { return std::any_of(e.begin(), e.end(), pred); };
            if (e.contains(QLatin1String(".PKGINFO"))) {
                if (e.contains(QLatin1String(".MTREE")) || e.contains(QLatin1String(".BUILDINFO")))
                    return set("arch", "Arch Linux package (pacman)");
                if (any([](const QString &n) { return n.startsWith(QLatin1String(".SIGN.")) || n.startsWith(QLatin1String(".pre-")) || n.startsWith(QLatin1String(".post-")); }))
                    return set("alpine", "Alpine package (apk)");
                return set("arch", "Arch Linux package (pacman)");
            }
            if (any([](const QString &n) { return n.startsWith(QLatin1String(".SIGN.")); })) return set("alpine", "Alpine package (apk)");
            if (e.contains(QLatin1String("debian-binary"))) return set("ipk", "OpenWrt/opkg package (.ipk)");
            if (e.contains(QLatin1String("props.plist")) || e.contains(QLatin1String("files.plist"))) return set("xbps", "Void Linux package (xbps)");
            if (any([](const QString &n) { return n.startsWith(QLatin1String("install/slack-desc")) || n.startsWith(QLatin1String("install/doinst.sh")); }))
                return set("slackware", "Slackware package");
            return set("tarball", "Tar archive");
        }
        return set("unknown", "Compressed data");
    }
    if (h.startsWith("PK\x03\x04") || h.startsWith("7z\xbc\xaf\x27\x1c") || h.startsWith("Rar!")
        || (h.size() > 0x8006 && h.mid(0x8001, 5) == "CD001"))
        return set("archive", "Archive");
    if (util::looksLikeText(h.left(8192))) return set("text", "Text file");
    return set("unknown", "Unknown binary data");
}

// ------------------------------------------------------------------ formats

void StaticAnalyzer::addScript(Ctx &c, const QString &name, const QString &stage, const QByteArray &content, const QString &interp)
{
    ScriptEntry s;
    s.name = name;
    s.stage = stage;
    s.interpreter = interp.isEmpty() ? shebangInterpreter(content) : interp;
    if (s.interpreter.isEmpty()) s.interpreter = QStringLiteral("/bin/sh (implicit)");
    s.content = QString::fromUtf8(content.left(2 * 1024 * 1024));
    m_scanner.scanText(content.left(2 * 1024 * 1024), name, ContentKind::MaintainerScript, c.r.findings, c.ioc, &s.flaggedLines);
    c.r.scripts << s;
}

bool StaticAnalyzer::doDeb(Ctx &c, bool outerTar)
{
    ExtractLimits lim;
    lim.maxTotalBytes = quint64(m_s.maxExtractMiB) * 1024 * 1024;
    ArchiveReader::DebParts parts;
    const bool ok = ArchiveReader::extractDeb(c.path, outerTar, c.ws.controlDir(), c.ws.payloadDir(), lim, &c.control, &c.payload, &parts, c.cancel);
    c.ws.payloadIsInstallTree = true;
    c.log(QStringLiteral("debian-binary %1, control member %2, data member %3").arg(parts.debianBinary, parts.controlMember, parts.dataMember));
    if (!parts.debianBinary.isEmpty() && !parts.debianBinary.startsWith(QLatin1String("2.")))
        c.finding(QStringLiteral("deb.format-version"), Severity::Low, QStringLiteral("Integrity"),
                  QStringLiteral("Unusual Debian package format version"), QStringLiteral("debian-binary contains '%1'.").arg(parts.debianBinary));

    const QString cd = c.ws.controlDir();
    const QByteArray control = securefs::readBeneath(cd, QStringLiteral("control"), 1 << 20);
    const auto f = parseRfc822(control);
    PackageMeta &m = c.r.meta;
    m.name = f.value(QStringLiteral("Package"));
    m.version = f.value(QStringLiteral("Version"));
    m.arch = f.value(QStringLiteral("Architecture"));
    m.maintainer = f.value(QStringLiteral("Maintainer"));
    m.description = f.value(QStringLiteral("Description"));
    m.homepage = f.value(QStringLiteral("Homepage"));
    for (const QString &k : {QStringLiteral("Pre-Depends"), QStringLiteral("Depends")})
        for (const QString &d : f.value(k).split(QLatin1Char(','), Qt::SkipEmptyParts)) m.depends << d.trimmed();
    for (const QString &k : {QStringLiteral("Section"), QStringLiteral("Priority"), QStringLiteral("Installed-Size"),
                             QStringLiteral("Source"), QStringLiteral("Provides"), QStringLiteral("Conflicts"), QStringLiteral("Replaces")})
        if (f.contains(k)) m.extra[k] = f.value(k);
    if (f.contains(QStringLiteral("Pre-Depends")))
        m.extra[QStringLiteral("Pre-Depends")] = f.value(QStringLiteral("Pre-Depends"));

    struct S { const char *file; const char *stage; };
    const S scripts[] = {{"preinst", "Pre-install"}, {"postinst", "Post-install"}, {"prerm", "Pre-remove"},
                         {"postrm", "Post-remove"}, {"config", "Debconf config"}};
    for (const S &s : scripts) {
        const QByteArray content = securefs::readBeneath(cd, QString::fromLatin1(s.file), 4 << 20);
        if (content.isEmpty()) continue;
        addScript(c, QString::fromLatin1(s.file), QString::fromLatin1(s.stage), content);
        writeFile(c.ws.scriptsDir() + QLatin1Char('/') + QString::fromLatin1(s.file), content, 0755);
    }
    const QByteArray triggers = securefs::readBeneath(cd, QStringLiteral("triggers"), 1 << 20);
    if (!triggers.isEmpty()) m.extra[QStringLiteral("Triggers")] = QString::fromUtf8(triggers).simplified().left(300);
    for (const QByteArray &line : securefs::readBeneath(cd, QStringLiteral("conffiles"), 4 << 20).split('\n'))
        if (!line.trimmed().isEmpty()) c.conffiles.insert(QString::fromUtf8(line.trimmed()).section(QLatin1Char(' '), -1));
    const QByteArray md5 = securefs::readBeneath(cd, QStringLiteral("md5sums"), 64 << 20);
    for (const QByteArray &line : md5.split('\n')) {
        const QByteArray t = line.trimmed();
        if (t.size() < 34) continue;
        const QByteArray hex = t.left(32);
        QString p = QString::fromUtf8(t.mid(32).trimmed());
        if (p.startsWith(QLatin1String("./"))) p = p.mid(1);
        if (!p.startsWith(QLatin1Char('/'))) p.prepend(QLatin1Char('/'));
        c.expectedMd5.insert(p, QByteArray::fromHex(hex));
    }
    c.integritySource = QStringLiteral("md5sums");
    if (md5.isEmpty())
        c.finding(QStringLiteral("deb.no-md5sums"), Severity::Low, QStringLiteral("Integrity"), QStringLiteral("Package has no md5sums file"),
                  QStringLiteral("Installed files cannot be verified later with debsums/dpkg --verify. Official packages almost always include it."));

    // Behaviour plan (simulated dpkg sequence)
    TracePlan &p = c.ws.plan;
    p.supported = true;
    const QStringList env = {QStringLiteral("DPKG_MAINTSCRIPT_PACKAGE=") + m.name, QStringLiteral("DPKG_MAINTSCRIPT_ARCH=") + m.arch,
                             QStringLiteral("DEBIAN_FRONTEND=noninteractive"), QStringLiteral("DPKG_ROOT=")};
    if (QFile::exists(c.ws.scriptsDir() + QStringLiteral("/preinst")))
        p.stages << TraceStage{QStringLiteral("preinst install"), {QStringLiteral("/sandbox/scripts/preinst"), QStringLiteral("install")}, QStringLiteral("/"),
                               env + QStringList{QStringLiteral("DPKG_MAINTSCRIPT_NAME=preinst")}, false};
    if (QFile::exists(c.ws.scriptsDir() + QStringLiteral("/postinst")))
        p.stages << TraceStage{QStringLiteral("postinst configure"), {QStringLiteral("/sandbox/scripts/postinst"), QStringLiteral("configure"), QString()},
                               QStringLiteral("/"), env + QStringList{QStringLiteral("DPKG_MAINTSCRIPT_NAME=postinst")}, true};
    else
        p.stages << TraceStage{QStringLiteral("unpack payload"), {QStringLiteral("/bin/true")}, QStringLiteral("/"), {}, true};
    p.reason = QStringLiteral("Simulates dpkg: preinst → unpack files → postinst, as fake root inside an isolated sandbox.");
    return ok;
}

bool StaticAnalyzer::doRpm(Ctx &c)
{
    QByteArray head = c.head;
    if (c.r.fileSize > static_cast<quint64>(head.size())) {
        QFile f(c.path);
        if (f.open(QIODevice::ReadOnly)) head = f.read(64 * 1024 * 1024);
    }
    RpmHeader h;
    QString err;
    if (!h.parse(head, &err)) {
        c.log(QStringLiteral("RPM header: %1").arg(err));
        c.finding(QStringLiteral("rpm.bad-header"), Severity::Medium, QStringLiteral("Integrity"), QStringLiteral("Malformed RPM header"), err);
    }
    PackageMeta &m = c.r.meta;
    m.name = h.string(RpmHeader::Name);
    const QString epoch = h.intArray(RpmHeader::Epoch).isEmpty() ? QString() : QString::number(h.intArray(RpmHeader::Epoch).first()) + QLatin1Char(':');
    m.version = epoch + h.string(RpmHeader::Version) + QLatin1Char('-') + h.string(RpmHeader::Release);
    m.arch = h.string(RpmHeader::Arch);
    m.maintainer = h.string(RpmHeader::Packager).isEmpty() ? h.string(RpmHeader::Vendor) : h.string(RpmHeader::Packager);
    m.description = h.string(RpmHeader::Summary);
    m.homepage = h.string(RpmHeader::Url);
    m.license = h.string(RpmHeader::License);
    m.depends = h.stringArray(RpmHeader::RequireName);
    m.depends.erase(std::remove_if(m.depends.begin(), m.depends.end(), [](const QString &d) { return d.startsWith(QLatin1String("rpmlib(")); }), m.depends.end());
    m.depends.removeDuplicates();
    if (!h.string(RpmHeader::Vendor).isEmpty()) m.extra[QStringLiteral("Vendor")] = h.string(RpmHeader::Vendor);
    if (!h.string(RpmHeader::Group).isEmpty()) m.extra[QStringLiteral("Group")] = h.string(RpmHeader::Group);
    if (!h.string(RpmHeader::PayloadCompressor).isEmpty()) m.extra[QStringLiteral("Payload")] = h.string(RpmHeader::PayloadCompressor);
    m.extra[QStringLiteral("Signature header")] = h.hasSignature() ? QStringLiteral("present (not verified)") : QStringLiteral("absent");

    ExtractLimits lim;
    lim.maxTotalBytes = quint64(m_s.maxExtractMiB) * 1024 * 1024;
    const bool ok = ArchiveReader::extractFile(c.path, ArchiveKind::RpmCpio, c.ws.payloadDir(), lim, &c.payload, c.cancel);
    c.ws.payloadIsInstallTree = true;

    // Authoritative metadata from the header.
    const QStringList paths = h.filePaths();
    const QVector<qint64> modes = h.intArray(RpmHeader::FileModes);
    const QStringList users = h.stringArray(RpmHeader::FileUserName);
    const QStringList groups = h.stringArray(RpmHeader::FileGroupName);
    const QVector<qint64> flags = h.intArray(RpmHeader::FileFlags);
    const QStringList digests = h.stringArray(RpmHeader::FileDigests);
    const QVector<qint64> algoV = h.intArray(RpmHeader::FileDigestAlgo);
    const qint64 algo = algoV.isEmpty() ? 1 : algoV.first();
    QHash<QString, int> idx;
    for (int i = 0; i < paths.size(); ++i) idx.insert(paths[i], i);
    for (FileEntry &fe : c.payload.entries) {
        const int i = idx.value(fe.path, -1);
        if (i < 0) continue;
        if (i < modes.size()) fe.mode = static_cast<quint32>(modes[i]) & 0xffff;
        if (i < users.size() && i < groups.size()) fe.owner = users[i] + QLatin1Char(':') + groups[i];
        if (i < flags.size() && (flags[i] & 1)) c.conffiles.insert(fe.path);
        if (i < digests.size() && !digests[i].isEmpty() && !(i < flags.size() && (flags[i] & 64))) {
            if (algo == 8) c.expectedSha256.insert(fe.path, QByteArray::fromHex(digests[i].toLatin1()));
            else if (algo == 1) c.expectedMd5.insert(fe.path, QByteArray::fromHex(digests[i].toLatin1()));
        }
    }
    c.integritySource = QStringLiteral("RPM file digests");

    struct S { RpmHeader::Tag tag; RpmHeader::Tag prog; const char *name; const char *stage; const char *arg; };
    const S scripts[] = {
        {RpmHeader::PreTrans, RpmHeader::PreTransProg, "%pretrans", "Pre-transaction", nullptr},
        {RpmHeader::PreIn, RpmHeader::PreInProg, "%pre", "Pre-install", "1"},
        {RpmHeader::PostIn, RpmHeader::PostInProg, "%post", "Post-install", "1"},
        {RpmHeader::PostTrans, RpmHeader::PostTransProg, "%posttrans", "Post-transaction", nullptr},
        {RpmHeader::PreUn, RpmHeader::PreUnProg, "%preun", "Pre-uninstall", nullptr},
        {RpmHeader::PostUn, RpmHeader::PostUnProg, "%postun", "Post-uninstall", nullptr},
    };
    TracePlan &p = c.ws.plan;
    p.supported = true;
    bool payloadPending = true;
    for (const S &s : scripts) {
        QStringList prog = h.stringArray(s.prog);
        const QString body = h.string(s.tag);
        if (body.isEmpty() && prog.isEmpty()) continue;
        if (prog.isEmpty()) prog << QStringLiteral("/bin/sh");
        const QString name = QString::fromLatin1(s.name);
        if (!body.isEmpty()) addScript(c, name, QString::fromLatin1(s.stage), body.toUtf8(), prog.join(QLatin1Char(' ')));
        const bool install = s.tag == RpmHeader::PreTrans || s.tag == RpmHeader::PreIn || s.tag == RpmHeader::PostIn || s.tag == RpmHeader::PostTrans;
        if (!install) continue;
        if (prog.first() == QLatin1String("<lua>")) {
            c.log(QStringLiteral("%1 is a Lua scriptlet (runs inside rpm itself) and cannot be traced.").arg(name));
            continue;
        }
        const QString file = QStringLiteral("rpm-") + name.mid(1);
        writeFile(c.ws.scriptsDir() + QLatin1Char('/') + file, body.toUtf8(), 0755);
        TraceStage st;
        st.name = name;
        st.argv = prog;
        st.argv << QStringLiteral("/sandbox/scripts/") + file;
        if (s.arg) st.argv << QString::fromLatin1(s.arg);
        st.cwd = QStringLiteral("/");
        if (s.tag == RpmHeader::PostIn || s.tag == RpmHeader::PostTrans) {
            st.installPayloadBefore = payloadPending;
            payloadPending = false;
        }
        p.stages << st;
    }
    if (payloadPending) p.stages << TraceStage{QStringLiteral("unpack payload"), {QStringLiteral("/bin/true")}, QStringLiteral("/"), {}, true};
    const QStringList triggers = h.stringArray(RpmHeader::TriggerScripts);
    for (int i = 0; i < triggers.size(); ++i)
        addScript(c, QStringLiteral("%trigger #%1").arg(i + 1), QStringLiteral("Trigger"), triggers[i].toUtf8());
    p.reason = QStringLiteral("Simulates rpm: %pre → unpack files → %post, as fake root inside an isolated sandbox.");
    return ok;
}

// Moves a regular file from beneath `root` to `dest` without following any symlink on the way. The
// archive may have replaced a directory of the payload by a link to somewhere on the host
// (install -> ~/.ssh); a pathname rename() would then carry the host's files away.
static bool moveBeneath(const QString &root, const QString &rel, const QString &dest)
{
    const int in = securefs::openBeneath(root, rel, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (in < 0) return false;
    struct stat st{};
    bool ok = ::fstat(in, &st) == 0 && S_ISREG(st.st_mode);
    if (ok) {
        const int out = ::open(QFile::encodeName(dest).constData(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0644);
        ok = out >= 0;
        char buf[65536];
        while (ok) {
            const ssize_t n = ::read(in, buf, sizeof buf);
            if (n < 0) { ok = false; break; }
            if (n == 0) break;
            for (ssize_t done = 0; done < n;) {
                const ssize_t w = ::write(out, buf + done, size_t(n - done));
                if (w < 0) { ok = false; break; }
                done += w;
            }
        }
        if (out >= 0) ::close(out);
    }
    ::close(in);
    if (!ok) return false;
    const QString parent = rel.section(QLatin1Char('/'), 0, -2);
    const int pfd = parent.isEmpty() ? ::open(QFile::encodeName(root).constData(), O_RDONLY | O_DIRECTORY | O_CLOEXEC)
                                     : securefs::openBeneath(root, parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (pfd >= 0) {
        ::unlinkat(pfd, QFile::encodeName(rel.section(QLatin1Char('/'), -1)).constData(), 0);
        ::close(pfd);
    }
    return true;
}

bool StaticAnalyzer::doTarPackage(Ctx &c)
{
    ExtractLimits lim;
    lim.maxTotalBytes = quint64(m_s.maxExtractMiB) * 1024 * 1024;
    const bool ok = ArchiveReader::extractFile(c.path, ArchiveKind::Tar, c.ws.payloadDir(), lim, &c.payload, c.cancel);
    c.ws.payloadIsInstallTree = true;
    const QString fmt = c.r.formatId;
    const QString pd = c.ws.payloadDir(), cd = c.ws.controlDir();

    // Move package metadata out of the install tree.
    const auto isMeta = [&](const QString &path) {
        const QString rel = path.mid(1);
        if (fmt == QLatin1String("arch") || fmt == QLatin1String("alpine")) return !rel.contains(QLatin1Char('/')) && rel.startsWith(QLatin1Char('.'));
        if (fmt == QLatin1String("xbps")) return rel == QLatin1String("props.plist") || rel == QLatin1String("files.plist") || rel == QLatin1String("INSTALL") || rel == QLatin1String("REMOVE");
        if (fmt == QLatin1String("slackware")) return rel == QLatin1String("install") || rel.startsWith(QLatin1String("install/"));
        return false;
    };
    QVector<FileEntry> kept;
    for (const FileEntry &fe : std::as_const(c.payload.entries)) {
        if (!isMeta(fe.path)) { kept << fe; continue; }
        if (fe.type == QLatin1String("file")) {
            const QString base = fe.path.section(QLatin1Char('/'), -1);
            moveBeneath(pd, fe.path.mid(1), cd + QLatin1Char('/') + base);
        }
    }
    c.payload.entries = kept;
    if (fmt == QLatin1String("slackware")) securefs::removeTree(pd + QStringLiteral("/install"));

    PackageMeta &m = c.r.meta;
    TracePlan &p = c.ws.plan;
    p.supported = true;

    if (fmt == QLatin1String("arch") || fmt == QLatin1String("alpine")) {
        const auto info = parseKeyEq(securefs::readBeneath(cd, QStringLiteral(".PKGINFO"), 1 << 20));
        m.name = info.value(QStringLiteral("pkgname")).value(0);
        m.version = info.value(QStringLiteral("pkgver")).value(0);
        m.arch = info.value(QStringLiteral("arch")).value(0);
        m.description = info.value(QStringLiteral("pkgdesc")).value(0);
        m.homepage = info.value(QStringLiteral("url")).value(0);
        m.license = info.value(QStringLiteral("license")).join(QStringLiteral(", "));
        m.maintainer = info.value(QStringLiteral("packager")).value(0);
        if (m.maintainer.isEmpty()) m.maintainer = info.value(QStringLiteral("maintainer")).value(0);
        m.depends = info.value(QStringLiteral("depend"));
        for (const QString &k : {QStringLiteral("size"), QStringLiteral("builddate"), QStringLiteral("origin"), QStringLiteral("commit")})
            if (info.contains(k)) m.extra[k] = info.value(k).value(0);
        if (info.contains(QStringLiteral("install"))) m.extra[QStringLiteral("install hooks")] = info.value(QStringLiteral("install")).join(QLatin1Char(' '));
    }

    if (fmt == QLatin1String("arch")) {
        const QByteArray install = securefs::readBeneath(cd, QStringLiteral(".INSTALL"), 4 << 20);
        if (!install.isEmpty()) {
            addScript(c, QStringLiteral(".INSTALL"), QStringLiteral("Install hooks (pre/post_install)"), install, QStringLiteral("/bin/bash (sourced by pacman)"));
            writeFile(c.ws.scriptsDir() + QStringLiteral("/INSTALL"), install, 0644);
        }
        const QByteArray mtree = ArchiveReader::decompressRaw(securefs::readBeneath(cd, QStringLiteral(".MTREE"), 64 << 20));
        for (const QByteArray &raw : mtree.split('\n')) {
            const QString line = QString::fromUtf8(raw);
            if (!line.startsWith(QLatin1String("./"))) continue;
            const QStringList parts = line.split(QLatin1Char(' '), Qt::SkipEmptyParts);
            const QString path = mtreeUnescape(parts.value(0)).mid(1);
            for (const QString &kv : parts.mid(1)) {
                if (kv.startsWith(QLatin1String("sha256digest="))) c.expectedSha256.insert(path, QByteArray::fromHex(kv.mid(13).toLatin1()));
                else if (kv.startsWith(QLatin1String("md5digest=")) && !c.expectedSha256.contains(path))
                    c.expectedMd5.insert(path, QByteArray::fromHex(kv.mid(10).toLatin1()));
            }
        }
        c.integritySource = QStringLiteral(".MTREE");
        const QString ver = m.version;
        const QString sh = shellBinary();
        const auto stage = [&](const QString &fn, bool payload) {
            return TraceStage{fn + QLatin1Char(' ') + ver,
                              {sh, QStringLiteral("-c"),
                               QStringLiteral(". /sandbox/scripts/INSTALL; if type %1 >/dev/null 2>&1; then %1 \"$1\"; fi").arg(fn),
                               QStringLiteral("pacman-hook"), ver},
                              QStringLiteral("/"), {}, payload};
        };
        if (!install.isEmpty()) p.stages << stage(QStringLiteral("pre_install"), false) << stage(QStringLiteral("post_install"), true);
        else p.stages << TraceStage{QStringLiteral("unpack payload"), {QStringLiteral("/bin/true")}, QStringLiteral("/"), {}, true};
        p.reason = QStringLiteral("Simulates pacman: pre_install → unpack files → post_install, as fake root inside an isolated sandbox. (Global ALPM hooks are not run.)");
    } else if (fmt == QLatin1String("alpine")) {
        bool payloadDone = false;
        for (const char *s : {".pre-install", ".post-install", ".pre-upgrade", ".post-upgrade", ".pre-deinstall", ".post-deinstall", ".trigger"}) {
            const QString n = QString::fromLatin1(s);
            const QByteArray body = securefs::readBeneath(cd, n, 4 << 20);
            if (body.isEmpty()) continue;
            addScript(c, n, n.mid(1), body);
            if (n == QLatin1String(".pre-install") || n == QLatin1String(".post-install")) {
                writeFile(c.ws.scriptsDir() + QLatin1Char('/') + n.mid(1), body, 0755);
                const bool post = n == QLatin1String(".post-install");
                p.stages << TraceStage{n.mid(1), {QStringLiteral("/sandbox/scripts/") + n.mid(1), m.version}, QStringLiteral("/"), {}, post};
                if (post) payloadDone = true;
            }
        }
        if (!payloadDone) p.stages << TraceStage{QStringLiteral("unpack payload"), {QStringLiteral("/bin/true")}, QStringLiteral("/"), {}, true};
        p.reason = QStringLiteral("Simulates apk: .pre-install → unpack files → .post-install.");
    } else if (fmt == QLatin1String("xbps")) {
        const QString plist = QString::fromUtf8(securefs::readBeneath(cd, QStringLiteral("props.plist"), 4 << 20));
        const auto key = [&](const QString &k) {
            static const QString pat = QStringLiteral("<key>%1</key>\\s*<string>([^<]*)</string>");
            return QRegularExpression(pat.arg(QRegularExpression::escape(k))).match(plist).captured(1);
        };
        const QString pkgver = key(QStringLiteral("pkgver"));
        m.name = key(QStringLiteral("pkgname"));
        m.version = pkgver.section(QLatin1Char('-'), -1);
        m.arch = key(QStringLiteral("architecture"));
        m.description = key(QStringLiteral("short_desc"));
        m.homepage = key(QStringLiteral("homepage"));
        m.license = key(QStringLiteral("license"));
        m.maintainer = key(QStringLiteral("maintainer"));
        for (const char *s : {"INSTALL", "REMOVE"}) {
            const QByteArray body = securefs::readBeneath(cd, QString::fromLatin1(s), 4 << 20);
            if (body.isEmpty()) continue;
            addScript(c, QString::fromLatin1(s), QString::fromLatin1(s) == QLatin1String("INSTALL") ? QStringLiteral("Install (pre/post)") : QStringLiteral("Remove"), body);
            if (QLatin1String(s) == QLatin1String("INSTALL")) writeFile(c.ws.scriptsDir() + QStringLiteral("/INSTALL"), body, 0755);
        }
        if (QFile::exists(c.ws.scriptsDir() + QStringLiteral("/INSTALL"))) {
            const QStringList args = {m.name, m.version, QStringLiteral("no"), QStringLiteral("no"), m.arch};
            p.stages << TraceStage{QStringLiteral("INSTALL pre"), QStringList{QStringLiteral("/sandbox/scripts/INSTALL"), QStringLiteral("pre")} + args, QStringLiteral("/"), {}, false};
            p.stages << TraceStage{QStringLiteral("INSTALL post"), QStringList{QStringLiteral("/sandbox/scripts/INSTALL"), QStringLiteral("post")} + args, QStringLiteral("/"), {}, true};
        } else {
            p.stages << TraceStage{QStringLiteral("unpack payload"), {QStringLiteral("/bin/true")}, QStringLiteral("/"), {}, true};
        }
        p.reason = QStringLiteral("Simulates xbps: INSTALL pre → unpack → INSTALL post.");
    } else if (fmt == QLatin1String("slackware")) {
        const QByteArray desc = securefs::readBeneath(cd, QStringLiteral("slack-desc"), 1 << 20);
        for (const QByteArray &l : desc.split('\n')) {
            const QString s = QString::fromUtf8(l);
            if (s.startsWith(QLatin1Char('#')) || !s.contains(QLatin1Char(':'))) continue;
            if (m.name.isEmpty()) m.name = s.section(QLatin1Char(':'), 0, 0).trimmed();
            const QString t = s.section(QLatin1Char(':'), 1).trimmed();
            if (!t.isEmpty() && m.description.isEmpty()) m.description = t;
        }
        const QString base = c.name.section(QLatin1Char('.'), 0, -2);
        const QStringList parts = base.split(QLatin1Char('-'));
        if (parts.size() >= 4) {
            m.version = parts[parts.size() - 3];
            m.arch = parts[parts.size() - 2];
        }
        const QByteArray doinst = securefs::readBeneath(cd, QStringLiteral("doinst.sh"), 4 << 20);
        if (!doinst.isEmpty()) {
            addScript(c, QStringLiteral("install/doinst.sh"), QStringLiteral("Post-install"), doinst);
            writeFile(c.ws.scriptsDir() + QStringLiteral("/doinst.sh"), doinst, 0755);
            p.stages << TraceStage{QStringLiteral("doinst.sh"), {QStringLiteral("/bin/sh"), QStringLiteral("/sandbox/scripts/doinst.sh")}, QStringLiteral("/"), {}, true};
        } else {
            p.stages << TraceStage{QStringLiteral("unpack payload"), {QStringLiteral("/bin/true")}, QStringLiteral("/"), {}, true};
        }
        p.reason = QStringLiteral("Simulates installpkg: unpack files → install/doinst.sh.");
    }
    return ok;
}

bool StaticAnalyzer::runUnsquashfs(Ctx &c, quint64 offset)
{
    const QString tool = unsquashfsPath(m_s);
    if (tool.isEmpty()) {
        c.finding(QStringLiteral("tool.unsquashfs-missing"), Severity::Info, QStringLiteral("Analysis"),
                  QStringLiteral("unsquashfs not found – contents not inspected"),
                  QStringLiteral("Install squashfs-tools (Arch: pacman -S squashfs-tools) to inspect AppImage/Snap contents. The image itself is never executed for unpacking."));
        return false;
    }
    const auto run = [&](const QStringList &args, QByteArray *out, int timeoutMs) -> int {
        QProcess pr;
        pr.setProgram(tool);
        pr.setArguments(args);
        pr.setProcessChannelMode(QProcess::SeparateChannels);
        pr.start();
        if (!pr.waitForStarted(5000)) return -1;
        QElapsedTimer t;
        t.start();
        while (!pr.waitForFinished(200)) {
            if (out) out->append(pr.readAllStandardOutput());
            if (c.cancelled() || t.elapsed() > timeoutMs) {
                pr.kill();
                pr.waitForFinished(2000);
                return -2;
            }
            if (out && out->size() > 256 * 1024 * 1024) { pr.kill(); pr.waitForFinished(2000); return -3; }
        }
        if (out) out->append(pr.readAllStandardOutput());
        const QByteArray e = pr.readAllStandardError().trimmed();
        if (!e.isEmpty()) c.log(QStringLiteral("unsquashfs: %1").arg(QString::fromUtf8(e.right(400))));
        return pr.exitCode();
    };

    const QString off = QString::number(offset);
    QByteArray listing;
    run({QStringLiteral("-lln"), QStringLiteral("-o"), off, c.path}, &listing, 120000);
    static const QRegularExpression re(QStringLiteral(R"(^([-dlcbps][-rwxsStT]{9})\s+(\S+)\s+([\d, ]+?)\s+\d{4}-\d\d-\d\d \d\d:\d\d(?::\d\d)?\s+squashfs-root(/.*)?$)"));
    quint64 total = 0;
    QVector<FileEntry> entries;
    for (const QByteArray &raw : listing.split('\n')) {
        const auto mm = re.match(QString::fromUtf8(raw));
        if (!mm.hasMatch() || mm.captured(4).isEmpty()) continue;
        FileEntry fe;
        fe.mode = parseModeString(mm.captured(1));
        fe.owner = mm.captured(2).replace(QLatin1Char('/'), QLatin1Char(':'));
        QString path = mm.captured(4);
        switch (fe.mode & S_IFMT) {
        case S_IFDIR: fe.type = QStringLiteral("dir"); break;
        case S_IFLNK: {
            fe.type = QStringLiteral("symlink");
            const qsizetype a = path.indexOf(QLatin1String(" -> "));
            if (a > 0) { fe.linkTarget = path.mid(a + 4); path = path.left(a); }
            break;
        }
        case S_IFCHR: fe.type = QStringLiteral("char"); break;
        case S_IFBLK: fe.type = QStringLiteral("block"); break;
        case S_IFIFO: fe.type = QStringLiteral("fifo"); break;
        case S_IFSOCK: fe.type = QStringLiteral("socket"); break;
        default: fe.type = QStringLiteral("file");
        }
        fe.path = path;
        if (fe.type == QLatin1String("file")) {
            fe.size = mm.captured(3).trimmed().toULongLong();
            total += fe.size;
        }
        entries << fe;
    }
    c.log(QStringLiteral("SquashFS listing: %1 entries, %2 uncompressed").arg(entries.size()).arg(util::humanSize(total)));
    if (total > quint64(m_s.maxExtractMiB) * 1024 * 1024) {
        c.payload.entries = entries;
        c.payload.truncated = true;
        return false;
    }

    securefs::removeTree(c.ws.payloadDir());
    const int rc = run({QStringLiteral("-n"), QStringLiteral("-no-xattrs"), QStringLiteral("-o"), off, QStringLiteral("-d"), c.ws.payloadDir(), c.path},
                       nullptr, 20 * 60 * 1000);
    QDir().mkpath(c.ws.payloadDir());
    if (rc != 0) c.log(QStringLiteral("unsquashfs exited with %1").arg(rc));
    securefs::sanitizeTree(c.ws.payloadDir());

    if (entries.isEmpty()) {
        securefs::walk(c.ws.payloadDir(), [&](const QString &rel, const struct stat &st) {
            FileEntry fe;
            fe.path = QLatin1Char('/') + rel;
            fe.mode = st.st_mode;
            fe.size = S_ISREG(st.st_mode) ? static_cast<quint64>(st.st_size) : 0;
            fe.type = S_ISDIR(st.st_mode) ? QStringLiteral("dir") : S_ISLNK(st.st_mode) ? QStringLiteral("symlink") : QStringLiteral("file");
            entries << fe;
            return entries.size() < 300000;
        });
    }
    c.payload.entries = entries;
    c.payload.totalBytes = total;
    return rc == 0;
}

bool StaticAnalyzer::doAppImage(Ctx &c, int type)
{
    TracePlan &p = c.ws.plan;
    c.ws.payloadIsInstallTree = false;
    PackageMeta &m = c.r.meta;

    // The runtime (ELF stub) itself.
    analyzeElf(c.head, QStringLiteral("[AppImage runtime]"), c.r.findings, c.r.binaries);
    const QByteArray sig = ElfParser::sectionData(c.head, ".sha256_sig");
    const bool signedImg = !sig.isEmpty() && sig.count('\0') != sig.size();
    m.extra[QStringLiteral("Signature")] = signedImg ? QStringLiteral("embedded (.sha256_sig present, not verified)") : QStringLiteral("none");
    const QByteArray upd = ElfParser::sectionData(c.head, ".upd_info");
    const QString updInfo = QString::fromUtf8(upd.left(upd.indexOf('\0') < 0 ? upd.size() : upd.indexOf('\0'))).trimmed();
    if (!updInfo.isEmpty()) {
        m.extra[QStringLiteral("Update information")] = updInfo;
        c.ioc.add(QStringLiteral("url"), updInfo.section(QLatin1Char('|'), 1, 1).isEmpty() ? updInfo : updInfo, QStringLiteral("[AppImage .upd_info]"));
    }
    if (!signedImg)
        c.finding(QStringLiteral("appimage.unsigned"), Severity::Info, QStringLiteral("Integrity"), QStringLiteral("AppImage is not signed"),
                  QStringLiteral("Authenticity relies entirely on where you downloaded it from."));

    bool ok = false;
    if (type == 2) {
        quint64 off = ElfParser::elfImageEnd(c.head);
        QFile f(c.path);
        QByteArray magic;
        if (f.open(QIODevice::ReadOnly) && f.seek(static_cast<qint64>(off))) magic = f.read(4);
        if (magic != "hsqs") {
            const qsizetype i = c.head.indexOf("hsqs", 4096);
            if (i > 0) off = static_cast<quint64>(i);
            c.log(QStringLiteral("SquashFS magic not at ELF end; using offset %1").arg(off));
        }
        m.extra[QStringLiteral("SquashFS offset")] = QString::number(off);
        ok = runUnsquashfs(c, off);
    } else {
        ExtractLimits lim;
        lim.maxTotalBytes = quint64(m_s.maxExtractMiB) * 1024 * 1024;
        ok = ArchiveReader::extractFile(c.path, ArchiveKind::Generic, c.ws.payloadDir(), lim, &c.payload, c.cancel);
    }

    const QString pd = c.ws.payloadDir();
    for (const FileEntry &fe : std::as_const(c.payload.entries)) {
        const QString rel = fe.path.mid(1);
        if (rel.contains(QLatin1Char('/')) || !rel.endsWith(QLatin1String(".desktop"))) continue;
        const auto d = parseDesktop(securefs::readBeneath(pd, rel, 1 << 20));
        m.name = d.value(QStringLiteral("Name"));
        m.description = d.value(QStringLiteral("Comment"));
        m.version = d.value(QStringLiteral("X-AppImage-Version"));
        m.extra[QStringLiteral("Exec")] = d.value(QStringLiteral("Exec"));
        m.extra[QStringLiteral("Categories")] = d.value(QStringLiteral("Categories"));
        m.extra[QStringLiteral("Desktop file")] = rel;
        break;
    }
    struct stat st{};
    const QString appRun = pd + QStringLiteral("/AppRun");
    if (::lstat(QFile::encodeName(appRun).constData(), &st) == 0) {
        if (S_ISLNK(st.st_mode)) {
            m.extra[QStringLiteral("AppRun")] = QStringLiteral("symlink → ") + QFileInfo(appRun).symLinkTarget().remove(pd);
        } else if (S_ISREG(st.st_mode)) {
            const QByteArray head = securefs::readBeneath(pd, QStringLiteral("AppRun"), 4 << 20);
            if (head.startsWith("#!")) {
                addScript(c, QStringLiteral("AppRun"), QStringLiteral("Launcher"), head);
                c.scannedPaths.insert(QStringLiteral("/AppRun"));
                m.extra[QStringLiteral("AppRun")] = QStringLiteral("script (%1)").arg(shebangInterpreter(head));
            } else {
                m.extra[QStringLiteral("AppRun")] = ElfParser::isElf(head) ? QStringLiteral("ELF binary") : QStringLiteral("file");
            }
        }
    } else {
        c.finding(QStringLiteral("appimage.no-apprun"), Severity::Low, QStringLiteral("Integrity"), QStringLiteral("AppImage has no AppRun entry point"),
                  QStringLiteral("A valid AppDir always contains AppRun."));
    }

    p.supported = ok || QFile::exists(appRun);
    p.bindPayloadAsAppDir = true;
    TraceStage s;
    s.name = QStringLiteral("AppRun");
    s.argv = {QStringLiteral("/sandbox/appdir/AppRun")};
    s.argv += QProcess::splitCommand(m_s.extraArgs);
    s.cwd = QStringLiteral("/root");
    s.env = {QStringLiteral("APPDIR=/sandbox/appdir"), QStringLiteral("APPIMAGE=/sandbox/input/") + safeFileName(c.name),
             QStringLiteral("ARGV0=") + safeFileName(c.name), QStringLiteral("OWD=/root")};
    p.stages << s;
    p.reason = QStringLiteral("Runs the unpacked AppDir's AppRun in the sandbox (no FUSE mount, the image is never executed on the host).");
    return ok;
}

bool StaticAnalyzer::doSnap(Ctx &c)
{
    c.ws.payloadIsInstallTree = false;
    const bool ok = runUnsquashfs(c, 0);
    const QString pd = c.ws.payloadDir();
    const QString yaml = QString::fromUtf8(securefs::readBeneath(pd, QStringLiteral("meta/snap.yaml"), 1 << 20));
    PackageMeta &m = c.r.meta;
    for (const QString &line : yaml.split(QLatin1Char('\n'))) {
        if (line.startsWith(QLatin1Char(' '))) continue;
        const QString k = line.section(QLatin1Char(':'), 0, 0).trimmed();
        const QString v = line.section(QLatin1Char(':'), 1).trimmed().remove(QLatin1Char('\'')).remove(QLatin1Char('"'));
        if (k == QLatin1String("name")) m.name = v;
        else if (k == QLatin1String("version")) m.version = v;
        else if (k == QLatin1String("summary")) m.description = v;
        else if (k == QLatin1String("architectures")) m.arch = v;
        else if (k == QLatin1String("confinement") || k == QLatin1String("grade") || k == QLatin1String("base")) m.extra[k] = v;
    }
    const QString conf = m.extra.value(QStringLiteral("confinement"));
    if (conf == QLatin1String("classic") || conf == QLatin1String("devmode"))
        c.finding(QStringLiteral("snap.unconfined"), Severity::Medium, QStringLiteral("Privilege"),
                  QStringLiteral("Snap uses '%1' confinement").arg(conf),
                  QStringLiteral("The snap runs without the usual snapd sandbox and has full access to your files."));
    for (const QString &dir : {QStringLiteral("meta/hooks"), QStringLiteral("snap/hooks")}) {
        for (const FileEntry &fe : std::as_const(c.payload.entries)) {
            if (!fe.path.startsWith(QLatin1Char('/') + dir + QLatin1Char('/')) || fe.type != QLatin1String("file")) continue;
            const QByteArray body = securefs::readBeneath(pd, fe.path.mid(1), 4 << 20);
            if (body.startsWith("#!")) {
                addScript(c, fe.path.mid(1), QStringLiteral("Snap hook"), body);
                c.scannedPaths.insert(fe.path);
            }
        }
    }
    c.ws.plan.supported = false;
    c.ws.plan.reason = QStringLiteral("Snap packages are executed by snapd under its own confinement; behaviour tracing is not supported.");
    return ok;
}

bool StaticAnalyzer::doGenericArchive(Ctx &c)
{
    ExtractLimits lim;
    lim.maxTotalBytes = quint64(m_s.maxExtractMiB) * 1024 * 1024;
    const bool ok = ArchiveReader::extractFile(c.path, c.r.formatId == QLatin1String("tarball") ? ArchiveKind::Tar : ArchiveKind::Generic,
                                               c.ws.payloadDir(), lim, &c.payload, c.cancel);
    c.ws.payloadIsInstallTree = false;
    QString best;
    static const QSet<QString> names = {QStringLiteral("install.sh"), QStringLiteral("install"), QStringLiteral("setup.sh"),
                                        QStringLiteral("installer.sh"), QStringLiteral("install.bash"), QStringLiteral("INSTALL.sh")};
    for (const FileEntry &fe : std::as_const(c.payload.entries)) {
        if (fe.type != QLatin1String("file") || fe.path.count(QLatin1Char('/')) > 3) continue;
        const QString base = fe.path.section(QLatin1Char('/'), -1);
        if (!names.contains(base) && !base.endsWith(QLatin1String(".run"))) continue;
        const QByteArray head = securefs::readBeneath(c.ws.payloadDir(), fe.path.mid(1), 256);
        if (!head.startsWith("#!") && !base.endsWith(QLatin1String(".sh"))) continue;
        if (best.isEmpty() || fe.path.size() < best.size()) best = fe.path;
    }
    TracePlan &p = c.ws.plan;
    if (!best.isEmpty()) {
        const QByteArray body = securefs::readBeneath(c.ws.payloadDir(), best.mid(1), 4 << 20);
        addScript(c, best.mid(1), QStringLiteral("Bundled installer"), body);
        c.scannedPaths.insert(best);
        p.supported = true;
        p.bindPayloadAsSource = true;
        const QString dir = best.section(QLatin1Char('/'), 0, -2);
        p.stages << TraceStage{QStringLiteral("run ") + best.mid(1), {QStringLiteral("/bin/sh"), QStringLiteral("/sandbox/src") + best},
                               QStringLiteral("/sandbox/src") + dir, {}, false};
        p.reason = QStringLiteral("Runs the bundled installer script %1 inside the sandbox.").arg(best.mid(1));
    } else {
        p.supported = false;
        p.reason = QStringLiteral("The archive contains no recognisable installer script to execute.");
    }
    return ok;
}

bool StaticAnalyzer::doSingleFile(Ctx &c)
{
    const QString fid = c.r.formatId;
    const QString safe = safeFileName(c.name);
    QByteArray data;
    {
        QFile f(c.path);
        if (f.open(QIODevice::ReadOnly)) data = f.read(qint64(m_s.maxDeepScanMiB) * 1024 * 1024);
    }
    FileEntry fe;
    fe.path = QLatin1Char('/') + c.name;
    fe.type = QStringLiteral("file");
    fe.size = c.r.fileSize;
    fe.sha256 = c.r.sha256;
    fe.mode = QFileInfo(c.path).permissions() & QFileDevice::ExeUser ? 0100755 : 0100644;
    TracePlan &p = c.ws.plan;
    const QString target = QStringLiteral("/sandbox/input/") + safe;

    if (fid == QLatin1String("elf")) {
        fe.kind = QStringLiteral("ELF");
        analyzeElf(data, c.name, c.r.findings, c.r.binaries);
        if (m_s.scanBinaryStrings) m_scanner.scanBinary(data, c.name, c.r.findings, c.ioc);
        const ElfInfo &e = c.r.binaries.last();
        c.r.meta.name = c.name;
        c.r.meta.arch = e.machine;
        c.r.meta.extra[QStringLiteral("Type")] = e.elfType;
        if (e.elfType == QLatin1String("Kernel module") || e.elfType == QLatin1String("Relocatable")) {
            fe.kind = QStringLiteral("Kernel module");
            for (auto it = e.modinfo.begin(); it != e.modinfo.end(); ++it) c.r.meta.extra[it.key()] = it.value();
            p.supported = false;
            p.reason = QStringLiteral("Kernel modules cannot be executed in a user-space sandbox.");
        } else {
            QFile::copy(c.path, c.ws.inputDir() + QLatin1Char('/') + safe);
            ::chmod(QFile::encodeName(c.ws.inputDir() + QLatin1Char('/') + safe).constData(), 0755);
            p.supported = true;
            p.stages << TraceStage{QStringLiteral("execute ") + c.name, QStringList{target} + QProcess::splitCommand(m_s.extraArgs),
                                   QStringLiteral("/root"), {}, false};
            p.reason = QStringLiteral("Executes the binary as fake root inside the sandbox.");
        }
    } else if (fid == QLatin1String("script") || fid == QLatin1String("text")) {
        const bool isScript = data.startsWith("#!") || kScriptExt.contains(util::lowerExt(c.name));
        fe.kind = isScript ? QStringLiteral("Script") : QStringLiteral("Text");
        if (isScript) {
            addScript(c, c.name, QStringLiteral("Installer / script"), data);
            if (data.contains("MS_Help") || data.contains("makeself")) {
                c.r.meta.extra[QStringLiteral("Self-extracting")] = QStringLiteral("makeself archive");
                c.finding(QStringLiteral("script.self-extracting"), Severity::Info, QStringLiteral("Analysis"),
                          QStringLiteral("Self-extracting installer (makeself)"),
                          QStringLiteral("The embedded archive is only visible at runtime – use 'Trace in Sandbox' to see what it installs."));
            }
            QFile::copy(c.path, c.ws.inputDir() + QLatin1Char('/') + safe);
            ::chmod(QFile::encodeName(c.ws.inputDir() + QLatin1Char('/') + safe).constData(), 0755);
            p.supported = true;
            QStringList argv = data.startsWith("#!") ? QStringList{target} : QStringList{QStringLiteral("/bin/sh"), target};
            p.stages << TraceStage{QStringLiteral("run ") + c.name, argv + QProcess::splitCommand(m_s.extraArgs), QStringLiteral("/root"), {}, false};
            p.reason = QStringLiteral("Runs the script as fake root inside the sandbox.");
        } else {
            m_scanner.scanText(data, c.name, ContentKind::Text, c.r.findings, c.ioc);
            p.reason = QStringLiteral("Plain text files are not executable.");
        }
        c.r.meta.name = c.name;
    } else {
        fe.kind = QStringLiteral("Data");
        if (m_s.scanBinaryStrings) m_scanner.scanBinary(data, c.name, c.r.findings, c.ioc);
        const double ent = util::shannonEntropy(data);
        c.r.meta.extra[QStringLiteral("Entropy")] = QString::number(ent, 'f', 2) + QStringLiteral(" bits/byte");
        if (ent > 7.5)
            c.finding(QStringLiteral("data.high-entropy"), Severity::Info, QStringLiteral("Analysis"), QStringLiteral("High-entropy data (compressed or encrypted)"),
                      QStringLiteral("Content could not be identified; it may be encrypted or use an unsupported format."));
        p.reason = QStringLiteral("Unknown format – nothing to execute.");
        c.r.meta.name = c.name;
    }
    c.r.files << fe;
    c.ws.payloadSha256.insert(fe.path, fe.sha256);
    return true;
}

// ------------------------------------------------------------------ payload scan

void StaticAnalyzer::analyzeElf(const QByteArray &data, const QString &location, QVector<Finding> &out, QVector<ElfInfo> &bins) const
{
    ElfInfo e;
    QString err;
    if (!ElfParser::parse(data, location, &e, &err)) return;
    bins << e;
    const auto add = [&](const QString &id, Severity sev, const QString &cat, const QString &title, const QString &detail, const QString &ev = {}) {
        Finding f;
        f.ruleId = id;
        f.severity = sev;
        f.category = cat;
        f.title = title;
        f.detail = detail;
        f.location = location;
        f.evidence = ev;
        f.origin = QStringLiteral("static");
        out << f;
    };
    if (!e.libcOverrides.isEmpty())
        add(QStringLiteral("elf.libc-hook"), Severity::High, QStringLiteral("Rootkit"),
            QStringLiteral("Shared library re-implements libc functions"),
            QStringLiteral("Exporting functions like readdir/open/accept is how LD_PRELOAD rootkits hide files, processes and connections. Legitimate exceptions: fakeroot, proxychains, torsocks, sanitizers."),
            e.libcOverrides.join(QStringLiteral(", ")));
    if (e.upx)
        add(QStringLiteral("elf.upx"), Severity::Medium, QStringLiteral("Obfuscation"), QStringLiteral("Executable is packed with UPX"),
            QStringLiteral("Packing hides code from static inspection. Rare in distribution packages, common in malware."));
    else if (e.noSectionHeaders && e.entropy > 7.0)
        add(QStringLiteral("elf.packed"), Severity::Medium, QStringLiteral("Obfuscation"), QStringLiteral("Packed or obfuscated executable"),
            QStringLiteral("No section headers and very high entropy (%1 bits/byte).").arg(e.entropy, 0, 'f', 2));
    else if (e.noSectionHeaders)
        add(QStringLiteral("elf.no-sections"), Severity::Low, QStringLiteral("Obfuscation"), QStringLiteral("Section headers stripped"),
            QStringLiteral("Removing section headers hinders analysis tools; normal binaries keep them even when stripped."));
    if (e.rwxSegment)
        add(QStringLiteral("elf.rwx"), Severity::Medium, QStringLiteral("Hardening"), QStringLiteral("Writable and executable memory segment"),
            QStringLiteral("RWX segments enable self-modifying code and make exploitation easier."));
    if (!e.nx && e.elfType != QLatin1String("Kernel module") && e.elfType != QLatin1String("Relocatable"))
        add(QStringLiteral("elf.exec-stack"), Severity::Low, QStringLiteral("Hardening"), QStringLiteral("Executable stack"),
            QStringLiteral("The stack is executable (no PT_GNU_STACK or it has PF_X)."));
    const QSet<QString> imp(e.notableImports.begin(), e.notableImports.end());
    if (imp.contains(QStringLiteral("init_module")) || imp.contains(QStringLiteral("finit_module")))
        add(QStringLiteral("elf.loads-kmod"), Severity::High, QStringLiteral("Kernel"), QStringLiteral("Binary can load kernel modules"),
            QStringLiteral("Imports init_module/finit_module."));
    if (imp.contains(QStringLiteral("memfd_create")) && (imp.contains(QStringLiteral("fexecve")) || imp.contains(QStringLiteral("execveat"))))
        add(QStringLiteral("elf.fileless"), Severity::High, QStringLiteral("Execution"), QStringLiteral("Fileless execution capability"),
            QStringLiteral("memfd_create + fexecve/execveat runs code that never touches the disk."));
    if (imp.contains(QStringLiteral("ptrace")) || imp.contains(QStringLiteral("process_vm_writev")))
        add(QStringLiteral("elf.injection"), Severity::Low, QStringLiteral("Execution"), QStringLiteral("Process inspection/injection capability"),
            QStringLiteral("Imports ptrace or process_vm_writev (normal for debuggers, unusual for regular apps)."));
    if (imp.contains(QStringLiteral("XRecordEnableContext")) || imp.contains(QStringLiteral("XQueryKeymap")))
        add(QStringLiteral("elf.keyboard"), Severity::Low, QStringLiteral("Collection"), QStringLiteral("Can observe global keyboard state (X11)"),
            QStringLiteral("XRecord/XQueryKeymap allow reading keystrokes of other applications."));
    QStringList badPaths;
    for (const QString &rp : e.rpath + e.runpath) {
        if (rp.isEmpty()) continue;
        if (rp.startsWith(QLatin1String("$ORIGIN")) || rp.startsWith(QLatin1String("${ORIGIN}"))) continue;
        if (!rp.startsWith(QLatin1Char('/')) || rp.startsWith(QLatin1String("/tmp")) || rp.startsWith(QLatin1String("/var/tmp"))
            || rp.startsWith(QLatin1String("/home")) || rp.startsWith(QLatin1String("/dev/shm")))
            badPaths << rp;
    }
    if (!badPaths.isEmpty())
        add(QStringLiteral("elf.insecure-rpath"), Severity::Medium, QStringLiteral("Hardening"), QStringLiteral("Insecure library search path (RPATH/RUNPATH)"),
            QStringLiteral("Relative or user-writable search paths let other users plant libraries that this binary will load."), badPaths.join(QLatin1Char(':')));
    if (!e.interpreter.isEmpty()) {
        static const QRegularExpression okInterp(QStringLiteral(R"(^/(usr/)?lib(32|64|x32)?/(ld-linux[^/]*|ld-musl[^/]*|ld\.so[^/]*|ld64\.so[^/]*|[a-z0-9_\-]+-linux-gnu[a-z]*/ld-linux[^/]*)$|^/system/bin/linker|^/nix/store/)"));
        if (!okInterp.match(e.interpreter).hasMatch())
            add(QStringLiteral("elf.odd-interpreter"), Severity::Medium, QStringLiteral("Execution"), QStringLiteral("Unusual ELF interpreter"),
                QStringLiteral("The binary is loaded by a non-standard dynamic loader."), e.interpreter);
    }
}

void StaticAnalyzer::scanFile(Ctx &c, FileEntry &fe)
{
    const QString pd = c.ws.payloadDir();
    const QString rel = fe.path.mid(1);
    QByteArray sha, md5;
    const bool needMd5 = !c.expectedMd5.isEmpty();
    if (securefs::hashBeneath(pd, rel, &sha, needMd5 ? &md5 : nullptr)) {
        fe.sha256 = util::hexDigest(sha);
        c.ws.payloadSha256.insert(fe.path, fe.sha256);
        if (m_s.verifyChecksums) {
            if (c.expectedSha256.contains(fe.path) && c.expectedSha256.value(fe.path) != sha) fe.flags << QStringLiteral("checksum-mismatch");
            else if (c.expectedMd5.contains(fe.path) && c.expectedMd5.value(fe.path) != md5) fe.flags << QStringLiteral("checksum-mismatch");
        }
    }
    const QByteArray head = securefs::readBeneath(pd, rel, 65536);
    const QString ext = util::lowerExt(fe.path);
    const bool doc = isDocPath(fe.path);

    if (ElfParser::isElf(head)) {
        fe.kind = QStringLiteral("ELF");
        bool trunc = false;
        const QByteArray data = securefs::readBeneath(pd, rel, qint64(m_s.maxDeepScanMiB) * 1024 * 1024, &trunc);
        const int before = c.r.binaries.size();
        analyzeElf(data, fe.path, c.r.findings, c.r.binaries);
        if (c.r.binaries.size() > before && c.r.binaries.last().elfType == QLatin1String("Kernel module")) fe.kind = QStringLiteral("Kernel module");
        if (m_s.scanBinaryStrings) m_scanner.scanBinary(data, fe.path, c.r.findings, c.ioc);
        if (fe.mode & 0111) fe.flags << QStringLiteral("executable");
        return;
    }
    if (c.scannedPaths.contains(fe.path)) {
        fe.kind = QStringLiteral("Script");
        return;
    }
    const bool text = util::looksLikeText(head);
    if (head.startsWith("#!") || (text && kScriptExt.contains(ext))) {
        fe.kind = QStringLiteral("Script");
        if (!doc) m_scanner.scanText(securefs::readBeneath(pd, rel, 8 << 20), fe.path, ContentKind::Script, c.r.findings, c.ioc);
        return;
    }
    if (!text) {
        fe.kind = QStringLiteral("Data");
        return;
    }
    fe.kind = QStringLiteral("Text");
    if (doc || fe.size > 6ull * 1024 * 1024) return;
    ContentKind k = ContentKind::Text;
    if (ext == QLatin1String("desktop")) k = ContentKind::Desktop;
    else if (kConfigExt.contains(ext) || (c.ws.payloadIsInstallTree && (fe.path.startsWith(QLatin1String("/etc/")) || fe.path.contains(QLatin1String("/systemd/")))))
        k = ContentKind::Config;
    const QByteArray data = securefs::readBeneath(pd, rel, 6 << 20);
    m_scanner.scanText(data, fe.path, k, c.r.findings, c.ioc);
    if (k == ContentKind::Desktop && fe.path.contains(QLatin1String("autostart")) && data.contains("NoDisplay=true"))
        c.finding(QStringLiteral("desktop.hidden-autostart"), Severity::Medium, QStringLiteral("Persistence"), QStringLiteral("Hidden autostart entry"),
                  QStringLiteral("Starts on every login and is hidden from menus (NoDisplay=true)."), fe.path);
    if (fe.path.contains(QLatin1String("/udev/rules.d/")) && data.contains("RUN+="))
        c.finding(QStringLiteral("udev.run"), Severity::Medium, QStringLiteral("Persistence"), QStringLiteral("udev rule runs a program"),
                  QStringLiteral("RUN+= executes commands as root whenever matching hardware appears."), fe.path);
}

void StaticAnalyzer::scanPayload(Ctx &c)
{
    const int total = std::max<int>(1, c.payload.entries.size());
    int i = 0;
    for (FileEntry fe : std::as_const(c.payload.entries)) {
        if (c.cancelled()) return;
        if (++i % 64 == 0) c.step(40 + 55 * i / total, QStringLiteral("Scanning %1/%2").arg(i).arg(total));
        if (c.conffiles.contains(fe.path)) {
            fe.conffile = true;
            fe.flags << QStringLiteral("conffile");
        }
        if (fe.mode & S_ISUID) fe.flags << QStringLiteral("setuid");
        if (fe.mode & S_ISGID && fe.type == QLatin1String("file")) fe.flags << QStringLiteral("setgid");
        if ((fe.mode & S_IWOTH) && fe.type != QLatin1String("symlink")) fe.flags << QStringLiteral("world-writable");
        if (fe.path.section(QLatin1Char('/'), -1).startsWith(QLatin1Char('.'))) fe.flags << QStringLiteral("hidden");
        if (fe.type == QLatin1String("file") || fe.type == QLatin1String("hardlink")) scanFile(c, fe);
        else if (fe.type == QLatin1String("symlink")) fe.kind = QStringLiteral("Symlink");
        else if (fe.type == QLatin1String("dir")) fe.kind = QStringLiteral("Directory");
        else fe.kind = QStringLiteral("Special");
        ContentScanner::checkInstallPath(fe, c.r.findings, c.ws.payloadIsInstallTree);
        c.r.files << fe;
    }
}

void StaticAnalyzer::verifyIntegrity(Ctx &c)
{
    if (c.expectedMd5.isEmpty() && c.expectedSha256.isEmpty()) return;
    QStringList mismatched, uncovered;
    for (const FileEntry &fe : std::as_const(c.r.files)) {
        if (fe.type != QLatin1String("file")) continue;
        if (fe.flags.contains(QStringLiteral("checksum-mismatch"))) mismatched << fe.path;
        else if (!c.expectedMd5.contains(fe.path) && !c.expectedSha256.contains(fe.path) && !fe.conffile) uncovered << fe.path;
    }
    if (!mismatched.isEmpty())
        c.finding(QStringLiteral("integrity.mismatch"), Severity::High, QStringLiteral("Integrity"),
                  QStringLiteral("%1 file(s) do not match the package's own checksums (%2)").arg(mismatched.size()).arg(c.integritySource),
                  QStringLiteral("The payload was modified after the checksum list was generated – a strong sign of tampering."),
                  mismatched.size() == 1 ? mismatched.first() : QString(), mismatched.mid(0, 8).join(QStringLiteral(", ")));
    else
        c.log(QStringLiteral("All files covered by %1 match.").arg(c.integritySource));
    if (!uncovered.isEmpty())
        c.finding(QStringLiteral("integrity.uncovered"), Severity::Low, QStringLiteral("Integrity"),
                  QStringLiteral("%1 file(s) are not listed in %2").arg(uncovered.size()).arg(c.integritySource),
                  QStringLiteral("Files missing from the checksum list cannot be verified."), QString(), uncovered.mid(0, 8).join(QStringLiteral(", ")));
}

void StaticAnalyzer::analyzeDroppedFile(const QString &root, const QString &rel, const QString &displayPath,
                                        QVector<Finding> &findings, QVector<ElfInfo> &binaries, IndicatorCollector &ioc) const
{
    const QByteArray head = securefs::readBeneath(root, rel, 65536);
    if (ElfParser::isElf(head)) {
        const QByteArray data = securefs::readBeneath(root, rel, qint64(m_s.maxDeepScanMiB) * 1024 * 1024);
        QVector<Finding> f;
        analyzeElf(data, displayPath, f, binaries);
        if (m_s.scanBinaryStrings) m_scanner.scanBinary(data, displayPath, f, ioc);
        for (Finding &x : f) x.origin = QStringLiteral("dynamic");
        findings += f;
        return;
    }
    if (!util::looksLikeText(head) || isDocPath(displayPath)) return;
    QVector<Finding> f;
    const ContentKind k = head.startsWith("#!") ? ContentKind::Script : ContentKind::Config;
    m_scanner.scanText(securefs::readBeneath(root, rel, 4 << 20), displayPath, k, f, ioc);
    for (Finding &x : f) x.origin = QStringLiteral("dynamic");
    findings += f;
}

} // namespace ps
