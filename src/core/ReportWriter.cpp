// SPDX-License-Identifier: MIT
#include "ReportWriter.h"
#include "Util.h"

#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QMap>
#include <QSaveFile>

namespace ps {

namespace {

QString esc(const QString &s) { return s.toHtmlEscaped(); }

QJsonArray strings(const QStringList &l)
{
    QJsonArray a;
    for (const QString &s : l) a << s;
    return a;
}

QJsonObject findingJson(const Finding &f)
{
    QJsonObject o{{QStringLiteral("severity"), severityName(f.severity)}, {QStringLiteral("rule"), f.ruleId},
                  {QStringLiteral("category"), f.category}, {QStringLiteral("title"), f.title},
                  {QStringLiteral("detail"), f.detail}, {QStringLiteral("origin"), f.origin}};
    if (!f.location.isEmpty()) o[QStringLiteral("location")] = f.location;
    if (f.line > 0) o[QStringLiteral("line")] = f.line;
    if (!f.evidence.isEmpty()) o[QStringLiteral("evidence")] = f.evidence;
    return o;
}

QJsonObject elfJson(const ElfInfo &e)
{
    QJsonObject o{{QStringLiteral("path"), e.path}, {QStringLiteral("class"), e.elfClass}, {QStringLiteral("machine"), e.machine},
                  {QStringLiteral("type"), e.elfType}, {QStringLiteral("language"), e.language}, {QStringLiteral("interpreter"), e.interpreter},
                  {QStringLiteral("pie"), e.pie}, {QStringLiteral("nx"), e.nx}, {QStringLiteral("relro"), e.relro},
                  {QStringLiteral("canary"), e.canary}, {QStringLiteral("fortify"), e.fortify}, {QStringLiteral("stripped"), e.stripped},
                  {QStringLiteral("static"), e.staticLinked}, {QStringLiteral("rwx"), e.rwxSegment}, {QStringLiteral("upx"), e.upx},
                  {QStringLiteral("entropy"), e.entropy}, {QStringLiteral("needed"), strings(e.needed)},
                  {QStringLiteral("rpath"), strings(e.rpath)}, {QStringLiteral("runpath"), strings(e.runpath)},
                  {QStringLiteral("notable_imports"), strings(e.notableImports)}};
    if (!e.libcOverrides.isEmpty()) o[QStringLiteral("libc_overrides")] = strings(e.libcOverrides);
    if (!e.modinfo.isEmpty()) {
        QJsonObject m;
        for (auto it = e.modinfo.begin(); it != e.modinfo.end(); ++it) m[it.key()] = it.value();
        o[QStringLiteral("modinfo")] = m;
    }
    return o;
}

QString sevClass(Severity s) { return severityName(s).toLower(); }

QString processTreeHtml(const QVector<ProcessInfo> &ps)
{
    QMultiMap<QString, int> children; // key: stage|ppid
    QSet<int> pids;
    for (const ProcessInfo &p : ps) pids.insert(p.pid);
    for (int i = 0; i < ps.size(); ++i) {
        const int parent = pids.contains(ps[i].ppid) ? ps[i].ppid : 0;
        children.insert(ps[i].stage + QLatin1Char('|') + QString::number(parent), i);
    }
    std::function<QString(const QString &, int, int)> rec = [&](const QString &stage, int ppid, int depth) -> QString {
        if (depth > 64) return {};
        QList<int> kids = children.values(stage + QLatin1Char('|') + QString::number(ppid));
        std::sort(kids.begin(), kids.end());
        if (kids.isEmpty()) return {};
        QString h = QStringLiteral("<ul class=\"tree\">");
        for (int i : kids) {
            const ProcessInfo &p = ps[i];
            QString status = p.exitSignal.isEmpty() ? (p.exitCode >= 0 ? QStringLiteral("exit %1").arg(p.exitCode) : QString()) : p.exitSignal;
            h += QStringLiteral("<li><code>%1</code> <span class=\"muted\">pid %2 · %3s%4</span><div class=\"argv\">%5</div>")
                     .arg(esc(p.exe.isEmpty() ? QStringLiteral("(fork)") : p.exe)).arg(p.pid).arg(p.start, 0, 'f', 2)
                     .arg(status.isEmpty() ? QString() : QStringLiteral(" · ") + esc(status))
                     .arg(esc(util::elide(p.argv.join(QLatin1Char(' ')), 600)));
            h += rec(stage, p.pid, depth + 1);
            h += QStringLiteral("</li>");
        }
        return h + QStringLiteral("</ul>");
    };
    QString out;
    QStringList stages;
    for (const ProcessInfo &p : ps)
        if (!stages.contains(p.stage)) stages << p.stage;
    for (const QString &s : stages) out += QStringLiteral("<h4>%1</h4>").arg(esc(s)) + rec(s, 0, 0);
    return out;
}

} // namespace

QJsonObject ReportWriter::toJson(const AnalysisResult &r)
{
    QJsonObject root;
    root[QStringLiteral("tool")] = QStringLiteral("PkgScope %1").arg(QStringLiteral(PKGSCOPE_VERSION));
    root[QStringLiteral("analyzed_at")] = r.analyzedAt.toString(Qt::ISODate);
    root[QStringLiteral("input")] = QJsonObject{{QStringLiteral("name"), r.fileName}, {QStringLiteral("size"), static_cast<qint64>(r.fileSize)},
                                                {QStringLiteral("sha256"), r.sha256}, {QStringLiteral("sha1"), r.sha1},
                                                {QStringLiteral("format"), r.formatName}, {QStringLiteral("format_id"), r.formatId}};
    QJsonObject meta{{QStringLiteral("name"), r.meta.name}, {QStringLiteral("version"), r.meta.version}, {QStringLiteral("arch"), r.meta.arch},
                     {QStringLiteral("maintainer"), r.meta.maintainer}, {QStringLiteral("description"), r.meta.description},
                     {QStringLiteral("homepage"), r.meta.homepage}, {QStringLiteral("license"), r.meta.license},
                     {QStringLiteral("depends"), strings(r.meta.depends)}};
    QJsonObject extra;
    for (auto it = r.meta.extra.begin(); it != r.meta.extra.end(); ++it) extra[it.key()] = it.value();
    meta[QStringLiteral("extra")] = extra;
    root[QStringLiteral("package")] = meta;
    root[QStringLiteral("risk")] = QJsonObject{{QStringLiteral("score"), r.riskScore()}, {QStringLiteral("verdict"), r.verdict()}};

    QJsonArray findings;
    for (const Finding &f : r.allFindings()) findings << findingJson(f);
    root[QStringLiteral("findings")] = findings;

    QJsonArray files;
    for (const FileEntry &f : r.files) {
        QJsonObject o{{QStringLiteral("path"), f.path}, {QStringLiteral("type"), f.type}, {QStringLiteral("size"), static_cast<qint64>(f.size)},
                      {QStringLiteral("mode"), util::modeString(f.mode)}, {QStringLiteral("owner"), f.owner}, {QStringLiteral("kind"), f.kind}};
        if (!f.sha256.isEmpty()) o[QStringLiteral("sha256")] = f.sha256;
        if (!f.linkTarget.isEmpty()) o[QStringLiteral("target")] = f.linkTarget;
        if (!f.flags.isEmpty()) o[QStringLiteral("flags")] = strings(f.flags);
        files << o;
    }
    root[QStringLiteral("files")] = files;
    QJsonArray bins;
    for (const ElfInfo &e : r.binaries) bins << elfJson(e);
    root[QStringLiteral("binaries")] = bins;
    QJsonArray scripts;
    for (const ScriptEntry &s : r.scripts) {
        QJsonArray fl;
        for (int l : s.flaggedLines) fl << l;
        scripts << QJsonObject{{QStringLiteral("name"), s.name}, {QStringLiteral("stage"), s.stage}, {QStringLiteral("interpreter"), s.interpreter},
                               {QStringLiteral("flagged_lines"), fl}, {QStringLiteral("content"), s.content}};
    }
    root[QStringLiteral("scripts")] = scripts;
    QJsonArray inds;
    for (const Indicator &i : r.indicators)
        inds << QJsonObject{{QStringLiteral("type"), i.type}, {QStringLiteral("value"), i.value}, {QStringLiteral("source"), i.source},
                            {QStringLiteral("count"), i.count}, {QStringLiteral("likely_benign"), i.likelyBenign}};
    root[QStringLiteral("indicators")] = inds;

    const BehaviorReport &b = r.behavior;
    if (b.ran) {
        QJsonObject bj;
        bj[QStringLiteral("network_allowed")] = b.networkAllowed;
        bj[QStringLiteral("display_allowed")] = b.displayAllowed;
        bj[QStringLiteral("duration_s")] = b.duration;
        bj[QStringLiteral("sandbox_notes")] = b.sandboxNotes;
        QJsonArray st;
        for (const StageResult &s : b.stages)
            st << QJsonObject{{QStringLiteral("name"), s.name}, {QStringLiteral("command"), s.command}, {QStringLiteral("exit_code"), s.exitCode},
                              {QStringLiteral("signal"), s.exitSignal}, {QStringLiteral("timed_out"), s.timedOut},
                              {QStringLiteral("duration_s"), s.duration}, {QStringLiteral("output"), s.output}};
        bj[QStringLiteral("stages")] = st;
        QJsonArray procs;
        for (const ProcessInfo &p : b.processes)
            procs << QJsonObject{{QStringLiteral("pid"), p.pid}, {QStringLiteral("ppid"), p.ppid}, {QStringLiteral("stage"), p.stage},
                                 {QStringLiteral("exe"), p.exe}, {QStringLiteral("argv"), strings(p.argv)}, {QStringLiteral("start_s"), p.start},
                                 {QStringLiteral("exit_code"), p.exitCode}, {QStringLiteral("signal"), p.exitSignal}};
        bj[QStringLiteral("processes")] = procs;
        QJsonArray fs;
        for (const FsEvent &e : b.fsEvents) {
            QJsonObject o{{QStringLiteral("t"), e.t}, {QStringLiteral("pid"), e.pid}, {QStringLiteral("stage"), e.stage}, {QStringLiteral("op"), e.op},
                          {QStringLiteral("path"), e.path}, {QStringLiteral("ok"), e.ok}};
            if (!e.path2.isEmpty()) o[QStringLiteral("path2")] = e.path2;
            if (!e.detail.isEmpty()) o[QStringLiteral("detail")] = e.detail;
            if (!e.error.isEmpty()) o[QStringLiteral("error")] = e.error;
            fs << o;
        }
        bj[QStringLiteral("file_events")] = fs;
        QJsonArray net;
        for (const NetEvent &n : b.netEvents)
            net << QJsonObject{{QStringLiteral("t"), n.t}, {QStringLiteral("pid"), n.pid}, {QStringLiteral("stage"), n.stage}, {QStringLiteral("op"), n.op},
                               {QStringLiteral("family"), n.family}, {QStringLiteral("proto"), n.proto}, {QStringLiteral("address"), n.address},
                               {QStringLiteral("port"), n.port}, {QStringLiteral("domain"), n.domain}, {QStringLiteral("ok"), n.ok},
                               {QStringLiteral("error"), n.error}};
        bj[QStringLiteral("network_events")] = net;
        bj[QStringLiteral("dns_queries")] = strings(b.dnsQueries);
        QJsonArray ch;
        for (const FsChange &c : b.changes) {
            QJsonObject o{{QStringLiteral("path"), c.path}, {QStringLiteral("change"), c.change}, {QStringLiteral("type"), c.type},
                          {QStringLiteral("size"), static_cast<qint64>(c.size)}, {QStringLiteral("mode"), util::modeString(c.mode)}};
            if (!c.sha256.isEmpty()) o[QStringLiteral("sha256")] = c.sha256;
            if (!c.linkTarget.isEmpty()) o[QStringLiteral("target")] = c.linkTarget;
            ch << o;
        }
        bj[QStringLiteral("filesystem_changes")] = ch;
        QJsonArray dropped;
        for (const ElfInfo &e : b.droppedBinaries) dropped << elfJson(e);
        bj[QStringLiteral("dropped_binaries")] = dropped;
        root[QStringLiteral("behavior")] = bj;
    }
    root[QStringLiteral("log")] = strings(r.log);
    return root;
}

QString ReportWriter::toHtml(const AnalysisResult &r)
{
    QString h;
    h.reserve(1 << 20);
    h += QStringLiteral(R"(<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark"><title>PkgScope report – )") + esc(r.fileName) + QStringLiteral(R"(</title><style>
:root{--bg:#f6f7f9;--fg:#1d2026;--muted:#636a75;--card:#fff;--border:#dfe2e7;--code:#f0f2f5;
--critical:#b3132b;--high:#d1451b;--medium:#b7791f;--low:#2b6cb0;--info:#5a6270;--ok:#2f855a}
@media (prefers-color-scheme:dark){:root{--bg:#15171b;--fg:#e6e8eb;--muted:#9aa2ad;--card:#1d2025;--border:#2e323a;--code:#262a31;
--critical:#ff5c72;--high:#ff8a5c;--medium:#f2c14e;--low:#6cb2ff;--info:#a0a8b4;--ok:#5fd394}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 64px}h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:32px 0 10px;border-bottom:1px solid var(--border);padding-bottom:6px}
h4{margin:14px 0 4px}.muted{color:var(--muted)}code,pre{font-family:ui-monospace,"JetBrains Mono","Fira Code",monospace;font-size:12.5px}
pre{background:var(--code);padding:10px;border-radius:8px;overflow:auto;max-height:420px}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:14px 16px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}
.kv{display:grid;grid-template-columns:max-content 1fr;gap:4px 14px}.kv div:nth-child(odd){color:var(--muted)}
.score{font-size:40px;font-weight:700;line-height:1}.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600;color:#fff}
.critical{background:var(--critical)}.high{background:var(--high)}.medium{background:var(--medium)}.low{background:var(--low)}.info{background:var(--info)}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--border);vertical-align:top;word-break:break-word}
th{color:var(--muted);font-weight:600}.tree{list-style:none;padding-left:18px;border-left:1px dashed var(--border)}.tree li{margin:4px 0}
.argv{color:var(--muted);font-family:ui-monospace,monospace;font-size:12px}.fl{background:rgba(209,69,27,.18)}
details summary{cursor:pointer;font-weight:600}footer{margin-top:40px;color:var(--muted);font-size:12px}
</style></head><body><main>)");

    const int score = r.riskScore();
    const QString verdictCls = score >= 70 ? QStringLiteral("critical") : score >= 35 ? QStringLiteral("high") : score >= 12 ? QStringLiteral("medium") : QStringLiteral("low");
    h += QStringLiteral("<h1>%1</h1><div class=\"muted\">%2 · %3 · analysed %4</div>")
             .arg(esc(r.fileName), esc(r.formatName), util::humanSize(r.fileSize), r.analyzedAt.toString(Qt::ISODate));
    h += QStringLiteral("<div class=\"grid\" style=\"margin-top:16px\"><div class=\"card\"><div class=\"muted\">Risk score</div><div class=\"score\">%1</div>"
                        "<span class=\"badge %2\">%3</span></div>").arg(score).arg(verdictCls, esc(r.verdict()));
    int counts[5] = {};
    for (const Finding &f : r.allFindings()) ++counts[static_cast<int>(f.severity)];
    h += QStringLiteral("<div class=\"card\"><div class=\"muted\">Findings</div><div style=\"margin-top:8px\">");
    for (int s = 4; s >= 0; --s)
        h += QStringLiteral("<span class=\"badge %1\">%2 %3</span> ").arg(sevClass(static_cast<Severity>(s))).arg(counts[s]).arg(severityName(static_cast<Severity>(s)));
    h += QStringLiteral("</div></div><div class=\"card\"><div class=\"muted\">SHA-256</div><code style=\"word-break:break-all\">%1</code></div></div>").arg(r.sha256);

    // Package
    h += QStringLiteral("<h2>Package</h2><div class=\"card kv\">");
    const auto kv = [&](const QString &k, const QString &v) {
        if (!v.trimmed().isEmpty()) h += QStringLiteral("<div>%1</div><div>%2</div>").arg(esc(k), esc(v));
    };
    kv(QStringLiteral("Name"), r.meta.name);
    kv(QStringLiteral("Version"), r.meta.version);
    kv(QStringLiteral("Architecture"), r.meta.arch);
    kv(QStringLiteral("Maintainer"), r.meta.maintainer);
    kv(QStringLiteral("Description"), r.meta.description);
    kv(QStringLiteral("Homepage"), r.meta.homepage);
    kv(QStringLiteral("License"), r.meta.license);
    kv(QStringLiteral("Depends"), r.meta.depends.join(QStringLiteral(", ")));
    for (auto it = r.meta.extra.begin(); it != r.meta.extra.end(); ++it) kv(it.key(), it.value());
    kv(QStringLiteral("Entries"), QString::number(r.files.size()));
    h += QStringLiteral("</div>");

    // Findings
    h += QStringLiteral("<h2>Findings</h2>");
    const QVector<Finding> all = r.allFindings();
    if (all.isEmpty()) h += QStringLiteral("<p class=\"muted\">No findings.</p>");
    else {
        h += QStringLiteral("<table><tr><th>Severity</th><th>Finding</th><th>Location</th><th>Source</th></tr>");
        for (const Finding &f : all) {
            h += QStringLiteral("<tr><td><span class=\"badge %1\">%2</span></td><td><b>%3</b><div class=\"muted\">%4</div>%5</td><td><code>%6</code></td><td>%7</td></tr>")
                     .arg(sevClass(f.severity), severityName(f.severity), esc(f.title), esc(f.detail),
                          f.evidence.isEmpty() ? QString() : QStringLiteral("<pre>%1</pre>").arg(esc(f.evidence)),
                          esc(f.location + (f.line > 0 ? QStringLiteral(":%1").arg(f.line) : QString())), esc(f.origin));
        }
        h += QStringLiteral("</table>");
    }

    // Scripts
    if (!r.scripts.isEmpty()) {
        h += QStringLiteral("<h2>Install scripts</h2>");
        for (const ScriptEntry &s : r.scripts) {
            h += QStringLiteral("<details%1><summary>%2 <span class=\"muted\">— %3 · %4%5</span></summary><pre>")
                     .arg(s.flaggedLines.isEmpty() ? QString() : QStringLiteral(" open"), esc(s.name), esc(s.stage), esc(s.interpreter),
                          s.flaggedLines.isEmpty() ? QString() : QStringLiteral(" · %1 flagged line(s)").arg(s.flaggedLines.size()));
            const QStringList lines = s.content.split(QLatin1Char('\n'));
            const QSet<int> fl(s.flaggedLines.begin(), s.flaggedLines.end());
            for (int i = 0; i < lines.size() && i < 5000; ++i) {
                const QString l = QStringLiteral("%1  %2").arg(i + 1, 4).arg(esc(lines[i]));
                h += fl.contains(i + 1) ? QStringLiteral("<span class=\"fl\">%1</span>\n").arg(l) : l + QLatin1Char('\n');
            }
            h += QStringLiteral("</pre></details>");
        }
    }

    // Behaviour
    const BehaviorReport &b = r.behavior;
    if (b.ran) {
        h += QStringLiteral("<h2>Behaviour (sandboxed run)</h2><div class=\"card\"><pre style=\"max-height:none;background:none;padding:0\">%1</pre></div>").arg(esc(b.sandboxNotes));
        h += QStringLiteral("<table><tr><th>Stage</th><th>Command</th><th>Result</th><th>Time</th></tr>");
        for (const StageResult &s : b.stages)
            h += QStringLiteral("<tr><td>%1</td><td><code>%2</code></td><td>%3</td><td>%4 s</td></tr>")
                     .arg(esc(s.name), esc(s.command),
                          esc(s.timedOut ? QStringLiteral("time limit") : (!s.exitSignal.isEmpty() ? s.exitSignal : QStringLiteral("exit %1").arg(s.exitCode))))
                     .arg(s.duration, 0, 'f', 1);
        h += QStringLiteral("</table><h3>Process tree</h3>") + processTreeHtml(b.processes);

        h += QStringLiteral("<h3>Filesystem changes</h3>");
        int shown = 0;
        h += QStringLiteral("<table><tr><th>Change</th><th>Path</th><th>Type</th><th>Size</th></tr>");
        QVector<FsChange> sorted = b.changes;
        std::sort(sorted.begin(), sorted.end(), [](const FsChange &a, const FsChange &c) {
            if (a.change != c.change) return a.change == QLatin1String("installed") ? false : (c.change == QLatin1String("installed") ? true : a.change < c.change);
            return a.path < c.path;
        });
        for (const FsChange &c : sorted) {
            if (++shown > 3000) { h += QStringLiteral("<tr><td colspan=4 class=\"muted\">… truncated, see JSON export</td></tr>"); break; }
            h += QStringLiteral("<tr><td>%1</td><td><code>%2</code>%3</td><td>%4</td><td>%5</td></tr>")
                     .arg(esc(c.change), esc(c.path), c.linkTarget.isEmpty() ? QString() : QStringLiteral(" → <code>%1</code>").arg(esc(c.linkTarget)),
                          esc(c.type), c.type == QLatin1String("file") ? util::humanSize(c.size) : QString());
        }
        h += QStringLiteral("</table><h3>Network</h3>");
        if (b.netEvents.isEmpty() && b.dnsQueries.isEmpty()) h += QStringLiteral("<p class=\"muted\">No network activity observed.</p>");
        else {
            h += QStringLiteral("<table><tr><th>Time</th><th>PID</th><th>Op</th><th>Destination</th><th>Domain</th><th>Result</th></tr>");
            int k = 0;
            for (const NetEvent &n : b.netEvents) {
                if (++k > 2000) break;
                h += QStringLiteral("<tr><td>%1</td><td>%2</td><td>%3 %4</td><td><code>%5</code></td><td>%6</td><td>%7</td></tr>")
                         .arg(n.t, 0, 'f', 2).arg(n.pid).arg(esc(n.op), esc(n.proto),
                              esc(n.address + (n.port ? QStringLiteral(":%1").arg(n.port) : QString())), esc(n.domain),
                              esc(n.ok ? QStringLiteral("ok") : n.error));
            }
            h += QStringLiteral("</table>");
            if (!b.dnsQueries.isEmpty()) h += QStringLiteral("<p><b>DNS queries:</b> <code>%1</code></p>").arg(esc(b.dnsQueries.join(QStringLiteral(", "))));
        }
        for (const StageResult &s : b.stages)
            if (!s.output.trimmed().isEmpty())
                h += QStringLiteral("<details><summary>Output of %1</summary><pre>%2</pre></details>").arg(esc(s.name), esc(util::elide(s.output, 20000)));
    }

    // Binaries
    if (!r.binaries.isEmpty()) {
        h += QStringLiteral("<h2>Binaries</h2><table><tr><th>Path</th><th>Type</th><th>PIE</th><th>NX</th><th>RELRO</th><th>Canary</th><th>Fortify</th><th>Stripped</th></tr>");
        const auto yn = [](bool v) { return v ? QStringLiteral("yes") : QStringLiteral("no"); };
        int k = 0;
        for (const ElfInfo &e : r.binaries) {
            if (++k > 2000) break;
            h += QStringLiteral("<tr><td><code>%1</code></td><td>%2 %3</td><td>%4</td><td>%5</td><td>%6</td><td>%7</td><td>%8</td><td>%9</td></tr>")
                     .arg(esc(e.path), esc(e.elfType), esc(e.machine), yn(e.pie), yn(e.nx), esc(e.relro), yn(e.canary), yn(e.fortify), yn(e.stripped));
        }
        h += QStringLiteral("</table>");
    }

    // Indicators
    QVector<Indicator> inds;
    for (const Indicator &i : r.indicators)
        if (!i.likelyBenign) inds << i;
    if (!inds.isEmpty()) {
        h += QStringLiteral("<h2>Indicators</h2><table><tr><th>Type</th><th>Value</th><th>Source</th><th>Count</th></tr>");
        int k = 0;
        for (const Indicator &i : inds) {
            if (++k > 1500) break;
            h += QStringLiteral("<tr><td>%1</td><td><code>%2</code></td><td><code>%3</code></td><td>%4</td></tr>")
                     .arg(esc(i.type), esc(i.value), esc(i.source)).arg(i.count);
        }
        h += QStringLiteral("</table>");
    }

    // Contents
    h += QStringLiteral("<h2>Contents</h2><details><summary>%1 entries</summary><table><tr><th>Path</th><th>Mode</th><th>Owner</th><th>Size</th><th>Kind</th></tr>").arg(r.files.size());
    int k = 0;
    for (const FileEntry &f : r.files) {
        if (++k > 20000) { h += QStringLiteral("<tr><td colspan=5 class=\"muted\">… truncated</td></tr>"); break; }
        h += QStringLiteral("<tr><td><code>%1</code>%2</td><td><code>%3</code></td><td>%4</td><td>%5</td><td>%6</td></tr>")
                 .arg(esc(f.path), f.linkTarget.isEmpty() ? QString() : QStringLiteral(" → <code>%1</code>").arg(esc(f.linkTarget)),
                      util::modeString(f.mode), esc(f.owner), f.type == QLatin1String("file") ? util::humanSize(f.size) : QString(),
                      esc(f.kind + (f.flags.isEmpty() ? QString() : QStringLiteral(" · ") + f.flags.join(QStringLiteral(", ")))));
    }
    h += QStringLiteral("</table></details>");
    h += QStringLiteral("<footer>Generated by PkgScope %1. Static heuristics and a single sandboxed run cannot prove a file is safe; "
                        "they surface behaviour worth reviewing.</footer></main></body></html>").arg(QStringLiteral(PKGSCOPE_VERSION));
    return h;
}

QString ReportWriter::toMarkdown(const AnalysisResult &r)
{
    const auto md = [](QString s) { return s.replace(QLatin1Char('|'), QLatin1String("\\|")).replace(QLatin1Char('\n'), QLatin1Char(' ')); };
    QString m;
    m += QStringLiteral("# PkgScope report: %1\n\n").arg(r.fileName);
    m += QStringLiteral("- **Format:** %1\n- **Size:** %2\n- **SHA-256:** `%3`\n- **Risk:** %4/100 — %5\n- **Analysed:** %6\n\n")
             .arg(r.formatName, util::humanSize(r.fileSize), r.sha256).arg(r.riskScore()).arg(r.verdict(), r.analyzedAt.toString(Qt::ISODate));
    m += QStringLiteral("## Package\n\n| Field | Value |\n|---|---|\n");
    const auto row = [&](const QString &k, const QString &v) { if (!v.isEmpty()) m += QStringLiteral("| %1 | %2 |\n").arg(k, md(v)); };
    row(QStringLiteral("Name"), r.meta.name);
    row(QStringLiteral("Version"), r.meta.version);
    row(QStringLiteral("Architecture"), r.meta.arch);
    row(QStringLiteral("Maintainer"), r.meta.maintainer);
    row(QStringLiteral("Description"), r.meta.description);
    row(QStringLiteral("Homepage"), r.meta.homepage);
    for (auto it = r.meta.extra.begin(); it != r.meta.extra.end(); ++it) row(it.key(), it.value());
    m += QStringLiteral("\n## Findings\n\n| Severity | Finding | Location | Source |\n|---|---|---|---|\n");
    for (const Finding &f : r.allFindings())
        m += QStringLiteral("| %1 | **%2** — %3%4 | `%5` | %6 |\n")
                 .arg(severityName(f.severity), md(f.title), md(f.detail), f.evidence.isEmpty() ? QString() : QStringLiteral(" `%1`").arg(md(f.evidence).replace(QLatin1Char('`'), QLatin1Char('\''))),
                      md(f.location + (f.line > 0 ? QStringLiteral(":%1").arg(f.line) : QString())), f.origin);
    if (r.behavior.ran) {
        const BehaviorReport &b = r.behavior;
        m += QStringLiteral("\n## Behaviour\n\n");
        for (const StageResult &s : b.stages)
            m += QStringLiteral("- **%1**: `%2` → %3 (%4 s)\n").arg(s.name, s.command,
                     s.timedOut ? QStringLiteral("time limit") : QStringLiteral("exit %1").arg(s.exitCode)).arg(s.duration, 0, 'f', 1);
        m += QStringLiteral("\n### Processes\n\n");
        for (const ProcessInfo &p : b.processes)
            m += QStringLiteral("- `%1` (pid %2, parent %3): `%4`\n").arg(p.exe).arg(p.pid).arg(p.ppid).arg(md(util::elide(p.argv.join(QLatin1Char(' ')), 200)));
        m += QStringLiteral("\n### Filesystem changes\n\n| Change | Path |\n|---|---|\n");
        int k = 0;
        for (const FsChange &c : b.changes) {
            if (c.change == QLatin1String("installed")) continue;
            if (++k > 1000) break;
            m += QStringLiteral("| %1 | `%2` |\n").arg(c.change, md(c.path));
        }
        m += QStringLiteral("\n### Network\n\n");
        for (const NetEvent &n : b.netEvents)
            if (n.family == QLatin1String("inet") || n.family == QLatin1String("inet6"))
                m += QStringLiteral("- %1 %2 `%3:%4` %5 — %6\n").arg(n.op, n.proto, n.address).arg(n.port).arg(n.domain, n.ok ? QStringLiteral("ok") : n.error);
        if (!b.dnsQueries.isEmpty()) m += QStringLiteral("\nDNS: `%1`\n").arg(b.dnsQueries.join(QStringLiteral("`, `")));
    }
    m += QStringLiteral("\n---\n_Generated by PkgScope %1_\n").arg(QStringLiteral(PKGSCOPE_VERSION));
    return m;
}

bool ReportWriter::write(const AnalysisResult &r, const QString &path, QString *error, const QString &format)
{
    QString fmt = format.isEmpty() ? QFileInfo(path).suffix().toLower() : format;
    QByteArray data;
    if (fmt == QLatin1String("json")) data = QJsonDocument(toJson(r)).toJson(QJsonDocument::Indented);
    else if (fmt == QLatin1String("md") || fmt == QLatin1String("markdown")) data = toMarkdown(r).toUtf8();
    else data = toHtml(r).toUtf8();
    QSaveFile f(path);
    if (!f.open(QIODevice::WriteOnly)) {
        if (error) *error = f.errorString();
        return false;
    }
    f.write(data);
    if (!f.commit()) {
        if (error) *error = f.errorString();
        return false;
    }
    return true;
}

} // namespace ps
