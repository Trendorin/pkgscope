// SPDX-License-Identifier: MIT
// pkgscope-cli — headless front-end (CI pipelines, servers, scripting).
#include "core/DynamicTracer.h"
#include "core/ReportWriter.h"
#include "core/StaticAnalyzer.h"
#include "core/Util.h"

#include <QCommandLineParser>
#include <QCoreApplication>
#include <QTextStream>

#include <csignal>

using namespace ps;

namespace {
std::atomic<bool> g_cancel{false};
void onSignal(int) { g_cancel = true; }
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    QCoreApplication::setApplicationName(QStringLiteral("pkgscope"));
    QCoreApplication::setOrganizationName(QStringLiteral("pkgscope"));
    QCoreApplication::setApplicationVersion(QStringLiteral(PKGSCOPE_VERSION));
    std::signal(SIGINT, onSignal);
    std::signal(SIGTERM, onSignal);

    QCommandLineParser p;
    p.setApplicationDescription(QStringLiteral("Inspect packages, AppImages and binaries; optionally trace them in a sandbox."));
    p.addHelpOption();
    p.addVersionOption();
    p.addPositionalArgument(QStringLiteral("file"), QStringLiteral("Package, AppImage, ELF binary or script to analyse."));
    const QCommandLineOption trace(QStringLiteral("trace"), QStringLiteral("Also run it inside the isolated sandbox and record behaviour."));
    const QCommandLineOption json({QStringLiteral("j"), QStringLiteral("json")}, QStringLiteral("Write JSON report."), QStringLiteral("path"));
    const QCommandLineOption html(QStringLiteral("html"), QStringLiteral("Write HTML report."), QStringLiteral("path"));
    const QCommandLineOption md(QStringLiteral("md"), QStringLiteral("Write Markdown report."), QStringLiteral("path"));
    const QCommandLineOption timeout(QStringLiteral("timeout"), QStringLiteral("Seconds per sandbox stage (default from settings)."), QStringLiteral("sec"));
    const QCommandLineOption net(QStringLiteral("allow-network"), QStringLiteral("Let the traced program reach the network (default: isolated)."));
    const QCommandLineOption keep(QStringLiteral("keep"), QStringLiteral("Keep the sandbox directory for manual inspection."));
    const QCommandLineOption quiet({QStringLiteral("q"), QStringLiteral("quiet")}, QStringLiteral("Only print the verdict line."));
    const QCommandLineOption failOn(QStringLiteral("fail-on"), QStringLiteral("Exit with status 3 if a finding of this severity or higher exists (low|medium|high|critical)."), QStringLiteral("severity"));
    p.addOptions({trace, json, html, md, timeout, net, keep, quiet, failOn});
    p.process(app);
    if (p.positionalArguments().size() != 1) p.showHelp(2);

    Settings s = Settings::load();
    if (p.isSet(timeout)) s.traceTimeoutSec = std::clamp(p.value(timeout).toInt(), 5, 3600);
    if (p.isSet(net)) s.allowNetwork = true;
    if (p.isSet(keep)) s.keepRunDir = true;

    QTextStream out(stdout), err(stderr);
    Workspace::cleanupStale();
    StaticAnalyzer analyzer(s);
    AnalysisResult r;
    std::shared_ptr<Workspace> ws;
    const bool q = p.isSet(quiet);
    const auto progress = [&](int pct, const QString &m) {
        if (!q) { err << QStringLiteral("\r[%1%] %2").arg(pct, 3).arg(util::elide(m, 70)).leftJustified(82) ; err.flush(); }
    };
    if (!analyzer.analyze(p.positionalArguments().first(), r, ws, progress, &g_cancel)) {
        err << "\nAnalysis failed: " << r.log.join(QLatin1Char('\n')) << '\n';
        return 1;
    }
    if (p.isSet(trace)) {
        DynamicTracer tracer(s, &analyzer);
        if (!tracer.run(r, *ws, progress, &g_cancel))
            err << "\nBehaviour trace incomplete: " << r.behavior.sandboxNotes << '\n';
        if (s.keepRunDir) ws->setKeep(true);
    }
    if (!q) err << "\r" << QString(82, QLatin1Char(' ')) << "\r";

    if (!q) {
        out << r.fileName << " — " << r.formatName << "\n";
        if (!r.meta.name.isEmpty()) out << "  package: " << r.meta.name << ' ' << r.meta.version << ' ' << r.meta.arch << '\n';
        out << "  sha256:  " << r.sha256 << '\n';
        out << "  entries: " << r.files.size() << ", binaries: " << r.binaries.size() << ", scripts: " << r.scripts.size() << '\n';
        if (r.behavior.ran)
            out << "  runtime: " << r.behavior.processes.size() << " processes, " << r.behavior.changes.size() << " fs changes, "
                << r.behavior.netEvents.size() << " network events, " << r.behavior.dnsQueries.size() << " DNS names\n";
        out << '\n';
        for (const Finding &f : r.allFindings())
            out << QStringLiteral("  [%1] %2%3%4\n").arg(severityName(f.severity).leftJustified(8), f.title,
                                                        f.location.isEmpty() ? QString() : QStringLiteral("  — ") + f.location,
                                                        f.origin == QLatin1String("dynamic") ? QStringLiteral(" (runtime)") : QString());
        out << '\n';
    }
    out << "Risk " << r.riskScore() << "/100 — " << r.verdict() << '\n';
    out.flush();

    QString e;
    if (p.isSet(json) && !ReportWriter::write(r, p.value(json), &e, QStringLiteral("json"))) err << "JSON: " << e << '\n';
    if (p.isSet(html) && !ReportWriter::write(r, p.value(html), &e, QStringLiteral("html"))) err << "HTML: " << e << '\n';
    if (p.isSet(md) && !ReportWriter::write(r, p.value(md), &e, QStringLiteral("md"))) err << "Markdown: " << e << '\n';

    if (p.isSet(failOn) && r.countAtLeast(severityFromName(p.value(failOn))) > 0) return 3;
    return 0;
}
