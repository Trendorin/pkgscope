// SPDX-License-Identifier: MIT
#include "core/Settings.h"
#include "core/Workspace.h"
#include "gui/MainWindow.h"
#include "gui/Theme.h"

#include <QApplication>
#include <QCommandLineParser>

int main(int argc, char **argv)
{
    QApplication app(argc, argv);
    QApplication::setApplicationName(QStringLiteral("PkgScope"));
    QApplication::setApplicationDisplayName(QStringLiteral("PkgScope"));
    QApplication::setOrganizationName(QStringLiteral("pkgscope"));
    QApplication::setOrganizationDomain(QStringLiteral("io.github.trendorin"));
    QApplication::setDesktopFileName(QStringLiteral("io.github.trendorin.PkgScope"));
    QApplication::setApplicationVersion(QStringLiteral(PKGSCOPE_VERSION));

    QCommandLineParser parser;
    parser.setApplicationDescription(QStringLiteral("Inspect Linux packages, AppImages and binaries, with sandboxed behaviour tracing."));
    parser.addHelpOption();
    parser.addVersionOption();
    parser.addPositionalArgument(QStringLiteral("file"), QStringLiteral("Optional package or binary to open on startup."));
    parser.process(app);

    const ps::Settings s = ps::Settings::load();
    ps::theme::apply(app, s.theme);
    app.setWindowIcon(ps::theme::appIcon());
    ps::Workspace::cleanupStale();

    ps::MainWindow win;
    win.show();
    if (!parser.positionalArguments().isEmpty())
        win.openPath(parser.positionalArguments().first());
    return app.exec();
}
