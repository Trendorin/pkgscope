// SPDX-License-Identifier: MIT
#include "Workspace.h"
#include "SecureFs.h"
#include "Settings.h"

#include <QDir>
#include <QFile>
#include <QRandomGenerator>

#include <csignal>
#include <sys/stat.h>
#include <unistd.h>

namespace ps {

std::shared_ptr<Workspace> Workspace::create(QString *error)
{
    const QString base = Settings::workRoot();
    for (int attempt = 0; attempt < 16; ++attempt) {
        const QString name = QStringLiteral("ws-%1-%2")
                                 .arg(::getpid())
                                 .arg(QRandomGenerator::system()->generate64(), 16, 16, QLatin1Char('0'));
        const QString path = base + QLatin1Char('/') + name;
        if (::mkdir(QFile::encodeName(path).constData(), 0700) == 0) {
            auto ws = std::shared_ptr<Workspace>(new Workspace(path));
            for (const QString &sub : {QStringLiteral("payload"), QStringLiteral("control"), QStringLiteral("input"),
                                       QStringLiteral("scripts"), QStringLiteral("runs")})
                ::mkdir(QFile::encodeName(path + QLatin1Char('/') + sub).constData(), 0700);
            return ws;
        }
    }
    if (error) *error = QStringLiteral("cannot create workspace in %1").arg(base);
    return {};
}

Workspace::~Workspace()
{
    if (!m_keep && !m_root.isEmpty()) securefs::removeTree(m_root);
}

void Workspace::cleanupStale()
{
    const QDir base(Settings::workRoot());
    for (const QString &name : base.entryList(QDir::Dirs | QDir::NoDotAndDotDot | QDir::Hidden)) {
        if (!name.startsWith(QLatin1String("ws-"))) continue;
        const int pid = name.section(QLatin1Char('-'), 1, 1).toInt();
        if (pid > 0 && (::kill(pid, 0) == 0 || errno == EPERM) && pid != ::getpid()) continue; // still alive
        if (pid == ::getpid()) continue;
        securefs::removeTree(base.filePath(name));
    }
}

} // namespace ps
