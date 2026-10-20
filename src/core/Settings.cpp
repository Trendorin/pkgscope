// SPDX-License-Identifier: MIT
#include "Settings.h"

#include <QDir>
#include <QSettings>
#include <QStandardPaths>

namespace ps {

Settings Settings::load()
{
    QSettings s;
    Settings d;
    d.maxExtractMiB = std::clamp(s.value(QStringLiteral("static/maxExtractMiB"), d.maxExtractMiB).toInt(), 64, 65536);
    d.maxDeepScanMiB = std::clamp(s.value(QStringLiteral("static/maxDeepScanMiB"), d.maxDeepScanMiB).toInt(), 1, 2048);
    d.scanBinaryStrings = s.value(QStringLiteral("static/scanBinaryStrings"), d.scanBinaryStrings).toBool();
    d.verifyChecksums = s.value(QStringLiteral("static/verifyChecksums"), d.verifyChecksums).toBool();
    d.showBenignIndicators = s.value(QStringLiteral("static/showBenignIndicators"), d.showBenignIndicators).toBool();
    d.traceTimeoutSec = std::clamp(s.value(QStringLiteral("dynamic/timeoutSec"), d.traceTimeoutSec).toInt(), 5, 3600);
    d.graceSec = std::clamp(s.value(QStringLiteral("dynamic/graceSec"), d.graceSec).toInt(), 0, 600);
    d.allowNetwork = s.value(QStringLiteral("dynamic/allowNetwork"), d.allowNetwork).toBool();
    d.allowDisplay = s.value(QStringLiteral("dynamic/allowDisplay"), d.allowDisplay).toBool();
    d.keepRunDir = s.value(QStringLiteral("dynamic/keepRunDir"), d.keepRunDir).toBool();
    d.maxFileSizeMiB = std::clamp(s.value(QStringLiteral("dynamic/maxFileSizeMiB"), d.maxFileSizeMiB).toInt(), 16, 65536);
    d.extraArgs = s.value(QStringLiteral("dynamic/extraArgs")).toString();
    d.straceOverride = s.value(QStringLiteral("dynamic/strace")).toString();
    d.unsquashfsOverride = s.value(QStringLiteral("static/unsquashfs")).toString();
    d.theme = s.value(QStringLiteral("ui/theme"), d.theme).toString();
    d.language = s.value(QStringLiteral("ui/language"), d.language).toString();
    d.lastExportDir = s.value(QStringLiteral("ui/lastExportDir")).toString();
    d.defaultExportFormat = s.value(QStringLiteral("ui/exportFormat"), d.defaultExportFormat).toString();
    return d;
}

void Settings::save() const
{
    QSettings s;
    s.setValue(QStringLiteral("static/maxExtractMiB"), maxExtractMiB);
    s.setValue(QStringLiteral("static/maxDeepScanMiB"), maxDeepScanMiB);
    s.setValue(QStringLiteral("static/scanBinaryStrings"), scanBinaryStrings);
    s.setValue(QStringLiteral("static/verifyChecksums"), verifyChecksums);
    s.setValue(QStringLiteral("static/showBenignIndicators"), showBenignIndicators);
    s.setValue(QStringLiteral("static/unsquashfs"), unsquashfsOverride);
    s.setValue(QStringLiteral("dynamic/timeoutSec"), traceTimeoutSec);
    s.setValue(QStringLiteral("dynamic/graceSec"), graceSec);
    s.setValue(QStringLiteral("dynamic/allowNetwork"), allowNetwork);
    s.setValue(QStringLiteral("dynamic/allowDisplay"), allowDisplay);
    s.setValue(QStringLiteral("dynamic/keepRunDir"), keepRunDir);
    s.setValue(QStringLiteral("dynamic/maxFileSizeMiB"), maxFileSizeMiB);
    s.setValue(QStringLiteral("dynamic/extraArgs"), extraArgs);
    s.setValue(QStringLiteral("dynamic/strace"), straceOverride);
    s.setValue(QStringLiteral("ui/theme"), theme);
    s.setValue(QStringLiteral("ui/language"), language);
    s.setValue(QStringLiteral("ui/lastExportDir"), lastExportDir);
    s.setValue(QStringLiteral("ui/exportFormat"), defaultExportFormat);
}

QString Settings::workRoot()
{
    QString base = QStandardPaths::writableLocation(QStandardPaths::GenericCacheLocation);
    if (base.isEmpty()) base = QDir::homePath() + QStringLiteral("/.cache");
    const QString p = base + QStringLiteral("/pkgscope/work");
    QDir().mkpath(p);
    QFile::setPermissions(p, QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);
    return p;
}

} // namespace ps
