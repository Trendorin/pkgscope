// SPDX-License-Identifier: MIT
#pragma once

#include <QString>
#include <QStringList>

namespace ps {

struct Settings {
    // Static analysis
    int maxExtractMiB = 4096;       // zip-bomb guard
    int maxDeepScanMiB = 96;        // per-file limit for ELF parse / string scan
    bool scanBinaryStrings = true;
    bool verifyChecksums = true;
    bool showBenignIndicators = false;

    // Dynamic analysis
    int traceTimeoutSec = 60;       // per stage
    int graceSec = 5;               // time background processes may keep running after the main process exits
    bool allowNetwork = false;      // default: isolated network namespace (attempts are still recorded)
    bool allowDisplay = false;      // pass Wayland/X11 socket (lets GUI apps start; reduces isolation)
    bool keepRunDir = false;        // keep sandbox upper dirs for manual inspection
    int maxFileSizeMiB = 2048;      // RLIMIT_FSIZE inside the sandbox
    QString extraArgs;              // extra argv for executables / AppImages
    QString straceOverride;
    QString unsquashfsOverride;

    // Reports / UI
    QString theme = QStringLiteral("system"); // system | light | dark
    QString lastExportDir;
    QString defaultExportFormat = QStringLiteral("html");

    static Settings load();
    void save() const;
    static QString workRoot();      // ~/.cache/pkgscope/work
};

} // namespace ps
