// SPDX-License-Identifier: MIT
#pragma once

#include "ContentScanner.h"
#include "Settings.h"
#include "Types.h"
#include "Workspace.h"

#include <atomic>
#include <functional>
#include <memory>

namespace ps {

class StaticAnalyzer
{
public:
    using Progress = std::function<void(int percent, const QString &message)>;

    explicit StaticAnalyzer(Settings s);

    // Returns false on fatal error (message in result.log). The workspace stays
    // alive as long as the caller keeps the shared_ptr (needed for tracing).
    bool analyze(const QString &path, AnalysisResult &result, std::shared_ptr<Workspace> &ws,
                 const Progress &progress, const std::atomic<bool> *cancel);

    // Analyses files dropped by a traced run (ELF + content scan).
    void analyzeDroppedFile(const QString &root, const QString &rel, const QString &displayPath,
                            QVector<Finding> &findings, QVector<ElfInfo> &binaries, IndicatorCollector &ioc) const;

    static QString unsquashfsPath(const Settings &s);

private:
    struct Ctx;
    void detect(Ctx &c);
    bool doDeb(Ctx &c, bool outerTar);
    bool doRpm(Ctx &c);
    bool doTarPackage(Ctx &c);
    bool doAppImage(Ctx &c, int type);
    bool doSnap(Ctx &c);
    bool doSingleFile(Ctx &c);
    bool doGenericArchive(Ctx &c);
    bool runUnsquashfs(Ctx &c, quint64 offset);

    void scanPayload(Ctx &c);
    void scanFile(Ctx &c, FileEntry &fe);
    void analyzeElf(const QByteArray &data, const QString &location, QVector<Finding> &out, QVector<ElfInfo> &bins) const;
    void addScript(Ctx &c, const QString &name, const QString &stage, const QByteArray &content, const QString &interp = {});
    void verifyIntegrity(Ctx &c);

    Settings m_s;
    ContentScanner m_scanner;
};

} // namespace ps
