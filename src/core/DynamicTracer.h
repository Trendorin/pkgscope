// SPDX-License-Identifier: MIT
#pragma once

#include "Settings.h"
#include "Types.h"
#include "Workspace.h"

#include <atomic>
#include <functional>

namespace ps {

class StaticAnalyzer;

class DynamicTracer
{
public:
    struct Environment {
        QString helper;   // pkgscope-sandbox
        QString strace;
        QString straceVersion;
        QStringList problems; // blocking issues (empty == ready)
        QStringList notes;    // non-blocking information
        bool ready() const { return problems.isEmpty(); }
    };
    static Environment probe(const Settings &s);

    using Progress = std::function<void(int percent, const QString &message)>;

    DynamicTracer(Settings s, const StaticAnalyzer *analyzer);

    // Executes the workspace's trace plan stage by stage. Results are written
    // into `result.behavior`; dynamic findings are appended there as well.
    bool run(AnalysisResult &result, Workspace &ws, const Progress &progress, const std::atomic<bool> *cancel);

private:
    struct StageRun;
    bool runStage(const TraceStage &stage, int index, Workspace &ws, const QString &runDir, const AnalysisResult &r,
                  const Environment &env, BehaviorReport &out, const Progress &progress, const std::atomic<bool> *cancel,
                  QStringList &mountpoints, double &timeOffset);
    void placePayload(Workspace &ws, const QString &runDir, BehaviorReport &out);
    void diff(Workspace &ws, const QString &runDir, const QStringList &mountpoints, BehaviorReport &out);
    void deriveFindings(AnalysisResult &r, Workspace &ws, const QString &runDir);

    Settings m_s;
    const StaticAnalyzer *m_analyzer;
};

} // namespace ps
