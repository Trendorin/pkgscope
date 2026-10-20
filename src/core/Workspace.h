// SPDX-License-Identifier: MIT
#pragma once

#include <QHash>
#include <QString>
#include <QStringList>
#include <QVector>

#include <memory>

namespace ps {

// One step executed inside the sandbox during behaviour tracing.
struct TraceStage {
    QString name;              // "preinst install", "AppRun", ...
    QStringList argv;          // paths are as seen inside the sandbox
    QString cwd = QStringLiteral("/");
    QStringList env;           // extra KEY=VALUE pairs
    bool installPayloadBefore = false;
};

struct TracePlan {
    bool supported = false;
    QString reason;            // why tracing is not possible / what will happen
    QVector<TraceStage> stages;
    bool bindPayloadAsAppDir = false; // AppImage: payload mounted read-only at /sandbox/appdir
    bool bindPayloadAsSource = false; // tarball: writable copy mounted at /sandbox/src
};

// Private, auto-cleaned working directory for one analysed input.
class Workspace
{
public:
    static std::shared_ptr<Workspace> create(QString *error);
    ~Workspace();
    Workspace(const Workspace &) = delete;
    Workspace &operator=(const Workspace &) = delete;

    QString root() const { return m_root; }
    QString payloadDir() const { return m_root + QStringLiteral("/payload"); }
    QString controlDir() const { return m_root + QStringLiteral("/control"); }
    QString inputDir() const { return m_root + QStringLiteral("/input"); }
    QString scriptsDir() const { return m_root + QStringLiteral("/scripts"); }
    QString runsDir() const { return m_root + QStringLiteral("/runs"); }

    TracePlan plan;
    bool payloadIsInstallTree = false;           // payload paths map to "/" when installed
    QHash<QString, QString> payloadSha256;       // "/usr/bin/x" -> hex

    void setKeep(bool keep) { m_keep = keep; }

    // Removes leftovers from crashed sessions (dirs whose owning PID is gone).
    static void cleanupStale();

private:
    explicit Workspace(QString root) : m_root(std::move(root)) {}
    QString m_root;
    bool m_keep = false;
};

} // namespace ps
