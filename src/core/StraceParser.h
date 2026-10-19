// SPDX-License-Identifier: MIT
#pragma once

#include "Types.h"

#include <QByteArray>
#include <QHash>
#include <QSet>
#include <QString>

namespace ps {

// Streaming parser for `strace -f -tt -xx -s N -o FILE` output.
// Turns raw syscalls into a process tree, file activity and network activity.
class StraceParser
{
public:
    struct Output {
        QVector<ProcessInfo> processes;
        QVector<FsEvent> fs;
        QVector<NetEvent> net;
        QStringList dns;
        qint64 lines = 0;
        qint64 dropped = 0;
        bool markerSeen = false;
    };

    StraceParser(QString stage, QByteArray marker, QString initialCwd, double timeOffset);

    bool parseFile(const QString &path, Output &out, qint64 maxEvents = 250000);
    void parseLine(QByteArray line, Output &out);

    // Exposed for tests
    static QString parseDnsQuery(const QByteArray &pkt, int *qtype = nullptr);
    static QString parseTlsSni(const QByteArray &buf);
    static QString parseHttpHost(const QByteArray &buf);

private:
    struct Sock {
        QString family, proto;
        QString peer;
        int port = 0;
        int netIndex = -1;
    };
    struct Call {
        int pid = 0;
        double t = 0;
        QByteArray name;
        QList<QByteArray> args;
        qint64 ret = 0;
        bool failed = false;
        QByteArray errnoName;
        bool unknownRet = false;
    };

    void handle(const Call &c, Output &out);
    int tgid(int pid) const { return m_tgid.value(pid, pid); }
    int procIndex(int tgid, Output &out, double t);
    QString resolve(int tg, const QByteArray &dirfd, const QString &path) const;
    void fsEvent(Output &out, const Call &c, const QString &op, const QString &path, const QString &path2 = {}, const QString &detail = {});
    void netFromSockaddr(Output &out, const Call &c, int fd, const QByteArray &sockaddr, const QString &op, const QList<QByteArray> &payloads);
    void inspectPayloads(Output &out, const QString &peer, int port, const QString &proto, const QList<QByteArray> &payloads, int netIndex);

    QString m_stage;
    QByteArray m_marker;
    QString m_initialCwd;
    double m_offset = 0;
    double m_t0 = -1;
    bool m_started = false;
    int m_rootPid = 0;
    qint64 m_maxEvents = 250000;
    QSet<int> m_preMarker;
    QHash<int, int> m_tgid;
    QHash<int, int> m_procIdx;
    QHash<int, QString> m_cwd;
    QHash<int, QHash<int, QString>> m_fdPath;
    QHash<int, QHash<int, Sock>> m_socks;
    QHash<int, QByteArray> m_pending; // unfinished calls per pid
    QSet<QString> m_dnsSeen;
};

} // namespace ps
