// SPDX-License-Identifier: MIT
#pragma once

#include <QByteArray>
#include <QHash>
#include <QString>
#include <QStringList>
#include <QVector>

namespace ps {

// Minimal, bounds-checked reader for the RPM v3/v4 lead + header structures.
class RpmHeader
{
public:
    enum Tag : quint32 {
        Name = 1000, Version = 1001, Release = 1002, Epoch = 1003, Summary = 1004, Description = 1005,
        Vendor = 1011, License = 1014, Packager = 1015, Group = 1016, Url = 1020, Arch = 1022,
        PreIn = 1023, PostIn = 1024, PreUn = 1025, PostUn = 1026,
        FileSizes = 1028, FileModes = 1030, FileDigests = 1035, FileLinkTos = 1036, FileFlags = 1037,
        FileUserName = 1039, FileGroupName = 1040, RequireName = 1049,
        PreInProg = 1085, PostInProg = 1086, PreUnProg = 1087, PostUnProg = 1088,
        DirIndexes = 1116, BaseNames = 1117, DirNames = 1118,
        PreTrans = 1151, PostTrans = 1152, PreTransProg = 1153, PostTransProg = 1154,
        TriggerScripts = 1065, TriggerScriptProg = 1092, TriggerName = 1066,
        PayloadCompressor = 1125, FileDigestAlgo = 5011,
    };

    bool parse(const QByteArray &fileHead, QString *error);

    bool has(quint32 tag) const { return m_entries.contains(tag); }
    QString string(quint32 tag) const;
    QStringList stringArray(quint32 tag) const;
    QVector<qint64> intArray(quint32 tag) const;
    qint64 headerEnd() const { return m_headerEnd; }
    bool hasSignature() const { return m_sigEntries > 0; }
    QStringList filePaths() const; // dirnames[dirindexes[i]] + basenames[i]

private:
    struct Entry { quint32 type; quint32 offset; quint32 count; };
    QHash<quint32, Entry> m_entries;
    QByteArray m_store;
    qint64 m_headerEnd = 0;
    int m_sigEntries = 0;
};

} // namespace ps
