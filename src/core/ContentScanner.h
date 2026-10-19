// SPDX-License-Identifier: MIT
#pragma once

#include "Types.h"

#include <QHash>
#include <QRegularExpression>

namespace ps {

enum class ContentKind {
    MaintainerScript, // runs as root during install/remove
    Script,           // shell/python/perl shipped in the package
    Desktop,          // .desktop entries
    Config,           // systemd units, udev rules, cron files, ...
    Text,             // other text
    Binary            // printable strings extracted from binaries
};

class IndicatorCollector
{
public:
    void add(const QString &type, const QString &value, const QString &source);
    QVector<Indicator> result() const;
    int size() const { return static_cast<int>(m_items.size()); }

private:
    QHash<QString, Indicator> m_items;
    QStringList m_order;
};

class ContentScanner
{
public:
    ContentScanner();

    // Scans text; returns flagged 1-based line numbers via `flagged`.
    void scanText(const QByteArray &data, const QString &location, ContentKind kind,
                  QVector<Finding> &out, IndicatorCollector &ioc, QVector<int> *flagged = nullptr) const;

    // Extracts printable strings (>= minLen) and scans them with binary-safe rules.
    void scanBinary(const QByteArray &data, const QString &location, QVector<Finding> &out, IndicatorCollector &ioc) const;

    static QByteArray extractStrings(const QByteArray &data, int minLen = 6, qsizetype maxOut = 16 * 1024 * 1024);

    // Path-based checks for files installed by a package.
    // `locationRules` = false checks only permissions (for trees that are not install roots).
    static void checkInstallPath(const FileEntry &fe, QVector<Finding> &out, bool locationRules = true);

    // Rules for paths written at runtime (dynamic analysis).
    struct PathRule { QString id; Severity sev; QString category; QString title; QRegularExpression re; };
    static const QVector<PathRule> &persistencePathRules();
    static const QVector<PathRule> &sensitiveReadRules();

private:
    struct Rule {
        QString id;
        Severity sev;
        QString category;
        QString title;
        QString detail;
        QRegularExpression re;
        bool scriptsOnly = false;   // skip for Text/Binary
        bool keepInBinary = false;  // do not downgrade for Binary/Text
    };
    QVector<Rule> m_rules;
    QRegularExpression m_url, m_ipv4, m_onion;

    void collectIndicators(const QString &line, const QString &location, IndicatorCollector &ioc) const;
};

} // namespace ps
