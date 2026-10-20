// SPDX-License-Identifier: MIT
#pragma once

#include "Types.h"

#include <QJsonObject>
#include <QString>

namespace ps {

class ReportWriter
{
public:
    static QJsonObject toJson(const AnalysisResult &r);
    static QString toHtml(const AnalysisResult &r);
    static QString toMarkdown(const AnalysisResult &r);

    // Writes atomically (temp file + rename). Format chosen from extension
    // (.json, .html/.htm, .md) unless `format` is given.
    static bool write(const AnalysisResult &r, const QString &path, QString *error, const QString &format = {});
};

} // namespace ps
