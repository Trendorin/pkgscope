// SPDX-License-Identifier: MIT
#include "Types.h"

#include <algorithm>

namespace ps {

QString severityName(Severity s)
{
    switch (s) {
    case Severity::Info: return QStringLiteral("Info");
    case Severity::Low: return QStringLiteral("Low");
    case Severity::Medium: return QStringLiteral("Medium");
    case Severity::High: return QStringLiteral("High");
    case Severity::Critical: return QStringLiteral("Critical");
    }
    return QStringLiteral("Info");
}

Severity severityFromName(const QString &s)
{
    const QString l = s.toLower();
    if (l == u"critical") return Severity::Critical;
    if (l == u"high") return Severity::High;
    if (l == u"medium") return Severity::Medium;
    if (l == u"low") return Severity::Low;
    return Severity::Info;
}

int severityWeight(Severity s)
{
    switch (s) {
    case Severity::Info: return 0;
    case Severity::Low: return 2;
    case Severity::Medium: return 6;
    case Severity::High: return 16;
    case Severity::Critical: return 40;
    }
    return 0;
}

Severity downgrade(Severity s)
{
    return s == Severity::Info ? s : static_cast<Severity>(static_cast<int>(s) - 1);
}

QVector<Finding> AnalysisResult::allFindings() const
{
    QVector<Finding> all = findings;
    all += behavior.findings;
    std::stable_sort(all.begin(), all.end(), [](const Finding &a, const Finding &b) {
        return static_cast<int>(a.severity) > static_cast<int>(b.severity);
    });
    return all;
}

int AnalysisResult::riskScore() const
{
    // Diminishing returns per rule: the same rule firing 50 times should not
    // dominate the score, but many distinct high-risk rules should.
    QMap<QString, int> perRule;
    double score = 0;
    for (const Finding &f : allFindings()) {
        const int n = perRule[f.ruleId]++;
        const double w = severityWeight(f.severity);
        score += w / (1.0 + n * 2.0);
    }
    return std::clamp(static_cast<int>(score + 0.5), 0, 100);
}

QString AnalysisResult::verdict() const
{
    const int s = riskScore();
    if (countAtLeast(Severity::Critical) > 0 || s >= 65) return QStringLiteral("High risk");
    if (s >= 35) return QStringLiteral("Suspicious");
    if (s >= 10) return QStringLiteral("Needs review");
    return QStringLiteral("No major concerns");
}

int AnalysisResult::countAtLeast(Severity s) const
{
    int n = 0;
    for (const Finding &f : findings)
        if (f.severity >= s) ++n;
    for (const Finding &f : behavior.findings)
        if (f.severity >= s) ++n;
    return n;
}

} // namespace ps
