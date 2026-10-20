// SPDX-License-Identifier: MIT
#pragma once

#include "core/Types.h"

#include <QColor>
#include <QIcon>
#include <QString>

class QApplication;

namespace ps::theme {

// Applies the chosen theme. "system" keeps the platform palette (so system
// accent/colours are respected); "light"/"dark" force a Fusion palette.
void apply(QApplication &app, const QString &mode);

bool isDark();
QColor severityColor(Severity s);
QColor severityBg(Severity s);
QString severityStyle(Severity s); // "background:#..;color:#.." for a pill label
QIcon severityIcon(Severity s);
QIcon appIcon();
// "color:#rrggbb" for secondary text in rich-text labels: palette(mid) is a frame
// colour and nearly invisible as text in many light themes.
QString mutedStyle();

} // namespace ps::theme
