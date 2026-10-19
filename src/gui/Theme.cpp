// SPDX-License-Identifier: MIT
#include "Theme.h"

#include <QApplication>
#include <QPainter>
#include <QPalette>
#include <QPixmap>
#include <QStyle>
#include <QStyleFactory>
#include <QStyleHints>

namespace ps::theme {

namespace {
QString g_mode = QStringLiteral("system");

QColor base(Severity s)
{
    const bool d = isDark();
    switch (s) {
    case Severity::Critical: return d ? QColor(0xff, 0x5c, 0x72) : QColor(0xb3, 0x13, 0x2b);
    case Severity::High: return d ? QColor(0xff, 0x8a, 0x5c) : QColor(0xd1, 0x45, 0x1b);
    case Severity::Medium: return d ? QColor(0xf2, 0xc1, 0x4e) : QColor(0xb7, 0x79, 0x1f);
    case Severity::Low: return d ? QColor(0x6c, 0xb2, 0xff) : QColor(0x2b, 0x6c, 0xb0);
    case Severity::Info: return d ? QColor(0xa0, 0xa8, 0xb4) : QColor(0x5a, 0x62, 0x70);
    }
    return Qt::gray;
}
} // namespace

bool isDark()
{
    if (g_mode == QLatin1String("dark")) return true;
    if (g_mode == QLatin1String("light")) return false;
    const QColor w = qApp ? qApp->palette().color(QPalette::Window) : QColor(Qt::white);
    return w.lightness() < 128;
}

void apply(QApplication &app, const QString &mode)
{
    g_mode = mode;
    if (mode == QLatin1String("system")) {
        app.setPalette(app.style()->standardPalette());
        return;
    }
    app.setStyle(QStyleFactory::create(QStringLiteral("Fusion")));
#if QT_VERSION >= QT_VERSION_CHECK(6, 8, 0)
    app.styleHints()->setColorScheme(mode == QLatin1String("dark") ? Qt::ColorScheme::Dark : Qt::ColorScheme::Light);
#endif
    QPalette p;
    if (mode == QLatin1String("dark")) {
        const QColor bg(0x1d, 0x20, 0x25), base(0x15, 0x17, 0x1b), text(0xe6, 0xe8, 0xeb), dis(0x6b, 0x72, 0x7c);
        const QColor hl(0x3b, 0x82, 0xf6);
        p.setColor(QPalette::Window, bg);
        p.setColor(QPalette::WindowText, text);
        p.setColor(QPalette::Base, base);
        p.setColor(QPalette::AlternateBase, QColor(0x23, 0x26, 0x2d));
        p.setColor(QPalette::Text, text);
        p.setColor(QPalette::Button, bg);
        p.setColor(QPalette::ButtonText, text);
        p.setColor(QPalette::ToolTipBase, QColor(0x26, 0x2a, 0x31));
        p.setColor(QPalette::ToolTipText, text);
        p.setColor(QPalette::Highlight, hl);
        p.setColor(QPalette::HighlightedText, Qt::white);
        p.setColor(QPalette::Link, QColor(0x6c, 0xb2, 0xff));
        p.setColor(QPalette::PlaceholderText, dis);
        for (QPalette::ColorRole r : {QPalette::WindowText, QPalette::Text, QPalette::ButtonText})
            p.setColor(QPalette::Disabled, r, dis);
    } else {
        const QColor bg(0xf6, 0xf7, 0xf9), text(0x1d, 0x20, 0x26);
        p.setColor(QPalette::Window, bg);
        p.setColor(QPalette::WindowText, text);
        p.setColor(QPalette::Base, Qt::white);
        p.setColor(QPalette::AlternateBase, QColor(0xef, 0xf1, 0xf4));
        p.setColor(QPalette::Text, text);
        p.setColor(QPalette::Button, QColor(0xec, 0xee, 0xf1));
        p.setColor(QPalette::ButtonText, text);
        p.setColor(QPalette::Highlight, QColor(0x2b, 0x6c, 0xb0));
        p.setColor(QPalette::HighlightedText, Qt::white);
        p.setColor(QPalette::Link, QColor(0x1a, 0x56, 0x99));
    }
    app.setPalette(p);
}

QColor severityColor(Severity s) { return base(s); }

QColor severityBg(Severity s)
{
    QColor c = base(s);
    c.setAlpha(isDark() ? 46 : 32);
    return c;
}

QString severityStyle(Severity s)
{
    const QColor c = base(s);
    return QStringLiteral("background:%1;color:white;border-radius:7px;padding:1px 7px;font-weight:600;")
        .arg(c.name());
}

QIcon severityIcon(Severity s)
{
    QPixmap pm(16, 16);
    pm.fill(Qt::transparent);
    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing);
    p.setPen(Qt::NoPen);
    p.setBrush(base(s));
    if (s >= Severity::High) {
        QPolygonF tri({QPointF(8, 1), QPointF(15, 14), QPointF(1, 14)});
        p.drawPolygon(tri);
        p.setPen(QPen(Qt::white, 1.6));
        p.drawLine(QPointF(8, 6), QPointF(8, 10));
        p.drawPoint(QPointF(8, 12));
    } else {
        p.drawEllipse(2, 2, 12, 12);
    }
    return QIcon(pm);
}

QIcon appIcon()
{
    QIcon i(QStringLiteral(":/icons/pkgscope.svg"));
    return i.isNull() ? QIcon::fromTheme(QStringLiteral("security-high")) : i;
}

} // namespace ps::theme
