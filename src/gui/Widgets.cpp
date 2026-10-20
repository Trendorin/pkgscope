// SPDX-License-Identifier: MIT
#include "Widgets.h"
#include "Theme.h"
#include "core/Util.h"

#include <QDragEnterEvent>
#include <QDropEvent>
#include <QLabel>
#include <QMimeData>
#include <QPainter>
#include <QTextBlock>

namespace ps {

void AnalysisWorker::run()
{
    StaticAnalyzer analyzer(m_s);
    AnalysisResult r;
    const auto prog = [this](int p, const QString &m) { emit progress(p, m); };
    if (!analyzer.analyze(m_path, r, m_ws, prog, &m_cancel)) {
        emit failed(r.log.isEmpty() ? QStringLiteral("Analysis failed.") : r.log.join(QLatin1Char('\n')));
        return;
    }
    if (m_trace && !m_cancel) {
        DynamicTracer tracer(m_s, &analyzer);
        if (m_s.keepRunDir) m_ws->setKeep(true);
        tracer.run(r, *m_ws, prog, &m_cancel);
    }
    if (m_cancel) {
        emit failed(QStringLiteral("Cancelled."));
        return;
    }
    emit finished(r);
}

// ------------------------------------------------------------------ DropArea

DropArea::DropArea(QWidget *parent) : QFrame(parent)
{
    setAcceptDrops(true);
    setMinimumHeight(260);
    setCursor(Qt::PointingHandCursor);
    setFrameShape(QFrame::NoFrame);
}

void DropArea::dragEnterEvent(QDragEnterEvent *e)
{
    if (e->mimeData()->hasUrls()) {
        m_hover = true;
        update();
        e->acceptProposedAction();
    }
}
void DropArea::dragLeaveEvent(QDragLeaveEvent *) { m_hover = false; update(); }

void DropArea::dropEvent(QDropEvent *e)
{
    m_hover = false;
    update();
    const QList<QUrl> urls = e->mimeData()->urls();
    for (const QUrl &u : urls)
        if (u.isLocalFile()) {
            emit fileChosen(u.toLocalFile());
            return;
        }
}
void DropArea::mousePressEvent(QMouseEvent *) { emit browseRequested(); }

void DropArea::paintEvent(QPaintEvent *)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    const QRectF r = rect().adjusted(16, 16, -16, -16);
    QColor line = palette().color(QPalette::WindowText);
    line.setAlpha(m_hover ? 180 : 80);
    QPen pen(line, m_hover ? 2.0 : 1.4, Qt::DashLine);
    pen.setDashPattern({6, 5});
    p.setPen(pen);
    if (m_hover) {
        QColor fill = palette().color(QPalette::Highlight);
        fill.setAlpha(28);
        p.setBrush(fill);
    } else {
        p.setBrush(Qt::NoBrush);
    }
    p.drawRoundedRect(r, 14, 14);

    p.setBrush(Qt::NoBrush);
    QColor icon = palette().color(QPalette::WindowText);
    icon.setAlpha(150);
    p.setPen(QPen(icon, 2.2, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
    const QPointF c(width() / 2.0, height() / 2.0 - 26);
    p.drawRoundedRect(QRectF(c.x() - 26, c.y() - 20, 52, 44), 6, 6);
    p.drawLine(c + QPointF(0, -4), c + QPointF(0, 14));
    p.drawLine(c + QPointF(-8, 4), c + QPointF(0, 14));
    p.drawLine(c + QPointF(8, 4), c + QPointF(0, 14));

    QColor tcol = palette().color(QPalette::WindowText);
    p.setPen(tcol);
    QFont f = font();
    f.setPointSizeF(f.pointSizeF() + 2);
    f.setBold(true);
    p.setFont(f);
    p.drawText(QRectF(0, height() / 2.0 + 6, width(), 30), Qt::AlignHCenter, tr("Drop a package, AppImage or binary here"));
    tcol.setAlpha(150);
    p.setPen(tcol);
    f.setPointSizeF(font().pointSizeF());
    f.setBold(false);
    p.setFont(f);
    p.drawText(QRectF(0, height() / 2.0 + 36, width(), 24), Qt::AlignHCenter,
               tr(".deb  .rpm  .pkg.tar.zst  .apk  .AppImage  .snap  ELF  scripts — or click to browse"));
}

// ------------------------------------------------------------------ pill

QLabel *severityPill(Severity s, QWidget *parent)
{
    auto *l = new QLabel(severityName(s), parent);
    l->setStyleSheet(theme::severityStyle(s));
    l->setAlignment(Qt::AlignCenter);
    l->setMaximumHeight(20);
    return l;
}

// ------------------------------------------------------------------ CodeView

class LineGutter : public QWidget
{
public:
    explicit LineGutter(CodeView *v) : QWidget(v), m_v(v) {}
    QSize sizeHint() const override { return QSize(m_v->lineNumberWidth(), 0); }
protected:
    void paintEvent(QPaintEvent *e) override { m_v->lineNumberPaint(e); }
private:
    CodeView *m_v;
};

CodeView::CodeView(QWidget *parent) : QPlainTextEdit(parent)
{
    setReadOnly(true);
    setLineWrapMode(QPlainTextEdit::NoWrap);
    setFrameShape(QFrame::NoFrame);
    QFont f(QStringLiteral("monospace"));
    f.setStyleHint(QFont::Monospace);
    f.setPointSize(10);
    setFont(f);
    m_gutter = new LineGutter(this);
    connect(this, &QPlainTextEdit::blockCountChanged, this, [this] { setViewportMargins(lineNumberWidth(), 0, 0, 0); });
    connect(this, &QPlainTextEdit::updateRequest, this, [this](const QRect &r, int dy) {
        if (dy) m_gutter->scroll(0, dy);
        else m_gutter->update(0, r.y(), m_gutter->width(), r.height());
    });
    setViewportMargins(lineNumberWidth(), 0, 0, 0);
}

int CodeView::lineNumberWidth() const
{
    int digits = 1;
    for (int m = qMax(1, blockCount()); m >= 10; m /= 10) ++digits;
    return 14 + fontMetrics().horizontalAdvance(QLatin1Char('9')) * qMax(3, digits);
}

void CodeView::resizeEvent(QResizeEvent *e)
{
    QPlainTextEdit::resizeEvent(e);
    const QRect cr = contentsRect();
    m_gutter->setGeometry(cr.left(), cr.top(), lineNumberWidth(), cr.height());
}

void CodeView::lineNumberPaint(QPaintEvent *e)
{
    QPainter p(m_gutter);
    QColor bg = palette().color(QPalette::Window);
    p.fillRect(e->rect(), bg);
    QTextBlock block = firstVisibleBlock();
    int num = block.blockNumber();
    int top = static_cast<int>(blockBoundingGeometry(block).translated(contentOffset()).top());
    int bottom = top + static_cast<int>(blockBoundingRect(block).height());
    QColor fg = palette().color(QPalette::PlaceholderText);
    if (!fg.isValid()) fg = palette().color(QPalette::WindowText);
    while (block.isValid() && top <= e->rect().bottom()) {
        if (block.isVisible() && bottom >= e->rect().top()) {
            const int line = num + 1;
            if (m_hl.contains(line)) {
                QColor h = theme::severityColor(Severity::High);
                h.setAlpha(60);
                p.fillRect(0, top, m_gutter->width(), fontMetrics().height(), h);
                p.setPen(theme::severityColor(Severity::High));
            } else {
                p.setPen(fg);
            }
            p.drawText(0, top, m_gutter->width() - 6, fontMetrics().height(), Qt::AlignRight, QString::number(line));
        }
        block = block.next();
        top = bottom;
        bottom = top + static_cast<int>(blockBoundingRect(block).height());
        ++num;
    }
}

void CodeView::setContent(const QString &text, const QVector<int> &highlightLines)
{
    m_hl = QSet<int>(highlightLines.begin(), highlightLines.end());
    setPlainText(text);
    QList<QTextEdit::ExtraSelection> sels;
    QColor hb = theme::severityColor(Severity::High);
    hb.setAlpha(36);
    for (int line : highlightLines) {
        QTextEdit::ExtraSelection sel;
        sel.format.setBackground(hb);
        sel.format.setProperty(QTextFormat::FullWidthSelection, true);
        QTextCursor cur(document()->findBlockByNumber(line - 1));
        sel.cursor = cur;
        sels << sel;
    }
    setExtraSelections(sels);
    setViewportMargins(lineNumberWidth(), 0, 0, 0);
}

void CodeView::gotoLine(int line)
{
    QTextCursor cur(document()->findBlockByNumber(qMax(0, line - 1)));
    setTextCursor(cur);
    centerCursor();
    setFocus();
}

} // namespace ps
