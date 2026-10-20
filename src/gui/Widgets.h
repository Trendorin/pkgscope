// SPDX-License-Identifier: MIT
#pragma once

#include "core/DynamicTracer.h"
#include "core/StaticAnalyzer.h"
#include "core/Types.h"

#include <QFrame>
#include <QPlainTextEdit>
#include <QThread>
#include <QWidget>

#include <atomic>
#include <memory>

class QLabel;

namespace ps {

// --- Analysis worker (runs StaticAnalyzer + optional DynamicTracer off the UI thread)

class AnalysisWorker : public QObject
{
    Q_OBJECT
public:
    AnalysisWorker(Settings s, QString path, bool trace) : m_s(std::move(s)), m_path(std::move(path)), m_trace(trace) {}
    void cancel() { m_cancel = true; }

public slots:
    void run();

signals:
    void progress(int percent, const QString &message);
    void finished(const ps::AnalysisResult &result);
    void failed(const QString &message);

private:
    Settings m_s;
    QString m_path;
    bool m_trace;
    std::atomic<bool> m_cancel{false};
    std::shared_ptr<Workspace> m_ws;
};

// --- Drop area shown before anything is loaded

class DropArea : public QFrame
{
    Q_OBJECT
public:
    explicit DropArea(QWidget *parent = nullptr);

signals:
    void fileChosen(const QString &path);
    void browseRequested();

protected:
    void dragEnterEvent(QDragEnterEvent *) override;
    void dragLeaveEvent(QDragLeaveEvent *) override;
    void dropEvent(QDropEvent *) override;
    void mousePressEvent(QMouseEvent *) override;
    void paintEvent(QPaintEvent *) override;

private:
    bool m_hover = false;
};

// --- A severity pill label

QLabel *severityPill(Severity s, QWidget *parent = nullptr);

// --- Read-only code view with line numbers and highlighted lines

class CodeView : public QPlainTextEdit
{
    Q_OBJECT
public:
    explicit CodeView(QWidget *parent = nullptr);
    void setContent(const QString &text, const QVector<int> &highlightLines);
    void gotoLine(int line);

    void lineNumberPaint(QPaintEvent *e);
    int lineNumberWidth() const;

protected:
    void resizeEvent(QResizeEvent *e) override;

private:
    QWidget *m_gutter;
    QSet<int> m_hl;
};

} // namespace ps
