// SPDX-License-Identifier: MIT
#pragma once

#include "core/Settings.h"
#include "core/Types.h"

#include <QMainWindow>

class QActionGroup;
class QLabel;
class QLineEdit;
class QlistWidget;
class QProgressBar;
class QPushButton;
class QStackedWidget;
class QTabWidget;
class QThread;
class QTreeWidget;
class QTreeWidgetItem;

namespace ps {

class DropArea;
class CodeView;
class AnalysisWorker;

class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;

    void openPath(const QString &path);

protected:
    void closeEvent(QCloseEvent *) override;

private slots:
    void browse();
    void startAnalysis(bool trace);
    void onProgress(int percent, const QString &message);
    void onFinished(const AnalysisResult &result);
    void onFailed(const QString &message);
    void cancel();
    void exportReport();
    void openSettings();
    void checkSandbox();

private:
    QWidget *buildOverviewTab();
    QWidget *buildFindingsTab();
    QWidget *buildContentsTab();
    QWidget *buildScriptsTab();
    QWidget *buildBinariesTab();
    QWidget *buildBehaviorTab();
    QWidget *buildIndicatorsTab();
    QWidget *buildLogTab();
    void populate();
    void setBusy(bool busy, const QString &stage);
    void updateActions();
    void showFinding(const Finding &f);

    Settings m_settings;
    AnalysisResult m_result;
    bool m_hasResult = false;
    QString m_pendingPath;

    QThread *m_thread = nullptr;
    AnalysisWorker *m_worker = nullptr;

    QStackedWidget *m_stack = nullptr;
    DropArea *m_drop = nullptr;
    QWidget *m_resultPage = nullptr;
    QTabWidget *m_tabs = nullptr;
    QProgressBar *m_progress = nullptr;
    QLabel *m_progressLabel = nullptr;
    QLabel *m_headerTitle = nullptr;
    QLabel *m_headerSub = nullptr;
    QLabel *m_scoreLabel = nullptr;
    QLabel *m_verdictLabel = nullptr;

    // tab widgets filled by populate()
    QLabel *m_ovInfo = nullptr;
    QLabel *m_ovCounts = nullptr;
    QTreeWidget *m_metaTree = nullptr;
    QLabel *m_ovTopFindings = nullptr;
    QTreeWidget *m_findings = nullptr;
    QLineEdit *m_findingFilter = nullptr;
    QTreeWidget *m_contents = nullptr;
    QLineEdit *m_contentsFilter = nullptr;
    QLabel *m_contentsSummary = nullptr;
    QTabWidget *m_scriptTabs = nullptr;
    QTreeWidget *m_binaries = nullptr;
    QLabel *m_binDetail = nullptr;
    QTabWidget *m_behaviorTabs = nullptr;
    QLabel *m_behaviorNotes = nullptr;
    QTreeWidget *m_procTree = nullptr;
    QTreeWidget *m_fsTree = nullptr;
    QLineEdit *m_fsFilter = nullptr;
    QTreeWidget *m_netTree = nullptr;
    QTreeWidget *m_changesTree = nullptr;
    CodeView *m_stageOutput = nullptr;
    QTreeWidget *m_indicators = nullptr;
    CodeView *m_log = nullptr;
    int m_behaviorTabIndex = -1;

    QAction *m_actOpen = nullptr, *m_actAnalyze = nullptr, *m_actTrace = nullptr, *m_actCancel = nullptr,
            *m_actExport = nullptr, *m_actSettings = nullptr, *m_actClose = nullptr;
};

} // namespace ps
