// SPDX-License-Identifier: MIT
#include "MainWindow.h"
#include "SettingsDialog.h"
#include "Theme.h"
#include "Widgets.h"
#include "core/DynamicTracer.h"
#include "core/ReportWriter.h"
#include "core/Util.h"

#include <QApplication>
#include <QCloseEvent>
#include <QFileDialog>
#include <QFileInfo>
#include <QGridLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMenuBar>
#include <QMessageBox>
#include <QProgressBar>
#include <QPushButton>
#include <QScrollArea>
#include <QSplitter>
#include <QStackedWidget>
#include <QStatusBar>
#include <QTabWidget>
#include <QThread>
#include <QToolBar>
#include <QTreeWidget>
#include <QVBoxLayout>

namespace ps {

namespace {

QTreeWidget *makeTree(const QStringList &headers)
{
    auto *t = new QTreeWidget;
    t->setHeaderLabels(headers);
    t->setRootIsDecorated(false);
    t->setAlternatingRowColors(true);
    t->setUniformRowHeights(true);
    t->setSelectionBehavior(QAbstractItemView::SelectRows);
    t->setSortingEnabled(true);
    t->setContextMenuPolicy(Qt::ActionsContextMenu);
    t->header()->setStretchLastSection(true);
    return t;
}

QString metaName(const QString &id) { return id; }

} // namespace

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent)
{
    m_settings = Settings::load();
    setWindowTitle(QStringLiteral("PkgScope"));
    setWindowIcon(theme::appIcon());
    resize(1180, 820);

    // ----- actions
    m_actOpen = new QAction(QIcon::fromTheme(QStringLiteral("document-open")), tr("&Open…"), this);
    m_actOpen->setShortcut(QKeySequence::Open);
    m_actAnalyze = new QAction(QIcon::fromTheme(QStringLiteral("system-search")), tr("&Inspect"), this);
    m_actAnalyze->setShortcut(QKeySequence(QStringLiteral("Ctrl+R")));
    m_actTrace = new QAction(QIcon::fromTheme(QStringLiteral("media-playback-start")), tr("Inspect && &Trace"), this);
    m_actTrace->setShortcut(QKeySequence(QStringLiteral("Ctrl+T")));
    m_actCancel = new QAction(QIcon::fromTheme(QStringLiteral("process-stop")), tr("&Cancel"), this);
    m_actCancel->setEnabled(false);
    m_actExport = new QAction(QIcon::fromTheme(QStringLiteral("document-save")), tr("&Export report…"), this);
    m_actExport->setShortcut(QKeySequence::Save);
    m_actSettings = new QAction(QIcon::fromTheme(QStringLiteral("preferences-system")), tr("&Settings…"), this);
    m_actSettings->setShortcut(QKeySequence(QStringLiteral("Ctrl+,")));
    m_actClose = new QAction(tr("C&lose result"), this);
    m_actClose->setShortcut(QKeySequence(QStringLiteral("Ctrl+W")));

    connect(m_actOpen, &QAction::triggered, this, &MainWindow::browse);
    connect(m_actAnalyze, &QAction::triggered, this, [this] { startAnalysis(false); });
    connect(m_actTrace, &QAction::triggered, this, [this] { startAnalysis(true); });
    connect(m_actCancel, &QAction::triggered, this, &MainWindow::cancel);
    connect(m_actExport, &QAction::triggered, this, &MainWindow::exportReport);
    connect(m_actSettings, &QAction::triggered, this, &MainWindow::openSettings);
    connect(m_actClose, &QAction::triggered, this, [this] {
        m_hasResult = false;
        m_pendingPath.clear();
        m_stack->setCurrentWidget(m_drop);
        updateActions();
    });

    // ----- menus
    QMenu *fileMenu = menuBar()->addMenu(tr("&File"));
    fileMenu->addAction(m_actOpen);
    fileMenu->addAction(m_actExport);
    fileMenu->addAction(m_actClose);
    fileMenu->addSeparator();
    QAction *quit = fileMenu->addAction(tr("&Quit"));
    quit->setShortcut(QKeySequence::Quit);
    connect(quit, &QAction::triggered, this, &QWidget::close);

    QMenu *analyzeMenu = menuBar()->addMenu(tr("&Analyze"));
    analyzeMenu->addAction(m_actAnalyze);
    analyzeMenu->addAction(m_actTrace);
    analyzeMenu->addAction(m_actCancel);
    analyzeMenu->addSeparator();
    QAction *diag = analyzeMenu->addAction(tr("Check &sandbox support…"));
    connect(diag, &QAction::triggered, this, &MainWindow::checkSandbox);

    QMenu *toolsMenu = menuBar()->addMenu(tr("&Tools"));
    toolsMenu->addAction(m_actSettings);

    QMenu *helpMenu = menuBar()->addMenu(tr("&Help"));
    connect(helpMenu->addAction(tr("&About PkgScope")), &QAction::triggered, this, [this] {
        QMessageBox::about(this, tr("About PkgScope"),
            tr("<h3>PkgScope %1</h3>"
               "<p>Inspects Linux packages, AppImages and binaries, and can run them "
               "inside an isolated, no-root sandbox to record exactly what they do — "
               "which files they touch and which hosts they contact.</p>"
               "<p>Static heuristics and a single sandboxed run cannot prove a file is "
               "safe; they surface behaviour worth reviewing.</p>"
               "<p>Native Qt&nbsp;%2 · libarchive. MIT licensed.</p>")
                .arg(QStringLiteral(PKGSCOPE_VERSION), QStringLiteral(QT_VERSION_STR)));
    });
    connect(helpMenu->addAction(tr("About &Qt")), &QAction::triggered, qApp, &QApplication::aboutQt);

    // ----- toolbar
    auto *tb = addToolBar(tr("Main"));
    tb->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    tb->setMovable(false);
    tb->addAction(m_actOpen);
    tb->addSeparator();
    tb->addAction(m_actAnalyze);
    tb->addAction(m_actTrace);
    tb->addAction(m_actCancel);
    tb->addSeparator();
    tb->addAction(m_actExport);
    auto *spacer = new QWidget;
    spacer->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    tb->addWidget(spacer);
    tb->addAction(m_actSettings);

    // ----- central stack
    m_stack = new QStackedWidget;
    m_drop = new DropArea;
    connect(m_drop, &DropArea::fileChosen, this, &MainWindow::openPath);
    connect(m_drop, &DropArea::browseRequested, this, &MainWindow::browse);

    auto *dropPage = new QWidget;
    auto *dl = new QVBoxLayout(dropPage);
    dl->setContentsMargins(40, 40, 40, 40);
    auto *welcome = new QLabel(tr("<h2>PkgScope</h2>"
        "<p style='color:palette(mid)'>Unpack and inspect a package without installing it, then optionally run it in an isolated sandbox to watch what it really does.</p>"));
    welcome->setAlignment(Qt::AlignHCenter);
    welcome->setWordWrap(true);
    dl->addWidget(welcome);
    dl->addWidget(m_drop, 1);

    m_resultPage = new QWidget;
    auto *rl = new QVBoxLayout(m_resultPage);
    rl->setContentsMargins(0, 0, 0, 0);
    rl->setSpacing(0);

    // header card
    auto *header = new QWidget;
    header->setObjectName(QStringLiteral("headerCard"));
    auto *hl = new QHBoxLayout(header);
    hl->setContentsMargins(16, 12, 16, 12);
    auto *titleBox = new QVBoxLayout;
    m_headerTitle = new QLabel;
    QFont tf = m_headerTitle->font();
    tf.setPointSizeF(tf.pointSizeF() + 4);
    tf.setBold(true);
    m_headerTitle->setFont(tf);
    m_headerTitle->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_headerSub = new QLabel;
    m_headerSub->setTextInteractionFlags(Qt::TextSelectableByMouse);
    QPalette subPal = m_headerSub->palette();
    subPal.setColor(QPalette::WindowText, subPal.color(QPalette::PlaceholderText));
    m_headerSub->setPalette(subPal);
    titleBox->addWidget(m_headerTitle);
    titleBox->addWidget(m_headerSub);
    hl->addLayout(titleBox, 1);

    auto *scoreBox = new QVBoxLayout;
    scoreBox->setAlignment(Qt::AlignRight);
    m_scoreLabel = new QLabel;
    QFont sf = m_scoreLabel->font();
    sf.setPointSizeF(sf.pointSizeF() + 12);
    sf.setBold(true);
    m_scoreLabel->setFont(sf);
    m_scoreLabel->setAlignment(Qt::AlignRight);
    m_verdictLabel = new QLabel;
    m_verdictLabel->setAlignment(Qt::AlignRight);
    scoreBox->addWidget(m_scoreLabel);
    scoreBox->addWidget(m_verdictLabel);
    hl->addLayout(scoreBox);
    rl->addWidget(header);

    m_tabs = new QTabWidget;
    m_tabs->setDocumentMode(true);
    m_tabs->addTab(buildOverviewTab(), tr("Overview"));
    m_tabs->addTab(buildFindingsTab(), tr("Findings"));
    m_tabs->addTab(buildContentsTab(), tr("Contents"));
    m_tabs->addTab(buildScriptsTab(), tr("Scripts"));
    m_tabs->addTab(buildBinariesTab(), tr("Binaries"));
    m_behaviorTabIndex = m_tabs->addTab(buildBehaviorTab(), tr("Behaviour"));
    m_tabs->addTab(buildIndicatorsTab(), tr("Indicators"));
    m_tabs->addTab(buildLogTab(), tr("Log"));
    rl->addWidget(m_tabs, 1);

    m_stack->addWidget(dropPage);
    m_stack->addWidget(m_resultPage);
    setCentralWidget(m_stack);

    // ----- status bar / progress
    m_progressLabel = new QLabel;
    m_progress = new QProgressBar;
    m_progress->setMaximumWidth(260);
    m_progress->setVisible(false);
    m_progressLabel->setVisible(false);
    statusBar()->addPermanentWidget(m_progressLabel);
    statusBar()->addPermanentWidget(m_progress);

    setStyleSheet(QStringLiteral(
        "#headerCard{border-bottom:1px solid palette(mid);}"
        "QTabWidget::pane{border:none;}"));

    updateActions();
    statusBar()->showMessage(tr("Ready. Open a file to begin."));
}

MainWindow::~MainWindow()
{
    if (m_thread) {
        if (m_worker) m_worker->cancel();
        m_thread->quit();
        m_thread->wait(8000);
    }
}

// ------------------------------------------------------------------ tabs

QWidget *MainWindow::buildOverviewTab()
{
    auto *scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    auto *w = new QWidget;
    auto *v = new QVBoxLayout(w);
    v->setContentsMargins(16, 16, 16, 16);
    v->setSpacing(14);

    m_ovCounts = new QLabel;
    m_ovCounts->setTextFormat(Qt::RichText);
    v->addWidget(m_ovCounts);

    auto *infoGroup = new QGroupBox(tr("File"));
    auto *ig = new QVBoxLayout(infoGroup);
    m_ovInfo = new QLabel;
    m_ovInfo->setTextFormat(Qt::RichText);
    m_ovInfo->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_ovInfo->setWordWrap(true);
    ig->addWidget(m_ovInfo);
    v->addWidget(infoGroup);

    auto *metaGroup = new QGroupBox(tr("Package metadata"));
    auto *mg = new QVBoxLayout(metaGroup);
    m_metaTree = makeTree({tr("Field"), tr("Value")});
    m_metaTree->setSortingEnabled(false);
    m_metaTree->setMinimumHeight(180);
    mg->addWidget(m_metaTree);
    v->addWidget(metaGroup);

    auto *topGroup = new QGroupBox(tr("Most important findings"));
    auto *tg = new QVBoxLayout(topGroup);
    m_ovTopFindings = new QLabel;
    m_ovTopFindings->setTextFormat(Qt::RichText);
    m_ovTopFindings->setWordWrap(true);
    m_ovTopFindings->setTextInteractionFlags(Qt::TextSelectableByMouse);
    tg->addWidget(m_ovTopFindings);
    v->addWidget(topGroup);
    v->addStretch(1);

    scroll->setWidget(w);
    return scroll;
}

QWidget *MainWindow::buildFindingsTab()
{
    auto *w = new QWidget;
    auto *v = new QVBoxLayout(w);
    v->setContentsMargins(8, 8, 8, 8);
    auto *top = new QHBoxLayout;
    m_findingFilter = new QLineEdit;
    m_findingFilter->setPlaceholderText(tr("Filter findings (title, category, path, severity)…"));
    m_findingFilter->setClearButtonEnabled(true);
    top->addWidget(m_findingFilter);
    v->addLayout(top);

    QSplitter *split = new QSplitter(Qt::Vertical);
    m_findings = makeTree({tr("Severity"), tr("Category"), tr("Finding"), tr("Location"), tr("Source")});
    m_findings->sortByColumn(0, Qt::AscendingOrder);
    split->addWidget(m_findings);

    auto *detail = new QLabel(tr("Select a finding to see the explanation and evidence."));
    detail->setWordWrap(true);
    detail->setTextFormat(Qt::RichText);
    detail->setTextInteractionFlags(Qt::TextSelectableByMouse);
    detail->setAlignment(Qt::AlignTop);
    detail->setMargin(10);
    auto *detailScroll = new QScrollArea;
    detailScroll->setWidgetResizable(true);
    detailScroll->setWidget(detail);
    detailScroll->setMinimumHeight(120);
    split->addWidget(detailScroll);
    split->setStretchFactor(0, 3);
    split->setStretchFactor(1, 1);
    v->addWidget(split);

    const auto showSel = [this, detail] {
        const QList<QTreeWidgetItem *> sel = m_findings->selectedItems();
        auto *it = sel.isEmpty() ? m_findings->currentItem() : sel.constFirst();
        if (!it) return;
        const int line = it->data(0, Qt::UserRole + 1).toInt();
        const QString loc = it->data(0, Qt::UserRole + 2).toString();
        detail->setText(QStringLiteral("<h3>%1</h3><p>%2</p>%3%4")
            .arg(it->text(2).toHtmlEscaped(), it->data(0, Qt::UserRole + 3).toString().toHtmlEscaped(),
                 loc.isEmpty() ? QString() : QStringLiteral("<p><b>%1</b> <code>%2%3</code></p>").arg(tr("Location:"), loc.toHtmlEscaped(), line > 0 ? QStringLiteral(":%1").arg(line) : QString()),
                 it->data(0, Qt::UserRole + 4).toString().isEmpty() ? QString() : QStringLiteral("<p><b>%1</b></p><pre style='white-space:pre-wrap'>%2</pre>").arg(tr("Evidence:"), it->data(0, Qt::UserRole + 4).toString().toHtmlEscaped())));
    };
    connect(m_findings, &QTreeWidget::itemSelectionChanged, this, showSel);
    connect(m_findings, &QTreeWidget::itemDoubleClicked, this, [this](QTreeWidgetItem *it) {
        const QString loc = it->data(0, Qt::UserRole + 2).toString();
        const int line = it->data(0, Qt::UserRole + 1).toInt();
        if (line > 0 && m_scriptTabs) {
            for (int i = 0; i < m_scriptTabs->count(); ++i)
                if (m_scriptTabs->tabText(i) == loc || loc.endsWith(m_scriptTabs->tabText(i))) {
                    m_tabs->setCurrentIndex(3);
                    m_scriptTabs->setCurrentIndex(i);
                    if (auto *cv = qobject_cast<CodeView *>(m_scriptTabs->widget(i))) cv->gotoLine(line);
                    return;
                }
        }
    });
    connect(m_findingFilter, &QLineEdit::textChanged, this, [this](const QString &q) {
        for (int i = 0; i < m_findings->topLevelItemCount(); ++i) {
            auto *it = m_findings->topLevelItem(i);
            bool match = q.isEmpty();
            for (int c = 0; c < m_findings->columnCount() && !match; ++c)
                match = it->text(c).contains(q, Qt::CaseInsensitive);
            it->setHidden(!match);
        }
    });
    return w;
}

QWidget *MainWindow::buildContentsTab()
{
    auto *w = new QWidget;
    auto *v = new QVBoxLayout(w);
    v->setContentsMargins(8, 8, 8, 8);
    auto *top = new QHBoxLayout;
    m_contentsFilter = new QLineEdit;
    m_contentsFilter->setPlaceholderText(tr("Filter by path, kind or flag…"));
    m_contentsFilter->setClearButtonEnabled(true);
    m_contentsSummary = new QLabel;
    top->addWidget(m_contentsFilter, 1);
    top->addWidget(m_contentsSummary);
    v->addLayout(top);
    m_contents = makeTree({tr("Path"), tr("Type"), tr("Mode"), tr("Owner"), tr("Size"), tr("Kind"), tr("Flags")});
    v->addWidget(m_contents);
    connect(m_contentsFilter, &QLineEdit::textChanged, this, [this](const QString &q) {
        int shown = 0;
        for (int i = 0; i < m_contents->topLevelItemCount(); ++i) {
            auto *it = m_contents->topLevelItem(i);
            bool match = q.isEmpty() || it->text(0).contains(q, Qt::CaseInsensitive) || it->text(5).contains(q, Qt::CaseInsensitive) || it->text(6).contains(q, Qt::CaseInsensitive);
            it->setHidden(!match);
            if (match) ++shown;
        }
        m_contentsSummary->setText(tr("%1 shown").arg(shown));
    });
    return w;
}

QWidget *MainWindow::buildScriptsTab()
{
    m_scriptTabs = new QTabWidget;
    m_scriptTabs->setDocumentMode(true);
    m_scriptTabs->setTabPosition(QTabWidget::West);
    return m_scriptTabs;
}

QWidget *MainWindow::buildBinariesTab()
{
    auto *split = new QSplitter(Qt::Vertical);
    m_binaries = makeTree({tr("Path"), tr("Type"), tr("Arch"), tr("Lang"), tr("PIE"), tr("NX"), tr("RELRO"), tr("Canary"), tr("Stripped")});
    split->addWidget(m_binaries);
    m_binDetail = new QLabel(tr("Select a binary to see linked libraries, notable imports and RPATH."));
    m_binDetail->setWordWrap(true);
    m_binDetail->setTextFormat(Qt::RichText);
    m_binDetail->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_binDetail->setAlignment(Qt::AlignTop);
    m_binDetail->setMargin(10);
    auto *sc = new QScrollArea;
    sc->setWidgetResizable(true);
    sc->setWidget(m_binDetail);
    split->addWidget(sc);
    split->setStretchFactor(0, 2);
    connect(m_binaries, &QTreeWidget::itemSelectionChanged, this, [this] {
        auto *it = m_binaries->currentItem();
        if (!it) return;
        const int i = it->data(0, Qt::UserRole).toInt();
        if (i < 0 || i >= m_result.binaries.size()) return;
        const ElfInfo &e = m_result.binaries[i];
        QString h = QStringLiteral("<h3>%1</h3><p>%2 · %3 · %4</p>").arg(e.path.toHtmlEscaped(), e.elfType, e.machine, e.language);
        const auto list = [](const QString &title, const QStringList &items) {
            return items.isEmpty() ? QString() : QStringLiteral("<p><b>%1</b><br><code>%2</code></p>").arg(title, items.join(QStringLiteral(", ")).toHtmlEscaped());
        };
        if (!e.interpreter.isEmpty()) h += QStringLiteral("<p><b>Interpreter:</b> <code>%1</code></p>").arg(e.interpreter.toHtmlEscaped());
        if (!e.soname.isEmpty()) h += QStringLiteral("<p><b>SONAME:</b> <code>%1</code></p>").arg(e.soname.toHtmlEscaped());
        h += list(tr("Notable imports"), e.notableImports);
        h += list(tr("libc functions re-implemented"), e.libcOverrides);
        h += list(tr("RPATH"), e.rpath);
        h += list(tr("RUNPATH"), e.runpath);
        h += list(tr("Needed libraries"), e.needed);
        if (!e.modinfo.isEmpty()) {
            h += QStringLiteral("<p><b>%1</b></p><ul>").arg(tr("Kernel module info"));
            for (auto it2 = e.modinfo.begin(); it2 != e.modinfo.end(); ++it2)
                h += QStringLiteral("<li><code>%1</code> = %2</li>").arg(it2.key().toHtmlEscaped(), it2.value().toHtmlEscaped());
            h += QStringLiteral("</ul>");
        }
        h += QStringLiteral("<p><b>Entropy:</b> %1 bits/byte%2</p>").arg(e.entropy, 0, 'f', 2).arg(e.upx ? QStringLiteral(" · UPX packed") : QString());
        m_binDetail->setText(h);
    });
    return split;
}

QWidget *MainWindow::buildBehaviorTab()
{
    m_behaviorTabs = new QTabWidget;
    m_behaviorTabs->setDocumentMode(true);

    m_behaviorNotes = new QLabel;
    m_behaviorNotes->setWordWrap(true);
    m_behaviorNotes->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_behaviorNotes->setAlignment(Qt::AlignTop);
    m_behaviorNotes->setMargin(12);
    auto *notesScroll = new QScrollArea;
    notesScroll->setWidgetResizable(true);
    notesScroll->setWidget(m_behaviorNotes);
    m_behaviorTabs->addTab(notesScroll, tr("Summary"));

    m_procTree = makeTree({tr("Process / command"), tr("PID"), tr("Start"), tr("Result")});
    m_procTree->setRootIsDecorated(true);
    m_procTree->setSortingEnabled(false);
    m_behaviorTabs->addTab(m_procTree, tr("Processes"));

    auto *fsPage = new QWidget;
    auto *fv = new QVBoxLayout(fsPage);
    fv->setContentsMargins(4, 4, 4, 4);
    m_fsFilter = new QLineEdit;
    m_fsFilter->setPlaceholderText(tr("Filter file activity…"));
    m_fsFilter->setClearButtonEnabled(true);
    fv->addWidget(m_fsFilter);
    m_fsTree = makeTree({tr("Time"), tr("Operation"), tr("Path"), tr("Detail"), tr("Result")});
    fv->addWidget(m_fsTree);
    connect(m_fsFilter, &QLineEdit::textChanged, this, [this](const QString &q) {
        for (int i = 0; i < m_fsTree->topLevelItemCount(); ++i) {
            auto *it = m_fsTree->topLevelItem(i);
            it->setHidden(!q.isEmpty() && !it->text(2).contains(q, Qt::CaseInsensitive) && !it->text(1).contains(q, Qt::CaseInsensitive));
        }
    });
    m_behaviorTabs->addTab(fsPage, tr("File activity"));

    m_netTree = makeTree({tr("Time"), tr("Op"), tr("Protocol"), tr("Destination"), tr("Port"), tr("Domain"), tr("Result")});
    m_behaviorTabs->addTab(m_netTree, tr("Network"));

    m_changesTree = makeTree({tr("Change"), tr("Path"), tr("Type"), tr("Mode"), tr("Size")});
    m_behaviorTabs->addTab(m_changesTree, tr("Filesystem diff"));

    m_stageOutput = new CodeView;
    m_behaviorTabs->addTab(m_stageOutput, tr("Program output"));
    return m_behaviorTabs;
}

QWidget *MainWindow::buildIndicatorsTab()
{
    m_indicators = makeTree({tr("Type"), tr("Value"), tr("Source"), tr("Count")});
    return m_indicators;
}

QWidget *MainWindow::buildLogTab()
{
    m_log = new CodeView;
    return m_log;
}

// ------------------------------------------------------------------ actions

void MainWindow::browse()
{
    const QString start = m_settings.lastExportDir.isEmpty() ? QDir::homePath() : m_settings.lastExportDir;
    const QString f = QFileDialog::getOpenFileName(this, tr("Open package or binary"), start,
        tr("All supported (*.deb *.rpm *.pkg.tar.* *.apk *.AppImage *.appimage *.snap *.ipk *.xbps *.tgz *.txz *.tar.* *.run);;All files (*)"));
    if (!f.isEmpty()) openPath(f);
}

void MainWindow::openPath(const QString &path)
{
    QFileInfo fi(path);
    if (!fi.isFile()) {
        QMessageBox::warning(this, tr("PkgScope"), tr("Not a readable file:\n%1").arg(path));
        return;
    }
    m_pendingPath = fi.absoluteFilePath();
    m_hasResult = false;
    m_headerTitle->setText(fi.fileName());
    m_headerSub->setText(tr("%1 — press Inspect, or Inspect & Trace to also run it in the sandbox").arg(util::humanSize(static_cast<quint64>(fi.size()))));
    m_scoreLabel->clear();
    m_verdictLabel->clear();
    updateActions();
    statusBar()->showMessage(tr("Loaded %1").arg(fi.fileName()));
    // Begin static inspection immediately; the user can trace afterwards.
    startAnalysis(false);
}

void MainWindow::startAnalysis(bool trace)
{
    if (m_pendingPath.isEmpty()) {
        browse();
        return;
    }
    if (m_thread) return;
    m_settings = Settings::load();
    setBusy(true, trace ? tr("Preparing sandbox…") : tr("Inspecting…"));

    m_thread = new QThread(this);
    m_worker = new AnalysisWorker(m_settings, m_pendingPath, trace);
    m_worker->moveToThread(m_thread);
    connect(m_thread, &QThread::started, m_worker, &AnalysisWorker::run);
    connect(m_worker, &AnalysisWorker::progress, this, &MainWindow::onProgress);
    connect(m_worker, &AnalysisWorker::finished, this, &MainWindow::onFinished);
    connect(m_worker, &AnalysisWorker::failed, this, &MainWindow::onFailed);
    m_thread->start();
}

void MainWindow::onProgress(int percent, const QString &message)
{
    m_progress->setValue(percent);
    m_progressLabel->setText(message);
}

void MainWindow::onFinished(const AnalysisResult &result)
{
    m_result = result;
    m_hasResult = true;
    if (m_thread) {
        m_thread->quit();
        m_thread->wait();
        delete m_worker;
        m_worker = nullptr;
        m_thread->deleteLater();
        m_thread = nullptr;
    }
    populate();
    setBusy(false, QString());
    m_stack->setCurrentWidget(m_resultPage);
    updateActions();
    statusBar()->showMessage(tr("%1 — %2 (risk %3/100)").arg(result.fileName, result.verdict()).arg(result.riskScore()), 10000);
}

void MainWindow::onFailed(const QString &message)
{
    if (m_thread) {
        m_thread->quit();
        m_thread->wait();
        delete m_worker;
        m_worker = nullptr;
        m_thread->deleteLater();
        m_thread = nullptr;
    }
    setBusy(false, QString());
    updateActions();
    if (message != QLatin1String("Cancelled."))
        QMessageBox::warning(this, tr("Analysis failed"), message);
    statusBar()->showMessage(message, 8000);
}

void MainWindow::cancel()
{
    if (m_worker) {
        m_worker->cancel();
        statusBar()->showMessage(tr("Cancelling…"));
    }
}

void MainWindow::setBusy(bool busy, const QString &stage)
{
    m_progress->setVisible(busy);
    m_progressLabel->setVisible(busy);
    if (busy) {
        m_progress->setRange(0, 100);
        m_progress->setValue(0);
        m_progressLabel->setText(stage);
    }
    m_actCancel->setEnabled(busy);
    m_actAnalyze->setEnabled(!busy && !m_pendingPath.isEmpty());
    m_actTrace->setEnabled(!busy && !m_pendingPath.isEmpty());
    m_actOpen->setEnabled(!busy);
}

void MainWindow::updateActions()
{
    const bool running = m_thread != nullptr;
    m_actAnalyze->setEnabled(!running && !m_pendingPath.isEmpty());
    m_actTrace->setEnabled(!running && !m_pendingPath.isEmpty());
    m_actExport->setEnabled(m_hasResult && !running);
    m_actClose->setEnabled(m_hasResult && !running);
    m_actCancel->setEnabled(running);
}

void MainWindow::exportReport()
{
    if (!m_hasResult) return;
    const QString base = QFileInfo(m_result.fileName).completeBaseName();
    const QString dir = m_settings.lastExportDir.isEmpty() ? QDir::homePath() : m_settings.lastExportDir;
    QString selected;
    const QString def = m_settings.defaultExportFormat;
    QString filters = tr("HTML report (*.html);;JSON report (*.json);;Markdown report (*.md)");
    const QString suggested = dir + QLatin1Char('/') + base + QStringLiteral("-pkgscope.") + (def == QLatin1String("json") ? QStringLiteral("json") : def == QLatin1String("md") ? QStringLiteral("md") : QStringLiteral("html"));
    QString path = QFileDialog::getSaveFileName(this, tr("Export report"), suggested, filters, &selected);
    if (path.isEmpty()) return;
    QString fmt;
    if (selected.contains(QLatin1String("JSON"))) fmt = QStringLiteral("json");
    else if (selected.contains(QLatin1String("Markdown"))) fmt = QStringLiteral("md");
    else fmt = QStringLiteral("html");
    if (QFileInfo(path).suffix().isEmpty()) path += QLatin1Char('.') + fmt;
    QString err;
    if (ReportWriter::write(m_result, path, &err, fmt)) {
        m_settings.lastExportDir = QFileInfo(path).absolutePath();
        m_settings.defaultExportFormat = fmt;
        m_settings.save();
        statusBar()->showMessage(tr("Report saved to %1").arg(path), 8000);
    } else {
        QMessageBox::warning(this, tr("Export failed"), err);
    }
}

void MainWindow::openSettings()
{
    SettingsDialog dlg(m_settings, this);
    if (dlg.exec() == QDialog::Accepted) {
        m_settings = dlg.settings();
        m_settings.save();
        theme::apply(*qApp, m_settings.theme);
        statusBar()->showMessage(tr("Settings saved."), 4000);
    }
}

void MainWindow::checkSandbox()
{
    const DynamicTracer::Environment env = DynamicTracer::probe(Settings::load());
    QString msg = QStringLiteral("<h3>%1</h3>").arg(env.ready() ? tr("Sandbox is ready") : tr("Sandbox is not available"));
    if (!env.problems.isEmpty()) {
        msg += QStringLiteral("<p><b>%1</b></p><ul>").arg(tr("Blocking issues:"));
        for (const QString &p : env.problems) msg += QStringLiteral("<li>%1</li>").arg(p.toHtmlEscaped());
        msg += QStringLiteral("</ul>");
    }
    if (!env.notes.isEmpty()) {
        msg += QStringLiteral("<p><b>%1</b></p><ul>").arg(tr("Notes:"));
        for (const QString &p : env.notes) msg += QStringLiteral("<li>%1</li>").arg(p.toHtmlEscaped());
        msg += QStringLiteral("</ul>");
    }
    msg += QStringLiteral("<p style='color:palette(mid)'>Helper: <code>%1</code><br>strace: <code>%2</code></p>")
               .arg(env.helper.isEmpty() ? tr("(not found)") : env.helper, env.straceVersion.isEmpty() ? env.strace : env.straceVersion);
    QMessageBox box(this);
    box.setWindowTitle(tr("Sandbox support"));
    box.setTextFormat(Qt::RichText);
    box.setText(msg);
    box.setIcon(env.ready() ? QMessageBox::Information : QMessageBox::Warning);
    box.exec();
}

void MainWindow::closeEvent(QCloseEvent *e)
{
    if (m_thread) {
        if (QMessageBox::question(this, tr("PkgScope"), tr("An analysis is still running. Stop it and quit?")) != QMessageBox::Yes) {
            e->ignore();
            return;
        }
        if (m_worker) m_worker->cancel();
        m_thread->quit();
        m_thread->wait(8000);
    }
    e->accept();
}

// ------------------------------------------------------------------ populate

namespace {
// Rows sort by a numeric key in Qt::UserRole when a column has one (severity
// rank, sizes), otherwise by their text.
class SortItem : public QTreeWidgetItem
{
public:
    using QTreeWidgetItem::QTreeWidgetItem;
    bool operator<(const QTreeWidgetItem &other) const override
    {
        const int c = treeWidget() ? treeWidget()->sortColumn() : 0;
        const QVariant a = data(c, Qt::UserRole), b = other.data(c, Qt::UserRole);
        const auto numeric = [](const QVariant &v) {
            const int id = v.metaType().id();
            return id == QMetaType::Int || id == QMetaType::LongLong || id == QMetaType::ULongLong || id == QMetaType::Double;
        };
        if (numeric(a) && numeric(b)) return a.toDouble() < b.toDouble();
        return QTreeWidgetItem::operator<(other);
    }
};

QTreeWidgetItem *addRow(QTreeWidget *t, const QStringList &cols)
{
    return new SortItem(t, cols);
}
} // namespace

void MainWindow::populate()
{
    const AnalysisResult &r = m_result;
    // header
    m_headerTitle->setText(r.fileName);
    QString sub = r.formatName + QStringLiteral(" · ") + util::humanSize(r.fileSize);
    if (!r.meta.name.isEmpty()) sub += QStringLiteral(" · ") + r.meta.name + QLatin1Char(' ') + r.meta.version;
    m_headerSub->setText(sub);
    const int score = r.riskScore();
    const Severity worst = score >= 65 ? Severity::Critical : score >= 35 ? Severity::High : score >= 10 ? Severity::Medium : Severity::Low;
    m_scoreLabel->setText(tr("%1<span style='font-size:14px'> / 100</span>").arg(score));
    m_scoreLabel->setStyleSheet(QStringLiteral("color:%1").arg(theme::severityColor(worst).name()));
    m_verdictLabel->setText(r.verdict());
    m_verdictLabel->setStyleSheet(QStringLiteral("%1 font-size:13px;").arg(theme::severityStyle(worst)));

    // overview
    const QVector<Finding> all = r.allFindings();
    int counts[5] = {};
    for (const Finding &f : all) ++counts[static_cast<int>(f.severity)];
    QString cnt;
    for (int s = 4; s >= 0; --s)
        cnt += QStringLiteral("<span style='%1 margin-right:6px'>&nbsp;%2 %3&nbsp;</span>")
                   .arg(theme::severityStyle(static_cast<Severity>(s))).arg(counts[s]).arg(severityName(static_cast<Severity>(s)));
    m_ovCounts->setText(cnt);

    m_ovInfo->setText(QStringLiteral("<table cellspacing=4>"
        "<tr><td><b>Format</b></td><td>%1</td></tr>"
        "<tr><td><b>Size</b></td><td>%2 (%3 bytes)</td></tr>"
        "<tr><td><b>SHA-256</b></td><td><code>%4</code></td></tr>"
        "<tr><td><b>SHA-1</b></td><td><code>%5</code></td></tr>"
        "<tr><td><b>Entries</b></td><td>%6 files · %7 binaries · %8 scripts</td></tr>"
        "<tr><td><b>Analysed</b></td><td>%9 (%10 ms)</td></tr></table>")
        .arg(r.formatName.toHtmlEscaped(), util::humanSize(r.fileSize)).arg(r.fileSize)
        .arg(r.sha256, r.sha1).arg(r.files.size()).arg(r.binaries.size()).arg(r.scripts.size())
        .arg(r.analyzedAt.toString(Qt::ISODate)).arg(r.durationMs));

    m_metaTree->clear();
    const auto meta = [&](const QString &k, const QString &v) {
        if (!v.trimmed().isEmpty()) addRow(m_metaTree, {k, v});
    };
    meta(tr("Name"), r.meta.name);
    meta(tr("Version"), r.meta.version);
    meta(tr("Architecture"), r.meta.arch);
    meta(tr("Maintainer"), r.meta.maintainer);
    meta(tr("Description"), r.meta.description);
    meta(tr("Homepage"), r.meta.homepage);
    meta(tr("License"), r.meta.license);
    meta(tr("Depends"), r.meta.depends.join(QStringLiteral(", ")));
    for (auto it = r.meta.extra.begin(); it != r.meta.extra.end(); ++it) meta(metaName(it.key()), it.value());
    m_metaTree->resizeColumnToContents(0);

    QString top;
    int shown = 0;
    for (const Finding &f : all) {
        if (f.severity < Severity::Medium || shown >= 8) continue;
        ++shown;
        top += QStringLiteral("<p style='margin:3px 0'><span style='%1'>&nbsp;%2&nbsp;</span> <b>%3</b>%4<br>"
                              "<span style='color:palette(mid)'>%5</span></p>")
                   .arg(theme::severityStyle(f.severity), severityName(f.severity), f.title.toHtmlEscaped(),
                        f.location.isEmpty() ? QString() : QStringLiteral(" <code>%1</code>").arg(f.location.toHtmlEscaped()),
                        f.detail.toHtmlEscaped());
    }
    m_ovTopFindings->setText(shown ? top : tr("<p style='color:palette(mid)'>No medium or higher findings. Lower-severity items (if any) are in the Findings tab.</p>"));

    // findings
    m_findings->clear();
    m_findings->setSortingEnabled(false);
    for (const Finding &f : all) {
        auto *it = addRow(m_findings, {QString(), f.category, f.title, f.location + (f.line > 0 ? QStringLiteral(":%1").arg(f.line) : QString()),
                                       f.origin == QLatin1String("dynamic") ? tr("runtime") : tr("static")});
        it->setText(0, severityName(f.severity));
        it->setIcon(0, theme::severityIcon(f.severity));
        it->setData(0, Qt::UserRole, -static_cast<int>(f.severity)); // for sort
        it->setData(0, Qt::UserRole + 1, f.line);
        it->setData(0, Qt::UserRole + 2, f.location);
        it->setData(0, Qt::UserRole + 3, f.detail);
        it->setData(0, Qt::UserRole + 4, f.evidence);
        QColor bg = theme::severityBg(f.severity);
        for (int c = 0; c < 5; ++c) it->setBackground(c, bg);
    }
    m_findings->setSortingEnabled(true);
    m_findings->sortByColumn(0, Qt::AscendingOrder);
    for (int c = 0; c < 4; ++c) m_findings->resizeColumnToContents(c);
    m_tabs->setTabText(1, tr("Findings (%1)").arg(all.size()));

    // contents
    m_contents->clear();
    m_contents->setSortingEnabled(false);
    for (const FileEntry &f : r.files) {
        auto *it = addRow(m_contents, {f.path, f.type, util::modeString(f.mode), f.owner,
                                       f.type == QLatin1String("file") ? util::humanSize(f.size) : QString(), f.kind,
                                       f.flags.join(QStringLiteral(", "))});
        if (!f.linkTarget.isEmpty()) it->setText(0, f.path + QStringLiteral(" → ") + f.linkTarget);
        it->setData(4, Qt::UserRole, static_cast<qulonglong>(f.size));
        if (f.flags.contains(QStringLiteral("setuid")) || f.flags.contains(QStringLiteral("world-writable")))
            for (int c = 0; c < 7; ++c) it->setBackground(c, theme::severityBg(Severity::Medium));
    }
    m_contents->setSortingEnabled(true);
    m_contents->resizeColumnToContents(0);
    m_contentsSummary->setText(tr("%1 entries").arg(r.files.size()));
    m_tabs->setTabText(2, tr("Contents (%1)").arg(r.files.size()));

    // scripts
    while (m_scriptTabs->count()) {
        QWidget *w = m_scriptTabs->widget(0);
        m_scriptTabs->removeTab(0);
        delete w;
    }
    for (const ScriptEntry &s : r.scripts) {
        auto *cv = new CodeView;
        cv->setContent(s.content, s.flaggedLines);
        const QString label = s.name.section(QLatin1Char('/'), -1) + (s.flaggedLines.isEmpty() ? QString() : QStringLiteral(" ⚠%1").arg(s.flaggedLines.size()));
        const int idx = m_scriptTabs->addTab(cv, label);
        m_scriptTabs->setTabToolTip(idx, QStringLiteral("%1 — %2").arg(s.name, s.interpreter));
    }
    if (r.scripts.isEmpty()) {
        auto *l = new QLabel(tr("This package ships no install scripts."));
        l->setAlignment(Qt::AlignCenter);
        m_scriptTabs->addTab(l, tr("(none)"));
    }
    m_tabs->setTabText(3, tr("Scripts (%1)").arg(r.scripts.size()));

    // binaries
    m_binaries->clear();
    const auto yn = [](bool v) { return v ? QStringLiteral("✓") : QStringLiteral("✗"); };
    for (int i = 0; i < r.binaries.size(); ++i) {
        const ElfInfo &e = r.binaries[i];
        auto *it = addRow(m_binaries, {e.path, e.elfType, e.machine, e.language, yn(e.pie), yn(e.nx), e.relro, yn(e.canary), yn(e.stripped)});
        it->setData(0, Qt::UserRole, i);
        if (!e.libcOverrides.isEmpty() || e.upx || e.rwxSegment)
            for (int c = 0; c < 9; ++c) it->setBackground(c, theme::severityBg(Severity::High));
    }
    m_binaries->resizeColumnToContents(0);
    m_tabs->setTabText(4, tr("Binaries (%1)").arg(r.binaries.size()));

    // indicators
    m_indicators->clear();
    int indShown = 0;
    for (const Indicator &i : r.indicators) {
        if (i.likelyBenign && !m_settings.showBenignIndicators) continue;
        auto *it = addRow(m_indicators, {i.type, i.value, i.source, QString::number(i.count)});
        it->setData(3, Qt::UserRole, i.count);
        if (i.likelyBenign) it->setForeground(0, palette().color(QPalette::PlaceholderText));
        ++indShown;
    }
    m_tabs->setTabText(6, tr("Indicators (%1)").arg(indShown));

    // behaviour
    const BehaviorReport &b = r.behavior;
    m_tabs->setTabEnabled(m_behaviorTabIndex, true);
    if (!b.ran) {
        m_behaviorNotes->setText(QStringLiteral("<h3>%1</h3><p>%2</p><p style='color:palette(mid)'>%3</p>")
            .arg(tr("No sandbox run"),
                 (b.sandboxNotes.isEmpty() ? tr("Use <b>Inspect &amp; Trace</b> to execute this file in the isolated sandbox and record its behaviour.") : b.sandboxNotes.toHtmlEscaped()),
                 tr("Check <i>Analyze → Check sandbox support</i> if tracing is unavailable.")));
        m_tabs->setTabText(m_behaviorTabIndex, tr("Behaviour"));
        for (QTreeWidget *t : {m_procTree, m_fsTree, m_netTree, m_changesTree}) t->clear();
        m_stageOutput->setContent(QString(), {});
    } else {
        QString notes = QStringLiteral("<h3>%1</h3>").arg(tr("Sandboxed run"));
        notes += QStringLiteral("<p>%1</p>").arg(b.sandboxNotes.toHtmlEscaped().replace(QLatin1Char('\n'), QStringLiteral("<br>")));
        notes += QStringLiteral("<table cellspacing=4><tr><td><b>%1</b></td><td><b>%2</b></td><td><b>%3</b></td></tr>").arg(tr("Stage"), tr("Result"), tr("Time"));
        for (const StageResult &s : b.stages)
            notes += QStringLiteral("<tr><td><code>%1</code></td><td>%2</td><td>%3 s</td></tr>")
                         .arg(s.name.toHtmlEscaped(), (s.timedOut ? tr("time limit") : (!s.exitSignal.isEmpty() ? s.exitSignal : tr("exit %1").arg(s.exitCode)))).arg(s.duration, 0, 'f', 1);
        notes += QStringLiteral("</table><p style='color:palette(mid)'>%1 processes · %2 file operations · %3 network events · %4 filesystem changes · %5 s total</p>")
                     .arg(b.processes.size()).arg(b.fsEvents.size()).arg(b.netEvents.size()).arg(b.changes.size()).arg(b.duration, 0, 'f', 1);
        m_behaviorNotes->setText(notes);
        m_tabs->setTabText(m_behaviorTabIndex, tr("Behaviour ✓"));

        m_procTree->clear();
        QHash<int, QTreeWidgetItem *> items;
        QSet<int> pids;
        for (const ProcessInfo &p : b.processes) pids.insert(p.pid);
        for (const ProcessInfo &p : b.processes) {
            const QString status = !p.exitSignal.isEmpty() ? p.exitSignal : (p.exitCode >= 0 ? tr("exit %1").arg(p.exitCode) : QString());
            auto *it = new QTreeWidgetItem(QStringList{p.exe.isEmpty() ? tr("(fork)") : p.exe, QString::number(p.pid), QStringLiteral("%1s").arg(p.start, 0, 'f', 2), status});
            it->setToolTip(0, p.argv.join(QLatin1Char(' ')));
            items.insert(p.pid, it);
        }
        for (const ProcessInfo &p : b.processes) {
            auto *it = items.value(p.pid);
            auto *parent = (p.ppid && pids.contains(p.ppid) && items.value(p.ppid) != it) ? items.value(p.ppid) : nullptr;
            if (parent) parent->addChild(it);
            else m_procTree->addTopLevelItem(it);
        }
        m_procTree->expandAll();
        m_procTree->resizeColumnToContents(0);

        m_fsTree->clear();
        m_fsTree->setSortingEnabled(false);
        for (const FsEvent &e : b.fsEvents) {
            auto *it = addRow(m_fsTree, {QStringLiteral("%1").arg(e.t, 0, 'f', 2), e.op,
                                         e.path + (e.path2.isEmpty() ? QString() : QStringLiteral(" → ") + e.path2), e.detail,
                                         e.ok ? QStringLiteral("ok") : e.error});
            if (!e.ok) it->setForeground(4, theme::severityColor(Severity::Medium));
            if (e.op == QLatin1String("exec") || e.op.startsWith(QLatin1String("read-sensitive")) || e.op == QLatin1String("ptrace"))
                for (int c = 0; c < 5; ++c) it->setBackground(c, theme::severityBg(Severity::Low));
        }
        m_behaviorTabs->setTabText(2, tr("File activity (%1)").arg(b.fsEvents.size()));

        m_netTree->clear();
        for (const NetEvent &n : b.netEvents)
            addRow(m_netTree, {QStringLiteral("%1").arg(n.t, 0, 'f', 2), n.op, n.proto.isEmpty() ? n.family : n.proto,
                               n.address, n.port ? QString::number(n.port) : QString(), n.domain, n.ok ? QStringLiteral("ok") : n.error});
        for (const QString &d : b.dnsQueries)
            addRow(m_netTree, {QString(), QStringLiteral("dns"), QStringLiteral("udp"), QString(), QStringLiteral("53"), d, QString()});
        m_behaviorTabs->setTabText(3, tr("Network (%1)").arg(b.netEvents.size() + b.dnsQueries.size()));

        m_changesTree->clear();
        for (const FsChange &c : b.changes) {
            auto *it = addRow(m_changesTree, {c.change, c.path + (c.linkTarget.isEmpty() ? QString() : QStringLiteral(" → ") + c.linkTarget),
                                              c.type, util::modeString(c.mode), c.type == QLatin1String("file") ? util::humanSize(c.size) : QString()});
            it->setData(4, Qt::UserRole, static_cast<qulonglong>(c.size));
            if (c.change == QLatin1String("modified") || c.change == QLatin1String("deleted") || c.change == QLatin1String("created"))
                it->setForeground(0, theme::severityColor(c.change == QLatin1String("deleted") ? Severity::High : Severity::Medium));
        }
        m_behaviorTabs->setTabText(4, tr("Filesystem diff (%1)").arg(b.changes.size()));

        QString out;
        for (const StageResult &s : b.stages)
            if (!s.output.trimmed().isEmpty())
                out += QStringLiteral("===== %1 =====\n%2\n\n").arg(s.name, s.output);
        m_stageOutput->setContent(out.isEmpty() ? tr("(no output captured)") : out, {});
    }

    // log
    m_log->setContent(r.log.join(QLatin1Char('\n')), {});

    m_tabs->setCurrentIndex(0);
}

void MainWindow::showFinding(const Finding &) {}

} // namespace ps
