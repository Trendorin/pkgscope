// SPDX-License-Identifier: MIT
#include "SettingsDialog.h"
#include "Theme.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QSpinBox>
#include <QTabWidget>
#include <QPushButton>
#include <QVBoxLayout>

namespace ps {

SettingsDialog::SettingsDialog(const Settings &s, QWidget *parent) : QDialog(parent), m_s(s)
{
    setWindowTitle(tr("Settings"));
    setMinimumWidth(520);
    auto *v = new QVBoxLayout(this);
    auto *tabs = new QTabWidget;
    v->addWidget(tabs);

    // --- Static analysis
    auto *stat = new QWidget;
    auto *sf = new QFormLayout(stat);
    m_maxExtract = new QSpinBox;
    m_maxExtract->setRange(64, 65536);
    m_maxExtract->setSuffix(tr(" MiB"));
    m_maxExtract->setToolTip(tr("Stop extracting once the uncompressed payload reaches this size (protects against decompression bombs)."));
    sf->addRow(tr("Maximum extracted size:"), m_maxExtract);
    m_maxDeep = new QSpinBox;
    m_maxDeep->setRange(1, 2048);
    m_maxDeep->setSuffix(tr(" MiB"));
    m_maxDeep->setToolTip(tr("Per-file limit for ELF parsing and string scanning."));
    sf->addRow(tr("Deep-scan file limit:"), m_maxDeep);
    m_scanStrings = new QCheckBox(tr("Scan printable strings inside binaries"));
    sf->addRow(QString(), m_scanStrings);
    m_verify = new QCheckBox(tr("Verify files against the package's own checksums"));
    sf->addRow(QString(), m_verify);
    m_showBenign = new QCheckBox(tr("Show indicators that are likely benign (schema/doc URLs)"));
    sf->addRow(QString(), m_showBenign);
    tabs->addTab(stat, tr("Static"));

    // --- Sandbox
    auto *dyn = new QWidget;
    auto *df = new QFormLayout(dyn);
    m_timeout = new QSpinBox;
    m_timeout->setRange(5, 3600);
    m_timeout->setSuffix(tr(" s"));
    df->addRow(tr("Time limit per stage:"), m_timeout);
    m_grace = new QSpinBox;
    m_grace->setRange(0, 600);
    m_grace->setSuffix(tr(" s"));
    m_grace->setToolTip(tr("How long background processes may keep running after the main process exits before they are stopped."));
    df->addRow(tr("Grace period for daemons:"), m_grace);
    m_maxFsize = new QSpinBox;
    m_maxFsize->setRange(16, 65536);
    m_maxFsize->setSuffix(tr(" MiB"));
    m_maxFsize->setToolTip(tr("Maximum size of any single file the traced program may create."));
    df->addRow(tr("Max file size in sandbox:"), m_maxFsize);
    m_allowNet = new QCheckBox(tr("Allow network access (default: isolated, attempts recorded but fail)"));
    df->addRow(QString(), m_allowNet);
    m_allowDisplay = new QCheckBox(tr("Share the display so GUI apps can start (reduces isolation)"));
    df->addRow(QString(), m_allowDisplay);
    m_keepRun = new QCheckBox(tr("Keep the sandbox working directory for manual inspection"));
    df->addRow(QString(), m_keepRun);
    m_extraArgs = new QLineEdit;
    m_extraArgs->setPlaceholderText(tr("e.g. --help"));
    m_extraArgs->setToolTip(tr("Extra arguments passed to executables, AppImages and scripts when traced."));
    df->addRow(tr("Extra arguments:"), m_extraArgs);
    auto *warn = new QLabel(tr("<span style='%1'>The sandbox runs the file as a fake root inside isolated namespaces with a copy-on-write "
                               "overlay, dropped capabilities and a seccomp filter. Your real filesystem is never modified. "
                               "Allowing network or display access weakens that isolation.</span>").arg(theme::mutedStyle()));
    warn->setWordWrap(true);
    df->addRow(warn);
    tabs->addTab(dyn, tr("Sandbox"));

    // --- Appearance / reports
    auto *ui = new QWidget;
    auto *uf = new QFormLayout(ui);
    m_theme = new QComboBox;
    m_theme->addItem(tr("Follow system"), QStringLiteral("system"));
    m_theme->addItem(tr("Light"), QStringLiteral("light"));
    m_theme->addItem(tr("Dark"), QStringLiteral("dark"));
    uf->addRow(tr("Theme:"), m_theme);
    m_language = new QComboBox;
    m_language->addItem(tr("Follow system"), QStringLiteral("auto"));
    m_language->addItem(QStringLiteral("English"), QStringLiteral("en"));
    m_language->addItem(QStringLiteral("Русский"), QStringLiteral("ru"));
    uf->addRow(tr("Language:"), m_language);
    m_exportFmt = new QComboBox;
    m_exportFmt->addItem(QStringLiteral("HTML"), QStringLiteral("html"));
    m_exportFmt->addItem(QStringLiteral("JSON"), QStringLiteral("json"));
    m_exportFmt->addItem(QStringLiteral("Markdown"), QStringLiteral("md"));
    uf->addRow(tr("Default export format:"), m_exportFmt);
    tabs->addTab(ui, tr("Appearance"));

    auto *box = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel | QDialogButtonBox::RestoreDefaults);
    v->addWidget(box);
    connect(box, &QDialogButtonBox::accepted, this, [this] { store(); accept(); });
    connect(box, &QDialogButtonBox::rejected, this, &QDialog::reject);
    connect(box->button(QDialogButtonBox::RestoreDefaults), &QPushButton::clicked, this, [this] {
        m_s = Settings();
        load();
    });

    load();
}

void SettingsDialog::load()
{
    m_maxExtract->setValue(m_s.maxExtractMiB);
    m_maxDeep->setValue(m_s.maxDeepScanMiB);
    m_scanStrings->setChecked(m_s.scanBinaryStrings);
    m_verify->setChecked(m_s.verifyChecksums);
    m_showBenign->setChecked(m_s.showBenignIndicators);
    m_timeout->setValue(m_s.traceTimeoutSec);
    m_grace->setValue(m_s.graceSec);
    m_maxFsize->setValue(m_s.maxFileSizeMiB);
    m_allowNet->setChecked(m_s.allowNetwork);
    m_allowDisplay->setChecked(m_s.allowDisplay);
    m_keepRun->setChecked(m_s.keepRunDir);
    m_extraArgs->setText(m_s.extraArgs);
    for (int i = 0; i < m_theme->count(); ++i)
        if (m_theme->itemData(i).toString() == m_s.theme) m_theme->setCurrentIndex(i);
    for (int i = 0; i < m_language->count(); ++i)
        if (m_language->itemData(i).toString() == m_s.language) m_language->setCurrentIndex(i);
    for (int i = 0; i < m_exportFmt->count(); ++i)
        if (m_exportFmt->itemData(i).toString() == m_s.defaultExportFormat) m_exportFmt->setCurrentIndex(i);
}

void SettingsDialog::store()
{
    m_s.maxExtractMiB = m_maxExtract->value();
    m_s.maxDeepScanMiB = m_maxDeep->value();
    m_s.scanBinaryStrings = m_scanStrings->isChecked();
    m_s.verifyChecksums = m_verify->isChecked();
    m_s.showBenignIndicators = m_showBenign->isChecked();
    m_s.traceTimeoutSec = m_timeout->value();
    m_s.graceSec = m_grace->value();
    m_s.maxFileSizeMiB = m_maxFsize->value();
    m_s.allowNetwork = m_allowNet->isChecked();
    m_s.allowDisplay = m_allowDisplay->isChecked();
    m_s.keepRunDir = m_keepRun->isChecked();
    m_s.extraArgs = m_extraArgs->text();
    m_s.theme = m_theme->currentData().toString();
    m_s.language = m_language->currentData().toString();
    m_s.defaultExportFormat = m_exportFmt->currentData().toString();
}

} // namespace ps
