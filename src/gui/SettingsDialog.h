// SPDX-License-Identifier: MIT
#pragma once

#include "core/Settings.h"

#include <QDialog>

class QCheckBox;
class QComboBox;
class QLineEdit;
class QSpinBox;

namespace ps {

class SettingsDialog : public QDialog
{
    Q_OBJECT
public:
    explicit SettingsDialog(const Settings &s, QWidget *parent = nullptr);
    Settings settings() const { return m_s; }

private:
    void load();
    void store();

    Settings m_s;
    QComboBox *m_theme;
    QSpinBox *m_maxExtract, *m_maxDeep, *m_timeout, *m_grace, *m_maxFsize;
    QCheckBox *m_scanStrings, *m_verify, *m_showBenign, *m_allowNet, *m_allowDisplay, *m_keepRun;
    QLineEdit *m_extraArgs;
    QComboBox *m_exportFmt;
};

} // namespace ps
