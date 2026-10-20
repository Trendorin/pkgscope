// SPDX-License-Identifier: MIT
#pragma once

#include <QString>

class QCoreApplication;

namespace ps::i18n {
// English is built in. `setting` is "auto" (follow the system language), "en" or "ru";
// PKGSCOPE_LANG overrides it.
void install(QCoreApplication &app, const QString &setting);
bool wantsRussian(const QString &setting);
} // namespace ps::i18n
