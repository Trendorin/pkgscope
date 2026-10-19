// SPDX-License-Identifier: MIT
#pragma once

#include "Types.h"

#include <QByteArray>

namespace ps {

class ElfParser
{
public:
    static bool isElf(const QByteArray &data);
    // AppImage magic at e_ident[8..10]: returns 0 (not AppImage), 1 or 2.
    static int appImageType(const QByteArray &data);
    // Offset just past the ELF image (end of section header table or last segment).
    static quint64 elfImageEnd(const QByteArray &data);

    // Full parse. `data` may be truncated; parser is bounds-checked.
    static bool parse(const QByteArray &data, const QString &path, ElfInfo *out, QString *error = nullptr);

    // Raw contents of a named section (empty if absent or out of bounds).
    static QByteArray sectionData(const QByteArray &data, const QByteArray &name, quint64 maxSize = 1 << 20);
};

} // namespace ps
