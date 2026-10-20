// SPDX-License-Identifier: MIT
//
// libFuzzer entry point for every parser that sees untrusted bytes without
// touching the filesystem: ELF, RPM header, DNS/TLS/HTTP sniffers, the content
// scanner and the raw decompressor. Build with -DPKGSCOPE_FUZZ=ON (clang).

#include "core/ArchiveReader.h"
#include "core/ContentScanner.h"
#include "core/ElfParser.h"
#include "core/RpmHeader.h"
#include "core/StraceParser.h"

#include <cstddef>
#include <cstdint>

using namespace ps;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    const QByteArray in = QByteArray::fromRawData(reinterpret_cast<const char *>(data), static_cast<qsizetype>(size));

    ElfInfo info;
    ElfParser::isElf(in);
    ElfParser::appImageType(in);
    ElfParser::elfImageEnd(in);
    ElfParser::parse(in, QStringLiteral("/fuzz"), &info);
    ElfParser::sectionData(in, QByteArrayLiteral(".dynstr"));

    RpmHeader rpm;
    if (rpm.parse(in, nullptr)) {
        rpm.filePaths();
        rpm.string(RpmHeader::Name);
    }

    StraceParser::parseDnsQuery(in);
    StraceParser::parseTlsSni(in);
    StraceParser::parseHttpHost(in);

    static const ContentScanner scanner;
    QVector<Finding> findings;
    IndicatorCollector ioc;
    if (size < 64 * 1024) {
        scanner.scanText(in, QStringLiteral("/fuzz.sh"), ContentKind::MaintainerScript, findings, ioc);
        scanner.scanBinary(in, QStringLiteral("/fuzz.bin"), findings, ioc);
    }
    ArchiveReader::decompressRaw(in, 1 << 20);
    return 0;
}
