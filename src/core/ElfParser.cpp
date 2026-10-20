// SPDX-License-Identifier: MIT
#include "ElfParser.h"
#include "Util.h"

#include <QSet>

namespace ps {

namespace {

constexpr quint32 PT_LOAD = 1, PT_DYNAMIC = 2, PT_INTERP = 3;
constexpr quint32 PT_GNU_STACK = 0x6474e551, PT_GNU_RELRO = 0x6474e552;
constexpr quint32 PF_X = 1, PF_W = 2;
constexpr quint32 SHT_SYMTAB = 2, SHT_DYNSYM = 11;
constexpr qint64 DT_NULL = 0, DT_NEEDED = 1, DT_STRTAB = 5, DT_SONAME = 14, DT_RPATH = 15,
                 DT_BIND_NOW = 24, DT_RUNPATH = 29, DT_FLAGS = 30, DT_FLAGS_1 = 0x6ffffffb;

class Reader
{
public:
    Reader(const QByteArray &d) : m_d(reinterpret_cast<const uchar *>(d.constData())), m_n(static_cast<quint64>(d.size()))
    {
        m_is64 = m_n > 4 && m_d[4] == 2;
        m_le = m_n > 5 && m_d[5] != 2;
    }
    bool is64() const { return m_is64; }
    quint64 size() const { return m_n; }
    bool in(quint64 off, quint64 len) const { return off <= m_n && len <= m_n - off; }

    quint64 u(quint64 off, int bytes) const
    {
        if (!in(off, static_cast<quint64>(bytes))) return 0;
        quint64 v = 0;
        for (int i = 0; i < bytes; ++i) {
            const quint64 b = m_d[off + (m_le ? i : bytes - 1 - i)];
            v |= b << (8 * i);
        }
        return v;
    }
    quint16 u16(quint64 o) const { return static_cast<quint16>(u(o, 2)); }
    quint32 u32(quint64 o) const { return static_cast<quint32>(u(o, 4)); }
    quint64 addr(quint64 o) const { return u(o, m_is64 ? 8 : 4); }

    QString cstr(quint64 off, quint64 limit = 4096) const
    {
        if (off >= m_n) return {};
        quint64 end = off;
        const quint64 max = std::min(m_n, off + limit);
        while (end < max && m_d[end]) ++end;
        return QString::fromUtf8(reinterpret_cast<const char *>(m_d + off), static_cast<qsizetype>(end - off));
    }
    const uchar *data() const { return m_d; }

private:
    const uchar *m_d;
    quint64 m_n;
    bool m_is64 = true, m_le = true;
};

struct Phdr { quint32 type, flags; quint64 offset, vaddr, filesz, memsz; };
struct Shdr { quint32 name, type; quint64 offset, size, addr; quint32 link; quint64 entsize; QString nameStr; };

QString machineName(quint16 m)
{
    switch (m) {
    case 2: return QStringLiteral("SPARC");
    case 3: return QStringLiteral("x86 (i386)");
    case 8: return QStringLiteral("MIPS");
    case 20: return QStringLiteral("PowerPC");
    case 21: return QStringLiteral("PowerPC64");
    case 22: return QStringLiteral("S/390");
    case 40: return QStringLiteral("ARM");
    case 43: return QStringLiteral("SPARC V9");
    case 50: return QStringLiteral("IA-64");
    case 62: return QStringLiteral("x86-64");
    case 183: return QStringLiteral("AArch64");
    case 243: return QStringLiteral("RISC-V");
    case 258: return QStringLiteral("LoongArch");
    default: return QStringLiteral("machine %1").arg(m);
    }
}

const QMap<QString, QString> &notableImportTable()
{
    static const QMap<QString, QString> t = {
        {QStringLiteral("ptrace"), QStringLiteral("ptrace")},
        {QStringLiteral("process_vm_writev"), QStringLiteral("process_vm_writev")},
        {QStringLiteral("process_vm_readv"), QStringLiteral("process_vm_readv")},
        {QStringLiteral("memfd_create"), QStringLiteral("memfd_create")},
        {QStringLiteral("fexecve"), QStringLiteral("fexecve")},
        {QStringLiteral("execveat"), QStringLiteral("execveat")},
        {QStringLiteral("init_module"), QStringLiteral("init_module")},
        {QStringLiteral("finit_module"), QStringLiteral("finit_module")},
        {QStringLiteral("delete_module"), QStringLiteral("delete_module")},
        {QStringLiteral("setuid"), QStringLiteral("setuid")},
        {QStringLiteral("setresuid"), QStringLiteral("setresuid")},
        {QStringLiteral("setreuid"), QStringLiteral("setreuid")},
        {QStringLiteral("capset"), QStringLiteral("capset")},
        {QStringLiteral("unshare"), QStringLiteral("unshare")},
        {QStringLiteral("setns"), QStringLiteral("setns")},
        {QStringLiteral("mount"), QStringLiteral("mount")},
        {QStringLiteral("pivot_root"), QStringLiteral("pivot_root")},
        {QStringLiteral("chroot"), QStringLiteral("chroot")},
        {QStringLiteral("socket"), QStringLiteral("socket")},
        {QStringLiteral("connect"), QStringLiteral("connect")},
        {QStringLiteral("bind"), QStringLiteral("bind")},
        {QStringLiteral("listen"), QStringLiteral("listen")},
        {QStringLiteral("system"), QStringLiteral("system")},
        {QStringLiteral("popen"), QStringLiteral("popen")},
        {QStringLiteral("execve"), QStringLiteral("execve")},
        {QStringLiteral("execvp"), QStringLiteral("execvp")},
        {QStringLiteral("execl"), QStringLiteral("execl")},
        {QStringLiteral("dlopen"), QStringLiteral("dlopen")},
        {QStringLiteral("XQueryKeymap"), QStringLiteral("XQueryKeymap")},
        {QStringLiteral("XRecordEnableContext"), QStringLiteral("XRecordEnableContext")},
        {QStringLiteral("XRecordCreateContext"), QStringLiteral("XRecordCreateContext")},
        {QStringLiteral("bpf"), QStringLiteral("bpf")},
        {QStringLiteral("perf_event_open"), QStringLiteral("perf_event_open")},
        {QStringLiteral("prctl"), QStringLiteral("prctl")},
        {QStringLiteral("inotify_add_watch"), QStringLiteral("inotify_add_watch")},
    };
    return t;
}

const QSet<QString> &libcHookTargets()
{
    static const QSet<QString> s = {
        QStringLiteral("readdir"), QStringLiteral("readdir64"), QStringLiteral("readdir_r"),
        QStringLiteral("opendir"), QStringLiteral("fopen"), QStringLiteral("fopen64"),
        QStringLiteral("open"), QStringLiteral("open64"), QStringLiteral("openat"),
        QStringLiteral("stat"), QStringLiteral("lstat"), QStringLiteral("__xstat"), QStringLiteral("__lxstat"),
        QStringLiteral("__xstat64"), QStringLiteral("__lxstat64"), QStringLiteral("access"),
        QStringLiteral("unlink"), QStringLiteral("unlinkat"), QStringLiteral("execve"),
        QStringLiteral("accept"), QStringLiteral("connect"), QStringLiteral("write"), QStringLiteral("read"),
        QStringLiteral("getpwnam"), QStringLiteral("getspnam"), QStringLiteral("pam_authenticate"),
        QStringLiteral("pcap_loop"), QStringLiteral("kill"), QStringLiteral("ptrace"),
    };
    return s;
}

bool isHookExemptLibrary(const QString &soname, const QString &path)
{
    const QString s = soname.isEmpty() ? path.section(QLatin1Char('/'), -1) : soname;
    static const QStringList prefixes = {
        QStringLiteral("libc.so"), QStringLiteral("libc-"), QStringLiteral("ld-linux"), QStringLiteral("ld-musl"),
        QStringLiteral("libpthread"), QStringLiteral("libasan"), QStringLiteral("libtsan"),
        QStringLiteral("liblsan"), QStringLiteral("libubsan"), QStringLiteral("libhwasan"),
        QStringLiteral("libfakeroot"), QStringLiteral("libfakechroot"), QStringLiteral("libgcompat"),
        QStringLiteral("libsandbox"), QStringLiteral("libc_malloc_debug"), QStringLiteral("libmemusage"),
        QStringLiteral("libpcprofile"), QStringLiteral("libSegFault"), QStringLiteral("libvalgrind"),
        QStringLiteral("vgpreload"), QStringLiteral("libnss_"), QStringLiteral("libpam.so"),
        QStringLiteral("libbsd.so"), QStringLiteral("libposix-"), QStringLiteral("libpseudo"),
    };
    for (const QString &p : prefixes)
        if (s.startsWith(p)) return true;
    return path.contains(QLatin1String("/security/pam_"));
}

} // namespace

bool ElfParser::isElf(const QByteArray &d)
{
    return d.size() >= 52 && d.startsWith("\x7f" "ELF") && (d[4] == 1 || d[4] == 2);
}

int ElfParser::appImageType(const QByteArray &d)
{
    if (!isElf(d) || d.size() < 11) return 0;
    if (d[8] == 'A' && d[9] == 'I') return static_cast<unsigned char>(d[10]) == 2 ? 2 : (d[10] == 1 ? 1 : 0);
    return 0;
}

quint64 ElfParser::elfImageEnd(const QByteArray &data)
{
    if (!isElf(data)) return 0;
    Reader r(data);
    const bool b64 = r.is64();
    const quint64 shoff = b64 ? r.u(40, 8) : r.u32(32);
    const quint16 shentsize = r.u16(b64 ? 58 : 46);
    const quint16 shnum = r.u16(b64 ? 60 : 48);
    quint64 end = shoff + static_cast<quint64>(shentsize) * shnum;
    const quint64 phoff = b64 ? r.u(32, 8) : r.u32(28);
    const quint16 phentsize = r.u16(b64 ? 54 : 42);
    const quint16 phnum = r.u16(b64 ? 56 : 44);
    for (quint16 i = 0; i < phnum; ++i) {
        const quint64 p = phoff + static_cast<quint64>(i) * phentsize;
        const quint64 off = b64 ? r.u(p + 8, 8) : r.u32(p + 4);
        const quint64 fsz = b64 ? r.u(p + 32, 8) : r.u32(p + 16);
        end = std::max(end, off + fsz);
    }
    return end;
}

QByteArray ElfParser::sectionData(const QByteArray &data, const QByteArray &name, quint64 maxSize)
{
    if (!isElf(data)) return {};
    Reader r(data);
    const bool b64 = r.is64();
    const quint64 shoff = b64 ? r.u(40, 8) : r.u32(32);
    const quint16 shentsize = r.u16(b64 ? 58 : 46);
    const quint16 shnum = r.u16(b64 ? 60 : 48);
    const quint16 shstrndx = r.u16(b64 ? 62 : 50);
    if (!shoff || shstrndx >= shnum || shentsize < (b64 ? 64 : 40)) return {};
    const auto secOff = [&](quint16 i) { return shoff + quint64(i) * shentsize; };
    const auto off = [&](quint16 i) { return b64 ? r.u(secOff(i) + 24, 8) : r.u32(secOff(i) + 16); };
    const auto size = [&](quint16 i) { return b64 ? r.u(secOff(i) + 32, 8) : r.u32(secOff(i) + 20); };
    const quint64 strBase = off(shstrndx);
    for (quint16 i = 0; i < shnum && i < 4096; ++i) {
        if (!r.in(secOff(i), shentsize)) break;
        if (r.cstr(strBase + r.u32(secOff(i)), 64).toLatin1() != name) continue;
        const quint64 o = off(i), s = std::min(size(i), maxSize);
        if (!r.in(o, s)) return {};
        return QByteArray(reinterpret_cast<const char *>(r.data() + o), static_cast<qsizetype>(s));
    }
    return {};
}

bool ElfParser::parse(const QByteArray &data, const QString &path, ElfInfo *out, QString *error)
{
    if (!isElf(data)) {
        if (error) *error = QStringLiteral("not an ELF file");
        return false;
    }
    Reader r(data);
    ElfInfo &e = *out;
    e.path = path;
    const bool b64 = r.is64();
    e.elfClass = b64 ? QStringLiteral("ELF64") : QStringLiteral("ELF32");
    const quint16 type = r.u16(16);
    e.machine = machineName(r.u16(18));
    e.entropy = util::shannonEntropy(data);

    const quint64 phoff = b64 ? r.u(32, 8) : r.u32(28);
    const quint64 shoff = b64 ? r.u(40, 8) : r.u32(32);
    const quint16 phentsize = r.u16(b64 ? 54 : 42);
    const quint16 phnum = r.u16(b64 ? 56 : 44);
    const quint16 shentsize = r.u16(b64 ? 58 : 46);
    quint16 shnum = r.u16(b64 ? 60 : 48);
    const quint16 shstrndx = r.u16(b64 ? 62 : 50);

    // ---- program headers
    QVector<Phdr> ph;
    if (phentsize >= (b64 ? 56 : 32) && phnum < 4096) {
        for (quint16 i = 0; i < phnum; ++i) {
            const quint64 p = phoff + static_cast<quint64>(i) * phentsize;
            if (!r.in(p, phentsize)) break;
            Phdr h{};
            h.type = r.u32(p);
            if (b64) {
                h.flags = r.u32(p + 4);
                h.offset = r.u(p + 8, 8);
                h.vaddr = r.u(p + 16, 8);
                h.filesz = r.u(p + 32, 8);
                h.memsz = r.u(p + 40, 8);
            } else {
                h.offset = r.u32(p + 4);
                h.vaddr = r.u32(p + 8);
                h.filesz = r.u32(p + 16);
                h.memsz = r.u32(p + 20);
                h.flags = r.u32(p + 24);
            }
            ph << h;
        }
    }

    const auto vaddrToOffset = [&](quint64 va) -> qint64 {
        for (const Phdr &h : ph)
            if (h.type == PT_LOAD && va >= h.vaddr && va < h.vaddr + h.filesz)
                return static_cast<qint64>(va - h.vaddr + h.offset);
        return -1;
    };

    bool hasInterp = false, hasDynamic = false, hasStack = false, hasRelro = false;
    Phdr dyn{};
    for (const Phdr &h : ph) {
        switch (h.type) {
        case PT_INTERP:
            hasInterp = true;
            e.interpreter = r.cstr(h.offset, std::min<quint64>(h.filesz, 512));
            break;
        case PT_DYNAMIC:
            hasDynamic = true;
            dyn = h;
            break;
        case PT_GNU_STACK:
            hasStack = true;
            e.nx = !(h.flags & PF_X);
            break;
        case PT_GNU_RELRO:
            hasRelro = true;
            break;
        case PT_LOAD:
            if ((h.flags & PF_W) && (h.flags & PF_X)) e.rwxSegment = true;
            break;
        default: break;
        }
    }
    if (!hasStack && type != 1) e.nx = false;

    // ---- dynamic section
    bool bindNow = false, flag1Pie = false;
    if (hasDynamic) {
        const int entSize = b64 ? 16 : 8;
        quint64 strtabVa = 0;
        QVector<QPair<qint64, quint64>> entries;
        for (quint64 off = dyn.offset; off + entSize <= dyn.offset + dyn.filesz && r.in(off, entSize); off += entSize) {
            const qint64 tag = static_cast<qint64>(r.addr(off));
            const quint64 val = r.addr(off + (b64 ? 8 : 4));
            if (tag == DT_NULL) break;
            entries.append({tag, val});
            if (tag == DT_STRTAB) strtabVa = val;
            if (entries.size() > 4096) break;
        }
        const qint64 strOff = vaddrToOffset(strtabVa);
        for (const auto &[tag, val] : entries) {
            const auto str = [&]() { return strOff >= 0 ? r.cstr(static_cast<quint64>(strOff) + val) : QString(); };
            switch (tag) {
            case DT_NEEDED: e.needed << str(); break;
            case DT_SONAME: e.soname = str(); break;
            case DT_RPATH: e.rpath << str().split(QLatin1Char(':'), Qt::SkipEmptyParts); break;
            case DT_RUNPATH: e.runpath << str().split(QLatin1Char(':'), Qt::SkipEmptyParts); break;
            case DT_BIND_NOW: bindNow = true; break;
            case DT_FLAGS: if (val & 0x8) bindNow = true; break;
            case DT_FLAGS_1:
                if (val & 0x1) bindNow = true;
                if (val & 0x08000000) flag1Pie = true;
                break;
            default: break;
            }
        }
    }
    e.relro = hasRelro ? (bindNow ? QStringLiteral("Full") : QStringLiteral("Partial")) : QStringLiteral("None");
    e.staticLinked = !hasInterp && !e.needed.size() && type == 2;

    switch (type) {
    case 1: e.elfType = QStringLiteral("Relocatable"); break;
    case 2: e.elfType = QStringLiteral("Executable"); e.pie = false; break;
    case 3:
        if (hasInterp || flag1Pie) {
            e.elfType = QStringLiteral("PIE executable");
            e.pie = true;
        } else {
            e.elfType = QStringLiteral("Shared object");
            e.pie = true;
        }
        if (!hasInterp && flag1Pie) e.staticLinked = e.needed.isEmpty();
        break;
    case 4: e.elfType = QStringLiteral("Core dump"); break;
    default: e.elfType = QStringLiteral("type %1").arg(type);
    }

    // ---- section headers
    QVector<Shdr> sh;
    if (shoff == 0 || shnum == 0 || shentsize < (b64 ? 64 : 40) || !r.in(shoff, static_cast<quint64>(shnum) * shentsize)) {
        e.noSectionHeaders = type != 1 || shoff == 0;
        shnum = 0;
    }
    for (quint16 i = 0; i < shnum && i < 8192; ++i) {
        const quint64 s = shoff + static_cast<quint64>(i) * shentsize;
        Shdr h{};
        h.name = r.u32(s);
        h.type = r.u32(s + 4);
        if (b64) {
            h.addr = r.u(s + 16, 8);
            h.offset = r.u(s + 24, 8);
            h.size = r.u(s + 32, 8);
            h.link = r.u32(s + 40);
            h.entsize = r.u(s + 56, 8);
        } else {
            h.addr = r.u32(s + 12);
            h.offset = r.u32(s + 16);
            h.size = r.u32(s + 20);
            h.link = r.u32(s + 24);
            h.entsize = r.u32(s + 36);
        }
        sh << h;
    }
    if (shstrndx < sh.size()) {
        const Shdr &strs = sh[shstrndx];
        for (Shdr &h : sh)
            if (h.name < strs.size) h.nameStr = r.cstr(strs.offset + h.name, 256);
    }

    QSet<QString> imports, exports;
    bool hasSymtab = false;
    for (const Shdr &h : sh) {
        if (h.type == SHT_SYMTAB) hasSymtab = true;
        if (h.nameStr == QLatin1String(".go.buildinfo") || h.nameStr == QLatin1String(".gopclntab")) e.language = QStringLiteral("Go");
        if (h.nameStr == QLatin1String(".rustc")) e.language = QStringLiteral("Rust");
        if (h.nameStr.startsWith(QLatin1String("UPX"))) e.upx = true;
        if (h.nameStr == QLatin1String(".modinfo") && r.in(h.offset, h.size)) {
            const QByteArray mi(reinterpret_cast<const char *>(r.data() + h.offset), static_cast<qsizetype>(std::min<quint64>(h.size, 65536)));
            for (const QByteArray &kv : mi.split('\0')) {
                const qsizetype eq = kv.indexOf('=');
                if (eq <= 0) continue;
                const QString k = QString::fromUtf8(kv.left(eq));
                const QString v = QString::fromUtf8(kv.mid(eq + 1));
                e.modinfo[k] = e.modinfo.contains(k) ? e.modinfo[k] + QStringLiteral(", ") + v : v;
            }
        }
        if ((h.type == SHT_DYNSYM || (h.type == SHT_SYMTAB && type == 1)) && h.link < sh.size()) {
            const int symSize = b64 ? 24 : 16;
            const Shdr &strs = sh[h.link];
            const quint64 count = std::min<quint64>(h.size / symSize, 200000);
            for (quint64 i = 1; i < count; ++i) {
                const quint64 s = h.offset + i * symSize;
                if (!r.in(s, symSize)) break;
                const quint32 nameOff = r.u32(s);
                const quint16 shndx = r.u16(s + (b64 ? 6 : 14));
                const uchar info = r.data()[s + (b64 ? 4 : 12)];
                const int bind = info >> 4;
                const int stype = info & 0xf;
                if (nameOff >= strs.size) continue;
                QString name = r.cstr(strs.offset + nameOff, 512);
                const qsizetype at = name.indexOf(QLatin1Char('@'));
                if (at > 0) name.truncate(at);
                if (name.isEmpty()) continue;
                if (shndx == 0) imports.insert(name);
                else if ((bind == 1 || bind == 2) && stype == 2) exports.insert(name);
            }
        }
    }
    e.stripped = !hasSymtab;

    for (const QString &imp : imports) {
        if (imp == QLatin1String("__stack_chk_fail") || imp == QLatin1String("__stack_chk_guard")) e.canary = true;
        if (imp.startsWith(QLatin1String("__")) && imp.endsWith(QLatin1String("_chk"))) e.fortify = true;
        auto it = notableImportTable().constFind(imp);
        if (it != notableImportTable().constEnd()) e.notableImports << it.value();
        if (e.language.isEmpty() && (imp.startsWith(QLatin1String("_Zn")) || imp.startsWith(QLatin1String("_ZSt")) || imp == QLatin1String("__cxa_throw")))
            e.language = QStringLiteral("C++");
    }
    std::sort(e.notableImports.begin(), e.notableImports.end());
    e.notableImports.removeDuplicates();

    if (type == 3 && !hasInterp && !isHookExemptLibrary(e.soname, path)) {
        for (const QString &x : exports)
            if (libcHookTargets().contains(x)) e.libcOverrides << x;
        std::sort(e.libcOverrides.begin(), e.libcOverrides.end());
    }

    // Language / packer heuristics from raw bytes (bounded search).
    const QByteArrayView head(data.constData(), std::min<qsizetype>(data.size(), 4096));
    if (head.indexOf(QByteArrayView("UPX!")) >= 0) e.upx = true;
    if (e.language.isEmpty()) {
        if (data.indexOf("Go build ID:") >= 0 || data.indexOf("runtime.gopanic") >= 0) e.language = QStringLiteral("Go");
        else if (data.indexOf("rust_panic") >= 0 || data.indexOf("/rustc/") >= 0) e.language = QStringLiteral("Rust");
        else if (data.indexOf("_MEIPASS") >= 0 || data.indexOf("pyi-runtime-tmpdir") >= 0) e.language = QStringLiteral("Python (PyInstaller)");
        else if (e.needed.join(QLatin1Char(' ')).contains(QLatin1String("libstdc++"))) e.language = QStringLiteral("C++");
        else if (!e.modinfo.isEmpty()) e.language = QStringLiteral("C (kernel module)");
        else e.language = QStringLiteral("C/C++ or other");
    }
    if (!e.modinfo.isEmpty()) e.elfType = QStringLiteral("Kernel module");
    return true;
}

} // namespace ps
