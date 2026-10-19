// SPDX-License-Identifier: MIT
//
// pkgscope-sandbox — minimal unprivileged namespace sandbox used by PkgScope's
// behaviour tracer. It is NOT setuid; isolation comes from user, mount, PID,
// IPC, UTS, cgroup and (by default) network namespaces, a copy-on-write
// overlay over the host's system directories, a dropped capability bounding
// set, rlimits and a seccomp filter. Every write the traced program performs
// lands in an "upper" directory on the host that PkgScope diffs afterwards.
//
// Usage:
//   pkgscope-sandbox --root-dir DIR --upper DIR --work DIR [options] -- CMD [ARGS...]
//
// Options:
//   --net                 share the host network (default: isolated, loopback only)
//   --ro-bind SRC DEST    bind SRC read-only at DEST (DEST under /sandbox, /run or /tmp/.X11-unix)
//   --rw-bind SRC DEST    bind SRC read-write at DEST
//   --chdir DIR           working directory inside the sandbox
//   --setenv KEY=VALUE    add an environment variable (repeatable)
//   --marker PATH         execve(PATH) is attempted right before the real exec (trace marker)
//   --status-file PATH    key=value status lines are written here
//   --output-file PATH    stdout+stderr of the program
//   --fsize BYTES         RLIMIT_FSIZE for the program
//   --timeout SEC         kill everything after SEC seconds
//   --grace SEC           let background processes run SEC seconds after the main process exits
//
// On kernels with Landlock ABI 6+ (Linux 6.12) the program is also scoped: it
// cannot connect to abstract Unix sockets or signal processes outside the
// sandbox. This matters with --net, where the network namespace (and with it
// the host's abstract sockets: X11, D-Bus, ...) is shared.

#include <cerrno>
#include <csignal>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <net/if.h>
#include <sched.h>
#include <stddef.h>
#include <string>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <vector>

#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif
#ifndef MS_NOSYMFOLLOW
#define MS_NOSYMFOLLOW 256
#endif

namespace {

struct Bind {
    std::string src, dest;
    bool rw;
};

struct Options {
    std::string rootDir, upper, work, chdir = "/", marker, statusFile, outputFile;
    bool net = false;
    std::vector<Bind> binds;
    std::vector<std::string> env;
    std::vector<std::string> argv;
    unsigned long long fsize = 2ull << 30;
    int timeout = 0;
    int grace = 3;
};

int g_statusFd = -1;

void status(const char *fmt, ...)
{
    if (g_statusFd < 0) return;
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf - 2, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if (n > static_cast<int>(sizeof buf) - 2) n = sizeof buf - 2;
    buf[n++] = '\n';
    ssize_t w = write(g_statusFd, buf, static_cast<size_t>(n));
    (void)w;
}

[[noreturn]] void die(const char *what)
{
    const int e = errno;
    status("error=%s: %s", what, strerror(e));
    fprintf(stderr, "pkgscope-sandbox: %s: %s\n", what, strerror(e));
    _exit(125);
}

bool writeFile(const char *path, const char *data)
{
    const int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return false;
    const ssize_t len = static_cast<ssize_t>(strlen(data));
    const bool ok = write(fd, data, static_cast<size_t>(len)) == len;
    close(fd);
    return ok;
}

void makeSymlink(const char *target, const std::string &at)
{
    if (symlink(target, at.c_str()) != 0 && errno != EEXIST) status("note=symlink %s failed: %s", at.c_str(), strerror(errno));
}

void mkdirs(const std::string &path, mode_t mode = 0755)
{
    std::string cur;
    size_t pos = 0;
    while (pos <= path.size()) {
        size_t next = path.find('/', pos);
        if (next == std::string::npos) next = path.size();
        cur = path.substr(0, next);
        if (!cur.empty()) mkdir(cur.c_str(), mode);
        pos = next + 1;
    }
}

bool safeForMountOpts(const std::string &s)
{
    return s.find_first_of(",:\\\n") == std::string::npos;
}

unsigned long lockedFlags(const char *path)
{
    struct statvfs sv{};
    unsigned long f = 0;
    if (statvfs(path, &sv) != 0) return f;
    if (sv.f_flag & ST_NOSUID) f |= MS_NOSUID;
    if (sv.f_flag & ST_NODEV) f |= MS_NODEV;
    if (sv.f_flag & ST_NOEXEC) f |= MS_NOEXEC;
    if (sv.f_flag & ST_NOATIME) f |= MS_NOATIME;
    if (sv.f_flag & ST_NODIRATIME) f |= MS_NODIRATIME;
    if (sv.f_flag & ST_RELATIME) f |= MS_RELATIME;
    return f;
}

bool bindMount(const std::string &src, const std::string &dst, bool rw, bool recursive = true)
{
    const unsigned long rec = recursive ? static_cast<unsigned long>(MS_REC) : 0ul;
    if (mount(src.c_str(), dst.c_str(), nullptr, MS_BIND | rec, nullptr) != 0) return false;
    unsigned long flags = MS_REMOUNT | MS_BIND | MS_NOSUID | MS_NODEV | lockedFlags(src.c_str());
    if (!rw) flags |= MS_RDONLY;
    if (mount(nullptr, dst.c_str(), nullptr, flags, nullptr) != 0) {
        // nodev may not be addable on some kernels; retry with only locked flags
        flags = MS_REMOUNT | MS_BIND | lockedFlags(src.c_str()) | (rw ? 0ul : static_cast<unsigned long>(MS_RDONLY));
        if (mount(nullptr, dst.c_str(), nullptr, flags, nullptr) != 0 && !rw) return false;
    }
    return true;
}

void setOpaque(const std::string &upperDir)
{
    mkdirs(upperDir, 0755);
    if (setxattr(upperDir.c_str(), "user.overlay.opaque", "y", 1, 0) != 0)
        status("note=cannot mark %s opaque: %s", upperDir.c_str(), strerror(errno));
}

// ---------------------------------------------------------------- seccomp

struct Insns {
    std::vector<sock_filter> v;
    void stmt(unsigned short code, unsigned int k) { v.push_back(BPF_STMT(code, k)); }
    void jump(unsigned short code, unsigned int k, unsigned char jt, unsigned char jf) { v.push_back(BPF_JUMP(code, k, jt, jf)); }
};

constexpr unsigned kNsMask = 0x7E020000u; // CLONE_NEWNS|NEWCGROUP|NEWUTS|NEWIPC|NEWUSER|NEWPID|NEWNET

// eperm: denied; enosys: reported as unimplemented (callers fall back); fakeOk: pretend success
// (chown/setuid family — only uid 0 is mapped, so real calls would fail and abort installers).
void emitArch(Insns &p, int cloneNr, int clone3Nr, const std::vector<int> &eperm, const std::vector<int> &enosys,
              const std::vector<int> &fakeOk, bool x32Check)
{
    const unsigned retEperm = SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA);
    const unsigned retEnosys = SECCOMP_RET_ERRNO | (ENOSYS & SECCOMP_RET_DATA);
    p.stmt(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr));
    if (x32Check) {
        p.jump(BPF_JMP | BPF_JGE | BPF_K, 0x40000000u, 0, 1);
        p.stmt(BPF_RET | BPF_K, retEperm);
    }
    if (cloneNr >= 0) {
        p.jump(BPF_JMP | BPF_JEQ | BPF_K, static_cast<unsigned>(cloneNr), 0, 4);
        p.stmt(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, args[0]));
        p.jump(BPF_JMP | BPF_JSET | BPF_K, kNsMask, 0, 1);
        p.stmt(BPF_RET | BPF_K, retEperm);
        p.stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    }
    if (clone3Nr >= 0) {
        p.jump(BPF_JMP | BPF_JEQ | BPF_K, static_cast<unsigned>(clone3Nr), 0, 1);
        p.stmt(BPF_RET | BPF_K, retEnosys);
    }
    for (int nr : enosys) {
        p.jump(BPF_JMP | BPF_JEQ | BPF_K, static_cast<unsigned>(nr), 0, 1);
        p.stmt(BPF_RET | BPF_K, retEnosys);
    }
    for (int nr : eperm) {
        p.jump(BPF_JMP | BPF_JEQ | BPF_K, static_cast<unsigned>(nr), 0, 1);
        p.stmt(BPF_RET | BPF_K, retEperm);
    }
    for (int nr : fakeOk) {
        p.jump(BPF_JMP | BPF_JEQ | BPF_K, static_cast<unsigned>(nr), 0, 1);
        p.stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 0);
    }
    p.stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
}

bool installSeccomp()
{
#if defined(__x86_64__) || defined(__aarch64__)
    std::vector<int> eperm = {
#ifdef __NR_kexec_load
        __NR_kexec_load,
#endif
#ifdef __NR_kexec_file_load
        __NR_kexec_file_load,
#endif
        __NR_init_module, __NR_finit_module, __NR_delete_module, __NR_bpf, __NR_perf_event_open,
        __NR_userfaultfd, __NR_keyctl, __NR_add_key, __NR_request_key, __NR_open_by_handle_at,
#ifdef __NR_iopl
        __NR_iopl,
#endif
#ifdef __NR_ioperm
        __NR_ioperm,
#endif
        __NR_swapon, __NR_swapoff, __NR_reboot, __NR_acct, __NR_quotactl, __NR_unshare, __NR_setns,
        __NR_mount, __NR_umount2, __NR_pivot_root, __NR_syslog,
#ifdef __NR_uselib
        __NR_uselib,
#endif
#ifdef __NR_lookup_dcookie
        __NR_lookup_dcookie,
#endif
#ifdef __NR_fsopen
        __NR_fsopen, __NR_fsmount, __NR_fspick, __NR_move_mount, __NR_open_tree,
#endif
#ifdef __NR_mount_setattr
        __NR_mount_setattr,
#endif
    };
    std::vector<int> enosys = {
#ifdef __NR_io_uring_setup
        __NR_io_uring_setup, __NR_io_uring_enter, __NR_io_uring_register,
#endif
    };
    std::vector<int> fakeOk = {
#ifdef __NR_chown
        __NR_chown, __NR_lchown,
#endif
        __NR_fchown, __NR_fchownat, __NR_setuid, __NR_setgid, __NR_setreuid, __NR_setregid, __NR_setresuid,
        __NR_setresgid, __NR_setgroups, __NR_setfsuid, __NR_setfsgid,
    };
#ifdef __NR_clone3
    const int clone3 = __NR_clone3;
#else
    const int clone3 = -1;
#endif
    Insns p;
    p.stmt(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, arch));
#if defined(__x86_64__)
    // native x86-64 → fall through; i386 compat → second block; anything else → deny
    Insns native;
    emitArch(native, __NR_clone, clone3, eperm, enosys, fakeOk, true);
    Insns compat;
    emitArch(compat, 120, 435,
             {283, 128, 350, 129, 357, 336, 374, 288, 286, 287, 342, 110, 101, 87, 115, 88, 51, 131, 310, 346, 21, 52, 217,
              166, 113, 103, 86, 428, 429, 430, 432, 433, 442},
             {425, 426, 427},
             {182, 16, 95, 212, 198, 207, 298, 23, 46, 70, 71, 164, 170, 81, 138, 139, 213, 214, 203, 204, 208, 210, 206, 215, 216},
             false);
    // 0: ld arch (above)
    // 1: x86_64 → 5 (native block)
    // 2: i386   → 3 (jump to compat block), otherwise → 4
    // 3: ja compat
    // 4: deny unknown architectures (x32 etc.)
    p.jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 3, 0);
    p.jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_I386, 0, 1);
    p.stmt(BPF_JMP | BPF_JA | BPF_K, static_cast<unsigned>(native.v.size() + 1));
    p.stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (ENOSYS & SECCOMP_RET_DATA));
    p.v.insert(p.v.end(), native.v.begin(), native.v.end());
    p.v.insert(p.v.end(), compat.v.begin(), compat.v.end());
#else
    p.jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0);
    p.stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (ENOSYS & SECCOMP_RET_DATA));
    Insns native;
    emitArch(native, __NR_clone, clone3, eperm, enosys, fakeOk, false);
    p.v.insert(p.v.end(), native.v.begin(), native.v.end());
#endif
    sock_fprog prog{static_cast<unsigned short>(p.v.size()), p.v.data()};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return false;
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == 0;
#else
    return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0;
#endif
}

// Landlock scoping (ABI 6). Declared here because older kernel headers lack it.
struct LandlockAttr {
    unsigned long long handledAccessFs, handledAccessNet, scoped;
};
constexpr unsigned kLandlockCreateVersion = 1u << 0;
constexpr unsigned long long kScopeAbstractUnix = 1ull << 0, kScopeSignal = 1ull << 1;
#ifndef SYS_landlock_create_ruleset
#define SYS_landlock_create_ruleset 444
#define SYS_landlock_restrict_self 446
#endif

// Returns the Landlock ABI that was applied, 0 if none.
int applyLandlockScope()
{
    const long abi = syscall(SYS_landlock_create_ruleset, nullptr, 0, kLandlockCreateVersion);
    if (abi < 6) return 0;
    LandlockAttr attr{0, 0, kScopeAbstractUnix | kScopeSignal};
    const int fd = static_cast<int>(syscall(SYS_landlock_create_ruleset, &attr, sizeof attr, 0));
    if (fd < 0) return 0;
    const bool ok = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 && syscall(SYS_landlock_restrict_self, fd, 0) == 0;
    close(fd);
    return ok ? static_cast<int>(abi) : 0;
}

void dropCapabilities()
{
    int last = 40;
    if (FILE *f = fopen("/proc/sys/kernel/cap_last_cap", "re")) {
        if (fscanf(f, "%d", &last) != 1) last = 40;
        fclose(f);
    }
    const int keep[] = {CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH, CAP_FOWNER, CAP_FSETID, CAP_KILL,
                        CAP_SETGID, CAP_SETUID, CAP_NET_BIND_SERVICE, CAP_SETFCAP};
    for (int c = 0; c <= last; ++c) {
        bool k = false;
        for (int x : keep) k = k || x == c;
        if (!k) prctl(PR_CAPBSET_DROP, c, 0, 0, 0);
    }
}

void bringUpLoopback()
{
    const int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (s < 0) return;
    ifreq ifr{};
    strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
    if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0) {
        ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
        ioctl(s, SIOCSIFFLAGS, &ifr);
    }
    close(s);
}

// ---------------------------------------------------------------- upper-dir preparation
//
// Unprivileged overlayfs keeps the ownership of lower inodes, and host root is
// not mapped into our user namespace, so lower directories appear as owned by
// "nobody" and even namespace-root cannot create files in them. We therefore
// pre-create a directory skeleton in the upper layer (owned by us == ns root)
// so that the merged directories become writable. Small /etc files are copied
// up as well so that in-place edits (echo >> /etc/foo) work. PkgScope's diff
// compares the upper layer against the host and ignores unchanged copies.

struct SkelBudget {
    long dirs = 0;
    long maxDirs = 80000;
    long long copied = 0;
    long long maxCopy = 64ll << 20;
};

bool skipVarPath(const std::string &rel)
{
    static const char *skip[] = {"tmp", "home", "roothome", "mail", "spool/mail", "mnt", "cache", "log/journal",
                                 "lib/docker", "lib/containers", "lib/flatpak", "lib/snapd", "lib/libvirt",
                                 "lib/machines", "lib/mysql", "lib/postgresql", "lib/lxc", "lib/lxd", "lib/systemd/coredump"};
    for (const char *s : skip)
        if (rel == s) return true;
    return false;
}

void copyFileAt(int srcDir, int dstDir, const char *name, const struct stat &st, SkelBudget &b)
{
    if (st.st_size > (1 << 20) || b.copied + st.st_size > b.maxCopy) return;
    const int in = openat(srcDir, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (in < 0) return;
    const int out = openat(dstDir, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, st.st_mode & 07777);
    if (out >= 0) {
        char buf[65536];
        ssize_t r;
        while ((r = read(in, buf, sizeof buf)) > 0) {
            if (write(out, buf, static_cast<size_t>(r)) != r) break;
            b.copied += r;
        }
        fchmod(out, st.st_mode & 07777);
        close(out);
    }
    close(in);
}

void skeleton(int srcDir, int dstDir, const std::string &rel, int depth, int maxDepth, bool copyFiles, bool isVar, SkelBudget &b)
{
    if (depth > maxDepth || b.dirs >= b.maxDirs) return;
    const int dupFd = fcntl(srcDir, F_DUPFD_CLOEXEC, 0);
    DIR *d = dupFd >= 0 ? fdopendir(dupFd) : nullptr;
    if (!d) { if (dupFd >= 0) close(dupFd); return; }
    std::vector<std::string> names;
    while (dirent *e = readdir(d))
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) names.emplace_back(e->d_name);
    closedir(d);
    for (const std::string &n : names) {
        struct stat st{};
        if (fstatat(srcDir, n.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) continue;
        const std::string r = rel.empty() ? n : rel + "/" + n;
        if (S_ISDIR(st.st_mode)) {
            if (isVar && skipVarPath(r)) continue;
            if (mkdirat(dstDir, n.c_str(), (st.st_mode & 07777) | 0700) != 0 && errno != EEXIST) continue;
            ++b.dirs;
            const int s = openat(srcDir, n.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            const int t = openat(dstDir, n.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (s >= 0 && t >= 0) {
                skeleton(s, t, r, depth + 1, maxDepth, copyFiles, isVar, b);
                fchmod(t, (st.st_mode & 07777) | 0700);
            }
            if (s >= 0) close(s);
            if (t >= 0) close(t);
        } else if (copyFiles && S_ISREG(st.st_mode)) {
            copyFileAt(srcDir, dstDir, n.c_str(), st, b);
        }
    }
}

void prepareUpper(const Options &o)
{
    SkelBudget b;
    struct Top { const char *name; int depth; bool copy; };
    const Top tops[] = {{"etc", 12, true}, {"var", 6, false}, {"usr", 5, false}, {"opt", 3, false}};
    for (const Top &t : tops) {
        const std::string host = std::string("/") + t.name;
        struct stat st{};
        if (lstat(host.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) continue;
        const std::string up = o.upper + "/" + t.name;
        mkdirs(up);
        chmod(up.c_str(), (st.st_mode & 07777) | 0700);
        const int s = open(host.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        const int d = open(up.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (s >= 0 && d >= 0) skeleton(s, d, "", 1, t.depth, t.copy, !strcmp(t.name, "var"), b);
        if (s >= 0) close(s);
        if (d >= 0) close(d);
    }
    status("skeleton_dirs=%ld", b.dirs);
    status("etc_copied_bytes=%lld", b.copied);
}

// ---------------------------------------------------------------- filesystem

const char *kOverlay[] = {"usr", "etc", "opt", "var", "bin", "sbin", "lib", "lib32", "lib64", "libx32"};
const char *kPrivateDirs[] = {"home", "root", "tmp"}; // writable, backed by the upper dir (captured)
const char *kHideInVar[] = {"tmp", "home", "roothome", "mail", "spool/mail", "mnt", "lib/flatpak/app", "cache"};

bool inList(const char *name, const char *const *list, size_t n)
{
    for (size_t i = 0; i < n; ++i)
        if (!strcmp(name, list[i])) return true;
    return false;
}

void setupDev(const std::string &root)
{
    const std::string dev = root + "/dev";
    mkdir(dev.c_str(), 0755);
    if (mount("tmpfs", dev.c_str(), "tmpfs", MS_NOSUID | MS_NOEXEC, "mode=0755,size=1m") != 0) die("mount /dev tmpfs");
    for (const char *d : {"null", "zero", "full", "random", "urandom", "tty"}) {
        const std::string p = dev + "/" + d;
        const int fd = open(p.c_str(), O_WRONLY | O_CREAT | O_CLOEXEC, 0666);
        if (fd >= 0) close(fd);
        if (mount((std::string("/dev/") + d).c_str(), p.c_str(), nullptr, MS_BIND, nullptr) != 0)
            status("note=cannot bind /dev/%s: %s", d, strerror(errno));
    }
    const std::string pts = dev + "/pts";
    mkdir(pts.c_str(), 0755);
    if (mount("devpts", pts.c_str(), "devpts", MS_NOSUID | MS_NOEXEC, "newinstance,ptmxmode=0666,mode=620") == 0)
        makeSymlink("pts/ptmx", dev + "/ptmx");
    const std::string shm = dev + "/shm";
    mkdir(shm.c_str(), 01777);
    mount("tmpfs", shm.c_str(), "tmpfs", MS_NOSUID | MS_NODEV, "mode=1777,size=256m");
    makeSymlink("/proc/self/fd", dev + "/fd");
    makeSymlink("/proc/self/fd/0", dev + "/stdin");
    makeSymlink("/proc/self/fd/1", dev + "/stdout");
    makeSymlink("/proc/self/fd/2", dev + "/stderr");
}

struct OverlayStats {
    int mounted = 0;
    int fallbacks = 0;
};

// Mounts a copy-on-write overlay of host "/rel" at newroot/rel. If the host
// directory has submounts, the kernel refuses to use it as an unprivileged
// lower layer ("failed to clone lowerpath"), so we split: newroot/rel becomes a
// real (captured) directory and each child is overlaid individually.
void overlayTree(const Options &o, const std::string &rel, int depth, std::vector<std::string> &mountpoints, OverlayStats &st)
{
    const std::string host = "/" + rel;
    const std::string dst = o.rootDir + "/" + rel;
    const std::string up = o.upper + "/" + rel, wk = o.work + "/" + rel;
    mkdirs(up);
    mkdirs(wk, 0700);
    mkdir(dst.c_str(), 0755);
    mountpoints.push_back(rel);
    if (safeForMountOpts(up) && safeForMountOpts(wk) && safeForMountOpts(host)) {
        const std::string opts = "lowerdir=" + host + ",upperdir=" + up + ",workdir=" + wk + ",userxattr";
        if (mount("overlay", dst.c_str(), "overlay", MS_NOSUID | MS_NODEV, opts.c_str()) == 0) {
            ++st.mounted;
            return;
        }
    }
    if (depth >= 3) {
        status("note=overlay %s failed (%s); read-only", rel.c_str(), strerror(errno));
        ++st.fallbacks;
        if (!bindMount(host, dst, false)) status("note=read-only bind of %s failed: %s", rel.c_str(), strerror(errno));
        return;
    }
    DIR *d = opendir(host.c_str());
    if (!d) return;
    std::vector<std::string> names;
    while (dirent *e = readdir(d))
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) names.emplace_back(e->d_name);
    closedir(d);
    for (const std::string &n : names) {
        const std::string childRel = rel + "/" + n;
        struct stat cs{};
        if (lstat(("/" + childRel).c_str(), &cs) != 0) continue;
        const std::string cdst = o.rootDir + "/" + childRel;
        if (S_ISDIR(cs.st_mode)) {
            overlayTree(o, childRel, depth + 1, mountpoints, st);
        } else if (S_ISLNK(cs.st_mode)) {
            char target[4096];
            const ssize_t len = readlink(("/" + childRel).c_str(), target, sizeof target - 1);
            if (len > 0) { target[len] = 0; makeSymlink(target, cdst); }
            mountpoints.push_back(childRel);
        } else if (S_ISREG(cs.st_mode)) {
            const int fd = open(cdst.c_str(), O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
            if (fd >= 0) close(fd);
            bindMount("/" + childRel, cdst, false, false);
            mountpoints.push_back(childRel);
        }
    }
}

void setupRoot(const Options &o)
{
    const std::string &root = o.rootDir;
    if (mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) != 0) die("make / private");
    if (mount(root.c_str(), root.c_str(), nullptr, MS_BIND, nullptr) != 0) die("bind new root");
    mount(nullptr, root.c_str(), nullptr, MS_REMOUNT | MS_BIND | MS_NOSUID | MS_NODEV | lockedFlags(root.c_str()), nullptr);

    OverlayStats ov;
    DIR *d = opendir("/");
    if (!d) die("opendir /");
    std::vector<std::string> mountpoints;
    while (dirent *e = readdir(d)) {
        const char *n = e->d_name;
        if (!strcmp(n, ".") || !strcmp(n, "..")) continue;
        const std::string host = std::string("/") + n;
        const std::string dst = root + "/" + n;
        struct stat st{};
        if (lstat(host.c_str(), &st) != 0) continue;
        if (S_ISLNK(st.st_mode)) {
            if (!inList(n, kOverlay, sizeof kOverlay / sizeof *kOverlay)) continue;
            char target[4096];
            const ssize_t len = readlink(host.c_str(), target, sizeof target - 1);
            if (len <= 0) continue;
            target[len] = 0;
            unlink(dst.c_str());
            makeSymlink(target, dst);
            continue;
        }
        if (!S_ISDIR(st.st_mode)) continue;
        if (inList(n, kOverlay, sizeof kOverlay / sizeof *kOverlay)) {
            if (!strcmp(n, "var"))
                for (const char *h : kHideInVar) {
                    struct stat hs{};
                    if (lstat((host + "/" + h).c_str(), &hs) == 0 && S_ISDIR(hs.st_mode)) setOpaque(o.upper + "/var/" + h);
                }
            overlayTree(o, n, 0, mountpoints, ov);
            continue;
        }
        if (inList(n, kPrivateDirs, sizeof kPrivateDirs / sizeof *kPrivateDirs)) continue; // handled below
        if (!strcmp(n, "dev") || !strcmp(n, "proc") || !strcmp(n, "sys") || !strcmp(n, "run")) continue;
        // Everything else (mnt, media, srv, boot, snap, data drives ...) stays invisible.
    }
    closedir(d);
    status("overlay=%s", ov.mounted ? (ov.fallbacks ? "partial" : "ok") : "unavailable");
    status("overlay_mounts=%d", ov.mounted);
    status("overlay_readonly=%d", ov.fallbacks);

    for (const char *n : kPrivateDirs) {
        const std::string up = o.upper + "/" + n, dst = root + "/" + n;
        mkdirs(up, 0755);
        chmod(up.c_str(), !strcmp(n, "tmp") ? 01777 : (!strcmp(n, "root") ? 0700 : 0755));
        mkdir(dst.c_str(), 0755);
        if (!bindMount(up, dst, true, false)) die("bind private dir");
        mountpoints.push_back(n);
    }

    setupDev(root);
    const std::string proc = root + "/proc";
    mkdir(proc.c_str(), 0555);
    if (mount("proc", proc.c_str(), "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr) != 0)
        status("proc=unavailable (%s)", strerror(errno));
    else
        status("proc=ok");
    const std::string sys = root + "/sys";
    mkdir(sys.c_str(), 0555);
    if (!bindMount("/sys", sys, false)) status("sys=unavailable");
    const std::string run = root + "/run";
    mkdir(run.c_str(), 0755);
    if (mount("tmpfs", run.c_str(), "tmpfs", MS_NOSUID | MS_NODEV, "mode=0755,size=64m") != 0) die("mount /run");
    mkdirs(run + "/user/0", 0700);
    mkdirs(run + "/lock", 01777);
    const std::string sb = root + "/sandbox";
    mkdir(sb.c_str(), 0755);
    if (mount("tmpfs", sb.c_str(), "tmpfs", MS_NOSUID | MS_NODEV, "mode=0755,size=1m") != 0) die("mount /sandbox");

    for (const Bind &b : o.binds) {
        const std::string dst = root + b.dest;
        struct stat st{};
        if (stat(b.src.c_str(), &st) != 0) { status("note=bind source missing: %s", b.src.c_str()); continue; }
        if (S_ISDIR(st.st_mode)) {
            mkdirs(dst);
        } else {
            mkdirs(dst.substr(0, dst.rfind('/')));
            const int fd = open(dst.c_str(), O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
            if (fd >= 0) close(fd);
        }
        if (!bindMount(b.src, dst, b.rw)) status("note=bind %s failed: %s", b.dest.c_str(), strerror(errno));
    }
    // Make the sandbox tree read-only at its top so programs cannot add files to it.
    mount(nullptr, sb.c_str(), nullptr, MS_REMOUNT | MS_NOSUID | MS_NODEV | MS_RDONLY, "mode=0755");

    for (const std::string &m : mountpoints) status("mountpoint=%s", m.c_str());
}

void pivotInto(const std::string &root)
{
    if (chdir(root.c_str()) != 0) die("chdir new root");
    if (syscall(SYS_pivot_root, ".", ".") != 0) die("pivot_root");
    if (umount2(".", MNT_DETACH) != 0) die("detach old root");
    if (chdir("/") != 0) die("chdir /");
}

// ---------------------------------------------------------------- process

volatile sig_atomic_t g_alarm = 0;
void onAlarm(int) { g_alarm = 1; }

std::string findInPath(const std::string &cmd, const std::vector<std::string> &env)
{
    if (cmd.find('/') != std::string::npos) return cmd;
    std::string path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    for (const std::string &e : env)
        if (e.rfind("PATH=", 0) == 0) path = e.substr(5);
    size_t pos = 0;
    while (pos <= path.size()) {
        size_t next = path.find(':', pos);
        if (next == std::string::npos) next = path.size();
        const std::string cand = path.substr(pos, next - pos) + "/" + cmd;
        if (access(cand.c_str(), X_OK) == 0) return cand;
        pos = next + 1;
    }
    return cmd;
}

[[noreturn]] void execTarget(const Options &o, int outFd)
{
    setsid();
    prctl(PR_SET_PDEATHSIG, SIGKILL);

    const int nullFd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (nullFd >= 0) dup2(nullFd, 0);
    if (outFd >= 0) {
        dup2(outFd, 1);
        dup2(outFd, 2);
    }
    // Close everything else (status fd, inherited descriptors).
    if (syscall(SYS_close_range, 3, ~0U, 0) != 0)
        for (int fd = 3; fd < 4096; ++fd) close(fd);

    rlimit rl{};
    rl = {0, 0};
    setrlimit(RLIMIT_CORE, &rl);
    rl = {o.fsize, o.fsize};
    setrlimit(RLIMIT_FSIZE, &rl);
    rl = {4096, 4096};
    setrlimit(RLIMIT_NOFILE, &rl);
    rl = {2048, 2048};
    setrlimit(RLIMIT_NPROC, &rl);

    std::vector<std::string> env = {
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME=/root", "USER=root", "LOGNAME=root", "SHELL=/bin/sh", "TERM=dumb",
        "LANG=C.UTF-8", "TMPDIR=/tmp", "XDG_RUNTIME_DIR=/run/user/0",
    };
    for (const std::string &e : o.env) {
        const std::string key = e.substr(0, e.find('=') + 1);
        bool replaced = false;
        for (std::string &x : env)
            if (x.rfind(key, 0) == 0) { x = e; replaced = true; }
        if (!replaced) env.push_back(e);
    }
    std::vector<char *> envp;
    for (std::string &e : env) envp.push_back(e.data());
    envp.push_back(nullptr);

    std::vector<std::string> args = o.argv;
    std::vector<char *> argv;
    for (std::string &a : args) argv.push_back(a.data());
    argv.push_back(nullptr);
    const std::string exe = findInPath(o.argv[0], env);

    if (chdir(o.chdir.c_str()) != 0 && chdir("/") != 0) _exit(126);

    dropCapabilities();
    if (!applyLandlockScope() && o.net)
        fprintf(stderr, "pkgscope-sandbox: warning: kernel without Landlock scoping; host abstract sockets are reachable\n");
    if (!installSeccomp()) fprintf(stderr, "pkgscope-sandbox: warning: seccomp filter not installed\n");

    if (!o.marker.empty()) {
        char *mArgv[] = {const_cast<char *>(o.marker.c_str()), nullptr};
        char *mEnv[] = {nullptr};
        execve(o.marker.c_str(), mArgv, mEnv); // expected to fail with ENOENT
    }
    execve(exe.c_str(), argv.data(), envp.data());
    fprintf(stderr, "pkgscope-sandbox: cannot execute %s: %s\n", exe.c_str(), strerror(errno));
    _exit(127);
}

[[noreturn]] void runInit(const Options &o, int outFd)
{
    prctl(PR_SET_PDEATHSIG, SIGKILL);
    setupRoot(o);
    if (sethostname("pkgscope-sandbox", 16) != 0) status("note=sethostname failed");
    if (!o.net) bringUpLoopback();
    status("network=%s", o.net ? "shared" : "isolated");
    pivotInto(o.rootDir);

    const pid_t child = fork();
    if (child < 0) die("fork target");
    if (child == 0) execTarget(o, outFd);
    if (outFd >= 0) close(outFd);
    status("started=1");

    struct sigaction sa{};
    sa.sa_handler = onAlarm;
    sigaction(SIGALRM, &sa, nullptr); // no SA_RESTART: waitpid gets EINTR
    if (o.timeout > 0) alarm(static_cast<unsigned>(o.timeout));

    int mainStatus = -1;
    bool mainDone = false;
    time_t mainExit = 0;
    int bgKilled = 0;
    for (;;) {
        int st = 0;
        const pid_t p = waitpid(-1, &st, mainDone ? WNOHANG : 0);
        if (p == child) {
            mainStatus = st;
            mainDone = true;
            mainExit = time(nullptr);
            continue;
        }
        if (p > 0) continue;
        if (p < 0 && errno == ECHILD) break;
        if (g_alarm) {
            status("timeout=1");
            kill(-1, SIGKILL);
            g_alarm = 0;
            alarm(0);
            continue;
        }
        if (mainDone) {
            if (time(nullptr) - mainExit >= o.grace) {
                // Count and kill whatever is still running in the namespace.
                if (DIR *d = opendir("/proc")) {
                    while (dirent *e = readdir(d))
                        if (atoi(e->d_name) > 1) ++bgKilled;
                    closedir(d);
                }
                kill(-1, SIGKILL);
                while (waitpid(-1, nullptr, 0) > 0) {}
                break;
            }
            usleep(100 * 1000);
        }
    }
    if (bgKilled) status("background_killed=%d", bgKilled);
    if (mainStatus < 0) {
        status("exit=unknown");
        _exit(124);
    }
    if (WIFEXITED(mainStatus)) {
        status("exit=%d", WEXITSTATUS(mainStatus));
        _exit(WEXITSTATUS(mainStatus));
    }
    status("signal=%d", WTERMSIG(mainStatus));
    _exit(128 + WTERMSIG(mainStatus));
}

void usage()
{
    fprintf(stderr, "usage: pkgscope-sandbox --root-dir DIR --upper DIR --work DIR [options] -- CMD [ARGS...]\n");
    _exit(2);
}

bool validDest(const std::string &d)
{
    if (d.empty() || d[0] != '/' || d.find("..") != std::string::npos) return false;
    return d.rfind("/sandbox/", 0) == 0 || d.rfind("/run/", 0) == 0 || d.rfind("/tmp/.X11-unix", 0) == 0;
}

} // namespace

int main(int argc, char **argv)
{
    Options o;
    int i = 1;
    for (; i < argc; ++i) {
        const std::string a = argv[i];
        const auto next = [&]() -> std::string { if (i + 1 >= argc) usage(); return argv[++i]; };
        if (a == "--") { ++i; break; }
        else if (a == "--root-dir") o.rootDir = next();
        else if (a == "--upper") o.upper = next();
        else if (a == "--work") o.work = next();
        else if (a == "--net") o.net = true;
        else if (a == "--chdir") o.chdir = next();
        else if (a == "--setenv") o.env.push_back(next());
        else if (a == "--marker") o.marker = next();
        else if (a == "--status-file") o.statusFile = next();
        else if (a == "--output-file") o.outputFile = next();
        else if (a == "--fsize") o.fsize = strtoull(next().c_str(), nullptr, 10);
        else if (a == "--timeout") o.timeout = atoi(next().c_str());
        else if (a == "--grace") o.grace = atoi(next().c_str());
        else if (a == "--ro-bind" || a == "--rw-bind") {
            Bind b;
            b.rw = a == "--rw-bind";
            b.src = next();
            b.dest = next();
            if (!validDest(b.dest)) { fprintf(stderr, "invalid bind destination %s\n", b.dest.c_str()); return 2; }
            o.binds.push_back(b);
        } else if (a == "--version") { puts("pkgscope-sandbox 1.0"); return 0; }
        else usage();
    }
    for (; i < argc; ++i) o.argv.emplace_back(argv[i]);
    if (o.argv.empty() || o.rootDir.empty() || o.upper.empty() || o.work.empty()) usage();
    if (o.rootDir[0] != '/' || o.upper[0] != '/' || o.work[0] != '/') usage();
    if (geteuid() == 0 && getuid() == 0)
        fprintf(stderr, "pkgscope-sandbox: note: running as real root; isolation still uses a user namespace\n");

    if (!o.statusFile.empty())
        g_statusFd = open(o.statusFile.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0600);
    int outFd = -1;
    if (!o.outputFile.empty()) {
        outFd = open(o.outputFile.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_APPEND | O_NOFOLLOW, 0600);
        if (outFd >= 0) fcntl(outFd, F_SETFD, FD_CLOEXEC); // dup2 in the target clears it
    }

    prctl(PR_SET_PDEATHSIG, SIGKILL);
    prepareUpper(o);
    const uid_t uid = getuid();
    const gid_t gid = getgid();

    int flags = CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWCGROUP;
    if (!o.net) flags |= CLONE_NEWNET;
    if (unshare(flags) != 0) die("unshare (are unprivileged user namespaces enabled?)");

    char map[64];
    writeFile("/proc/self/setgroups", "deny");
    snprintf(map, sizeof map, "0 %u 1", static_cast<unsigned>(uid));
    if (!writeFile("/proc/self/uid_map", map)) die("write uid_map");
    snprintf(map, sizeof map, "0 %u 1", static_cast<unsigned>(gid));
    if (!writeFile("/proc/self/gid_map", map)) die("write gid_map");
    if (setgid(0) != 0 || setuid(0) != 0) die("become namespace root");

    const pid_t init = fork();
    if (init < 0) die("fork init");
    if (init == 0) runInit(o, outFd);
    if (outFd >= 0) close(outFd);

    int st = 0;
    while (waitpid(init, &st, 0) < 0 && errno == EINTR) {}
    if (WIFEXITED(st)) return WEXITSTATUS(st);
    if (WIFSIGNALED(st)) return 128 + WTERMSIG(st);
    return 1;
}
