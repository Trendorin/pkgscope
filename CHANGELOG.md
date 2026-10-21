# Changelog

All notable changes to PkgScope. The format follows [Keep a Changelog](https://keepachangelog.com/),
and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- The AppImage carries its own `strace` and `unsquashfs` (built from the release tarballs, checked
  against pinned SHA-256 sums), so tracing and unpacking AppImages and Snaps work without installing
  anything. `--setup-sandbox` prepares Ubuntu 24.04+ and systems without overlayfs for tracing,
  `--remove-sandbox` undoes it.
- `install.sh` offers to install missing build tools, `strace` and `squashfs-tools` with pacman, apt,
  dnf or zypper (openSUSE is new) instead of stopping with a command to copy. `--no-packages` turns
  that off. It now says up front when Qt is older than 6.4 and points to the AppImage.
- CI installs PkgScope with `install.sh` on bare Arch, Debian 12 and 13, Ubuntu 24.04, Fedora 44 and
  openSUSE Tumbleweed images, runs it and uninstalls it.

### Security
- Compressed data inside packages is decoded only by the libraries linked into libarchive. Before,
  lrzip, lzop or grzip data made libarchive run those programs on the untrusted input when they
  were installed.
- On Ubuntu 24.04+, `install.sh --setup` gave the AppArmor user-namespace permission to the helper in
  `~/.local`, which any program of the user could replace. It now installs a root-owned copy in
  `/usr/local/libexec/pkgscope` with its own profile (`pkgscope-sandbox-local`), removes the old
  profile, and PkgScope uses that copy whenever AppArmor restricts user namespaces.
- Package names, versions, file names and traced command lines are no longer read as rich text in
  the window header, message boxes and tooltips, so a package cannot restyle what the window shows.
- Builds add `-fstack-clash-protection`, `-fcf-protection` and `_GLIBCXX_ASSERTIONS`.

### Fixed
- The 1.1.1 AppImage held world-writable copyright files, and PkgScope rated its own binaries
  Critical because a rule title contained the path it looks for. Inspecting the AppImage with
  itself now gives "No major concerns"; the release workflow checks both.
- Builds with Qt 6.4 (Debian 12, Ubuntu 24.04) failed; the minimum Qt is now stated as 6.4.
- With `overlay` missing, `install.sh --setup` also adds `/etc/modules-load.d/pkgscope.conf`, so the
  module is there after a reboot too.

## [1.1.1] — 2026-10-20

### Fixed
- The AppImage did not start on Wayland: it lacked Qt's Wayland shell plugins (the build tool that packs it
  was pinned to a release that does not deploy them). The release workflow now checks that they are inside.
  The distribution packages were not affected.


## [1.1.0] — 2026-10-20

### Added
- **Language** (Settings → Appearance → Language): follow the system, English or Russian; applies at the
  next start (`PKGSCOPE_LANG=ru` for one run). Menus, tabs, tables, settings and messages are
  translated. The texts of the analysis rules (finding titles and explanations) stay English.

### Fixed
- The **Open** dialog could not select scripts: its filter listed only packages. It now has Packages,
  AppImages, Scripts and installers (`.sh`, `.bash`, `.py`, `.run`, …), Libraries and kernel modules,
  and All files.


## [1.0.1] — 2026-10-20

Security and correctness fixes after an independent review.

### Security
- Slackware and other tar packages: package metadata is moved out of the install tree without
  following symlinks. A package could replace `install/` by a link to a host directory and make
  the move carry files from there into the workspace.
- A tracing run copies archive symlinks as symlinks. Before, a link such as `loot -> ~/.ssh/id_rsa`
  put the host file into the sandbox as a regular file where installer code could read it.
- The sandbox binds `/sys` without the host's submounts. They kept writable flags, so a delegated
  cgroup's `cgroup.kill` could be written from inside.
- Hardlinks count against the extraction size limit like any other file.
- Release builds pin every GitHub Action to a commit and check the AppImage tools against a SHA-256.
- The installer no longer interpolates the prefix into `sed` programs, quotes the desktop entry path
  and refuses uninstall manifest entries that leave the prefix.

### Fixed
- Behaviour traces no longer drop the main program's activity: the helper's own calls before the
  marker used to hide the program from the parser.
- `pkgscope-cli` returns a failure when `--trace` could not complete (4) or a requested report could not
  be written (1); before, both looked like success to CI.


## [1.0.0] — 2026-10-20

First release.

### Inspection
- Formats: deb and ipk, rpm (own bounds-checked header reader), pacman (`.pkg.tar.zst/xz/gz` with
  `.INSTALL` and `.MTREE`), apk, xbps, Slackware, AppImage (type 1 and 2), Snap, SquashFS, ELF
  executables and libraries, kernel modules, scripts and makeself installers.
- File tree with install paths, modes, owners and SHA-256; setuid/setgid, world-writable, hidden
  and device files highlighted.
- Install scripts with the lines that triggered a rule marked; more than 100 heuristics with a
  severity, an explanation and the evidence; a 0–100 risk score with a plain verdict.
- ELF analysis: PIE, NX, RELRO, stack protector, FORTIFY, RPATH/RUNPATH, notable imports,
  packers, and shared libraries that re-implement libc functions (`LD_PRELOAD` rootkits).
- Integrity check against the package's own checksums; URLs, IPs, domains and `.onion` addresses.

### Behaviour tracing
- Runs the install sequence of the package manager as a fake root in user, mount, PID, IPC, UTS,
  cgroup and (by default) network namespaces, over a copy-on-write overlay of the system, with a
  dropped capability bounding set, rlimits and a seccomp filter. No root, no setuid helper.
- On Linux 6.12 and newer the program is also confined with Landlock scoping: it cannot reach the
  host's abstract Unix sockets (X11, D-Bus) or signal processes outside, even with network access.
- Process tree, file activity, sensitive reads (including blocked attempts), a filesystem diff,
  network connections and DNS/SNI/HTTP hosts, and analysis of files dropped during the install.

### Reports and front-ends
- HTML, JSON and Markdown reports; `pkgscope-cli` with `--fail-on` for CI.
- Qt 6 window that follows the system theme, with explicit light and dark themes.

### Packaging and quality
- Packages for Arch Linux, Debian and Fedora, and an AppImage; each one is built in a clean
  container of its distribution, installed and started there before a release.
- The packages load `overlay` at boot (`modules-load.d`); the Debian package installs the
  AppArmor profile that Ubuntu 24.04+ needs for unprivileged user namespaces.
- Interactive installer (`install.sh`) for source checkouts, into `~/.local` without root, with
  `--yes`, `--prefix`, `--no-gui`, `--setup` (AppArmor profile and overlay when the system needs
  them), `--uninstall` and `--purge`. It removes exactly the files it installed.
- The window and `pkgscope-cli` share one settings file.
- Tests for hostile archives (path traversal, symlink and hardlink escapes, absolute paths,
  setuid bits, device nodes, size limits) and a libFuzzer harness for every parser, run under
  AddressSanitizer and UndefinedBehaviorSanitizer in CI.

[Unreleased]: https://github.com/Trendorin/pkgscope/compare/v1.1.1...HEAD
[1.1.1]: https://github.com/Trendorin/pkgscope/releases/tag/v1.1.1
[1.1.0]: https://github.com/Trendorin/pkgscope/releases/tag/v1.1.0
[1.0.1]: https://github.com/Trendorin/pkgscope/releases/tag/v1.0.1
[1.0.0]: https://github.com/Trendorin/pkgscope/releases/tag/v1.0.0
