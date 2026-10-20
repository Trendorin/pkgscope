# Changelog

All notable changes to PkgScope. The format follows [Keep a Changelog](https://keepachangelog.com/),
and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/Trendorin/pkgscope/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/Trendorin/pkgscope/releases/tag/v1.1.0
[1.0.1]: https://github.com/Trendorin/pkgscope/releases/tag/v1.0.1
[1.0.0]: https://github.com/Trendorin/pkgscope/releases/tag/v1.0.0
