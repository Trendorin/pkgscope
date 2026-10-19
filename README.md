<div align="center">

[![English](https://img.shields.io/badge/English-e4e4e4?style=for-the-badge)](README.md)
[![Русский](https://img.shields.io/badge/%D0%A0%D1%83%D1%81%D1%81%D0%BA%D0%B8%D0%B9-0a0a0a?style=for-the-badge)](README.ru.md)

<picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/header-dark.svg"><img src=".github/assets/header-light.svg" alt="PKGSCOPE: look inside Linux packages before you install"></picture>

**Look inside Linux packages, AppImages and binaries before you install them.**<br>
See what goes where, which scripts run as root, and what an installer really does, traced in a no-root sandbox.

[![release](https://img.shields.io/badge/release-v1.0.0-e4e4e4?style=flat-square&labelColor=0a0a0a)](https://github.com/Trendorin/pkgscope/releases/latest) [![license](https://img.shields.io/badge/license-MIT-e4e4e4?style=flat-square&labelColor=0a0a0a)](LICENSE) ![Qt](https://img.shields.io/badge/Qt-6-e4e4e4?style=flat-square&labelColor=0a0a0a) ![root](https://img.shields.io/badge/root-not_needed-e4e4e4?style=flat-square&labelColor=0a0a0a)<br>
[![packages](https://img.shields.io/badge/packages-pkg_%C2%B7_deb_%C2%B7_rpm_%C2%B7_AppImage-e4e4e4?style=flat-square&labelColor=0a0a0a)](#install) [![formats](https://img.shields.io/badge/formats-deb_%C2%B7_rpm_%C2%B7_pkg_%C2%B7_apk_%C2%B7_AppImage_%C2%B7_Snap_%C2%B7_ELF-e4e4e4?style=flat-square&labelColor=0a0a0a)](#features)

<img src=".github/assets/screenshot-overview.png" width="100%" alt="PkgScope with a suspicious demo package: risk 100 of 100, findings by severity, file and package details">

[![download](https://img.shields.io/badge/download-latest_release-e4e4e4?style=for-the-badge&labelColor=0a0a0a)](https://github.com/Trendorin/pkgscope/releases/latest)
[![install](https://img.shields.io/badge/install-4_ways-0a0a0a?style=for-the-badge&labelColor=0a0a0a)](#install)
[![cli](https://img.shields.io/badge/cli-and_CI-0a0a0a?style=for-the-badge&labelColor=0a0a0a)](#docs)

</div>

<a id="about"></a>

<div align="center">

<picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/label-about-dark.svg"><img src=".github/assets/label-about-light.svg" alt="01 / About"></picture>

</div>

PkgScope unpacks a package without installing it, builds a tree of *what goes where*, flags
suspicious components and explains why they matter. It can also run the installer inside a
throwaway sandbox and record every file it touches and every host it contacts. Your system is
never modified, and nothing is left behind.

<div align="center">

<picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/mark-dark.svg"><img src=".github/assets/mark-light.svg" alt="The PkgScope mark: a package under a magnifying glass"></picture> <picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/spec-dark.svg"><img src=".github/assets/spec-light.svg" alt="pkgscope@linux: version, stack, packages, bundles, rules, sandbox, tracing, reports, license"></picture>

</div>

<a id="features"></a>

<div align="center">

<picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/label-features-dark.svg"><img src=".github/assets/label-features-light.svg" alt="02 / Features"></picture>

</div>

<div align="center">

<picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/feature-formats-dark.svg"><img src=".github/assets/feature-formats-light.svg" alt="Formats: deb, rpm, pacman, apk, AppImage, Snap, ELF"></picture> <picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/feature-scripts-dark.svg"><img src=".github/assets/feature-scripts-light.svg" alt="Scripts: install scripts with the risky lines marked"></picture>
<picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/feature-binaries-dark.svg"><img src=".github/assets/feature-binaries-light.svg" alt="Binaries: ELF hardening, imports, libc hooks, packers"></picture> <picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/feature-sandbox-dark.svg"><img src=".github/assets/feature-sandbox-light.svg" alt="Sandbox: no root, namespaces, overlay, seccomp"></picture>
<picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/feature-trace-dark.svg"><img src=".github/assets/feature-trace-light.svg" alt="Trace: every process, file and host the installer uses"></picture> <picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/feature-reports-dark.svg"><img src=".github/assets/feature-reports-light.svg" alt="Reports: risk score, HTML, JSON, Markdown, CI gate"></picture>

</div>

<details>
<summary><b>All formats and checks</b></summary>

| | |
|---|---|
| **Debian** | `.deb`, `.ipk` (OpenWrt) |
| **RPM** | `.rpm`, read by its own bounds-checked header parser |
| **Arch** | `.pkg.tar.zst` / `.xz` / `.gz` with `.INSTALL` and `.MTREE` |
| **Others** | Alpine `.apk`, Void `.xbps`, Slackware `.txz` / `.tgz` with `doinst.sh` |
| **Bundles** | AppImage (type 1 and 2), Snap, SquashFS |
| **Single files** | ELF executables and libraries, kernel modules, shell / Python / Perl scripts, makeself installers |
| **File tree** | install path, mode, owner, size, SHA-256; setuid, world-writable, hidden and device files highlighted |
| **Scripts** | preinst / postinst, `%pre` / `%post`, `.INSTALL`, `doinst.sh` with the lines that triggered a rule |
| **ELF** | PIE, NX, RELRO, canary, FORTIFY, RPATH / RUNPATH, notable imports, packers, libraries that re-implement libc (`LD_PRELOAD` rootkits) |
| **Integrity** | every file against the package's own checksums (`md5sums`, RPM digests, `.MTREE`) |
| **Heuristics** | more than 100 rules: download-and-run, reverse shells, cron / systemd / PAM / udev persistence, credential theft, miners, anti-forensics, destructive commands |
| **Indicators** | URLs, IPs, domains and `.onion` addresses, documentation links filtered out |

</details>

<a id="install"></a>

<div align="center">

<picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/label-install-dark.svg"><img src=".github/assets/label-install-light.svg" alt="03 / Install"></picture>

</div>

| your system | file from the [latest release](https://github.com/Trendorin/pkgscope/releases/latest) |
|---|---|
| **Arch Linux**, CachyOS, Manjaro | `pkgscope-1.0.0-1-x86_64.pkg.tar.zst` |
| **Debian 13** and newer | `pkgscope_1.0.0-1_amd64.deb` |
| **Fedora 44** and newer | `pkgscope-1.0.0-1.fc44.x86_64.rpm` |
| **any distribution** with glibc 2.35+ | `PkgScope-1.0.0-x86_64.AppImage`, nothing to install |

```sh
sudo pacman -U ./pkgscope-1.0.0-1-x86_64.pkg.tar.zst       # Arch
sudo apt install ./pkgscope_1.0.0-1_amd64.deb               # Debian
sudo dnf install ./pkgscope-1.0.0-1.fc44.x86_64.rpm       # Fedora
chmod +x PkgScope-1.0.0-x86_64.AppImage && ./PkgScope-1.0.0-x86_64.AppImage
```

Each package is built in a clean container of its distribution, installed and started there
before it is published. Check downloads with `sha256sum --ignore-missing -c SHA256SUMS`.

`./PkgScope-*.AppImage --cli FILE` runs the command line. Tracing needs `strace` and
`squashfs-tools` from your distribution; the packages pull them in.

<details>
<summary><b>Build from source</b></summary>

Needs CMake 3.19+, a C++20 compiler, Qt 6 and libarchive development files; tracing also needs
`strace` and `squashfs-tools` at run time.

```sh
git clone https://github.com/Trendorin/pkgscope && cd pkgscope
./install.sh                     # build + install to /usr/local
./install.sh --prefix ~/.local   # per user, no root
./uninstall.sh                   # removes exactly what was installed
```

</details>

<a id="quick-start"></a>

<div align="center">

<picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/label-quick-start-dark.svg"><img src=".github/assets/label-quick-start-light.svg" alt="04 / Quick start"></picture>

</div>

Open a file (or drop it on the window) and press **Inspect**. **Inspect & Trace** also runs the
installer in the sandbox. Every finding shows its severity, an explanation and the evidence.

<div align="center">

<img src=".github/assets/screenshot-findings.png" width="49%" alt="Findings sorted by severity, with the explanation and evidence of the selected one"> <img src=".github/assets/screenshot-scripts.png" width="49%" alt="The postinst script with the lines that triggered rules highlighted">

</div>

<a id="sandbox"></a>

<div align="center">

<picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/label-sandbox-dark.svg"><img src=".github/assets/label-sandbox-light.svg" alt="05 / Sandbox"></picture>

</div>

**Inspect & Trace** simulates the package manager (dpkg `preinst → unpack → postinst`, rpm
`%pre → unpack → %post`, pacman `pre_install → post_install`) as a fake root inside:

- user, mount, PID, IPC, UTS, cgroup and (by default) network namespaces: no root, no setuid helper;
- a **copy-on-write overlay** over `/usr`, `/etc`, `/opt`, `/var`, so nothing on your disk changes;
- a dropped capability bounding set, rlimits and a **seccomp** filter (module loading, `bpf`,
  `kexec`, mounts, new namespaces, `io_uring` and more are blocked);
- on Linux 6.12+, **Landlock** scoping: no host abstract sockets (X11, D-Bus), no signals outside.

The report shows the process tree, file activity with sensitive reads (also blocked ones), a
filesystem diff, network connections with DNS / SNI / HTTP hosts, and files dropped and run
during the install.

| if tracing does not start | |
|---|---|
| Ubuntu 24.04+ | the Debian package installs the AppArmor profile; from source: `sudo install -Dm644 packaging/apparmor/pkgscope-sandbox /etc/apparmor.d/` and `sudo apparmor_parser -r /etc/apparmor.d/pkgscope-sandbox` |
| `overlay … read-only` | `sudo modprobe overlay` (the packages load it at boot) |
| anything else | **Analyze → Check sandbox support** tells what is missing |

<a id="how-it-works"></a>

<div align="center">

<picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/label-how-it-works-dark.svg"><img src=".github/assets/label-how-it-works-light.svg" alt="06 / How it works"></picture>

</div>

<div align="center">

<picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/flow-dark.svg"><img src=".github/assets/flow-light.svg" alt="A package goes through static analysis and the sandbox into one report"></picture>

</div>

```
src/core      no UI: format detection, ELF and RPM parsers, libarchive extraction that refuses
              traversal and symlink escapes, rules, strace parser, the sandbox orchestrator
src/sandbox   pkgscope-sandbox: a small Qt-free, non-setuid helper (namespaces, overlay, seccomp)
src/gui       Qt 6 Widgets window          src/cli_main.cpp   the same core, headless
```

<a id="security"></a>

<div align="center">

<picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/label-security-dark.svg"><img src=".github/assets/label-security-light.svg" alt="07 / Security"></picture>

</div>

PkgScope reads hostile files, so it is built for that: static analysis never executes the
input; every parser is bounds-checked and has a libFuzzer harness that CI runs under
AddressSanitizer and UndefinedBehaviorSanitizer; extraction refuses path traversal, absolute
paths, symlink and hardlink escapes and strips setuid bits and device nodes (tested with crafted
archives); the sandbox helper is not setuid and drops everything before it runs the target.

A clean result means *nothing obvious was found*, not that a file is safe: one static pass and
one sandboxed run cannot prove that. Report vulnerabilities privately, see [SECURITY.md](SECURITY.md).

<a id="docs"></a>

<div align="center">

<picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/label-docs-dark.svg"><img src=".github/assets/label-docs-light.svg" alt="08 / Docs"></picture>

</div>

<div align="center">

<a href="https://github.com/Trendorin/pkgscope/releases/latest"><picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/link-download-dark.svg"><img src=".github/assets/link-download-light.svg" alt="Download: pkg, deb, rpm, AppImage"></picture></a> <a href="#docs"><picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/link-cli-dark.svg"><img src=".github/assets/link-cli-light.svg" alt="Command line: scripts and CI"></picture></a>
<a href="SECURITY.md"><picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/link-security-dark.svg"><img src=".github/assets/link-security-light.svg" alt="Security: threat model, reporting"></picture></a> <a href="CHANGELOG.md"><picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/link-changelog-dark.svg"><img src=".github/assets/link-changelog-light.svg" alt="Changelog: what changed and when"></picture></a>

</div>

### Command line

```sh
pkgscope-cli FILE                                # static inspection
pkgscope-cli --trace FILE                        # also run it in the sandbox
pkgscope-cli --trace --allow-network FILE
pkgscope-cli FILE --json out.json --html out.html --md out.md
pkgscope-cli --trace --fail-on high FILE         # exit code 3 on a High finding (CI)
```

See also [CONTRIBUTING.md](CONTRIBUTING.md) · [SECURITY.md](SECURITY.md) · [CHANGELOG.md](CHANGELOG.md).

<div align="center">

<picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/eof-dark.svg"><img src=".github/assets/eof-light.svg" alt="EOF"></picture>

<img src=".github/assets/logo.svg" width="40" alt=""><br>
<sub>MIT · made by <a href="https://github.com/Trendorin">Trendorin</a></sub>

</div>
