# Formats and checks

## What it reads

| | |
|---|---|
| Debian | `.deb`, `.ipk` (OpenWrt) |
| RPM | `.rpm`, read by its own bounds-checked header parser |
| Arch | `.pkg.tar.zst`, `.xz`, `.gz` with `.INSTALL` and `.MTREE` |
| Others | Alpine `.apk`, Void `.xbps`, Slackware `.txz` and `.tgz` with `doinst.sh` |
| Bundles | AppImage (type 1 and 2), Snap, SquashFS |
| Single files | ELF executables and libraries, kernel modules, shell, Python and Perl scripts, makeself installers |

## What it shows

| | |
|---|---|
| File tree | install path, mode, owner, size, SHA-256; setuid, world-writable, hidden and device files highlighted |
| Scripts | preinst and postinst, `%pre` and `%post`, `.INSTALL`, `doinst.sh`, with the lines that triggered a rule |
| ELF | PIE, NX, RELRO, stack protector, FORTIFY, RPATH and RUNPATH, notable imports, packers, libraries that re-implement libc (`LD_PRELOAD` rootkits) |
| Integrity | every file against the package's own checksums (`md5sums`, RPM digests, `.MTREE`) |
| Rules | more than 100: download-and-run, reverse shells, cron, systemd, PAM and udev persistence, credential theft, miners, anti-forensics, destructive commands |
| Indicators | URLs, IPs, domains and `.onion` addresses; documentation links are filtered out |

## Severity and risk

Each finding is Critical, High, Medium, Low or Info, with an explanation and the evidence (the
file and line, or the runtime event). The 0–100 risk score and the verdict at the top summarise
them; the Overview lists the findings of Medium and above.

A clean result means nothing obvious was found. It does not prove that a file is safe.
