# The sandbox

**Inspect & Trace** (or `pkgscope-cli --trace`) runs the installer and records what it does.

## What runs

For packages it plays the package manager: dpkg `preinst → unpack → postinst`, rpm
`%pre → unpack → %post`, pacman `pre_install → post_install`. AppImages, ELF files and scripts are
started directly, with the extra arguments from the settings.

## How it is isolated

`pkgscope-sandbox` is a small helper without Qt and without setuid. As a fake root it sets up:

- user, mount, PID, IPC, UTS, cgroup and, by default, network namespaces;
- a copy-on-write overlay over `/usr`, `/etc`, `/opt` and `/var`, so nothing on your disk changes;
- a dropped capability bounding set, rlimits and a seccomp filter that blocks module loading,
  `bpf`, `kexec`, mounts, new namespaces, `io_uring` and more;
- on Linux 6.12+, Landlock scoping: no host abstract sockets (X11, D-Bus) and no signals to
  processes outside.

Allowing network or display access in the settings weakens that isolation.

## What you get

The process tree, file activity including sensitive reads (and blocked ones), a filesystem diff,
network connections with DNS, SNI and HTTP hosts, and the files dropped and run during the
install. Runtime findings are marked "runtime".

## If tracing does not start

**Analyze → Check sandbox support** tells what is missing.

| message or system | fix |
|---|---|
| Ubuntu 24.04+ | the Debian package installs the AppArmor profile; from source run `./install.sh --setup` |
| `overlay … read-only`, no overlayfs | `sudo modprobe overlay` (the packages load it at boot) |
| `strace` not found | install `strace` |
| AppImage cannot be unpacked | install `squashfs-tools` |
