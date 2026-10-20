# Installation

## Packages

The [latest release](https://github.com/Trendorin/pkgscope/releases/latest) has a package for
Arch Linux, Debian 13+ and Fedora 44+, and an AppImage for any distribution with glibc 2.35+.

```sh
sudo pacman -U ./pkgscope-*-x86_64.pkg.tar.zst     # Arch, CachyOS, Manjaro
sudo apt install ./pkgscope_*_amd64.deb             # Debian, Ubuntu
sudo dnf install ./pkgscope-*.x86_64.rpm            # Fedora
```

The packages pull in `strace` and `squashfs-tools`, load the `overlay` module at boot and, on
Debian and Ubuntu, install the AppArmor profile the sandbox needs on Ubuntu 24.04+.

Check a download against the release's `SHA256SUMS`:

```sh
sha256sum --ignore-missing -c SHA256SUMS
```

## From source

`install.sh` builds the checkout with CMake and installs into `~/.local`. It never uses `sudo`
for the install itself.

| distribution | build dependencies |
|---|---|
| Arch | `base-devel cmake ninja qt6-base libarchive strace squashfs-tools` |
| Debian, Ubuntu | `build-essential cmake ninja-build qt6-base-dev libarchive-dev strace squashfs-tools` |
| Fedora | `gcc-c++ cmake ninja-build qt6-qtbase-devel libarchive-devel strace squashfs-tools` |

```sh
./install.sh                    # interactive: location, window or not, sandbox setup
./install.sh --yes              # no questions, defaults
./install.sh --prefix /opt/pkgscope
./install.sh --no-gui           # pkgscope-cli and the sandbox helper only
./install.sh --setup            # also prepare the system for tracing (asks for your password)
```

If something is missing, the installer stops and prints the command that installs it on your
distribution.

`--setup` does only what this system needs: on Ubuntu 24.04+ it installs an AppArmor profile that
lets the helper create user namespaces, and if `overlay` is not available it loads the module.

## Updating

Pull the new version and run `./install.sh` again. It sees the installed version and offers to
update it in place.

## Removal

```sh
./install.sh --uninstall           # removes exactly the files it installed
./install.sh --uninstall --purge   # also settings and cache
```

The list of installed files is kept in `<prefix>/share/pkgscope/installed-files`. Packages are
removed with your package manager.

## Files

| what | where |
|---|---|
| settings | `~/.config/pkgscope/PkgScope.conf` (the window and `pkgscope-cli` share it) |
| language | **Settings → Language** (English, Russian or follow the system; applies after a restart), or `PKGSCOPE_LANG=ru` for one run |
| sandbox work directories | `~/.cache/pkgscope/work` (removed after each run unless you keep them) |
