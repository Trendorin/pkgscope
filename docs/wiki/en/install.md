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

## AppImage

```sh
chmod +x PkgScope-*-x86_64.AppImage
./PkgScope-*-x86_64.AppImage              # the window
./PkgScope-*-x86_64.AppImage --cli FILE   # the command line
```

It carries its own `strace` and `unsquashfs`, so inspecting and tracing work without installing
anything. Two systems need a one-time step, which `--setup-sandbox` does (it asks for your
password; `--remove-sandbox` undoes it):

- Ubuntu 24.04+ lets only programs with an AppArmor profile create user namespaces. A profile
  for a file inside the AppImage or in your home would let any program you run replace that file
  and get the same permission, so the helper is copied to
  `/usr/local/libexec/pkgscope/pkgscope-sandbox` (owned by root) and the profile names that copy.
- If the `overlay` module is not loaded, it is loaded now and at every boot.

Check a download against the release's `SHA256SUMS`:

```sh
sha256sum --ignore-missing -c SHA256SUMS
```

## From source

`install.sh` builds the checkout with CMake and installs into `~/.local`. PkgScope itself goes
in without `sudo`; the installer asks for it only to install missing distribution packages and for
`--setup`. It needs Qt 6.4 or newer (Debian 12, Ubuntu 24.04, Fedora 38 and later); on older
systems use the AppImage.

| distribution | packages the installer offers to install |
|---|---|
| Arch | `base-devel cmake ninja qt6-base libarchive strace squashfs-tools` |
| Debian, Ubuntu | `build-essential cmake ninja-build qt6-base-dev libarchive-dev strace squashfs-tools` |
| Fedora | `gcc-c++ cmake ninja-build qt6-qtbase-devel libarchive-devel strace squashfs-tools` |
| openSUSE | `gcc-c++ cmake ninja qt6-base-devel libarchive-devel strace squashfs` |

```sh
./install.sh                    # interactive: location, window or not, sandbox setup
./install.sh --yes              # no questions, defaults
./install.sh --prefix /opt/pkgscope
./install.sh --no-gui           # pkgscope-cli and the sandbox helper only
./install.sh --setup            # also prepare the system for tracing (asks for your password)
./install.sh --no-packages      # never install packages, only name the missing ones
```

If something is missing, the installer names it and offers to install it (the default answer is
yes, also with `--yes`). Without a terminal and without password-less `sudo` it prints the command
instead. The build tools are required; without `strace` and `unsquashfs` PkgScope still inspects
packages but cannot trace or unpack AppImages.

`--setup` does only what this system needs. On Ubuntu 24.04+ it copies the helper to
`/usr/local/libexec/pkgscope/pkgscope-sandbox` (owned by root, so no program of yours can replace
it) and installs the AppArmor profile `pkgscope-sandbox-local` for that copy; PkgScope uses the
copy whenever AppArmor restricts user namespaces. If `overlay` is not available it loads the
module and adds `/etc/modules-load.d/pkgscope.conf`. An update offers to refresh the copy when the
helper changed; `--uninstall` offers to remove all of it.

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
