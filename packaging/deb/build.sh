#!/usr/bin/env bash
# Builds dist/pkgscope_<version>-1_<arch>.deb from this source tree on Debian or Ubuntu.
#
#   sudo apt-get install build-essential cmake ninja-build dpkg-dev qt6-base-dev libarchive-dev
#   packaging/deb/build.sh
#   sudo apt install ./dist/pkgscope_*.deb
set -euo pipefail

ROOT=$(cd "$(dirname "$(readlink -f "$0")")/../.." && pwd)
cd "$ROOT"
VERSION=$(sed -n 's/^project(PkgScope VERSION \([0-9.]*\).*/\1/p' CMakeLists.txt)
ARCH=$(dpkg --print-architecture)
BUILD=$ROOT/build-deb
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
PKG=$STAGE/pkgscope

cmake -S . -B "$BUILD" -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr -DPKGSCOPE_BUILD_TESTS=ON
cmake --build "$BUILD"
ctest --test-dir "$BUILD" --output-on-failure
DESTDIR=$PKG cmake --install "$BUILD"

# Debian keeps the licence in /usr/share/doc/<package>/copyright.
rm -rf "$PKG/usr/share/licenses"
install -Dm644 LICENSE "$PKG/usr/share/doc/pkgscope/copyright"
# Ubuntu 24.04+ restricts unprivileged user namespaces through AppArmor.
install -Dm644 packaging/apparmor/pkgscope-sandbox "$PKG/etc/apparmor.d/pkgscope-sandbox"

# Shared-library dependencies, the way dh_shlibdeps finds them.
mkdir -p "$STAGE/debian"
printf 'Source: pkgscope\n\nPackage: pkgscope\n' > "$STAGE/debian/control"
SHLIBS=$(cd "$STAGE" && dpkg-shlibdeps -O -e pkgscope/usr/bin/pkgscope -e pkgscope/usr/bin/pkgscope-cli \
    -e pkgscope/usr/libexec/pkgscope/pkgscope-sandbox | sed -n 's/^shlibs:Depends=//p')

install -d "$PKG/DEBIAN"
cat > "$PKG/DEBIAN/control" <<CONTROL
Package: pkgscope
Version: $VERSION-1
Architecture: $ARCH
Maintainer: Trendorin <193045225+Trendorin@users.noreply.github.com>
Installed-Size: $(du -sk "$PKG" | cut -f1)
Depends: $SHLIBS, strace, squashfs-tools
Section: utils
Priority: optional
Homepage: https://github.com/Trendorin/pkgscope
Description: inspect Linux packages before installing them
 PkgScope unpacks deb, rpm, pacman, apk, xbps, Slackware and ipk packages,
 AppImages, Snaps and ELF binaries without installing them, shows what goes
 where, flags risky install scripts, setuid files, rootkit-style libraries and
 network indicators, and can run the installer in a no-root sandbox to record
 every process, file and host it touches.
CONTROL
echo /etc/apparmor.d/pkgscope-sandbox > "$PKG/DEBIAN/conffiles"
cat > "$PKG/DEBIAN/postinst" <<'SCRIPT'
#!/bin/sh
set -e
if [ "$1" = configure ]; then
    if command -v apparmor_parser >/dev/null 2>&1 && [ -d /sys/kernel/security/apparmor ]; then
        apparmor_parser -r -T -W /etc/apparmor.d/pkgscope-sandbox || true
    fi
    modprobe overlay 2>/dev/null || true
fi
SCRIPT
cat > "$PKG/DEBIAN/postrm" <<'SCRIPT'
#!/bin/sh
set -e
if [ "$1" = remove ] && command -v apparmor_parser >/dev/null 2>&1 && [ -d /sys/kernel/security/apparmor ]; then
    apparmor_parser -R /etc/apparmor.d/pkgscope-sandbox 2>/dev/null || true
fi
SCRIPT
chmod 0755 "$PKG/DEBIAN/postinst" "$PKG/DEBIAN/postrm"

mkdir -p dist
OUT=dist/pkgscope_${VERSION}-1_${ARCH}.deb
dpkg-deb --root-owner-group -Zxz --build "$PKG" "$OUT"
echo "$OUT"
