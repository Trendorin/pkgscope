#!/usr/bin/env bash
# Builds dist/PkgScope-<version>-x86_64.AppImage with Qt, libarchive, strace and unsquashfs inside,
# so inspecting AppImages/Snaps and tracing work without installing anything else.
#
# Build on Ubuntu 22.04 (glibc 2.35): the AppImage then runs on that and anything
# newer (Debian 12+, Fedora 36+, Arch). The release workflow uses GitHub's
# ubuntu-22.04 runner.
#
#   packaging/appimage/build.sh --deps   install build dependencies (apt, needs sudo) and Qt
#   packaging/appimage/build.sh          build the AppImage
#
# Work files (Qt, tools, build tree) go to $PKGSCOPE_APPIMAGE_WORK, default build-appimage/.
set -euo pipefail

QT_VERSION=6.8.3
# Bundled helpers, built from release tarballs checked against these SHA-256 sums.
STRACE_VERSION=7.2
STRACE_SHA256=4bde6246926890dcee824f6e6ac42a06752f47d77e5097d86e3c0d6d4b709fe5
SQUASHFS_VERSION=4.7.5
SQUASHFS_SHA256=547b7b7f4d2e44bf91b6fc554664850c69563701deab9fd9cd7e21f694c88ea6
ROOT=$(cd "$(dirname "$(readlink -f "$0")")/../.." && pwd)
WORK=${PKGSCOPE_APPIMAGE_WORK:-$ROOT/build-appimage}
QT_DIR=$WORK/qt/$QT_VERSION/gcc_64
ID=io.github.trendorin.PkgScope

if [[ ${1:-} == --deps ]]; then
    sudo apt-get update -q
    sudo apt-get install -yq --no-install-recommends \
        build-essential gcc-12 g++-12 cmake ninja-build pkg-config patchelf file curl ca-certificates python3-pip \
        xz-utils zlib1g-dev liblzma-dev libzstd-dev liblz4-dev liblzo2-dev \
        libarchive-dev libgl-dev libegl-dev libxkbcommon-dev libxkbcommon-x11-0 libfontconfig1 libfreetype6 \
        libdbus-1-3 libglib2.0-0 libwayland-dev libx11-xcb1 libxcb-cursor0 libxcb-icccm4 libxcb-image0 \
        libxcb-keysyms1 libxcb-randr0 libxcb-render-util0 libxcb-shape0 libxcb-xinerama0 libxcb-xkb1 \
        libxcb-xfixes0 libxrender1 libsm6 libice6
    python3 -m pip install --user --quiet aqtinstall
    python3 -m aqt install-qt linux desktop "$QT_VERSION" linux_gcc_64 -O "$WORK/qt"
    exit 0
fi

[[ -x $QT_DIR/bin/qmake ]] || { echo "Qt $QT_VERSION not found in $QT_DIR: run $0 --deps first" >&2; exit 1; }
VERSION=$(sed -n 's/^project(PkgScope VERSION \([0-9.]*\).*/\1/p' "$ROOT/CMakeLists.txt")
export CC=gcc-12 CXX=g++-12

# Build tools are checked against a pinned SHA-256 before they run. The plugin-qt release 1-alpha-20250213-1
# does not deploy Qt's Wayland shell plugins (the AppImage would not start on Wayland), the "continuous"
# build does; if upstream replaces a file the check fails, so re-pin it after testing the AppImage.
fetch_tool() { # URL SHA256 DIR
    local url=$1 sha=$2 file=$3/${1##*/}
    if [[ -x $file ]] && echo "$sha  $file" | sha256sum -c --status; then return; fi
    curl -fsSL --retry 3 -o "$file" "$url"
    echo "$sha  $file" | sha256sum -c --status || { echo "checksum mismatch for $url" >&2; rm -f "$file"; exit 1; }
    chmod +x "$file"
}

# fetch_source URL SHA256 → unpacks the tarball into $WORK/src and prints the directory
fetch_source() {
    local url=$1 sha=$2 file=$WORK/src/${1##*/}
    mkdir -p "$WORK/src"
    if ! { [[ -f $file ]] && echo "$sha  $file" | sha256sum -c --status; }; then
        curl -fsSL --retry 3 -o "$file" "$url"
        echo "$sha  $file" | sha256sum -c --status || { echo "checksum mismatch for $url" >&2; rm -f "$file"; exit 1; }
    fi
    local dir
    dir=$WORK/src/$(tar -tf "$file" | sed -n 1p | cut -d/ -f1)
    rm -rf "$dir"
    tar -xf "$file" -C "$WORK/src"
    printf '%s' "$dir"
}

# strace records the sandboxed run, unsquashfs unpacks AppImages and Snaps. PkgScope looks for both
# next to its own binary first, so the AppImage never depends on the host having them.
build_helpers() {
    local src out=$WORK/helpers
    rm -rf "$out"
    mkdir -p "$out"
    src=$(fetch_source "https://github.com/strace/strace/releases/download/v$STRACE_VERSION/strace-$STRACE_VERSION.tar.xz" "$STRACE_SHA256")
    (cd "$src" && ./configure --prefix=/usr --disable-mpers --disable-gcc-Werror \
        --without-libunwind --without-libdw --without-libselinux >/dev/null && make -j"$(nproc)" >/dev/null)
    install -m755 "$src/src/strace" "$out/strace"
    src=$(fetch_source "https://github.com/plougher/squashfs-tools/releases/download/$SQUASHFS_VERSION/squashfs-tools-$SQUASHFS_VERSION.tar.gz" "$SQUASHFS_SHA256")
    make -C "$src/squashfs-tools" -j"$(nproc)" unsquashfs \
        GZIP_SUPPORT=1 XZ_SUPPORT=1 LZO_SUPPORT=1 LZ4_SUPPORT=1 ZSTD_SUPPORT=1 >/dev/null
    install -m755 "$src/squashfs-tools/unsquashfs" "$out/unsquashfs"
    "$out/strace" -V | sed -n 1p
    "$out/unsquashfs" -v 2>&1 | sed -n 1p
}

mkdir -p "$WORK/tools" "$ROOT/dist"
fetch_tool https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage \
    8aea8da0f7f7039d2a2cecb14657d752a222a5e1d3825caeef186c82f751cdd1 "$WORK/tools"
fetch_tool https://github.com/linuxdeploy/linuxdeploy-plugin-qt/releases/download/continuous/linuxdeploy-plugin-qt-x86_64.AppImage \
    cfc1055b2b9dbc08412b579f20990b7b41a17b61beaa5847dc9477c96c9e9617 "$WORK/tools"

build_helpers
rm -rf "$WORK/build" "$WORK/AppDir"
cmake -S "$ROOT" -B "$WORK/build" -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr \
    -DCMAKE_PREFIX_PATH="$QT_DIR" -DPKGSCOPE_BUILD_TESTS=ON
cmake --build "$WORK/build"
ctest --test-dir "$WORK/build" --output-on-failure
DESTDIR=$WORK/AppDir cmake --install "$WORK/build"
rm -rf "$WORK/AppDir/usr/lib/modules-load.d"   # a system setting, not part of a portable app
install -m755 "$WORK/helpers/strace" "$WORK/helpers/unsquashfs" "$WORK/AppDir/usr/bin/"
install -Dm644 "$ROOT/packaging/apparmor/pkgscope-sandbox-local" "$WORK/AppDir/usr/share/pkgscope/apparmor/pkgscope-sandbox-local"
install -Dm644 "$ROOT/packaging/modules-load.d/pkgscope.conf" "$WORK/AppDir/usr/share/pkgscope/modules-load.d/pkgscope.conf"

# `PkgScope.AppImage --cli FILE` runs the command-line front-end. `--setup-sandbox` prepares a
# system that restricts user namespaces (Ubuntu 24.04+) or lacks overlayfs; `--remove-sandbox`
# undoes it. Both ask for the password through sudo.
cat > "$WORK/AppRun" <<'APPRUN'
#!/bin/sh
HERE=$(dirname "$(readlink -f "$0")")
HELPER=/usr/local/libexec/pkgscope/pkgscope-sandbox
PROFILE=/etc/apparmor.d/pkgscope-sandbox-local
MODULES=/etc/modules-load.d/pkgscope.conf
asroot() { if [ "$(id -u)" = 0 ]; then "$@"; else sudo "$@"; fi; }
case "$1" in
--cli)
    shift
    exec "$HERE/usr/bin/pkgscope-cli" "$@"
    ;;
--setup-sandbox)
    set -e
    # Only a root-owned copy may carry the AppArmor permission: the AppImage itself is replaceable.
    asroot install -D -o root -g root -m 755 "$HERE/usr/libexec/pkgscope/pkgscope-sandbox" "$HELPER"
    echo "sandbox helper → $HELPER"
    if [ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null)" = 1 ]; then
        asroot install -D -o root -g root -m 644 "$HERE/usr/share/pkgscope/apparmor/pkgscope-sandbox-local" "$PROFILE"
        asroot apparmor_parser -r "$PROFILE"
        echo "AppArmor profile → $PROFILE"
    fi
    if ! grep -qs overlay /proc/filesystems; then
        asroot install -D -o root -g root -m 644 "$HERE/usr/share/pkgscope/modules-load.d/pkgscope.conf" "$MODULES"
        asroot modprobe overlay || true
        echo "overlay module → $MODULES"
    fi
    echo "The sandbox is ready."
    exit 0
    ;;
--remove-sandbox)
    [ -f "$PROFILE" ] && { asroot apparmor_parser -R "$PROFILE" 2>/dev/null || true; asroot rm -f "$PROFILE"; }
    asroot rm -f "$HELPER" "$MODULES"
    asroot rmdir /usr/local/libexec/pkgscope 2>/dev/null || true
    echo "Removed the sandbox setup."
    exit 0
    ;;
esac
exec "$HERE/usr/bin/pkgscope" "$@"
APPRUN
chmod +x "$WORK/AppRun"

export APPIMAGE_EXTRACT_AND_RUN=1 QMAKE=$QT_DIR/bin/qmake LD_LIBRARY_PATH=$QT_DIR/lib
export EXTRA_PLATFORM_PLUGINS="libqwayland-generic.so" LDAI_COMP=zstd
export LDAI_OUTPUT=$ROOT/dist/PkgScope-$VERSION-x86_64.AppImage
rm -f "$LDAI_OUTPUT"
cd "$WORK"
./tools/linuxdeploy-x86_64.AppImage --appdir AppDir \
    --executable AppDir/usr/bin/pkgscope \
    --executable AppDir/usr/bin/pkgscope-cli \
    --executable AppDir/usr/bin/strace \
    --executable AppDir/usr/bin/unsquashfs \
    --desktop-file AppDir/usr/share/applications/$ID.desktop \
    --icon-file AppDir/usr/share/icons/hicolor/scalable/apps/$ID.svg \
    --custom-apprun AppRun \
    --plugin qt
# linuxdeploy left the copyright files of bundled libraries world-writable (0777 in 1.1.1). Fix the
# modes, then pack without deploying those files again.
find AppDir -type f -perm /022 -exec chmod go-w {} +
DISABLE_COPYRIGHT_FILES_DEPLOYMENT=1 ./tools/linuxdeploy-x86_64.AppImage --appdir AppDir --output appimage
echo "$LDAI_OUTPUT"
