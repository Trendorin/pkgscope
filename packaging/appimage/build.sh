#!/usr/bin/env bash
# Builds dist/PkgScope-<version>-x86_64.AppImage with Qt and libarchive inside.
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
ROOT=$(cd "$(dirname "$(readlink -f "$0")")/../.." && pwd)
WORK=${PKGSCOPE_APPIMAGE_WORK:-$ROOT/build-appimage}
QT_DIR=$WORK/qt/$QT_VERSION/gcc_64
ID=io.github.trendorin.PkgScope

if [[ ${1:-} == --deps ]]; then
    sudo apt-get update -q
    sudo apt-get install -yq --no-install-recommends \
        build-essential gcc-12 g++-12 cmake ninja-build pkg-config patchelf file curl ca-certificates python3-pip \
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

mkdir -p "$WORK/tools" "$ROOT/dist"
for t in linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage \
         linuxdeploy/linuxdeploy-plugin-qt/releases/download/continuous/linuxdeploy-plugin-qt-x86_64.AppImage; do
    [[ -x $WORK/tools/${t##*/} ]] && continue
    curl -fsSL --retry 3 -o "$WORK/tools/${t##*/}" "https://github.com/$t"
    chmod +x "$WORK/tools/${t##*/}"
done

rm -rf "$WORK/build" "$WORK/AppDir"
cmake -S "$ROOT" -B "$WORK/build" -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr \
    -DCMAKE_PREFIX_PATH="$QT_DIR" -DPKGSCOPE_BUILD_TESTS=ON
cmake --build "$WORK/build"
ctest --test-dir "$WORK/build" --output-on-failure
DESTDIR=$WORK/AppDir cmake --install "$WORK/build"
rm -rf "$WORK/AppDir/usr/lib/modules-load.d"   # a system setting, not part of a portable app

# `PkgScope.AppImage --cli FILE` runs the command-line front-end.
cat > "$WORK/AppRun" <<'APPRUN'
#!/bin/sh
HERE=$(dirname "$(readlink -f "$0")")
if [ "$1" = --cli ]; then
    shift
    exec "$HERE/usr/bin/pkgscope-cli" "$@"
fi
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
    --desktop-file AppDir/usr/share/applications/$ID.desktop \
    --icon-file AppDir/usr/share/icons/hicolor/scalable/apps/$ID.svg \
    --custom-apprun AppRun \
    --plugin qt --output appimage
echo "$LDAI_OUTPUT"
