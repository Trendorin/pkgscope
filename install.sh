#!/usr/bin/env bash
# PkgScope installer — builds from source and installs cleanly, or installs a
# prebuilt tree. Records every installed path so uninstall.sh removes exactly
# what was added, nothing more.
#
#   ./install.sh                 # build + install to /usr/local (uses sudo for the copy)
#   ./install.sh --prefix ~/.local   # per-user install, no root needed
#   ./install.sh --uninstall     # remove a previous install
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="/usr/local"
DO_UNINSTALL=0
JOBS="$(nproc 2>/dev/null || echo 2)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2;;
    --prefix=*) PREFIX="${1#*=}"; shift;;
    --uninstall) DO_UNINSTALL=1; shift;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "unknown option: $1" >&2; exit 2;;
  esac
done

msg()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

MANIFEST_DIR="$PREFIX/share/pkgscope"
MANIFEST="$MANIFEST_DIR/install_manifest.txt"

# sudo only when the prefix is not writable by us
SUDO=""
need_root() { [[ ! -w "$(dirname "$PREFIX")" && ! -w "$PREFIX" ]] 2>/dev/null; }
if need_root && [[ "$(id -u)" != 0 ]]; then
  command -v sudo >/dev/null && SUDO="sudo" || die "need write access to $PREFIX (run as root or use --prefix ~/.local)"
fi

if [[ $DO_UNINSTALL == 1 ]]; then
  exec "$here/uninstall.sh" --prefix "$PREFIX"
fi

command -v cmake >/dev/null || die "cmake is required"
for t in bwrap unsquashfs strace; do
  command -v "$t" >/dev/null || echo "note: '$t' not found — behaviour tracing needs it (see README for the package name)." >&2
done

msg "Configuring (prefix: $PREFIX)"
GEN="Unix Makefiles"; command -v ninja >/dev/null && GEN="Ninja"
cmake -B "$here/build" -S "$here" -G "$GEN" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$PREFIX"

msg "Building"
cmake --build "$here/build" -j "$JOBS"

msg "Installing"
$SUDO cmake --install "$here/build"

# cmake writes build/install_manifest.txt; keep a copy for the uninstaller.
if [[ -f "$here/build/install_manifest.txt" ]]; then
  $SUDO install -d "$MANIFEST_DIR"
  $SUDO cp "$here/build/install_manifest.txt" "$MANIFEST"
fi

# refresh desktop / icon caches (best effort)
command -v update-desktop-database >/dev/null && $SUDO update-desktop-database "$PREFIX/share/applications" 2>/dev/null || true
command -v gtk-update-icon-cache >/dev/null && $SUDO gtk-update-icon-cache -q "$PREFIX/share/icons/hicolor" 2>/dev/null || true

msg "Done. Launch 'pkgscope' from your menu, or run 'pkgscope-cli --help'."
[[ "$PREFIX" == "$HOME"* ]] && echo "note: ensure $PREFIX/bin is in your PATH." || true
