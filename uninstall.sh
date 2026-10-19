#!/usr/bin/env bash
# PkgScope uninstaller — removes exactly the files recorded at install time,
# then prunes the empty directories it leaves behind. Leaves user settings
# (~/.config/pkgscope) and the cache unless --purge is given.
#
#   ./uninstall.sh                 # remove from /usr/local
#   ./uninstall.sh --prefix ~/.local
#   ./uninstall.sh --purge         # also remove settings and cache
set -euo pipefail

PREFIX="/usr/local"
PURGE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2;;
    --prefix=*) PREFIX="${1#*=}"; shift;;
    --purge) PURGE=1; shift;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "unknown option: $1" >&2; exit 2;;
  esac
done

msg() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }

MANIFEST="$PREFIX/share/pkgscope/install_manifest.txt"
SUDO=""
if [[ ! -w "$PREFIX" && "$(id -u)" != 0 ]]; then
  command -v sudo >/dev/null && SUDO="sudo"
fi

remove_known() {
  local f
  # Remove files listed in the manifest (and the manifest/dirs afterwards).
  while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    [[ -e "$f" || -L "$f" ]] && $SUDO rm -f "$f" && echo "  removed $f"
  done < "$1"
}

if [[ -f "$MANIFEST" ]]; then
  msg "Removing files recorded in the install manifest"
  remove_known "$MANIFEST"
  $SUDO rm -f "$MANIFEST"
else
  msg "No manifest found; removing the standard install paths"
  for f in \
    "$PREFIX/bin/pkgscope" \
    "$PREFIX/bin/pkgscope-cli" \
    "$PREFIX/lib/pkgscope/pkgscope-sandbox" \
    "$PREFIX/libexec/pkgscope/pkgscope-sandbox" \
    "$PREFIX/lib/modules-load.d/pkgscope.conf" \
    "$PREFIX/share/applications/io.github.trendorin.PkgScope.desktop" \
    "$PREFIX/share/metainfo/io.github.trendorin.PkgScope.metainfo.xml" \
    "$PREFIX/share/icons/hicolor/scalable/apps/io.github.trendorin.PkgScope.svg" \
    "$PREFIX/share/licenses/pkgscope/LICENSE"; do
    [[ -e "$f" || -L "$f" ]] && $SUDO rm -f "$f" && echo "  removed $f"
  done
fi

# prune now-empty directories we own
for d in "$PREFIX/lib/pkgscope" "$PREFIX/libexec/pkgscope" "$PREFIX/share/pkgscope" "$PREFIX/share/licenses/pkgscope"; do
  [[ -d "$d" ]] && $SUDO rmdir --ignore-fail-on-non-empty "$d" 2>/dev/null || true
done

command -v update-desktop-database >/dev/null && $SUDO update-desktop-database "$PREFIX/share/applications" 2>/dev/null || true
command -v gtk-update-icon-cache >/dev/null && $SUDO gtk-update-icon-cache -q "$PREFIX/share/icons/hicolor" 2>/dev/null || true

if [[ $PURGE == 1 ]]; then
  msg "Purging user settings and cache"
  rm -rf "${XDG_CONFIG_HOME:-$HOME/.config}/pkgscope"
  rm -rf "${XDG_CACHE_HOME:-$HOME/.cache}/pkgscope"
fi

msg "PkgScope removed."
[[ $PURGE == 0 ]] && echo "note: settings kept in ~/.config/pkgscope (use --purge to remove)." || true
