#!/usr/bin/env bash
# PkgScope installer.
#
#   ./install.sh                 interactive install or update (asks a few questions)
#   ./install.sh --yes           no questions: defaults plus the flags below
#   ./install.sh --prefix DIR    install into DIR/bin and DIR/share (default ~/.local)
#   ./install.sh --no-gui        command line only (pkgscope-cli and the sandbox helper)
#   ./install.sh --setup         also prepare the system for tracing (AppArmor, overlay; asks for your password)
#   ./install.sh --uninstall     remove PkgScope (add --purge to delete settings and cache too)
#
# Builds from this source checkout with CMake. Prebuilt packages (Arch, Debian,
# Fedora, AppImage) are on the releases page. Never uses sudo for the install:
# only the optional sandbox setup asks for your password.

set -euo pipefail

# ---- options ------------------------------------------------------------------------

PREFIX="$HOME/.local"
GUI=1
SETUP=ask
ASSUME_YES=0
ACTION=install
PURGE=0

usage() { sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) PREFIX="${2:?--prefix needs a directory}"; shift 2 ;;
        --prefix=*) PREFIX="${1#--prefix=}"; shift ;;
        --no-gui) GUI=0; shift ;;
        --setup) SETUP=yes; shift ;;
        --no-setup) SETUP=no; shift ;;
        -y | --yes) ASSUME_YES=1; shift ;;
        --uninstall) ACTION=uninstall; shift ;;
        --purge) PURGE=1; shift ;;
        -h | --help) usage; exit 0 ;;
        *) printf 'unknown option: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
done

INTERACTIVE=0
if [ "$ASSUME_YES" = 0 ] && [ -t 0 ] && [ -t 1 ]; then INTERACTIVE=1; fi

NAME=PkgScope SLUG=pkgscope TAGLINE="package inspector · sandbox · Linux"
ACCENT_RGB="11;143;122" ACCENT_256=36

# ---- look ---------------------------------------------------------------------------
# Shared by the installers of Engram, PkgScope and Sotto; only the name, tagline,
# accent colour and the build progress line differ.

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    R=$'\e[0m' B=$'\e[1m' D=$'\e[2m' RED=$'\e[31m' GRN=$'\e[32m' YEL=$'\e[33m' CLR=$'\e[K'
    case "${COLORTERM:-}" in
        truecolor | 24bit) ACC=$'\e[38;2;'"${ACCENT_RGB}m" ;;
        *) ACC=$'\e[38;5;'"${ACCENT_256}m" ;;
    esac
else
    R='' B='' D='' RED='' GRN='' YEL='' CLR='' ACC=''
fi
case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in *UTF-8* | *utf8*) UTF=1 ;; *) UTF=0 ;; esac

step() { printf '\n%s%s▸ %s%s\n' "$B" "$ACC" "$1" "$R"; }
ok() { printf '  %s✓%s %s\n' "$GRN" "$R" "$*"; }
warn() { printf '  %s!%s %s\n' "$YEL" "$R" "$*"; }
info() { printf '    %s%s%s\n' "$D" "$*" "$R"; }
die() { printf '\n  %s✗ %s%s\n\n' "$RED" "$*" "$R" >&2; exit 1; }
tilde() { case "$1" in "$HOME"/*) printf '~/%s' "${1#"$HOME"/}" ;; "$HOME") printf '~' ;; *) printf '%s' "$1" ;; esac; }

# Closed input is never taken as an answer: stop before doing anything else.
read_answer() {
    if ! read -r REPLY; then
        printf '\n\n  %sNo answer (input closed) — stopping.%s\n\n' "$YEL" "$R" >&2
        exit 1
    fi
}

# ask_yn "question" y|n → exit status 0 for yes
ask_yn() {
    local q="$1" def="$2" hint ans
    if [ "$INTERACTIVE" = 0 ]; then [ "$def" = y ]; return; fi
    if [ "$def" = y ]; then hint="Y/n"; else hint="y/N"; fi
    printf '  %s?%s %s %s[%s]%s ' "$ACC" "$R" "$q" "$D" "$hint" "$R"
    read_answer
    ans="$(printf '%s' "$REPLY" | tr '[:upper:]' '[:lower:]')"
    case "$ans" in
        "") [ "$def" = y ] ;;
        y* | д*) return 0 ;;
        *) return 1 ;;
    esac
}

# ask_text "question" default → prints the answer
ask_text() {
    local q="$1" def="$2" ans
    if [ "$INTERACTIVE" = 0 ]; then printf '%s' "$def"; return; fi
    printf '  %s?%s %s %s[%s]%s ' "$ACC" "$R" "$q" "$D" "$(tilde "$def")" "$R" >&2
    read_answer
    ans="$REPLY"
    case "$ans" in "~"/*) ans="$HOME/${ans#"~/"}" ;; esac
    printf '%s' "${ans:-$def}"
}

# choose "question" option... → prints the chosen number (1-based)
choose() {
    local q="$1" i=1 ans
    shift
    printf '  %s?%s %s\n' "$ACC" "$R" "$q" >&2
    for opt in "$@"; do printf '    %s%d)%s %s\n' "$B" "$i" "$R" "$opt" >&2; i=$((i + 1)); done
    while true; do
        printf '    %s>%s ' "$ACC" "$R" >&2
        read_answer
        ans="${REPLY:-1}"
        if [ "$ans" -ge 1 ] 2>/dev/null && [ "$ans" -le $# ]; then printf '%s' "$ans"; return; fi
    done
}

banner() {
    local bar='▍' w=48 title="$NAME $1"
    [ "$UTF" = 1 ] || bar='|'
    printf '\n  %s╭%s╮%s\n' "$D" "$(printf '─%.0s' $(seq $w))" "$R"
    printf '  %s│%s  %s%s%s %s%s%s %s%s%s%*s%s│%s\n' "$D" "$R" "$ACC" "$bar" "$R" "$B" "$NAME" "$R" "$D" "$1" "$R" \
        $((w - 4 - ${#title})) "" "$D" "$R"
    printf '  %s│%s  %s%s%s %s%*s%s│%s\n' "$D" "$R" "$ACC" "$bar" "$R" "$TAGLINE" $((w - 4 - ${#TAGLINE})) "" "$D" "$R"
    printf '  %s╰%s╯%s\n' "$D" "$(printf '─%.0s' $(seq $w))" "$R"
}

# spin "label" command... — runs the command with a progress line; output goes to a log.
# progress LOG (defined per project) prints what the build is doing right now.
spin() {
    local label="$1" log status frames='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏' i=0 start=$SECONDS now
    shift
    [ "$UTF" = 1 ] || frames='|/-\|/-\||'
    log="$(mktemp "${TMPDIR:-/tmp}/$SLUG-install.XXXXXX")"
    "$@" >"$log" 2>&1 &
    local pid=$!
    if [ -t 1 ]; then
        while kill -0 "$pid" 2>/dev/null; do
            now="$(progress "$log" 2>/dev/null || true)"
            printf '\r  %s%s%s %s %s%s%ss%s%s' "$ACC" "${frames:i++%10:1}" "$R" "$label" "$D" "${now:+$now · }" "$((SECONDS - start))" "$R" "$CLR"
            sleep 0.12
        done
        printf '\r%s' "$CLR"
    fi
    status=0
    wait "$pid" || status=$?
    if [ "$status" -ne 0 ]; then
        printf '  %s✗%s %s failed. Last lines of the log:\n\n' "$RED" "$R" "$label"
        tail -n 25 "$log" | sed 's/^/    /'
        printf '\n    Full log: %s\n\n' "$log"
        exit 1
    fi
    rm -f "$log"
    local t=$((SECONDS - start))
    ok "$label done in $((t / 60))m $((t % 60))s"
}

# progress for CMake + Ninja/Make builds: "[12/40]" or "[ 30%]"
cmake_progress() {
    grep -oE '^\[ *[0-9]+(/[0-9]+|%)\]' "$1" | tail -1 | tr -d '[] '
}

# Distribution family for package hints: arch, debian, fedora or other.
distro() {
    local id like
    id="$(. /etc/os-release 2>/dev/null && printf '%s' "${ID:-}")"
    like="$(. /etc/os-release 2>/dev/null && printf '%s' "${ID_LIKE:-}")"
    case " $id $like " in
        *" arch "*) printf arch ;;
        *" debian "* | *" ubuntu "*) printf debian ;;
        *" fedora "* | *" rhel "*) printf fedora ;;
        *) printf other ;;
    esac
}

# need_packages "what" arch-pkgs debian-pkgs fedora-pkgs → stops with the right install command
need_packages() {
    local what="$1" cmd
    case "$(distro)" in
        arch) cmd="sudo pacman -S --needed $2" ;;
        debian) cmd="sudo apt install $3" ;;
        fedora) cmd="sudo dnf install $4" ;;
        *) cmd="" ;;
    esac
    printf '\n  %s✗ %s%s\n' "$RED" "$what" "$R" >&2
    [ -n "$cmd" ] && printf '\n    Install them with:\n      %s%s%s\n' "$B" "$cmd" "$R" >&2
    printf '\n    Then run ./install.sh again.\n\n' >&2
    exit 1
}

progress() { cmake_progress "$1"; }

# ---- where things are -----------------------------------------------------------

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "$SRC_DIR/CMakeLists.txt" ] && [ -d "$SRC_DIR/src/core" ] || die "run install.sh from the PkgScope source folder"
VERSION="$(sed -n 's/^project(PkgScope VERSION \([0-9.]*\).*/\1/p' "$SRC_DIR/CMakeLists.txt")"
BUILD_DIR="$SRC_DIR/build"
APPARMOR_PROFILE=/etc/apparmor.d/pkgscope-sandbox

set_paths() {
    case "$PREFIX" in /*) ;; *) PREFIX="$PWD/$PREFIX" ;; esac
    PREFIX="${PREFIX%/}"
    BIN_DIR="$PREFIX/bin"
    HELPER="$PREFIX/libexec/pkgscope/pkgscope-sandbox"
    MANIFEST="$PREFIX/share/pkgscope/installed-files"
}
set_paths

installed_version() {
    if [ -x "$BIN_DIR/pkgscope-cli" ]; then "$BIN_DIR/pkgscope-cli" --version 2>/dev/null | awk '{print $2}'; fi
}

refresh_menus() {
    command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q "$PREFIX/share/applications" 2>/dev/null || true
    command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -qtf "$PREFIX/share/icons/hicolor" 2>/dev/null || true
}

# ---- uninstall --------------------------------------------------------------------------

uninstall() {
    step "Uninstall"
    local manifest="$MANIFEST" f d
    # Installs from 1.0.0 kept the list here.
    [ -f "$manifest" ] || manifest="$PREFIX/share/pkgscope/install_manifest.txt"
    if [ ! -f "$manifest" ]; then
        ok "PkgScope is not installed in $(tilde "$PREFIX")"
        exit 0
    fi
    ask_yn "Remove PkgScope from $(tilde "$PREFIX")?" y || { info "Nothing changed."; exit 0; }
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        case "$f" in "$PREFIX"/*) ;; *) continue ;; esac
        if [ -e "$f" ] || [ -L "$f" ]; then rm -f "$f"; ok "removed $(tilde "$f")"; fi
    done <"$manifest"
    rm -f "$manifest" "$MANIFEST"
    for d in "$PREFIX/libexec/pkgscope" "$PREFIX/share/pkgscope" "$PREFIX/share/licenses/pkgscope" "$PREFIX/lib/modules-load.d"; do
        [ -d "$d" ] && rmdir --ignore-fail-on-non-empty "$d" 2>/dev/null || true
    done
    refresh_menus
    if [ -f "$APPARMOR_PROFILE" ] && grep -q "$PREFIX" "$APPARMOR_PROFILE" 2>/dev/null; then
        if ask_yn "Also remove the AppArmor profile for the sandbox (asks for your password)?" y; then
            sudo apparmor_parser -R "$APPARMOR_PROFILE" 2>/dev/null || true
            sudo rm -f "$APPARMOR_PROFILE" && ok "removed $APPARMOR_PROFILE"
        fi
    fi
    if [ "$PURGE" = 1 ] || { [ "$ASSUME_YES" = 0 ] && ask_yn "Also delete your settings and cache?" n; }; then
        for d in "${XDG_CONFIG_HOME:-$HOME/.config}/pkgscope" "${XDG_CACHE_HOME:-$HOME/.cache}/pkgscope"; do
            if [ -d "$d" ]; then rm -rf "$d"; ok "removed $(tilde "$d")"; fi
        done
    fi
    ok "PkgScope is uninstalled."
}

# ---- checks --------------------------------------------------------------------------------

check_system() {
    step "Checking your system"
    [ "$(uname -s)" = Linux ] || die "PkgScope runs on Linux only"
    ok "Linux $(uname -m)"
    local missing=0 q="" cand
    command -v cmake >/dev/null 2>&1 || missing=1
    command -v c++ >/dev/null 2>&1 || command -v g++ >/dev/null 2>&1 || command -v clang++ >/dev/null 2>&1 || missing=1
    for cand in qmake6 /usr/lib/qt6/bin/qmake /usr/lib64/qt6/bin/qmake qmake-qt6 qmake; do
        if command -v "$cand" >/dev/null 2>&1 && "$cand" -query QT_VERSION 2>/dev/null | grep -q '^6\.'; then q="$cand"; break; fi
    done
    [ -n "$q" ] || missing=1
    [ -e /usr/include/archive.h ] || pkg-config --exists libarchive 2>/dev/null || missing=1
    if [ "$missing" = 1 ]; then
        need_packages "CMake, a C++ compiler, Qt 6 and libarchive are needed to build PkgScope." \
            "base-devel cmake ninja qt6-base libarchive strace squashfs-tools" \
            "build-essential cmake ninja-build qt6-base-dev libarchive-dev strace squashfs-tools" \
            "gcc-c++ cmake ninja-build qt6-qtbase-devel libarchive-devel strace squashfs-tools"
    fi
    ok "CMake $(cmake --version | awk 'NR==1{print $3}') · Qt $("$q" -query QT_VERSION) · libarchive"
    local t absent=()
    for t in strace unsquashfs; do command -v "$t" >/dev/null 2>&1 || absent+=("$t"); done
    if [ ${#absent[@]} -gt 0 ]; then
        warn "$(IFS=,; printf '%s' "${absent[*]}" | sed 's/,/, /g') not found — inspection works, tracing in the sandbox needs them"
        info "strace and squashfs-tools from your distribution"
    fi
}

NEEDS_SETUP=0
check_sandbox() {
    NEEDS_SETUP=0
    if [ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo 0)" = 1 ] &&
        ! grep -qs "$HELPER" "$APPARMOR_PROFILE"; then
        NEEDS_SETUP=1
    fi
    if [ ! -d /sys/module/overlay ] && ! grep -qs overlay /proc/filesystems; then NEEDS_SETUP=1; fi
}

# ---- install --------------------------------------------------------------------------------

build() {
    step "Building"
    local gen=()
    command -v ninja >/dev/null 2>&1 && gen=(-G Ninja)
    [ -f "$BUILD_DIR/CMakeCache.txt" ] && ! grep -q "^CMAKE_INSTALL_PREFIX:PATH=$PREFIX\$" "$BUILD_DIR/CMakeCache.txt" && rm -rf "$BUILD_DIR"
    spin "Configure" cmake -S "$SRC_DIR" -B "$BUILD_DIR" "${gen[@]}" -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX="$PREFIX" -DPKGSCOPE_BUILD_GUI="$([ "$GUI" = 1 ] && echo ON || echo OFF)"
    spin "Release build" cmake --build "$BUILD_DIR" -j "$(nproc 2>/dev/null || echo 2)"
}

install_files() {
    step "Installing into $(tilde "$PREFIX")"
    mkdir -p "$BIN_DIR" "$PREFIX/share/pkgscope" || die "cannot create $BIN_DIR"
    [ -w "$BIN_DIR" ] || die "$(tilde "$BIN_DIR") is not writable — choose another location"
    # A GUI from an earlier install goes away with --no-gui.
    [ "$GUI" = 1 ] || rm -f "$BIN_DIR/pkgscope" "$PREFIX/share/applications/io.github.trendorin.PkgScope.desktop"
    cmake --install "$BUILD_DIR" >/dev/null || die "cmake --install failed"
    local desktop="$PREFIX/share/applications/io.github.trendorin.PkgScope.desktop"
    [ -f "$desktop" ] && sed -i "s|^Exec=pkgscope|Exec=$BIN_DIR/pkgscope|; s|^TryExec=pkgscope|TryExec=$BIN_DIR/pkgscope|" "$desktop"
    { cat "$BUILD_DIR/install_manifest.txt"; printf '\n%s\n' "$MANIFEST"; } | sed '/^$/d' >"$MANIFEST"
    rm -f "$PREFIX/share/pkgscope/install_manifest.txt"
    refresh_menus
    ok "pkgscope-cli$([ "$GUI" = 1 ] && printf ', pkgscope') → $(tilde "$BIN_DIR")"
    ok "sandbox helper → $(tilde "$HELPER")"
    [ "$GUI" = 1 ] && ok "menu entry and icon"
    ok "uninstall manifest"
    if pgrep -x pkgscope >/dev/null 2>&1; then warn "a PkgScope window is open — restart it to use the new version"; fi
}

setup_sandbox() {
    step "Sandbox setup"
    if [ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo 0)" = 1 ]; then
        info "this system restricts user namespaces; an AppArmor profile allows them for the helper only"
        sed "s|^profile pkgscope-sandbox .* flags=|profile pkgscope-sandbox $HELPER flags=|" \
            "$SRC_DIR/packaging/apparmor/pkgscope-sandbox" | sudo tee "$APPARMOR_PROFILE" >/dev/null &&
            sudo apparmor_parser -r "$APPARMOR_PROFILE" && ok "AppArmor profile for $(tilde "$HELPER")" ||
            warn "the AppArmor profile was not installed"
    fi
    if [ ! -d /sys/module/overlay ] && ! grep -qs overlay /proc/filesystems; then
        sudo modprobe overlay && ok "overlay module loaded" || warn "could not load the overlay module"
    fi
}

summary() {
    local on_path=1 c="pkgscope-cli" g="pkgscope"
    case ":$PATH:" in *":$BIN_DIR:"*) ;; *) on_path=0 ;; esac
    if [ "$on_path" = 0 ]; then c="$(tilde "$BIN_DIR")/pkgscope-cli"; g="$(tilde "$BIN_DIR")/pkgscope"; fi
    printf '\n  %s%s✓ PkgScope %s is installed%s\n\n' "$B" "$GRN" "$VERSION" "$R"
    [ "$GUI" = 1 ] && printf '    %-14s %s  %s(or "PkgScope" in your app menu)%s\n' "Open" "$g" "$D" "$R"
    printf '    %-14s %s FILE\n' "Inspect" "$c"
    printf '    %-14s %s --trace FILE\n' "Trace" "$c"
    printf '    %-14s ./install.sh --uninstall\n' "Uninstall"
    if [ "$SETUP" != yes ] && [ "$NEEDS_SETUP" = 1 ]; then
        printf '\n    %sTracing may need a one-time setup on this system:%s ./install.sh --setup\n' "$YEL" "$R"
    fi
    if [ "$on_path" = 0 ]; then
        printf '\n    %s%s is not on your PATH.%s Add it in your shell profile, e.g.\n' "$YEL" "$(tilde "$BIN_DIR")" "$R"
        printf '      export PATH="%s:$PATH"\n' "$BIN_DIR"
    fi
    printf '\n'
}

# ---- main --------------------------------------------------------------------------------------

banner "$VERSION"

if [ "$ACTION" = uninstall ]; then
    uninstall
    exit 0
fi

current="$(installed_version || true)"
if [ -n "$current" ] && [ "$INTERACTIVE" = 1 ]; then
    printf '\n  PkgScope %s is installed in %s.\n' "$current" "$(tilde "$PREFIX")"
    pick="$(choose "What do you want to do?" "Update to $VERSION" "Uninstall" "Quit")"
    case "$pick" in
        2) uninstall; exit 0 ;;
        3) exit 0 ;;
    esac
fi

check_system
check_sandbox

if [ "$INTERACTIVE" = 1 ]; then
    step "A few questions"
    if [ -z "$current" ]; then
        PREFIX="$(ask_text "Install location" "$PREFIX")"
        set_paths
        check_sandbox
    fi
    if [ "$GUI" = 1 ] && ! ask_yn "Install the desktop window (pkgscope)?" y; then GUI=0; fi
    if [ "$SETUP" = ask ] && [ "$NEEDS_SETUP" = 1 ]; then
        info "Tracing needs user namespaces and overlayfs, which this system restricts or lacks."
        if ask_yn "Prepare the system for tracing (asks for your password)?" y; then SETUP=yes; else SETUP=no; fi
    fi
fi
[ "$SETUP" = ask ] && SETUP=no

build
install_files
if [ "$SETUP" = yes ] && [ "$NEEDS_SETUP" = 1 ]; then
    setup_sandbox
elif [ "$SETUP" = yes ]; then
    ok "sandbox: nothing to set up on this system"
fi
summary
