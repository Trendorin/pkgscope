#!/usr/bin/env python3
"""README art for pkgscope in the pixel style of github.com/Trendorin.

    python3 tools/art/build.py                    SVGs, application icon, social preview
    python3 tools/art/build.py --shots DIR        ...and frame the raw screenshots in DIR

Writes into .github/assets/ (and the application icon, see APP_ICONS). Every SVG comes
in -dark and -light variants for <picture>; the "screens" stay dark in both, only their
outer frame changes. Needs rsvg-convert (librsvg) and magick (ImageMagick) for the PNGs.
pixel.py is the profile's 5x7 font and pieces, shared verbatim by every project.
"""
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pixel as P  # noqa: E402
from pixel import (SCREEN, THEMES, Svg, bitmap, esc, label_svg, pixel_rects,  # noqa: E402
                   portrait_svg, screen, spec_svg, text_layout, text_pixels)

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / ".github" / "assets"

# ── Project ──────────────────────────────────────────────────────────────────
NAME, WORDMARK, HOST = "pkgscope", "PKGSCOPE", "linux"
VERSION = re.search(r"project\(PkgScope VERSION ([0-9.]+)", (ROOT / "CMakeLists.txt").read_text())[1]
APP_ICONS = ["resources/icons/pkgscope.svg"]
MARK_ALT = "a package under a magnifying glass"

# Two-tone marks: "#" bright, "+" mid. MARK is the icon, MARK_BIG the header glyph (12 rows).
MARK = """
#############.....
#....+++....#.....
#....+++....#.....
#############.....
#...........#.....
#...........#.....
#.................
#.........#####...
#........##...##..
#.......##.....##.
#.......#.++++..#.
#######.#.......#.
........#.+++...#.
........##.....##.
.........##...##..
..........#####.#.
................##
.................#"""

MARK_BIG = """
##########.......
#...++...#.......
########.........
#......#####.....
#.....##...##....
#.....#.+++.#....
#.....#.....#....
#####.#.++..#....
......##...##....
.......#####.#...
.............##..
..............##."""

LABEL_SLUGS = ["about", "features", "install", "quick-start", "sandbox", "how-it-works", "security", "docs"]

TEXT = {
    "en": {
        "tagline": "Look inside Linux packages before you install",
        "social": "Look inside packages before you install",
        "labels": ["About", "Features", "Install", "Quick start", "Sandbox", "How it works", "Security", "Docs"],
        "spec": [("Version", VERSION), ("Stack", "C++20 · Qt 6 · libarchive"), ("Packages", "deb · rpm · pkg · apk · ipk"),
                 ("Bundles", "AppImage · Snap · ELF"), ("Rules", "100+ heuristics"),
                 ("Sandbox", "userns · overlay · seccomp"), ("Tracing", "strace · fs diff · hosts"),
                 ("Reports", "HTML · JSON · Markdown"), ("License", "MIT")],
        "features": [
            ("formats", "box", "FORMATS", ["deb, rpm, pacman, apk,", "AppImage, Snap, ELF"]),
            ("scripts", "script", "SCRIPTS", ["install scripts with the", "risky lines marked"]),
            ("binaries", "binary", "BINARIES", ["ELF hardening, imports,", "libc hooks, packers"]),
            ("sandbox", "sandbox", "SANDBOX", ["no root: namespaces,", "overlay, seccomp"]),
            ("trace", "tree", "TRACE", ["every process, file and", "host the installer uses"]),
            ("reports", "report", "REPORTS", ["0-100 risk score, HTML,", "JSON, Markdown, CI gate"]),
        ],
        "links": [
            ("download", "download", "DOWNLOAD", "pkg · deb · rpm · AppImage"),
            ("cli", "terminal", "COMMAND LINE", "scripts and CI pipelines"),
            ("security", "sandbox", "SECURITY", "threat model, reporting"),
            ("changelog", "layers", "CHANGELOG", "what changed and when"),
        ],
        "frames": {"overview": "PKGSCOPE · OVERVIEW", "findings": "PKGSCOPE · FINDINGS", "scripts": "PKGSCOPE · SCRIPTS"},
    },
    "ru": {
        "tagline": "Загляните в пакет до установки",
        "social": "Загляните в пакет до установки",
        "labels": ["О проекте", "Возможности", "Установка", "Быстрый старт", "Песочница", "Как устроено",
                   "Безопасность", "Документация"],
        "spec": [("Версия", VERSION), ("Стек", "C++20 · Qt 6 · libarchive"), ("Пакеты", "deb · rpm · pkg · apk · ipk"),
                 ("Образы", "AppImage · Snap · ELF"), ("Правила", "больше 100 эвристик"),
                 ("Изоляция", "userns · overlay · seccomp"), ("Запуск", "strace · diff ФС · хосты"),
                 ("Отчёты", "HTML · JSON · Markdown"), ("Лицензия", "MIT")],
        "features": [
            ("formats", "box", "ФОРМАТЫ", ["deb, rpm, pacman, apk,", "AppImage, Snap, ELF"]),
            ("scripts", "script", "СКРИПТЫ", ["скрипты установки,", "опасные строки отмечены"]),
            ("binaries", "binary", "БИНАРНИКИ", ["защита ELF, импорты,", "подмена libc, упаковщики"]),
            ("sandbox", "sandbox", "ПЕСОЧНИЦА", ["без root: namespaces,", "overlay, seccomp"]),
            ("trace", "tree", "ТРАССИРОВКА", ["все процессы, файлы и", "хосты установщика"]),
            ("reports", "report", "ОТЧЁТЫ", ["риск 0-100, HTML, JSON,", "Markdown, порог для CI"]),
        ],
        "links": [
            ("download", "download", "СКАЧАТЬ", "pkg · deb · rpm · AppImage"),
            ("cli", "terminal", "КОМАНДНАЯ СТРОКА", "скрипты и CI"),
            ("security", "sandbox", "БЕЗОПАСНОСТЬ", "угрозы и как сообщить"),
            ("changelog", "layers", "ИЗМЕНЕНИЯ", "что и когда менялось"),
        ],
        "frames": {"overview": "PKGSCOPE · ОБЗОР", "behaviour": "PKGSCOPE · ПОВЕДЕНИЕ", "scripts": "PKGSCOPE · СКРИПТЫ"},
    },
}

FLOW = {
    "en": {"cols": [[("package", "deb, rpm, ...")],
                    [("static", "parse, rules"), ("sandbox", "run, strace")],
                    [("report", "risk, findings")]],
           "bright": 2,
           "foot": "nothing is installed · the host is never written"},
    "ru": {"cols": [[("пакет", "deb, rpm, ...")],
                    [("статика", "разбор, правила"), ("песочница", "запуск, strace")],
                    [("отчёт", "риск, находки")]],
           "bright": 2,
           "foot": "ничего не устанавливается · система не меняется"},
}


# ── Card icons (20x20, one tone) ──────────────────────────────────────────────
ICONS = {
    "see": """
    .......######.......
    .....##......##.....
    ...##..........##...
    ..#.....####.....#..
    .#.....######.....#.
    #.....###..###.....#
    #.....###..###.....#
    .#.....######.....#.
    ..#.....####.....#..
    ...##..........##...
    .....##......##.....
    .......######.......""",
    "sandbox": """
    ........##........
    ......##..##......
    ....##......##....
    ..##..........##..
    .#..............#.
    .#......##......#.
    .#.....####.....#.
    .#.....####.....#.
    .#......##......#.
    .#......##......#.
    ..#.....##.....#..
    ..#............#..
    ...#..........#...
    ....##......##....
    ......##..##......
    ........##........""",
    "local": """
    ....#..#..#..#....
    ....#..#..#..#....
    ..##############..
    ..#............#..
    ###..########..###
    ..#..#......#..#..
    ..#..#......#..#..
    ###..#......#..###
    ..#..#......#..#..
    ..#..#......#..#..
    ###..########..###
    ..#............#..
    ..##############..
    ....#..#..#..#....
    ....#..#..#..#....""",
    "download": """
    ........####........
    ........####........
    ........####........
    ........####........
    ........####........
    ....############....
    .....##########.....
    ......########......
    .......######.......
    ........####........
    .........##.........
    ....................
    ##................##
    ##................##
    ####################
    ####################""",
    "book": """
    .######....######.
    #......#..#......#
    #.####.#..#.####.#
    #......#..#......#
    #.####.#..#.####.#
    #......#..#......#
    #.####.#..#.####.#
    #......#..#......#
    #.####.#..#.####.#
    #......#..#......#
    #......#..#......#
    .#######..#######.
    ........##........""",
    "layers": """
    ........####........
    ......##....##......
    ....##........##....
    ..##............##..
    ....##........##....
    ..#...##....##...#..
    ..##....####....##..
    ....##........##....
    ..#...##....##...#..
    ..##....####....##..
    ....##........##....
    ......##....##......
    ........####........""",
    "magnifier": """
    ....######......
    ..##......##....
    .#..........#...
    #..####......#..
    #..#.........#..
    #............#..
    #............#..
    #............#..
    .#..........#...
    ..##......###...
    ....######.###..
    ............###.
    .............###
    ..............##""",
    "freeze": """
    .........#.........
    .......#.#.#.......
    ........###........
    ..#......#......#..
    ...#.....#.....#...
    #...#....#....#...#
    .#...#...#...#...#.
    ..#...#..#..#...#..
    ......###.###......
    ###########.#######
    ......###.###......
    ..#...#..#..#...#..
    .#...#...#...#...#.
    #...#....#....#...#
    ...#.....#.....#...
    ..#......#......#..
    ........###........
    .......#.#.#.......
    .........#.........""",
    "chain": """
    ..........######....
    .........#......#...
    ........#..####..#..
    ........#.#....#.#..
    ........#.#....#.#..
    .......####....#.#..
    ......#..#....#..#..
    .....#..#.#..#..#...
    ....#..#...##..#....
    ...#..#...##..#.....
    ..#..#..#.#..#......
    ..#.#....#..#.......
    ..#.#....####.......
    ..#.#....#.#........
    ..#.#....#.#........
    ..#..####..#........
    ...#......#.........
    ....######..........""",
    "wine": """
    ##############
    #............#
    #............#
    .#..........#.
    .#.########.#.
    ..#.######.#..
    ...#......#...
    ....######....
    ......##......
    ......##......
    ......##......
    ......##......
    ......##......
    ......##......
    ...########...
    ..##########..""",
    "agent": """
    ####################
    #..................#
    #..................#
    #..##..............#
    #...##.............#
    #....##............#
    #...##.............#
    #..##....#######...#
    #..................#
    #..................#
    ####################""",
    "box": """
    ......########......
    ....##........##....
    ..##............##..
    ##......####......##
    #.##............##.#
    #...##........##...#
    #.....##....##.....#
    #.......####.......#
    #........##........#
    #........##........#
    #........##........#
    #........##........#
    .##......##......##.
    ...##....##....##...
    .....##..##..##.....
    .......######.......""",
    "script": """
    ##############....
    #............##...
    #.#######....#.#..
    #............####.
    #.##########.....#
    #................#
    ##################
    #.##############.#
    ##################
    #................#
    #.#########......#
    #................#
    #.#######........#
    #................#
    ##################""",
    "binary": """
    .##....#.....#..
    #..#..##....##..
    #..#...#.....#..
    #..#...#.....#..
    .##...###...###.
    ................
    .#.....##....#..
    ##....#..#..##..
    .#....#..#...#..
    .#....#..#...#..
    ###....##...###.""",
    "tree": """
    ######..............
    ######..............
    ..#.................
    ..#.................
    ..#......######.....
    ..########....#.....
    ..#......######.....
    ..#.................
    ..#.................
    ..#......######.....
    ..########....#.....
    .........######.....
    .............#......
    .............#......
    .............######.
    .............#....#.
    .............######.""",
    "report": """
    ##############....
    #............##...
    #............#.#..
    #.#######....####.
    #................#
    #.##########.....#
    #................#
    #.########.......#
    #..........#####.#
    #..........#...#.#
    #.######...#.#.#.#
    #..........#...#.#
    #..........#####.#
    #................#
    ##################""",
    "key": """
    .##################.
    #..................#
    #.################.#
    #.#..............#.#
    #.#..............#.#
    #.#..............#.#
    #.#..#........#..#.#
    #.#..##########..#.#
    #.#..............#.#
    #.################.#
    #..................#
    .##################.""",
    "window": """
    ####################
    #.#.#..............#
    ####################
    #..................#
    #..................#
    #..................#
    #.....########.....#
    #.....#.#.#..#.....#
    #.....########.....#
    #..................#
    ####################""",
    "wave": """
    .........##.........
    .........##.........
    ....##...##.........
    ....##...##...##....
    ....##...##...##....
    ##..##...##...##..##
    ##..##...##...##..##
    ##..##...##...##..##
    ....##...##...##....
    ....##...##...##....
    ....##...##.........
    .........##.........
    .........##.........""",
    "gpu": """
    ##..................
    ####################
    #..................#
    #.######....######.#
    #.#....#....#....#.#
    #.#.##.#....#.##.#.#
    #.#....#....#....#.#
    #.######....######.#
    #..................#
    ####################
    ..#.#.#.#.#.#.#.....""",
    "hash": """
    .....##......##.....
    .....##......##.....
    ####################
    ####################
    .....##......##.....
    .....##......##.....
    .....##......##.....
    ####################
    ####################
    .....##......##.....
    .....##......##.....""",
    "terminal": """
    ####################
    #..................#
    #..................#
    #..##..............#
    #...##.............#
    #....##............#
    #...##.............#
    #..##....#######...#
    #..................#
    #..................#
    ####################""",
}

# ── Engine: the same in every Trendorin project, only the config above differs ──
ICONS.update({"mark": "\n".join(r.replace("+", "#") for r in MARK.split())})


def rows_of(drawing: str) -> list[str]:
    rows = [r.strip() for r in drawing.strip().splitlines() if r.strip()]
    assert len({len(r) for r in rows}) == 1, f"ragged drawing: {rows[0]!r}"
    return rows


def icon_rows(name: str) -> list[str]:
    rows = rows_of(ICONS[name])
    w = len(rows[0])
    assert w <= 20 and len(rows) <= 20, f"icon {name}: bigger than 20x20"
    top, left = (20 - len(rows)) // 2, (20 - w) // 2
    return ["." * 20] * top + ["." * left + r + "." * (20 - w - left) for r in rows] + ["." * 20] * (20 - len(rows) - top)


for _name in ICONS:
    P.LOGOS[_name] = " ".join(icon_rows(_name))
P.LOGOS["heart"] = P.LOGOS["mark"]  # card_svg's fallback
_big = rows_of(MARK_BIG)
assert len(_big) == 12, "MARK_BIG must be 12 rows (the header font height)"
P.BIG_GLYPHS["◆"] = [r.replace("+", "#") for r in _big]
P.BIG_GLYPHS["‿"] = ["."] * 12  # narrow space between the mark and the name


def feature_svg(title, lines, logo, theme, W=380, H=96, gap=8):
    """Feature card: pixel icon, title, two caption lines."""
    s, tx = 2, 74
    for line in lines:
        assert text_layout(line, upper=False)[1] * s <= W - tx - 16, f"feature line too long: {line!r}"
    svg = Svg(W, H + gap, None, f"{title}: {' '.join(lines)}")
    screen(svg, W, H, theme)
    svg.rects(pixel_rects(bitmap(P.LOGOS[logo]), 2, 18, (H - 40) // 2), "hi")
    svg.rects(pixel_rects(text_pixels(title, upper=False)[0], s, tx, 18), "hi")
    for i, line in enumerate(lines):
        svg.rects(pixel_rects(text_pixels(line, upper=False)[0], s, tx, 42 + i * 20), "va")
    return svg


def mark_grid(n=26):
    """The mark inside a detection box, as portrait tones 0-3 (shadow, mid, bright)."""
    rows = rows_of(MARK)
    h, w = len(rows), len(rows[0])
    g = [[0] * n for _ in range(n)]
    ox, oy = (n - w) // 2, (n - h) // 2
    for y, r in enumerate(rows):
        for x, c in enumerate(r):
            if c != ".":
                g[oy + y + 1][ox + x + 1] = 1
    for y, r in enumerate(rows):
        for x, c in enumerate(r):
            if c != ".":
                g[oy + y][ox + x] = 3 if c == "#" else 2
    k = 4  # bracket arm length
    for bx, by, dx, dy in ((0, 0, 1, 1), (n - 1, 0, -1, 1), (0, n - 1, 1, -1), (n - 1, n - 1, -1, -1)):
        for i in range(k):
            g[by][bx + i * dx] = 2
            g[by + i * dy][bx] = 2
    return g


def header(lang, theme, W=764, H=248):
    return P.header_svg("◆‿" + WORDMARK, TEXT[lang]["tagline"], theme, W, H)


def logo_svg():
    """Application icon: the two-tone mark with a one-pixel shadow on a notched dark tile."""
    rows = rows_of(MARK)
    w, h = len(rows[0]), len(rows)
    n = max(w, h) + 6
    ox, oy = (n - w) // 2, (n - h) // 2

    def path(pick, dx=0, dy=0):
        return "".join(f"M{ox + x + dx} {oy + y + dy}h1v1h-1z" for y, r in enumerate(rows)
                       for x, c in enumerate(r) if pick(c))
    tile = f"M2 0h{n - 4}v1h1v1h1v{n - 4}h-1v1h-1v1H2v-1H1v-1H0V2h1V1h1z"
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{n * 8}" height="{n * 8}" viewBox="0 0 {n} {n}" '
            f'shape-rendering="crispEdges"><title>{esc(NAME)}</title>'
            f'<path fill="#0a0a0a" d="{tile}"/>'
            f'<path fill="#262626" d="{path(lambda c: c != ".", 1, 1)}"/>'
            f'<path fill="#8c8c8c" d="{path(lambda c: c == "+")}"/>'
            f'<path fill="#e4e4e4" d="{path(lambda c: c == "#")}"/></svg>\n')


def social_png(png: Path):
    """1280x640 social preview: the header screen at 640x248 rendered 2x, centred on the same black."""
    svg = P.header_svg("◆‿" + WORDMARK, TEXT["en"]["social"], "dark", 640, 248)
    rsvg(str(svg), png, zoom=2)
    subprocess.run(["magick", str(png), "-shave", "4x4", "-background", SCREEN["bg"], "-gravity", "center",
                    "-extent", "1280x640", str(png)], check=True)


def notched_scaled(x, y, w, h, t):
    """notched() with steps of t pixels instead of 2."""
    return [(x + 2 * t, y, w - 4 * t, h), (x + t, y + t, w - 2 * t, h - 2 * t), (x, y + 2 * t, w, h - 4 * t)]


def frame_svg(shot: Path, title: str, right: str, s=5):
    """A dark pixel window around a screenshot: notched frame, title bar in the pixel font."""
    import struct
    with open(shot, "rb") as f:
        head = f.read(24)
    iw, ih = struct.unpack(">II", head[16:24])
    pad, bar = 4 * s, 16 * s
    W, H = iw + 2 * pad, ih + bar + pad
    c = SCREEN
    svg = Svg(W, H, None, title)
    svg.css.append(f".bg{{fill:{c['bg']}}}.fr{{fill:#2a2a2a}}.hi{{fill:{c['hi']}}}.lo{{fill:{c['lo']}}}"
                   f".sb{{fill:{c['sub']}}}.hd{{fill:{c['rule']}}}")
    t = s
    svg.rects(notched_scaled(0, 0, W, H, t), "fr")
    svg.rects(notched_scaled(t, t, W - 2 * t, H - 2 * t, t), "bg")
    ms = max(2, s * 7 // 12 + 1)  # the 12-row mark, about as tall as the 7-row title text
    big = rows_of(MARK_BIG)
    my = (bar - 12 * ms) // 2
    svg.rects(pixel_rects([(x, y) for y, r in enumerate(big) for x, ch in enumerate(r) if ch == "#"], ms, pad, my), "hi")
    svg.rects(pixel_rects([(x, y) for y, r in enumerate(big) for x, ch in enumerate(r) if ch == "+"], ms, pad, my), "lo")
    tx = pad + (len(big[0]) + 3) * ms
    ty = (bar - 7 * s) // 2
    svg.rects(pixel_rects(text_pixels(title)[0], s, tx, ty), "hi")
    rpx, rw = text_pixels(right)
    svg.rects(pixel_rects(rpx, s, W - pad - rw * s, ty), "sb")
    svg.rects([(pad, bar - 2 * s, iw, s)], "hd")
    svg.body.append(f'<image x="{pad}" y="{bar}" width="{iw}" height="{ih}" href="{esc(shot.resolve().as_uri())}"/>')
    return svg


def flow_svg(lang, theme, W=900):
    """How it works: columns of boxes joined left to right, a footnote underneath."""
    f, s = FLOW[lang], 2
    cols = f["cols"]
    tw = lambda t: text_layout(t, upper=False)[1] * s  # noqa: E731
    box_h, pitch, top, pad, side = 62, 78, 26, 18, 28
    widths = [max(max(tw(a), tw(b)) for a, b in col) + 2 * pad for col in cols]
    gap = (W - 2 * side - sum(widths)) // max(len(cols) - 1, 1)
    assert gap >= 40, f"flow too wide for {W}px ({lang})"
    xs = [side]
    for w in widths[:-1]:
        xs.append(xs[-1] + w + gap)
    tallest = max(len(c) for c in cols)
    H = top + tallest * pitch - (pitch - box_h) + 64
    label = " → ".join(" / ".join(a for a, _ in col) for col in cols)
    svg = Svg(W, H, None, label)
    screen(svg, W, H, theme)

    def ys(col):
        block = len(col) * pitch - (pitch - box_h)
        y0 = top + (tallest * pitch - (pitch - box_h) - block) // 2
        return [y0 + i * pitch for i in range(len(col))]

    def arrow(x0, x1, y):
        svg.rects([(x0, y - 1, x1 - x0 - 6, 2)], "sb")
        svg.rects([(x1 - 8 + i, y - 4 + i, 2, 8 - 2 * i) for i in range(4)], "sb")

    for ci, col in enumerate(cols):
        for (title, caption), y in zip(col, ys(col)):
            bright = ci == f.get("bright", -1)
            svg.rects(P.frame_rects(xs[ci], y, widths[ci], box_h), "hi" if bright else "hd")
            svg.rects(pixel_rects(text_pixels(title, upper=False)[0], s, xs[ci] + pad, y + 14), "hi")
            svg.rects(pixel_rects(text_pixels(caption, upper=False)[0], s, xs[ci] + pad, y + 36), "va")
        if ci + 1 < len(cols):
            a, b = [y + box_h // 2 for y in ys(col)], [y + box_h // 2 for y in ys(cols[ci + 1])]
            x0, x1 = xs[ci] + widths[ci], xs[ci + 1]
            if len(a) == 1 and len(b) == 1 and a[0] == b[0]:
                arrow(x0, x1, a[0])
                continue
            mid = x0 + gap // 2
            for y in a:
                svg.rects([(x0, y - 1, mid - x0, 2)], "sb")
            lo, hi = min(a + b), max(a + b)
            svg.rects([(mid - 1, lo - 1, 2, hi - lo + 2)], "sb")
            for y in b:
                arrow(mid, x1, y)
    foot = text_pixels(f["foot"], upper=False)
    assert foot[1] * s <= W - 2 * side, f"flow footnote too long ({lang})"
    svg.rects(pixel_rects(foot[0], s, (W - foot[1] * s) // 2, H - 38), "sb")
    return svg


def rsvg(svg: str, png: Path, zoom=1.0):
    with tempfile.NamedTemporaryFile("w", suffix=".svg", delete=False) as f:
        f.write(svg)
    try:
        subprocess.run(["rsvg-convert", "-z", str(zoom), "-o", str(png), f.name], check=True)
    finally:
        Path(f.name).unlink()


def build(shots: Path | None):
    OUT.mkdir(parents=True, exist_ok=True)
    written: set[str] = set()

    def svg2(name, make):
        for theme in THEMES:
            (OUT / f"{name}-{theme}.svg").write_text(str(make(theme)))
            written.add(f"{name}-{theme}.svg")

    for lang, T in TEXT.items():
        sfx = "" if lang == "en" else f"-{lang}"
        svg2(f"header{sfx}", lambda t: header(lang, t))
        for i, (slug, label) in enumerate(zip(LABEL_SLUGS, T["labels"]), 1):
            svg2(f"label-{slug}{sfx}", lambda t, i=i, label=label: label_svg(label, t, num=i))
        keyw = max(text_layout(k, upper=False)[1] for k, _ in T["spec"]) * 2 + 18
        for _k, v in T["spec"]:
            assert text_layout(v, upper=False)[1] * 2 <= 460 - 48 - keyw, f"spec value wraps: {v!r}"
        height = spec_svg(NAME, HOST, T["spec"], "dark", gap=0).h
        svg2(f"spec{sfx}", lambda t: spec_svg(NAME, HOST, T["spec"], t, H=height))
        if lang == "en":
            svg2("mark", lambda t: portrait_svg(mark_grid(), t, f"{NAME}: {MARK_ALT}", H=height))
        for key, icon, title, lines in T["features"]:
            svg2(f"feature-{key}{sfx}", lambda t, ic=icon, ti=title, li=lines: feature_svg(ti, li, ic, t))
        for key, icon, title, caption in T["links"]:
            svg2(f"link-{key}{sfx}", lambda t, ic=icon, ti=title, ca=caption: P.card_svg(ti, ca, ic, t))
        svg2(f"flow{sfx}", lambda t: flow_svg(lang, t))
    svg2("eof", lambda t: label_svg("EOF", t))

    logo = logo_svg()
    (OUT / "logo.svg").write_text(logo)
    for target in APP_ICONS:
        (ROOT / target).write_text(logo)
    rsvg(logo, OUT / "logo.png", zoom=512 / (8 * (max(len(r) for r in rows_of(MARK)) + 6)))
    social_png(OUT / "social-preview.png")
    written |= {"logo.svg", "logo.png", "social-preview.png"}

    for lang, T in TEXT.items():
        for key, title in T["frames"].items():
            name = f"screenshot-{key}{'' if lang == 'en' else '.' + lang}.png"
            src = shots / f"{key}{'' if lang == 'en' else '.' + lang}.png" if shots else None
            if src and src.exists():
                rsvg(str(frame_svg(src, title, f"{NAME} {VERSION}")), OUT / name)
            if (OUT / name).exists():
                written.add(name)

    unknown = P.UNKNOWN - {"◆", "‿"}
    if unknown:
        print("glyphs missing from the pixel font:", " ".join(sorted(unknown)), file=sys.stderr)
    generated = re.compile(r"(header|label|spec|mark|feature|link|eof|flow|screenshot)[-.\w]*\.(svg|png)$")
    stale = sorted(f.name for f in OUT.iterdir() if generated.match(f.name) and f.name not in written)
    for name in stale:
        (OUT / name).unlink()
    print(f"{len(written)} files in {OUT.relative_to(ROOT)}" + (f", removed: {', '.join(stale)}" if stale else ""))


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--shots", type=Path, help="folder with raw screenshots to frame")
    for tool in ("rsvg-convert", "magick"):
        if not shutil.which(tool):
            sys.exit(f"{tool} is needed (librsvg, ImageMagick)")
    build(ap.parse_args().shots)
