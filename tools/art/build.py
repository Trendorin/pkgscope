#!/usr/bin/env python3
"""README art: the flow diagram, the application icon (from logo.svg)
and the social preview, in English and Russian, light and dark.

    python3 tools/art/build.py

Writes into .github/assets/. Needs fonttools, uharfbuzz and rsvg-convert; engine.py
explains the details.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from engine import Flow, Node, build  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]

build(
    ROOT, "PkgScope", ("#0b8f7a", "#3dd9b0"),
    tagline={
        "en": "See inside Linux packages before you install them",
        "ru": "Загляните внутрь Linux-пакета до установки",
    },
    flows={
        "en": Flow([[Node("Package", "deb · rpm · AppImage")],
                    [Node("Static analysis", "files · scripts · ELF"), Node("Sandbox trace", "optional, no root")],
                    [Node("Findings", "severity · evidence", accent=True)],
                    [Node("Report", "window · JSON · HTML")]]),
        "ru": Flow([[Node("Пакет", "deb · rpm · AppImage")],
                    [Node("Статический анализ", "файлы · скрипты · ELF"), Node("Трассировка", "по желанию, без root")],
                    [Node("Находки", "уровень · доказательства", accent=True)],
                    [Node("Отчёт", "окно · JSON · HTML")]]),
    },
    flow_alt={
        "en": "A package goes through static analysis and an optional sandbox trace; findings become a report",
        "ru": "Пакет проходит статический анализ и, по желанию, трассировку в песочнице; находки собираются в отчёт",
    },
    app_icons=["resources/icons/pkgscope.svg"],
)
