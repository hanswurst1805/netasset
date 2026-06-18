#!/usr/bin/env python3
"""
Erzeugt docs/handbuch.html aus docs/handbuch.md.

Übernimmt das CSS unverändert aus der bestehenden handbuch.html (Single Source
of Truth fürs Styling) und rendert Markdown mit TOC-Sidebar.

Aufruf:  python scripts/build_handbuch.py
"""

from __future__ import annotations

import re
from pathlib import Path

import markdown

DOCS = Path(__file__).resolve().parent.parent / "docs"
MD = DOCS / "handbuch.md"
HTML = DOCS / "handbuch.html"
TITLE = "DRUCKER – Benutzer- und Betriebshandbuch"


def main() -> None:
    text = MD.read_text(encoding="utf-8")

    # CSS aus der vorhandenen HTML übernehmen
    existing = HTML.read_text(encoding="utf-8") if HTML.exists() else ""
    m = re.search(r"<style>.*?</style>", existing, re.DOTALL)
    style = m.group(0) if m else "<style></style>"

    md = markdown.Markdown(extensions=["fenced_code", "tables", "toc"])
    body = md.convert(text)
    toc = md.toc  # <div class="toc">…</div>

    out = f"""<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{TITLE}</title>
{style}
</head>
<body>
<nav id="toc">
<h2>Inhaltsverzeichnis</h2>
{toc}</nav>
<main>
{body}
</main>
</body>
</html>
"""
    HTML.write_text(out, encoding="utf-8")
    print(f"geschrieben: {HTML}")


if __name__ == "__main__":
    main()
