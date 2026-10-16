"""Prepare existing artwork, fonts and tokenizer tables when building an app.

This build step downloads public tokenizer tables, never model weights or model
responses. It is not invoked by the desktop application at runtime.
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path


desktop = Path(__file__).resolve().parents[1]
root = desktop.parent
cache = desktop / "dist" / "tokenizer_cache"
cache.mkdir(parents=True, exist_ok=True)
os.environ["TIKTOKEN_CACHE_DIR"] = str(cache)

import tiktoken

for encoding in ("cl100k_base", "o200k_base", "p50k_base", "r50k_base"):
    tiktoken.get_encoding(encoding)

fonts = desktop / "ui" / "fonts"
fonts.mkdir(parents=True, exist_ok=True)
for weight in ("Regular", "SemiBold"):
    source = root / "web" / "node_modules" / "@ibm" / "plex-sans-sc" / "fonts" / "complete" / "woff2" / "hinted" / f"IBMPlexSansSC-{weight}.woff2"
    shutil.copy2(source, fonts / source.name)
shutil.copy2(root / "src" / "codexscope" / "workbench_dist" / "fonts" / "IBM-Plex-OFL.txt", fonts / "IBM-Plex-OFL.txt")

if sys.platform == "win32":
    from PIL import Image
    with Image.open(desktop / "assets" / "icon.png") as icon:
        icon.convert("RGBA").save(desktop / "assets" / "icon.ico", format="ICO", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])

print("Desktop fonts, icon and tokenizer tables prepared.")
