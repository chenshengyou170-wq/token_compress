from pathlib import Path
import sys

from PyInstaller.utils.hooks import collect_data_files, collect_submodules


root = Path(SPECPATH).resolve().parent
datas = [
    (source, destination)
    for source, destination in collect_data_files("codexscope")
    if not source.endswith(".bak")
]
windows = sys.platform == "win32"
cache = root / "desktop" / "dist" / "tokenizer_cache"
if not cache.is_dir() or not any(cache.iterdir()):
    raise RuntimeError("Tokenizer assets missing; run desktop/scripts/build-backend.mjs through npm.")
datas.append((str(cache), "tokenizer_cache"))
hiddenimports = sorted(
    set(
        ([
            "codexscope.monitor",
            "codexscope.workbench_cmd",
            "codexscope.workbench_controller",
            "codexscope.workbench_server",
            "codexscope.workbench_store",
        ] if not windows else [])
        + ["codexscope.desktop_companion", "codexscope.desktop_connection", "codexscope.context_tools",
           "codexscope.unified_compression", "codexscope.full_compression",
           "codexscope.skill_catalog_compression", "codexscope.session_compression",
           "codexscope.tool_output_cleanup", "tomlkit", "tiktoken_ext.openai_public"]
        + collect_submodules("token_compression")
        + collect_submodules("uvicorn")
        + collect_submodules("websockets")
    )
)

a = Analysis(
    [str(root / "desktop" / "backend_entry.py")],
    pathex=[str(root / "src")],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "codexscope.hidden_token_estimator",
        "codexscope.palace_lite",
        "codexscope.palace_rt",
        "joblib",
        "numpy",
        "scipy",
        "sklearn",
    ] + (["codexscope.cli", "codexscope.monitor", "codexscope.gateway", "codexscope.workbench_cmd",
          "codexscope.workbench_controller", "codexscope.workbench_server", "fcntl", "termios"] if windows else []),
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="lingmou-backend",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="lingmou-backend",
)
