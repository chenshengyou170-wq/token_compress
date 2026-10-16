"""PyInstaller entry point for the self-contained CodexScope desktop sidecar."""

import sys
import os
from pathlib import Path


def main():
    if getattr(sys, "frozen", False):
        os.environ["TIKTOKEN_CACHE_DIR"] = str(Path(sys._MEIPASS) / "tokenizer_cache")
    # The portable companion must not import the Linux monitor/CLI graph.
    if sys.argv[1:2] == ["compression-companion"]:
        from codexscope.desktop_companion import main as companion_main
        return companion_main(sys.argv[2:])
    if sys.argv[1:2] == ["context"]:
        from codexscope.context_tools import main as context_main
        return context_main(sys.argv[2:])
    if sys.platform == "win32":
        print("Windows 本地模式请通过灵眸桌面端的 Token 压缩入口启动。", file=sys.stderr)
        return 2
    from codexscope.cli import main as cli_main
    return cli_main()


if __name__ == "__main__":
    raise SystemExit(main())
