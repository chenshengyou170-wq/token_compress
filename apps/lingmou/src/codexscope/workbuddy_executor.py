"""Narrow child-process executor for authorized WorkBuddy actions."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .workbuddy_actions import WorkBuddyActionError, execute_action_payload

try:
    import sqlite3  # type: ignore[import-not-found]
except (ImportError, ModuleNotFoundError):  # pragma: no cover - platform dependent
    import pysqlite3 as sqlite3  # type: ignore[import-not-found,no-redef]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="codexscope-workbuddy-executor")
    parser.add_argument("--db", required=True, type=Path)
    parser.add_argument("--action-id", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = execute_action_payload(args.db, args.action_id)
    except (OSError, sqlite3.Error, WorkBuddyActionError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0
if __name__ == "__main__":
    raise SystemExit(main())
