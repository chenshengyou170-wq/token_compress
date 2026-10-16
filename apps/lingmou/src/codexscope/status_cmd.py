"""CLI helpers for live session status (real-time token + activity)."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Mapping, Sequence

from .monitor import MonitorError, active_monitor_path, read_active_monitor
from .storage import json_load


class StatusError(RuntimeError):
    """Live status is unavailable."""


def _tcp_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 0 <= port <= 65_535:
        raise argparse.ArgumentTypeError("port must be between 0 and 65535")
    return port


def resolve_live_status_path(
    *,
    run_dir: Path | None = None,
    status_file: Path | None = None,
) -> Path:
    if status_file is not None:
        return status_file.expanduser().resolve()
    if run_dir is not None:
        return (run_dir.expanduser().resolve() / "live_status.json")
    try:
        registry = read_active_monitor()
    except MonitorError as exc:
        raise StatusError(str(exc)) from exc
    root = registry.get("run_dir")
    if not root:
        raise StatusError("active monitor registry has no run_dir")
    return Path(str(root)).expanduser().resolve() / "live_status.json"


def load_live_status(path: Path) -> dict[str, Any]:
    path = path.expanduser().resolve()
    if not path.is_file():
        raise StatusError(
            f"live status file not found: {path}\n"
            "Start `codexscope monitor` and use Codex through `codexscope attach` "
            "so token usage events can populate live_status.json."
        )
    try:
        data = json_load(path)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise StatusError(f"cannot read live status: {exc}") from exc
    if not isinstance(data, dict):
        raise StatusError(f"invalid live status payload: {path}")
    return data


def format_status_text(data: Mapping[str, Any], *, verbose: bool = False) -> str:
    """Default: one short line with total tokens. ``verbose`` adds activity detail."""

    if verbose:
        line = data.get("status_line_verbose") or data.get("status_line")
        if isinstance(line, str) and line.strip():
            return line

    inflight = data.get("inflight_token_estimate")
    if isinstance(inflight, Mapping) and inflight.get("active"):
        line = data.get("status_line")
        if isinstance(line, str) and line.strip():
            return line

    usage = data.get("token_usage") if isinstance(data.get("token_usage"), dict) else None
    total = usage.get("total") if isinstance(usage, dict) else None
    if isinstance(total, dict):
        from .live_status import format_tokens_simple

        try:
            normalized = {
                "total_tokens": int(total.get("total_tokens", total.get("totalTokens"))),
                "input_tokens": int(total.get("input_tokens", total.get("inputTokens"))),
                "output_tokens": int(
                    total.get("output_tokens", total.get("outputTokens"))
                ),
            }
            return format_tokens_simple(normalized)
        except (TypeError, ValueError):
            pass

    line = data.get("status_line")
    if isinstance(line, str) and line.strip():
        return line
    return "tokens: n/a"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="codexscope status",
        description=(
            "Show how many tokens the active Codex monitor session has used. "
            "Default output is a single short line."
        ),
    )
    parser.add_argument(
        "--run-dir",
        type=Path,
        default=None,
        help="CodexScope run directory containing live_status.json",
    )
    parser.add_argument(
        "--status-file",
        type=Path,
        default=None,
        help="explicit path to live_status.json",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the raw live_status.json object",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="also show activity / turn details",
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="refresh until interrupted",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=0.25,
        help="watch refresh interval in seconds (default: 0.25)",
    )
    parser.add_argument(
        "--web",
        action="store_true",
        help="serve the browser live-token dashboard instead of printing once",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="dashboard bind interface (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=_tcp_port,
        default=8765,
        help="dashboard TCP port (default: 8765; 0 selects a free port)",
    )
    parser.add_argument(
        "--open-browser",
        action="store_true",
        help="open the dashboard in the default browser (implies --web)",
    )
    parser.add_argument(
        "--frontend",
        choices=("token", "lingmou"),
        default="lingmou",
        help=(
            "serve one isolated frontend: token opens the live Token page; "
            "lingmou opens the behavior page (default: lingmou)"
        ),
    )
    parser.add_argument(
        "--analysis-backend",
        choices=("codex", "local"),
        default="codex",
        help="analysis backend for the web dashboard (default: real Codex CLI)",
    )
    parser.add_argument(
        "--analysis-codex-bin",
        default="codex",
        help="Codex executable used by the analysis workers (default: codex)",
    )
    parser.add_argument(
        "--analysis-model",
        default=None,
        help="optional Codex analysis model override (default: Codex CLI default)",
    )
    parser.add_argument(
        "--analysis-timeout",
        type=float,
        default=90.0,
        help="timeout in seconds for each Codex analysis role (default: 90)",
    )
    parser.add_argument(
        "--analysis-min-interval",
        type=float,
        default=1.5,
        help="minimum seconds between Codex analysis batches (default: 1.5)",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    if (args.web or args.open_browser) and args.watch:
        parser.error("--web and --watch cannot be used together")

    try:
        path = resolve_live_status_path(
            run_dir=args.run_dir,
            status_file=args.status_file,
        )
    except StatusError as exc:
        print(f"codexscope status: {exc}", file=sys.stderr)
        if not active_monitor_path().exists():
            print(
                "hint: no active monitor registry; run `codexscope monitor` first",
                file=sys.stderr,
            )
        return 1

    if args.web or args.open_browser:
        from .live_status_server import LiveStatusServerError, serve_live_status

        try:
            serve_live_status(
                path,
                host=args.host,
                port=args.port,
                open_browser=args.open_browser,
                frontend=args.frontend,
                analysis_backend=args.analysis_backend,
                analysis_codex_bin=args.analysis_codex_bin,
                analysis_model=args.analysis_model,
                analysis_timeout_seconds=args.analysis_timeout,
                analysis_min_interval_seconds=args.analysis_min_interval,
            )
        except LiveStatusServerError as exc:
            print(f"codexscope status: cannot serve dashboard: {exc}", file=sys.stderr)
            return 1
        return 0

    if not args.watch:
        try:
            data = load_live_status(path)
        except StatusError as exc:
            print(f"codexscope status: {exc}", file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps(data, ensure_ascii=False, indent=2))
        else:
            print(format_status_text(data, verbose=args.verbose))
        return 0

    # Watch mode: rewrite one status line.
    try:
        while True:
            try:
                data = load_live_status(path)
                text = (
                    json.dumps(data, ensure_ascii=False)
                    if args.json
                    else format_status_text(data, verbose=args.verbose)
                )
            except StatusError as exc:
                text = f"waiting for tokens ({exc})"
            sys.stdout.write(f"\r\033[K{text}")
            sys.stdout.flush()
            time.sleep(max(0.1, float(args.interval)))
    except KeyboardInterrupt:
        sys.stdout.write("\n")
        sys.stdout.flush()
        return 0
