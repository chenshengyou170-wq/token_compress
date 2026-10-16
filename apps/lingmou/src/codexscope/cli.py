from __future__ import annotations

import argparse
import asyncio
import importlib.resources
import json
import os
import shlex
import sys
from pathlib import Path
from typing import Sequence

from .align import align_tokens, tokens_from_actions
from .enrich import enrich_run
from .environment import capture_protocol_schema
from .function_trace import copy_c_runtime_files
from .normalize import normalize_run
from .provenance import build_provenance
from .render import render_comparison, render_timeline
from .runner import run_codex_trace
from .storage import RunLayout, atomic_json_dump, json_load
from .context_compression import COMPRESSION_MODES


def _function_call_limit(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if not 1 <= parsed <= 10_000_000:
        raise argparse.ArgumentTypeError("must be between 1 and 10000000")
    return parsed


def _tcp_port(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if not 1 <= parsed <= 65_535:
        raise argparse.ArgumentTypeError("must be between 1 and 65535")
    return parsed


def process_run(run_dir: Path) -> list[dict]:
    normalize_run(run_dir)
    actions = enrich_run(run_dir)
    graph = build_provenance(actions)
    layout = RunLayout.open(run_dir)
    atomic_json_dump(layout.graph, graph)
    render_timeline(run_dir, actions)
    return actions


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="codexscope",
        description="Capture, map, visualize, and compare Codex agent actions.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run Codex through app-server and capture a trace")
    run.add_argument("--repo", type=Path, required=True)
    prompt_group = run.add_mutually_exclusive_group(required=True)
    prompt_group.add_argument("--prompt")
    prompt_group.add_argument("--prompt-file", type=Path)
    run.add_argument("--out", type=Path, required=True)
    run.add_argument("--codex-bin", default="codex")
    run.add_argument("--model")
    run.add_argument("--timeout", type=float, default=1800)
    run.add_argument(
        "--include-sensitive",
        action="store_true",
        help="retain prompt/message text after credential redaction",
    )

    monitor = sub.add_parser(
        "monitor",
        help="monitor an interactive Codex TUI through a private Unix-socket gateway",
    )
    monitor.add_argument(
        "--repo",
        "-C",
        type=Path,
        default=Path("."),
        help="workspace to observe (default: current directory)",
    )
    monitor.add_argument(
        "--out",
        type=Path,
        help="new trace directory outside the workspace (default: private state directory)",
    )
    monitor.add_argument("--codex-bin", default="codex")
    monitor.add_argument(
        "--socket",
        type=Path,
        help="explicit public Unix socket path; must not already exist",
    )
    monitor.add_argument(
        "--once",
        action="store_true",
        help="finalize after the first connected TUI disconnects",
    )
    monitor.add_argument(
        "--include-sensitive",
        action="store_true",
        help="retain prompt/message text after credential redaction",
    )
    monitor.add_argument(
        "--no-schema",
        action="store_true",
        help="do not snapshot the installed app-server JSON schema",
    )
    monitor.add_argument(
        "--function-trace",
        choices=("off", "python", "c", "all"),
        default="off",
        help="optional project function tracing inherited by Codex tool processes",
    )
    monitor.add_argument(
        "--function-max-calls",
        type=_function_call_limit,
        default=100_000,
        help="maximum activations per instrumented process (default: 100000)",
    )
    monitor.add_argument(
        "--file-audit",
        choices=("off", "auto", "inotify"),
        default="off",
        help=(
            "optional Linux path-event observation: off (default), graceful "
            "auto detection, or strict inotify"
        ),
    )
    monitor.add_argument(
        "--file-audit-max-events",
        type=_function_call_limit,
        default=100_000,
        help="maximum filesystem JSONL events (default: 100000)",
    )
    monitor.add_argument(
        "--os-audit",
        choices=("off", "auto", "strace"),
        default="off",
        help=(
            "optional App Server descendant-process syscall audit: off "
            "(default), graceful auto detection, or strict strace"
        ),
    )
    monitor.add_argument(
        "--os-audit-max-events",
        type=_function_call_limit,
        default=200_000,
        help="maximum OS-audit JSONL events (default: 200000)",
    )
    monitor.add_argument(
        "--os-audit-profile",
        choices=("behavior", "focused", "full"),
        default="behavior",
        help=(
            "syscall capture profile: behavior-relevant process/file/network "
            "evidence (default), focused key calls, or broader full capture"
        ),
    )
    monitor.add_argument(
        "--harness-telemetry",
        choices=("off", "auto", "otel"),
        default="off",
        help=(
            "Codex open-harness trace-safe telemetry: off (default), "
            "best-effort auto collector startup, or strict OTLP collection"
        ),
    )
    monitor.add_argument(
        "--harness-telemetry-max-events",
        type=_function_call_limit,
        default=100_000,
        help="maximum normalized harness span/event records (default: 100000)",
    )
    monitor.add_argument(
        "--security-policy",
        choices=("observe", "enforce"),
        default="observe",
        help=(
            "observe only (default), or decline high-risk commands that reach "
            "the Codex pre-execution approval gate"
        ),
    )
    monitor.add_argument(
        "--capture-surfaced-reasoning",
        action="store_true",
        help=(
            "retain reasoning events surfaced by Codex app-server; this does "
            "not expose hidden chain-of-thought"
        ),
    )
    monitor.add_argument(
        "--request-token-tap-upstream",
        metavar="URL",
        default=None,
        help=(
            "opt in to a loopback Responses relay and model-aware full-request "
            "input estimate; PDF/image/audio requests also use provider token "
            "preflight when available; URL is the original provider base, "
            "and non-loopback upstreams must use HTTPS; for example "
            "https://chatgpt.com/backend-api/codex or https://api.openai.com/v1"
        ),
    )

    monitor.add_argument(
        "--input-compression",
        choices=COMPRESSION_MODES,
        default="off",
        help=(
            "data-only compression: structure/hybrid, extract/auto (local), jev/kimi (source selection), "
            "llmlingua2 (local weights), or unified Caveman/Headroom/GenericAgent adapters; "
            "requires --request-token-tap-upstream; default: off"
        ),
    )

    attach = sub.add_parser(
        "attach", help="launch the normal Codex TUI through the active monitor"
    )
    attach.add_argument(
        "--print-command",
        action="store_true",
        help="print the resolved Codex command instead of executing it",
    )
    attach.add_argument(
        "codex_args",
        nargs=argparse.REMAINDER,
        help="arguments for Codex; use `--` before Codex options",
    )
    sub.add_parser(
        "workbench",
        help="open the interactive Lingmou web client for the active monitor",
        add_help=False,
    )
    sub.add_parser(
        "context", help="compress requests, reread retained sources, or report task usage", add_help=False,
    )
    sub.add_parser(
        "workbuddy",
        help="run a clean Lingmou WorkBuddy MCP scenario with Codex by default",
        add_help=False,
    )
    sub.add_parser(
        "workbuddy-desktop",
        help="prepare a real WorkBuddy Desktop MCP connection for a running scenario",
        add_help=False,
    )
    run.add_argument(
        "--no-schema",
        action="store_true",
        help="do not snapshot the installed app-server JSON schema",
    )
    run.add_argument(
        "--function-trace",
        choices=("off", "python", "c", "all"),
        default="off",
        help=(
            "off (default), CPython auto-bootstrap, explicitly instrumented "
            "C/C++, or both; runtime calls are written to JSON/graph and the unified report"
        ),
    )
    run.add_argument(
        "--function-max-calls",
        type=_function_call_limit,
        default=100_000,
        help=(
            "maximum activations per instrumented process, 1..10000000 "
            "(default: 100000)"
        ),
    )

    process = sub.add_parser(
        "process", help="rebuild derived data and report from an existing raw trace"
    )
    process.add_argument(
        "--run-dir", type=Path, required=True, help="existing CodexScope run directory"
    )

    serve = sub.add_parser(
        "serve",
        help="serve one run's self-contained HTML report over HTTP",
        description=(
            "Serve only timeline.html. The server has no authentication or TLS; "
            "bind to a LAN interface only inside a trusted network."
        ),
    )
    serve.add_argument(
        "--run-dir", type=Path, required=True, help="processed CodexScope run directory"
    )
    serve.add_argument(
        "--host",
        default="127.0.0.1",
        help="interface to bind (default: 127.0.0.1; use 0.0.0.0 for intranet access)",
    )
    serve.add_argument(
        "--port", type=_tcp_port, default=8000, help="TCP port (default: 8000)"
    )

    compare = sub.add_parser("compare", help="semantically compare two processed runs")
    compare.add_argument("run_a", type=Path)
    compare.add_argument("run_b", type=Path)
    compare.add_argument("--out", type=Path, required=True)

    hook = sub.add_parser("hook-collect", help="record one Codex lifecycle hook from stdin")
    hook.add_argument("--out", type=Path)
    hook.add_argument("--default-out", type=Path)
    hook.add_argument("--strict", action="store_true")

    hook_example = sub.add_parser("hooks-example", help="copy the example Codex hook config")
    hook_example.add_argument("--out", type=Path, required=True)

    schema = sub.add_parser("capture-schema", help="snapshot and hash the installed app-server schema")
    schema.add_argument("--out", type=Path, required=True)
    schema.add_argument("--codex-bin", default="codex")

    c_runtime = sub.add_parser(
        "runtime-c-files",
        help="copy the C/C++ -finstrument-functions runtime without overwriting files",
    )
    c_runtime.add_argument(
        "--out",
        type=Path,
        required=True,
        help="destination directory; existing same-named runtime files are refused",
    )

    status = sub.add_parser(
        "status",
        help="show real-time Codex token usage and activity for the active monitor",
        description=(
            "Read live_status.json written by `codexscope monitor` while a TUI "
            "session is attached. Displays cumulative tokens and whether Codex "
            "appears to be waiting for the model, streaming, running a local "
            "tool, or awaiting user approval."
        ),
    )
    status.add_argument(
        "--run-dir",
        type=Path,
        default=None,
        help="run directory containing live_status.json (default: active monitor)",
    )
    status.add_argument(
        "--status-file",
        type=Path,
        default=None,
        help="explicit live_status.json path",
    )
    status.add_argument(
        "--json",
        action="store_true",
        help="print raw JSON",
    )
    status.add_argument(
        "--watch",
        action="store_true",
        help="refresh until interrupted",
    )
    status.add_argument(
        "--interval",
        type=float,
        default=0.25,
        help="watch interval seconds (default: 0.25)",
    )
    status.add_argument(
        "--web",
        action="store_true",
        help="serve the browser live behavior dashboard",
    )
    status.add_argument(
        "--host",
        default="127.0.0.1",
        help="dashboard bind interface (default: 127.0.0.1)",
    )
    status.add_argument(
        "--port",
        type=_tcp_port,
        default=8765,
        help="dashboard TCP port (default: 8765)",
    )
    status.add_argument(
        "--open-browser",
        action="store_true",
        help="open the dashboard in the default browser (implies --web)",
    )
    status.add_argument(
        "--frontend",
        choices=("token", "lingmou"),
        default="lingmou",
        help="serve only the token or Lingmou frontend (default: lingmou)",
    )
    status.add_argument(
        "--analysis-backend",
        choices=("codex", "local"),
        default="codex",
        help="web analysis backend (default: real Codex CLI)",
    )
    status.add_argument(
        "--analysis-codex-bin",
        default="codex",
        help="Codex executable used by analysis workers",
    )
    status.add_argument(
        "--analysis-model",
        default=None,
        help="optional model override for Codex analysis workers",
    )
    status.add_argument("--analysis-timeout", type=float, default=90.0)
    status.add_argument("--analysis-min-interval", type=float, default=1.5)

    usage = sub.add_parser(
        "usage-history",
        help="historical Codex token totals via open-source ccusage (not live)",
        description=(
            "Optional historical reports via ccusage "
            "(https://github.com/ccusage/ccusage). For live session tokens use "
            "`codexscope status` or the monitor status bar instead."
        ),
    )
    usage.add_argument(
        "--ccusage-bin",
        default=None,
        help="ccusage executable (default: PATH, else npx ccusage@latest)",
    )
    usage.add_argument(
        "--codex-home",
        type=Path,
        default=None,
        help="Codex home for ccusage (sets CODEX_HOME; default ~/.codex)",
    )
    usage.add_argument(
        "usage_args",
        nargs=argparse.REMAINDER,
        help=(
            "optional report name (daily|monthly|session, default daily) and "
            "arguments forwarded to ccusage, e.g. --json --since 2026-07-01"
        ),
    )
    return parser


def _normalized_file_audit_meta(meta: dict) -> dict[str, object]:
    raw = meta.get("file_audit")
    audit = raw if isinstance(raw, dict) else {}
    requested = str(audit.get("requested") or "off")
    enabled = bool(audit.get("enabled", False))
    if requested == "off" and not enabled:
        status = "disabled"
        backend: object = None
        max_events: object = None
    else:
        status = str(
            audit.get("status")
            or ("enabled_unknown" if enabled else "unavailable")
        )
        backend = audit.get("backend")
        max_events = audit.get("max_events")
    nested = audit.get("collector")
    collector = nested if isinstance(nested, dict) else audit

    def count(key: str) -> int:
        value = collector.get(key, audit.get(key, 0))
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    loss_counts = {
        key: count(key)
        for key in (
            "kernel_overflows",
            "buffer_dropped",
            "jsonl_dropped",
            "callback_dropped",
            "snapshot_windows_dropped",
            "watch_add_errors",
            "watch_limit_errors",
        )
    }
    return {
        "requested": requested,
        "enabled": enabled,
        "backend": backend,
        "max_events": max_events,
        "status": status,
        "known_loss_detected": bool(
            audit.get("known_loss_detected") or any(loss_counts.values())
        ),
        **loss_counts,
    }


def _normalized_os_audit_meta(meta: dict) -> dict[str, object]:
    raw = meta.get("os_audit")
    audit = raw if isinstance(raw, dict) else {}
    requested = str(audit.get("requested") or "off")
    enabled = bool(audit.get("enabled", False))
    nested = audit.get("collector")
    collector = nested if isinstance(nested, dict) else audit
    if requested == "off" and not enabled:
        return {
            "requested": "off",
            "enabled": False,
            "backend": None,
            "scope": None,
            "max_events": None,
            "max_bytes": None,
            "strace_version": None,
            "status": "disabled",
            "known_loss_detected": False,
            "dropped": 0,
            "parse_errors": 0,
            "unfinished_pending": 0,
            "limit_reached": False,
            "reader_failed": False,
        }

    def count(key: str) -> int:
        value = collector.get(key, audit.get(key, 0))
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    dropped = count("dropped")
    parse_errors = count("parse_errors")
    unfinished_pending = count("unfinished_pending")
    limit_reached = bool(collector.get("limit_reached", audit.get("limit_reached")))
    reader_failed = bool(collector.get("reader_error", audit.get("reader_error")))
    return {
        "requested": requested,
        "enabled": enabled,
        "backend": audit.get("backend"),
        "scope": audit.get("scope"),
        "max_events": audit.get("max_events", collector.get("max_events")),
        "max_bytes": collector.get("max_bytes", audit.get("max_bytes")),
        "strace_version": collector.get("strace_version"),
        "status": str(
            audit.get("status")
            or ("enabled_unknown" if enabled else "unavailable")
        ),
        "known_loss_detected": bool(
            audit.get("known_loss_detected")
            or collector.get("known_loss")
            or dropped
            or parse_errors
            or unfinished_pending
            or limit_reached
            or reader_failed
        ),
        "dropped": dropped,
        "parse_errors": parse_errors,
        "unfinished_pending": unfinished_pending,
        "limit_reached": limit_reached,
        "reader_failed": reader_failed,
    }


def _normalized_harness_telemetry_meta(meta: dict) -> dict[str, object]:
    raw = meta.get("harness_telemetry")
    telemetry = raw if isinstance(raw, dict) else {}
    requested = str(telemetry.get("requested") or "off")
    enabled = bool(telemetry.get("enabled", False))
    collector_value = telemetry.get("collector")
    collector = collector_value if isinstance(collector_value, dict) else {}

    def count(key: str) -> int:
        value = collector.get(key, telemetry.get(key, 0))
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    known_loss = bool(
        telemetry.get("known_loss_detected")
        or count("dropped_records")
        or count("parse_errors")
        or count("rejected_requests")
        or count("persistence_errors")
    )
    return {
        "requested": requested,
        "enabled": enabled,
        "backend": telemetry.get("backend") if enabled else None,
        "max_events": (
            None
            if requested == "off" and not enabled
            else telemetry.get("max_events", collector.get("max_events"))
        ),
        "status": str(
            telemetry.get("status")
            or ("enabled_unknown" if enabled else "disabled")
        ),
        "content_capture": bool(telemetry.get("content_capture", False)),
        "known_loss_detected": known_loss,
        "dropped_records": count("dropped_records"),
        "parse_errors": count("parse_errors"),
    }


def _compatibility_warnings(meta_a: dict, meta_b: dict) -> list[str]:
    warnings: list[str] = []
    fields = (
        "git_head",
        "prompt_sha256",
        "codex_version",
        "model_resolved",
        "config_sha256",
    )
    for key in fields:
        if meta_a.get(key) != meta_b.get(key):
            warnings.append(f"{key} differs: {meta_a.get(key)!r} vs {meta_b.get(key)!r}")
    schema_a = (meta_a.get("protocol_schema") or {}).get("sha256")
    schema_b = (meta_b.get("protocol_schema") or {}).get("sha256")
    if schema_a != schema_b:
        warnings.append(f"protocol schema differs: {schema_a!r} vs {schema_b!r}")
    if meta_a.get("status") != "completed" or meta_b.get("status") != "completed":
        warnings.append(
            f"at least one run is incomplete: {meta_a.get('status')!r} vs {meta_b.get('status')!r}"
        )
    trace_a = meta_a.get("function_trace") or {}
    trace_b = meta_b.get("function_trace") or {}
    for key in ("enabled", "requested", "max_calls_per_process"):
        if trace_a.get(key) != trace_b.get(key):
            warnings.append(
                f"function_trace.{key} differs: {trace_a.get(key)!r} vs {trace_b.get(key)!r}"
            )
    harness_a = _normalized_harness_telemetry_meta(meta_a)
    harness_b = _normalized_harness_telemetry_meta(meta_b)
    for key in (
        "requested",
        "enabled",
        "backend",
        "max_events",
        "status",
        "content_capture",
        "known_loss_detected",
        "dropped_records",
        "parse_errors",
    ):
        if harness_a.get(key) != harness_b.get(key):
            warnings.append(
                f"harness_telemetry.{key} differs: "
                f"{harness_a.get(key)!r} vs {harness_b.get(key)!r}"
            )
    audit_a = _normalized_file_audit_meta(meta_a)
    audit_b = _normalized_file_audit_meta(meta_b)
    for key in (
        "enabled",
        "requested",
        "backend",
        "max_events",
        "status",
        "known_loss_detected",
        "kernel_overflows",
        "buffer_dropped",
        "jsonl_dropped",
        "callback_dropped",
        "snapshot_windows_dropped",
        "watch_add_errors",
        "watch_limit_errors",
    ):
        if audit_a.get(key) != audit_b.get(key):
            warnings.append(
                f"file_audit.{key} differs: {audit_a.get(key)!r} vs {audit_b.get(key)!r}"
            )
    os_audit_a = _normalized_os_audit_meta(meta_a)
    os_audit_b = _normalized_os_audit_meta(meta_b)
    for key in (
        "enabled",
        "requested",
        "backend",
        "scope",
        "max_events",
        "max_bytes",
        "strace_version",
        "status",
        "known_loss_detected",
        "dropped",
        "parse_errors",
        "unfinished_pending",
        "limit_reached",
        "reader_failed",
    ):
        if os_audit_a.get(key) != os_audit_b.get(key):
            warnings.append(
                f"os_audit.{key} differs: "
                f"{os_audit_a.get(key)!r} vs {os_audit_b.get(key)!r}"
            )
    return warnings


def _compare(run_a: Path, run_b: Path, out: Path) -> Path:
    layout_a, layout_b = RunLayout.open(run_a), RunLayout.open(run_b)
    meta_a, meta_b = json_load(layout_a.manifest), json_load(layout_b.manifest)
    actions_a = json_load(layout_a.enriched)
    actions_b = json_load(layout_b.enriched)
    nonsemantic_observations = {
        "function_call",
        "filesystem_event",
        "workspace_reconcile",
        "os_syscall",
    }
    semantic_a = [
        action
        for action in actions_a
        if action.get("action_type") not in nonsemantic_observations
        and action.get("source") != "otel"
    ]
    semantic_b = [
        action
        for action in actions_b
        if action.get("action_type") not in nonsemantic_observations
        and action.get("source") != "otel"
    ]
    comparison = align_tokens(tokens_from_actions(semantic_a), tokens_from_actions(semantic_b))
    comparison["warnings"] = _compatibility_warnings(meta_a, meta_b)
    comparison["run_a"] = str(layout_a.root)
    comparison["run_b"] = str(layout_b.root)
    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    atomic_json_dump(out / "comparison.json", comparison)
    return render_comparison(out, comparison)


def _hooks_example(out: Path) -> None:
    source = importlib.resources.files("codexscope").joinpath("templates/hooks.toml.example")
    out = out.expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        raise FileExistsError(out)
    out.write_bytes(source.read_bytes())


def main(argv: Sequence[str] | None = None) -> int:
    # Route subcommands that accept third-party / free-form flags early so the
    # top-level parser does not reject them.
    raw = list(sys.argv[1:] if argv is None else argv)
    if raw and raw[0] == "context":
        from .context_tools import main as context_main
        return context_main(raw[1:])
    if raw and raw[0] == "status":
        from .status_cmd import main as status_main

        return status_main(raw[1:])
    if raw and raw[0] == "workbench":
        from .workbench_cmd import main as workbench_main

        return workbench_main(raw[1:])
    if raw and raw[0] == "workbuddy":
        from .workbuddy_cmd import main as workbuddy_main

        return workbuddy_main(raw[1:])
    if raw and raw[0] == "workbuddy-desktop":
        from .workbuddy_desktop import main as workbuddy_desktop_main

        return workbuddy_desktop_main(raw[1:])
    if raw and raw[0] in {"usage-history", "usage"}:
        # `usage` remains as a friendly alias pointing at historical ccusage;
        # live session stats are `codexscope status`.
        if raw[0] == "usage":
            print(
                "note: `codexscope usage` is historical (ccusage). "
                "For live session tokens use `codexscope status`.",
                file=sys.stderr,
            )
        from .usage import main as usage_main

        return usage_main(raw[1:])

    parser = _parser()
    args = parser.parse_args(argv)
    if (
        args.command == "monitor"
        and args.input_compression != "off"
        and args.request_token_tap_upstream is None
    ):
        parser.error("--input-compression requires --request-token-tap-upstream")
    if args.command == "hook-collect":
        from .hook_collector import main as hook_main

        hook_args: list[str] = []
        if args.out:
            hook_args.extend(["--out", str(args.out)])
        if args.default_out:
            hook_args.extend(["--default-out", str(args.default_out)])
        if args.strict:
            hook_args.append("--strict")
        return hook_main(hook_args)

    if args.command == "hooks-example":
        _hooks_example(args.out)
        print(args.out.resolve())
        return 0

    if args.command == "capture-schema":
        result = capture_protocol_schema(args.codex_bin, args.out.resolve())
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result.get("captured") else 1

    if args.command == "runtime-c-files":
        for path in copy_c_runtime_files(args.out):
            print(path)
        return 0

    if args.command == "serve":
        from .report_server import ReportServerError, serve_report

        try:
            serve_report(args.run_dir, host=args.host, port=args.port)
        except (ReportServerError, OSError) as exc:
            print(f"Cannot serve CodexScope report: {exc}", file=sys.stderr)
            return 1
        return 0

    if args.command == "process":
        process_run(args.run_dir)
        print((args.run_dir.resolve() / "timeline.html"))
        return 0

    if args.command == "compare":
        print(_compare(args.run_a, args.run_b, args.out))
        return 0

    if args.command == "attach":
        from .monitor import (
            LINGMOU_SECURITY_PATH_ENV,
            attach_command,
            attach_environment,
            read_active_monitor,
        )

        try:
            registry = read_active_monitor()
            command = attach_command(registry, args.codex_args)
            environment = attach_environment(registry)
        except BaseException as exc:
            print(f"Cannot attach to CodexScope monitor: {exc}", file=sys.stderr)
            return 1
        if args.print_command:
            security_path = registry.get("lingmou_security_path")
            display_command = (
                ["env", f"{LINGMOU_SECURITY_PATH_ENV}={security_path}", *command]
                if isinstance(security_path, str) and security_path
                else command
            )
            print(shlex.join(display_command))
            return 0
        try:
            os.execvpe(command[0], command, environment)
        except OSError as exc:
            print(f"Cannot launch Codex TUI: {exc}", file=sys.stderr)
            return 1
        return 0

    if args.command == "monitor":
        from .monitor import default_run_dir, monitor_codex

        repo = args.repo.expanduser().resolve()
        output = (
            args.out.expanduser().resolve()
            if args.out is not None
            else default_run_dir(repo)
        )
        manifest_path = output / "manifest.json"
        manifest_existed_before = manifest_path.exists()
        monitor_error: BaseException | None = None
        try:
            asyncio.run(
                monitor_codex(
                    repo=repo,
                    run_dir=output,
                    codex_bin=args.codex_bin,
                    include_sensitive=args.include_sensitive,
                    capture_schema=not args.no_schema,
                    function_trace=args.function_trace,
                    function_max_calls=args.function_max_calls,
                    file_audit=args.file_audit,
                    file_audit_max_events=args.file_audit_max_events,
                    os_audit=args.os_audit,
                    os_audit_max_events=args.os_audit_max_events,
                    os_audit_profile=args.os_audit_profile,
                    harness_telemetry=args.harness_telemetry,
                    harness_telemetry_max_events=(
                        args.harness_telemetry_max_events
                    ),
                    security_policy=args.security_policy,
                    capture_surfaced_reasoning=args.capture_surfaced_reasoning,
                    request_token_tap_upstream=args.request_token_tap_upstream,
                    input_compression=args.input_compression,
                    frontend_socket=args.socket,
                    once=args.once,
                )
            )
        except BaseException as exc:
            monitor_error = exc

        process_error: BaseException | None = None
        run_created = not manifest_existed_before and manifest_path.exists()
        if run_created:
            try:
                layout = RunLayout.open(output)
                if layout.appserver_raw.exists():
                    process_run(output)
            except BaseException as exc:
                process_error = exc

        if monitor_error is not None:
            print(f"Interactive monitor failed: {monitor_error}", file=sys.stderr)
        if process_error is not None:
            print(f"Trace processing failed: {process_error}", file=sys.stderr)
        if monitor_error is not None or process_error is not None:
            if run_created:
                print(f"Partial trace: {output}", file=sys.stderr)
            return 1
        print(output / "timeline.html")
        return 0

    prompt = args.prompt if args.prompt is not None else args.prompt_file.read_text(encoding="utf-8")
    run_error: BaseException | None = None
    try:
        asyncio.run(
            run_codex_trace(
                repo=args.repo,
                prompt=prompt,
                run_dir=args.out,
                codex_bin=args.codex_bin,
                model=args.model,
                timeout_seconds=args.timeout,
                include_sensitive=args.include_sensitive,
                capture_schema=not args.no_schema,
                function_trace=args.function_trace,
                function_max_calls=args.function_max_calls,
            )
        )
    except BaseException as exc:
        run_error = exc

    process_error: BaseException | None = None
    try:
        layout = RunLayout.open(args.out)
        if layout.appserver_raw.exists():
            process_run(args.out)
    except BaseException as exc:
        process_error = exc

    if run_error is not None:
        print(f"Codex run failed: {run_error}", file=sys.stderr)
    if process_error is not None:
        print(f"Trace processing failed: {process_error}", file=sys.stderr)
    if run_error is not None or process_error is not None:
        return 1
    print(args.out.resolve() / "timeline.html")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
