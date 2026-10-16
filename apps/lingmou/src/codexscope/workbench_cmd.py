"""Command-line entry point for the local Lingmou workbench."""

from __future__ import annotations

import argparse
import fcntl
import ipaddress
import json
import os
import secrets
import stat
import sys
import threading
import webbrowser
from pathlib import Path
from typing import Sequence
from urllib.parse import urlencode

import uvicorn

from .investigation import HistoryUnavailable
from .monitor import read_active_monitor
from .storage import json_load
from .workbench_controller import WorkbenchController
from .workbench_server import create_workbench_app
from .workbench_store import WorkbenchEventStore
from .workbuddy_portal import (
    default_workbuddy_portal_path,
    load_workbuddy_launch_urls,
)


def _port(value: str) -> int:
    try:
        result = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if not 1 <= result <= 65_535:
        raise argparse.ArgumentTypeError("must be between 1 and 65535")
    return result


def _is_loopback(host: str) -> bool:
    if host.casefold() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _is_private_bind(host: str) -> bool:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return bool(
        address.is_private
        and not address.is_loopback
        and not address.is_unspecified
        and not address.is_multicast
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="codexscope workbench",
        description=(
            "Run the Lingmou interactive web client against the active local "
            "CodexScope monitor. The browser never receives the monitor's Unix socket."
        ),
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="bind address (default: 127.0.0.1)",
    )
    parser.add_argument("--port", type=_port, default=8766)
    parser.add_argument("--open-browser", action="store_true")
    parser.add_argument(
        "--allow-lan",
        action="store_true",
        help=(
            "allow one explicit private-network bind; requires an HTTPS "
            "certificate and enables capability-token authentication"
        ),
    )
    parser.add_argument("--ssl-certfile", type=Path)
    parser.add_argument("--ssl-keyfile", type=Path)
    parser.add_argument(
        "--persist-conversation",
        action="store_true",
        help=(
            "persist prompt and Agent message text after credential redaction; "
            "the default stores only hashes and lengths"
        ),
    )
    parser.add_argument(
        "--forensic-key-file",
        type=Path,
        help=(
            "enable encrypted full-text Context Capsules with a private 32-byte "
            "AES key file; mutually exclusive with plaintext --persist-conversation "
            "and requires codexscope[forensic]"
        ),
    )
    parser.add_argument(
        "--approval-policy",
        choices=("untrusted", "on-request", "never"),
        default="untrusted",
        help="Codex approval policy for workbench-created threads (default: untrusted)",
    )
    parser.add_argument(
        "--sandbox",
        choices=("read-only", "workspace-write", "danger-full-access"),
        default="workspace-write",
        help="sandbox mode for workbench-created threads (default: workspace-write)",
    )
    parser.add_argument(
        "--security-mode",
        choices=("inherit", "observe", "enforce"),
        default="inherit",
        help="inherit the active monitor policy, or override it for this web client",
    )
    parser.add_argument(
        "--workbuddy-registry",
        type=Path,
        help=(
            "owner-only JSON registry for running WorkBuddy scenarios "
            "(default: the per-user CodexScope state directory)"
        ),
    )
    return parser


def _manifest_security_mode(run_dir: Path) -> str:
    try:
        manifest = json_load(run_dir / "manifest.json")
    except (OSError, ValueError, json.JSONDecodeError):
        return "observe"
    if not isinstance(manifest, dict):
        return "observe"
    policy = manifest.get("security_policy")
    if not isinstance(policy, dict):
        return "observe"
    return "enforce" if policy.get("mode") == "enforce" else "observe"


def _acquire_workbench_lock(run_dir: Path) -> int:
    path = run_dir / "workbench.lock"
    descriptor = os.open(
        path,
        os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise OSError(f"workbench lock is not a regular file: {path}")
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _load_forensic_key(path: Path) -> bytes:
    resolved = path.expanduser().resolve()
    metadata = resolved.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise OSError(f"forensic key must be a regular non-symlink file: {resolved}")
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise OSError(f"forensic key is owned by another user: {resolved}")
    if metadata.st_mode & 0o077:
        raise OSError(f"forensic key permissions must be 0600 or stricter: {resolved}")
    value = resolved.read_bytes()
    if len(value) != 32:
        raise ValueError("forensic key file must contain exactly 32 raw bytes")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    loopback = _is_loopback(args.host)
    if not loopback and (not args.allow_lan or not _is_private_bind(args.host)):
        print(
            "Cannot start Lingmou workbench: non-loopback binds require "
            "--allow-lan and one explicit private-network IP address.",
            file=sys.stderr,
        )
        return 2
    if bool(args.ssl_certfile) != bool(args.ssl_keyfile):
        print(
            "Cannot start Lingmou workbench: --ssl-certfile and --ssl-keyfile "
            "must be provided together.",
            file=sys.stderr,
        )
        return 2
    if not loopback and not (args.ssl_certfile and args.ssl_keyfile):
        print(
            "Cannot start Lingmou workbench: LAN mode requires "
            "--ssl-certfile and --ssl-keyfile.",
            file=sys.stderr,
        )
        return 2
    for tls_path in (args.ssl_certfile, args.ssl_keyfile):
        if tls_path and not tls_path.is_file():
            print(
                f"Cannot start Lingmou workbench: TLS file not found: {tls_path}",
                file=sys.stderr,
            )
            return 2
    try:
        registry = read_active_monitor()
    except BaseException as exc:
        print(f"Cannot start Lingmou workbench: {exc}", file=sys.stderr)
        return 1

    run_dir = Path(str(registry["run_dir"])).expanduser().resolve()
    repo = Path(str(registry["repo"])).expanduser().resolve()
    inherited = _manifest_security_mode(run_dir)
    security_mode = inherited if args.security_mode == "inherit" else args.security_mode
    if security_mode == "enforce" and args.approval_policy == "never":
        print(
            "Cannot start Lingmou workbench: enforce mode requires an approval "
            "policy that reaches the pre-execution gate.",
            file=sys.stderr,
        )
        return 2
    if args.forensic_key_file and args.persist_conversation:
        print(
            "Cannot start Lingmou workbench: --forensic-key-file and "
            "--persist-conversation are mutually exclusive; forensic mode keeps "
            "full context only in the encrypted capsule.",
            file=sys.stderr,
        )
        return 2
    forensic_key: bytes | None = None
    if args.forensic_key_file:
        try:
            forensic_key = _load_forensic_key(args.forensic_key_file)
        except (OSError, ValueError) as exc:
            print(f"Cannot start Lingmou workbench: {exc}", file=sys.stderr)
            return 2
    try:
        lock_fd = _acquire_workbench_lock(run_dir)
    except (OSError, BlockingIOError) as exc:
        print(f"Cannot start Lingmou workbench: another instance is active ({exc})", file=sys.stderr)
        return 1
    try:
        store = WorkbenchEventStore(
            run_dir / "workbench_events.jsonl",
            persist_conversation=args.persist_conversation,
            project_root=repo,
            forensic_key=forensic_key,
        )
    except (HistoryUnavailable, OSError, ValueError) as exc:
        os.close(lock_fd)
        print(f"Cannot start Lingmou workbench: {exc}", file=sys.stderr)
        return 2
    controller = WorkbenchController(
        endpoint=str(registry["endpoint"]),
        repo=repo,
        run_dir=run_dir,
        store=store,
        approval_policy=args.approval_policy,
        sandbox=args.sandbox,
        security_mode=security_mode,
    )
    workbuddy_registry = args.workbuddy_registry or default_workbuddy_portal_path()
    try:
        scenario_launch_urls = load_workbuddy_launch_urls(workbuddy_registry)
    except (OSError, ValueError) as exc:
        store.close()
        os.close(lock_fd)
        print(f"Cannot start Lingmou workbench: {exc}", file=sys.stderr)
        return 2
    access_token = secrets.token_urlsafe(32) if not loopback else None
    app = create_workbench_app(
        controller,
        store,
        allowed_hosts=[args.host],
        access_token=access_token,
        secure_cookie=bool(args.ssl_certfile),
        scenario_launch_urls=scenario_launch_urls,
    )
    url_host = "localhost" if args.host in {"::1", "[::1]"} else args.host
    scheme = "https" if args.ssl_certfile else "http"
    url = f"{scheme}://{url_host}:{args.port}/"
    access_url = (
        f"{url}?{urlencode({'access_token': access_token})}"
        if access_token
        else url
    )
    print("\n灵眸交互工作台已启动。", flush=True)
    print(f"页面:       {access_url}", flush=True)
    print(f"工作区:     {repo}", flush=True)
    print(f"Agent 链路: {registry['endpoint']}（仅后端持有）", flush=True)
    print(f"安全策略:   {security_mode}", flush=True)
    print(
        f"WorkBuddy:  {len(scenario_launch_urls)} 个独立场景入口"
        if scenario_launch_urls
        else "WorkBuddy:  尚未注册独立场景入口",
        flush=True,
    )
    print(
        "会话落盘:   "
        + (
            "AES-GCM 加密取证胶囊；普通日志仅哈希与长度"
            if forensic_key
            else "脱敏后保留全文"
            if args.persist_conversation
            else "仅哈希与长度"
        ),
        flush=True,
    )
    if access_token:
        print("内网访问:   HTTPS + 随机访问令牌", flush=True)
    if args.open_browser:
        threading.Timer(0.8, webbrowser.open, args=(access_url,)).start()
    try:
        uvicorn.run(
            app,
            host=args.host,
            port=args.port,
            log_level="info",
            access_log=False,
            ssl_certfile=str(args.ssl_certfile) if args.ssl_certfile else None,
            ssl_keyfile=str(args.ssl_keyfile) if args.ssl_keyfile else None,
        )
    except OSError as exc:
        print(f"Cannot serve Lingmou workbench: {exc}", file=sys.stderr)
        return 1
    finally:
        store.close()
        os.close(lock_fd)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
