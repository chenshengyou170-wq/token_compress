"""Launch one clean Lingmou WorkBuddy run with a fixed local MCP gateway."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import webbrowser
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Any, Sequence
from urllib.parse import urlencode

import httpx
import uvicorn

from .codebuddy_acp import CodeBuddyACPAdapter
from .storage import atomic_json_dump
from .workbench_controller import WorkbenchController
from .workbench_server import create_workbench_app
from .workbench_store import WorkbenchEventStore
from .workbuddy_actions import WorkBuddyRuntime
from .workbuddy_mcp import MCP_TOKEN_ENV, mcp_cli_config, mcp_server_config
from .workbuddy_scenarios import get_scenario, runnable_scenario_ids


_MCP_SERVER_NAME = "lingmou_workbuddy"
_UNIX_SOCKET_SAFE_BYTES = 100
_STRACE_RAW_NETWORK_PAYLOAD_CALLS = (
    "recvfrom,recvmsg,recvmmsg,sendto,sendmsg,sendmmsg"
)


def _port(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 0 <= parsed <= 65_535:
        raise argparse.ArgumentTypeError("port must be between 0 and 65535")
    return parsed


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


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


def _short_appserver_socket() -> tuple[Path, Path]:
    """Create a private short directory that stays below Unix SUN_LEN limits."""

    candidates = [Path(tempfile.gettempdir()), Path("/tmp")]
    checked: set[Path] = set()
    for root in candidates:
        resolved = root.expanduser().resolve()
        if resolved in checked or not resolved.is_dir():
            continue
        checked.add(resolved)
        socket_dir = resolved / f"lmwb-{secrets.token_hex(6)}"
        socket_path = socket_dir / "app.sock"
        if len(os.fsencode(socket_path)) >= _UNIX_SOCKET_SAFE_BYTES:
            continue
        socket_dir.mkdir(mode=0o700, exist_ok=False)
        socket_dir.chmod(0o700)
        return socket_dir, socket_path
    raise RuntimeError("cannot create a short private app-server Unix socket path")


def _resolved_port(requested: int, used: set[int]) -> int:
    result = requested
    while not result or result in used:
        result = _free_port()
    used.add(result)
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="codexscope workbuddy",
        description=(
            "Run one clean Lingmou WorkBuddy scenario. Codex is the default Agent; "
            "WorkBuddy is exposed only as a fixed local MCP transaction gateway."
        ),
    )
    parser.add_argument("--scenario", required=True, choices=runnable_scenario_ids())
    parser.add_argument(
        "--agent",
        choices=("codex", "codebuddy"),
        default="codex",
        help="Agent backend; Codex is the default and CodeBuddy is optional",
    )
    parser.add_argument("--repo", "-C", type=Path, default=Path.cwd())
    parser.add_argument(
        "--runs-root",
        type=Path,
        default=Path.home() / ".local" / "state" / "codexscope" / "workbuddy-runs",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Lingmou UI bind address")
    parser.add_argument(
        "--port",
        type=_port,
        default=0,
        help="Lingmou UI port; 0 chooses a free port",
    )
    parser.add_argument("--codebuddy-port", type=_port, default=0)
    parser.add_argument("--mcp-port", type=_port, default=0)
    parser.add_argument("--codex-bin", default="codex")
    parser.add_argument("--request-token-tap-upstream", help="Original Codex provider base URL for measured token compression")
    parser.add_argument("--input-compression", choices=("off", "structure", "extract", "auto", "full"), default="off")
    parser.add_argument("--codebuddy-bin", default="codebuddy")
    parser.add_argument("--open-browser", action="store_true")
    parser.add_argument(
        "--allow-lan",
        action="store_true",
        help="allow one explicit private-network UI bind with HTTPS and an access token",
    )
    parser.add_argument("--ssl-certfile", type=Path)
    parser.add_argument("--ssl-keyfile", type=Path)
    parser.add_argument("--persist-conversation", action="store_true")
    parser.add_argument(
        "--os-audit",
        choices=("off", "auto", "strace"),
        default="auto",
        help="trace only the MCP gateway and its controlled executor children",
    )
    return parser


def _resolve_executable(value: str) -> str | None:
    candidate = Path(value).expanduser()
    if candidate.parent != Path(".") or os.sep in value:
        resolved = candidate.resolve()
        return os.fspath(resolved) if resolved.is_file() and os.access(resolved, os.X_OK) else None
    return shutil.which(value)


def _codebuddy_command(
    executable: str, *, port: int, mcp_config_path: Path
) -> list[str]:
    """Build the reviewed serve command; intentionally no bypass flag exists."""

    return [
        executable,
        "--serve",
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--strict-mcp-config",
        "--mcp-config",
        os.fspath(mcp_config_path),
        "--permission-mode",
        "default",
        "--disallowedTools",
        "Bash Edit Write MultiEdit NotebookEdit",
        "--no-session-persistence",
    ]


def _configured_mcp_names(executable: str, *, cwd: Path) -> list[str]:
    """Read only the configured MCP names so this run can disable every other server."""

    try:
        completed = subprocess.run(
            [executable, "mcp", "list", "--json"],
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=10.0,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"cannot inspect Codex MCP configuration: {exc}") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or f"exit {completed.returncode}"
        raise RuntimeError(f"cannot inspect Codex MCP configuration: {detail[:300]}")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Codex MCP list did not return valid JSON") from exc
    if not isinstance(value, list):
        raise RuntimeError("Codex MCP list returned an unsupported shape")
    names = {
        str(item["name"])
        for item in value
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    return sorted(name for name in names if name != _MCP_SERVER_NAME)


def _toml_string(value: str) -> str:
    """Encode a bounded string as a TOML-compatible basic string."""

    return json.dumps(value, ensure_ascii=False)


def _codex_mcp_override(mcp_endpoint: str, disabled_names: Sequence[str]) -> str:
    entries = [
        f"{_toml_string(name)}={{enabled=false}}" for name in disabled_names
    ]
    entries.append(
        f"{_toml_string(_MCP_SERVER_NAME)}={{"
        f"url={_toml_string(mcp_endpoint)},"
        f"bearer_token_env_var={_toml_string(MCP_TOKEN_ENV)},"
        "required=true,default_tools_approval_mode=\"approve\",tool_timeout_sec=660}"
    )
    return "mcp_servers={" + ",".join(entries) + "}"


def _codex_command(
    executable: str,
    *,
    socket_path: Path,
    mcp_endpoint: str,
    disabled_mcp_names: Sequence[str],
) -> list[str]:
    """Build a run-scoped Codex app-server command with only WorkBuddy MCP enabled."""

    return [
        executable,
        "app-server",
        "--listen",
        f"unix://{socket_path}",
        "-c",
        _codex_mcp_override(mcp_endpoint, disabled_mcp_names),
        "-c",
        'web_search="disabled"',
    ]


def _mcp_command(*, db_path: Path, scenario_id: str, port: int) -> list[str]:
    return [
        sys.executable,
        "-m",
        "codexscope.workbuddy_mcp",
        "--db",
        os.fspath(db_path),
        "--scenario",
        scenario_id,
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
    ]


def _audited_mcp_command(
    strace: str, *, command: Sequence[str], trace_prefix: Path
) -> list[str]:
    """Trace process/file/network metadata without persisting HTTP payloads."""

    return [
        strace,
        "-ff",
        "-ttt",
        "-s",
        "256",
        "-o",
        os.fspath(trace_prefix),
        "-e",
        "trace=process,file,network",
        "-e",
        f"raw={_STRACE_RAW_NETWORK_PAYLOAD_CALLS}",
        *command,
    ]


def _sha256_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _wait_health(
    url: str,
    *,
    process: subprocess.Popen[str],
    headers: dict[str, str] | None = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last_error = "not ready"
    with httpx.Client(timeout=1.0, follow_redirects=False) as client:
        while time.monotonic() < deadline:
            returncode = process.poll()
            if returncode is not None:
                raise RuntimeError(f"child exited before health check (exit {returncode})")
            try:
                response = client.get(url, headers=headers)
                response.raise_for_status()
                value = response.json()
                return value if isinstance(value, dict) else {"status": "ok"}
            except (httpx.HTTPError, ValueError) as exc:
                last_error = str(exc)
                time.sleep(0.1)
    raise RuntimeError(f"health check timed out: {last_error}")


def _wait_socket(
    path: Path, *, process: subprocess.Popen[str], timeout: float = 30.0
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        returncode = process.poll()
        if returncode is not None:
            raise RuntimeError(f"child exited before socket was ready (exit {returncode})")
        if path.exists():
            return
        time.sleep(0.1)
    raise RuntimeError(f"app-server socket timed out: {path}")


@dataclass(slots=True)
class _OwnedChild:
    name: str
    process: subprocess.Popen[str]
    log: IO[str]


class _ChildSupervisor:
    def __init__(self) -> None:
        self.children: list[_OwnedChild] = []

    def launch(
        self,
        name: str,
        command: Sequence[str],
        *,
        cwd: Path,
        env: dict[str, str],
        log_path: Path,
    ) -> subprocess.Popen[str]:
        log_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        log = log_path.open("a", encoding="utf-8")
        process = subprocess.Popen(
            list(command),
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
        self.children.append(_OwnedChild(name, process, log))
        return process

    def stop_all(self) -> None:
        # Only process groups created and retained by this supervisor are touched.
        for child in reversed(self.children):
            if child.process.poll() is None:
                try:
                    os.killpg(child.process.pid, signal.SIGTERM)
                except (ProcessLookupError, PermissionError):
                    pass
        deadline = time.monotonic() + 5.0
        for child in reversed(self.children):
            remaining = max(0.0, deadline - time.monotonic())
            try:
                child.process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(child.process.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
                try:
                    child.process.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    pass
            child.log.close()


def _new_run_dir(root: Path, scenario_id: str) -> tuple[str, Path]:
    run_id = (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + f"-{scenario_id.lower()}-{uuid.uuid4().hex[:10]}"
    )
    run_dir = root.expanduser().resolve() / run_id
    run_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
    (run_dir / "raw").mkdir(mode=0o700)
    return run_id, run_dir


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.input_compression != "off" and not args.request_token_tap_upstream:
        print("--input-compression requires --request-token-tap-upstream", file=sys.stderr)
        return 2
    if args.agent != "codex" and args.request_token_tap_upstream:
        print("The request token relay currently requires --agent codex", file=sys.stderr)
        return 2
    loopback = _is_loopback(args.host)
    if not loopback and (not args.allow_lan or not _is_private_bind(args.host)):
        print(
            "Cannot start WorkBuddy: non-loopback UI binds require --allow-lan "
            "and one explicit private-network IP address.",
            file=sys.stderr,
        )
        return 2
    if bool(args.ssl_certfile) != bool(args.ssl_keyfile):
        print(
            "Cannot start WorkBuddy: --ssl-certfile and --ssl-keyfile "
            "must be provided together.",
            file=sys.stderr,
        )
        return 2
    if not loopback and not (args.ssl_certfile and args.ssl_keyfile):
        print(
            "Cannot start WorkBuddy: LAN mode requires --ssl-certfile and --ssl-keyfile.",
            file=sys.stderr,
        )
        return 2
    for tls_path in (args.ssl_certfile, args.ssl_keyfile):
        if tls_path and not tls_path.expanduser().is_file():
            print(
                f"Cannot start WorkBuddy: TLS file not found: {tls_path}",
                file=sys.stderr,
            )
            return 2
    repo = args.repo.expanduser().resolve()
    if not repo.is_dir():
        print(f"Cannot start WorkBuddy: repository not found: {repo}", file=sys.stderr)
        return 2
    executable_name = args.codex_bin if args.agent == "codex" else args.codebuddy_bin
    executable = _resolve_executable(executable_name)
    if executable is None:
        agent_name = "Codex" if args.agent == "codex" else "CodeBuddy"
        print(
            f"Cannot start WorkBuddy: no {args.agent} executable was found. "
            f"Lingmou did not install anything automatically; install and log in to {agent_name}, "
            "then retry.",
            file=sys.stderr,
        )
        return 3
    disabled_mcp_names: list[str] = []
    if args.agent == "codex":
        try:
            disabled_mcp_names = _configured_mcp_names(executable, cwd=repo)
        except RuntimeError as exc:
            print(f"Cannot start WorkBuddy: {exc}", file=sys.stderr)
            return 3

    scenario = get_scenario(args.scenario)
    try:
        run_id, run_dir = _new_run_dir(args.runs_root, args.scenario)
    except OSError as exc:
        print(f"Cannot create clean WorkBuddy run: {exc}", file=sys.stderr)
        return 2

    used_ports: set[int] = set()
    page_port = _resolved_port(args.port, used_ports)
    codebuddy_port = (
        _resolved_port(args.codebuddy_port, used_ports)
        if args.agent == "codebuddy"
        else None
    )
    mcp_port = _resolved_port(args.mcp_port, used_ports)
    gateway_password = (
        secrets.token_urlsafe(36) if args.agent == "codebuddy" else None
    )
    mcp_token = secrets.token_urlsafe(36)
    mcp_endpoint = f"http://127.0.0.1:{mcp_port}/mcp"
    db_path = run_dir / "workbuddy.sqlite3"
    config_path = run_dir / "mcp.strict.json"
    token_tap = None
    appserver_socket: Path | None = None
    appserver_socket_dir: Path | None = None
    atomic_json_dump(config_path, mcp_cli_config(mcp_endpoint, mcp_token))

    runtime = WorkBuddyRuntime(db_path, scenario_id=args.scenario, policy_workspace=repo)
    store = WorkbenchEventStore(
        run_dir / "workbench_events.jsonl",
        persist_conversation=args.persist_conversation,
        project_root=repo,
        history_path=run_dir / "investigation.sqlite3",
        history_discovery=False,
        run_id=run_id,
    )
    supervisor = _ChildSupervisor()
    strace = shutil.which("strace") if args.os_audit != "off" else None
    if args.os_audit == "strace" and strace is None:
        store.close()
        print("Cannot start WorkBuddy: --os-audit strace requested but strace is missing", file=sys.stderr)
        return 2
    os_audit = {
        "requested": args.os_audit,
        "enabled": strace is not None,
        "backend": "strace" if strace else None,
        "scope": "mcp_gateway_and_controlled_executor_descendants",
        "status": "enabled" if strace else "disabled" if args.os_audit == "off" else "unavailable",
        "trace_prefix": os.fspath(run_dir / "raw" / "workbuddy-executor.strace") if strace else None,
    }
    manifest: dict[str, Any] = {
        "schema_version": "lingmou.workbuddy-run.v1",
        "run_id": run_id,
        "created_at": time.time(),
        "repo": os.fspath(repo),
        "run_dir": os.fspath(run_dir),
        "agent_backend": args.agent,
        "scenario": scenario,
        "ports": {"workbench": page_port, "codebuddy": codebuddy_port, "mcp": mcp_port},
        "security": {
            "mcp_token_sha256": _sha256_secret(mcp_token),
            "strict_mcp_config": True,
            "permission_bypass": False,
            "business_approval": "one_shot_only",
            **(
                {
                    "codex_auth": "existing_cli_login",
                    "codex_sandbox": "read-only",
                    "codex_approval_policy": "never",
                    "mcp_tool_approval": "approve_transport_business_gateway_enforced",
                    "disabled_mcp_servers": disabled_mcp_names,
                    "app_server_socket": None,
                }
                if args.agent == "codex"
                else {
                    "codebuddy_bind": "127.0.0.1",
                    "codebuddy_password_sha256": _sha256_secret(
                        gateway_password or ""
                    ),
                    "public_codebuddy_paths": [
                        "/api/v1/health",
                        "/api/v1/acp/connect",
                        "/api/v1/acp",
                    ],
                }
            ),
        },
        "os_audit": os_audit,
        "network": {
            "web_bind": args.host,
            "web_transport": "https" if args.ssl_certfile else "http",
            "lan_access": not loopback,
            "mcp_bind": "127.0.0.1",
            "agent_transport": (
                "private_unix_socket"
                if args.agent == "codex"
                else "loopback_http"
            ),
        },
        "processes": {},
        "status": "starting",
    }
    atomic_json_dump(run_dir / "manifest.json", manifest)

    base_env = {
        **os.environ,
        MCP_TOKEN_ENV: mcp_token,
        "NO_PROXY": "127.0.0.1,localhost",
    }
    mcp_command = _mcp_command(
        db_path=db_path,
        scenario_id=args.scenario,
        port=mcp_port,
    )
    if strace:
        mcp_command = _audited_mcp_command(
            strace,
            command=mcp_command,
            trace_prefix=run_dir / "raw" / "workbuddy-executor.strace",
        )
    adapter: CodeBuddyACPAdapter | WorkbenchController | None = None
    try:
        mcp_process = supervisor.launch(
            "mcp_gateway",
            mcp_command,
            cwd=repo,
            env=base_env,
            log_path=run_dir / "mcp-gateway.log",
        )
        manifest["processes"]["mcp_gateway"] = {"pid": mcp_process.pid, "owned": True}
        atomic_json_dump(run_dir / "manifest.json", manifest)
        _wait_health(
            f"http://127.0.0.1:{mcp_port}/healthz", process=mcp_process, timeout=30.0
        )

        if args.agent == "codebuddy":
            assert codebuddy_port is not None and gateway_password is not None
            codebuddy_url = f"http://127.0.0.1:{codebuddy_port}"
            codebuddy_env = {
                **base_env,
                "CODEBUDDY_GATEWAY_AUTH": "password",
                "CODEBUDDY_GATEWAY_PASSWORD": gateway_password,
                "SERVER__HOST": "127.0.0.1",
            }
            command = _codebuddy_command(
                executable, port=codebuddy_port, mcp_config_path=config_path
            )
            codebuddy_process = supervisor.launch(
                "codebuddy",
                command,
                cwd=repo,
                env=codebuddy_env,
                log_path=run_dir / "codebuddy.log",
            )
            manifest["processes"]["codebuddy"] = {
                "pid": codebuddy_process.pid,
                "owned": True,
            }
            atomic_json_dump(run_dir / "manifest.json", manifest)
            _wait_health(
                f"{codebuddy_url}/api/v1/health",
                process=codebuddy_process,
                headers={
                    "X-CodeBuddy-Request": "1",
                    "Authorization": f"Bearer {gateway_password}",
                },
                timeout=45.0,
            )
            adapter = CodeBuddyACPAdapter(
                base_url=codebuddy_url,
                password=gateway_password,
                repo=repo,
                run_dir=run_dir,
                store=store,
                runtime=runtime,
                mcp_server=mcp_server_config(mcp_endpoint, mcp_token),
                os_audit=os_audit,
            )
            agent_label = "CodeBuddy（公开 HTTP ACP v1）"
        else:
            appserver_socket_dir, appserver_socket = _short_appserver_socket()
            manifest["security"]["app_server_socket"] = os.fspath(appserver_socket)
            atomic_json_dump(run_dir / "manifest.json", manifest)
            command = _codex_command(
                executable,
                socket_path=appserver_socket,
                mcp_endpoint=mcp_endpoint,
                disabled_mcp_names=disabled_mcp_names,
            )
            if args.request_token_tap_upstream:
                from .monitor import _request_tap_provider_arguments
                from .request_token_tap import RequestTokenTap
                from .unified_compression import UnifiedInputCompressor
                from .reference_selection import SourceStore
                from .context_tools import source_mcp_arguments

                def save_request_usage(record):
                    with (run_dir / 'request_usage.jsonl').open('a', encoding='utf-8') as stream:
                        stream.write(json.dumps(record, ensure_ascii=False) + '\n')

                token_tap = RequestTokenTap(args.request_token_tap_upstream,
                    input_compressor=UnifiedInputCompressor(args.input_compression,
                        source_store=SourceStore(run_dir / 'compression_sources'),
                        settings_path=run_dir / 'compression_settings.json'),
                    on_request_usage=save_request_usage).start()
                command.extend(_request_tap_provider_arguments(token_tap.local_base_url))
                command.extend(source_mcp_arguments(run_dir / 'compression_sources'))
                manifest['request_token_tap'] = {**token_tap.stats_dict(), 'configurable': True}
            codex_process = supervisor.launch(
                "codex_app_server",
                command,
                cwd=repo,
                env=base_env,
                log_path=run_dir / "codex-app-server.log",
            )
            manifest["processes"]["codex_app_server"] = {
                "pid": codex_process.pid,
                "owned": True,
            }
            atomic_json_dump(run_dir / "manifest.json", manifest)
            _wait_socket(appserver_socket, process=codex_process, timeout=30.0)
            adapter = WorkbenchController(
                endpoint=f"unix://{appserver_socket}",
                repo=repo,
                run_dir=run_dir,
                store=store,
                approval_policy="never",
                sandbox="read-only",
                security_mode="enforce",
                reconnect_delay=0.25,
                workbuddy_runtime=runtime,
                os_audit=os_audit,
            )
            agent_label = "Codex app-server（沿用当前 Codex 登录与模型）"
        access_token = secrets.token_urlsafe(32) if not loopback else None
        app = create_workbench_app(
            adapter,
            store,
            allowed_hosts=[args.host],
            access_token=access_token,
            secure_cookie=bool(args.ssl_certfile),
            token_tap=token_tap,
        )
        url_host = "localhost" if args.host in {"::1", "[::1]"} else args.host
        scheme = "https" if args.ssl_certfile else "http"
        page_url = f"{scheme}://{url_host}:{page_port}/"
        access_url = (
            f"{page_url}?{urlencode({'access_token': access_token})}"
            if access_token
            else page_url
        )
        if access_token:
            manifest["security"]["web_access_token_sha256"] = _sha256_secret(access_token)
        manifest["status"] = "running"
        manifest["page_url"] = page_url
        manifest["sandbox_id"] = run_dir.name
        atomic_json_dump(run_dir / "manifest.json", manifest)
        print("\n灵眸 WorkBuddy 已创建全新隔离 Run。", flush=True)
        print(f"页面:       {access_url}", flush=True)
        print(f"场景:       {args.scenario} · {scenario['title']}", flush=True)
        print(f"Agent:      {agent_label}", flush=True)
        print(f"MCP 网关:   {mcp_endpoint}（严格配置，随机令牌）", flush=True)
        print(f"业务沙箱:   {db_path}", flush=True)
        print(f"审计 Run:   {run_dir}", flush=True)
        print(f"OS 证据:    {os_audit['status']}（仅受控执行器后代）", flush=True)
        if access_token:
            print(
                "内网访问:   HTTPS + 随机访问令牌；"
                "Codex socket 与 MCP 仍仅本机可达",
                flush=True,
            )
        if args.open_browser:
            threading.Timer(0.8, webbrowser.open, args=(access_url,)).start()
        uvicorn.run(
            app,
            host=args.host,
            port=page_port,
            access_log=False,
            log_level="info",
            ssl_certfile=(
                os.fspath(args.ssl_certfile.expanduser().resolve())
                if args.ssl_certfile
                else None
            ),
            ssl_keyfile=(
                os.fspath(args.ssl_keyfile.expanduser().resolve())
                if args.ssl_keyfile
                else None
            ),
        )
        manifest["status"] = "stopped"
        manifest["stopped_at"] = time.time()
        return 0
    except (OSError, RuntimeError, ValueError, httpx.HTTPError) as exc:
        manifest["status"] = "failed"
        manifest["error"] = str(exc)[:500]
        print(f"Cannot start WorkBuddy: {exc}", file=sys.stderr)
        return 1
    finally:
        supervisor.stop_all()
        if token_tap is not None:
            manifest['request_token_tap'] = {**token_tap.stop(), 'configurable': False}
        if appserver_socket is not None:
            try:
                appserver_socket.unlink(missing_ok=True)
            except OSError:
                pass
        if appserver_socket_dir is not None:
            try:
                appserver_socket_dir.rmdir()
            except OSError:
                pass
        manifest["processes_stopped"] = True
        manifest.setdefault("stopped_at", time.time())
        try:
            atomic_json_dump(run_dir / "manifest.json", manifest)
        except OSError:
            pass
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "_codebuddy_command",
    "_codex_command",
    "_configured_mcp_names",
    "_mcp_command",
    "_short_appserver_socket",
    "main",
]
