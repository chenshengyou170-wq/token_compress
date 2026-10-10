from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import os
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import types
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from functools import partial
from pathlib import Path
from typing import Any

from .environment import (
    capture_protocol_schema,
    capture_transform,
    codex_version,
    runtime_metadata,
)
from .filesystem_guard import wrap_agent
from .fswatch import InotifyWorkspaceObserver
from .function_trace import FunctionTraceCollector, FunctionTraceConfig
from .gateway import UnixSocketGateway
from .live_status import (
    MODEL_OUTPUT_DELTA_METHODS,
    LiveSessionStatus,
    consume_envelope,
)
from .live_security import build_live_security_payload, classify_live_command
from .local_policies import load_local_policies
from .osaudit import StraceAuditCollector
from .otel_trace import OtelTraceCollector, codex_trace_config_arguments
from .payment_security import PAYMENT_POLICY_RULES
from .redaction import redact_event, redact_text
from .request_token_tap import (
    RequestInputEstimate,
    RequestTokenTap,
)
from .context_compression import COMPRESSION_MODES, make_input_compressor
from .reference_selection import SourceStore
from .context_tools import source_mcp_arguments
from .runner import _CAPTURE_AFTER_ITEM_TYPES
from .security_policy import (
    ENFORCEMENT_STAGE,
    POLICY_ID,
    assess_approval_policies,
    intercept_dangerous_command_approval,
)
from .runtime_policy import (
    RuntimePolicySession,
    assess_file_change_policies,
    decisions_from_rule_ids,
    merge_policy_decisions,
)
from .snapshots import SnapshotManager
from .storage import RunLayout, atomic_json_dump, json_load
from .util import now_iso

_STARTUP_TIMEOUT_SECONDS = 20.0
_PROCESS_STOP_TIMEOUT_SECONDS = 5.0
_FILE_AUDIT_DEBOUNCE_SECONDS = 0.25
_LIVE_STATUS_TICK_SECONDS = 0.25
_LIVE_STATUS_HEARTBEAT_SECONDS = 1.0
_LIVE_SECURITY_TICK_SECONDS = 0.5
_OS_AUDIT_MANIFEST_HEARTBEAT_SECONDS = 1.0
_PREFLIGHT_LOG_POLL_SECONDS = 0.05
_CODEXSCOPE_PREFLIGHT_TARGET = "codex_core::codexscope_preflight_usage"
_REQUEST_TAP_PROVIDER_ID = "codexscope_request_tap"
LINGMOU_SECURITY_PATH_ENV = "CODEXSCOPE_LINGMOU_SECURITY_PATH"


class MonitorError(RuntimeError):
    """Interactive monitor setup or transport failure."""


class _MonitorStartupStopped(Exception):
    """Internal control flow for a requested stop before the monitor is ready."""


def _enable_codexscope_preflight_trace(environment: dict[str, str]) -> None:
    """Enable the count-only Codex request-boundary trace in JSON form."""

    directive = f"{_CODEXSCOPE_PREFLIGHT_TARGET}=trace"
    current = environment.get("RUST_LOG", "").strip()
    environment["RUST_LOG"] = f"{current},{directive}" if current else f"warn,{directive}"
    environment["LOG_FORMAT"] = "json"


def _parse_codexscope_preflight_log(line: str) -> dict[str, Any] | None:
    """Parse one count-only tracing event without accepting arbitrary log data."""

    try:
        row = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(row, Mapping) or row.get("target") != _CODEXSCOPE_PREFLIGHT_TARGET:
        return None
    fields = row.get("fields")
    if not isinstance(fields, Mapping):
        return None
    raw_estimate = fields.get("estimated_input_tokens")
    if isinstance(raw_estimate, str):
        candidate = raw_estimate.strip()
        if candidate.startswith("Some(") and candidate.endswith(")"):
            candidate = candidate[5:-1]
        try:
            raw_estimate = int(candidate)
        except ValueError:
            return None
    if type(raw_estimate) is not int or raw_estimate < 0:
        return None
    turn_id = fields.get("turn_id")
    model = fields.get("model")
    return {
        "estimated_input_tokens": raw_estimate,
        "turn_id": turn_id if isinstance(turn_id, str) else None,
        "model": model if isinstance(model, str) else None,
    }


def _request_tap_provider_arguments(
    local_base_url: str,
    *,
    codex_version_value: object = None,
) -> list[str]:
    """Select an HTTP-only OpenAI provider for the loopback request tap."""

    version_header = "unknown"
    if isinstance(codex_version_value, str) and codex_version_value.strip():
        version_header = codex_version_value.strip().rsplit(maxsplit=1)[-1]
    provider = (
        f"model_providers.{_REQUEST_TAP_PROVIDER_ID}={{"
        'name="OpenAI",'
        f"base_url={json.dumps(local_base_url)},"
        'wire_api="responses",'
        f"http_headers={{version={json.dumps(version_header)}}},"
        'env_http_headers={"OpenAI-Organization"="OPENAI_ORGANIZATION",'
        '"OpenAI-Project"="OPENAI_PROJECT"},'
        "requires_openai_auth=true,"
        "supports_websockets=false,"
        "supports_standalone_web_search=true"
        "}"
    )
    return [
        "-c",
        f"model_provider={json.dumps(_REQUEST_TAP_PROVIDER_ID)}",
        "-c",
        provider,
        "-c",
        "features.enable_request_compression=false",
    ]


def _error_record(error: BaseException) -> dict[str, str]:
    return {"type": type(error).__name__, "message": redact_text(str(error))}


def _os_audit_known_loss(stats: Mapping[str, Any]) -> bool:
    return bool(
        stats.get("known_loss")
        or stats.get("limit_reached")
        or stats.get("dropped")
        or stats.get("parse_errors")
        or stats.get("unfinished_pending")
        or stats.get("reader_error")
    )


def _os_audit_runtime_loss(stats: Mapping[str, Any]) -> bool:
    """Loss signals safe to interpret before strace has reached EOF."""

    return bool(
        stats.get("limit_reached")
        or stats.get("dropped")
        or stats.get("parse_errors")
        or stats.get("reader_error")
    )


def _resolve_codex_bin(value: str) -> str:
    """Resolve one executable path so monitor and attach use the same binary."""

    if not value:
        raise MonitorError("--codex-bin cannot be empty")
    has_separator = os.sep in value or bool(os.altsep and os.altsep in value)
    if has_separator:
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        found = shutil.which(os.fspath(candidate))
    else:
        found = shutil.which(value)
    if found is None:
        raise MonitorError(f"cannot find executable for --codex-bin: {value}")
    return os.fspath(Path(found).resolve())


def _is_within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _private_monitor_runtime(repo: Path) -> Path:
    """Create monitor sockets outside the observed workspace."""

    candidates = [Path(tempfile.gettempdir()), Path("/tmp"), Path("/var/tmp")]
    for base in candidates:
        try:
            resolved = base.expanduser().resolve()
        except OSError:
            continue
        if _is_within(resolved, repo) or not resolved.is_dir():
            continue
        created = Path(tempfile.mkdtemp(prefix="codexscope-monitor-", dir=resolved))
        created.chmod(0o700)
        return created
    raise MonitorError("cannot create a private monitor runtime outside the workspace")


def _request_key(connection_id: str, value: Any) -> tuple[str, str, int | str] | None:
    if isinstance(value, str):
        return connection_id, "str", value
    if type(value) is int:
        return connection_id, "int", value
    return None


def _prompt_metadata(params: Mapping[str, Any]) -> dict[str, Any]:
    hashes: list[str] = []
    lengths: list[int] = []
    for item in params.get("input") or []:
        if not isinstance(item, Mapping):
            continue
        text = item.get("text")
        if not isinstance(text, str):
            continue
        hashes.append(hashlib.sha256(text.encode("utf-8")).hexdigest())
        lengths.append(len(text))
    if not hashes:
        return {}
    aggregate = hashlib.sha256("\x1f".join(hashes).encode("ascii")).hexdigest()
    return {
        "prompt_sha256": hashes[0] if len(hashes) == 1 else aggregate,
        "prompt_part_sha256s": hashes,
        "prompt_length": sum(lengths),
    }


def _prompt_text(params: Mapping[str, Any]) -> str:
    parts = [
        str(item.get("text"))
        for item in params.get("input") or []
        if isinstance(item, Mapping) and isinstance(item.get("text"), str)
    ]
    return "\n".join(parts)


def _runtime_policy_observation(
    decisions: Sequence[Mapping[str, Any]],
    *,
    security_mode: str,
) -> dict[str, Any] | None:
    merged = merge_policy_decisions(decisions)
    if not merged:
        return None
    rank = {"normal": 0, "notice": 1, "warning": 2, "high": 3, "critical": 4}
    level = max(
        (str(decision.get("level") or "warning") for decision in merged),
        key=lambda value: rank.get(value, 0),
    )
    return {
        "policy_id": POLICY_ID,
        "mode": security_mode,
        "action": "record",
        "stage": str(merged[0].get("stage") or "runtime_observation"),
        "matched_rules": [str(decision["policy_id"]) for decision in merged],
        "policy_decisions": merged,
        "risk": {
            "level": level,
            "reasons": [
                str(decision.get("reason"))[:160]
                for decision in merged
                if str(decision.get("reason") or "").strip()
            ][:12],
        },
    }


def _store_private_text(
    target: dict[str, Any],
    key: str,
    value: Any,
    *,
    include_sensitive: bool,
) -> None:
    """Store a conversational label according to the trace privacy policy."""

    if value is None:
        target.pop(key, None)
        target.pop(f"{key}_sha256", None)
        target.pop(f"{key}_length", None)
        return
    if not isinstance(value, str):
        return
    if include_sensitive:
        target[key] = redact_text(value)
        return
    target.pop(key, None)
    target[f"{key}_sha256"] = hashlib.sha256(value.encode("utf-8")).hexdigest()
    target[f"{key}_length"] = len(value)


def workspace_metadata(repo: Path) -> dict[str, Any]:
    """Capture useful Git identity without requiring a clean Git root."""

    repo = repo.expanduser().resolve()
    if not repo.is_dir():
        raise NotADirectoryError(repo)
    result: dict[str, Any] = {
        "repo": os.fspath(repo),
        "git_available": False,
        "git_root": None,
        "git_head": None,
        "git_branch": None,
        "git_status_before": None,
    }
    try:
        top = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=repo,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout.strip()
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout.strip()
        branch = subprocess.run(
            ["git", "branch", "--show-current"],
            cwd=repo,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout.strip()
        status_text = subprocess.run(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"],
            cwd=repo,
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return result
    result.update(
        {
            "git_available": True,
            "git_root": os.fspath(Path(top).resolve()),
            "git_head": head,
            "git_branch": branch,
            "git_status_before": status_text,
        }
    )
    return result


def default_run_dir(repo: Path) -> Path:
    state_root_value = os.environ.get("XDG_STATE_HOME")
    state_root = (
        Path(state_root_value).expanduser()
        if state_root_value
        else Path.home() / ".local" / "state"
    )
    parent = state_root / "codexscope" / "runs"
    repo = repo.expanduser().resolve()
    try:
        parent.resolve().relative_to(repo)
    except ValueError:
        pass
    else:
        uid = os.getuid() if hasattr(os, "getuid") else "user"
        parent = Path(tempfile.gettempdir()) / f"codexscope-runs-{uid}"
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return parent / f"interactive-{stamp}-{uuid.uuid4().hex[:8]}"


def _runtime_registry_dir() -> Path:
    configured = os.environ.get("XDG_RUNTIME_DIR")
    uid = os.getuid() if hasattr(os, "getuid") else "user"
    root = (
        Path(configured).expanduser() / "codexscope"
        if configured
        else Path(tempfile.gettempdir()) / f"codexscope-{uid}"
    )
    if root.exists() and root.is_symlink():
        raise MonitorError(f"refusing symlink runtime directory: {root}")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = root.stat()
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise MonitorError(f"runtime directory is owned by another user: {root}")
    root.chmod(0o700)
    return root


def active_monitor_path() -> Path:
    return _runtime_registry_dir() / "active.json"


def _acquire_monitor_lock() -> int:
    """Hold the per-user monitor ownership lock for one process lifetime."""

    path = _runtime_registry_dir() / "monitor.lock"
    flags = os.O_CREAT | os.O_RDWR
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise MonitorError(f"cannot open monitor ownership lock: {path}") from exc
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise MonitorError(f"monitor ownership lock is not a regular file: {path}")
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise MonitorError(f"monitor ownership lock is owned by another user: {path}")
        os.fchmod(fd, 0o600)
        try:
            import fcntl
        except ImportError as exc:  # pragma: no cover - monitor is Unix-only
            raise MonitorError("interactive monitor locking requires fcntl") from exc
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise MonitorError(
                "another CodexScope monitor is already active for this user"
            ) from exc
    except BaseException:
        os.close(fd)
        raise
    return fd


def _monitor_lock_is_held() -> bool:
    """Return whether another process currently owns the monitor lock."""

    path = _runtime_registry_dir() / "monitor.lock"
    flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise MonitorError(f"cannot inspect monitor ownership lock: {path}") from exc
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise MonitorError(f"monitor ownership lock is not a regular file: {path}")
        try:
            import fcntl
        except ImportError as exc:  # pragma: no cover - monitor is Unix-only
            raise MonitorError("interactive monitor locking requires fcntl") from exc
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    finally:
        os.close(fd)


def _pid_is_live(value: Any) -> bool:
    if type(value) is not int or value <= 0:
        return False
    try:
        os.kill(value, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def read_active_monitor() -> dict[str, Any]:
    path = active_monitor_path()
    if not path.exists():
        raise MonitorError("no active CodexScope monitor; start `codexscope monitor` first")
    if path.is_symlink():
        raise MonitorError(f"refusing symlink monitor registry: {path}")
    value = json_load(path)
    if not isinstance(value, dict):
        raise MonitorError(f"invalid monitor registry: {path}")
    if not _monitor_lock_is_held() or not _pid_is_live(value.get("pid")):
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise MonitorError("the registered CodexScope monitor is no longer running")
    endpoint = value.get("endpoint")
    if not isinstance(endpoint, str) or not endpoint.startswith("unix://"):
        raise MonitorError(f"invalid monitor endpoint in {path}")
    socket_path = Path(endpoint.removeprefix("unix://"))
    try:
        socket_info = socket_path.stat()
    except OSError as exc:
        raise MonitorError(f"active monitor socket is unavailable: {socket_path}") from exc
    if not stat.S_ISSOCK(socket_info.st_mode):
        raise MonitorError(f"active monitor endpoint is not a Unix socket: {socket_path}")
    if hasattr(os, "getuid") and socket_info.st_uid != os.getuid():
        raise MonitorError(f"active monitor socket is owned by another user: {socket_path}")
    return value


def attach_command(
    registry: Mapping[str, Any], extra_args: Sequence[str] = ()
) -> list[str]:
    codex_bin = str(registry.get("codex_bin") or "codex")
    endpoint = str(registry["endpoint"])
    repo = str(registry["repo"])
    values = list(extra_args)
    if values[:1] == ["--"]:
        values = values[1:]
    return [codex_bin, "--remote", endpoint, "-C", repo, *values]


def attach_environment(
    registry: Mapping[str, Any],
    base_environment: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Pass the monitor's private Lingmou feed to an aware Codex TUI."""

    environment = dict(os.environ if base_environment is None else base_environment)
    # Never leak a feed from a previously attached monitor into this process.
    environment.pop(LINGMOU_SECURITY_PATH_ENV, None)
    raw_path = registry.get("lingmou_security_path")
    if isinstance(raw_path, str) and raw_path.strip():
        path = Path(raw_path).expanduser()
        if path.is_absolute():
            environment[LINGMOU_SECURITY_PATH_ENV] = os.fspath(path)
    return environment


def _remove_registry(run_id: str) -> None:
    path = active_monitor_path()
    try:
        current = json_load(path)
    except (FileNotFoundError, ValueError, json.JSONDecodeError):
        return
    if isinstance(current, dict) and current.get("run_id") == run_id:
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def _clear_stale_registry(path: Path) -> None:
    """Remove an old registry after the lifetime ownership lock is acquired."""

    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(metadata.st_mode):
        raise MonitorError(f"refusing symlink monitor registry: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise MonitorError(f"monitor registry is not a regular file: {path}")
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise MonitorError(f"monitor registry is owned by another user: {path}")
    path.unlink()


def _is_surfaced_reasoning_message(message: Mapping[str, Any]) -> bool:
    """Return whether app-server explicitly labels this as reasoning output.

    This is deliberately narrow.  Enabling it retains only reasoning fields
    that Codex chose to expose through the public protocol; it neither asks
    for nor claims access to a model's hidden chain-of-thought.
    """

    method = message.get("method")
    if isinstance(method, str) and method.startswith("item/reasoning/"):
        return True
    if method not in {"item/started", "item/completed"}:
        return False
    params = message.get("params")
    if not isinstance(params, Mapping):
        return False
    item = params.get("item")
    return isinstance(item, Mapping) and item.get("type") == "reasoning"


class GatewayRecorder:
    """Persist gateway envelopes while keeping forwarded messages untouched."""

    def __init__(
        self,
        path: Path,
        *,
        include_sensitive: bool,
        capture_surfaced_reasoning: bool = False,
    ) -> None:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        flags |= getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags, 0o600)
        os.fchmod(fd, 0o600)
        self._fp = os.fdopen(
            fd,
            "w",
            encoding="utf-8",
            errors="backslashreplace",
            buffering=1,
        )
        self.include_sensitive = include_sensitive
        self.capture_surfaced_reasoning = capture_surfaced_reasoning
        self.closed = False

    def write(self, envelope: Mapping[str, Any]) -> None:
        if self.closed:
            raise RuntimeError("gateway recorder is closed")
        row = dict(envelope)
        message = row.get("message")
        if not isinstance(message, dict):
            raise TypeError("gateway envelope message must be an object")
        include_message_text = self.include_sensitive or (
            self.capture_surfaced_reasoning
            and row.get("direction") == "server_to_client"
            and _is_surfaced_reasoning_message(message)
        )
        row["message"] = capture_transform(
            copy.deepcopy(message), include_sensitive=include_message_text
        )
        self._fp.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self._fp.close()


@dataclass(slots=True)
class InteractiveState:
    include_sensitive: bool = False
    pending: dict[
        tuple[str, str, int | str], tuple[str, dict[str, Any], dict[str, Any]]
    ] = field(default_factory=dict)
    threads: dict[str, dict[str, Any]] = field(default_factory=dict)
    turns: dict[str, dict[str, Any]] = field(default_factory=dict)
    connections: list[dict[str, Any]] = field(default_factory=list)
    active_turns: set[str] = field(default_factory=set)
    message_count: int = 0
    connected_once: bool = False
    last_token_usage: dict[str, Any] | None = None

    def connection_started(self, event: Mapping[str, Any]) -> None:
        self.connected_once = True
        self.connections.append(
            {
                "connection_id": event.get("connection_id"),
                "connected_at": event.get("wall_time") or now_iso(),
                "disconnected_at": None,
                "status": "connected",
            }
        )

    def connection_stopped(self, event: Mapping[str, Any]) -> None:
        connection_id = event.get("connection_id")
        for connection in reversed(self.connections):
            if connection.get("connection_id") == connection_id:
                connection["disconnected_at"] = event.get("wall_time") or now_iso()
                connection["status"] = "disconnected"
                if event.get("error"):
                    connection["error"] = redact_text(str(event.get("error")))
                break

    def consume(self, envelope: Mapping[str, Any]) -> bool:
        self.message_count += 1
        message = envelope.get("message")
        if not isinstance(message, dict):
            return False
        connection_id = str(envelope.get("connection_id") or "legacy")
        direction = envelope.get("direction")
        method = message.get("method")
        key = _request_key(connection_id, message.get("id"))
        important = False

        if direction == "client_to_server" and isinstance(method, str):
            params = message.get("params")
            params = dict(params) if isinstance(params, Mapping) else {}
            if key is not None:
                prompt = _prompt_metadata(params)
                if method in {"turn/start", "turn/steer"}:
                    prompt["requested_at_seq"] = envelope.get("seq")
                self.pending[key] = (method, params, prompt)
            if method in {"turn/start", "turn/steer", "turn/interrupt"}:
                important = True
            return important

        if direction != "server_to_client":
            return important

        if key is not None and not isinstance(method, str):
            pending = self.pending.pop(key, None)
            if pending is None:
                return important
            request_method, request_params, prompt = pending
            result = message.get("result")
            result = result if isinstance(result, Mapping) else {}
            if request_method in {"thread/start", "thread/resume", "thread/fork"}:
                thread = result.get("thread")
                if isinstance(thread, Mapping) and thread.get("id"):
                    thread_id = str(thread["id"])
                    current = {
                        "id": thread_id,
                        "status": thread.get("status"),
                        "model": result.get("model") or request_params.get("model"),
                        "model_provider": result.get("modelProvider"),
                        "approval_policy": result.get("approvalPolicy")
                        or request_params.get("approvalPolicy"),
                        "sandbox": result.get("sandbox") or request_params.get("sandbox"),
                    }
                    if "name" in thread:
                        _store_private_text(
                            current,
                            "name",
                            thread.get("name"),
                            include_sensitive=self.include_sensitive,
                        )
                    self.threads[thread_id] = current
                    important = True
            elif request_method == "turn/start":
                turn = result.get("turn")
                if isinstance(turn, Mapping) and turn.get("id"):
                    turn_id = str(turn["id"])
                    current = self.turns.setdefault(
                        turn_id,
                        {
                            "id": turn_id,
                            "thread_id": request_params.get("threadId"),
                        },
                    )
                    current.setdefault("status", turn.get("status") or "pending")
                    current["response_at_seq"] = envelope.get("seq")
                    current.update(prompt)
                    important = True
            elif request_method == "turn/steer":
                turn_value = result.get("turnId") or request_params.get("turnId")
                if turn_value is not None:
                    turn_id = str(turn_value)
                    current = self.turns.setdefault(
                        turn_id,
                        {
                            "id": turn_id,
                            "thread_id": request_params.get("threadId"),
                        },
                    )
                    steering = dict(prompt)
                    steering["response_at_seq"] = envelope.get("seq")
                    current.setdefault("steering_prompts", []).append(steering)
                    important = True
            return important

        params = message.get("params")
        params = params if isinstance(params, Mapping) else {}
        if method == "thread/started":
            thread = params.get("thread")
            if isinstance(thread, Mapping) and thread.get("id"):
                thread_id = str(thread["id"])
                current = self.threads.setdefault(thread_id, {"id": thread_id})
                if "status" in thread:
                    current["status"] = thread.get("status")
                if "name" in thread:
                    _store_private_text(
                        current,
                        "name",
                        thread.get("name"),
                        include_sensitive=self.include_sensitive,
                    )
                important = True
        elif method == "thread/name/updated":
            thread_value = params.get("threadId")
            if thread_value is not None:
                thread_id = str(thread_value)
                current = self.threads.setdefault(thread_id, {"id": thread_id})
                _store_private_text(
                    current,
                    "name",
                    params.get("threadName")
                    if params.get("threadName") is not None
                    else params.get("name"),
                    include_sensitive=self.include_sensitive,
                )
                important = True
        elif method == "turn/started":
            turn = params.get("turn")
            if isinstance(turn, Mapping) and turn.get("id"):
                turn_id = str(turn["id"])
                current = self.turns.setdefault(
                    turn_id,
                    {"id": turn_id, "thread_id": params.get("threadId")},
                )
                current.update(
                    {
                        "status": turn.get("status") or "inProgress",
                        "started_at_seq": envelope.get("seq"),
                    }
                )
                self.active_turns.add(turn_id)
                important = True
        elif method == "turn/completed":
            turn = params.get("turn")
            if isinstance(turn, Mapping) and turn.get("id"):
                turn_id = str(turn["id"])
                current = self.turns.setdefault(
                    turn_id,
                    {"id": turn_id, "thread_id": params.get("threadId")},
                )
                current.update(
                    {
                        "status": turn.get("status"),
                        "duration_ms": turn.get("durationMs"),
                        "completed_at_seq": envelope.get("seq"),
                    }
                )
                if turn.get("error") is not None:
                    current["error"] = redact_event(turn.get("error"))
                self.active_turns.discard(turn_id)
                important = True
        elif method == "thread/tokenUsage/updated":
            usage = params.get("tokenUsage")
            if isinstance(usage, Mapping):
                cleaned = redact_event(dict(usage))
                self.last_token_usage = cleaned if isinstance(cleaned, dict) else None
                important = True
        return important

    def apply_manifest(self, manifest: dict[str, Any]) -> None:
        threads = list(self.threads.values())
        turns = list(self.turns.values())
        manifest["connections"] = self.connections
        manifest["threads"] = threads
        manifest["turns"] = turns
        manifest["message_count"] = self.message_count
        manifest["active_turn_ids"] = sorted(self.active_turns)
        if self.last_token_usage is not None:
            manifest["last_token_usage"] = self.last_token_usage
        if threads:
            latest_thread = threads[-1]
            manifest["thread_id"] = latest_thread.get("id")
            manifest["model_resolved"] = latest_thread.get("model")
            manifest["effective_approval_policy"] = latest_thread.get("approval_policy")
            manifest["effective_sandbox_policy"] = latest_thread.get("sandbox")
        if turns:
            latest_turn = turns[-1]
            manifest["turn_id"] = latest_turn.get("id")
            manifest["turn_status"] = latest_turn.get("status")
            prompt_entries: list[dict[str, Any]] = []
            for turn in turns:
                if turn.get("prompt_sha256"):
                    prompt_entries.append(turn)
                prompt_entries.extend(
                    entry
                    for entry in turn.get("steering_prompts") or []
                    if isinstance(entry, dict) and entry.get("prompt_sha256")
                )
            if prompt_entries:
                manifest["prompt_sha256"] = prompt_entries[0]["prompt_sha256"]
                manifest["prompt_length"] = prompt_entries[0].get("prompt_length")
                manifest["turn_prompt_sha256s"] = [
                    entry["prompt_sha256"] for entry in prompt_entries
                ]
                manifest["steering_prompt_count"] = sum(
                    len(turn.get("steering_prompts") or []) for turn in turns
                )


class LivePrinter:
    """Stdout event log + single-line live token/activity status bar."""

    def __init__(self, live: LiveSessionStatus | None = None) -> None:
        self.live = live if live is not None else LiveSessionStatus()
        self._status_dirty = False
        self._last_status_line = ""
        self._approval_methods = {
            "item/commandExecution/requestApproval",
            "item/fileChange/requestApproval",
            "item/permissions/requestApproval",
            "execCommandApproval",
            "applyPatchApproval",
        }

    def _clear_status_line(self) -> None:
        if not self._status_dirty:
            return
        # Move to line start, erase to end of line, then emit a normal log line.
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()
        self._status_dirty = False

    def _emit_log(self, text: str) -> None:
        self._clear_status_line()
        print(text, flush=True)
        self.render_status(force=True)

    def render_status(self, *, force: bool = False) -> None:
        line = self.live.format_line()
        if not force and line == self._last_status_line:
            return
        self._last_status_line = line
        # Carriage-return status bar (does not scroll the event log).
        sys.stdout.write(f"\r\033[K{line}")
        sys.stdout.flush()
        self._status_dirty = True

    def message(self, envelope: Mapping[str, Any]) -> None:
        message = envelope.get("message")
        if not isinstance(message, Mapping):
            return
        method = message.get("method")
        params = message.get("params")
        params = params if isinstance(params, Mapping) else {}
        prefix = f"[{datetime.now().strftime('%H:%M:%S')}]"
        if envelope.get("direction") == "client_to_server" and method == "turn/start":
            self._emit_log(f"{prefix} turn requested")
        elif method == "turn/started":
            turn = params.get("turn") if isinstance(params.get("turn"), Mapping) else {}
            self._emit_log(f"{prefix} turn started  {turn.get('id', '')}")
        elif method == "turn/completed":
            turn = params.get("turn") if isinstance(params.get("turn"), Mapping) else {}
            self._emit_log(
                f"{prefix} turn {turn.get('status', 'completed')}  {turn.get('id', '')}"
            )
        elif method == "item/started":
            item = params.get("item") if isinstance(params.get("item"), Mapping) else {}
            item_type = item.get("type")
            if item_type not in {"userMessage", "agentMessage", "reasoning"}:
                self._emit_log(f"{prefix} item started  {item_type or 'unknown'}")
            else:
                self.render_status()
        elif method == "item/completed":
            item = params.get("item") if isinstance(params.get("item"), Mapping) else {}
            item_type = item.get("type")
            if item_type not in {"userMessage", "agentMessage", "reasoning"}:
                self._emit_log(
                    f"{prefix} item {item.get('status', 'completed')}  {item_type or 'unknown'}"
                )
            else:
                self.render_status()
        elif method in self._approval_methods:
            self._emit_log(f"{prefix} approval requested  {method}")
        elif method == "thread/tokenUsage/updated":
            # Token ticks update the status bar only (high frequency).
            self.render_status(force=True)
        elif method in MODEL_OUTPUT_DELTA_METHODS:
            # The estimator changes on every model delta, independently of
            # the provider's eventual tokenUsage notification.
            self.render_status(force=True)


async def _wait_for_socket(
    process: asyncio.subprocess.Process,
    path: Path,
    *,
    stop_event: asyncio.Event | None = None,
) -> None:
    deadline = asyncio.get_running_loop().time() + _STARTUP_TIMEOUT_SECONDS
    while asyncio.get_running_loop().time() < deadline:
        if stop_event is not None and stop_event.is_set():
            raise _MonitorStartupStopped
        if process.returncode is not None:
            raise MonitorError(
                f"codex app-server exited during startup with status {process.returncode}"
            )
        try:
            mode = path.stat().st_mode
        except FileNotFoundError:
            pass
        else:
            if stat.S_ISSOCK(mode):
                return
        await asyncio.sleep(0.05)
    raise MonitorError(f"timed out waiting for app-server socket: {path}")


async def _stop_process(
    process: asyncio.subprocess.Process, *, process_group: bool = False
) -> None:
    """Stop the app server and, for traced sessions, its whole private group."""

    if not process_group:
        if process.returncode is not None:
            return
        process.terminate()
        try:
            await asyncio.wait_for(
                process.wait(), timeout=_PROCESS_STOP_TIMEOUT_SECONDS
            )
            return
        except asyncio.TimeoutError:
            process.kill()
        await process.wait()
        return

    pid = getattr(process, "pid", None)
    if type(pid) is not int or pid <= 0:
        raise MonitorError("traced app-server process has no valid process-group id")
    try:
        os.killpg(pid, signal.SIGTERM)
    except ProcessLookupError:
        if process.returncode is None:
            await asyncio.wait_for(
                process.wait(), timeout=_PROCESS_STOP_TIMEOUT_SECONDS
            )
        return

    deadline = asyncio.get_running_loop().time() + _PROCESS_STOP_TIMEOUT_SECONDS
    if process.returncode is None:
        try:
            await asyncio.wait_for(
                process.wait(),
                timeout=max(0.0, deadline - asyncio.get_running_loop().time()),
            )
        except asyncio.TimeoutError:
            pass

    # The wrapper (strace) can exit before one of its tracees.  Give the whole
    # group the remainder of the TERM grace period rather than treating the
    # leader's exit as proof that every descendant is gone.
    while asyncio.get_running_loop().time() < deadline:
        try:
            os.killpg(pid, 0)
        except ProcessLookupError:
            return
        except PermissionError:
            # It still exists; the final SIGKILL below will surface any real
            # permission failure to the caller.
            pass
        await asyncio.sleep(0.05)

    # Address the original private session/process-group ID, not just the
    # leader process object, so tracees that ignored SIGTERM cannot leak.
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    if process.returncode is None:
        await process.wait()


async def monitor_codex(
    *,
    repo: Path,
    run_dir: Path | None = None,
    codex_bin: str = "codex",
    include_sensitive: bool = False,
    capture_schema: bool = True,
    function_trace: str = "off",
    function_max_calls: int = 100_000,
    file_audit: str = "off",
    file_audit_max_events: int = 100_000,
    os_audit: str = "off",
    os_audit_max_events: int = 200_000,
    os_audit_profile: str = "behavior",
    harness_telemetry: str = "off",
    harness_telemetry_max_events: int = 100_000,
    security_policy: str = "observe",
    capture_surfaced_reasoning: bool = False,
    request_token_tap_upstream: str | None = None,
    input_compression: str = "off",
    frontend_socket: Path | None = None,
    once: bool = False,
    external_stop: asyncio.Event | None = None,
) -> Path:
    """Monitor a normal remote Codex TUI and build a processed-run layout."""

    lock_fd = _acquire_monitor_lock()
    try:
        resolved_codex_bin = _resolve_codex_bin(codex_bin)
        return await _monitor_codex_locked(
            repo=repo,
            run_dir=run_dir,
            codex_bin=resolved_codex_bin,
            include_sensitive=include_sensitive,
            capture_schema=capture_schema,
            function_trace=function_trace,
            function_max_calls=function_max_calls,
            file_audit=file_audit,
            file_audit_max_events=file_audit_max_events,
            os_audit=os_audit,
            os_audit_max_events=os_audit_max_events,
            os_audit_profile=os_audit_profile,
            harness_telemetry=harness_telemetry,
            harness_telemetry_max_events=harness_telemetry_max_events,
            security_policy=security_policy,
            capture_surfaced_reasoning=capture_surfaced_reasoning,
            request_token_tap_upstream=request_token_tap_upstream,
            input_compression=input_compression,
            frontend_socket=frontend_socket,
            once=once,
            external_stop=external_stop,
        )
    finally:
        os.close(lock_fd)


async def _monitor_codex_locked(
    *,
    repo: Path,
    run_dir: Path | None = None,
    codex_bin: str = "codex",
    include_sensitive: bool = False,
    capture_schema: bool = True,
    function_trace: str = "off",
    function_max_calls: int = 100_000,
    file_audit: str = "off",
    file_audit_max_events: int = 100_000,
    os_audit: str = "off",
    os_audit_max_events: int = 200_000,
    os_audit_profile: str = "behavior",
    harness_telemetry: str = "off",
    harness_telemetry_max_events: int = 100_000,
    security_policy: str = "observe",
    capture_surfaced_reasoning: bool = False,
    request_token_tap_upstream: str | None = None,
    input_compression: str = "off",
    frontend_socket: Path | None = None,
    once: bool = False,
    external_stop: asyncio.Event | None = None,
) -> Path:
    """Implementation entered only while the per-user lock is held."""

    repo = repo.expanduser().resolve()
    if not repo.is_dir():
        raise NotADirectoryError(repo)
    if file_audit not in {"off", "auto", "inotify"}:
        raise ValueError("file_audit must be 'off', 'auto', or 'inotify'")
    if not 1 <= file_audit_max_events <= 10_000_000:
        raise ValueError("file_audit_max_events must be between 1 and 10000000")
    if os_audit not in {"off", "auto", "strace"}:
        raise ValueError("os_audit must be 'off', 'auto', or 'strace'")
    if not 1 <= os_audit_max_events <= 10_000_000:
        raise ValueError("os_audit_max_events must be between 1 and 10000000")
    if os_audit_profile not in {"behavior", "focused", "full"}:
        raise ValueError("os_audit_profile must be 'behavior', 'focused', or 'full'")
    if harness_telemetry not in {"off", "auto", "otel"}:
        raise ValueError("harness_telemetry must be 'off', 'auto', or 'otel'")
    if not 1 <= harness_telemetry_max_events <= 10_000_000:
        raise ValueError(
            "harness_telemetry_max_events must be between 1 and 10000000"
        )
    if security_policy not in {"observe", "enforce"}:
        raise ValueError("security_policy must be 'observe' or 'enforce'")
    if input_compression not in COMPRESSION_MODES:
        raise ValueError("input_compression must be one of " + ', '.join(COMPRESSION_MODES))
    if input_compression != "off" and request_token_tap_upstream is None:
        raise ValueError("input compression requires --request-token-tap-upstream")
    stop_event = external_stop or asyncio.Event()
    registry_path = active_monitor_path()
    # The flock held by the public wrapper is the ownership authority.  A
    # registry left after SIGKILL is stale even if its PID has since been
    # reused by an unrelated process.
    _clear_stale_registry(registry_path)

    if frontend_socket is not None:
        requested_socket = frontend_socket.expanduser().resolve()
        if requested_socket.exists() or requested_socket.is_symlink():
            raise MonitorError(
                f"frontend socket path already exists: {requested_socket}"
            )
        if len(os.fsencode(requested_socket)) > 100:
            raise MonitorError(
                f"frontend Unix socket path is too long "
                f"({len(os.fsencode(requested_socket))} bytes): {requested_socket}"
            )
        if file_audit != "off" and _is_within(requested_socket, repo):
            raise MonitorError(
                "--socket must be outside the observed workspace when file audit is enabled"
            )

    target = (run_dir or default_run_dir(repo)).expanduser().resolve()
    layout = RunLayout.create(target, repo=repo)
    if stop_event.is_set():
        # A caller may hand in an already-set event.  Create a minimal,
        # well-formed interrupted run without invoking Git, scanning the
        # workspace, or starting any process/socket.
        metadata = {
            "repo": os.fspath(repo),
            "git_available": False,
            "git_root": None,
            "git_head": None,
            "git_branch": None,
            "git_status_before": None,
            "workspace_metadata_skipped": "stop_requested_before_startup",
        }
    else:
        metadata = await asyncio.to_thread(workspace_metadata, repo)
    trace_config = FunctionTraceConfig(
        mode=function_trace,
        max_calls_per_process=function_max_calls,
        max_records_per_run=max(10_000, min(2_000_000, function_max_calls * 4)),
    )
    started_mono_ns = time.monotonic_ns()
    run_id = str(uuid.uuid4())
    manifest: dict[str, Any] = {
        "schema_version": "1.1",
        "run_id": run_id,
        "capture_mode": "interactive_monitor",
        "status": "starting",
        "created_at": now_iso(),
        "started_at": now_iso(),
        "runtime": runtime_metadata(),
        **metadata,
        "codex_bin": codex_bin,
        "codex_version": None,
        "model_requested": None,
        "model_resolved": None,
        "approval_policy": "interactive_tui",
        "sandbox_policy": "selected_by_tui",
        "security_policy": {
            "mode": security_policy,
            "policy_id": POLICY_ID,
            "threshold": "high",
            "enforcement_stage": ENFORCEMENT_STAGE,
            "fail_mode": "forward_to_codex_approval_ui",
            "coverage": "command_and_file_approval_requests_plus_runtime_observation",
            "rules": [
                {
                    "id": policy["id"],
                    "label": policy["name"],
                    "condition": policy["action"],
                    "effect": policy["mode"],
                }
                for policy in load_local_policies()
            ]
            + list(PAYMENT_POLICY_RULES),
        },
        "privacy": {
            "include_sensitive": include_sensitive,
            "conversation_text": (
                "retained_after_credential_redaction"
                if include_sensitive
                else "omitted_with_hashes_and_lengths"
            ),
            "surfaced_reasoning": (
                "retained_after_credential_redaction"
                if capture_surfaced_reasoning
                else "omitted"
            ),
            "credentials": "recursively_redacted",
        },
        "reasoning_capture": {
            "requested": bool(capture_surfaced_reasoning),
            "enabled": bool(capture_surfaced_reasoning),
            "mode": (
                "surfaced_reasoning_only"
                if capture_surfaced_reasoning
                else "disabled"
            ),
            "surfaced_reasoning_only": bool(capture_surfaced_reasoning),
            "hidden_chain_of_thought": False,
            "credentials": "recursively_redacted",
            "limitations": [
                "only_reasoning_events_exposed_by_codex_app_server",
                "does_not_capture_hidden_model_chain_of_thought",
            ],
        },
        "request_token_tap": {
            "input_compression_mode": input_compression,
            "retained_reference_sources": ('compression_sources' if input_compression in {'extract', 'jev', 'kimi', 'llmlingua2'} else None),
            "requested": request_token_tap_upstream is not None,
            "enabled": False,
            "status": (
                "pending" if request_token_tap_upstream is not None else "disabled"
            ),
            "request_body_persistence": False,
            "credential_persistence": False,
            "bind_host": "127.0.0.1",
            "multimodal_provider_preflight": "parallel_best_effort",
            "multimodal_breakdown": "provider_differential",
            "limitations": [
                "provider_final_usage_remains_authoritative",
                "multimodal_is_partial_when_provider_count_is_unavailable",
                "modality_breakdown_is_derived_not_provider_itemized",
                "direct_upstream_connection_does_not_apply_system_proxy",
            ],
        },
        "protocol_schema": {"captured": False, "pending": bool(capture_schema)},
        "function_trace": {
            "requested": trace_config.mode,
            "enabled": trace_config.enabled,
            "languages": list(trace_config.languages),
            "raw_schema": "codexscope.function_trace.v1",
            "max_calls_per_process": trace_config.max_calls_per_process,
            "max_records_per_run": trace_config.max_records_per_run,
            "max_bytes_per_run": trace_config.max_bytes_per_run,
            "trust": "instrumented_process_self_report; peer_pid_when_supported",
            "tamper_resistant": False,
        },
        "harness_telemetry": {
            "requested": harness_telemetry,
            "enabled": False,
            "status": "disabled" if harness_telemetry == "off" else "pending",
            "backend": None,
            "raw_schema": "codexscope.otel.trace.v1",
            "max_events": harness_telemetry_max_events,
            "bind_host": "127.0.0.1",
            "transport": "otlp_http_json",
            "codex_exporters": {
                "traces": "trace_safe_only",
                "logs": "disabled",
                "metrics": "disabled",
            },
            "content_capture": False,
            "unknown_attributes_persisted": False,
            "trust": "codex_open_source_harness_self_report",
            "tamper_resistant": False,
            "limitations": [
                "does_not_replace_app_server_or_os_evidence",
                "does_not_capture_prompts_tool_arguments_or_tool_output",
                "trace_events_can_be_lost_at_configured_or_storage_limits",
                "requires_a_codex_build_with_otlp_http_trace_export_support",
            ],
        },
        "file_audit": {
            "requested": file_audit,
            "enabled": False,
            "status": "disabled" if file_audit == "off" else "pending",
            "backend": None,
            "raw_schema": "codexscope.filesystem.v1",
            "max_events": file_audit_max_events,
            "scope": "workspace_recursive_filtered",
            "content_capture": False,
            "process_identity": False,
            "trust": "kernel_inotify_notification_without_pid_or_causal_attribution",
            "tamper_resistant": False,
            "snapshot_windows": 0,
            "snapshot_windows_empty": 0,
            "snapshot_windows_failed": 0,
            "snapshot_windows_dropped": 0,
            "recent_snapshot_windows": [],
            "limitations": [
                "no_pid_or_syscall_identity",
                "new_directory_watch_installation_race",
                "kernel_queue_can_overflow",
                "ignored_cache_dependency_and_build_directories_are_excluded",
            ],
        },
        "os_audit": {
            "requested": os_audit,
            "enabled": False,
            "status": "disabled" if os_audit == "off" else "pending",
            "backend": None,
            "raw_schema": "codexscope.os_audit.v1",
            "max_events": os_audit_max_events,
            "trace_profile": os_audit_profile,
            "scope": "appserver_descendant_process_tree",
            "capabilities": {
                "pid": True,
                "syscall": True,
                "read_access": True,
                "network_activity": True,
            },
            "process_identity": False,
            "syscalls": False,
            "read_access": False,
            "network_activity": False,
            "appserver_descendants_created_after_start": True,
            "preexisting_external_processes": False,
            "unrelated_external_processes": False,
            "content_capture": False,
            "trust": "strace_ptrace_observation_of_appserver_descendant_processes",
            "tamper_resistant": False,
            "limitations": [
                "does_not_observe_processes_outside_the_appserver_descendant_tree",
                "does_not_observe_external_processes_that_existed_before_appserver_start",
                "cannot_recover_hidden_model_chain_of_thought",
                "strace_can_add_runtime_overhead",
                "events_can_be_lost_at_configured_or_storage_limits",
                "encrypted_network_payloads_are_not_decrypted",
            ],
            "intentional_filtering": os_audit_profile == "behavior",
        },
    }
    atomic_json_dump(layout.manifest, manifest)

    recorder: GatewayRecorder | None = None
    snapshots: SnapshotManager | None = None
    function_collector: FunctionTraceCollector | None = None
    file_observer: InotifyWorkspaceObserver | None = None
    os_audit_collector: StraceAuditCollector | None = None
    otel_trace_collector: OtelTraceCollector | None = None
    request_token_tap: RequestTokenTap | None = None
    appserver_process_group = False
    gateway: UnixSocketGateway | None = None
    appserver: asyncio.subprocess.Process | None = None
    appserver_watch: asyncio.Task[int] | None = None
    stop_task: asyncio.Task[bool] | None = None
    live_status_tick_task: asyncio.Task[None] | None = None
    live_security_tick_task: asyncio.Task[None] | None = None
    preflight_usage_task: asyncio.Task[None] | None = None
    snapshot_worker: asyncio.Task[None] | None = None
    file_audit_debounce_task: asyncio.Task[None] | None = None
    file_audit_health_task: asyncio.Task[None] | None = None
    os_audit_health_task: asyncio.Task[None] | None = None
    snapshot_queue: asyncio.Queue[
        tuple[int, dict[str, Any], asyncio.Future[dict[str, Any]]] | None
    ] = asyncio.Queue()
    snapshot_errors: list[dict[str, str]] = []
    file_audit_pending: dict[str, int] | None = None
    file_audit_window_count = 0
    file_audit_shutdown = False
    file_audit_wakeup = asyncio.Event()
    latest_gateway_seq = 0
    file_audit_warnings: set[str] = set()
    active_write_items: dict[tuple[str, str], dict[str, Any]] = {}
    state = InteractiveState(include_sensitive=include_sensitive)
    live_status = LiveSessionStatus()
    runtime_policy_session = RuntimePolicySession(repo)
    printer = LivePrinter(live_status)
    live_status_path = layout.root / "live_status.json"
    live_security_path = layout.root / "live_security.json"
    token_reconciliation_path = layout.root / "token_reconciliation_history.json"
    persisted_reconciliation_count = -1
    caught: BaseException | None = None
    caught_traceback: types.TracebackType | None = None
    cleanup_errors: list[dict[str, str]] = []
    stopping = False
    stop_reason = "requested"
    connected_count = 0
    registry_written = False
    temp_runtime = _private_monitor_runtime(repo)
    backend_socket = temp_runtime / "backend.sock"
    public_socket = (
        frontend_socket.expanduser().resolve()
        if frontend_socket is not None
        else temp_runtime / "codexscope.sock"
    )

    def persist_live_status(
        *,
        monitor_state: str | None = None,
        finished_at: str | None = None,
    ) -> None:
        nonlocal persisted_reconciliation_count
        payload = live_status.to_dict()
        updated_at = now_iso()
        state_name = monitor_state or ("stopping" if stopping else "active")
        payload["schema_version"] = "codexscope.live-status.v2"
        payload["updated_at"] = updated_at
        payload["run_id"] = run_id
        payload["run_dir"] = os.fspath(layout.root)
        payload["monitor"] = {
            "state": state_name,
            "active": state_name == "active",
            "pid": os.getpid(),
            "heartbeat_at": updated_at,
            "heartbeat_interval_seconds": _LIVE_STATUS_HEARTBEAT_SECONDS,
            "started_at": manifest.get("started_at"),
            "finished_at": finished_at,
        }
        atomic_json_dump(live_status_path, payload)
        reconciliation_count = len(live_status.reconciliation_history)
        if reconciliation_count != persisted_reconciliation_count:
            atomic_json_dump(
                token_reconciliation_path,
                {
                    "schema_version": "codexscope.token-reconciliation.v1",
                    "run_id": run_id,
                    "summary": live_status.reconciliation_summary(),
                    "history": list(live_status.reconciliation_history),
                },
            )
            persisted_reconciliation_count = reconciliation_count

    async def live_status_tick_loop() -> None:
        """Advance estimates and persist one coalesced status heartbeat."""

        last_persisted_mono = time.monotonic()
        while True:
            await asyncio.sleep(_LIVE_STATUS_TICK_SECONDS)
            now_mono = time.monotonic()
            estimating = (
                live_status.has_active_inflight() and not live_status.inflight_paused
            )
            if estimating:
                printer.render_status()
            if (
                not estimating
                and now_mono - last_persisted_mono < _LIVE_STATUS_HEARTBEAT_SECONDS
            ):
                continue
            try:
                persist_live_status()
            except OSError:
                # Status output is best-effort and must not stop trace capture.
                pass
            else:
                last_persisted_mono = now_mono

    def persist_live_security() -> None:
        status_payload = json_load(live_status_path)
        if not isinstance(status_payload, Mapping):
            raise ValueError("live status payload must be an object")
        atomic_json_dump(
            live_security_path,
            build_live_security_payload(status_payload, run_dir=layout.root),
        )

    async def live_security_tick_loop() -> None:
        """Persist the same bounded security DTO consumed by the Lingmou web UI."""

        while True:
            await asyncio.sleep(_LIVE_SECURITY_TICK_SECONDS)
            try:
                persist_live_security()
            except (OSError, ValueError):
                # The TUI feed is best-effort and must not stop trace capture.
                pass

    async def preflight_usage_log_loop() -> None:
        """Follow Codex's count-only preflight trace and update live status."""

        with layout.appserver_stderr.open(
            "r", encoding="utf-8", errors="replace"
        ) as stream:
            while True:
                line = stream.readline()
                if not line:
                    await asyncio.sleep(_PREFLIGHT_LOG_POLL_SECONDS)
                    continue
                observation = _parse_codexscope_preflight_log(line)
                if observation is None:
                    continue
                changed = live_status.observe_preflight_input_estimate(
                    observation["estimated_input_tokens"],
                    turn_id=observation["turn_id"],
                    model=observation["model"],
                )
                if not changed:
                    continue
                printer.render_status()
                try:
                    persist_live_status()
                except OSError:
                    pass

    async def persist_manifest() -> None:
        if os.environ.get("LINGMOU_MANAGED_POLICIES") == "1":
            try:
                manifest["filesystem_guard"] = json_load(layout.root / "agent-control/status.json")
            except (OSError, ValueError):
                pass
        state.apply_manifest(manifest)
        await asyncio.to_thread(atomic_json_dump, layout.manifest, manifest)

    async def snapshot_loop() -> None:
        while True:
            value = await snapshot_queue.get()
            try:
                if value is None:
                    return
                seq, item, completion = value
                assert snapshots is not None
                try:
                    rows = await asyncio.to_thread(
                        snapshots.capture_after, seq, item
                    )
                    result = snapshots.last_capture
                    result["changed_count"] = len(rows)
                except BaseException as exc:
                    error = _error_record(exc)
                    snapshot_errors.append(error)
                    result = {"changed_count": 0, "error": error}
                finally:
                    if not completion.done():
                        completion.set_result(result)
            finally:
                snapshot_queue.task_done()

    def record_file_audit_window(
        window_id: str,
        window: Mapping[str, int],
        result: Mapping[str, Any],
    ) -> None:
        audit = manifest["file_audit"]
        changed_count = int(result.get("changed_count") or 0)
        failed = bool(result.get("error"))
        if failed:
            audit["snapshot_windows_failed"] = (
                int(audit.get("snapshot_windows_failed") or 0) + 1
            )
        elif changed_count == 0:
            audit["snapshot_windows_empty"] = (
                int(audit.get("snapshot_windows_empty") or 0) + 1
            )
        recent = audit.setdefault("recent_snapshot_windows", [])
        if not isinstance(recent, list):
            recent = []
            audit["recent_snapshot_windows"] = recent
        recent.append(
            {
                "id": window_id,
                "event_seq_start": window["seq_start"],
                "event_seq_end": window["seq_end"],
                "event_count": window["event_count"],
                "observed_from_monotonic_ns": window["mono_start"],
                "observed_to_monotonic_ns": window["mono_end"],
                "observed_from_wall_time_ns": window["wall_start"],
                "observed_to_wall_time_ns": window["wall_end"],
                "changed_count": changed_count,
                "capture_started_monotonic_ns": result.get(
                    "capture_started_monotonic_ns"
                ),
                "capture_ended_monotonic_ns": result.get(
                    "capture_ended_monotonic_ns"
                ),
                "capture_started_wall_time_ns": result.get(
                    "capture_started_wall_time_ns"
                ),
                "capture_ended_wall_time_ns": result.get(
                    "capture_ended_wall_time_ns"
                ),
                "error": result.get("error"),
            }
        )
        del recent[:-100]

    async def flush_file_audit_window(*, force: bool = False) -> bool:
        nonlocal file_audit_pending, file_audit_window_count
        if active_write_items and not force:
            return False
        window = file_audit_pending
        file_audit_pending = None
        if window is None:
            return False
        if (
            snapshots is None
            or snapshot_worker is None
            or snapshot_worker.done()
        ):
            manifest["file_audit"]["known_loss_detected"] = True
            manifest["file_audit"]["status"] = "degraded"
            manifest["file_audit"]["snapshot_windows_dropped"] = (
                int(manifest["file_audit"].get("snapshot_windows_dropped") or 0)
                + 1
            )
            return False
        file_audit_window_count += 1
        manifest["file_audit"]["snapshot_windows"] = file_audit_window_count
        window_id = f"filesystem-window-{file_audit_window_count:06d}"
        completion = asyncio.get_running_loop().create_future()
        await snapshot_queue.put(
            (
                latest_gateway_seq,
                {
                    "id": window_id,
                    "type": "filesystemObservation",
                    "action_type": "filesystem_observation",
                    "filesystem_event_seq_start": window["seq_start"],
                    "filesystem_event_seq_end": window["seq_end"],
                    "observed_from_monotonic_ns": window["mono_start"],
                    "observed_to_monotonic_ns": window["mono_end"],
                    "observed_from_wall_time_ns": window["wall_start"],
                    "observed_to_wall_time_ns": window["wall_end"],
                    "event_count": window["event_count"],
                },
                completion,
            )
        )
        # Waiting here is the backpressure boundary: while one audit scan is
        # running, later callbacks only merge into ``file_audit_pending``.
        result = await asyncio.shield(completion)
        record_file_audit_window(window_id, window, result)
        return True

    async def file_audit_debounce_loop() -> None:
        nonlocal file_audit_debounce_task
        try:
            while file_audit_pending is not None:
                if not file_audit_shutdown:
                    file_audit_wakeup.clear()
                    try:
                        await asyncio.wait_for(
                            file_audit_wakeup.wait(),
                            timeout=_FILE_AUDIT_DEBOUNCE_SECONDS,
                        )
                    except asyncio.TimeoutError:
                        pass
                if active_write_items and not file_audit_shutdown:
                    continue
                await flush_file_audit_window(force=file_audit_shutdown)
        finally:
            file_audit_debounce_task = None
            # A callback can arrive after the loop's final condition check but
            # before this ``finally`` runs. Hand that newly pending window to a
            # fresh task instead of leaving it stranded until shutdown.
            if (
                file_audit_pending is not None
                and not file_audit_shutdown
                and snapshot_worker is not None
                and not snapshot_worker.done()
            ):
                file_audit_debounce_task = asyncio.create_task(
                    file_audit_debounce_loop(),
                    name="codexscope-file-audit-debounce",
                )

    def note_file_audit_event(row: dict[str, object]) -> None:
        nonlocal file_audit_pending, file_audit_debounce_task
        try:
            source_seq = int(row.get("seq") or 0)
            mono = int(row.get("monotonic_ns") or 0)
        except (TypeError, ValueError):
            return
        try:
            wall = int(row.get("wall_time_ns") or 0)
        except (TypeError, ValueError):
            wall = 0
        operation = str(row.get("operation") or "unknown")
        if (
            operation != "limit_reached"
            and operation != "callback_limit_reached"
            and file_observer is not None
            and getattr(file_observer.stats, "jsonl_dropped", 0)
        ):
            manifest["file_audit"]["known_loss_detected"] = True
            manifest["file_audit"]["status"] = "degraded"
            if "jsonl_limit" not in file_audit_warnings:
                file_audit_warnings.add("jsonl_limit")
                print(
                    f"[{datetime.now().strftime('%H:%M:%S')}] file audit warning  JSONL size limit reached",
                    flush=True,
                )
        if operation in {
            "queue_overflow",
            "watch_limit",
            "watch_error",
            "limit_reached",
            "callback_limit_reached",
            "unmount",
            "delete_self",
            "move_self",
        }:
            manifest["file_audit"]["known_loss_detected"] = True
            manifest["file_audit"]["status"] = "degraded"
            if operation not in file_audit_warnings:
                file_audit_warnings.add(operation)
                print(
                    f"[{datetime.now().strftime('%H:%M:%S')}] file audit warning  {operation}",
                    flush=True,
                )
        if file_audit_pending is None:
            file_audit_pending = {
                "seq_start": source_seq,
                "seq_end": source_seq,
                "mono_start": mono,
                "mono_end": mono,
                "wall_start": wall,
                "wall_end": wall,
                "event_count": 1,
            }
        else:
            file_audit_pending["seq_start"] = min(
                file_audit_pending["seq_start"], source_seq
            )
            file_audit_pending["seq_end"] = max(
                file_audit_pending["seq_end"], source_seq
            )
            file_audit_pending["mono_start"] = min(
                file_audit_pending["mono_start"], mono
            )
            file_audit_pending["mono_end"] = max(
                file_audit_pending["mono_end"], mono
            )
            file_audit_pending["wall_start"] = min(
                file_audit_pending["wall_start"], wall
            )
            file_audit_pending["wall_end"] = max(
                file_audit_pending["wall_end"], wall
            )
            file_audit_pending["event_count"] += 1
        if file_audit_debounce_task is None and snapshot_worker is not None:
            file_audit_debounce_task = asyncio.create_task(
                file_audit_debounce_loop(), name="codexscope-file-audit-debounce"
            )

    def on_file_audit_event(row: dict[str, object]) -> None:
        try:
            loop.call_soon_threadsafe(note_file_audit_event, dict(row))
        except RuntimeError:
            # The observer is stopped before the event loop closes.  This is a
            # final defensive guard for embedding callers that cancel the loop.
            return

    def write_item_key(
        envelope: Mapping[str, Any], item: Mapping[str, Any]
    ) -> tuple[str, str] | None:
        item_id = item.get("id")
        if item_id is None:
            return None
        return str(envelope.get("connection_id") or ""), str(item_id)

    def is_snapshot_boundary(envelope: Mapping[str, Any]) -> bool:
        message = envelope.get("message")
        if envelope.get("direction") != "server_to_client" or not isinstance(
            message, Mapping
        ):
            return False
        if message.get("method") != "item/completed":
            return False
        params = message.get("params")
        item = params.get("item") if isinstance(params, Mapping) else None
        return bool(
            isinstance(item, Mapping)
            and item.get("type") in _CAPTURE_AFTER_ITEM_TYPES
        )

    async def on_message(envelope: dict[str, Any]) -> None:
        nonlocal latest_gateway_seq
        assert recorder is not None
        latest_gateway_seq = max(
            latest_gateway_seq, int(envelope.get("seq") or 0)
        )
        message = envelope.get("message")
        runtime_decisions: list[dict[str, Any]] = []
        if isinstance(message, Mapping):
            direction = envelope.get("direction")
            method = str(message.get("method") or "")
            params = message.get("params")
            params = params if isinstance(params, Mapping) else {}
            if direction == "client_to_server" and method in {
                "turn/start",
                "turn/steer",
            }:
                prompt_text = _prompt_text(params)
                if prompt_text:
                    runtime_decisions = runtime_policy_session.assess_user_text(
                        prompt_text
                    )
            elif direction == "server_to_client" and method in {
                "item/commandExecution/requestApproval",
                "execCommandApproval",
            }:
                raw_command = params.get("command")
                command = (
                    raw_command.strip()
                    if isinstance(raw_command, str)
                    else shlex.join(raw_command)
                    if isinstance(raw_command, list)
                    and all(isinstance(value, str) for value in raw_command)
                    else ""
                )
                if command:
                    assessment = classify_live_command(
                        command,
                        status="review",
                        cwd=str(params.get("cwd") or "") or None,
                    )
                    interception = envelope.get("interception")
                    if isinstance(interception, Mapping) and isinstance(interception.get("policy_decisions"), list):
                        # Replay the verdict that actually stopped execution; do
                        # not ask a stochastic judge again for the same denial.
                        runtime_decisions = interception["policy_decisions"]
                    else:
                        evaluated = assess_approval_policies(
                            command, workspace=repo, cwd=params.get("cwd"),
                            runtime_session=runtime_policy_session,
                            assessment=assessment, principal=params,
                        )
                        runtime_decisions = evaluated["policy_decisions"]
                    if security_policy != "enforce":
                        runtime_decisions = [
                            {
                                **d,
                                "blocking": False,
                                "result": "detected"
                                if d["mode"] == "deny"
                                else d["result"],
                            }
                            for d in runtime_decisions
                        ]
                    if not isinstance(envelope.get("interception"), Mapping):
                        observation = _runtime_policy_observation(
                            runtime_decisions,
                            security_mode=security_policy,
                        )
                        if observation is not None:
                            envelope["policy_observation"] = observation
            elif direction == "server_to_client" and method in {
                "item/fileChange/requestApproval",
                "applyPatchApproval",
            }:
                changes = params.get("changes") or params.get("fileChanges") or []
                runtime_decisions = assess_file_change_policies(
                    [value for value in changes if isinstance(value, Mapping)]
                    if isinstance(changes, list)
                    else []
                )
                if not isinstance(envelope.get("interception"), Mapping):
                    observation = _runtime_policy_observation(
                        runtime_decisions,
                        security_mode=security_policy,
                    )
                    if observation is not None:
                        envelope["policy_observation"] = observation
            elif direction == "server_to_client" and method in {
                "item/started",
                "item/completed",
            }:
                item = params.get("item")
                item = item if isinstance(item, Mapping) else {}
                lifecycle = "started" if method == "item/started" else "completed"
                item_type = str(item.get("type") or "")
                if item_type == "commandExecution" and lifecycle == "completed":
                    command = str(item.get("command") or "")
                    assessment = classify_live_command(
                        command,
                        status=item.get("status"),
                        cwd=str(item.get("cwd") or "") or None,
                    )
                    risk = assessment.get("risk")
                    risk = risk if isinstance(risk, Mapping) else {}
                    runtime_decisions = merge_policy_decisions(
                        assessment.get("policy_decisions", []),
                        runtime_policy_session.assess_command(
                            command,
                            cwd=str(item.get("cwd") or "") or None,
                            principal=item,
                        ),
                        decisions_from_rule_ids(
                            [
                                str(value)
                                for value in assessment.get("matched_rules", [])
                                if str(value).strip()
                            ],
                            reasons=(
                                [str(value) for value in risk.get("reasons", [])]
                                if isinstance(risk.get("reasons"), list)
                                else []
                            ),
                            stage="command_lifecycle",
                        ),
                    )
                elif item_type == "fileChange" and lifecycle == "completed":
                    changes = item.get("changes")
                    runtime_decisions = assess_file_change_policies(
                        [value for value in changes if isinstance(value, Mapping)]
                        if isinstance(changes, list)
                        else []
                    )
                else:
                    runtime_decisions = runtime_policy_session.assess_tool_item(
                        item,
                        lifecycle=lifecycle,
                    )
        if runtime_decisions:
            envelope["runtime_policy_decisions"] = runtime_decisions
        if (
            envelope.get("direction") == "server_to_client"
            and isinstance(message, Mapping)
            and message.get("method") == "item/completed"
        ):
            params = message.get("params")
            item = params.get("item") if isinstance(params, Mapping) else None
            if isinstance(item, Mapping) and item.get("type") == "commandExecution":
                runtime_policy_session.observe_command(
                    str(item.get("command") or ""),
                    cwd=str(item.get("cwd") or "") or None,
                    status=str(item.get("status") or "completed"),
                    exit_code=(
                        int(item.get("exitCode"))
                        if isinstance(item.get("exitCode"), int)
                        else None
                    ),
                    observed_at=float(envelope.get("wall_time") or time.time()),
                    turn_id=(
                        str(params.get("turnId"))
                        if isinstance(params, Mapping) and params.get("turnId") is not None
                        else None
                    ),
                    item_id=(str(item.get("id")) if item.get("id") is not None else None),
                )
        recorder.write(envelope)
        important = state.consume(envelope)
        live_changed = consume_envelope(live_status, envelope)
        # Prefer the latest resolved thread model so the live estimator can
        # select a matching tokenizer before official usage exists.
        for thread in reversed(list(state.threads.values())):
            if thread.get("model"):
                live_changed = (
                    live_status.set_model(str(thread.get("model"))) or live_changed
                )
                break
        printer.message(envelope)
        message = envelope.get("message")
        method = message.get("method") if isinstance(message, Mapping) else None
        # Deltas can arrive much faster than disk should be rewritten.  The
        # coalesced ticker persists those; lifecycle and exact usage stay eager.
        if live_changed and method not in MODEL_OUTPUT_DELTA_METHODS:
            try:
                persist_live_status()
            except OSError:
                pass
        if (
            envelope.get("direction") == "server_to_client"
            and isinstance(message, dict)
            and message.get("method") == "item/started"
        ):
            params = message.get("params")
            item = params.get("item") if isinstance(params, dict) else None
            if (
                isinstance(item, dict)
                and item.get("type") in _CAPTURE_AFTER_ITEM_TYPES
            ):
                key = write_item_key(envelope, item)
                if key is not None:
                    active_write_items[key] = dict(item)
                    file_audit_wakeup.set()
        if (
            envelope.get("direction") == "server_to_client"
            and isinstance(message, dict)
            and message.get("method") == "item/completed"
        ):
            params = message.get("params")
            item = params.get("item") if isinstance(params, dict) else None
            if isinstance(item, dict) and item.get("type") in _CAPTURE_AFTER_ITEM_TYPES:
                key = write_item_key(envelope, item)
                candidates = list(active_write_items.values())
                if key is None or key not in active_write_items:
                    candidates.append(item)
                capture_item = dict(item)
                candidate_ids = sorted(
                    {
                        str(candidate.get("id"))
                        for candidate in candidates
                        if candidate.get("id") is not None
                    }
                )
                if len(candidates) > 1:
                    capture_item["_codexscope_attribution_ambiguous"] = True
                    capture_item[
                        "_codexscope_attribution_candidate_item_ids"
                    ] = candidate_ids
                completion = asyncio.get_running_loop().create_future()
                try:
                    await snapshot_queue.put(
                        (
                            int(envelope.get("seq") or 0),
                            capture_item,
                            completion,
                        )
                    )
                    # Keep the item active until its tool-boundary scan has
                    # committed. Filesystem debounce scans therefore cannot
                    # consume an early write from a long-running tool.
                    await asyncio.shield(completion)
                finally:
                    if key is not None:
                        active_write_items.pop(key, None)
                    file_audit_wakeup.set()
        if important:
            await persist_manifest()

    async def on_connect(event: dict[str, Any]) -> None:
        nonlocal connected_count
        connected_count += 1
        state.connection_started(event)
        print(
            f"[{datetime.now().strftime('%H:%M:%S')}] TUI connected  {event.get('connection_id', '')}",
            flush=True,
        )
        await persist_manifest()

    async def on_disconnect(event: dict[str, Any]) -> None:
        state.connection_stopped(event)
        print(
            f"[{datetime.now().strftime('%H:%M:%S')}] TUI disconnected  {event.get('connection_id', '')}",
            flush=True,
        )
        await persist_manifest()
        if once and connected_count > 0:
            stop_event.set()

    loop = asyncio.get_running_loop()
    installed_signals: list[signal.Signals] = []

    def apply_request_input_estimate(observation: RequestInputEstimate) -> None:
        tokenizer_backed = "tokenizer" in observation.tokenizer_source
        if observation.source == "provider_preflight_exact":
            source = "provider_preflight_exact"
        elif not observation.context_complete:
            source = "request_body_partial"
        elif tokenizer_backed:
            source = "request_body_tokenized"
        else:
            source = "request_body_heuristic"
        changed = live_status.observe_preflight_input_estimate(
            observation.input_tokens,
            model=observation.model,
            source=source,
            tokenizer_source=observation.tokenizer_source,
            component_tokens=observation.component_tokens,
            context_complete=observation.context_complete,
            request_id=observation.request_id,
            modality_counts=observation.modality_counts,
            text_input_tokens=observation.text_input_tokens,
            multimodal_input_tokens=observation.multimodal_input_tokens,
            multimodal_input_quality=observation.multimodal_input_quality,
            provider_count_latency_ms=observation.provider_count_latency_ms,
            provider_count_status=observation.provider_count_status,
        )
        if not changed:
            return
        printer.render_status()
        try:
            persist_live_status()
        except OSError:
            pass

    def on_request_input_estimate(observation: RequestInputEstimate) -> None:
        try:
            loop.call_soon_threadsafe(apply_request_input_estimate, observation)
        except RuntimeError:
            return

    def apply_request_usage(record: dict) -> None:
        # Full numeric per-request history survives the in-memory 200-row cap.
        usage_path = layout.manifest.parent / 'request_usage.jsonl'
        with usage_path.open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(record, ensure_ascii=False) + '\n')
        manifest['request_token_tap']['usage_log'] = usage_path.name
        if request_token_tap is not None:
            manifest['request_token_tap'].update(request_token_tap.stats_dict())
        atomic_json_dump(layout.manifest, manifest)

    def on_request_usage(record: dict) -> None:
        try:
            loop.call_soon_threadsafe(apply_request_usage, record)
        except RuntimeError:
            return

    def apply_tapped_sse_event(
        event_name: str,
        data: Mapping[str, Any],
    ) -> None:
        event_type = data.get("type") or event_name
        if event_type != "response.function_call_arguments.delta":
            return
        delta = data.get("delta")
        item_id = data.get("item_id") or data.get("itemId")
        if not isinstance(delta, str) or item_id is None:
            return
        changed = live_status.observe_model_tool_argument_delta(
            delta,
            item_id=str(item_id),
            method="response.function_call_arguments.delta",
            stream_source="request_tap",
        )
        if changed:
            printer.render_status()

    def on_tapped_sse_event(
        event_name: str,
        data: Mapping[str, Any],
    ) -> None:
        try:
            loop.call_soon_threadsafe(apply_tapped_sse_event, event_name, data)
        except RuntimeError:
            return

    def request_stop(reason: str) -> None:
        nonlocal stop_reason
        stop_reason = reason
        stop_event.set()

    async def file_audit_health_loop(
        observer: InotifyWorkspaceObserver,
    ) -> None:
        """Surface asynchronous watcher death while the TUI is still active."""

        nonlocal stop_reason
        while not stopping:
            await asyncio.sleep(0.1)
            running = getattr(observer, "running", True)
            if callable(running):
                running = running()
            if running:
                continue
            if stopping:
                return
            try:
                stats = observer.stats_dict()
            except BaseException as exc:
                stats = {"last_error": repr(exc)}
            message = str(
                stats.get("last_error")
                or "filesystem observer stopped unexpectedly"
            )
            manifest["file_audit"].update(
                {
                    "status": "degraded",
                    "known_loss_detected": True,
                    "runtime_stopped_unexpectedly": True,
                    "runtime_error": {
                        "type": "FileAuditRuntimeError",
                        "message": redact_text(message),
                    },
                    "collector": stats,
                }
            )
            try:
                await persist_manifest()
            except BaseException as exc:
                manifest["file_audit"]["manifest_update_error"] = _error_record(
                    exc
                )
            print(
                f"[{datetime.now().strftime('%H:%M:%S')}] file audit warning  {redact_text(message)}",
                flush=True,
            )
            if file_audit == "inotify":
                stop_reason = "file_audit_failed"
                stop_event.set()
            return

    async def os_audit_health_loop(collector: StraceAuditCollector) -> None:
        """Surface a reader failure/limit while an interactive run is active."""

        nonlocal stop_reason
        last_manifest_update = 0.0
        stats_method = getattr(collector, "stats_dict", None)
        if not callable(stats_method):
            # Older/injected collectors still receive definitive close-time
            # validation; current collectors expose a non-blocking snapshot.
            return
        while not stopping:
            await asyncio.sleep(0.1)
            try:
                value = await asyncio.to_thread(stats_method)
                stats = dict(value) if isinstance(value, Mapping) else {}
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                stats = {"reader_error": redact_text(str(exc)), "known_loss": True}
            running = getattr(collector, "running", True)
            if callable(running):
                running = running()
            unexpected_stop = running is False and not stopping
            runtime_loss = _os_audit_runtime_loss(stats)
            now_mono = time.monotonic()
            if not unexpected_stop and not runtime_loss:
                if (
                    now_mono - last_manifest_update
                    < _OS_AUDIT_MANIFEST_HEARTBEAT_SECONDS
                ):
                    continue
                manifest["os_audit"].update(
                    {
                        "status": "running",
                        "known_loss_detected": False,
                        "collector": stats,
                    }
                )
                try:
                    await persist_manifest()
                    last_manifest_update = now_mono
                except BaseException as exc:
                    manifest["os_audit"]["manifest_update_error"] = _error_record(
                        exc
                    )
                continue
            manifest["os_audit"].update(
                {
                    "status": "degraded",
                    "known_loss_detected": True,
                    "runtime_stopped_unexpectedly": unexpected_stop,
                    "collector": stats,
                }
            )
            try:
                await persist_manifest()
            except BaseException as exc:
                manifest["os_audit"]["manifest_update_error"] = _error_record(exc)
            print(
                f"[{datetime.now().strftime('%H:%M:%S')}] OS audit warning  collection gap detected",
                flush=True,
            )
            if os_audit == "strace":
                stop_reason = "os_audit_failed"
                stop_event.set()
            return

    def startup_checkpoint(stage: str) -> None:
        if stop_event.is_set():
            manifest["startup_stop_stage"] = stage
            raise _MonitorStartupStopped

    if external_stop is None:
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, request_stop, sig.name.lower())
            except (NotImplementedError, RuntimeError):
                continue
            installed_signals.append(sig)

    try:
        # Create an empty raw stream even when startup is stopped.  The CLI can
        # then process the interrupted run into the usual report layout.
        recorder = GatewayRecorder(
            layout.appserver_raw,
            include_sensitive=include_sensitive,
            capture_surfaced_reasoning=capture_surfaced_reasoning,
        )
        startup_checkpoint("before_codex_version")
        version = await asyncio.to_thread(codex_version, codex_bin)
        startup_checkpoint("after_codex_version")
        manifest["codex_version"] = version
        manifest["codex"] = {"binary": codex_bin, "version": version}
        if capture_schema:
            startup_checkpoint("before_protocol_schema")
            manifest["protocol_schema"] = await asyncio.to_thread(
                capture_protocol_schema, codex_bin, layout.root / "protocol"
            )
            startup_checkpoint("after_protocol_schema")
        else:
            manifest["protocol_schema"] = {"captured": False, "skipped": True}

        startup_checkpoint("before_snapshot_setup")
        snapshots = SnapshotManager(repo, layout.root, baseline_source="workspace")
        if file_audit != "off":
            startup_checkpoint("before_file_audit")
            try:
                file_observer = await asyncio.to_thread(
                    lambda: InotifyWorkspaceObserver(
                        repo,
                        layout.filesystem_raw,
                        max_events=file_audit_max_events,
                        on_event=on_file_audit_event,
                        fail_on_overflow=file_audit == "inotify",
                    ).start()
                )
            except Exception as exc:
                manifest["file_audit"].update(
                    {
                        "enabled": False,
                        "status": "unavailable",
                        "error": _error_record(exc),
                    }
                )
                atomic_json_dump(
                    layout.file_audit_summary,
                    {
                        "schema_version": "1.0",
                        "requested": file_audit,
                        "status": "unavailable",
                        "error": _error_record(exc),
                    },
                )
                if file_audit == "inotify":
                    raise
                print(
                    f"[{datetime.now().strftime('%H:%M:%S')}] file audit unavailable  {_error_record(exc)['message']}",
                    flush=True,
                )
            else:
                manifest["file_audit"].update(
                    {
                        "enabled": True,
                        "status": "running",
                        "backend": "linux_inotify",
                    }
                )
                file_audit_health_task = asyncio.create_task(
                    file_audit_health_loop(file_observer),
                    name="codexscope-file-audit-health",
                )
            startup_checkpoint("after_file_audit")
        startup_checkpoint("before_workspace_baseline")
        await asyncio.to_thread(snapshots.capture_baseline)
        snapshot_worker = asyncio.create_task(snapshot_loop(), name="codexscope-snapshots")
        if file_audit_pending is not None and file_audit_debounce_task is None:
            file_audit_debounce_task = asyncio.create_task(
                file_audit_debounce_loop(), name="codexscope-file-audit-debounce"
            )
        startup_checkpoint("after_workspace_baseline")

        if trace_config.enabled:
            startup_checkpoint("before_function_collector")
            function_collector = await asyncio.to_thread(
                FunctionTraceCollector.start, layout.functions_raw, trace_config
            )
            startup_checkpoint("after_function_collector")

        if os_audit != "off":
            startup_checkpoint("before_os_audit")
            try:
                os_audit_collector = await asyncio.to_thread(
                    lambda: StraceAuditCollector(
                        repo,
                        layout.os_audit_raw,
                        max_events=os_audit_max_events,
                        trace_profile=os_audit_profile,
                    ).start()
                )
            except Exception as exc:
                manifest["os_audit"].update(
                    {
                        "enabled": False,
                        "status": "unavailable",
                        "error": _error_record(exc),
                    }
                )
                atomic_json_dump(
                    layout.os_audit_summary,
                    {
                        "schema_version": "1.0",
                        "requested": os_audit,
                        "status": "unavailable",
                        "known_loss_detected": False,
                        "trace_profile": os_audit_profile,
                        "error": _error_record(exc),
                    },
                )
                if os_audit == "strace":
                    raise
                print(
                    f"[{datetime.now().strftime('%H:%M:%S')}] OS audit unavailable  {_error_record(exc)['message']}",
                    flush=True,
                )
            else:
                manifest["os_audit"].update(
                    {
                        "enabled": True,
                        "status": "running",
                        "backend": "linux_strace",
                        "process_identity": True,
                        "syscalls": True,
                        "read_access": True,
                        "network_activity": True,
                    }
                )
                os_audit_health_task = asyncio.create_task(
                    os_audit_health_loop(os_audit_collector),
                    name="codexscope-os-audit-health",
                )
            startup_checkpoint("after_os_audit")

        if request_token_tap_upstream is not None:
            startup_checkpoint("before_request_token_tap")
            try:
                request_token_tap = RequestTokenTap(
                    request_token_tap_upstream,
                    on_input_estimate=on_request_input_estimate,
                    on_sse_event=on_tapped_sse_event,
                    on_request_usage=on_request_usage,
                    **({'input_compressor': make_input_compressor(input_compression,
                        **({'source_store': SourceStore(layout.root / 'compression_sources')}
                           if input_compression in {'extract', 'jev', 'kimi', 'llmlingua2'} else {}))}
                       if input_compression != 'off' else {}),
                )
                await asyncio.to_thread(request_token_tap.start)
            except BaseException as exc:
                manifest["request_token_tap"].update(
                    {
                        "enabled": False,
                        "status": "unavailable",
                        "startup_error": _error_record(exc),
                    }
                )
                raise
            else:
                manifest["request_token_tap"].update(
                    {
                        "enabled": True,
                        "status": "running",
                        "transport": "http_sse",
                        "provider_id": _REQUEST_TAP_PROVIDER_ID,
                        "local_base_path": request_token_tap.upstream.path or "/",
                    }
                )
            startup_checkpoint("after_request_token_tap")

        if harness_telemetry != "off":
            startup_checkpoint("before_harness_telemetry")
            try:
                otel_trace_collector = await asyncio.to_thread(
                    lambda: OtelTraceCollector(
                        layout.otel_trace_raw,
                        max_events=harness_telemetry_max_events,
                    ).start()
                )
            except BaseException as exc:
                manifest["harness_telemetry"].update(
                    {
                        "enabled": False,
                        "status": "unavailable",
                        "startup_error": _error_record(exc),
                    }
                )
                atomic_json_dump(
                    layout.otel_trace_summary,
                    {
                        "schema_version": "codexscope.otel.trace.v1",
                        "requested": harness_telemetry,
                        "status": "unavailable",
                        "error": _error_record(exc),
                    },
                )
                if harness_telemetry == "otel":
                    raise
                print(
                    f"[{datetime.now().strftime('%H:%M:%S')}] harness telemetry unavailable  "
                    f"{_error_record(exc)['message']}",
                    flush=True,
                )
            else:
                manifest["harness_telemetry"].update(
                    {
                        "enabled": True,
                        "status": "running",
                        "backend": "codex_trace_safe_otlp_http",
                        "endpoint": otel_trace_collector.endpoint,
                    }
                )
            startup_checkpoint("after_harness_telemetry")

        child_env = os.environ.copy()
        child_env["CODEXSCOPE_HOOK_SPOOL"] = os.fspath(layout.hooks_raw)
        child_env["CODEXSCOPE_INCLUDE_SENSITIVE"] = (
            "1" if include_sensitive else "0"
        )
        _enable_codexscope_preflight_trace(child_env)
        if function_collector is not None:
            child_env.update(
                function_collector.child_environment(repo, run_id=run_id)
            )

        log_flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        log_flags |= getattr(os, "O_NOFOLLOW", 0)
        log_fd = os.open(layout.appserver_stderr, log_flags, 0o600)
        os.fchmod(log_fd, 0o600)
        log_stream = os.fdopen(log_fd, "wb", buffering=0)
        try:
            appserver_command = [
                codex_bin,
                "app-server",
                "--listen",
                f"unix://{backend_socket}",
            ]
            if capture_surfaced_reasoning:
                appserver_command.extend(
                    ["-c", "show_raw_agent_reasoning=true"]
                )
            if otel_trace_collector is not None:
                appserver_command.extend(
                    codex_trace_config_arguments(otel_trace_collector.endpoint)
                )
            if request_token_tap is not None:
                appserver_command.extend(
                    _request_tap_provider_arguments(
                        request_token_tap.local_base_url,
                        codex_version_value=manifest.get("codex_version"),
                    )
                )
                if input_compression in {'extract', 'jev', 'kimi', 'llmlingua2'}:
                    appserver_command.extend(source_mcp_arguments(layout.root / 'compression_sources'))
            if os.environ.get("LINGMOU_MANAGED_POLICIES") == "1":
                (layout.root / "agent-control").mkdir(mode=0o700)
                filesystem_guard = {"managed": True, "status": "starting"}
                appserver_command = [sys.executable, "-m", "codexscope.agent_supervisor",
                                     "--workspace", str(repo), "--run-dir", str(layout.root),
                                     "--socket", str(backend_socket), "--", *appserver_command]
            else:
                appserver_command, filesystem_guard = wrap_agent(
                    appserver_command, workspace=repo, run_dir=layout.root
                )
            manifest["filesystem_guard"] = filesystem_guard
            atomic_json_dump(layout.manifest, manifest)
            pass_fds: tuple[int, ...] = ()
            if os_audit_collector is not None:
                appserver_command = os_audit_collector.wrap_command(
                    appserver_command
                )
                pass_fds = tuple(os_audit_collector.pass_fds)
                appserver_process_group = True

            startup_checkpoint("before_app_server_spawn")
            appserver = await asyncio.create_subprocess_exec(
                *appserver_command,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=log_stream,
                stderr=asyncio.subprocess.STDOUT,
                env=child_env,
                cwd=os.fspath(repo),
                pass_fds=pass_fds,
                start_new_session=appserver_process_group,
            )
            if os_audit_collector is not None:
                os_audit_collector.after_spawn()
            startup_checkpoint("after_app_server_spawn")
        finally:
            log_stream.close()
        preflight_usage_task = asyncio.create_task(
            preflight_usage_log_loop(),
            name="codexscope-preflight-usage-log",
        )
        await _wait_for_socket(appserver, backend_socket, stop_event=stop_event)
        startup_checkpoint("after_app_server_socket")

        startup_checkpoint("before_gateway_start")
        gateway = UnixSocketGateway(
            public_socket,
            backend_socket,
            on_message=on_message,
            on_connect=on_connect,
            on_disconnect=on_disconnect,
            callback_barrier=is_snapshot_boundary,
            message_interceptor=(
                partial(
                    intercept_dangerous_command_approval,
                    workspace=repo,
                    runtime_session=runtime_policy_session,
                )
                if security_policy == "enforce"
                else None
            ),
        )
        await gateway.start()
        startup_checkpoint("after_gateway_start")

        registry = {
            "schema_version": "1.0",
            "run_id": run_id,
            "pid": os.getpid(),
            "endpoint": gateway.endpoint,
            "repo": os.fspath(repo),
            "run_dir": os.fspath(layout.root),
            "lingmou_security_path": os.fspath(live_security_path),
            "codex_bin": codex_bin,
            "started_at": manifest["started_at"],
        }
        startup_checkpoint("before_registry_publish")
        atomic_json_dump(registry_path, registry)
        registry_written = True
        startup_checkpoint("after_registry_publish")
        manifest["endpoint"] = gateway.endpoint
        manifest["status"] = "running"
        await persist_manifest()
        startup_checkpoint("after_ready_manifest")

        command = attach_command(registry)
        print("\nCodexScope interactive monitor is ready.", flush=True)
        print(f"Run directory: {layout.root}", flush=True)
        print(f"Endpoint:      {gateway.endpoint}", flush=True)
        print(
            f"File audit:    {manifest['file_audit']['status']}", flush=True
        )
        print(f"OS audit:      {manifest['os_audit']['status']}", flush=True)
        print(
            f"Harness OTEL:  {manifest['harness_telemetry']['status']}",
            flush=True,
        )
        print(
            f"Security:      {security_policy} (pre-execution approval gate)",
            flush=True,
        )
        print(
            f"Reasoning:     {manifest['reasoning_capture']['mode']}", flush=True
        )
        print(
            f"Request tap:   {manifest['request_token_tap']['status']}",
            flush=True,
        )
        print("\nOpen another terminal and run:", flush=True)
        print("  codexscope attach", flush=True)
        print("\nLive token / activity status:", flush=True)
        print("  this terminal updates a status bar on each event", flush=True)
        print("  codexscope status          # snapshot from another terminal", flush=True)
        print("  codexscope status --watch  # refresh four times/second", flush=True)
        print("  codexscope status --web    # browser dashboard", flush=True)
        print(f"  file: {live_status_path}", flush=True)
        print("\nEquivalent Codex command:", flush=True)
        print(f"  {shlex.join(command)}", flush=True)
        print("\nPress Ctrl-C here to finalize the report.\n", flush=True)
        try:
            persist_live_status()
        except OSError:
            pass
        try:
            persist_live_security()
        except (OSError, ValueError):
            pass
        printer.render_status(force=True)
        live_status_tick_task = asyncio.create_task(
            live_status_tick_loop(),
            name="codexscope-live-status-tick",
        )
        live_security_tick_task = asyncio.create_task(
            live_security_tick_loop(),
            name="codexscope-live-security-tick",
        )

        appserver_watch = asyncio.create_task(appserver.wait(), name="codexscope-appserver")
        stop_task = asyncio.create_task(stop_event.wait(), name="codexscope-monitor-stop")
        done, _ = await asyncio.wait(
            {appserver_watch, stop_task}, return_when=asyncio.FIRST_COMPLETED
        )
        if appserver_watch in done and not stop_event.is_set():
            stop_reason = "app_server_exited"
            raise MonitorError(
                f"codex app-server exited unexpectedly with status {appserver.returncode}"
            )
    except _MonitorStartupStopped:
        # A requested stop is not a monitor failure.  The final manifest below
        # records an interrupted run and any safely collected startup evidence.
        pass
    except BaseException as exc:
        caught = exc
        caught_traceback = exc.__traceback__
    finally:
        stopping = True
        for sig in installed_signals:
            loop.remove_signal_handler(sig)

        if live_status_tick_task is not None:
            if not live_status_tick_task.done():
                live_status_tick_task.cancel()
            try:
                await live_status_tick_task
            except asyncio.CancelledError:
                pass
            except BaseException as exc:
                cleanup_errors.append(_error_record(exc))

        if live_security_tick_task is not None:
            if not live_security_tick_task.done():
                live_security_tick_task.cancel()
            try:
                await live_security_tick_task
            except asyncio.CancelledError:
                pass
            except BaseException as exc:
                cleanup_errors.append(_error_record(exc))

        if stop_task is not None:
            if not stop_task.done():
                stop_task.cancel()
            try:
                await stop_task
            except asyncio.CancelledError:
                pass
            except BaseException as exc:
                cleanup_errors.append(_error_record(exc))
                if caught is None:
                    caught = exc
                    caught_traceback = exc.__traceback__

        if gateway is not None:
            try:
                await gateway.close()
                if gateway.callback_errors:
                    callback_error = MonitorError(
                        f"gateway observer failed {len(gateway.callback_errors)} time(s): "
                        f"{gateway.callback_errors[0]}"
                    )
                    cleanup_errors.append(_error_record(callback_error))
                    if caught is None:
                        caught = callback_error
                        caught_traceback = callback_error.__traceback__
            except BaseException as exc:
                cleanup_errors.append(_error_record(exc))
                if caught is None:
                    caught = exc
                    caught_traceback = exc.__traceback__

        if appserver is not None:
            try:
                await _stop_process(
                    appserver, process_group=appserver_process_group
                )
            except BaseException as exc:
                cleanup_errors.append(_error_record(exc))
                if caught is None:
                    caught = exc
                    caught_traceback = exc.__traceback__

        # Codex flushes its trace provider while the app-server exits, so keep
        # the loopback collector alive until after process shutdown.
        if otel_trace_collector is not None:
            try:
                otel_stats = await asyncio.to_thread(otel_trace_collector.stop)
                known_loss = bool(
                    otel_stats.get("dropped_records")
                    or otel_stats.get("parse_errors")
                    or otel_stats.get("rejected_requests")
                    or otel_stats.get("reader_stop_timeout")
                    or otel_stats.get("persistence_errors")
                )
                telemetry_status = "degraded" if known_loss else "completed"
                manifest["harness_telemetry"].update(
                    {
                        "status": telemetry_status,
                        "known_loss_detected": known_loss,
                        "collector": otel_stats,
                    }
                )
                atomic_json_dump(
                    layout.otel_trace_summary,
                    {
                        "schema_version": "codexscope.otel.trace.v1",
                        "requested": harness_telemetry,
                        "status": telemetry_status,
                        "known_loss_detected": known_loss,
                        "collector": otel_stats,
                    },
                )
                if harness_telemetry == "otel" and known_loss and caught is None:
                    telemetry_error = MonitorError(
                        "strict harness telemetry reported a collection gap; "
                        "the partial trace was retained"
                    )
                    caught = telemetry_error
                    caught_traceback = telemetry_error.__traceback__
            except BaseException as exc:
                manifest["harness_telemetry"].update(
                    {
                        "status": "degraded",
                        "known_loss_detected": True,
                        "close_error": _error_record(exc),
                    }
                )
                cleanup_errors.append(_error_record(exc))
                if harness_telemetry == "otel" and caught is None:
                    caught = exc
                    caught_traceback = exc.__traceback__

        if request_token_tap is not None:
            try:
                previous_tap_status = manifest["request_token_tap"].get(
                    "status"
                )
                tap_stats = await asyncio.to_thread(request_token_tap.stop)
                manifest["request_token_tap"].update(tap_stats)
                if previous_tap_status == "running":
                    manifest["request_token_tap"]["status"] = "completed"
            except BaseException as exc:
                manifest["request_token_tap"].update(
                    {
                        "status": "degraded",
                        "close_error": _error_record(exc),
                    }
                )
                cleanup_errors.append(_error_record(exc))

        if appserver_watch is not None and not appserver_watch.done():
            appserver_watch.cancel()
            try:
                await appserver_watch
            except (asyncio.CancelledError, BaseException):
                pass

        if preflight_usage_task is not None:
            if not preflight_usage_task.done():
                preflight_usage_task.cancel()
            try:
                await preflight_usage_task
            except asyncio.CancelledError:
                pass
            except BaseException as exc:
                cleanup_errors.append(_error_record(exc))

        if os_audit_health_task is not None:
            if not os_audit_health_task.done():
                os_audit_health_task.cancel()
            try:
                await os_audit_health_task
            except asyncio.CancelledError:
                pass
            except BaseException as exc:
                cleanup_errors.append(_error_record(exc))

        if os_audit_collector is not None:
            os_close_error: BaseException | None = None
            os_stats: dict[str, Any] = {}
            try:
                result = await asyncio.to_thread(os_audit_collector.close)
                if isinstance(result, Mapping):
                    os_stats = dict(result)
            except BaseException as exc:
                os_close_error = exc
                cleanup_errors.append(_error_record(exc))

            known_loss = bool(
                os_close_error
                or manifest["os_audit"].get("known_loss_detected")
                or _os_audit_known_loss(os_stats)
            )
            manifest["os_audit"].update(
                {
                    "status": "degraded" if known_loss else "completed",
                    "known_loss_detected": known_loss,
                    "collector": os_stats,
                }
            )
            if os_close_error is not None:
                manifest["os_audit"]["close_error"] = _error_record(
                    os_close_error
                )
            summary: dict[str, Any] = {
                "schema_version": "1.0",
                "requested": os_audit,
                "status": manifest["os_audit"]["status"],
                "known_loss_detected": known_loss,
                "scope": "appserver_descendant_process_tree",
                "trace_profile": os_audit_profile,
                "collector": os_stats,
            }
            if os_close_error is not None:
                summary["close_error"] = _error_record(os_close_error)
            try:
                atomic_json_dump(layout.os_audit_summary, summary)
            except BaseException as exc:
                cleanup_errors.append(_error_record(exc))
                if caught is None:
                    caught = exc
                    caught_traceback = exc.__traceback__
            if os_audit == "strace" and known_loss and caught is None:
                audit_error = MonitorError(
                    "strict strace OS audit reported a collection gap; "
                    "the partial trace was retained"
                )
                caught = audit_error
                caught_traceback = audit_error.__traceback__

        if file_audit_health_task is not None:
            if not file_audit_health_task.done():
                file_audit_health_task.cancel()
            try:
                await file_audit_health_task
            except asyncio.CancelledError:
                pass
            except BaseException as exc:
                cleanup_errors.append(_error_record(exc))

        if file_observer is not None:
            close_error: BaseException | None = None
            audit_stats: dict[str, Any] = {}
            try:
                await asyncio.to_thread(
                    file_observer.close, raise_on_error=False
                )
            except BaseException as exc:
                close_error = exc
                cleanup_errors.append(_error_record(exc))
                # A custom/injected close implementation may fail before it
                # actually asks the reader thread to stop. Make one best-effort
                # stop call, while still preserving the original close error.
                stop_method = getattr(file_observer, "stop", None)
                if callable(stop_method):
                    try:
                        await asyncio.to_thread(
                            stop_method, raise_on_error=False
                        )
                    except BaseException as stop_exc:
                        cleanup_errors.append(_error_record(stop_exc))

            # Always finish callback and debounce cleanup, even when observer
            # close itself failed. This avoids leaving an audit task or queued
            # snapshot behind in embedding event loops.
            await asyncio.sleep(0)
            file_audit_shutdown = True
            file_audit_wakeup.set()
            debounce = file_audit_debounce_task
            if debounce is not None:
                try:
                    await debounce
                except BaseException as exc:
                    cleanup_errors.append(_error_record(exc))
                    if caught is None:
                        caught = exc
                        caught_traceback = exc.__traceback__
            if file_audit_pending is not None:
                try:
                    await flush_file_audit_window(force=True)
                except BaseException as exc:
                    cleanup_errors.append(_error_record(exc))
                    if caught is None:
                        caught = exc
                        caught_traceback = exc.__traceback__

            try:
                audit_stats = file_observer.stats_dict()
            except BaseException as exc:
                cleanup_errors.append(_error_record(exc))
                if close_error is None:
                    close_error = exc
            known_loss = bool(
                close_error
                or manifest["file_audit"].get("known_loss_detected")
                or audit_stats.get("kernel_overflows")
                or audit_stats.get("jsonl_dropped")
                or audit_stats.get("watch_add_errors")
                or audit_stats.get("watch_limit_errors")
                or audit_stats.get("callback_errors")
                or audit_stats.get("callback_dropped")
                or audit_stats.get("callback_limit_reached")
                or audit_stats.get("last_error")
            )
            manifest["file_audit"].update(
                {
                    "status": "degraded" if known_loss else "completed",
                    "known_loss_detected": known_loss,
                    "snapshot_windows": file_audit_window_count,
                    "collector": audit_stats,
                }
            )
            if close_error is not None:
                manifest["file_audit"]["close_error"] = _error_record(
                    close_error
                )
            summary = {
                "schema_version": "1.0",
                "requested": file_audit,
                "status": manifest["file_audit"]["status"],
                "known_loss_detected": known_loss,
                "snapshot_windows": file_audit_window_count,
                "snapshot_windows_empty": int(
                    manifest["file_audit"].get("snapshot_windows_empty") or 0
                ),
                "snapshot_windows_failed": int(
                    manifest["file_audit"].get("snapshot_windows_failed") or 0
                ),
                "snapshot_windows_dropped": int(
                    manifest["file_audit"].get("snapshot_windows_dropped") or 0
                ),
                **audit_stats,
            }
            if close_error is not None:
                summary["close_error"] = _error_record(close_error)
            try:
                atomic_json_dump(layout.file_audit_summary, summary)
            except BaseException as exc:
                cleanup_errors.append(_error_record(exc))
                if caught is None:
                    caught = exc
                    caught_traceback = exc.__traceback__
            if file_audit == "inotify" and known_loss and caught is None:
                audit_error = MonitorError(
                    "strict inotify file audit reported a collection gap; "
                    "the partial trace was retained"
                )
                caught = audit_error
                caught_traceback = audit_error.__traceback__

        if snapshot_worker is not None:
            try:
                await snapshot_queue.join()
                await snapshot_queue.put(None)
                await snapshot_worker
            except BaseException as exc:
                cleanup_errors.append(_error_record(exc))
                if caught is None:
                    caught = exc
                    caught_traceback = exc.__traceback__
        if snapshot_errors:
            snapshot_error = MonitorError(
                f"workspace snapshot failed {len(snapshot_errors)} time(s): "
                f"{snapshot_errors[0]['message']}"
            )
            cleanup_errors.extend(snapshot_errors)
            if caught is None:
                caught = snapshot_error
                caught_traceback = snapshot_error.__traceback__

        if function_collector is not None:
            try:
                stats = await asyncio.to_thread(function_collector.close)
                manifest["function_trace"]["collector"] = stats
                atomic_json_dump(
                    layout.function_trace_summary,
                    {
                        "schema_version": "1.0",
                        "mode": trace_config.mode,
                        "languages": list(trace_config.languages),
                        "collector": stats,
                        "loss_counts_are_observed_lower_bounds": True,
                    },
                )
            except BaseException as exc:
                cleanup_errors.append(_error_record(exc))
                manifest["function_trace"]["collector_error"] = _error_record(exc)
                if caught is None:
                    caught = exc
                    caught_traceback = exc.__traceback__

        if snapshots is not None:
            try:
                await asyncio.to_thread(snapshots.close)
            except BaseException as exc:
                cleanup_errors.append(_error_record(exc))
                if caught is None:
                    caught = exc
                    caught_traceback = exc.__traceback__

        if recorder is not None:
            try:
                recorder.close()
            except BaseException as exc:
                cleanup_errors.append(_error_record(exc))
                if caught is None:
                    caught = exc
                    caught_traceback = exc.__traceback__

        if registry_written:
            _remove_registry(run_id)

        # Gateway removes the public socket only when its inode still matches
        # the socket it created.  Never unlink a user path here: another file
        # could have appeared after shutdown.  The backend lives inside our
        # private mkdtemp directory and is safe to remove exactly.
        try:
            if backend_socket.exists() or backend_socket.is_symlink():
                backend_socket.unlink()
        except OSError:
            pass
        try:
            temp_runtime.rmdir()
        except OSError:
            pass

        if manifest["file_audit"].get("status") == "pending":
            manifest["file_audit"]["status"] = "not_started"
        if manifest["os_audit"].get("status") == "pending":
            manifest["os_audit"]["status"] = "not_started"
        if manifest["harness_telemetry"].get("status") == "pending":
            manifest["harness_telemetry"]["status"] = "not_started"
        if manifest["request_token_tap"].get("status") == "pending":
            manifest["request_token_tap"]["status"] = "not_started"
        state.apply_manifest(manifest)
        if caught is not None:
            manifest["status"] = "failed"
            manifest["error"] = capture_transform(
                {"value": _error_record(caught)}, include_sensitive=False
            ).get("value")
        elif state.active_turns:
            manifest["status"] = "interrupted"
        elif state.connected_once:
            manifest["status"] = "completed"
        else:
            manifest["status"] = "interrupted"
        manifest["stop_reason"] = stop_reason
        manifest["finished_at"] = now_iso()
        manifest["duration_ms"] = (
            time.monotonic_ns() - started_mono_ns
        ) / 1_000_000
        if cleanup_errors:
            manifest["cleanup_errors"] = cleanup_errors
        atomic_json_dump(layout.manifest, manifest)
        try:
            persist_live_status(
                monitor_state=str(manifest["status"]),
                finished_at=str(manifest["finished_at"]),
            )
        except OSError as exc:
            cleanup_errors.append(_error_record(exc))
        try:
            persist_live_security()
        except (OSError, ValueError) as exc:
            cleanup_errors.append(_error_record(exc))

    if caught is not None:
        raise caught.with_traceback(caught_traceback)
    return layout.root
