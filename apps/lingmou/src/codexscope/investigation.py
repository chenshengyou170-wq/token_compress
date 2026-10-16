"""Project-level investigation history and evidence-chain extraction for Lingmou.

The append-only workbench JSONL journals remain the source of truth.  This
module builds a disposable SQLite index over those facts, records file identity
and version metadata without retaining file contents, and extracts bounded
forward/backward graph slices around a risky event.  A relation is never called
causal merely because two events are close in time.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import threading
import time
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlsplit


INVESTIGATION_SCHEMA_VERSION = "lingmou.investigation.v1"
HISTORY_SCHEMA_VERSION = 3
_RISK_RANK = {
    "normal": 0,
    "low": 0,
    "notice": 1,
    "warning": 2,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
_STAGE_ORDER = ("entry", "access", "collect", "transform", "egress", "outcome")
_SQL_BATCH_SIZE = 400
_MAX_INVESTIGATION_EVENTS = 5_000
_GRAPH_NOISE_KINDS = (
    "agent_delta",
    "agent_message",
    "command_output",
    "connection",
    "reasoning_summary",
    "session",
    "turn",
)
_SENSITIVE_PATH = re.compile(
    r"(?:^|[/_.-])(?:\.env|secret|secrets|credential|credentials|token|tokens|"
    r"private[-_ ]?key|api[-_ ]?key|payment[-_ ]?key|passwd|shadow|id[-_]?rsa|"
    r"authorized[-_]?keys|netrc|npmrc|pypirc|kubeconfig|dockerconfigjson|"
    r"aws[-_]?credentials|service[-_]?account)(?:$|[/_.-])",
    re.IGNORECASE,
)
_TRANSFORM_TEXT = re.compile(
    r"\b(?:base64|openssl\s+enc|gzip|bzip2|xz|tar\s|zip\s|cp\s|mv\s|tee\s)\b",
    re.IGNORECASE,
)
_DESTRUCTIVE_TEXT = re.compile(
    r"\b(?:rm\s+-[^\n]*r|unlink|shred|truncate|mkfs|dd\s+if=)\b",
    re.IGNORECASE,
)


class HistoryUnavailable(RuntimeError):
    """The optional, rebuildable history index cannot be opened."""


def _sqlite_module() -> Any:
    try:
        import sqlite3  # type: ignore[import-not-found]

        return sqlite3
    except (ImportError, ModuleNotFoundError):
        try:
            import pysqlite3 as sqlite3  # type: ignore[import-not-found]

            return sqlite3
        except (ImportError, ModuleNotFoundError) as exc:
            raise HistoryUnavailable(
                "SQLite driver unavailable; install a Python build with sqlite3 "
                "or the pysqlite3-binary compatibility driver"
            ) from exc


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _object(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list) else []


def _digest(*parts: object, size: int = 24) -> str:
    material = "\x1f".join(str(part) for part in parts)
    return hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()[:size]


def _batches(values: Sequence[str], size: int = _SQL_BATCH_SIZE) -> Iterable[list[str]]:
    for offset in range(0, len(values), size):
        yield list(values[offset : offset + size])


def project_id_for(project_root: Path | str) -> str:
    root = Path(project_root).expanduser().resolve()
    return f"project-{_digest(os.fspath(root), size=20)}"


def _state_root() -> Path:
    configured = os.environ.get("XDG_STATE_HOME")
    return Path(configured).expanduser() if configured else Path.home() / ".local" / "state"


def default_history_path(project_root: Path | str) -> Path:
    root = Path(project_root).expanduser().resolve()
    parent = _state_root() / "codexscope" / "projects" / project_id_for(root)
    try:
        parent.resolve().relative_to(root)
    except ValueError:
        pass
    else:
        uid = os.getuid() if hasattr(os, "getuid") else "user"
        parent = Path(tempfile.gettempdir()) / f"codexscope-projects-{uid}" / project_id_for(root)
    return parent / "lingmou_history.sqlite3"


def _safe_chmod(path: Path, mode: int) -> None:
    try:
        path.chmod(mode)
    except OSError:
        pass


def _timestamp(value: Any) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    return None


def _summary_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping) and value.get("omitted"):
        characters = value.get("characters")
        return f"内容未落盘 · {characters} 字符" if characters is not None else "内容未落盘"
    if value is None:
        return ""
    try:
        return json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(value)


def _event_key(run_id: str, event: Mapping[str, Any]) -> str:
    identifier = str(event.get("event_id") or f"seq-{event.get('seq', 0)}")
    return f"{run_id}:{identifier}"


def _network_entity_key(value: object) -> str:
    """Return a credential-free, stable key for one observed network target."""

    raw = str(value or "").strip()
    if not raw:
        return ""
    candidate = raw if "://" in raw else f"//{raw}"
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return raw.casefold().rstrip("/")
    host = (parsed.hostname or "").casefold()
    if not host:
        return raw.casefold().rstrip("/")
    try:
        port = parsed.port
    except ValueError:
        port = None
    authority = f"{host}:{port}" if port is not None else host
    path = parsed.path.rstrip("/")
    return f"{authority}{path}" if path else authority


def _entity_observations(
    run_id: str,
    event: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Extract linkable process/network/executable/policy entities from one event.

    Entity equality is an association key, never causality by itself.  Process
    and executable keys are scoped to one run so PID reuse and ubiquitous
    command names cannot join unrelated runs.  Exact network targets may join
    runs, but remain non-causal strong/candidate relations in the graph.
    """

    rows: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    occurred_at = float(event.get("occurred_at") or 0.0)

    def add(
        entity_type: str,
        value: object,
        *,
        role: str,
        source: str,
        tier: str,
        scope_key: str,
        attributes: Mapping[str, Any] | None = None,
        observed_at: float | None = None,
    ) -> None:
        raw = str(value or "").strip()
        if not raw:
            return
        entity_key = _network_entity_key(raw) if entity_type == "network" else raw.casefold()
        if not entity_key:
            return
        key = (entity_type, scope_key, entity_key, role)
        current = rows.get(key)
        rank = {"unproven": 0, "candidate": 1, "strong": 2, "fact": 3}
        if current is None or rank.get(tier, 0) > rank.get(str(current["confidence_tier"]), 0):
            rows[key] = {
                "entity_type": entity_type,
                "entity_key": entity_key,
                "scope_key": scope_key,
                "role": role,
                "display_value": raw,
                "source": source,
                "confidence_tier": tier,
                "observed_at": observed_at if observed_at is not None else occurred_at,
                "attributes": dict(attributes or {}),
            }

    explanation = _object(event.get("explanation"))
    effects = _object(explanation.get("effects"))
    for target in _list(effects.get("network")):
        add(
            "network",
            target,
            role="requested",
            source="deterministic_command_analysis",
            tier="candidate",
            scope_key="project",
        )
    for executable in _list(effects.get("processes")):
        add(
            "executable",
            executable,
            role="declared",
            source="deterministic_command_analysis",
            tier="candidate",
            scope_key=run_id,
        )

    evidence = _object(event.get("evidence"))
    for observation in _list(evidence.get("observations")):
        if not isinstance(observation, Mapping):
            continue
        source = str(observation.get("source") or "unknown")
        tier = "fact" if source in {"os_observation", "codex_app_server", "security_policy"} else "strong"
        observed_at = _timestamp(observation.get("observed_at")) or occurred_at
        kind = str(observation.get("kind") or "observed")
        network_target = observation.get("network_target") or observation.get("endpoint")
        if network_target:
            add(
                "network",
                network_target,
                role="observed" if source == "os_observation" else "reported",
                source=source,
                tier=tier,
                scope_key="project",
                attributes={"kind": kind, "syscall": observation.get("syscall")},
                observed_at=observed_at,
            )
        pid = observation.get("pid")
        ppid = observation.get("ppid")
        if pid is not None:
            add(
                "process",
                pid,
                role="observed",
                source=source,
                tier=tier,
                scope_key=run_id,
                attributes={"kind": kind, "ppid": ppid, "syscall": observation.get("syscall")},
                observed_at=observed_at,
            )
        if ppid is not None:
            add(
                "process",
                ppid,
                role="parent",
                source=source,
                tier=tier,
                scope_key=run_id,
                attributes={"child_pid": pid, "kind": kind},
                observed_at=observed_at,
            )
        if kind == "process" and observation.get("file_path"):
            add(
                "executable",
                observation["file_path"],
                role="executed",
                source=source,
                tier=tier,
                scope_key=run_id,
                attributes={"pid": pid, "ppid": ppid},
                observed_at=observed_at,
            )

    correlation = _object(evidence.get("correlation"))
    correlation_source = str(correlation.get("source") or "codex_app_server")
    for role, value in (("observed", correlation.get("pid")), ("parent", correlation.get("ppid"))):
        if value is not None:
            add(
                "process",
                value,
                role=role,
                source=correlation_source,
                tier="fact" if correlation.get("confidence") not in {None, "none"} else "candidate",
                scope_key=run_id,
                attributes={"correlation": correlation.get("confidence")},
            )

    risk = _object(explanation.get("risk"))
    for role, value in (("policy", risk.get("policy_id")), ("rule", risk.get("blocking_rule"))):
        if value:
            add(
                "policy",
                value,
                role=role,
                source="security_policy",
                tier="fact",
                scope_key="project",
            )
    return sorted(
        rows.values(),
        key=lambda row: (
            str(row["entity_type"]),
            str(row["scope_key"]),
            str(row["entity_key"]),
            str(row["role"]),
        ),
    )


def _risk(event: Mapping[str, Any]) -> tuple[str, int]:
    explanation = _object(event.get("explanation"))
    risk = _object(explanation.get("risk"))
    level = str(risk.get("level") or ("critical" if event.get("kind") == "policy_block" else "normal")).lower()
    return level, _RISK_RANK.get(level, 0)


def _is_anchor(event: Mapping[str, Any]) -> bool:
    level, rank = _risk(event)
    explanation = _object(event.get("explanation"))
    effects = _object(explanation.get("effects"))
    action = str(explanation.get("action") or "").lower()
    return bool(
        event.get("kind") == "policy_block"
        or event.get("status") == "blocked"
        or rank >= 3
        or (
            rank >= 2
            and (
                effects.get("network")
                or effects.get("external_write")
                or action in {"upload_data", "delete_files", "change_permissions"}
            )
        )
        or (level == "warning" and _DESTRUCTIVE_TEXT.search(_summary_text(event.get("summary"))))
    )


def _sensitive_labels(path: str) -> list[str]:
    labels: list[str] = []
    normalized = path.casefold()
    if _SENSITIVE_PATH.search(normalized):
        labels.append("sensitive_path")
    if "payment" in normalized and any(term in normalized for term in ("key", "secret", ".env")):
        labels.append("payment_credential")
    if any(term in normalized for term in ("private_key", "id_rsa", "authorized_keys")):
        labels.append("authentication_material")
    return labels


class FileSnapshotter:
    """Capture identity/version metadata for event-referenced project files."""

    def __init__(self, project_root: Path | str, *, max_hash_bytes: int = 64 * 1024 * 1024) -> None:
        self.project_root = Path(project_root).expanduser().resolve()
        self.project_id = project_id_for(self.project_root)
        self.max_hash_bytes = max_hash_bytes
        self._git_object_format: str | None | bool = None

    def _git_format(self) -> str | None:
        if self._git_object_format is not None:
            return self._git_object_format if isinstance(self._git_object_format, str) else None
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--show-object-format"],
                cwd=self.project_root,
                check=True,
                capture_output=True,
                text=True,
                timeout=3,
            )
            value = result.stdout.strip().lower()
            self._git_object_format = value if value in {"sha1", "sha256"} else False
        except (OSError, subprocess.SubprocessError):
            self._git_object_format = False
        return self._git_object_format if isinstance(self._git_object_format, str) else None

    def _normalize(self, value: object) -> tuple[str, Path | None, str]:
        raw = str(value or "").strip()
        if not raw:
            return "", None, "unknown"
        candidate = Path(raw).expanduser()
        resolved = candidate.resolve(strict=False) if candidate.is_absolute() else (self.project_root / candidate).resolve(strict=False)
        try:
            relative = resolved.relative_to(self.project_root).as_posix()
        except ValueError:
            return raw, None, "external"
        return relative, resolved, "workspace"

    @staticmethod
    def _access_for_observation(kind: str) -> str | None:
        return {
            "file_read": "read",
            "file_write": "write",
            "file_change": "write",
            "file_delete": "delete",
            "file_move": "rename",
            "permission_change": "metadata_write",
            "process": "execute",
        }.get(kind)

    def _capture_path(
        self,
        path: str,
        resolved: Path | None,
        *,
        scope: str,
        accesses: Sequence[str],
        sources: Sequence[str],
        confidence_tier: str,
        observed_at: float,
        observed_from: float,
        observed_to: float,
        processes: Sequence[Mapping[str, Any]] = (),
        line_ranges: Sequence[Mapping[str, Any]] = (),
    ) -> dict[str, Any]:
        base: dict[str, Any] = {
            "path": path,
            "scope": scope,
            "accesses": sorted(set(accesses)),
            "sources": sorted(set(sources)),
            "confidence_tier": confidence_tier,
            "observed_at": observed_at,
            "observed_from": observed_from,
            "observed_to": observed_to,
            "processes": [dict(value) for value in processes],
            "line_ranges": [dict(value) for value in line_ranges],
            "device": None,
            "inode": None,
            "mode": None,
            "size": None,
            "mtime_ns": None,
            "content_sha256": None,
            "git_blob": None,
            "capture_completeness": "unavailable",
        }
        if resolved is None:
            base["identity_id"] = f"file-{_digest(self.project_id, 'path', path)}"
            base["identity_basis"] = "path_only"
            base["version_id"] = None
            return base
        try:
            metadata = resolved.lstat()
        except OSError:
            base["identity_id"] = f"file-{_digest(self.project_id, 'path', path)}"
            base["identity_basis"] = "path_only"
            base["version_id"] = None
            return base

        base.update(
            {
                "device": int(metadata.st_dev),
                "inode": int(metadata.st_ino),
                "mode": int(metadata.st_mode),
                "size": int(metadata.st_size),
                "mtime_ns": int(metadata.st_mtime_ns),
                "capture_completeness": "metadata_only",
            }
        )
        identity_id = f"file-{_digest(self.project_id, metadata.st_dev, metadata.st_ino, stat.S_IFMT(metadata.st_mode))}"
        base["identity_id"] = identity_id
        base["identity_basis"] = "device_inode"
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > self.max_hash_bytes:
            base["version_id"] = f"version-{_digest(identity_id, metadata.st_size, metadata.st_mtime_ns)}"
            return base

        descriptor: int | None = None
        try:
            descriptor = os.open(
                resolved,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            )
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise OSError("file identity changed during metadata capture")
            sha256 = hashlib.sha256()
            object_format = self._git_format()
            git_hasher = hashlib.new(object_format) if object_format else None
            if git_hasher is not None:
                git_hasher.update(f"blob {opened.st_size}\0".encode("ascii"))
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                sha256.update(chunk)
                if git_hasher is not None:
                    git_hasher.update(chunk)
            base["content_sha256"] = sha256.hexdigest()
            base["git_blob"] = git_hasher.hexdigest() if git_hasher is not None else None
            base["capture_completeness"] = "content_hash"
        except OSError:
            pass
        finally:
            if descriptor is not None:
                os.close(descriptor)
        base["version_id"] = f"version-{_digest(identity_id, base.get('content_sha256'), base.get('git_blob'), metadata.st_size, metadata.st_mtime_ns)}"
        return base

    def capture(
        self,
        *,
        explanation: Mapping[str, Any] | None,
        evidence: Mapping[str, Any] | None,
        payload: Any,
        kind: str,
        status: str,
        observed_at: float,
    ) -> list[dict[str, Any]]:
        candidates: dict[str, dict[str, Any]] = {}
        safe_evidence = _object(evidence)
        correlation = _object(safe_evidence.get("correlation"))

        def interval(value: Mapping[str, Any] | None = None) -> tuple[float, float]:
            item = value or {}
            start = (
                _timestamp(item.get("started_at"))
                or _timestamp(item.get("observed_at"))
                or _timestamp(correlation.get("started_at"))
                or observed_at
            )
            end = (
                _timestamp(item.get("ended_at"))
                or _timestamp(item.get("observed_at"))
                or _timestamp(correlation.get("ended_at"))
                or start
            )
            return min(start, end), max(start, end)

        def process(value: Mapping[str, Any] | None = None) -> dict[str, Any] | None:
            item = value or {}
            pid = item.get("pid", correlation.get("pid"))
            ppid = item.get("ppid", correlation.get("ppid"))
            if pid is None and ppid is None:
                return None
            return {
                "pid": pid,
                "ppid": ppid,
                "source": str(item.get("source") or correlation.get("source") or "unknown"),
            }

        def add(
            value: object,
            access: str,
            source: str,
            tier: str,
            line_ranges: Sequence[Mapping[str, Any]] = (),
            observation: Mapping[str, Any] | None = None,
        ) -> None:
            path, resolved, scope = self._normalize(value)
            if not path:
                return
            current = candidates.setdefault(
                path,
                {
                    "resolved": resolved,
                    "scope": scope,
                    "accesses": set(),
                    "sources": set(),
                    "tier": tier,
                    "line_ranges": [],
                    "observed_from": [],
                    "observed_to": [],
                    "processes": {},
                },
            )
            current["accesses"].add(access)
            current["sources"].add(source)
            if tier == "fact" or current["tier"] == "unproven":
                current["tier"] = tier
            current["line_ranges"].extend(dict(item) for item in line_ranges)
            has_explicit_interval = bool(
                (observation and any(observation.get(key) is not None for key in ("started_at", "ended_at", "observed_at")))
                or any(correlation.get(key) is not None for key in ("started_at", "ended_at"))
            )
            if has_explicit_interval or not current["observed_from"]:
                started_at, ended_at = interval(observation)
                current["observed_from"].append(started_at)
                current["observed_to"].append(ended_at)
            process_value = process(observation)
            if process_value is not None:
                process_key = (
                    str(process_value.get("pid")),
                    str(process_value.get("ppid")),
                    str(process_value.get("source")),
                )
                current["processes"][process_key] = process_value

        for observation in _list(safe_evidence.get("observations")):
            if not isinstance(observation, Mapping) or not observation.get("file_path"):
                continue
            access = self._access_for_observation(str(observation.get("kind") or ""))
            if access:
                add(
                    observation["file_path"],
                    access,
                    str(observation.get("source") or "os_observation"),
                    "fact" if observation.get("source") == "os_observation" else "strong",
                    observation=observation,
                )

        safe_explanation = _object(explanation)
        effects = _object(safe_explanation.get("effects"))
        pre_execution = safe_evidence.get("availability") == "pre_execution" or status == "blocked"
        for path in _list(effects.get("reads")):
            add(
                path,
                "attempted_read" if pre_execution else "read",
                str(safe_explanation.get("sources", ["deterministic_command_analysis"])[0] if _list(safe_explanation.get("sources")) else "deterministic_command_analysis"),
                "strong" if pre_execution else "candidate",
            )
        for path in _list(effects.get("writes")):
            add(
                path,
                "attempted_write" if pre_execution else "write",
                "deterministic_command_analysis",
                "strong" if pre_execution else "candidate",
            )

        safe_payload = _object(payload)
        item = _object(safe_payload.get("item"))
        nested_item = _object(item.get("item")) if "item" in item else item
        for change in _list(nested_item.get("changes")):
            if isinstance(change, Mapping) and change.get("path"):
                add(
                    change["path"],
                    "write" if status != "blocked" else "attempted_write",
                    "codex_app_server",
                    "fact" if status != "blocked" else "strong",
                    _list(change.get("line_ranges")),
                )

        snapshots = [
            self._capture_path(
                path,
                value["resolved"],
                scope=str(value["scope"]),
                accesses=sorted(value["accesses"]),
                sources=sorted(value["sources"]),
                confidence_tier=str(value["tier"]),
                observed_at=observed_at,
                observed_from=min(value["observed_from"]) if value["observed_from"] else observed_at,
                observed_to=max(value["observed_to"]) if value["observed_to"] else observed_at,
                processes=list(value["processes"].values()),
                line_ranges=value["line_ranges"],
            )
            for path, value in sorted(candidates.items())
        ]
        for snapshot in snapshots:
            snapshot["sensitivity_labels"] = _sensitive_labels(str(snapshot["path"]))
        return snapshots


def _load_manifest(run_dir: Path) -> dict[str, Any]:
    path = run_dir / "manifest.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def run_id_for(run_dir: Path | str) -> str:
    path = Path(run_dir).expanduser().resolve()
    manifest = _load_manifest(path)
    return str(manifest.get("run_id") or f"run-{_digest(path, size=20)}")


class ProjectHistoryIndex:
    """Rebuildable project index and investigation query engine."""

    def __init__(
        self,
        project_root: Path | str,
        *,
        path: Path | str | None = None,
        forensic_key: bytes | None = None,
    ) -> None:
        self.project_root = Path(project_root).expanduser().resolve()
        self.project_id = project_id_for(self.project_root)
        self.path = Path(path).expanduser().resolve() if path else default_history_path(self.project_root)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        _safe_chmod(self.path.parent, 0o700)
        self._forensic_key = forensic_key
        if forensic_key is not None and len(forensic_key) != 32:
            raise ValueError("forensic_key must contain exactly 32 bytes")
        if forensic_key is not None:
            try:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
            except (ImportError, ModuleNotFoundError) as exc:
                raise HistoryUnavailable(
                    "forensic history encryption requires the codexscope[forensic] extra"
                ) from exc
        self._sqlite = _sqlite_module()
        self._connection = self._sqlite.connect(os.fspath(self.path), check_same_thread=False)
        self._connection.row_factory = self._sqlite.Row
        self._lock = threading.RLock()
        self._initialize()
        _safe_chmod(self.path, 0o600)

    def _initialize(self) -> None:
        with self._lock, self._connection:
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA synchronous=NORMAL")
            self._connection.execute("PRAGMA foreign_keys=ON")
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    run_dir TEXT NOT NULL,
                    journal_path TEXT NOT NULL,
                    started_at REAL,
                    ended_at REAL,
                    thread_count INTEGER NOT NULL DEFAULT 0,
                    event_count INTEGER NOT NULL DEFAULT 0,
                    anchor_count INTEGER NOT NULL DEFAULT 0,
                    manifest_json TEXT NOT NULL DEFAULT '{}',
                    last_indexed_seq INTEGER NOT NULL DEFAULT 0,
                    indexed_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events (
                    event_key TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                    seq INTEGER NOT NULL,
                    event_id TEXT NOT NULL,
                    occurred_at REAL NOT NULL,
                    kind TEXT NOT NULL,
                    source TEXT NOT NULL,
                    status TEXT NOT NULL,
                    thread_id TEXT,
                    turn_id TEXT,
                    item_id TEXT,
                    title TEXT NOT NULL,
                    summary_text TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    risk_rank INTEGER NOT NULL,
                    is_anchor INTEGER NOT NULL,
                    event_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS events_anchor_time ON events(is_anchor, occurred_at DESC);
                CREATE INDEX IF NOT EXISTS events_scope ON events(run_id, thread_id, turn_id, occurred_at);
                CREATE INDEX IF NOT EXISTS events_item ON events(run_id, item_id, occurred_at);
                CREATE TABLE IF NOT EXISTS file_identities (
                    identity_id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    preferred_path TEXT NOT NULL,
                    identity_basis TEXT NOT NULL,
                    device INTEGER,
                    inode INTEGER,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS file_versions (
                    version_id TEXT PRIMARY KEY,
                    identity_id TEXT NOT NULL REFERENCES file_identities(identity_id) ON DELETE CASCADE,
                    path TEXT NOT NULL,
                    content_sha256 TEXT,
                    git_blob TEXT,
                    size INTEGER,
                    mtime_ns INTEGER,
                    capture_completeness TEXT NOT NULL,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS file_versions_content ON file_versions(content_sha256);
                CREATE INDEX IF NOT EXISTS file_versions_blob ON file_versions(git_blob);
                CREATE TABLE IF NOT EXISTS file_aliases (
                    identity_id TEXT NOT NULL REFERENCES file_identities(identity_id) ON DELETE CASCADE,
                    path TEXT NOT NULL,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    PRIMARY KEY(identity_id, path)
                );
                CREATE INDEX IF NOT EXISTS file_alias_path ON file_aliases(path);
                CREATE TABLE IF NOT EXISTS file_accesses (
                    event_key TEXT NOT NULL REFERENCES events(event_key) ON DELETE CASCADE,
                    identity_id TEXT NOT NULL REFERENCES file_identities(identity_id) ON DELETE CASCADE,
                    version_id TEXT,
                    path TEXT NOT NULL,
                    access TEXT NOT NULL,
                    source TEXT NOT NULL,
                    confidence_tier TEXT NOT NULL,
                    observed_at REAL NOT NULL,
                    observed_from REAL,
                    observed_to REAL,
                    processes_json TEXT NOT NULL DEFAULT '[]',
                    line_ranges_json TEXT NOT NULL DEFAULT '[]',
                    capture_completeness TEXT NOT NULL,
                    PRIMARY KEY(event_key, identity_id, path, access)
                );
                CREATE INDEX IF NOT EXISTS file_access_identity_time ON file_accesses(identity_id, observed_at);
                CREATE INDEX IF NOT EXISTS file_access_path_time ON file_accesses(path, observed_at);
                CREATE TABLE IF NOT EXISTS entity_observations (
                    event_key TEXT NOT NULL REFERENCES events(event_key) ON DELETE CASCADE,
                    entity_type TEXT NOT NULL,
                    entity_key TEXT NOT NULL,
                    scope_key TEXT NOT NULL,
                    role TEXT NOT NULL,
                    display_value TEXT NOT NULL,
                    source TEXT NOT NULL,
                    confidence_tier TEXT NOT NULL,
                    observed_at REAL NOT NULL,
                    attributes_json TEXT NOT NULL DEFAULT '{}',
                    PRIMARY KEY(event_key, entity_type, scope_key, entity_key, role)
                );
                CREATE INDEX IF NOT EXISTS entity_observation_lookup
                    ON entity_observations(entity_type, scope_key, entity_key, observed_at);
                CREATE INDEX IF NOT EXISTS entity_observation_event
                    ON entity_observations(event_key, observed_at);
                CREATE TABLE IF NOT EXISTS sensitivity_labels (
                    identity_id TEXT NOT NULL REFERENCES file_identities(identity_id) ON DELETE CASCADE,
                    label TEXT NOT NULL,
                    source_event_key TEXT NOT NULL,
                    confidence_tier TEXT NOT NULL,
                    PRIMARY KEY(identity_id, label, source_event_key)
                );
                CREATE TABLE IF NOT EXISTS context_capsules (
                    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                    thread_id TEXT NOT NULL,
                    turn_id TEXT NOT NULL,
                    started_at REAL,
                    ended_at REAL,
                    summary_json TEXT NOT NULL,
                    context_hash TEXT NOT NULL,
                    encrypted_context TEXT,
                    encryption TEXT,
                    PRIMARY KEY(run_id, thread_id, turn_id)
                );
                """
            )
            existing_access_columns = {
                str(row[1])
                for row in self._connection.execute("PRAGMA table_info(file_accesses)").fetchall()
            }
            for name, declaration in (
                ("observed_from", "REAL"),
                ("observed_to", "REAL"),
                ("processes_json", "TEXT NOT NULL DEFAULT '[]'"),
            ):
                if name not in existing_access_columns:
                    self._connection.execute(
                        f"ALTER TABLE file_accesses ADD COLUMN {name} {declaration}"
                    )
            self._connection.execute(
                "INSERT OR REPLACE INTO metadata(key, value) VALUES('schema_version', ?)",
                (str(HISTORY_SCHEMA_VERSION),),
            )
            self._connection.execute(
                "INSERT OR REPLACE INTO metadata(key, value) VALUES('project_id', ?)",
                (self.project_id,),
            )
            self._connection.execute(
                "INSERT OR REPLACE INTO metadata(key, value) VALUES('project_root', ?)",
                (os.fspath(self.project_root),),
            )

    def register_run(
        self,
        run_id: str,
        run_dir: Path | str,
        *,
        journal_path: Path | str,
        manifest: Mapping[str, Any] | None = None,
    ) -> None:
        directory = Path(run_dir).expanduser().resolve()
        safe_manifest = dict(manifest or {})
        started_at = _timestamp(safe_manifest.get("started_at"))
        ended_at = _timestamp(safe_manifest.get("finished_at"))
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO runs(
                    run_id, project_id, run_dir, journal_path, started_at, ended_at,
                    manifest_json, indexed_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    run_dir=excluded.run_dir,
                    journal_path=excluded.journal_path,
                    started_at=COALESCE(runs.started_at, excluded.started_at),
                    ended_at=COALESCE(excluded.ended_at, runs.ended_at),
                    manifest_json=excluded.manifest_json,
                    indexed_at=excluded.indexed_at
                """,
                (
                    run_id,
                    self.project_id,
                    os.fspath(directory),
                    os.fspath(Path(journal_path).expanduser().resolve()),
                    started_at,
                    ended_at,
                    _json(safe_manifest),
                    time.time(),
                ),
            )

    def _write_snapshot(self, event_key: str, snapshot: Mapping[str, Any]) -> None:
        identity_id = str(snapshot.get("identity_id") or f"file-{_digest(self.project_id, snapshot.get('path'))}")
        path = str(snapshot.get("path") or "<unknown>")
        observed_at = float(snapshot.get("observed_at") or 0.0)
        observed_from = float(snapshot.get("observed_from") or observed_at)
        observed_to = float(snapshot.get("observed_to") or observed_at)
        self._connection.execute(
            """
            INSERT INTO file_identities(
                identity_id, project_id, preferred_path, identity_basis, device, inode,
                first_seen, last_seen
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(identity_id) DO UPDATE SET
                preferred_path=excluded.preferred_path,
                device=COALESCE(file_identities.device, excluded.device),
                inode=COALESCE(file_identities.inode, excluded.inode),
                first_seen=MIN(file_identities.first_seen, excluded.first_seen),
                last_seen=MAX(file_identities.last_seen, excluded.last_seen)
            """,
            (
                identity_id,
                self.project_id,
                path,
                str(snapshot.get("identity_basis") or "path_only"),
                snapshot.get("device"),
                snapshot.get("inode"),
                observed_at,
                observed_at,
            ),
        )
        self._connection.execute(
            """
            INSERT INTO file_aliases(identity_id, path, first_seen, last_seen)
            VALUES(?, ?, ?, ?)
            ON CONFLICT(identity_id, path) DO UPDATE SET
                first_seen=MIN(file_aliases.first_seen, excluded.first_seen),
                last_seen=MAX(file_aliases.last_seen, excluded.last_seen)
            """,
            (identity_id, path, observed_at, observed_at),
        )
        version_id = snapshot.get("version_id")
        if version_id:
            self._connection.execute(
                """
                INSERT INTO file_versions(
                    version_id, identity_id, path, content_sha256, git_blob, size,
                    mtime_ns, capture_completeness, first_seen, last_seen
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(version_id) DO UPDATE SET
                    path=excluded.path,
                    first_seen=MIN(file_versions.first_seen, excluded.first_seen),
                    last_seen=MAX(file_versions.last_seen, excluded.last_seen)
                """,
                (
                    str(version_id),
                    identity_id,
                    path,
                    snapshot.get("content_sha256"),
                    snapshot.get("git_blob"),
                    snapshot.get("size"),
                    snapshot.get("mtime_ns"),
                    str(snapshot.get("capture_completeness") or "unavailable"),
                    observed_at,
                    observed_at,
                ),
            )
        sources = [str(value) for value in _list(snapshot.get("sources"))] or ["unknown"]
        for access in [str(value) for value in _list(snapshot.get("accesses"))]:
            self._connection.execute(
                """
                INSERT OR REPLACE INTO file_accesses(
                    event_key, identity_id, version_id, path, access, source,
                    confidence_tier, observed_at, observed_from, observed_to,
                    processes_json, line_ranges_json, capture_completeness
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_key,
                    identity_id,
                    str(version_id) if version_id else None,
                    path,
                    access,
                    "+".join(sorted(set(sources))),
                    str(snapshot.get("confidence_tier") or "candidate"),
                    observed_at,
                    observed_from,
                    observed_to,
                    _json(_list(snapshot.get("processes"))),
                    _json(_list(snapshot.get("line_ranges"))),
                    str(snapshot.get("capture_completeness") or "unavailable"),
                ),
            )
        for label in [str(value) for value in _list(snapshot.get("sensitivity_labels"))]:
            self._connection.execute(
                """
                INSERT OR IGNORE INTO sensitivity_labels(
                    identity_id, label, source_event_key, confidence_tier
                ) VALUES(?, ?, ?, ?)
                """,
                (identity_id, label, event_key, str(snapshot.get("confidence_tier") or "candidate")),
            )

    def _propagate_sensitivity(self, event_key: str) -> None:
        rows = self._connection.execute(
            "SELECT identity_id, access, confidence_tier FROM file_accesses WHERE event_key=?",
            (event_key,),
        ).fetchall()
        inputs = [row for row in rows if row["access"] in {"read", "attempted_read"}]
        outputs = [row for row in rows if row["access"] in {"write", "attempted_write", "rename"}]
        if not inputs or not outputs:
            return
        labels: list[tuple[str, str]] = []
        for row in inputs:
            labels.extend(
                (str(value["label"]), str(value["confidence_tier"]))
                for value in self._connection.execute(
                    "SELECT label, confidence_tier FROM sensitivity_labels WHERE identity_id=?",
                    (row["identity_id"],),
                ).fetchall()
            )
        for output in outputs:
            for label, input_tier in labels:
                tier = "strong" if input_tier in {"fact", "strong"} and output["confidence_tier"] in {"fact", "strong"} else "candidate"
                self._connection.execute(
                    """
                    INSERT OR IGNORE INTO sensitivity_labels(
                        identity_id, label, source_event_key, confidence_tier
                    ) VALUES(?, ?, ?, ?)
                    """,
                    (output["identity_id"], f"derived:{label}", event_key, tier),
                )

    def _write_entities(
        self,
        run_id: str,
        event_key: str,
        event: Mapping[str, Any],
    ) -> None:
        self._connection.execute(
            "DELETE FROM entity_observations WHERE event_key=?",
            (event_key,),
        )
        for row in _entity_observations(run_id, event):
            self._connection.execute(
                """
                INSERT OR REPLACE INTO entity_observations(
                    event_key, entity_type, entity_key, scope_key, role,
                    display_value, source, confidence_tier, observed_at,
                    attributes_json
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_key,
                    row["entity_type"],
                    row["entity_key"],
                    row["scope_key"],
                    row["role"],
                    row["display_value"],
                    row["source"],
                    row["confidence_tier"],
                    row["observed_at"],
                    _json(row["attributes"]),
                ),
            )

    def _write_event(self, run_id: str, event: Mapping[str, Any]) -> None:
        event_key = _event_key(run_id, event)
        level, rank = _risk(event)
        self._connection.execute(
            """
            INSERT OR REPLACE INTO events(
                event_key, run_id, seq, event_id, occurred_at, kind, source, status,
                thread_id, turn_id, item_id, title, summary_text, risk_level,
                risk_rank, is_anchor, event_json
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_key,
                run_id,
                int(event.get("seq") or 0),
                str(event.get("event_id") or f"seq-{event.get('seq', 0)}"),
                float(event.get("occurred_at") or 0.0),
                str(event.get("kind") or "unknown"),
                str(event.get("source") or "unknown"),
                str(event.get("status") or "info"),
                str(event.get("thread_id")) if event.get("thread_id") is not None else None,
                str(event.get("turn_id")) if event.get("turn_id") is not None else None,
                str(event.get("item_id")) if event.get("item_id") is not None else None,
                str(event.get("title") or "Agent 活动"),
                _summary_text(event.get("summary")),
                level,
                rank,
                1 if _is_anchor(event) else 0,
                _json(dict(event)),
            ),
        )
        self._connection.execute("DELETE FROM file_accesses WHERE event_key=?", (event_key,))
        for snapshot in _list(event.get("file_snapshots")):
            if isinstance(snapshot, Mapping):
                self._write_snapshot(event_key, snapshot)
        self._propagate_sensitivity(event_key)
        self._write_entities(run_id, event_key, event)

    def _refresh_run_stats(self, run_id: str) -> None:
        counts = self._connection.execute(
            """
            SELECT COUNT(*) AS events,
                   COUNT(DISTINCT thread_id) AS threads,
                   SUM(is_anchor) AS anchors,
                   MAX(seq) AS last_seq,
                   MIN(occurred_at) AS first_time,
                   MAX(occurred_at) AS last_time
            FROM events WHERE run_id=?
            """,
            (run_id,),
        ).fetchone()
        self._connection.execute(
            """
            UPDATE runs SET event_count=?, thread_count=?, anchor_count=?,
                last_indexed_seq=?, started_at=COALESCE(started_at, ?),
                ended_at=CASE WHEN ended_at IS NULL THEN ? ELSE ended_at END,
                indexed_at=?
            WHERE run_id=?
            """,
            (
                int(counts["events"] or 0),
                int(counts["threads"] or 0),
                int(counts["anchors"] or 0),
                int(counts["last_seq"] or 0),
                counts["first_time"],
                counts["last_time"],
                time.time(),
                run_id,
            ),
        )

    def index_event(
        self,
        run_id: str,
        event: Mapping[str, Any],
        *,
        forensic_events: Sequence[Mapping[str, Any]] | None = None,
    ) -> None:
        with self._lock, self._connection:
            self._write_event(run_id, event)
            self._refresh_run_stats(run_id)
            if event.get("turn_id") and (
                event.get("kind") == "turn"
                and str(event.get("status")) in {"completed", "failed", "interrupted", "blocked"}
            ):
                self._rebuild_capsule(
                    run_id,
                    str(event.get("thread_id") or "unknown-thread"),
                    str(event.get("turn_id")),
                    forensic_events=forensic_events,
                )

    def ingest_run(
        self,
        run_dir: Path | str,
        events: Iterable[Mapping[str, Any]],
        *,
        run_id: str | None = None,
    ) -> int:
        directory = Path(run_dir).expanduser().resolve()
        identifier = run_id or run_id_for(directory)
        manifest = _load_manifest(directory)
        journal_path = directory / "workbench_events.jsonl"
        self.register_run(identifier, directory, journal_path=journal_path, manifest=manifest)
        count = 0
        scopes: set[tuple[str, str]] = set()
        with self._lock, self._connection:
            for event in events:
                self._write_event(identifier, event)
                count += 1
                if event.get("turn_id"):
                    scopes.add((str(event.get("thread_id") or "unknown-thread"), str(event["turn_id"])))
            self._refresh_run_stats(identifier)
            for thread_id, turn_id in scopes:
                self._rebuild_capsule(identifier, thread_id, turn_id)
        return count

    @staticmethod
    def _read_journal(path: Path) -> list[dict[str, Any]]:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []
        events: list[dict[str, Any]] = []
        for index, line in enumerate(lines):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                if index == len(lines) - 1:
                    break
                continue
            if isinstance(value, dict):
                events.append(value)
        return events

    def discover_run_dirs(self, current_run_dir: Path | str | None = None) -> list[Path]:
        roots = {_state_root() / "codexscope" / "runs"}
        if current_run_dir is not None:
            current = Path(current_run_dir).expanduser().resolve()
            roots.add(current.parent)
        matches: set[Path] = set()
        for root in roots:
            try:
                candidates = list(root.iterdir())[:10_000]
            except OSError:
                continue
            for candidate in candidates:
                if not candidate.is_dir() or not (candidate / "workbench_events.jsonl").is_file():
                    continue
                manifest = _load_manifest(candidate)
                repo = manifest.get("repo")
                if repo is None:
                    continue
                try:
                    if Path(str(repo)).expanduser().resolve() == self.project_root:
                        matches.add(candidate.resolve())
                except OSError:
                    continue
        if current_run_dir is not None:
            current = Path(current_run_dir).expanduser().resolve()
            if (current / "workbench_events.jsonl").is_file():
                matches.add(current)
        return sorted(matches)

    def rebuild(
        self,
        *,
        current_run_dir: Path | str | None = None,
        discover_runs: bool = True,
    ) -> dict[str, Any]:
        if discover_runs:
            run_dirs = self.discover_run_dirs(current_run_dir)
        elif current_run_dir is not None:
            current = Path(current_run_dir).expanduser().resolve()
            run_dirs = (
                [current]
                if (current / "workbench_events.jsonl").is_file()
                else []
            )
        else:
            run_dirs = []
        with self._lock, self._connection:
            preserved_capsules = [
                dict(row)
                for row in self._connection.execute(
                    "SELECT * FROM context_capsules WHERE encrypted_context IS NOT NULL"
                ).fetchall()
            ]
            for table in (
                "context_capsules",
                "sensitivity_labels",
                "file_accesses",
                "file_aliases",
                "file_versions",
                "file_identities",
                "events",
                "runs",
            ):
                self._connection.execute(f"DELETE FROM {table}")
        indexed_events = 0
        for run_dir in run_dirs:
            indexed_events += self.ingest_run(
                run_dir,
                self._read_journal(run_dir / "workbench_events.jsonl"),
            )
        with self._lock, self._connection:
            for capsule in preserved_capsules:
                if self._connection.execute(
                    "SELECT 1 FROM runs WHERE run_id=?",
                    (capsule["run_id"],),
                ).fetchone() is None:
                    continue
                current = self._connection.execute(
                    """
                    SELECT * FROM context_capsules
                    WHERE run_id=? AND thread_id=? AND turn_id=?
                    """,
                    (capsule["run_id"], capsule["thread_id"], capsule["turn_id"]),
                ).fetchone()
                summary = json.loads(
                    current["summary_json"] if current is not None else capsule["summary_json"]
                )
                privacy = _object(summary.get("privacy"))
                privacy.update(
                    {
                        "conversation": "encrypted",
                        "forensic_capture": "preserved_encrypted_capsule",
                    }
                )
                summary["privacy"] = privacy
                self._connection.execute(
                    """
                    INSERT OR REPLACE INTO context_capsules(
                        run_id, thread_id, turn_id, started_at, ended_at, summary_json,
                        context_hash, encrypted_context, encryption
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        capsule["run_id"],
                        capsule["thread_id"],
                        capsule["turn_id"],
                        current["started_at"] if current is not None else capsule["started_at"],
                        current["ended_at"] if current is not None else capsule["ended_at"],
                        _json(summary),
                        capsule["context_hash"],
                        capsule["encrypted_context"],
                        capsule["encryption"],
                    ),
                )
        return {
            "schema_version": INVESTIGATION_SCHEMA_VERSION,
            "project_id": self.project_id,
            "run_count": len(run_dirs),
            "event_count": indexed_events,
            "index_path": os.fspath(self.path),
            "rebuilt_at": time.time(),
        }

    def sync_discovered_runs(
        self,
        *,
        current_run_dir: Path | str | None = None,
    ) -> dict[str, Any]:
        """Incrementally import matching journals without clearing the index."""

        run_dirs = self.discover_run_dirs(current_run_dir)
        current = (
            Path(current_run_dir).expanduser().resolve()
            if current_run_dir is not None
            else None
        )
        imported_runs = 0
        imported_events = 0
        for run_dir in run_dirs:
            if current is not None and run_dir == current:
                continue
            journal = run_dir / "workbench_events.jsonl"
            events = self._read_journal(journal)
            identifier = run_id_for(run_dir)
            last_seq = max((int(event.get("seq") or 0) for event in events), default=0)
            with self._lock:
                row = self._connection.execute(
                    "SELECT last_indexed_seq FROM runs WHERE run_id=?",
                    (identifier,),
                ).fetchone()
            if row is not None and int(row["last_indexed_seq"] or 0) >= last_seq:
                continue
            imported_events += self.ingest_run(run_dir, events, run_id=identifier)
            imported_runs += 1
        return {
            "schema_version": INVESTIGATION_SCHEMA_VERSION,
            "run_count": len(run_dirs),
            "imported_run_count": imported_runs,
            "imported_event_count": imported_events,
        }

    def _encrypt_context(self, payload: bytes, *, run_id: str, thread_id: str, turn_id: str) -> str | None:
        if self._forensic_key is None:
            return None
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore[import-not-found]
        except (ImportError, ModuleNotFoundError) as exc:
            raise HistoryUnavailable(
                "forensic history encryption requires the codexscope[forensic] extra"
            ) from exc
        nonce = os.urandom(12)
        aad = f"{INVESTIGATION_SCHEMA_VERSION}:{run_id}:{thread_id}:{turn_id}".encode("utf-8")
        encrypted = AESGCM(self._forensic_key).encrypt(nonce, payload, aad)
        return base64.b64encode(nonce + encrypted).decode("ascii")

    def _decrypt_context(self, value: str, *, run_id: str, thread_id: str, turn_id: str) -> Any:
        if self._forensic_key is None:
            raise HistoryUnavailable("forensic context key is not loaded")
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore[import-not-found]
        except (ImportError, ModuleNotFoundError) as exc:
            raise HistoryUnavailable(
                "forensic history decryption requires the codexscope[forensic] extra"
            ) from exc
        try:
            data = base64.b64decode(value, validate=True)
            if len(data) < 29:
                raise ValueError("encrypted context envelope is truncated")
            aad = f"{INVESTIGATION_SCHEMA_VERSION}:{run_id}:{thread_id}:{turn_id}".encode("utf-8")
            plaintext = AESGCM(self._forensic_key).decrypt(data[:12], data[12:], aad)
            return json.loads(plaintext)
        except Exception as exc:
            raise HistoryUnavailable(
                "forensic context could not be decrypted with the loaded key"
            ) from exc

    def _rebuild_capsule(
        self,
        run_id: str,
        thread_id: str,
        turn_id: str,
        *,
        forensic_events: Sequence[Mapping[str, Any]] | None = None,
    ) -> None:
        rows = self._connection.execute(
            """
            SELECT event_json FROM events
            WHERE run_id=? AND COALESCE(thread_id, 'unknown-thread')=? AND turn_id=?
            ORDER BY occurred_at, seq
            """,
            (run_id, thread_id, turn_id),
        ).fetchall()
        if not rows:
            return
        events = [json.loads(row["event_json"]) for row in rows]
        accesses = self._connection.execute(
            """
            SELECT DISTINCT fa.path, fa.access
            FROM file_accesses fa JOIN events e ON e.event_key=fa.event_key
            WHERE e.run_id=? AND COALESCE(e.thread_id, 'unknown-thread')=? AND e.turn_id=?
            ORDER BY fa.path
            """,
            (run_id, thread_id, turn_id),
        ).fetchall()
        prompts = [event for event in events if event.get("kind") == "user_prompt"]
        plan_titles = list(
            dict.fromkeys(
                str(_object(event.get("step")).get("title"))
                for event in events
                if _object(event.get("step")).get("title")
            )
        )
        reads = sorted({str(row["path"]) for row in accesses if row["access"] in {"read", "attempted_read"}})
        writes = sorted({str(row["path"]) for row in accesses if row["access"] in {"write", "attempted_write", "rename"}})
        outcomes = [
            str(event.get("title"))
            for event in events
            if event.get("kind") in {"policy_block", "approval", "turn"}
            and event.get("status") in {"blocked", "completed", "failed", "interrupted"}
        ]
        conversation_hashes: list[str] = []
        for event in events:
            summary = event.get("summary")
            if isinstance(summary, Mapping) and summary.get("sha256"):
                conversation_hashes.append(str(summary["sha256"]))
        prompt_label = _summary_text(prompts[-1].get("summary")) if prompts else "未记录提示词"
        existing = self._connection.execute(
            """
            SELECT context_hash, encrypted_context, encryption
            FROM context_capsules WHERE run_id=? AND thread_id=? AND turn_id=?
            """,
            (run_id, thread_id, turn_id),
        ).fetchone()
        rich_events = [
            dict(event)
            for event in (forensic_events or ())
            if event.get("kind") in {"user_prompt", "agent_message", "plan", "reasoning_summary"}
        ]
        context_payload = {
            "events": [
                event
                for event in (rich_events or events)
                if event.get("kind") in {"user_prompt", "agent_message", "plan", "reasoning_summary"}
            ]
        }
        serialized = _json(context_payload).encode("utf-8")
        encrypted = (
            self._encrypt_context(serialized, run_id=run_id, thread_id=thread_id, turn_id=turn_id)
            if rich_events
            else str(existing["encrypted_context"])
            if existing is not None and existing["encrypted_context"]
            else None
        )
        encryption = (
            "AES-256-GCM"
            if rich_events and encrypted
            else str(existing["encryption"])
            if existing is not None and existing["encryption"]
            else None
        )
        context_hash = (
            hashlib.sha256(serialized).hexdigest()
            if rich_events or existing is None or not existing["context_hash"]
            else str(existing["context_hash"])
        )
        summary = {
            "schema_version": "lingmou.context-capsule.v1",
            "run_id": run_id,
            "thread_id": thread_id,
            "turn_id": turn_id,
            "event_count": len(events),
            "prompt": prompt_label,
            "plan_steps": plan_titles[:12],
            "reads": reads[:64],
            "writes": writes[:64],
            "outcomes": outcomes[-8:],
            "conversation_hashes": conversation_hashes,
            "privacy": {
                "credentials": "redacted",
                "conversation": "encrypted" if encrypted else "hash_and_length",
                "forensic_capture": (
                    "current_process_turn"
                    if rich_events
                    else "preserved_encrypted_capsule"
                    if encrypted
                    else "not_captured"
                ),
            },
        }
        started_at = min(float(event.get("occurred_at") or 0.0) for event in events)
        ended_at = max(float(event.get("occurred_at") or 0.0) for event in events)
        self._connection.execute(
            """
            INSERT OR REPLACE INTO context_capsules(
                run_id, thread_id, turn_id, started_at, ended_at, summary_json,
                context_hash, encrypted_context, encryption
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                thread_id,
                turn_id,
                started_at,
                ended_at,
                _json(summary),
                context_hash,
                encrypted,
                encryption,
            ),
        )

    def context_capsule(
        self,
        run_id: str,
        thread_id: str,
        turn_id: str,
        *,
        include_forensic: bool = False,
    ) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT * FROM context_capsules
                WHERE run_id=? AND thread_id=? AND turn_id=?
                """,
                (run_id, thread_id, turn_id),
            ).fetchone()
        if row is None:
            return None
        result = json.loads(row["summary_json"])
        result.update(
            {
                "context_hash": row["context_hash"],
                "encrypted_context_available": bool(row["encrypted_context"]),
                "encryption": row["encryption"],
            }
        )
        if include_forensic:
            if not row["encrypted_context"]:
                raise HistoryUnavailable("this turn has no encrypted forensic context")
            result["forensic_context"] = self._decrypt_context(
                str(row["encrypted_context"]),
                run_id=run_id,
                thread_id=thread_id,
                turn_id=turn_id,
            )
        return result

    def runs(self, *, limit: int = 100) -> dict[str, Any]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT run_id, run_dir, started_at, ended_at, thread_count,
                       event_count, anchor_count, last_indexed_seq
                FROM runs ORDER BY COALESCE(started_at, indexed_at) DESC LIMIT ?
                """,
                (max(1, min(limit, 500)),),
            ).fetchall()
        return {
            "schema_version": INVESTIGATION_SCHEMA_VERSION,
            "project_id": self.project_id,
            "index_path": os.fspath(self.path),
            "runs": [dict(row) for row in rows],
        }

    @staticmethod
    def _anchor_identity(row: Any) -> str:
        item_id = row["item_id"]
        return (
            f"{row['run_id']}:item:{item_id}"
            if item_id
            else str(row["event_key"])
        )

    @staticmethod
    def _investigation_id(anchor_identity: str) -> str:
        return f"inv-{_digest(anchor_identity, size=24)}"

    def investigations(self, *, limit: int = 50) -> dict[str, Any]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT event_key, run_id, event_id, occurred_at, kind, status,
                       thread_id, turn_id, item_id, title, summary_text,
                       risk_level, event_json
                FROM events WHERE is_anchor=1
                ORDER BY occurred_at DESC, seq DESC LIMIT ?
                """,
                (max(1, min(limit, 200)),),
            ).fetchall()
        items: list[dict[str, Any]] = []
        seen: set[str] = set()
        for row in rows:
            identity = self._anchor_identity(row)
            if identity in seen:
                continue
            seen.add(identity)
            event = json.loads(row["event_json"])
            explanation = _object(event.get("explanation"))
            evidence = _object(event.get("evidence"))
            risk = _object(explanation.get("risk"))
            items.append(
                {
                    "id": self._investigation_id(identity),
                    "anchor_event_key": row["event_key"],
                    "run_id": row["run_id"],
                    "event_id": row["event_id"],
                    "occurred_at": row["occurred_at"],
                    "thread_id": row["thread_id"],
                    "turn_id": row["turn_id"],
                    "item_id": row["item_id"],
                    "title": explanation.get("headline") or row["title"],
                    "summary": row["summary_text"],
                    "risk_level": row["risk_level"],
                    "status": row["status"],
                    "evidence_availability": evidence.get("availability") or "unavailable",
                    "blocked": row["kind"] == "policy_block" or row["status"] == "blocked",
                    "action": explanation.get("action"),
                    "policy_id": risk.get("policy_id"),
                    "blocking_rule": risk.get("blocking_rule"),
                }
            )
        return {
            "schema_version": INVESTIGATION_SCHEMA_VERSION,
            "project_id": self.project_id,
            "items": items,
            "total": len(items),
        }

    def _anchor_row(self, investigation_id: str) -> Any:
        rows = self._connection.execute(
            "SELECT * FROM events WHERE is_anchor=1 ORDER BY occurred_at DESC"
        ).fetchall()
        seen: set[str] = set()
        for row in rows:
            identity = self._anchor_identity(row)
            if identity in seen:
                continue
            seen.add(identity)
            if self._investigation_id(identity) == investigation_id:
                return row
        return None

    @staticmethod
    def _access_tier(*tiers: str) -> str:
        values = set(tiers)
        if "unproven" in values:
            return "unproven"
        if "candidate" in values:
            return "candidate"
        if "strong" in values:
            return "strong"
        return "fact"

    @staticmethod
    def _tier_score(tier: str) -> float:
        return {"fact": 1.0, "strong": 0.88, "candidate": 0.48, "unproven": 0.0}.get(tier, 0.0)

    @staticmethod
    def _event_action_stage(
        event: Mapping[str, Any],
        accesses: Sequence[Mapping[str, Any]],
        sensitive: bool,
    ) -> str:
        explanation = _object(event.get("explanation"))
        action = str(explanation.get("action") or "").lower()
        effects = _object(explanation.get("effects"))
        summary = _summary_text(event.get("summary"))
        access_values = {str(row.get("access")) for row in accesses}
        if str(event.get("kind") or "") in {"user_prompt", "plan"}:
            return "entry"
        if effects.get("network") or effects.get("external_write") or action in {"upload_data", "delete_files"} or _DESTRUCTIVE_TEXT.search(summary):
            return "egress"
        if (access_values & {"read", "attempted_read"}) and (access_values & {"write", "attempted_write", "rename"}):
            return "transform"
        if _TRANSFORM_TEXT.search(summary):
            return "transform"
        if sensitive and access_values & {"read", "attempted_read"}:
            return "collect"
        if access_values & {"read", "attempted_read"}:
            return "access"
        if access_values & {"write", "attempted_write", "rename"}:
            return "transform"
        if _risk(event)[1] >= 3:
            # A high-risk action with no file/network shape (for example a
            # reverse shell, security-control disablement, or container escape)
            # still belongs in the high-impact execution stage rather than
            # being mislabeled as a file read.
            return "egress"
        return "access"

    @classmethod
    def _event_stage(
        cls,
        event: Mapping[str, Any],
        accesses: Sequence[Mapping[str, Any]],
        sensitive: bool,
    ) -> str:
        kind = str(event.get("kind") or "")
        status = str(event.get("status") or "")
        if kind in {"policy_block", "approval"} or status in {"blocked", "failed", "interrupted"}:
            return "outcome"
        return cls._event_action_stage(event, accesses, sensitive)

    def investigation(self, investigation_id: str) -> dict[str, Any] | None:
        with self._lock:
            anchor = self._anchor_row(investigation_id)
            if anchor is None:
                return None
            anchor_key = str(anchor["event_key"])
            anchor_time = float(anchor["occurred_at"])
            anchor_accesses = self._connection.execute(
                "SELECT * FROM file_accesses WHERE event_key=?", (anchor_key,)
            ).fetchall()
            identities = {str(row["identity_id"]) for row in anchor_accesses}
            paths = {str(row["path"]) for row in anchor_accesses}
            candidate_keys = {anchor_key}

            noise_placeholders = ",".join("?" for _ in _GRAPH_NOISE_KINDS)
            same_scope = self._connection.execute(
                f"""
                SELECT event_key FROM events
                WHERE run_id=? AND (
                    (turn_id IS NOT NULL AND turn_id=?) OR
                    (item_id IS NOT NULL AND item_id=?)
                ) AND kind NOT IN ({noise_placeholders})
                ORDER BY occurred_at LIMIT 1000
                """,
                (
                    anchor["run_id"],
                    anchor["turn_id"],
                    anchor["item_id"],
                    *_GRAPH_NOISE_KINDS,
                ),
            ).fetchall()
            candidate_keys.update(str(row["event_key"]) for row in same_scope)

            for _ in range(3):
                if not identities and not paths:
                    break
                rows_by_access: dict[tuple[str, str, str], Any] = {}
                for column, values in (
                    ("identity_id", sorted(identities)),
                    ("path", sorted(paths)),
                ):
                    for batch in _batches(values):
                        placeholders = ",".join("?" for _ in batch)
                        rows = self._connection.execute(
                            f"""
                            SELECT DISTINCT fa.event_key, fa.identity_id, fa.path
                            FROM file_accesses fa JOIN events e ON e.event_key=fa.event_key
                            WHERE fa.{column} IN ({placeholders}) AND e.occurred_at<=?
                            ORDER BY e.occurred_at DESC LIMIT ?
                            """,
                            (*batch, anchor_time + 86_400, _MAX_INVESTIGATION_EVENTS),
                        ).fetchall()
                        for row in rows:
                            rows_by_access[
                                (str(row["event_key"]), str(row["identity_id"]), str(row["path"]))
                            ] = row
                        if len(rows_by_access) >= _MAX_INVESTIGATION_EVENTS:
                            break
                    if len(rows_by_access) >= _MAX_INVESTIGATION_EVENTS:
                        break
                before = len(candidate_keys)
                newly_added: set[str] = set()
                for row in rows_by_access.values():
                    event_key_value = str(row["event_key"])
                    if event_key_value not in candidate_keys:
                        newly_added.add(event_key_value)
                    candidate_keys.add(event_key_value)
                    identities.add(str(row["identity_id"]))
                    paths.add(str(row["path"]))
                    if len(candidate_keys) >= _MAX_INVESTIGATION_EVENTS:
                        break
                if newly_added:
                    for batch in _batches(sorted(newly_added)):
                        new_placeholders = ",".join("?" for _ in batch)
                        expanded = self._connection.execute(
                            f"SELECT identity_id, path FROM file_accesses WHERE event_key IN ({new_placeholders})",
                            batch,
                        ).fetchall()
                        identities.update(str(row["identity_id"]) for row in expanded)
                        paths.update(str(row["path"]) for row in expanded)
                if len(candidate_keys) == before or len(candidate_keys) >= _MAX_INVESTIGATION_EVENTS:
                    break

            # File identity is the strongest cross-run join, but real attack
            # chains are not always file-shaped.  Exact network targets may
            # connect runs; PID and executable identities only connect events
            # inside their originating run.  All resulting graph edges remain
            # explicitly non-causal unless a separate observed relation proves
            # otherwise.
            linkable_entity_types = {"network", "process", "executable"}
            anchor_entities = self._connection.execute(
                """
                SELECT entity_type, entity_key, scope_key
                FROM entity_observations WHERE event_key=?
                """,
                (anchor_key,),
            ).fetchall()
            entity_keys = {
                (str(row["entity_type"]), str(row["scope_key"]), str(row["entity_key"]))
                for row in anchor_entities
                if str(row["entity_type"]) in linkable_entity_types
            }
            for _ in range(3):
                if not entity_keys or len(candidate_keys) >= _MAX_INVESTIGATION_EVENTS:
                    break
                rows_by_entity: dict[tuple[str, str, str, str], Any] = {}
                grouped: dict[tuple[str, str], list[str]] = defaultdict(list)
                for entity_type, scope_key, entity_key in sorted(entity_keys):
                    grouped[(entity_type, scope_key)].append(entity_key)
                for (entity_type, scope_key), values in grouped.items():
                    for batch in _batches(sorted(set(values))):
                        placeholders = ",".join("?" for _ in batch)
                        rows = self._connection.execute(
                            f"""
                            SELECT DISTINCT eo.event_key, eo.entity_type,
                                            eo.entity_key, eo.scope_key
                            FROM entity_observations eo
                            JOIN events e ON e.event_key=eo.event_key
                            WHERE eo.entity_type=? AND eo.scope_key=?
                              AND eo.entity_key IN ({placeholders})
                              AND e.occurred_at<=?
                            ORDER BY e.occurred_at DESC LIMIT ?
                            """,
                            (
                                entity_type,
                                scope_key,
                                *batch,
                                anchor_time + 86_400,
                                _MAX_INVESTIGATION_EVENTS,
                            ),
                        ).fetchall()
                        for row in rows:
                            rows_by_entity[
                                (
                                    str(row["event_key"]),
                                    str(row["entity_type"]),
                                    str(row["scope_key"]),
                                    str(row["entity_key"]),
                                )
                            ] = row
                        if len(rows_by_entity) >= _MAX_INVESTIGATION_EVENTS:
                            break
                    if len(rows_by_entity) >= _MAX_INVESTIGATION_EVENTS:
                        break
                before = len(candidate_keys)
                newly_added: set[str] = set()
                for row in rows_by_entity.values():
                    value = str(row["event_key"])
                    if value not in candidate_keys:
                        newly_added.add(value)
                    candidate_keys.add(value)
                    entity_keys.add(
                        (
                            str(row["entity_type"]),
                            str(row["scope_key"]),
                            str(row["entity_key"]),
                        )
                    )
                    if len(candidate_keys) >= _MAX_INVESTIGATION_EVENTS:
                        break
                if newly_added:
                    for batch in _batches(sorted(newly_added)):
                        placeholders = ",".join("?" for _ in batch)
                        expanded = self._connection.execute(
                            f"""
                            SELECT entity_type, entity_key, scope_key
                            FROM entity_observations
                            WHERE event_key IN ({placeholders})
                            """,
                            batch,
                        ).fetchall()
                        entity_keys.update(
                            (
                                str(row["entity_type"]),
                                str(row["scope_key"]),
                                str(row["entity_key"]),
                            )
                            for row in expanded
                            if str(row["entity_type"]) in linkable_entity_types
                        )
                if len(candidate_keys) == before:
                    break

            scope_rows: list[Any] = []
            for batch in _batches(sorted(candidate_keys)):
                placeholders = ",".join("?" for _ in batch)
                scope_rows.extend(
                    self._connection.execute(
                        f"""
                        SELECT run_id, thread_id, turn_id
                        FROM events
                        WHERE event_key IN ({placeholders}) AND turn_id IS NOT NULL
                        """,
                        batch,
                    ).fetchall()
                )
            scopes_by_run: dict[str, set[tuple[str, str]]] = defaultdict(set)
            for row in scope_rows:
                scopes_by_run[str(row["run_id"])].add(
                    (str(row["thread_id"] or ""), str(row["turn_id"]))
                )
            for run_id, scopes in scopes_by_run.items():
                turn_ids = sorted({turn_id for _thread_id, turn_id in scopes})
                for batch in _batches(turn_ids):
                    placeholders = ",".join("?" for _ in batch)
                    context_rows = self._connection.execute(
                        f"""
                        SELECT event_key, thread_id, turn_id
                        FROM events
                        WHERE run_id=? AND turn_id IN ({placeholders})
                          AND kind IN ('user_prompt', 'plan')
                        ORDER BY occurred_at, seq
                        """,
                        (run_id, *batch),
                    ).fetchall()
                    for row in context_rows:
                        scope = (str(row["thread_id"] or ""), str(row["turn_id"]))
                        if scope in scopes:
                            candidate_keys.add(str(row["event_key"]))
                        if len(candidate_keys) >= _MAX_INVESTIGATION_EVENTS:
                            break
                    if len(candidate_keys) >= _MAX_INVESTIGATION_EVENTS:
                        break
                # app-server emits the submitted prompt immediately before it
                # assigns a turn id.  Recover that nearest same-thread prompt
                # as the entry context without pulling message deltas or other
                # streaming telemetry into the graph.
                for thread_id, turn_id in sorted(scopes):
                    turn_start = self._connection.execute(
                        """
                        SELECT MIN(occurred_at) AS started_at
                        FROM events
                        WHERE run_id=? AND COALESCE(thread_id, '')=? AND turn_id=?
                        """,
                        (run_id, thread_id, turn_id),
                    ).fetchone()
                    if turn_start is None or turn_start["started_at"] is None:
                        continue
                    prompt = self._connection.execute(
                        """
                        SELECT event_key
                        FROM events
                        WHERE run_id=? AND COALESCE(thread_id, '')=?
                          AND kind='user_prompt' AND occurred_at<=?
                        ORDER BY occurred_at DESC, seq DESC LIMIT 1
                        """,
                        (run_id, thread_id, float(turn_start["started_at"])),
                    ).fetchone()
                    if prompt is not None:
                        candidate_keys.add(str(prompt["event_key"]))
                    if len(candidate_keys) >= _MAX_INVESTIGATION_EVENTS:
                        break
                if len(candidate_keys) >= _MAX_INVESTIGATION_EVENTS:
                    break

            keys = sorted(candidate_keys)[:_MAX_INVESTIGATION_EVENTS]
            event_rows: list[Any] = []
            access_rows: list[Any] = []
            entity_rows: list[Any] = []
            for batch in _batches(keys):
                placeholders = ",".join("?" for _ in batch)
                event_rows.extend(
                    self._connection.execute(
                        f"SELECT * FROM events WHERE event_key IN ({placeholders})",
                        batch,
                    ).fetchall()
                )
                access_rows.extend(
                    self._connection.execute(
                        f"""
                        SELECT fa.*, fv.content_sha256, fv.git_blob, fi.device, fi.inode,
                               EXISTS(SELECT 1 FROM sensitivity_labels sl WHERE sl.identity_id=fa.identity_id) AS sensitive
                        FROM file_accesses fa
                        LEFT JOIN file_versions fv ON fv.version_id=fa.version_id
                        JOIN file_identities fi ON fi.identity_id=fa.identity_id
                        WHERE fa.event_key IN ({placeholders})
                        """,
                        batch,
                    ).fetchall()
                )
                entity_rows.extend(
                    self._connection.execute(
                        f"""
                        SELECT * FROM entity_observations
                        WHERE event_key IN ({placeholders})
                        """,
                        batch,
                    ).fetchall()
                )
            event_rows.sort(key=lambda row: (float(row["occurred_at"]), int(row["seq"])))
            access_rows.sort(key=lambda row: (float(row["observed_at"]), str(row["event_key"])))
            entity_rows.sort(
                key=lambda row: (
                    float(row["observed_at"]),
                    str(row["event_key"]),
                    str(row["entity_type"]),
                )
            )
            capsule_rows = self._connection.execute(
                """
                SELECT * FROM context_capsules WHERE run_id=? AND turn_id=?
                """,
                (anchor["run_id"], anchor["turn_id"]),
            ).fetchall()

        events = {str(row["event_key"]): json.loads(row["event_json"]) for row in event_rows}
        db_rows = {str(row["event_key"]): row for row in event_rows}
        accesses_by_event: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in access_rows:
            accesses_by_event[str(row["event_key"])].append(dict(row))
        entities_by_event: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in entity_rows:
            value = dict(row)
            value["attributes"] = json.loads(str(value.pop("attributes_json") or "{}"))
            entities_by_event[str(row["event_key"])].append(value)
        capsules = [json.loads(row["summary_json"]) for row in capsule_rows]
        anchor_event = events[anchor_key]
        anchor_explanation = _object(anchor_event.get("explanation"))
        anchor_effects = _object(anchor_explanation.get("effects"))
        anchor_sensitive = any(
            bool(value.get("sensitive")) for value in accesses_by_event.get(anchor_key, [])
        )
        anchor_action_stage = self._event_action_stage(
            anchor_event,
            accesses_by_event.get(anchor_key, []),
            anchor_sensitive,
        )

        nodes: list[dict[str, Any]] = []
        node_by_id: dict[str, dict[str, Any]] = {}
        for key, event in events.items():
            accesses = accesses_by_event.get(key, [])
            sensitive = any(bool(value.get("sensitive")) for value in accesses)
            evidence = _object(event.get("evidence"))
            observed_files = any(
                "os_observation" in str(value.get("source") or "").split("+")
                and value.get("confidence_tier") == "fact"
                for value in accesses
            )
            file_claims = bool(accesses)
            proof_scope = (
                "OS 级文件访问已观察"
                if observed_files
                else "仅能证明 Agent 操作或策略请求；无法证明实际文件访问"
                if file_claims
                else "事件来自已记录的 Agent / 策略生命周期"
            )
            stage = "outcome" if key == anchor_key else self._event_stage(event, accesses, sensitive)
            access_values = {str(value.get("access")) for value in accesses}
            stage_memberships = {stage}
            if key != anchor_key and "read" in access_values:
                stage_memberships.add("access")
                if sensitive:
                    stage_memberships.add("collect")
            if key != anchor_key and "read" in access_values and access_values & {"write", "rename"}:
                stage_memberships.add("transform")
            explanation = _object(event.get("explanation"))
            if key == anchor_key:
                status_label = {
                    "blocked": "执行前阻断",
                    "completed": "执行完成",
                    "failed": "执行失败",
                    "interrupted": "执行中断",
                }.get(str(event.get("status") or ""), "状态已记录")
                proof_scope = f"同一锚点事件已记录最终结果：{status_label}"
            node = {
                "id": key,
                "node_type": "event",
                "stage": stage,
                "stage_memberships": sorted(
                    stage_memberships,
                    key=_STAGE_ORDER.index,
                ),
                "title": str(explanation.get("headline") or event.get("title") or "Agent 活动"),
                "summary": _summary_text(event.get("summary")),
                "occurred_at": float(event.get("occurred_at") or 0.0),
                "run_id": db_rows[key]["run_id"],
                "event_id": event.get("event_id"),
                "thread_id": event.get("thread_id"),
                "turn_id": event.get("turn_id"),
                "item_id": event.get("item_id"),
                "kind": event.get("kind"),
                "status": event.get("status"),
                "risk_level": _risk(event)[0],
                "confidence_tier": "fact",
                "confidence": 1.0,
                "fact_scope": proof_scope,
                "evidence_availability": evidence.get("availability") or "unavailable",
                "evidence_completeness": evidence.get("completeness") or "none",
                "file_snapshots": _list(event.get("file_snapshots")),
                "entities": entities_by_event.get(key, []),
                "sensitive": sensitive,
                "event": event,
            }
            nodes.append(node)
            node_by_id[key] = node

        action_id = f"{anchor_key}:action"
        anchor_status = str(anchor_event.get("status") or "recorded")
        action_status = {
            "blocked": "requested_not_executed",
            "completed": "executed",
            "failed": "attempt_failed",
            "interrupted": "attempt_interrupted",
        }.get(anchor_status, "requested")
        action_fact_scope = {
            "blocked": "app-server / 策略记录证明操作被请求，不代表命令已执行",
            "completed": "同一 Item 生命周期记录操作已完成；具体 OS 影响仍以节点证据为准",
            "failed": "同一 Item 生命周期记录操作尝试后失败，不能推定预期影响已完成",
            "interrupted": "同一 Item 生命周期记录操作被中断，不能推定预期影响已完成",
        }.get(anchor_status, "已记录危险操作请求；尚无终态可证明其是否完成")
        action = {
            "id": action_id,
            "node_type": "action",
            "stage": anchor_action_stage,
            "stage_memberships": [anchor_action_stage],
            "title": (
                "危险操作请求"
                if anchor_status == "blocked"
                else str(anchor_explanation.get("headline") or anchor_event.get("title") or "危险操作")
            ),
            "summary": _summary_text(anchor_event.get("summary")),
            "occurred_at": float(anchor_event.get("occurred_at") or 0.0) - 0.0001,
            "run_id": anchor["run_id"],
            "event_id": anchor_event.get("event_id"),
            "thread_id": anchor_event.get("thread_id"),
            "turn_id": anchor_event.get("turn_id"),
            "item_id": anchor_event.get("item_id"),
            "kind": "dangerous_action",
            "status": action_status,
            "risk_level": _risk(anchor_event)[0],
            "confidence_tier": "fact",
            "confidence": 1.0,
            "fact_scope": action_fact_scope,
            "evidence_availability": (
                _object(anchor_event.get("evidence")).get("availability") or "unavailable"
            ),
            "evidence_completeness": (
                _object(anchor_event.get("evidence")).get("completeness") or "none"
            ),
            "file_snapshots": _list(anchor_event.get("file_snapshots")),
            "entities": entities_by_event.get(anchor_key, []),
            "sensitive": anchor_sensitive,
            "event": anchor_event,
        }
        nodes.append(action)
        node_by_id[action_id] = action

        edges: list[dict[str, Any]] = []
        edge_keys: set[tuple[str, str, str]] = set()

        def relation_node(event_key: str) -> str:
            return action_id if event_key == anchor_key else event_key

        def add_edge(source: str, target: str, relation: str, tier: str, evidence: str, *, causal: bool = False) -> None:
            if source == target or source not in node_by_id or target not in node_by_id:
                return
            key = (source, target, relation)
            if key in edge_keys:
                return
            edge_keys.add(key)
            edges.append(
                {
                    "id": f"edge-{_digest(source, target, relation)}",
                    "source": source,
                    "target": target,
                    "relation": relation,
                    "confidence_tier": tier,
                    "confidence": self._tier_score(tier),
                    "evidence": evidence,
                    "causal": causal,
                }
            )

        by_item: dict[tuple[str, str], list[str]] = defaultdict(list)
        for key, event in events.items():
            if event.get("item_id"):
                by_item[(str(db_rows[key]["run_id"]), str(event["item_id"]))].append(key)
        for item_keys in by_item.values():
            ordered = sorted(item_keys, key=lambda value: node_by_id[value]["occurred_at"])
            for left, right in zip(ordered, ordered[1:]):
                add_edge(
                    relation_node(left),
                    relation_node(right),
                    "SAME_ITEM_LIFECYCLE",
                    "fact",
                    "相同 run + app-server item id",
                    causal=False,
                )

        by_identity: dict[str, list[dict[str, Any]]] = defaultdict(list)
        by_path: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in access_rows:
            value = dict(row)
            by_identity[str(row["identity_id"])].append(value)
            by_path[str(row["path"])].append(value)
        for identity_rows in by_identity.values():
            ordered = sorted(identity_rows, key=lambda value: (value["observed_at"], value["event_key"]))
            deduped: list[dict[str, Any]] = []
            for value in ordered:
                if not deduped or value["event_key"] != deduped[-1]["event_key"]:
                    deduped.append(value)
            for left, right in zip(deduped, deduped[1:]):
                same_version = bool(left.get("version_id") and left.get("version_id") == right.get("version_id"))
                tier = self._access_tier(str(left.get("confidence_tier")), str(right.get("confidence_tier")))
                if tier == "fact":
                    tier = "strong"
                relation = "SAME_FILE_VERSION" if same_version else "SAME_FILE_IDENTITY"
                basis = (
                    f"同一内容版本 {str(left.get('content_sha256') or left.get('git_blob'))[:12]}"
                    if same_version
                    else f"同一 device/inode 文件身份 {left.get('device')}/{left.get('inode')}"
                )
                add_edge(
                    relation_node(str(left["event_key"])),
                    relation_node(str(right["event_key"])),
                    relation,
                    tier,
                    basis,
                    causal=False,
                )
        for path_rows in by_path.values():
            ordered = sorted(path_rows, key=lambda value: (value["observed_at"], value["event_key"]))
            deduped: list[dict[str, Any]] = []
            for value in ordered:
                if not deduped or value["event_key"] != deduped[-1]["event_key"]:
                    deduped.append(value)
            for left, right in zip(deduped, deduped[1:]):
                if left["identity_id"] == right["identity_id"]:
                    continue
                add_edge(
                    relation_node(str(left["event_key"])),
                    relation_node(str(right["event_key"])),
                    "SAME_PATH_CANDIDATE",
                    "candidate",
                    f"路径相同：{left['path']}；文件身份不同，不能据此证明因果",
                    causal=False,
                )

        by_entity: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
        for row in entity_rows:
            value = dict(row)
            by_entity[
                (
                    str(row["entity_type"]),
                    str(row["scope_key"]),
                    str(row["entity_key"]),
                )
            ].append(value)
        for (entity_type, scope_key, entity_key), values in by_entity.items():
            if entity_type not in {"network", "process", "executable"}:
                continue
            ordered = sorted(
                values,
                key=lambda value: (float(value["observed_at"]), str(value["event_key"])),
            )
            deduped: list[dict[str, Any]] = []
            for value in ordered:
                if deduped and value["event_key"] == deduped[-1]["event_key"]:
                    if self._tier_score(str(value["confidence_tier"])) > self._tier_score(
                        str(deduped[-1]["confidence_tier"])
                    ):
                        deduped[-1] = value
                    continue
                deduped.append(value)
            for left, right in zip(deduped, deduped[1:]):
                left_tier = str(left["confidence_tier"])
                right_tier = str(right["confidence_tier"])
                if entity_type == "process":
                    tier = "fact" if left_tier == right_tier == "fact" else "strong"
                    relation = "SAME_PROCESS"
                    reason = f"同一运行中已记录进程 PID {left['display_value']}"
                elif entity_type == "network":
                    tier = (
                        "strong"
                        if left_tier in {"fact", "strong"}
                        and right_tier in {"fact", "strong"}
                        else "candidate"
                    )
                    relation = "SAME_NETWORK_TARGET"
                    reason = f"同一网络目标：{left['display_value']}；目标相同不自动证明因果"
                else:
                    tier = "candidate"
                    relation = "SAME_EXECUTABLE"
                    reason = (
                        f"同一运行中使用相同执行体：{left['display_value']}；"
                        "仅表示工具关联"
                    )
                add_edge(
                    relation_node(str(left["event_key"])),
                    relation_node(str(right["event_key"])),
                    relation,
                    tier,
                    reason,
                    causal=False,
                )

        by_turn: dict[tuple[str, str, str], list[str]] = defaultdict(list)
        unassigned_contexts: dict[tuple[str, str], list[str]] = defaultdict(list)
        for key, event in events.items():
            if event.get("turn_id"):
                by_turn[(str(db_rows[key]["run_id"]), str(event.get("thread_id") or ""), str(event["turn_id"]))].append(key)
            elif event.get("kind") in {"user_prompt", "plan"}:
                unassigned_contexts[
                    (str(db_rows[key]["run_id"]), str(event.get("thread_id") or ""))
                ].append(key)
        for (run_id, thread_id, _turn_id), turn_keys in by_turn.items():
            ordered = sorted(turn_keys, key=lambda value: node_by_id[value]["occurred_at"])
            contexts = [value for value in ordered if events[value].get("kind") in {"user_prompt", "plan"}]
            if not contexts and ordered:
                turn_started_at = node_by_id[ordered[0]]["occurred_at"]
                preceding = [
                    value
                    for value in unassigned_contexts.get((run_id, thread_id), [])
                    if node_by_id[value]["occurred_at"] <= turn_started_at
                ]
                if preceding:
                    contexts = [max(preceding, key=lambda value: node_by_id[value]["occurred_at"])]
            actions = [
                value
                for value in ordered
                if events[value].get("kind")
                not in {
                    "user_prompt",
                    "plan",
                    "agent_message",
                    "agent_delta",
                    "reasoning_summary",
                    "turn",
                    "connection",
                    "session",
                }
            ]
            if contexts and actions:
                add_edge(
                    contexts[-1],
                    relation_node(actions[0]),
                    "DECLARED_CONTEXT",
                    "candidate",
                    "同一 run/thread/turn 的公开任务语境；仅表示上下文关联",
                    causal=False,
                )
            for left, right in zip(actions, actions[1:]):
                add_edge(
                    relation_node(left),
                    relation_node(right),
                    "TURN_SEQUENCE",
                    "candidate",
                    "同一 run/thread/turn 中按记录顺序相邻；顺序本身不证明因果",
                    causal=False,
                )
        if anchor_event.get("kind") == "policy_block" or anchor_status == "blocked":
            add_edge(
                action_id,
                anchor_key,
                "POLICY_DECIDES",
                "fact",
                "同一策略事件记录了操作请求与执行前拒绝",
                causal=True,
            )
        else:
            add_edge(
                action_id,
                anchor_key,
                "ACTION_RESULT",
                "fact",
                "同一 app-server Item 生命周期记录了危险操作及其最终状态",
                causal=True,
            )

        adjacency: dict[str, list[tuple[str, float]]] = defaultdict(list)
        for edge in edges:
            adjacency[edge["source"]].append((edge["target"], float(edge["confidence"])))
            adjacency[edge["target"]].append((edge["source"], float(edge["confidence"])))
        relevance = {anchor_key: 1.0}
        relevance[action_id] = 1.0
        frontier = list(relevance)
        while frontier:
            current = frontier.pop(0)
            for target, weight in adjacency.get(current, []):
                candidate = relevance[current] * weight
                if candidate > relevance.get(target, -1.0):
                    relevance[target] = candidate
                    frontier.append(target)
        for node in nodes:
            node["chain_relevance"] = round(relevance.get(node["id"], 0.0), 3)

        selected: list[dict[str, Any]] = []
        for stage in _STAGE_ORDER:
            candidates = [
                node
                for node in nodes
                if stage in node.get("stage_memberships", [node["stage"]])
                and node["chain_relevance"] > 0
            ]
            if not candidates:
                continue
            if stage == "outcome":
                chosen = node_by_id[anchor_key]
            elif stage == "entry":
                chosen = min(candidates, key=lambda node: (node["occurred_at"], -node["chain_relevance"]))
            elif stage in {"access", "collect"}:
                chosen = max(
                    candidates,
                    key=lambda node: (
                        1
                        if node["stage"] == stage
                        else 1
                        if stage == "access" and node["stage"] == "collect"
                        else 0,
                        1 if node["sensitive"] else 0,
                        1 if "OS 级" in node["fact_scope"] else 0,
                        node["chain_relevance"],
                        -node["occurred_at"],
                    ),
                )
            else:
                chosen = max(candidates, key=lambda node: (node["chain_relevance"], node["occurred_at"]))
            if chosen not in selected:
                selected.append(chosen)
        selected.sort(key=lambda node: (node["occurred_at"], _STAGE_ORDER.index(node["stage"])))

        timeline: list[dict[str, Any]] = []
        for node in selected:
            if timeline:
                previous_time = float(timeline[-1].get("occurred_at") or 0.0)
                delta = float(node["occurred_at"]) - previous_time
                if delta >= 300:
                    timeline.append(
                        {
                            "id": f"gap-{_digest(previous_time, node['occurred_at'])}",
                            "node_type": "time_gap",
                            "duration_seconds": round(delta, 3),
                            "occurred_at": previous_time,
                            "title": "无相关事件区间已压缩",
                            "summary": f"{round(delta / 60)} 分钟内没有进入最小充分链的事件",
                        }
                    )
            timeline.append(node)

        selected_ids = {node["id"] for node in selected}
        minimal_edges = [
            edge
            for edge in edges
            if edge["source"] in selected_ids and edge["target"] in selected_ids
        ]
        sensitive_paths = [
            str(value["path"])
            for value in access_rows
            if bool(value["sensitive"])
        ]
        affected_paths = list(
            dict.fromkeys(str(value["path"]) for value in access_rows if value["path"])
        )
        entry = next((node for node in selected if node["stage"] == "entry"), None)
        egress = next((node for node in reversed(selected) if node["stage"] == "egress"), None)
        outcome = node_by_id[anchor_key]
        network_targets = [str(value) for value in _list(anchor_effects.get("network"))]
        if not network_targets:
            network_targets = list(
                dict.fromkeys(
                    str(value["display_value"])
                    for value in entities_by_event.get(anchor_key, [])
                    if value["entity_type"] == "network"
                )
            )
        if sensitive_paths:
            key_asset_value = sensitive_paths[0]
            key_asset_detail = "仅显示路径、文件身份和内容哈希，不保存或展示敏感正文。"
            key_asset_tier = "strong"
        elif affected_paths:
            key_asset_value = affected_paths[0]
            key_asset_detail = "这是与风险锚点连通的文件对象；是否实际访问以节点证据为准。"
            key_asset_tier = "strong"
        else:
            entity = next(
                (
                    value
                    for value in entities_by_event.get(anchor_key, [])
                    if value["entity_type"] in {"network", "executable", "process"}
                ),
                None,
            )
            key_asset_value = (
                str(entity["display_value"])
                if entity
                else "未识别到与锚点连通的关键对象"
            )
            key_asset_detail = (
                "该对象来自结构化进程或网络证据，不代表它与其他事件存在业务因果。"
                if entity
                else "索引中没有足够的文件、进程或网络实体证据。"
            )
            key_asset_tier = str(entity["confidence_tier"]) if entity else "unproven"
        evidence_gaps: list[dict[str, Any]] = []
        for node in selected:
            if node.get("file_snapshots") and "无法证明" in str(node.get("fact_scope")):
                evidence_gaps.append(
                    {
                        "node_id": node["id"],
                        "title": "缺少可归因的 OS 文件访问证据",
                        "detail": node["fact_scope"],
                        "impact": "该节点只能显示为命令/上下文关联，不能显示为已证明的实际读取。",
                    }
                )
        stage_rows = []
        for stage in _STAGE_ORDER:
            node = next(
                (
                    value
                    for value in selected
                    if stage in value.get("stage_memberships", [value["stage"]])
                ),
                None,
            )
            stage_rows.append(
                {
                    "id": stage,
                    "status": "present" if node else "missing",
                    "node_id": node["id"] if node else None,
                    "confidence_tier": node["confidence_tier"] if node else "unproven",
                }
            )
        relation_scores = [float(edge["confidence"]) for edge in minimal_edges]
        coverage = len([row for row in stage_rows if row["status"] == "present"]) / len(_STAGE_ORDER)
        chain_score = round(100 * (0.55 * coverage + 0.45 * (sum(relation_scores) / len(relation_scores) if relation_scores else 0.0)))

        return {
            "schema_version": INVESTIGATION_SCHEMA_VERSION,
            "id": investigation_id,
            "project_id": self.project_id,
            "anchor_event_key": anchor_key,
            "created_at": time.time(),
            "summary": {
                "earliest_trigger": {
                    "value": entry["title"] if entry else "没有足够证据定位更早诱因",
                    "detail": entry["summary"] if entry else "索引中没有与危险点连通的提示词或计划事件",
                    "confidence_tier": "candidate" if entry else "unproven",
                    "occurred_at": entry["occurred_at"] if entry else None,
                },
                "key_asset": {
                    "value": key_asset_value,
                    "detail": key_asset_detail,
                    "confidence_tier": key_asset_tier,
                },
                "dangerous_outlet": {
                    "value": network_targets[0] if network_targets else egress["summary"] if egress else "未识别到出口",
                    "detail": egress["fact_scope"] if egress else "没有与锚点连通的外发或破坏性操作",
                    "confidence_tier": "fact" if egress else "unproven",
                },
                "final_outcome": {
                    "value": outcome["title"],
                    "detail": _object(anchor_event.get("explanation")).get("result", {}).get("summary") if isinstance(_object(anchor_event.get("explanation")).get("result"), Mapping) else outcome["summary"],
                    "confidence_tier": "fact",
                    "status": outcome["status"],
                },
            },
            "chain_score": chain_score,
            "stage_coverage": round(coverage, 3),
            "stages": stage_rows,
            "minimal_chain": selected,
            "minimal_edges": minimal_edges,
            "timeline": timeline,
            "evidence_gaps": evidence_gaps,
            "context_capsules": capsules,
            "graph": {
                "nodes": sorted(nodes, key=lambda node: (node["occurred_at"], node["id"])),
                "edges": edges,
                "node_count": len(nodes),
                "edge_count": len(edges),
                "entity_count": len(
                    {
                        (
                            str(row["entity_type"]),
                            str(row["scope_key"]),
                            str(row["entity_key"]),
                        )
                        for row in entity_rows
                    }
                ),
            },
            "privacy": {
                "credentials": "redacted",
                "file_contents": "not_stored",
                "file_versions": "hash_and_metadata_only",
                "conversation_default": "hash_and_length",
                "forensic_context_available": any(bool(row["encrypted_context"]) for row in capsule_rows),
            },
            "proof_boundary": [
                "事件存在、精确 item/PID 关联和策略决定可显示为已观察事实。",
                "同一文件身份或内容哈希只构成强关联，不自动证明业务因果。",
                "同一网络目标、执行体或进程身份只按其证据等级构成关联，不自动证明业务因果。",
                "相同路径、同一 Turn 和时间邻近只构成候选关联。",
                "没有 strace/PID 证据时，界面必须明确显示无法证明实际读取或执行。",
            ],
        }

    def close(self) -> None:
        with self._lock:
            self._connection.close()


__all__ = [
    "FileSnapshotter",
    "HistoryUnavailable",
    "INVESTIGATION_SCHEMA_VERSION",
    "ProjectHistoryIndex",
    "default_history_path",
    "project_id_for",
    "run_id_for",
]
