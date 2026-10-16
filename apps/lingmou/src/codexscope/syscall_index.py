"""Incremental, rebuildable query index for one run's Linux syscall stream.

The strace collector remains the source of truth.  This module indexes only the
collector's already-redacted JSONL fields, never read/write buffers or exec
arguments.  The SQLite database may be deleted or rebuilt without affecting the
run evidence.
"""

from __future__ import annotations

import json
import os
import stat
import threading
import time
from pathlib import Path
from typing import Any, Mapping, Sequence

from .redaction import redact_text


SCHEMA_VERSION = "lingmou.syscall-index.v1"
INDEX_FILENAME = "syscall_index.sqlite3"
RAW_RELATIVE_PATH = Path("raw") / "os_audit.jsonl"
DEFAULT_PAGE_SIZE = 200
MAX_PAGE_SIZE = 500
MAX_DENSITY_BUCKETS = 240
_MAX_JSONL_LINE = 2 * 1024 * 1024
_MAX_TEXT = 4_096
_EXEC_SYSCALLS = frozenset({"execve", "execveat"})
_BUFFER_SYSCALLS = frozenset(
    {
        "read", "write", "pread64", "pwrite64", "readv", "writev",
        "preadv", "pwritev", "preadv2", "pwritev2", "getdents", "getdents64",
        "readlink", "readlinkat", "getxattr", "lgetxattr", "fgetxattr",
        "listxattr", "llistxattr", "flistxattr", "setxattr", "lsetxattr",
        "fsetxattr", "sendto", "recvfrom", "sendmsg", "recvmsg", "sendmmsg",
        "recvmmsg",
    }
)
_BEHAVIOR_ROLLUP_WINDOW_NS = 60_000_000_000


class SyscallIndexError(RuntimeError):
    """Raised when a syscall index cannot be read or updated safely."""


def _sqlite_module() -> Any:
    try:
        import sqlite3  # type: ignore[import-not-found]

        return sqlite3
    except (ImportError, ModuleNotFoundError):
        try:
            import pysqlite3 as sqlite3  # type: ignore[import-not-found]

            return sqlite3
        except (ImportError, ModuleNotFoundError) as exc:
            raise SyscallIndexError(
                "SQLite driver unavailable; install sqlite3 or pysqlite3-binary"
            ) from exc


def _as_int(value: object) -> int | None:
    if type(value) is int:
        return value
    if isinstance(value, str):
        try:
            return int(value, 10)
        except ValueError:
            return None
    return None


def _as_float(value: object) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    return None


def _safe_text(value: object, *, limit: int = _MAX_TEXT) -> str | None:
    if value is None:
        return None
    text = redact_text(str(value))
    return text[:limit]


def _read_json_object(path: Path, *, max_bytes: int = 4 * 1024 * 1024) -> dict[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return {}
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > max_bytes:
            return {}
        with os.fdopen(descriptor, "r", encoding="utf-8", errors="replace") as source:
            descriptor = -1
            value = json.load(source)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return value if isinstance(value, dict) else {}


def _endpoint_fields(value: object) -> tuple[str | None, str | None, int | None, str | None, str | None]:
    if isinstance(value, Mapping):
        family = _safe_text(value.get("family"), limit=64)
        address = _safe_text(value.get("address"), limit=512)
        port = _as_int(value.get("port"))
        path = _safe_text(value.get("path"), limit=512)
        if path:
            label = path
        elif address and port is not None:
            label = f"{address}:{port}"
        else:
            label = address or family
        return family, address, port, path, label
    label = _safe_text(value, limit=512)
    return None, None, None, None, label


class SyscallIndex:
    """Maintain and query a per-run SQLite index over ``os_audit.jsonl``."""

    def __init__(
        self,
        run_dir: Path | str,
        *,
        event_store: object | None = None,
        index_path: Path | str | None = None,
    ) -> None:
        self.run_dir = Path(run_dir).expanduser().resolve()
        if not self.run_dir.is_dir():
            raise FileNotFoundError(self.run_dir)
        self.raw_path = self.run_dir / RAW_RELATIVE_PATH
        self.index_path = (
            Path(index_path).expanduser().resolve()
            if index_path is not None
            else self.run_dir / INDEX_FILENAME
        )
        if self.index_path.exists() and self.index_path.is_symlink():
            raise SyscallIndexError(f"refusing symlink syscall index: {self.index_path}")
        self.event_store = event_store
        self._lock = threading.RLock()
        self._closed = False
        self._syncing = False
        self._last_sync_started_at: float | None = None
        self._last_sync_finished_at: float | None = None
        self._last_sync_error: str | None = None
        self._sqlite = _sqlite_module()
        self._connection = self._sqlite.connect(
            self.index_path,
            timeout=10,
            check_same_thread=False,
        )
        self._connection.row_factory = self._sqlite.Row
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=NORMAL")
        self._connection.execute("PRAGMA temp_store=MEMORY")
        self._connection.execute("PRAGMA busy_timeout=10000")
        self._initialize_schema()
        self._secure_index_files()

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("syscall index is closed")

    def _secure_index_files(self) -> None:
        for suffix in ("", "-wal", "-shm"):
            path = Path(f"{self.index_path}{suffix}")
            try:
                if path.is_file() and not path.is_symlink():
                    path.chmod(0o600)
            except OSError:
                continue

    def _initialize_schema(self) -> None:
        with self._connection:
            self._connection.execute(
                "CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            existing = self._meta("schema_version")
            if existing not in {None, SCHEMA_VERSION}:
                self._connection.execute("DROP TABLE IF EXISTS syscalls")
                self._connection.execute("DELETE FROM metadata")
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS syscalls (
                    seq INTEGER PRIMARY KEY,
                    wall_time_ns INTEGER NOT NULL,
                    monotonic_ns INTEGER,
                    pid INTEGER,
                    tid INTEGER,
                    ppid INTEGER,
                    comm TEXT,
                    syscall TEXT NOT NULL,
                    category TEXT,
                    access TEXT,
                    path TEXT,
                    path_scope TEXT,
                    fd INTEGER,
                    byte_count INTEGER,
                    endpoint_family TEXT,
                    endpoint_address TEXT,
                    endpoint_port INTEGER,
                    endpoint_path TEXT,
                    endpoint_text TEXT,
                    result_json TEXT,
                    errno TEXT,
                    success INTEGER,
                    duration_ns INTEGER,
                    arguments TEXT,
                    synthetic INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            for statement in (
                "CREATE INDEX IF NOT EXISTS syscall_wall_idx ON syscalls(wall_time_ns, seq)",
                "CREATE INDEX IF NOT EXISTS syscall_pid_idx ON syscalls(pid, seq)",
                "CREATE INDEX IF NOT EXISTS syscall_ppid_idx ON syscalls(ppid, seq)",
                "CREATE INDEX IF NOT EXISTS syscall_name_idx ON syscalls(syscall, seq)",
                "CREATE INDEX IF NOT EXISTS syscall_category_idx ON syscalls(category, seq)",
                "CREATE INDEX IF NOT EXISTS syscall_success_idx ON syscalls(success, seq)",
                "CREATE INDEX IF NOT EXISTS syscall_path_idx ON syscalls(path)",
                "CREATE INDEX IF NOT EXISTS syscall_endpoint_idx ON syscalls(endpoint_text)",
                "CREATE INDEX IF NOT EXISTS syscall_behavior_network_idx "
                "ON syscalls(category, endpoint_text, pid, access, success, errno, wall_time_ns, seq)",
                "CREATE INDEX IF NOT EXISTS syscall_behavior_file_idx "
                "ON syscalls(category, access, pid, path, success, errno, wall_time_ns, seq)",
            ):
                self._connection.execute(statement)
            self._set_meta("schema_version", SCHEMA_VERSION)
            self._set_meta_default("raw_offset", "0")
            self._set_meta_default("raw_device", "")
            self._set_meta_default("raw_inode", "")
            self._set_meta_default("last_seq", "0")
            self._set_meta_default("index_parse_errors", "0")

    def _meta(self, key: str, default: str | None = None) -> str | None:
        row = self._connection.execute(
            "SELECT value FROM metadata WHERE key = ?", (key,)
        ).fetchone()
        return str(row[0]) if row is not None else default

    def _set_meta(self, key: str, value: object) -> None:
        self._connection.execute(
            "INSERT INTO metadata(key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, str(value)),
        )

    def _set_meta_default(self, key: str, value: str) -> None:
        self._connection.execute(
            "INSERT OR IGNORE INTO metadata(key, value) VALUES (?, ?)", (key, value)
        )

    def _reset_rows(self) -> None:
        with self._connection:
            self._connection.execute("DELETE FROM syscalls")
            for key, value in (
                ("raw_offset", "0"),
                ("raw_device", ""),
                ("raw_inode", ""),
                ("last_seq", "0"),
                ("index_parse_errors", "0"),
            ):
                self._set_meta(key, value)

    @staticmethod
    def _row_values(row: Mapping[str, Any]) -> tuple[object, ...] | None:
        seq = _as_int(row.get("seq"))
        syscall = _safe_text(row.get("syscall"), limit=128)
        if seq is None or seq < 1 or not syscall:
            return None
        wall_time_ns = _as_int(row.get("wall_time_ns")) or 0
        family, address, port, endpoint_path, endpoint_text = _endpoint_fields(
            row.get("endpoint")
        )
        success_value = row.get("success")
        success = 1 if success_value is True else 0 if success_value is False else None
        if syscall in _EXEC_SYSCALLS:
            executable = _safe_text(row.get("path")) or "unknown"
            arguments = f"executable={executable}; argv_omitted=true"
        elif syscall in _BUFFER_SYSCALLS:
            descriptor = _as_int(row.get("fd"))
            arguments = f"fd={descriptor if descriptor is not None else 'unknown'}; payload_omitted=true"
        else:
            arguments = _safe_text(row.get("arguments"), limit=2_048)
        try:
            result_json = json.dumps(
                row.get("result"), ensure_ascii=False, separators=(",", ":")
            )
        except (TypeError, ValueError):
            result_json = "null"
        return (
            seq,
            wall_time_ns,
            _as_int(row.get("monotonic_ns")),
            _as_int(row.get("pid")),
            _as_int(row.get("tid")),
            _as_int(row.get("ppid")),
            _safe_text(row.get("comm"), limit=256),
            syscall,
            _safe_text(row.get("category"), limit=64),
            _safe_text(row.get("access"), limit=64),
            _safe_text(row.get("path")),
            _safe_text(row.get("path_scope"), limit=64),
            _as_int(row.get("fd")),
            _as_int(row.get("bytes")),
            family,
            address,
            port,
            endpoint_path,
            endpoint_text,
            result_json,
            _safe_text(row.get("errno"), limit=128),
            success,
            _as_int(row.get("duration_ns")),
            arguments,
            1 if row.get("synthetic") is True else 0,
        )

    def sync(self) -> dict[str, Any]:
        """Index every complete JSONL row currently available."""

        with self._lock:
            self._ensure_open()
            self._syncing = True
            self._last_sync_started_at = time.time()
            self._last_sync_error = None
            try:
                result = self._sync_locked()
            except BaseException as exc:
                self._last_sync_error = redact_text(f"{type(exc).__name__}: {exc}")[:512]
                raise
            finally:
                self._syncing = False
                self._last_sync_finished_at = time.time()
                self._secure_index_files()
            return result

    def _sync_locked(self) -> dict[str, Any]:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.raw_path, flags)
        except FileNotFoundError:
            return self._sync_result(raw_available=False)
        except OSError as exc:
            raise SyscallIndexError(f"cannot open syscall source: {exc}") from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise SyscallIndexError(f"syscall source is not a regular file: {self.raw_path}")
            offset = int(self._meta("raw_offset", "0") or 0)
            old_device = self._meta("raw_device", "") or ""
            old_inode = self._meta("raw_inode", "") or ""
            identity_changed = bool(
                offset
                and (
                    old_device != str(metadata.st_dev)
                    or old_inode != str(metadata.st_ino)
                    or metadata.st_size < offset
                )
            )
            if identity_changed:
                self._reset_rows()
                offset = 0
            os.lseek(descriptor, offset, os.SEEK_SET)
            inserted = 0
            parse_errors = int(self._meta("index_parse_errors", "0") or 0)
            last_complete_offset = offset
            batch: list[tuple[object, ...]] = []
            with os.fdopen(descriptor, "rb", closefd=True) as source:
                descriptor = -1
                while True:
                    line_start = source.tell()
                    raw_line = source.readline(_MAX_JSONL_LINE + 1)
                    if not raw_line:
                        break
                    if len(raw_line) > _MAX_JSONL_LINE and not raw_line.endswith(b"\n"):
                        while raw_line and not raw_line.endswith(b"\n"):
                            raw_line = source.readline(_MAX_JSONL_LINE + 1)
                        parse_errors += 1
                        last_complete_offset = source.tell()
                        continue
                    if not raw_line.endswith(b"\n"):
                        source.seek(line_start)
                        break
                    last_complete_offset = source.tell()
                    if not raw_line.strip():
                        continue
                    try:
                        value = json.loads(raw_line)
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        parse_errors += 1
                        continue
                    if not isinstance(value, Mapping):
                        parse_errors += 1
                        continue
                    normalized = self._row_values(value)
                    if normalized is None:
                        parse_errors += 1
                        continue
                    batch.append(normalized)
                    if len(batch) >= 1_000:
                        inserted += self._insert_batch(batch)
                        batch.clear()
                if batch:
                    inserted += self._insert_batch(batch)
            with self._connection:
                self._set_meta("raw_offset", last_complete_offset)
                self._set_meta("raw_device", metadata.st_dev)
                self._set_meta("raw_inode", metadata.st_ino)
                self._set_meta("index_parse_errors", parse_errors)
                row = self._connection.execute(
                    "SELECT COALESCE(MAX(seq), 0) FROM syscalls"
                ).fetchone()
                self._set_meta("last_seq", int(row[0]) if row else 0)
            return self._sync_result(
                raw_available=True,
                inserted=inserted,
                raw_size=metadata.st_size,
                partial_line=metadata.st_size > last_complete_offset,
                reset=identity_changed,
            )
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _insert_batch(self, rows: Sequence[tuple[object, ...]]) -> int:
        before = self._connection.total_changes
        with self._connection:
            self._connection.executemany(
                """
                INSERT OR REPLACE INTO syscalls (
                    seq, wall_time_ns, monotonic_ns, pid, tid, ppid, comm,
                    syscall, category, access, path, path_scope, fd, byte_count,
                    endpoint_family, endpoint_address, endpoint_port, endpoint_path,
                    endpoint_text, result_json, errno, success, duration_ns,
                    arguments, synthetic
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?
                )
                """,
                rows,
            )
        return self._connection.total_changes - before

    def _sync_result(
        self,
        *,
        raw_available: bool,
        inserted: int = 0,
        raw_size: int = 0,
        partial_line: bool = False,
        reset: bool = False,
    ) -> dict[str, Any]:
        count = int(self._connection.execute("SELECT COUNT(*) FROM syscalls").fetchone()[0])
        return {
            "schema_version": SCHEMA_VERSION,
            "raw_available": raw_available,
            "inserted": inserted,
            "indexed_events": count,
            "last_seq": int(self._meta("last_seq", "0") or 0),
            "raw_offset": int(self._meta("raw_offset", "0") or 0),
            "raw_size": raw_size,
            "partial_line": partial_line,
            "reset": reset,
            "parse_errors": int(self._meta("index_parse_errors", "0") or 0),
        }

    def rebuild(self) -> dict[str, Any]:
        """Discard only the derived rows and rebuild from the raw JSONL source."""

        with self._lock:
            self._ensure_open()
            self._reset_rows()
        return self.sync()

    @staticmethod
    def _key_evidence_clause() -> str:
        return """(
            category = 'network'
            OR success = 0
            OR (category = 'process' AND access IN ('execute', 'spawn'))
            OR access IN ('write', 'read_write', 'metadata_write')
            OR synthetic = 1
        )"""

    @staticmethod
    def _behavior_evidence_clause() -> str:
        """Select semantic behavior while retaining the raw index as evidence.

        Network activity is represented once per PID, endpoint, result and
        one-minute window.  This is a presentation/index roll-up, not a claim
        that the grouped kernel calls did not occur.
        """

        return f"""(
            synthetic = 1
            OR (
                category = 'process'
                AND access IN ('execute', 'spawn')
                AND (
                    success = 1
                    OR COALESCE(errno, '') NOT IN ('ENOENT', 'ENOTDIR')
                )
            )
            OR (
                category = 'file'
                AND access IN ('write', 'read_write', 'metadata_write')
                AND NOT EXISTS (
                    SELECT 1
                    FROM syscalls AS candidate
                    WHERE candidate.category = 'file'
                      AND candidate.access = syscalls.access
                      AND candidate.pid IS syscalls.pid
                      AND candidate.path IS syscalls.path
                      AND candidate.success IS syscalls.success
                      AND candidate.errno IS syscalls.errno
                      AND candidate.wall_time_ns >=
                          CAST(syscalls.wall_time_ns / 1000000000 AS INTEGER) * 1000000000
                      AND candidate.wall_time_ns <
                          (CAST(syscalls.wall_time_ns / 1000000000 AS INTEGER) + 1) * 1000000000
                      AND candidate.seq < syscalls.seq
                )
            )
            OR (
                category = 'file'
                AND access IN ('read', 'metadata_read')
                AND (
                    path_scope = 'workspace'
                    OR lower(COALESCE(path, '')) LIKE '%/.ssh/%'
                    OR lower(COALESCE(path, '')) LIKE '%/.aws/%'
                    OR lower(COALESCE(path, '')) LIKE '%/.config/gcloud/%'
                    OR lower(COALESCE(path, '')) LIKE '%/.kube/%'
                    OR lower(COALESCE(path, '')) LIKE '%/.docker/config.json'
                    OR lower(COALESCE(path, '')) LIKE '%/.git-credentials'
                    OR lower(COALESCE(path, '')) LIKE '%/.npmrc'
                    OR lower(COALESCE(path, '')) LIKE '%/.pypirc'
                    OR lower(COALESCE(path, '')) LIKE '%/.env'
                    OR lower(COALESCE(path, '')) LIKE '%/.env.%'
                    OR lower(COALESCE(path, '')) IN (
                        '/etc/passwd', '/etc/shadow', '/etc/sudoers'
                    )
                    OR lower(COALESCE(path, '')) LIKE '/proc/%/environ'
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM syscalls AS candidate
                    WHERE candidate.category = 'file'
                      AND candidate.access = syscalls.access
                      AND candidate.pid IS syscalls.pid
                      AND candidate.path IS syscalls.path
                      AND candidate.success IS syscalls.success
                      AND candidate.errno IS syscalls.errno
                      AND candidate.wall_time_ns >=
                          CAST(syscalls.wall_time_ns / 5000000000 AS INTEGER) * 5000000000
                      AND candidate.wall_time_ns <
                          (CAST(syscalls.wall_time_ns / 5000000000 AS INTEGER) + 1) * 5000000000
                      AND candidate.seq < syscalls.seq
                )
            )
            OR (
                category = 'network'
                AND endpoint_text IS NOT NULL
                AND NOT EXISTS (
                    SELECT 1
                    FROM syscalls AS candidate
                    WHERE candidate.category = 'network'
                      AND candidate.endpoint_text = syscalls.endpoint_text
                      AND candidate.pid IS syscalls.pid
                      AND candidate.access IS syscalls.access
                      AND candidate.success IS syscalls.success
                      AND candidate.errno IS syscalls.errno
                      AND candidate.wall_time_ns >=
                          CAST(syscalls.wall_time_ns / {_BEHAVIOR_ROLLUP_WINDOW_NS} AS INTEGER)
                          * {_BEHAVIOR_ROLLUP_WINDOW_NS}
                      AND candidate.wall_time_ns <
                          (CAST(syscalls.wall_time_ns / {_BEHAVIOR_ROLLUP_WINDOW_NS} AS INTEGER) + 1)
                          * {_BEHAVIOR_ROLLUP_WINDOW_NS}
                      AND candidate.seq < syscalls.seq
                )
            )
        )"""

    def _item_associations(self) -> list[dict[str, Any]]:
        store = self.event_store
        events_method = getattr(store, "events", None)
        if not callable(events_method):
            return []
        try:
            last_seq = int(getattr(store, "last_seq", 0) or 0)
            rows = events_method(after_seq=max(0, last_seq - 5_000), limit=5_000)
        except (TypeError, ValueError, RuntimeError):
            return []
        merged: dict[str, dict[str, Any]] = {}
        for event in rows:
            if not isinstance(event, Mapping):
                continue
            item_id = _safe_text(event.get("item_id"), limit=256)
            if not item_id:
                continue
            evidence = event.get("evidence")
            evidence = evidence if isinstance(evidence, Mapping) else {}
            correlation = evidence.get("correlation")
            correlation = correlation if isinstance(correlation, Mapping) else {}
            payload = event.get("payload")
            payload = payload if isinstance(payload, Mapping) else {}
            item = payload.get("item")
            item = item if isinstance(item, Mapping) else {}
            pid = _as_int(correlation.get("pid"))
            if pid is None:
                pid = _as_int(item.get("processId") or item.get("process_id"))
            current = merged.setdefault(
                item_id,
                {
                    "item_id": item_id,
                    "event_id": _safe_text(event.get("event_id"), limit=256),
                    "turn_id": _safe_text(event.get("turn_id"), limit=256),
                    "title": _safe_text(event.get("title"), limit=256) or "Agent 命令",
                    "pid": pid,
                    "started_at": None,
                    "ended_at": None,
                },
            )
            if current.get("pid") is None and pid is not None:
                current["pid"] = pid
            started_at = _as_float(correlation.get("started_at"))
            ended_at = _as_float(correlation.get("ended_at"))
            occurred_at = _as_float(event.get("occurred_at"))
            if started_at is None and str(payload.get("lifecycle")) == "started":
                started_at = occurred_at
            if ended_at is None and str(payload.get("lifecycle")) == "completed":
                ended_at = occurred_at
            if started_at is not None:
                previous = current.get("started_at")
                current["started_at"] = min(float(previous), started_at) if previous is not None else started_at
            if ended_at is not None:
                previous = current.get("ended_at")
                current["ended_at"] = max(float(previous), ended_at) if previous is not None else ended_at
            current["event_id"] = _safe_text(event.get("event_id"), limit=256) or current.get("event_id")
            current["title"] = _safe_text(event.get("title"), limit=256) or current.get("title")
        return list(merged.values())

    def _descendant_pids(
        self, root_pid: int, started_at: float | None, ended_at: float | None
    ) -> set[int]:
        conditions = ["pid IS NOT NULL", "ppid IS NOT NULL"]
        values: list[object] = []
        if started_at is not None:
            conditions.append("wall_time_ns >= ?")
            values.append(int((started_at - 1.0) * 1_000_000_000))
        if ended_at is not None:
            conditions.append("wall_time_ns <= ?")
            values.append(int((ended_at + 1.0) * 1_000_000_000))
        pairs = self._connection.execute(
            f"SELECT DISTINCT pid, ppid FROM syscalls WHERE {' AND '.join(conditions)}",
            values,
        ).fetchall()
        children: dict[int, set[int]] = {}
        for row in pairs:
            pid, ppid = _as_int(row[0]), _as_int(row[1])
            if pid is not None and ppid is not None:
                children.setdefault(ppid, set()).add(pid)
        matched = {root_pid}
        frontier = [root_pid]
        while frontier and len(matched) < 20_000:
            parent = frontier.pop()
            for child in children.get(parent, ()):  # pragma: no branch - tiny loop
                if child not in matched:
                    matched.add(child)
                    frontier.append(child)
        return matched

    def _association_for_item(self, item_id: str | None) -> dict[str, Any] | None:
        if not item_id:
            return None
        match = next(
            (row for row in self._item_associations() if row.get("item_id") == item_id),
            None,
        )
        if match is None:
            return {
                "item_id": item_id,
                "availability": "not_found",
                "confidence": "none",
                "reason": "当前工作台事件中未找到该 Agent Item",
            }
        if _as_int(match.get("pid")) is None:
            return {
                **match,
                "availability": "available_unassociated",
                "confidence": "none",
                "reason": "该 Agent Item 没有可用于事实关联的 PID；未使用纯时间窗强行归因",
            }
        root_pid = int(match["pid"])
        started_at = _as_float(match.get("started_at"))
        ended_at = _as_float(match.get("ended_at"))
        candidate_pids = sorted(
            self._descendant_pids(root_pid, started_at, ended_at)
        )
        clauses = [f"pid IN ({','.join('?' for _ in candidate_pids)})"]
        values: list[object] = list(candidate_pids)
        if started_at is not None:
            clauses.append("wall_time_ns >= ?")
            values.append(int((started_at - 1.0) * 1_000_000_000))
        if ended_at is not None:
            clauses.append("wall_time_ns <= ?")
            values.append(int((ended_at + 1.0) * 1_000_000_000))
        observed_pids = sorted(
            int(row[0])
            for row in self._connection.execute(
                f"SELECT DISTINCT pid FROM syscalls WHERE {' AND '.join(clauses)}",
                values,
            ).fetchall()
            if row[0] is not None
        )
        if not observed_pids:
            return {
                **match,
                "availability": "available_unassociated",
                "confidence": "none",
                "reason": (
                    "该 Agent Item 的 PID 未在当前 Run 的 OS 审计范围与生命周期内观察到；"
                    "未使用纯时间窗强行归因"
                ),
            }
        return {
            **match,
            "availability": "available",
            "confidence": (
                "exact_pid_or_process_tree"
                if root_pid in observed_pids
                else "descendant_process_tree"
            ),
            "pids": observed_pids,
        }

    def _build_filters(
        self,
        *,
        pid: int | None = None,
        tid: int | None = None,
        syscalls: Sequence[str] = (),
        category: str | None = None,
        access: str | None = None,
        path: str | None = None,
        endpoint: str | None = None,
        success: bool | None = None,
        query: str | None = None,
        from_ns: int | None = None,
        to_ns: int | None = None,
        key_only: bool = False,
        behavior_only: bool = False,
        association: Mapping[str, Any] | None = None,
    ) -> tuple[list[str], list[object]]:
        clauses: list[str] = []
        values: list[object] = []
        if pid is not None:
            clauses.append("pid = ?")
            values.append(pid)
        if tid is not None:
            clauses.append("tid = ?")
            values.append(tid)
        names = [name.strip()[:128] for name in syscalls if name.strip()][:32]
        if names:
            clauses.append(f"syscall IN ({','.join('?' for _ in names)})")
            values.extend(names)
        if category:
            clauses.append("category = ?")
            values.append(category[:64])
        if access:
            clauses.append("access = ?")
            values.append(access[:64])
        if path:
            clauses.append("instr(COALESCE(path, ''), ?) > 0")
            values.append(redact_text(path)[:512])
        if endpoint:
            clauses.append("instr(COALESCE(endpoint_text, ''), ?) > 0")
            values.append(redact_text(endpoint)[:512])
        if success is not None:
            clauses.append("success = ?")
            values.append(1 if success else 0)
        if query:
            clauses.append(
                "(instr(COALESCE(comm, ''), ?) > 0 OR instr(syscall, ?) > 0 "
                "OR instr(COALESCE(path, ''), ?) > 0 "
                "OR instr(COALESCE(endpoint_text, ''), ?) > 0 "
                "OR instr(COALESCE(errno, ''), ?) > 0)"
            )
            needle = redact_text(query)[:256]
            values.extend([needle] * 5)
        if from_ns is not None:
            clauses.append("wall_time_ns >= ?")
            values.append(from_ns)
        if to_ns is not None:
            clauses.append("wall_time_ns <= ?")
            values.append(to_ns)
        if key_only:
            clauses.append(self._key_evidence_clause())
        if behavior_only:
            clauses.append(self._behavior_evidence_clause())
        if association is not None:
            pids = [int(value) for value in association.get("pids", []) if _as_int(value) is not None]
            if association.get("availability") != "available" or not pids:
                clauses.append("0 = 1")
            else:
                clauses.append(f"pid IN ({','.join('?' for _ in pids)})")
                values.extend(pids)
                started_at = _as_float(association.get("started_at"))
                ended_at = _as_float(association.get("ended_at"))
                if started_at is not None:
                    clauses.append("wall_time_ns >= ?")
                    values.append(int((started_at - 1.0) * 1_000_000_000))
                if ended_at is not None:
                    clauses.append("wall_time_ns <= ?")
                    values.append(int((ended_at + 1.0) * 1_000_000_000))
        return clauses, values

    @staticmethod
    def _decode_result(value: object) -> object:
        try:
            return json.loads(str(value))
        except (TypeError, ValueError, json.JSONDecodeError):
            return None

    def _public_row(self, row: Mapping[str, Any]) -> dict[str, Any]:
        endpoint: dict[str, Any] | None = None
        if any(
            row[key] is not None
            for key in (
                "endpoint_family",
                "endpoint_address",
                "endpoint_port",
                "endpoint_path",
            )
        ):
            endpoint = {
                key.removeprefix("endpoint_"): row[key]
                for key in (
                    "endpoint_family",
                    "endpoint_address",
                    "endpoint_port",
                    "endpoint_path",
                )
                if row[key] is not None
            }
        return {
            "seq": int(row["seq"]),
            "wall_time_ns": int(row["wall_time_ns"]),
            "monotonic_ns": row["monotonic_ns"],
            "pid": row["pid"],
            "tid": row["tid"],
            "ppid": row["ppid"],
            "comm": row["comm"],
            "syscall": row["syscall"],
            "category": row["category"],
            "access": row["access"],
            "path": row["path"],
            "path_scope": row["path_scope"],
            "fd": row["fd"],
            "bytes": row["byte_count"],
            "endpoint": endpoint,
            "endpoint_text": row["endpoint_text"],
            "result": self._decode_result(row["result_json"]),
            "errno": row["errno"],
            "success": True if row["success"] == 1 else False if row["success"] == 0 else None,
            "duration_ns": row["duration_ns"],
            "arguments": row["arguments"],
            "synthetic": bool(row["synthetic"]),
        }

    def _attach_agent_items(self, items: list[dict[str, Any]]) -> None:
        if not items:
            return
        associations = [
            row for row in self._item_associations() if _as_int(row.get("pid")) is not None
        ]
        if not associations:
            return
        descendants: dict[str, set[int]] = {}
        for association in associations:
            descendants[str(association["item_id"])] = self._descendant_pids(
                int(association["pid"]),
                _as_float(association.get("started_at")),
                _as_float(association.get("ended_at")),
            )
        for item in items:
            timestamp = int(item.get("wall_time_ns") or 0) / 1_000_000_000
            candidates: list[tuple[int, dict[str, Any]]] = []
            for association in associations:
                root_pid = int(association["pid"])
                pid = _as_int(item.get("pid"))
                if pid is None or pid not in descendants[str(association["item_id"])]:
                    continue
                started = _as_float(association.get("started_at"))
                ended = _as_float(association.get("ended_at"))
                if started is not None and timestamp < started - 1.0:
                    continue
                if ended is not None and timestamp > ended + 1.0:
                    continue
                exact = pid == root_pid
                bounded = started is not None or ended is not None
                score = (4 if exact else 2) + (2 if bounded else 0)
                candidates.append(
                    (
                        score,
                        {
                            "item_id": association["item_id"],
                            "event_id": association.get("event_id"),
                            "turn_id": association.get("turn_id"),
                            "title": association.get("title"),
                            "confidence_tier": "fact" if exact and bounded else "strong",
                            "basis": "exact_pid_and_item_lifecycle" if exact and bounded else "descendant_process_tree",
                        },
                    )
                )
            if candidates:
                candidates.sort(key=lambda value: value[0], reverse=True)
                item["agent_item"] = candidates[0][1]

    def query(
        self,
        *,
        after_seq: int | None = None,
        before_seq: int | None = None,
        limit: int = DEFAULT_PAGE_SIZE,
        order: str = "desc",
        pid: int | None = None,
        tid: int | None = None,
        syscalls: Sequence[str] = (),
        category: str | None = None,
        access: str | None = None,
        path: str | None = None,
        endpoint: str | None = None,
        success: bool | None = None,
        query: str | None = None,
        from_ns: int | None = None,
        to_ns: int | None = None,
        key_only: bool = False,
        behavior_only: bool = False,
        item_id: str | None = None,
        include_total: bool = True,
    ) -> dict[str, Any]:
        if not 1 <= limit <= MAX_PAGE_SIZE:
            raise ValueError(f"limit must be between 1 and {MAX_PAGE_SIZE}")
        if order not in {"asc", "desc"}:
            raise ValueError("order must be asc or desc")
        with self._lock:
            self._ensure_open()
            sync = self.sync()
            association = self._association_for_item(item_id)
            base_clauses, base_values = self._build_filters(
                pid=pid,
                tid=tid,
                syscalls=syscalls,
                category=category,
                access=access,
                path=path,
                endpoint=endpoint,
                success=success,
                query=query,
                from_ns=from_ns,
                to_ns=to_ns,
                key_only=key_only,
                behavior_only=behavior_only,
                association=association,
            )
            raw_clauses: list[str] = []
            raw_values: list[object] = []
            if include_total and behavior_only:
                raw_clauses, raw_values = self._build_filters(
                    pid=pid,
                    tid=tid,
                    syscalls=syscalls,
                    category=category,
                    access=access,
                    path=path,
                    endpoint=endpoint,
                    success=success,
                    query=query,
                    from_ns=from_ns,
                    to_ns=to_ns,
                    key_only=key_only,
                    behavior_only=False,
                    association=association,
                )
            clauses = list(base_clauses)
            values = list(base_values)
            if after_seq is not None:
                clauses.append("seq > ?")
                values.append(after_seq)
            if before_seq is not None:
                clauses.append("seq < ?")
                values.append(before_seq)
            where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
            rows = self._connection.execute(
                f"SELECT * FROM syscalls {where} ORDER BY seq {order.upper()} LIMIT ?",
                [*values, limit + 1],
            ).fetchall()
            has_more = len(rows) > limit
            public = [self._public_row(row) for row in rows[:limit]]
            self._attach_agent_items(public)
            total = None
            raw_matching_total = None
            if include_total:
                base_where = (
                    f"WHERE {' AND '.join(base_clauses)}" if base_clauses else ""
                )
                total = int(
                    self._connection.execute(
                        f"SELECT COUNT(*) FROM syscalls {base_where}", base_values
                    ).fetchone()[0]
                )
                if behavior_only:
                    raw_where = (
                        f"WHERE {' AND '.join(raw_clauses)}" if raw_clauses else ""
                    )
                    raw_matching_total = int(
                        self._connection.execute(
                            f"SELECT COUNT(*) FROM syscalls {raw_where}", raw_values
                        ).fetchone()[0]
                    )
                else:
                    raw_matching_total = total
            return {
                "schema_version": "lingmou.syscall-query.v1",
                "items": public,
                "total": total,
                "view": {
                    "mode": "behavior" if behavior_only else "key" if key_only else "all",
                    "matching_raw": raw_matching_total,
                    "shown": total,
                    "filtered_or_grouped": (
                        max(0, raw_matching_total - total)
                        if raw_matching_total is not None and total is not None
                        else None
                    ),
                    "rollup_window_seconds": (
                        _BEHAVIOR_ROLLUP_WINDOW_NS // 1_000_000_000
                        if behavior_only
                        else None
                    ),
                },
                "association": association,
                "page": {
                    "limit": limit,
                    "order": order,
                    "has_more": has_more,
                    "next_before_seq": public[-1]["seq"] if public and order == "desc" and has_more else None,
                    "next_after_seq": public[-1]["seq"] if public and order == "asc" and has_more else None,
                },
                "index": sync,
            }

    def detail(self, seq: int) -> dict[str, Any] | None:
        with self._lock:
            self._ensure_open()
            self.sync()
            row = self._connection.execute(
                "SELECT * FROM syscalls WHERE seq = ?", (seq,)
            ).fetchone()
            if row is None:
                return None
            item = self._public_row(row)
            self._attach_agent_items([item])
            neighbors = self._connection.execute(
                "SELECT MAX(CASE WHEN seq < ? THEN seq END), "
                "MIN(CASE WHEN seq > ? THEN seq END) FROM syscalls",
                (seq, seq),
            ).fetchone()
            return {
                "schema_version": "lingmou.syscall-detail.v1",
                "item": item,
                "previous_seq": neighbors[0] if neighbors else None,
                "next_seq": neighbors[1] if neighbors else None,
            }

    def density(
        self,
        *,
        buckets: int = 96,
        from_ns: int | None = None,
        to_ns: int | None = None,
        key_only: bool = False,
        behavior_only: bool = False,
        pid: int | None = None,
        category: str | None = None,
    ) -> dict[str, Any]:
        if not 1 <= buckets <= MAX_DENSITY_BUCKETS:
            raise ValueError(f"buckets must be between 1 and {MAX_DENSITY_BUCKETS}")
        with self._lock:
            self._ensure_open()
            self.sync()
            clauses, values = self._build_filters(
                pid=pid,
                category=category,
                from_ns=from_ns,
                to_ns=to_ns,
                key_only=key_only,
                behavior_only=behavior_only,
            )
            where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
            bounds = self._connection.execute(
                f"SELECT MIN(wall_time_ns), MAX(wall_time_ns) FROM syscalls {where}",
                values,
            ).fetchone()
            start = int(bounds[0]) if bounds and bounds[0] is not None else 0
            end = int(bounds[1]) if bounds and bounds[1] is not None else start
            width = max(1, (end - start + buckets) // buckets)
            grouped = self._connection.execute(
                f"""
                SELECT MIN(?, CAST((wall_time_ns - ?) / ? AS INTEGER)) AS bucket,
                       COUNT(*) AS total,
                       SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) AS failed,
                       SUM(CASE WHEN category = 'network' THEN 1 ELSE 0 END) AS network,
                       SUM(CASE WHEN access IN ('write','read_write','metadata_write') THEN 1 ELSE 0 END) AS writes
                FROM syscalls {where}
                GROUP BY bucket ORDER BY bucket
                """,
                [buckets - 1, start, width, *values],
            ).fetchall() if start else []
            by_bucket = {int(row[0]): row for row in grouped}
            items = []
            for index in range(buckets):
                row = by_bucket.get(index)
                items.append(
                    {
                        "index": index,
                        "from_ns": start + index * width if start else 0,
                        "to_ns": min(end, start + (index + 1) * width - 1) if start else 0,
                        "total": int(row[1] or 0) if row else 0,
                        "failed": int(row[2] or 0) if row else 0,
                        "network": int(row[3] or 0) if row else 0,
                        "writes": int(row[4] or 0) if row else 0,
                    }
                )
            return {
                "schema_version": "lingmou.syscall-density.v1",
                "from_ns": start,
                "to_ns": end,
                "bucket_width_ns": width,
                "view": "behavior" if behavior_only else "key" if key_only else "all",
                "items": items,
            }

    def processes(self, *, limit: int = 5_000) -> dict[str, Any]:
        if not 1 <= limit <= 20_000:
            raise ValueError("limit must be between 1 and 20000")
        with self._lock:
            self._ensure_open()
            self.sync()
            rows = self._connection.execute(
                """
                SELECT pid, MAX(ppid) AS ppid, MAX(comm) AS comm, COUNT(*) AS total,
                       MIN(wall_time_ns) AS first_seen_ns, MAX(wall_time_ns) AS last_seen_ns,
                       SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) AS failed,
                       SUM(CASE WHEN category = 'network' THEN 1 ELSE 0 END) AS network
                FROM syscalls WHERE pid IS NOT NULL
                GROUP BY pid ORDER BY total DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
            known = {int(row[0]) for row in rows}
            parent_by_pid = {
                int(row[0]): int(row[1]) if row[1] is not None else None for row in rows
            }

            def depth(pid: int) -> int:
                seen = {pid}
                parent = parent_by_pid.get(pid)
                value = 0
                while parent in known and parent not in seen and value < 32:
                    seen.add(parent)
                    value += 1
                    parent = parent_by_pid.get(parent)
                return value

            items = [
                {
                    "pid": int(row[0]),
                    "ppid": int(row[1]) if row[1] is not None else None,
                    "comm": row[2],
                    "total": int(row[3]),
                    "first_seen_ns": int(row[4]),
                    "last_seen_ns": int(row[5]),
                    "failed": int(row[6] or 0),
                    "network": int(row[7] or 0),
                    "depth": depth(int(row[0])),
                    "is_root": row[1] is None or int(row[1]) not in known,
                }
                for row in rows
            ]
            item_by_pid = {row["pid"]: row for row in items}
            children_by_pid: dict[int, list[dict[str, Any]]] = {}
            roots: list[dict[str, Any]] = []
            for item in items:
                parent = item["ppid"]
                if parent in item_by_pid and parent != item["pid"]:
                    children_by_pid.setdefault(parent, []).append(item)
                else:
                    roots.append(item)

            def process_order(item: Mapping[str, Any]) -> tuple[int, int]:
                return (-int(item["total"]), int(item["pid"]))

            roots.sort(key=process_order)
            for children in children_by_pid.values():
                children.sort(key=process_order)

            ordered: list[dict[str, Any]] = []
            visited: set[int] = set()

            def visit(item: dict[str, Any]) -> None:
                pid = int(item["pid"])
                if pid in visited:
                    return
                visited.add(pid)
                ordered.append(item)
                for child in children_by_pid.get(pid, []):
                    visit(child)

            for root in roots:
                visit(root)
            # Malformed/cyclic parent data must stay visible instead of disappearing.
            for item in sorted(items, key=process_order):
                visit(item)
            return {
                "schema_version": "lingmou.syscall-processes.v1",
                "items": ordered,
                "total": len(ordered),
            }

    def status(self) -> dict[str, Any]:
        with self._lock:
            self._ensure_open()
            sync = self.sync()
            aggregate = self._connection.execute(
                """
                SELECT COUNT(*) AS total, COUNT(DISTINCT pid) AS pids,
                       COALESCE(SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END), 0) AS failed,
                       COALESCE(SUM(CASE WHEN category = 'network' THEN 1 ELSE 0 END), 0) AS network,
                       COALESCE(SUM(CASE WHEN access IN ('write','read_write','metadata_write') THEN 1 ELSE 0 END), 0) AS writes,
                       MIN(wall_time_ns) AS first_ns, MAX(wall_time_ns) AS last_ns
                FROM syscalls
                """
            ).fetchone()
            categories = {
                str(row[0]): int(row[1])
                for row in self._connection.execute(
                    "SELECT COALESCE(category, 'other'), COUNT(*) FROM syscalls GROUP BY category"
                ).fetchall()
            }
            top_syscalls = [
                {"name": str(row[0]), "count": int(row[1])}
                for row in self._connection.execute(
                    "SELECT syscall, COUNT(*) AS total FROM syscalls GROUP BY syscall "
                    "ORDER BY total DESC, syscall LIMIT 12"
                ).fetchall()
            ]
            now_ns = time.time_ns()
            five_seconds_ago = now_ns - 5_000_000_000
            recent = int(
                self._connection.execute(
                    "SELECT COUNT(*) FROM syscalls WHERE wall_time_ns >= ?",
                    (five_seconds_ago,),
                ).fetchone()[0]
            )
            rate = recent / 5.0
            manifest = _read_json_object(self.run_dir / "manifest.json")
            audit = manifest.get("os_audit")
            audit = audit if isinstance(audit, Mapping) else {}
            collector = audit.get("collector")
            collector = collector if isinstance(collector, Mapping) else {}
            indexed_total = int(aggregate[0] or 0)
            captured_total = max(
                indexed_total,
                _as_int(collector.get("events")) or 0,
                int(sync.get("last_seq") or 0),
            )
            raw_size = int(sync.get("raw_size") or 0)
            if not raw_size:
                try:
                    raw_size = self.raw_path.stat().st_size
                except OSError:
                    raw_size = 0
            dropped = _as_int(collector.get("dropped")) or _as_int(audit.get("dropped")) or 0
            collector_parse_errors = _as_int(collector.get("parse_errors")) or 0
            known_loss = bool(
                audit.get("known_loss_detected")
                or collector.get("known_loss")
                or collector.get("limit_reached")
                or dropped
                or collector_parse_errors
            )
            enabled = bool(audit.get("enabled")) or sync.get("raw_available") is True
            collection_status = str(
                audit.get("status")
                or ("running" if manifest.get("status") == "running" and enabled else "available" if enabled else "disabled")
            )
            # Runs created before trace_profile was persisted used the former
            # focused default.  Keep that legacy fact distinct from the new
            # behavior default applied to future monitor processes.
            profile = str(audit.get("trace_profile") or audit.get("profile") or "focused")
            profile_label = {
                "behavior": "行为档",
                "focused": "重点档",
                "full": "全量档",
            }.get(profile, profile)
            observed_events = max(
                captured_total,
                _as_int(collector.get("observed_events")) or 0,
            )
            filtered_events = _as_int(collector.get("filtered_events")) or 0
            return {
                "schema_version": "lingmou.syscall-status.v1",
                "run_id": manifest.get("run_id"),
                "scope": str(audit.get("scope") or "appserver_descendant_process_tree"),
                "scope_label": "当前 Run · Codex app-server 及其后代进程",
                "profile": profile,
                "profile_label": profile_label,
                "collection": {
                    "enabled": enabled,
                    "requested": audit.get("requested", "off"),
                    "status": collection_status,
                    "known_loss": known_loss,
                    "captured_events": captured_total,
                    "observed_events": observed_events,
                    "filtered_events": filtered_events,
                    "filtered_noise": _as_int(collector.get("filtered_noise")) or 0,
                    "filtered_repeats": _as_int(collector.get("filtered_repeats")) or 0,
                    "rate_per_second": rate,
                    "raw_bytes": raw_size,
                    "dropped": dropped,
                    "parse_errors": collector_parse_errors,
                    "reader_error": collector.get("reader_error") or audit.get("runtime_error"),
                    "limit_reached": bool(collector.get("limit_reached")),
                    "max_events": _as_int(collector.get("max_events")) or _as_int(audit.get("max_events")),
                    "max_bytes": _as_int(collector.get("max_bytes")),
                    "content_capture": False,
                    "exec_argv_capture": False,
                },
                "index": {
                    **sync,
                    "path": os.fspath(self.index_path),
                    "lag_events": max(0, captured_total - indexed_total),
                    "syncing": self._syncing,
                    "last_sync_started_at": self._last_sync_started_at,
                    "last_sync_finished_at": self._last_sync_finished_at,
                    "last_error": self._last_sync_error,
                },
                "summary": {
                    "total": indexed_total,
                    "pids": int(aggregate[1] or 0),
                    "failed": int(aggregate[2] or 0),
                    "network": int(aggregate[3] or 0),
                    "writes": int(aggregate[4] or 0),
                    "first_event_ns": int(aggregate[5]) if aggregate[5] is not None else None,
                    "last_event_ns": int(aggregate[6]) if aggregate[6] is not None else None,
                    "categories": categories,
                    "top_syscalls": top_syscalls,
                },
                "privacy": {
                    "buffer_payloads": "omitted",
                    "exec_arguments": "omitted",
                    "credentials": "redacted",
                },
            }

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            try:
                self._connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except self._sqlite.Error:
                pass
            self._connection.close()
            self._closed = True
            self._secure_index_files()


__all__ = [
    "DEFAULT_PAGE_SIZE",
    "INDEX_FILENAME",
    "MAX_DENSITY_BUCKETS",
    "MAX_PAGE_SIZE",
    "RAW_RELATIVE_PATH",
    "SCHEMA_VERSION",
    "SyscallIndex",
    "SyscallIndexError",
]
