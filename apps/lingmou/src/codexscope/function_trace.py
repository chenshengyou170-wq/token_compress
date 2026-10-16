from __future__ import annotations

import hashlib
import json
import os
import socket
import stat
import struct
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from .model import CanonicalEvent, EventPhase, EventSource, EventStatus, FunctionRef


RAW_SCHEMA = "codexscope.function_trace.v1"
_SUPPORTED_MODES = frozenset({"off", "python", "c", "all"})
_FUNCTION_RECORDS = frozenset({"frame_enter", "frame_exit"})
_MAX_DATAGRAM = 16 * 1024
_MAX_RAW_LINE = 64 * 1024
_ADDR2LINE_BATCH = 1024
_MAX_IDENTITY_TEXT = 4096
_MAX_CALLS_PER_PROCESS = 10_000_000
_MAX_CREDENTIAL_CACHE = 4096


@dataclass(frozen=True, slots=True)
class FunctionTraceConfig:
    """Configuration for the opt-in cooperative function instrumentation."""

    mode: str = "off"
    max_calls_per_process: int = 100_000
    max_records_per_run: int = 400_000
    max_bytes_per_run: int = 128 * 1024 * 1024

    def __post_init__(self) -> None:
        if self.mode not in _SUPPORTED_MODES:
            raise ValueError(f"unsupported function trace mode: {self.mode}")
        for name in (
            "max_calls_per_process",
            "max_records_per_run",
            "max_bytes_per_run",
        ):
            if type(getattr(self, name)) is not int:
                raise TypeError(f"{name} must be an integer")
        if self.max_calls_per_process < 1:
            raise ValueError("max_calls_per_process must be positive")
        if self.max_calls_per_process > _MAX_CALLS_PER_PROCESS:
            raise ValueError(
                f"max_calls_per_process cannot exceed {_MAX_CALLS_PER_PROCESS}"
            )
        if self.max_records_per_run < 1:
            raise ValueError("max_records_per_run must be positive")
        if self.max_bytes_per_run < 1:
            raise ValueError("max_bytes_per_run must be positive")

    @property
    def enabled(self) -> bool:
        return self.mode != "off"

    @property
    def languages(self) -> tuple[str, ...]:
        if self.mode == "all":
            return ("python", "c")
        if self.mode == "off":
            return ()
        return (self.mode,)


def _stable_id(prefix: str, *parts: object) -> str:
    material = "\x1f".join(str(part) for part in parts)
    digest = hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()[:20]
    return f"{prefix}:{digest}"


def _proc_parent(pid: int) -> int | None:
    """Read a Linux process parent without trusting the instrumented payload."""

    try:
        value = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8", errors="replace")
        fields = value[value.rfind(")") + 2 :].split()
        parent = int(fields[1])
    except (OSError, ValueError, IndexError):
        return None
    return parent if parent > 0 else None


def _proc_start_marker(pid: int) -> str | None:
    """Return Linux's kernel process start tick for PID-reuse-safe caching."""

    try:
        value = Path(f"/proc/{pid}/stat").read_text(
            encoding="utf-8", errors="replace"
        )
        fields = value[value.rfind(")") + 2 :].split()
        marker = fields[19]
    except (OSError, IndexError):
        return None
    return marker or None


def _proc_ancestry(pid: int, *, limit: int = 16) -> tuple[int | None, list[int]]:
    ancestors: list[int] = []
    seen = {pid}
    current = pid
    for _ in range(limit):
        parent = _proc_parent(current)
        if parent is None or parent in seen:
            break
        ancestors.append(parent)
        seen.add(parent)
        current = parent
    return (ancestors[0] if ancestors else None), ancestors


class FunctionTraceCollector:
    """Receive bounded runtime datagrams and remain the sole raw-file writer.

    On Linux, ``SO_PASSCRED`` supplies a kernel-authenticated sender PID. The
    function identity remains cooperative/self-reported and is not presented as
    tamper-proof evidence.
    """

    def __init__(self, destination: Path, config: FunctionTraceConfig) -> None:
        if not config.enabled:
            raise ValueError("cannot start a disabled function trace collector")
        if not hasattr(socket, "AF_UNIX") or not hasattr(socket.socket, "recvmsg"):
            raise RuntimeError(
                "function tracing requires Unix-domain sockets with recvmsg support"
            )
        self.destination = destination
        self.config = config
        self._directory: Path | None = None
        self._socket_path: Path | None = None
        self._socket: socket.socket | None = None
        self._fd: int | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._closed = False
        self._credential_cache: dict[
            tuple[int, str], tuple[str | None, int | None, list[int]]
        ] = {}
        self._drain_deadline: float | None = None
        self._stats: dict[str, Any] = {
            "raw_schema": RAW_SCHEMA,
            "transport": "unix_datagram",
            "peer_credentials": False,
            "received_datagrams": 0,
            "written_records": 0,
            "written_bytes": 0,
            "invalid_datagrams": 0,
            "unsupported_schema_records": 0,
            "declared_pid_mismatches": 0,
            "records_dropped_by_run_limit": 0,
            "receiver_errors": [],
        }

    @classmethod
    def start(
        cls, destination: Path, config: FunctionTraceConfig
    ) -> "FunctionTraceCollector":
        collector = cls(destination, config)
        collector._start()
        return collector

    @property
    def socket_path(self) -> Path:
        if self._socket_path is None:
            raise RuntimeError("function trace collector is not started")
        return self._socket_path

    def _start(self) -> None:
        self.destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.destination.parent.chmod(0o700)
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        flags |= getattr(os, "O_NOFOLLOW", 0)
        self._fd = os.open(self.destination, flags, 0o600)
        os.fchmod(self._fd, 0o600)
        if not stat.S_ISREG(os.fstat(self._fd).st_mode):
            os.close(self._fd)
            self._fd = None
            raise OSError(f"refusing non-regular function trace file: {self.destination}")

        try:
            directory = Path(tempfile.mkdtemp(prefix="codexscope-ftrace-"))
            directory.chmod(0o700)
            socket_path = directory / "events.sock"
            receiver = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            if hasattr(socket, "SO_PASSCRED"):
                receiver.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                self._stats["peer_credentials"] = True
            receiver.bind(os.fspath(socket_path))
            socket_path.chmod(0o600)
            receiver.settimeout(0.2)
            self._directory = directory
            self._socket_path = socket_path
            self._socket = receiver
            self._thread = threading.Thread(
                target=self._receive_loop,
                name="codexscope-function-trace",
                daemon=True,
            )
            self._thread.start()
        except BaseException:
            self._cleanup_transport()
            if self._fd is not None:
                os.close(self._fd)
                self._fd = None
            raise

    def child_environment(
        self, repo: Path, *, run_id: str, inherited: Mapping[str, str] | None = None
    ) -> dict[str, str]:
        inherited = os.environ if inherited is None else inherited
        values = {
            "CODEXSCOPE_FUNCTION_TRACE": ",".join(self.config.languages),
            "CODEXSCOPE_FUNCTION_SOCKET": os.fspath(self.socket_path),
            "CODEXSCOPE_FUNCTION_ROOT": os.fspath(repo.expanduser().resolve()),
            "CODEXSCOPE_FUNCTION_RUN_ID": run_id,
            "CODEXSCOPE_FUNCTION_MAX_CALLS": str(self.config.max_calls_per_process),
            # Suppression is scoped to telemetry commands. An exported parent
            # value must not silently disable the explicitly requested run.
            "CODEXSCOPE_FUNCTION_TRACE_SUPPRESS": "0",
        }
        if "python" in self.config.languages:
            bootstrap = Path(__file__).with_name("runtime_bootstrap")
            if not (bootstrap / "sitecustomize.py").is_file():
                raise FileNotFoundError(f"Python trace bootstrap is missing: {bootstrap}")
            existing = inherited.get("PYTHONPATH", "")
            values["PYTHONPATH"] = (
                os.fspath(bootstrap)
                if not existing
                else os.pathsep.join((os.fspath(bootstrap), existing))
            )
        return values

    def _credentials(self, ancillary: list[tuple[int, int, bytes]]) -> tuple[int | None, int | None, int | None]:
        scm_credentials = getattr(socket, "SCM_CREDENTIALS", None)
        if scm_credentials is None:
            return None, None, None
        for level, kind, value in ancillary:
            if level == socket.SOL_SOCKET and kind == scm_credentials and len(value) >= 12:
                return struct.unpack("3i", value[:12])
        return None, None, None

    def _receive_loop(self) -> None:
        assert self._socket is not None and self._fd is not None
        receiver = self._socket
        destination_fd = self._fd
        ancillary_size = socket.CMSG_SPACE(12) if hasattr(socket, "CMSG_SPACE") else 0
        while True:
            if (
                self._stop.is_set()
                and self._drain_deadline is not None
                and time.monotonic() >= self._drain_deadline
            ):
                break
            try:
                data, ancillary, flags, _address = receiver.recvmsg(
                    _MAX_DATAGRAM, ancillary_size
                )
            except socket.timeout:
                if self._stop.is_set():
                    break
                continue
            except OSError as exc:
                if not self._stop.is_set():
                    self._record_receiver_error(exc)
                break
            if data == b"__codexscope_stop__":
                continue
            self._stats["received_datagrams"] += 1
            if flags & getattr(socket, "MSG_TRUNC", 0):
                self._stats["invalid_datagrams"] += 1
                continue
            try:
                row = json.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._stats["invalid_datagrams"] += 1
                continue
            if not isinstance(row, dict):
                self._stats["invalid_datagrams"] += 1
                continue
            if row.get("schema") != RAW_SCHEMA:
                self._stats["unsupported_schema_records"] += 1
                continue
            if self._stats["written_records"] >= self.config.max_records_per_run:
                self._stats["records_dropped_by_run_limit"] += 1
                continue

            pid, uid, gid = self._credentials(ancillary)
            declared_pid = row.get("pid")
            # Never retain sender-provided values in fields reserved for
            # transport verification.
            for key in (
                "peer_pid",
                "peer_uid",
                "peer_gid",
                "peer_ppid",
                "peer_ancestor_pids",
                "peer_process_start_marker",
            ):
                row.pop(key, None)
            row["peer_credentials_verified"] = False
            if pid is not None:
                if declared_pid is not None and declared_pid != pid:
                    row["declared_pid"] = declared_pid
                    row["declared_pid_mismatch"] = True
                    self._stats["declared_pid_mismatches"] += 1
                row["pid"] = pid
                row["peer_pid"] = pid
                row["peer_uid"] = uid
                row["peer_gid"] = gid
                row["peer_credentials_verified"] = True
                instance = str(row.get("process_instance_id") or "")[:4096]
                credential_key = (pid, instance)
                cached_credentials = self._credential_cache.get(credential_key)
                if cached_credentials is None or row.get("kind") == "process_start":
                    if len(self._credential_cache) >= _MAX_CREDENTIAL_CACHE:
                        self._credential_cache.clear()
                    start_marker = _proc_start_marker(pid)
                    peer_parent, ancestors = _proc_ancestry(pid)
                    cached_credentials = (
                        start_marker,
                        peer_parent,
                        ancestors,
                    )
                    self._credential_cache[credential_key] = cached_credentials
                _start_marker, peer_parent, ancestors = cached_credentials
                row["peer_process_start_marker"] = _start_marker
                row["peer_ppid"] = peer_parent
                row["peer_ancestor_pids"] = ancestors
            row["collector_seq"] = self._stats["written_records"] + 1
            row["collector_wall_time_ns"] = time.time_ns()
            encoded = (
                json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n"
            ).encode("utf-8")
            if (
                self._stats["written_bytes"] + len(encoded)
                > self.config.max_bytes_per_run
            ):
                self._stats["records_dropped_by_run_limit"] += 1
                continue
            try:
                view = memoryview(encoded)
                while view:
                    written = os.write(destination_fd, view)
                    view = view[written:]
            except OSError as exc:
                self._record_receiver_error(exc)
                continue
            self._stats["written_records"] += 1
            self._stats["written_bytes"] += len(encoded)

        # If close() had to return while a filesystem write was still
        # blocked, the receiver retains ownership and releases the descriptor
        # itself once it can leave the loop.
        if self._closed and self._fd == destination_fd:
            try:
                os.fsync(destination_fd)
            except OSError as exc:
                self._record_receiver_error(exc)
            try:
                os.close(destination_fd)
            except OSError as exc:
                self._record_receiver_error(exc)
            self._fd = None

    def _record_receiver_error(self, error: BaseException) -> None:
        errors = self._stats["receiver_errors"]
        if len(errors) < 20:
            errors.append({"type": type(error).__name__, "message": str(error)[:500]})

    def close(self) -> dict[str, Any]:
        if self._closed:
            return dict(self._stats)
        self._closed = True
        self._stop.set()
        self._drain_deadline = time.monotonic() + 0.5
        if self._socket is not None and self._socket_path is not None:
            try:
                self._socket.sendto(b"__codexscope_stop__", os.fspath(self._socket_path))
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            if self._thread.is_alive():
                # Force a blocked recvmsg to return, then give the sole writer
                # one final bounded opportunity to leave before closing its fd.
                if self._socket is not None:
                    try:
                        self._socket.close()
                    except OSError:
                        pass
                    self._socket = None
                self._thread.join(timeout=1.0)
            if self._thread.is_alive():
                self._record_receiver_error(
                    RuntimeError("collector thread did not stop; destination fd retained")
                )
        self._cleanup_transport()
        if self._fd is not None and (
            self._thread is None or not self._thread.is_alive()
        ):
            try:
                os.fsync(self._fd)
            except OSError as exc:
                self._record_receiver_error(exc)
            os.close(self._fd)
            self._fd = None
        return dict(self._stats)

    def _cleanup_transport(self) -> None:
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None
        if self._socket_path is not None:
            try:
                self._socket_path.unlink()
            except OSError:
                pass
            self._socket_path = None
        if self._directory is not None:
            # Remove only the exact empty directory we created. If an
            # instrumented process placed anything unexpected inside, retain it
            # rather than recursively deleting target-controlled paths.
            try:
                self._directory.rmdir()
            except OSError:
                pass
            self._directory = None


def read_function_rows(path: Path) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Read runtime JSONL defensively; one malformed record never loses a run."""

    stats = {
        "raw_lines": 0,
        "valid_records": 0,
        "invalid_records": 0,
        "unsupported_schema_records": 0,
        "oversized_records": 0,
    }
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows, stats
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        stats["invalid_records"] += 1
        return rows, stats
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            stats["invalid_records"] += 1
            return rows, stats
        with os.fdopen(fd, "rb", closefd=False) as fp:
            while True:
                line = fp.readline(_MAX_RAW_LINE + 1)
                if not line:
                    break
                stats["raw_lines"] += 1
                if len(line) > _MAX_RAW_LINE:
                    stats["oversized_records"] += 1
                    while line and not line.endswith(b"\n"):
                        line = fp.readline(_MAX_RAW_LINE + 1)
                    continue
                try:
                    row = json.loads(line.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    stats["invalid_records"] += 1
                    continue
                if not isinstance(row, dict):
                    stats["invalid_records"] += 1
                    continue
                if row.get("schema") != RAW_SCHEMA:
                    stats["unsupported_schema_records"] += 1
                    continue
                rows.append(row)
                stats["valid_records"] += 1
    finally:
        os.close(fd)
    return rows, stats


def _safe_repo_path(repo: Path, value: object) -> tuple[str | None, Path | None]:
    if not isinstance(value, str) or not value or "\x00" in value:
        return None, None
    raw = Path(value)
    if raw.is_absolute() or ".." in raw.parts:
        return None, None
    candidate = (repo / raw).resolve(strict=False)
    try:
        relative = candidate.relative_to(repo)
    except ValueError:
        return None, None
    return relative.as_posix(), candidate


def _safe_int(value: object, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError):
        return default


def _bounded_text(value: object, fallback: str) -> str:
    text = value if isinstance(value, str) else fallback
    return text[:_MAX_IDENTITY_TEXT]


def _elf_type(path: Path) -> int | None:
    try:
        with path.open("rb") as stream:
            header = stream.read(20)
    except OSError:
        return None
    if len(header) < 18 or header[:4] != b"\x7fELF":
        return None
    byteorder = "little" if header[5] == 1 else "big" if header[5] == 2 else None
    return int.from_bytes(header[16:18], byteorder) if byteorder else None


def _module_identity_matches(row: Mapping[str, Any], path: Path) -> bool:
    expected = (
        row.get("module_device"),
        row.get("module_inode"),
        row.get("module_size"),
        row.get("module_mtime_ns"),
    )
    if not any(value is not None for value in expected):
        return True
    try:
        current = path.stat()
    except OSError:
        return False
    actual = (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns)
    try:
        normalized = tuple(
            int(value) if value is not None else actual[index]
            for index, value in enumerate(expected)
        )
    except (TypeError, ValueError):
        return False
    return normalized == actual


def _address_token(row: Mapping[str, Any], elf_type: int | None) -> str | None:
    # ET_EXEC uses the absolute virtual address; ET_DYN (PIE/DSO) uses the
    # load-bias-relative module offset.
    value = row.get("function_address") if elf_type == 2 else row.get("module_offset")
    if type(value) is int:
        return hex(value) if 0 <= value <= (2**64 - 1) else None
    if (
        isinstance(value, str)
        and value.startswith("0x")
        and 2 < len(value) <= 18
    ):
        try:
            parsed = int(value, 16)
        except ValueError:
            return None
        return value if parsed <= (2**64 - 1) else None
    return None


def _parse_source_location(value: str, repo: Path) -> tuple[str | None, int | None]:
    value = value.split(" (discriminator ", 1)[0]
    if ":" not in value:
        return None, None
    raw_path, raw_line = value.rsplit(":", 1)
    try:
        line = int(raw_line)
    except ValueError:
        return None, None
    if line <= 0 or raw_path in {"??", "?"}:
        return None, None
    path = Path(raw_path)
    if not path.is_absolute():
        path = repo / path
    try:
        relative = path.resolve(strict=False).relative_to(repo).as_posix()
    except ValueError:
        return None, None
    return relative, line


_C_MODULE_IDENTITY_FIELDS = (
    "module_device",
    "module_inode",
    "module_size",
    "module_mtime_ns",
)


def _c_symbol_key(row: Mapping[str, Any], module: str) -> tuple[str, ...]:
    """Key symbol evidence by both address and the observed module artifact."""

    identity = tuple(
        f"{type(row.get(field)).__name__}:{row.get(field)!r}"
        for field in _C_MODULE_IDENTITY_FIELDS
    )
    return (module, str(row.get("function_address") or ""), *identity)


def _symbolize_c_rows(
    rows: Iterable[dict[str, Any]], repo: Path
) -> dict[tuple[str, ...], tuple[FunctionRef, str | None]]:
    grouped: dict[Path, list[tuple[dict[str, Any], str, tuple[str, ...]]]] = {}
    fallbacks: dict[tuple[str, ...], tuple[FunctionRef, str | None]] = {}
    for row in rows:
        module, binary = _safe_repo_path(repo, row.get("module"))
        address = str(row.get("function_address") or "")
        module_key = module or str(row.get("module") or "<unknown>")
        key = _c_symbol_key(row, module_key)
        symbol = _bounded_text(
            row.get("symbol"), f"sub_{address or 'unknown'}"
        )
        fallback = FunctionRef(
            path=module or "<unknown>",
            name=symbol,
            role="executed",
            confidence=0.7 if row.get("symbol") else 0.45,
            evidence="dladdr_symbol" if row.get("symbol") else "runtime_address",
        )
        if module is None or binary is None or not binary.is_file():
            fallbacks[key] = (fallback, "runtime_module_unavailable")
            continue
        if not _module_identity_matches(row, binary):
            fallbacks[key] = (fallback, "runtime_module_identity_mismatch")
            continue
        token = _address_token(row, _elf_type(binary))
        if token is None:
            fallbacks[key] = (fallback, "runtime_address_invalid")
            continue
        grouped.setdefault(binary, []).append((row, token, key))
        fallbacks[key] = (fallback, None)

    for binary, values in grouped.items():
        unique_tokens = list(dict.fromkeys(token for _row, token, _key in values))
        resolved: dict[str, tuple[str, str]] = {}
        for offset in range(0, len(unique_tokens), _ADDR2LINE_BATCH):
            batch = unique_tokens[offset : offset + _ADDR2LINE_BATCH]
            try:
                process = subprocess.run(
                    ["addr2line", "-f", "-C", "-e", os.fspath(binary), *batch],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
            except (OSError, subprocess.SubprocessError):
                break
            lines = process.stdout.splitlines()
            if process.returncode != 0 or len(lines) < 2 * len(batch):
                continue
            resolved.update(
                {
                    token: (
                        lines[index * 2].strip(),
                        lines[index * 2 + 1].strip(),
                    )
                    for index, token in enumerate(batch)
                }
            )
        for row, token, key in values:
            if token not in resolved:
                continue
            raw_name, raw_location = resolved[token]
            source, line = _parse_source_location(raw_location, repo)
            if raw_name in {"??", "?", ""} and source is None:
                continue
            name = raw_name if raw_name not in {"??", "?", ""} else fallbacks[key][0].name
            fallbacks[key] = (
                FunctionRef(
                    path=source or key[0],
                    name=name,
                    start_line=line,
                    end_line=line,
                    role="executed",
                    confidence=0.98 if source is not None else 0.82,
                    evidence="addr2line" if source is not None else "addr2line_symbol",
                ),
                None,
            )
    return fallbacks


def _runtime_key(row: Mapping[str, Any]) -> tuple[str, int, str] | None:
    instance = row.get("process_instance_id")
    thread_id = row.get("runtime_thread_id")
    activation = row.get("activation_id")
    if (
        not isinstance(instance, str)
        or not instance
        or not isinstance(activation, str)
        or not activation
        or len(instance) > _MAX_IDENTITY_TEXT
        or len(activation) > _MAX_IDENTITY_TEXT
        or isinstance(thread_id, bool)
    ):
        return None
    try:
        native_thread = int(thread_id)
    except (TypeError, ValueError):
        return None
    return (
        instance,
        native_thread,
        activation,
    )


def normalize_function_rows(
    rows: Iterable[dict[str, Any]], repo: Path
) -> list[CanonicalEvent]:
    """Pair runtime enter/exit observations into function activation events."""

    repo = repo.expanduser().resolve()
    records = [row for row in rows if row.get("kind") in _FUNCTION_RECORDS]
    c_symbols = _symbolize_c_rows(
        (row for row in records if row.get("language") == "c"),
        repo,
    )
    pending: dict[tuple[str, int, str], dict[str, Any]] = {}
    pairs: list[tuple[dict[str, Any] | None, dict[str, Any] | None, list[str]]] = []
    for row in records:
        key = _runtime_key(row)
        if key is None:
            continue
        if row.get("kind") == "frame_enter":
            previous = pending.pop(key, None)
            if previous is not None:
                pairs.append((previous, None, ["duplicate_function_enter", "function_did_not_exit"]))
            pending[key] = row
        else:
            start = pending.pop(key, None)
            if start is None:
                pairs.append((None, row, ["function_exit_without_enter"]))
            else:
                anomalies: list[str] = []
                if start.get("function_address") and row.get("function_address") and start.get("function_address") != row.get("function_address"):
                    anomalies.append("function_exit_address_mismatch")
                pairs.append((start, row, anomalies))
    for start in pending.values():
        pairs.append((start, None, ["function_did_not_exit"]))

    events: list[CanonicalEvent] = []
    events_by_key: dict[tuple[str, int, str], list[CanonicalEvent]] = {}
    ordered_pairs = sorted(
        pairs,
        key=lambda pair: _safe_int(
            (pair[0] or pair[1] or {}).get("collector_seq")
        ),
    )
    for start, end, anomalies in ordered_pairs:
        row = start or end
        assert row is not None
        key = _runtime_key(row)
        assert key is not None
        instance, native_thread, activation = key
        language = _bounded_text(row.get("language"), "unknown")
        backend = _bounded_text(row.get("backend"), "runtime")
        function_anomaly: str | None = None
        if language == "python":
            relative, _source = _safe_repo_path(repo, row.get("path"))
            name = _bounded_text(
                row.get("qualname") or row.get("function"), "<unknown>"
            )
            try:
                first_line = int(row.get("first_line")) if row.get("first_line") is not None else None
            except (TypeError, ValueError):
                first_line = None
            function = FunctionRef(
                path=relative or "<unknown>",
                name=name,
                start_line=first_line,
                end_line=first_line,
                role="executed",
                confidence=0.99 if relative else 0.5,
                evidence="python_code_object",
            )
            if relative is None:
                function_anomaly = "runtime_source_path_invalid"
        else:
            normalized_module, _binary = _safe_repo_path(repo, row.get("module"))
            module_key = normalized_module or str(row.get("module") or "<unknown>")
            module = _bounded_text(normalized_module or row.get("module"), "<unknown>")
            address = _bounded_text(row.get("function_address"), "")
            function, function_anomaly = c_symbols.get(
                _c_symbol_key(row, module_key),
                (
                    FunctionRef(
                        path=module,
                        name=_bounded_text(
                            row.get("symbol"), f"sub_{address or 'unknown'}"
                        ),
                        role="executed",
                        confidence=0.45,
                        evidence="runtime_address",
                    ),
                    "runtime_symbol_unresolved",
                ),
            )
        if function_anomaly:
            anomalies.append(function_anomaly)
        if row.get("declared_pid_mismatch"):
            anomalies.append("runtime_declared_pid_mismatch")
        start_mono = _safe_int((start or row).get("monotonic_ns"))
        end_mono = _safe_int((end or row).get("monotonic_ns"), start_mono)
        start_wall = _safe_int((start or row).get("wall_time_ns"))
        end_wall = _safe_int((end or row).get("wall_time_ns"), start_wall)
        if end_mono and start_mono and end_mono < start_mono:
            anomalies.append("runtime_monotonic_clock_reversed")
        completed = start is not None and end is not None
        raw_parent_call = row.get("caller_activation_id")
        if raw_parent_call is None:
            parent_call = None
        elif (
            isinstance(raw_parent_call, str)
            and 0 < len(raw_parent_call) <= _MAX_IDENTITY_TEXT
        ):
            parent_call = raw_parent_call
        else:
            parent_call = None
            anomalies.append("runtime_parent_call_invalid")
        identity_occurrence = len(events_by_key.get(key, []))
        if identity_occurrence:
            anomalies.append("runtime_activation_identity_duplicate")
        event_id = _stable_id("function-call", instance, native_thread, activation)
        if identity_occurrence:
            event_id = _stable_id(
                "function-call-duplicate",
                instance,
                native_thread,
                activation,
                identity_occurrence,
                _safe_int(row.get("collector_seq")),
            )
        verified_pid = row.get("peer_credentials_verified") is True
        process_id_value = (
            row.get("peer_pid") if verified_pid else row.get("pid")
        )
        process_id = _safe_int(process_id_value) or None
        parent_process_id = _safe_int(
            row.get("peer_ppid") if verified_pid else row.get("ppid")
        ) or None
        ancestors: list[int] = []
        verified_ancestors = row.get("peer_ancestor_pids") if verified_pid else []
        for value in verified_ancestors or []:
            candidate = _safe_int(value)
            if candidate <= 0:
                continue
            if candidate not in ancestors:
                ancestors.append(candidate)
        label = f"{function.path}::{function.name}"
        event = CanonicalEvent(
            event_id=event_id,
            seq=_safe_int(row.get("collector_seq")),
            source=EventSource.RUNTIME,
            source_event=backend,
            phase=EventPhase.COMPLETED if completed else EventPhase.INCOMPLETE,
            action_type="function_call",
            actor=f"runtime_process:{instance}",
            timestamp_start_ns=start_mono,
            timestamp_end_ns=end_mono,
            wall_time_start_ns=start_wall,
            wall_time_end_ns=end_wall,
            process_id=process_id,
            process_id_verified=verified_pid,
            parent_process_id=parent_process_id,
            ancestor_process_ids=ancestors,
            process_instance_id=instance,
            runtime_thread_id=native_thread,
            language=language,
            call_id=activation,
            parent_call_id=parent_call,
            tool=backend,
            operation=label,
            status=EventStatus.COMPLETED if completed else EventStatus.INCOMPLETE,
            duration_ms=(max(0, end_mono - start_mono) / 1_000_000) if completed else None,
            executed_functions=[function],
            payload={
                "backend": backend,
                "outcome": "unknown",
                "stack_relation": "nearest_tracked_ancestor",
                "code_kind": row.get("code_kind"),
                "module": row.get("module"),
                "function_address": row.get("function_address"),
                "module_offset": row.get("module_offset"),
                "enter_collector_seq": start.get("collector_seq") if start else None,
                "exit_collector_seq": end.get("collector_seq") if end else None,
            },
            anomalies=list(dict.fromkeys(anomalies)),
        )
        events.append(event)
        events_by_key.setdefault(key, []).append(event)

    for event in events:
        if event.parent_call_id is None or event.process_instance_id is None or event.runtime_thread_id is None:
            continue
        callers = events_by_key.get(
            (event.process_instance_id, event.runtime_thread_id, event.parent_call_id),
            [],
        )
        if not callers:
            event.anomalies.append("runtime_parent_call_not_observed")
        elif len(callers) > 1:
            event.anomalies.append("runtime_parent_call_ambiguous")
        else:
            event.caller_event_id = callers[0].event_id
    return events


def _time_compatible(function: CanonicalEvent, command: CanonicalEvent) -> bool:
    function_start = function.timestamp_start_ns or 0
    function_end = function.timestamp_end_ns or function_start
    command_start = command.timestamp_start_ns or 0
    command_end = command.timestamp_end_ns or command_start
    if (
        function_start <= 0
        or command_start <= 0
        or function_end < function_start
        or command_end < command_start
    ):
        return False
    tolerance = 250_000_000
    return function_end >= command_start - tolerance and function_start <= command_end + tolerance


def _strictly_contained(function: CanonicalEvent, command: CanonicalEvent) -> bool:
    function_start = function.timestamp_start_ns or 0
    function_end = function.timestamp_end_ns or function_start
    command_start = command.timestamp_start_ns or 0
    command_end = command.timestamp_end_ns or command_start
    return bool(
        function_start > 0
        and command_start > 0
        and function_end >= function_start
        and command_end >= command_start
        and command_start <= function_start <= function_end <= command_end
    )


def correlate_function_events(events: list[CanonicalEvent]) -> dict[str, int]:
    functions = [event for event in events if event.action_type == "function_call"]
    commands = [event for event in events if event.action_type == "command_execution"]
    matched = 0
    ambiguous = 0
    for function in functions:
        strict = [
            command
            for command in commands
            if _strictly_contained(function, command)
        ]
        candidates = strict
        confidence = 0.75
        evidence = "unique_strict_app_server_command_time_containment"
        if not candidates:
            candidates = [
                command
                for command in commands
                if _time_compatible(function, command)
            ]
            confidence = 0.6
            evidence = "unique_expanded_app_server_command_time_overlap"
        if len(candidates) > 1:
            function.anomalies.append("runtime_command_correlation_ambiguous")
            ambiguous += 1
            continue
        if not candidates:
            continue
        command = candidates[0]
        function.related_event_id = command.event_id
        function.correlation_kind = "runtime_to_command_temporal"
        function.correlation_evidence = evidence
        function.correlation_confidence = confidence
        function.thread_id = command.thread_id
        function.turn_id = command.turn_id
        matched += 1
    return {
        "function_call_events": len(functions),
        "matched_to_commands": matched,
        "unmatched_to_commands": len(functions) - matched,
        "ambiguous_command_matches": ambiguous,
    }


def copy_c_runtime_files(destination: Path) -> list[Path]:
    """Copy the versioned C instrumentation runtime without overwriting files."""

    import importlib.resources

    destination = destination.expanduser().resolve()
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    copied: list[Path] = []
    resources = importlib.resources.files("codexscope").joinpath("runtime")
    names = ("codexscope_function_trace.h", "codexscope_function_trace.c")
    contents = {name: resources.joinpath(name).read_bytes() for name in names}
    targets = [destination / name for name in names]
    for target in targets:
        if target.exists() or target.is_symlink():
            raise FileExistsError(target)
    try:
        for name, target in zip(names, targets, strict=True):
            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
            flags |= getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(target, flags, 0o600)
            copied.append(target)
            try:
                view = memoryview(contents[name])
                while view:
                    written = os.write(fd, view)
                    view = view[written:]
            finally:
                os.close(fd)
    except BaseException:
        for target in copied:
            try:
                target.unlink()
            except OSError:
                pass
        raise
    return copied
