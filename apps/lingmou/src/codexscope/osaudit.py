"""Bounded, payload-safe Linux process-tree auditing through ``strace``.

The collector traces a command that the caller starts as its own child.  It
does not need root and deliberately sends strace output through a pipe: a
reader thread keeps draining the pipe even after the persistent JSONL limit is
reached, so a busy tracee cannot deadlock on audit backpressure.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Mapping, Sequence

from .redaction import redact_text


SCHEMA_VERSION = "codexscope.os_audit.v1"
BACKEND_NAME = "linux_strace"
DEFAULT_MAX_EVENTS = 200_000
DEFAULT_MAX_BYTES = 64 * 1024 * 1024
_MAX_ARGUMENT_CHARS = 2_048
_MAX_PATH_CHARS = 4_096
_MAX_RAW_LINE_BYTES = 1024 * 1024
_MARKER_RESERVE = 768

_TRACE_SYSCALLS = (
    "%file,%network,%process,read,write,pread64,pwrite64,readv,writev,"
    "preadv,pwritev,preadv2,pwritev2,getdents,getdents64,close,dup,dup2,dup3,"
    "mprotect,ptrace,process_vm_writev"
)
_FOCUSED_TRACE_SYSCALLS = (
    "execve,execveat,open,openat,creat,chdir,fchdir,"
    "connect,sendto,sendmsg,unlink,unlinkat,rename,renameat,renameat2,"
    "chmod,fchmod,fchmodat,chown,lchown,fchown,fchownat,truncate,ftruncate"
)
_BEHAVIOR_TRACE_SYSCALLS = (
    "execve,execveat,clone,clone3,fork,vfork,kill,tgkill,tkill,"
    "open,openat,creat,chdir,fchdir,connect,bind,listen,accept,accept4,"
    "shutdown,sendto,sendmsg,unlink,unlinkat,rename,renameat,renameat2,"
    "link,linkat,symlink,symlinkat,mkdir,mkdirat,rmdir,chmod,fchmod,"
    "fchmodat,chown,lchown,fchown,fchownat,truncate,ftruncate,mount,"
    "umount,umount2,setxattr,lsetxattr,fsetxattr,removexattr,"
    "lremovexattr,fremovexattr,mprotect,ptrace,process_vm_writev"
)
_RAW_SYSCALLS = (
    "read,write,pread64,pwrite64,readv,writev,preadv,pwritev,preadv2,pwritev2,"
    "getdents,getdents64,readlink,readlinkat,getxattr,lgetxattr,fgetxattr,"
    "listxattr,llistxattr,flistxattr,setxattr,lsetxattr,fsetxattr,"
    "recvfrom,recvmsg,recvmmsg"
)
_BUFFER_CALLS = frozenset(
    {
        "read", "write", "pread64", "pwrite64", "readv", "writev",
        "preadv", "pwritev", "preadv2", "pwritev2", "getdents", "getdents64",
        "readlink", "readlinkat", "getxattr", "lgetxattr", "fgetxattr",
        "listxattr", "llistxattr", "flistxattr",
        "setxattr", "lsetxattr", "fsetxattr",
        "sendto", "recvfrom", "sendmsg", "recvmsg", "sendmmsg", "recvmmsg",
    }
)
_READ_CALLS = frozenset(
    {"read", "pread64", "readv", "preadv", "preadv2", "getdents", "getdents64"}
)
_WRITE_CALLS = frozenset({"write", "pwrite64", "writev", "pwritev", "pwritev2"})
_SEND_CALLS = frozenset({"sendto", "sendmsg", "sendmmsg"})
_RECV_CALLS = frozenset({"recvfrom", "recvmsg", "recvmmsg"})
_OPEN_CALLS = frozenset({"open", "openat", "openat2", "creat"})
_EXEC_CALLS = frozenset({"execve", "execveat"})
_SPAWN_CALLS = frozenset({"clone", "clone3", "fork", "vfork"})
_NETWORK_CALLS = frozenset(
    {
        "socket", "socketpair", "connect", "bind", "listen", "accept",
        "accept4", "getsockname", "getpeername", "getsockopt", "setsockopt",
        "shutdown", *_SEND_CALLS, *_RECV_CALLS,
    }
)
_METADATA_WRITE_CALLS = frozenset(
    {
        "unlink", "unlinkat", "rename", "renameat", "renameat2", "link",
        "linkat", "symlink", "symlinkat", "mkdir", "mkdirat", "rmdir",
        "chmod", "fchmod", "fchmodat", "chown", "lchown", "fchown",
        "fchownat", "truncate", "ftruncate", "utime", "utimes", "utimensat",
        "mknod", "mknodat", "mount", "umount", "umount2",
        "setxattr", "lsetxattr", "fsetxattr", "removexattr", "lremovexattr",
        "fremovexattr",
    }
)
_METADATA_READ_CALLS = frozenset(
    {
        "access", "faccessat", "faccessat2", "stat", "lstat", "fstat",
        "newfstatat", "statx", "readlink", "readlinkat", "getxattr",
        "lgetxattr", "fgetxattr", "listxattr", "llistxattr", "flistxattr",
    }
)
_PROCESS_CALLS = frozenset(
    {
        *_EXEC_CALLS, *_SPAWN_CALLS, "wait4", "waitid", "waitpid", "kill",
        "tgkill", "tkill", "exit", "exit_group",
    }
)
_FD_PATH_FIRST_CALLS = frozenset(
    {
        "fstat", "fgetxattr", "flistxattr", "fsetxattr", "fremovexattr",
        "fchmod", "fchown", "ftruncate",
    }
)
_AT_DIRFD_PATH_FIRST_CALLS = frozenset(
    {
        "openat", "openat2", "execveat", "faccessat", "faccessat2",
        "newfstatat", "unlinkat", "mkdirat", "mknodat", "renameat",
        "renameat2", "linkat", "fchmodat", "fchownat", "utimensat",
    }
)
_BEHAVIOR_EXEC_NOISE_ERRNOS = frozenset({"ENOENT", "ENOTDIR"})
_BEHAVIOR_SENSITIVE_READ_MARKERS = (
    "/.ssh/",
    "/.aws/",
    "/.config/gcloud/",
    "/.kube/",
    "/.docker/config.json",
    "/.git-credentials",
    "/.npmrc",
    "/.pypirc",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/environ",
)
_BEHAVIOR_NETWORK_WINDOW_NS = 30_000_000_000
_BEHAVIOR_READ_WINDOW_NS = 5_000_000_000
_BEHAVIOR_MUTATION_WINDOW_NS = 1_000_000_000

_LINE_RE = re.compile(
    r"^\s*(?:\[pid\s+)?(?P<tid>\d+)(?:\])?\s+"
    r"(?P<timestamp>\d+(?:\.\d+)?)\s+(?P<body>.*)$"
)
_CALL_RE = re.compile(
    r"^(?P<syscall>[A-Za-z_][A-Za-z0-9_]*)\((?P<arguments>.*)\)\s+"
    r"=\s+(?P<result>.*?)(?:\s+<(?P<duration>\d+(?:\.\d+)?)>)?$"
)
_UNFINISHED_RE = re.compile(r"^(?P<syscall>\w+)\(.*<unfinished \.\.\.>$")
_RESUMED_RE = re.compile(r"^<\.\.\. (?P<syscall>\w+) resumed>(?P<rest>.*)$")
_QUOTED_RE = re.compile(r'"((?:\\.|[^"\\])*)"')
_FD_RE = re.compile(r"^\s*(?P<fd>-?(?:0x[0-9a-fA-F]+|\d+))(?:<(?P<label>.*)>)?")
_ERRNO_RE = re.compile(r"^-1\s+([A-Z][A-Z0-9_]+)\b")


class OsAuditError(RuntimeError):
    """Base class for OS-audit collector errors."""


class StraceUnavailable(OsAuditError):
    """Raised when the requested strace executable is not usable."""


@dataclass(frozen=True, slots=True)
class OsAuditStats:
    backend: str
    status: str
    available: bool
    strace_version: str | None
    lines: int
    observed_events: int
    events: int
    filtered_events: int
    filtered_noise: int
    filtered_repeats: int
    dropped: int
    parse_errors: int
    unfinished_pending: int
    reader_error: str | None
    limit_reached: bool
    max_events: int
    max_bytes: int
    output_bytes: int
    known_loss: bool


def _trace_support_reason(executable: str) -> str | None:
    """Return why an exact-filter ptrace self-test failed, if it failed."""

    if Path("/bin/true").is_file():
        probe_command = ["/bin/true"]
    elif Path("/usr/bin/true").is_file():
        probe_command = ["/usr/bin/true"]
    else:
        probe_command = [sys.executable, "-c", "pass"]
    try:
        result = subprocess.run(
            [
                executable,
                "-f",
                "-qq",
                "-e",
                f"trace={_TRACE_SYSCALLS}",
                "-e",
                f"raw={_RAW_SYSCALLS}",
                "-o",
                os.devnull,
                "--",
                *probe_command,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return f"strace self-test could not run: {redact_text(str(exc))[:256]}"
    if result.returncode == 0:
        return None
    diagnostic = redact_text(result.stderr or "no diagnostic output")[:512]
    return f"strace self-test exited with {result.returncode}: {diagnostic}"


def probe_strace(strace_bin: str = "strace") -> dict[str, object]:
    """Return a non-raising Linux/strace availability probe."""

    if not sys.platform.startswith("linux"):
        return {"available": False, "version": None, "reason": "strace requires Linux"}
    executable = shutil.which(strace_bin)
    if executable is None:
        return {
            "available": False,
            "version": None,
            "reason": f"strace executable not found: {strace_bin}",
        }
    try:
        result = subprocess.run(
            [executable, "--version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"available": False, "version": None, "reason": str(exc)}
    first = (result.stdout or "").splitlines()
    version = redact_text(first[0])[:256] if first else None
    if result.returncode != 0:
        return {
            "available": False,
            "version": version,
            "reason": f"strace --version exited with {result.returncode}",
        }
    trace_reason = _trace_support_reason(executable)
    if trace_reason is not None:
        return {
            "available": False,
            "version": version,
            "reason": trace_reason,
            "path": executable,
        }
    return {"available": True, "version": version, "reason": None, "path": executable}


def strace_available(strace_bin: str = "strace") -> bool:
    return bool(probe_strace(strace_bin)["available"])


def strace_unavailable_reason(strace_bin: str = "strace") -> str | None:
    probe = probe_strace(strace_bin)
    return None if probe["available"] else str(probe.get("reason") or "unavailable")


def _parse_int(value: str) -> int | None:
    try:
        return int(value, 0)
    except (TypeError, ValueError):
        return None


def _decode_c_string(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        token = match.group(0)
        if token.startswith("\\x") and len(token) == 4:
            return chr(int(token[2:], 16))
        if len(token) > 1 and token[1:].isdigit():
            return chr(int(token[1:], 8) & 0xFF)
        return {"\\n": "\n", "\\r": "\r", "\\t": "\t", '\\"': '"', "\\\\": "\\"}.get(token, token[1:])

    return re.sub(r"\\x[0-9a-fA-F]{2}|\\[0-7]{1,3}|\\.", replace, value)


class StraceAuditCollector:
    """Collect a child command's process-tree syscalls into bounded JSONL."""

    def __init__(
        self,
        repo: str | Path,
        output_path: str | Path,
        max_events: int = DEFAULT_MAX_EVENTS,
        max_bytes: int = DEFAULT_MAX_BYTES,
        strace_bin: str = "strace",
        trace_profile: str = "behavior",
    ) -> None:
        if max_events < 1:
            raise ValueError("max_events must be at least 1")
        if max_bytes < _MARKER_RESERVE:
            raise ValueError(f"max_bytes must be at least {_MARKER_RESERVE}")
        if trace_profile not in {"behavior", "focused", "full"}:
            raise ValueError("trace_profile must be 'behavior', 'focused', or 'full'")
        root = Path(repo).expanduser().resolve()
        if not root.is_dir():
            raise ValueError(f"repository is not a directory: {root}")
        self.repo = root
        self.output_path = Path(os.path.abspath(os.fspath(Path(output_path).expanduser())))
        self.max_events = max_events
        self.max_bytes = max_bytes
        self.strace_bin = strace_bin
        self.trace_profile = trace_profile

        self._lock = threading.RLock()
        self._state = "new"
        self._read_fd = -1
        self._write_fd = -1
        self._output_fd = -1
        self._thread: threading.Thread | None = None
        self._version: str | None = None
        # Convert strace's epoch timestamp into the same monotonic clock used
        # by app-server and inotify events.  Using parser time would shift busy
        # traces later by however long the reader thread was backlogged.
        self._monotonic_wall_offset_ns = time.monotonic_ns() - time.time_ns()
        self._lines = 0
        self._observed_events = 0
        self._events = 0
        self._filtered_events = 0
        self._filtered_noise = 0
        self._filtered_repeats = 0
        self._dropped = 0
        self._parse_errors = 0
        self._output_bytes = 0
        self._seq = 0
        self._limit_reached = False
        self._reader_error: str | None = None
        self._storage_failed = False
        self._unfinished: dict[tuple[int, str], tuple[str, str]] = {}
        self._task_info: dict[int, tuple[int, int | None, str | None]] = {}
        self._cwd: dict[int, str] = {}
        self._fd_paths: dict[tuple[int, int], str] = {}
        self._fd_endpoints: dict[tuple[int, int], object] = {}
        self._behavior_recent: dict[tuple[object, ...], int] = {}

    @property
    def pass_fds(self) -> tuple[int, ...]:
        with self._lock:
            return (self._write_fd,) if self._write_fd >= 0 else ()

    @property
    def running(self) -> bool:
        with self._lock:
            return self._state == "running" and bool(self._thread and self._thread.is_alive())

    @property
    def reader_alive(self) -> bool:
        with self._lock:
            return bool(self._thread and self._thread.is_alive())

    @property
    def stats(self) -> OsAuditStats:
        with self._lock:
            closed = self._state == "closed"
            known_loss = bool(
                self._dropped or self._parse_errors or self._reader_error
                or self._limit_reached or (closed and self._unfinished)
            )
            if self._reader_error:
                status = "failed"
            elif known_loss:
                status = "degraded"
            elif self._state == "running":
                status = "running"
            elif closed:
                status = "complete"
            else:
                status = self._state
            return OsAuditStats(
                backend=BACKEND_NAME,
                status=status,
                available=self._version is not None,
                strace_version=self._version,
                lines=self._lines,
                observed_events=self._observed_events,
                events=self._events,
                filtered_events=self._filtered_events,
                filtered_noise=self._filtered_noise,
                filtered_repeats=self._filtered_repeats,
                dropped=self._dropped,
                parse_errors=self._parse_errors,
                unfinished_pending=len(self._unfinished),
                reader_error=self._reader_error,
                limit_reached=self._limit_reached,
                max_events=self.max_events,
                max_bytes=self.max_bytes,
                output_bytes=self._output_bytes,
                known_loss=known_loss,
            )

    def stats_dict(self) -> dict[str, object]:
        return asdict(self.stats)

    def start(self) -> "StraceAuditCollector":
        with self._lock:
            if self._state != "new":
                raise RuntimeError("StraceAuditCollector instances can only be started once")
            self._state = "starting"
        probe = probe_strace(self.strace_bin)
        if not probe["available"]:
            with self._lock:
                self._state = "closed"
            raise StraceUnavailable(str(probe.get("reason") or "strace unavailable"))
        self._version = str(probe.get("version") or "unknown")
        self.strace_bin = str(probe.get("path") or self.strace_bin)
        try:
            self.output_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            self._output_fd = os.open(self.output_path, flags, 0o600)
            opened = os.fstat(self._output_fd)
            if not stat.S_ISREG(opened.st_mode):
                raise OsAuditError(f"OS audit output must be a regular file: {self.output_path}")
            os.fchmod(self._output_fd, 0o600)
            pipe_flags = getattr(os, "O_CLOEXEC", 0)
            self._read_fd, self._write_fd = os.pipe2(pipe_flags)
            self._thread = threading.Thread(target=self._reader_main, name="codexscope-strace-reader", daemon=True)
            with self._lock:
                self._state = "running"
            self._thread.start()
            return self
        except BaseException:
            self._close_descriptors()
            with self._lock:
                self._state = "closed"
            raise

    def wrap_command(self, argv: Sequence[str]) -> list[str]:
        if not argv:
            raise ValueError("argv cannot be empty")
        with self._lock:
            if self._state != "running" or self._write_fd < 0:
                raise RuntimeError("collector must be started before wrap_command")
            output = f"/proc/self/fd/{self._write_fd}"
        trace_syscalls = {
            "behavior": _BEHAVIOR_TRACE_SYSCALLS,
            "focused": _FOCUSED_TRACE_SYSCALLS,
            "full": _TRACE_SYSCALLS,
        }[self.trace_profile]
        return [
            self.strace_bin, "-f", "-qq", "-ttt", "-T", "-yy", "-s", "4096",
            "-e", f"trace={trace_syscalls}", "-e", f"raw={_RAW_SYSCALLS}",
            "-o", output, "--", *[os.fspath(value) for value in argv],
        ]

    def after_spawn(self) -> None:
        with self._lock:
            fd, self._write_fd = self._write_fd, -1
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass

    def close(self) -> dict[str, object]:
        self.after_spawn()
        with self._lock:
            if self._state == "closed":
                return self.stats_dict()
            thread = self._thread
        if thread is not None:
            thread.join(10.0)
            if thread.is_alive():
                with self._lock:
                    self._reader_error = self._reader_error or "strace reader did not reach EOF before timeout"
                    read_fd, self._read_fd = self._read_fd, -1
                if read_fd >= 0:
                    try:
                        os.close(read_fd)
                    except OSError:
                        pass
                thread.join(1.0)
        with self._lock:
            out_fd, self._output_fd = self._output_fd, -1
            self._state = "closed"
        if out_fd >= 0:
            try:
                os.fsync(out_fd)
            except OSError:
                pass
            os.close(out_fd)
        return self.stats_dict()

    def _close_descriptors(self) -> None:
        for name in ("_read_fd", "_write_fd", "_output_fd"):
            fd = getattr(self, name)
            setattr(self, name, -1)
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass

    def _reader_main(self) -> None:
        buffer = bytearray()
        discarding = False
        try:
            while True:
                try:
                    chunk = os.read(self._read_fd, 64 * 1024)
                except OSError as exc:
                    if self._read_fd < 0:
                        break
                    raise exc
                if not chunk:
                    break
                buffer.extend(chunk)
                while True:
                    newline = buffer.find(b"\n")
                    if newline < 0:
                        if len(buffer) > _MAX_RAW_LINE_BYTES:
                            buffer.clear()
                            discarding = True
                        break
                    raw = bytes(buffer[:newline])
                    del buffer[: newline + 1]
                    with self._lock:
                        self._lines += 1
                    if discarding:
                        discarding = False
                        with self._lock:
                            self._parse_errors += 1
                        continue
                    self._handle_line(raw.decode("utf-8", errors="backslashreplace"))
            if buffer and not discarding:
                with self._lock:
                    self._lines += 1
                self._handle_line(buffer.decode("utf-8", errors="backslashreplace"))
        except BaseException as exc:
            with self._lock:
                self._reader_error = redact_text(f"{type(exc).__name__}: {exc}")[:512]
        finally:
            with self._lock:
                fd, self._read_fd = self._read_fd, -1
                if self._state == "running":
                    self._state = "reader_stopped"
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass

    def _handle_line(self, line: str) -> None:
        match = _LINE_RE.match(line)
        if not match:
            stripped = line.strip()
            if stripped.startswith("strace:"):
                with self._lock:
                    self._parse_errors += 1
                    self._reader_error = self._reader_error or redact_text(stripped)[:512]
            elif stripped and not line.lstrip().startswith(("---", "+++")):
                with self._lock:
                    self._parse_errors += 1
            return
        tid = int(match.group("tid"))
        timestamp = match.group("timestamp")
        body = match.group("body")
        if body.startswith(("---", "+++")):
            return
        unfinished = _UNFINISHED_RE.match(body)
        if unfinished:
            syscall = unfinished.group("syscall")
            prefix = body[: body.rfind("<unfinished ...>")]
            with self._lock:
                self._unfinished[(tid, syscall)] = (timestamp, prefix)
            return
        resumed = _RESUMED_RE.match(body)
        if resumed:
            syscall = resumed.group("syscall")
            with self._lock:
                pending = self._unfinished.pop((tid, syscall), None)
            if pending is None:
                with self._lock:
                    self._parse_errors += 1
                return
            timestamp, prefix = pending
            body = prefix + resumed.group("rest")
        call = _CALL_RE.match(body)
        if not call:
            with self._lock:
                self._parse_errors += 1
            return
        row = self._make_event(
            tid,
            timestamp,
            call.group("syscall"),
            call.group("arguments"),
            call.group("result"),
            call.group("duration"),
        )
        with self._lock:
            self._observed_events += 1
        if self.trace_profile == "behavior":
            keep, reason = self._behavior_decision(row)
            if not keep:
                with self._lock:
                    self._filtered_events += 1
                    if reason == "repeated_behavior":
                        self._filtered_repeats += 1
                    else:
                        self._filtered_noise += 1
                return
            row["behavior_reason"] = reason
        self._persist(row)

    def _task(self, tid: int) -> tuple[int, int | None, str | None]:
        cached = self._task_info.get(tid)
        if cached is not None:
            return cached
        pid, ppid, comm = tid, None, None
        try:
            values: dict[str, str] = {}
            with open(f"/proc/{tid}/status", encoding="utf-8", errors="replace") as fp:
                for line in fp:
                    if ":" in line:
                        key, value = line.split(":", 1)
                        values[key] = value.strip()
            pid = int(values.get("Tgid", tid))
            ppid = int(values["PPid"]) if values.get("PPid", "").isdigit() else None
            comm = values.get("Name")
        except OSError:
            pass
        result = (pid, ppid, comm)
        self._task_info[tid] = result
        self._cwd.setdefault(pid, os.fspath(self.repo))
        return result

    def _make_event(
        self, tid: int, timestamp: str, syscall: str, arguments: str,
        raw_result: str, duration: str | None,
    ) -> dict[str, object]:
        pid, ppid, comm = self._task(tid)
        result, error_name, success = self._parse_result(raw_result)
        fd, fd_label = self._parse_fd(arguments)
        path_value = self._extract_path(syscall, arguments, raw_result, pid, fd, fd_label)
        path, path_scope = self._scope_path(path_value, pid)
        endpoint = self._extract_endpoint(arguments)
        if endpoint is None and fd is not None:
            endpoint = self._fd_endpoints.get((pid, fd))
        category, access = self._classify(syscall, arguments, fd, pid)
        byte_count = result if syscall in _BUFFER_CALLS and isinstance(result, int) and result >= 0 else None
        safe_arguments = self._safe_arguments(syscall, arguments, fd)
        try:
            wall_time_ns = int(Decimal(timestamp) * 1_000_000_000)
        except (InvalidOperation, ValueError):
            wall_time_ns = time.time_ns()
        monotonic_ns = max(1, wall_time_ns + self._monotonic_wall_offset_ns)
        try:
            duration_ns = int(Decimal(duration) * 1_000_000_000) if duration else None
        except (InvalidOperation, ValueError):
            duration_ns = None
        row: dict[str, object] = {
            "schema_version": SCHEMA_VERSION,
            "seq": 0,
            "backend": BACKEND_NAME,
            "wall_time_ns": wall_time_ns,
            "monotonic_ns": monotonic_ns,
            "pid": pid,
            "tid": tid,
            "ppid": ppid,
            "comm": comm,
            "syscall": syscall,
            "category": category,
            "access": access,
            "path": path,
            "path_scope": path_scope,
            "fd": fd,
            "bytes": byte_count,
            "endpoint": endpoint,
            "result": result,
            "errno": error_name,
            "success": success,
            "duration_ns": duration_ns,
            "arguments": safe_arguments,
            "synthetic": False,
        }
        self._update_state(row, arguments, raw_result, path_value)
        return row

    @staticmethod
    def _is_sensitive_behavior_path(path: object) -> bool:
        value = str(path or "").casefold()
        if not value:
            return False
        if value.endswith("/.env") or "/.env." in value:
            return True
        return any(marker in value for marker in _BEHAVIOR_SENSITIVE_READ_MARKERS)

    @staticmethod
    def _behavior_target(row: Mapping[str, object]) -> str:
        endpoint = row.get("endpoint")
        if isinstance(endpoint, Mapping):
            return json.dumps(endpoint, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        return str(row.get("path") or "")

    def _behavior_repeat(
        self,
        row: Mapping[str, object],
        *,
        window_ns: int,
    ) -> bool:
        timestamp = int(row.get("monotonic_ns") or row.get("wall_time_ns") or 0)
        key = (
            row.get("pid"),
            row.get("category"),
            row.get("access"),
            self._behavior_target(row),
            row.get("success"),
            row.get("errno"),
        )
        previous = self._behavior_recent.get(key)
        self._behavior_recent[key] = timestamp
        if len(self._behavior_recent) > 8_192:
            cutoff = timestamp - _BEHAVIOR_NETWORK_WINDOW_NS
            self._behavior_recent = {
                candidate: seen
                for candidate, seen in self._behavior_recent.items()
                if seen >= cutoff
            }
        return previous is not None and 0 <= timestamp - previous < window_ns

    def _behavior_decision(self, row: Mapping[str, object]) -> tuple[bool, str]:
        """Return whether one syscall explains observable Agent behavior.

        The decision is intentionally semantic rather than a claim that an
        omitted syscall did not happen.  State tracking has already consumed
        the row before this method runs, so dropping a noisy open/chdir does
        not break later path or descriptor attribution.
        """

        if row.get("synthetic") is True:
            return True, "collector_diagnostic"
        category = str(row.get("category") or "")
        access = str(row.get("access") or "")
        syscall = str(row.get("syscall") or "")
        success = row.get("success")
        errno = str(row.get("errno") or "")
        path_scope = str(row.get("path_scope") or "")

        if category == "process":
            if access == "execute" and success is False and errno in _BEHAVIOR_EXEC_NOISE_ERRNOS:
                return False, "path_search_probe"
            if access in {"execute", "spawn"} or syscall in {"kill", "tgkill", "tkill"}:
                return True, "process_lifecycle"
            return False, "process_bookkeeping"

        if category == "network":
            if row.get("endpoint") is None:
                return False, "network_without_target"
            if self._behavior_repeat(row, window_ns=_BEHAVIOR_NETWORK_WINDOW_NS):
                return False, "repeated_behavior"
            return True, "network_endpoint_activity"

        if category == "file" and access in {"write", "read_write", "metadata_write"}:
            if self._behavior_repeat(row, window_ns=_BEHAVIOR_MUTATION_WINDOW_NS):
                return False, "repeated_behavior"
            return True, "file_mutation"

        if category == "file" and access in {"read", "metadata_read"}:
            # User-defined directory boundaries may live outside the workspace.
            # Keep actual access denials even when routine external reads are filtered.
            if success is False and errno in {"EACCES", "EPERM", "EROFS"}:
                return True, "file_access_denied"
            if path_scope != "workspace" and not self._is_sensitive_behavior_path(row.get("path")):
                return False, "routine_external_read"
            if self._behavior_repeat(row, window_ns=_BEHAVIOR_READ_WINDOW_NS):
                return False, "repeated_behavior"
            return True, "workspace_or_sensitive_read"

        if syscall in {"chdir", "fchdir"} and path_scope == "workspace":
            if self._behavior_repeat(row, window_ns=_BEHAVIOR_READ_WINDOW_NS):
                return False, "repeated_behavior"
            return True, "workspace_directory_change"
        return False, "non_behavioral_bookkeeping"

    @staticmethod
    def _parse_result(raw: str) -> tuple[object, str | None, bool | None]:
        error_match = _ERRNO_RE.match(raw)
        if error_match:
            return -1, error_match.group(1), False
        token = raw.strip().split(None, 1)[0] if raw.strip() else "?"
        token = token.split("<", 1)[0]
        parsed = _parse_int(token)
        if parsed is not None:
            return parsed, None, parsed >= 0
        errno_match = re.search(r"\b(E[A-Z0-9_]+)\b", raw)
        return None, errno_match.group(1) if errno_match else None, None

    @staticmethod
    def _parse_fd(arguments: str) -> tuple[int | None, str | None]:
        match = _FD_RE.match(arguments)
        if not match:
            return None, None
        return _parse_int(match.group("fd")), match.group("label")

    def _extract_path(
        self, syscall: str, arguments: str, raw_result: str, pid: int,
        fd: int | None, fd_label: str | None,
    ) -> str | None:
        if syscall in _OPEN_CALLS and not raw_result.lstrip().startswith("-1"):
            annotation = re.match(r"\s*(?:0x[0-9a-fA-F]+|\d+)<(.+)>\s*$", raw_result)
            if annotation:
                return self._clean_fd_label(annotation.group(1))
        quoted = [_decode_c_string(value) for value in _QUOTED_RE.findall(arguments)]
        if syscall in _FD_PATH_FIRST_CALLS and fd is not None:
            mapped = self._fd_paths.get((pid, fd))
            if mapped:
                return mapped
        if syscall in _AT_DIRFD_PATH_FIRST_CALLS and quoted:
            candidate = quoted[0]
            if os.path.isabs(candidate):
                return candidate
            directory = self._fd_paths.get((pid, fd)) if fd is not None else None
            directory = directory or self._clean_fd_label(fd_label)
            if directory and os.path.isabs(directory):
                # strace renders *at(2) calls as
                # ``10</absolute/dir>, "relative-name", ...``.  Resolving the
                # relative name against the traced process cwd misattributes
                # external Codex cache maintenance to the observed workspace.
                return os.path.join(directory, candidate)
        if syscall in _EXEC_CALLS or syscall in _OPEN_CALLS or syscall in _METADATA_READ_CALLS or syscall in _METADATA_WRITE_CALLS or syscall in {"chdir", "chroot"}:
            if quoted:
                return quoted[0]
        if fd is not None:
            mapped = self._fd_paths.get((pid, fd))
            if mapped:
                return mapped
        return self._clean_fd_label(fd_label) if fd_label else None

    @staticmethod
    def _clean_fd_label(label: str | None) -> str | None:
        if not label:
            return None
        if label.startswith(("socket:[", "pipe:[", "anon_inode:")):
            return label
        return re.sub(r"<(?:char|block) [^>]+>$", "", label)

    def _scope_path(self, value: str | None, pid: int) -> tuple[str | None, str | None]:
        if not value:
            return None, None
        if value.startswith(("socket:[", "pipe:[", "anon_inode:")):
            # Kernel descriptor labels are not filesystem paths.  Keeping them
            # out of ``path`` prevents the provenance layer from inventing a
            # file node for a socket or pipe.
            return None, "kernel"
        candidate = value
        if not os.path.isabs(candidate):
            candidate = os.path.join(self._cwd.get(pid, os.fspath(self.repo)), candidate)
        candidate = os.path.normpath(candidate)
        try:
            common = os.path.commonpath((candidate, os.fspath(self.repo)))
        except ValueError:
            common = ""
        if common == os.fspath(self.repo):
            relative = os.path.relpath(candidate, self.repo)
            return redact_text(Path(relative).as_posix())[:_MAX_PATH_CHARS], "workspace"
        return redact_text(candidate)[:_MAX_PATH_CHARS], "external"

    @staticmethod
    def _extract_endpoint(arguments: str) -> dict[str, object] | None:
        family_match = re.search(r"sa_family=(AF_[A-Z0-9_]+)", arguments)
        if not family_match:
            return None
        endpoint: dict[str, object] = {"family": family_match.group(1)}
        address = re.search(
            r'(?:inet_addr\(|inet_pton\([^,]+,\s*)"([^"]+)"', arguments
        )
        if address:
            endpoint["address"] = address.group(1)
        port = re.search(r"sin6?_port=htons\((\d+)\)", arguments)
        if port:
            endpoint["port"] = int(port.group(1))
        unix_path = re.search(r'sun_path="((?:\\.|[^"\\])*)"', arguments)
        if unix_path:
            endpoint["path"] = redact_text(_decode_c_string(unix_path.group(1)))[:512]
        return endpoint

    def _classify(self, syscall: str, arguments: str, fd: int | None, pid: int) -> tuple[str, str]:
        if syscall in _EXEC_CALLS:
            return "process", "execute"
        if syscall in _SPAWN_CALLS:
            return "process", "spawn"
        if syscall.startswith("wait"):
            return "process", "wait"
        if syscall in {"exit", "exit_group"}:
            return "process", "exit"
        if syscall in _NETWORK_CALLS:
            access = "other"
            if syscall == "connect": access = "connect"
            elif syscall == "bind": access = "bind"
            elif syscall == "listen": access = "listen"
            elif syscall in {"accept", "accept4"}: access = "accept"
            elif syscall in _SEND_CALLS: access = "send"
            elif syscall in _RECV_CALLS: access = "receive"
            elif syscall in {"socket", "socketpair"}: access = "create"
            return "network", access
        label = self._fd_paths.get((pid, fd)) if fd is not None else None
        if syscall in _READ_CALLS:
            return ("ipc" if label and label.startswith("pipe:[") else "file", "read")
        if syscall in _WRITE_CALLS:
            return ("ipc" if label and label.startswith("pipe:[") else "file", "write")
        if syscall in _OPEN_CALLS:
            if syscall == "creat" or "O_WRONLY" in arguments:
                access = "write"
            elif "O_RDWR" in arguments:
                access = "read_write"
            else:
                access = "read"
            return "file", access
        if syscall in _METADATA_WRITE_CALLS:
            return "file", "metadata_write"
        if syscall in _METADATA_READ_CALLS:
            return "file", "metadata_read"
        if syscall == "close":
            return "fd", "close"
        if syscall.startswith("dup"):
            return "fd", "duplicate"
        if syscall in _PROCESS_CALLS:
            return "process", "other"
        return "file", "other"

    @staticmethod
    def _safe_arguments(syscall: str, arguments: str, fd: int | None) -> str:
        if syscall in _BUFFER_CALLS:
            return f"fd={fd if fd is not None else 'unknown'}; payload_omitted=true"
        quoted = [_decode_c_string(value) for value in _QUOTED_RE.findall(arguments)]
        if syscall in _EXEC_CALLS:
            executable = redact_text(quoted[0])[:512] if quoted else "unknown"
            return f"executable={executable}; argv_omitted=true"
        value = redact_text(arguments)
        if len(value) > _MAX_ARGUMENT_CHARS:
            value = value[:_MAX_ARGUMENT_CHARS] + "[TRUNCATED]"
        return value

    def _update_state(self, row: Mapping[str, object], arguments: str, raw_result: str, path_value: str | None) -> None:
        if row["success"] is not True:
            if row["syscall"] == "connect" and row["fd"] is not None and row["endpoint"] is not None:
                self._fd_endpoints[(int(row["pid"]), int(row["fd"]))] = row["endpoint"]
            return
        pid, syscall = int(row["pid"]), str(row["syscall"])
        result = row["result"]
        if syscall in _OPEN_CALLS and isinstance(result, int) and path_value:
            absolute = path_value if os.path.isabs(path_value) else os.path.join(self._cwd.get(pid, os.fspath(self.repo)), path_value)
            self._fd_paths[(pid, result)] = os.path.normpath(absolute)
        elif syscall == "socket" and isinstance(result, int):
            self._fd_paths[(pid, result)] = f"socket:[fd={result}]"
        elif syscall in {"accept", "accept4"} and isinstance(result, int):
            self._fd_paths[(pid, result)] = f"socket:[fd={result}]"
            if row["endpoint"] is not None:
                self._fd_endpoints[(pid, result)] = row["endpoint"]
        elif syscall == "connect" and row["fd"] is not None and row["endpoint"] is not None:
            self._fd_endpoints[(pid, int(row["fd"]))] = row["endpoint"]
        elif syscall.startswith("dup") and row["fd"] is not None and isinstance(result, int):
            old = int(row["fd"])
            if (pid, old) in self._fd_paths:
                self._fd_paths[(pid, result)] = self._fd_paths[(pid, old)]
            if (pid, old) in self._fd_endpoints:
                self._fd_endpoints[(pid, result)] = self._fd_endpoints[(pid, old)]
        elif syscall == "close" and row["fd"] is not None:
            self._fd_paths.pop((pid, int(row["fd"])), None)
            self._fd_endpoints.pop((pid, int(row["fd"])), None)
        elif syscall == "chdir" and path_value:
            target = path_value if os.path.isabs(path_value) else os.path.join(self._cwd.get(pid, os.fspath(self.repo)), path_value)
            self._cwd[pid] = os.path.normpath(target)
        elif syscall in _EXEC_CALLS:
            # ``comm`` changes after a successful exec.  Keep the exec event's
            # pre-exec identity, then refresh metadata for the next syscall.
            self._task_info.pop(int(row["tid"]), None)
        elif syscall in _SPAWN_CALLS and isinstance(result, int) and result > 0:
            child = result
            is_thread = "CLONE_THREAD" in arguments
            child_pid = pid if is_thread else child
            child_ppid = row.get("ppid") if is_thread else pid
            self._task_info[child] = (
                child_pid,
                int(child_ppid) if isinstance(child_ppid, int) else None,
                row.get("comm") if isinstance(row.get("comm"), str) else None,
            )
            self._cwd[child_pid] = self._cwd.get(pid, os.fspath(self.repo))
            for (owner, fd), value in tuple(self._fd_paths.items()):
                if owner == pid:
                    self._fd_paths[(child_pid, fd)] = value
            for (owner, fd), value in tuple(self._fd_endpoints.items()):
                if owner == pid:
                    self._fd_endpoints[(child_pid, fd)] = value

    def _persist(self, row: Mapping[str, object]) -> None:
        with self._lock:
            persisted = dict(row)
            persisted["seq"] = self._seq + 1
            encoded = (
                json.dumps(persisted, ensure_ascii=True, separators=(",", ":")) + "\n"
            ).encode("utf-8")
            can_write = (
                not self._storage_failed
                and not self._limit_reached
                and self._events < self.max_events
                and self._output_bytes + len(encoded) + _MARKER_RESERVE <= self.max_bytes
            )
        if not can_write:
            with self._lock:
                self._dropped += 1
                storage_failed = self._storage_failed
            if not storage_failed:
                self._emit_limit_marker(
                    "event_limit" if self._events >= self.max_events else "byte_limit"
                )
            return
        try:
            self._write_all(encoded)
        except OSError as exc:
            with self._lock:
                self._reader_error = redact_text(f"cannot write OS audit JSONL: {exc}")[:512]
                self._storage_failed = True
                self._dropped += 1
            return
        with self._lock:
            self._seq += 1
            self._events += 1
            self._output_bytes += len(encoded)

    def _emit_limit_marker(self, reason: str) -> None:
        with self._lock:
            if self._limit_reached:
                return
            self._limit_reached = True
            self._seq += 1
            marker = {
                "schema_version": SCHEMA_VERSION, "seq": self._seq, "backend": BACKEND_NAME,
                "wall_time_ns": time.time_ns(), "monotonic_ns": time.monotonic_ns(),
                "pid": None, "tid": None, "ppid": None, "comm": None,
                "syscall": "limit_reached", "category": "diagnostic", "access": "loss",
                "path": None, "path_scope": None, "fd": None, "bytes": None,
                "endpoint": None, "result": None, "errno": None, "success": None,
                "duration_ns": None, "arguments": reason, "synthetic": True,
            }
        encoded = (json.dumps(marker, ensure_ascii=True, separators=(",", ":")) + "\n").encode("utf-8")
        if self._output_bytes + len(encoded) > self.max_bytes:
            return
        try:
            self._write_all(encoded)
        except OSError as exc:
            with self._lock:
                self._reader_error = redact_text(f"cannot write OS audit limit marker: {exc}")[:512]
            return
        with self._lock:
            self._output_bytes += len(encoded)

    def _write_all(self, payload: bytes) -> None:
        view = memoryview(payload)
        while view:
            written = os.write(self._output_fd, view)
            view = view[written:]


__all__ = [
    "BACKEND_NAME", "DEFAULT_MAX_BYTES", "DEFAULT_MAX_EVENTS", "OsAuditError",
    "OsAuditStats", "SCHEMA_VERSION", "StraceAuditCollector", "StraceUnavailable",
    "probe_strace", "strace_available", "strace_unavailable_reason",
]
