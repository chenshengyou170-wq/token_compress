"""Best-effort Linux workspace observation using inotify.

This module intentionally has no third-party dependencies and does not require
root.  It is an observation layer, not an audit boundary: inotify can report
that a pathname changed, but not which process caused the change, and its
kernel queue can overflow under sustained load.
"""

from __future__ import annotations

import ctypes
import errno
import json
import os
import selectors
import stat
import struct
import sys
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Mapping


DEFAULT_EXCLUDED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".cache",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".nox",
        ".gradle",
        ".next",
        ".turbo",
        "build",
        "dist",
        "target",
    }
)


class FswatchError(RuntimeError):
    """Base class for workspace watcher errors."""


class InotifyUnavailable(FswatchError):
    """Raised when Linux inotify cannot be used on the current host."""


class WatchLimitError(FswatchError):
    """Raised when a configured or kernel inotify watch limit is reached."""


class QueueOverflowError(FswatchError):
    """Raised by ``check_health`` after a fatal kernel queue overflow."""


class WorkspaceUnavailableError(FswatchError):
    """Raised when the watched workspace root disappears or becomes invalid."""


@dataclass(frozen=True, slots=True)
class WatchStats:
    watches: int
    watches_added: int
    watches_removed: int
    watch_add_errors: int
    watch_limit_errors: int
    kernel_events: int
    events_emitted: int
    kernel_overflows: int
    buffer_dropped: int
    jsonl_dropped: int
    callback_events: int
    callback_dropped: int
    callback_limit_markers: int
    callback_limit_reached: bool
    callback_errors: int
    last_error: str | None


SCHEMA_VERSION = "codexscope.filesystem.v1"
BACKEND_NAME = "linux_inotify"


# linux/inotify.h.  Values are part of Linux's stable userspace ABI.
IN_MODIFY = 0x00000002
IN_ATTRIB = 0x00000004
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_UNMOUNT = 0x00002000
IN_Q_OVERFLOW = 0x00004000
IN_IGNORED = 0x00008000
IN_ONLYDIR = 0x01000000
IN_DONT_FOLLOW = 0x02000000
IN_ISDIR = 0x40000000

_EVENT_MASK = (
    IN_MODIFY
    | IN_ATTRIB
    | IN_CLOSE_WRITE
    | IN_MOVED_FROM
    | IN_MOVED_TO
    | IN_CREATE
    | IN_DELETE
    | IN_DELETE_SELF
    | IN_MOVE_SELF
    | IN_UNMOUNT
)
_WATCH_MASK = _EVENT_MASK | IN_ONLYDIR | IN_DONT_FOLLOW
_EVENT_HEADER = struct.Struct("iIII")
_READ_SIZE = 1024 * 1024
_MOVE_EXPIRY_SECONDS = 0.25

_KIND_BY_MASK = (
    (IN_CREATE, "create"),
    (IN_MODIFY, "modify"),
    (IN_CLOSE_WRITE, "close_write"),
    (IN_DELETE, "delete"),
    (IN_MOVED_FROM, "move_from"),
    (IN_MOVED_TO, "move_to"),
    (IN_ATTRIB, "attrib"),
    (IN_DELETE_SELF, "delete_self"),
    (IN_MOVE_SELF, "move_self"),
)


def _load_inotify() -> tuple[object | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, f"inotify requires Linux (current platform: {sys.platform})"
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        init1 = libc.inotify_init1
        add_watch = libc.inotify_add_watch
        rm_watch = libc.inotify_rm_watch
    except (AttributeError, OSError) as exc:
        return None, f"libc does not expose the required inotify API: {exc}"
    init1.argtypes = [ctypes.c_int]
    init1.restype = ctypes.c_int
    add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
    add_watch.restype = ctypes.c_int
    rm_watch.argtypes = [ctypes.c_int, ctypes.c_int]
    rm_watch.restype = ctypes.c_int
    return libc, None


_LIBC, _UNAVAILABLE_REASON = _load_inotify()


def inotify_available() -> bool:
    """Return whether this interpreter can call the Linux inotify API."""

    return _LIBC is not None


def inotify_unavailable_reason() -> str | None:
    """Return a human-readable degradation reason, or ``None`` when usable."""

    return _UNAVAILABLE_REASON


class WorkspaceWatcher:
    """Recursively observe workspace pathname changes with Linux inotify.

    Events are retained in a bounded in-memory deque and may additionally be
    delivered to ``callback`` and/or a size-bounded JSONL file.  Paths are
    relative to ``root`` and symlinked directories are never traversed.

    The callback runs on the reader thread and therefore should return quickly.
    Callback exceptions are counted and do not stop observation.  Call
    :meth:`check_health` to surface fatal asynchronous failures.
    """

    def __init__(
        self,
        root: str | Path,
        *,
        callback: Callable[[Mapping[str, object]], None] | None = None,
        jsonl_path: str | Path | None = None,
        max_buffered_events: int = 4096,
        max_jsonl_bytes: int = 8 * 1024 * 1024,
        max_jsonl_events: int | None = None,
        max_callback_events: int | None = None,
        excluded_dirs: set[str] | frozenset[str] = DEFAULT_EXCLUDED_DIRS,
        max_watches: int | None = None,
        fail_on_overflow: bool = False,
    ) -> None:
        if max_buffered_events < 1:
            raise ValueError("max_buffered_events must be at least 1")
        if max_jsonl_bytes < 0:
            raise ValueError("max_jsonl_bytes cannot be negative")
        if max_jsonl_events is not None and max_jsonl_events < 1:
            raise ValueError("max_jsonl_events must be at least 1")
        if max_callback_events is not None and max_callback_events < 1:
            raise ValueError("max_callback_events must be at least 1")
        if max_watches is not None and max_watches < 1:
            raise ValueError("max_watches must be at least 1")

        candidate = Path(os.path.abspath(os.fspath(Path(root).expanduser())))
        try:
            root_stat = candidate.stat(follow_symlinks=False)
        except OSError as exc:
            raise ValueError(f"workspace root is not accessible: {candidate}") from exc
        if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
            raise ValueError(f"workspace root must be a real directory: {candidate}")

        self.root = candidate
        self.callback = callback
        self.jsonl_path = (
            Path(os.path.abspath(os.fspath(Path(jsonl_path).expanduser())))
            if jsonl_path is not None
            else None
        )
        self.max_jsonl_bytes = max_jsonl_bytes
        self.max_jsonl_events = max_jsonl_events
        self.max_callback_events = max_callback_events
        self.excluded_dirs = frozenset(excluded_dirs)
        self.max_watches = max_watches
        self.fail_on_overflow = fail_on_overflow

        self._events: deque[dict[str, object]] = deque(maxlen=max_buffered_events)
        self._data_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._stop_requested = threading.Event()
        self._state = "new"
        self._thread: threading.Thread | None = None
        self._fd = -1
        self._wake_read = -1
        self._wake_write = -1
        self._root_fd = -1
        self._jsonl_fp = None
        self._jsonl_bytes = 0
        self._jsonl_events = 0
        self._fatal_error: BaseException | None = None
        self._last_callback_error: BaseException | None = None

        self._wd_to_path: dict[int, Path] = {}
        self._path_to_wd: dict[Path, int] = {}
        self._pending_moves: dict[int, tuple[Path, float]] = {}
        self._seq = 0
        self._watches_added = 0
        self._watches_removed = 0
        self._watch_add_errors = 0
        self._watch_limit_errors = 0
        self._kernel_events = 0
        self._events_emitted = 0
        self._kernel_overflows = 0
        self._buffer_dropped = 0
        self._jsonl_dropped = 0
        self._callback_events = 0
        self._callback_dropped = 0
        self._callback_limit_markers = 0
        self._callback_limit_marker_emitted = False
        self._callback_errors = 0
        self._root_identity = (root_stat.st_dev, root_stat.st_ino)

    @property
    def running(self) -> bool:
        with self._state_lock:
            return self._state == "running"

    @property
    def events(self) -> tuple[dict[str, object], ...]:
        """Return a stable copy of the currently buffered events."""

        with self._data_lock:
            return tuple(dict(event) for event in self._events)

    def drain_events(self) -> list[dict[str, object]]:
        """Remove and return all currently buffered events."""

        with self._data_lock:
            result = [dict(event) for event in self._events]
            self._events.clear()
            return result

    @property
    def stats(self) -> WatchStats:
        with self._data_lock:
            last_error = self._fatal_error or self._last_callback_error
            return WatchStats(
                watches=len(self._wd_to_path),
                watches_added=self._watches_added,
                watches_removed=self._watches_removed,
                watch_add_errors=self._watch_add_errors,
                watch_limit_errors=self._watch_limit_errors,
                kernel_events=self._kernel_events,
                events_emitted=self._events_emitted,
                kernel_overflows=self._kernel_overflows,
                buffer_dropped=self._buffer_dropped,
                jsonl_dropped=self._jsonl_dropped,
                callback_events=self._callback_events,
                callback_dropped=self._callback_dropped,
                callback_limit_markers=self._callback_limit_markers,
                callback_limit_reached=self._callback_limit_marker_emitted,
                callback_errors=self._callback_errors,
                last_error=repr(last_error) if last_error is not None else None,
            )

    def stats_dict(self) -> dict[str, int | str | None]:
        return asdict(self.stats)

    @property
    def last_callback_error(self) -> BaseException | None:
        with self._data_lock:
            return self._last_callback_error

    def start(self) -> "WorkspaceWatcher":
        """Allocate watches and start the reader thread."""

        with self._state_lock:
            if self._state != "new":
                raise RuntimeError("WorkspaceWatcher instances can only be started once")
            if _LIBC is None:
                self._state = "stopped"
                raise InotifyUnavailable(_UNAVAILABLE_REASON or "inotify is unavailable")
            self._state = "starting"

        try:
            flags = os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
            fd = _LIBC.inotify_init1(flags)
            if fd < 0:
                error_number = ctypes.get_errno()
                raise InotifyUnavailable(
                    f"inotify_init1 failed: {os.strerror(error_number)}"
                )
            self._fd = fd
            self._wake_read, self._wake_write = os.pipe2(flags)
            self._open_root()
            self._open_jsonl()
            self._add_tree(self.root, root_required=True)
            self._thread = threading.Thread(
                target=self._run,
                name="codexscope-fswatch",
                daemon=True,
            )
            with self._state_lock:
                self._state = "running"
            self._thread.start()
            return self
        except BaseException:
            self._close_resources()
            with self._state_lock:
                self._state = "stopped"
            raise

    def stop(self, timeout: float = 5.0, *, raise_on_error: bool = True) -> None:
        """Request a clean stop and wait for the reader thread.

        The method is idempotent.  A callback may call it safely, although an
        external caller is still responsible for subsequently checking health.
        """

        with self._state_lock:
            state = self._state
            if state == "new":
                self._state = "stopped"
                return
            thread = self._thread

        self._stop_requested.set()
        if self._wake_write >= 0:
            try:
                os.write(self._wake_write, b"x")
            except OSError:
                pass

        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout)
            if thread.is_alive():
                raise TimeoutError("workspace watcher did not stop before timeout")

        if raise_on_error:
            self.check_health()

    def close(self, timeout: float = 5.0, *, raise_on_error: bool = True) -> WatchStats:
        """Stop observation and return a final immutable statistics snapshot."""

        self.stop(timeout=timeout, raise_on_error=raise_on_error)
        return self.stats

    def check_health(self) -> None:
        """Raise a fatal error recorded by the background reader, if any."""

        with self._data_lock:
            error = self._fatal_error
        if error is not None:
            raise error

    def __enter__(self) -> "WorkspaceWatcher":
        return self.start()

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.stop(raise_on_error=exc is None)

    def _open_jsonl(self) -> None:
        if self.jsonl_path is None:
            return
        self.jsonl_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NONBLOCK
            | getattr(os, "O_CLOEXEC", 0)
        )
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(self.jsonl_path, flags, 0o600)
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode):
                raise FswatchError(
                    f"filesystem event output must be a regular file: {self.jsonl_path}"
                )
            os.fchmod(fd, 0o600)
            self._jsonl_fp = os.fdopen(fd, "wb", buffering=0)
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            raise

    def _open_root(self) -> None:
        """Pin the workspace root used for every recursive traversal."""

        flags = (
            os.O_RDONLY
            | os.O_DIRECTORY
            | os.O_NONBLOCK
            | getattr(os, "O_CLOEXEC", 0)
        )
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(self.root, flags)
        except OSError as exc:
            raise WorkspaceUnavailableError(
                f"cannot open workspace root {self.root}: {exc}"
            ) from exc
        opened = os.fstat(fd)
        if not stat.S_ISDIR(opened.st_mode) or (
            opened.st_dev,
            opened.st_ino,
        ) != self._root_identity:
            os.close(fd)
            raise WorkspaceUnavailableError(
                f"workspace root changed before observation started: {self.root}"
            )
        self._root_fd = fd

    def _open_directory_fd(self, directory: Path) -> int:
        """Open a directory below the pinned root without following symlinks.

        Each component is resolved from an already-open parent directory.  A
        concurrent intermediate-component symlink swap therefore fails closed
        instead of redirecting discovery outside the workspace.
        """

        try:
            relative = directory.relative_to(self.root)
        except ValueError as exc:
            raise OSError(errno.EXDEV, "directory is outside workspace") from exc
        if any(component in {os.curdir, os.pardir} for component in relative.parts):
            raise OSError(errno.EXDEV, "directory traversal escapes workspace")
        if self._root_fd < 0:
            raise OSError(errno.EBADF, "workspace root is not open")

        current = os.dup(self._root_fd)
        flags = (
            os.O_RDONLY
            | os.O_DIRECTORY
            | os.O_NONBLOCK
            | getattr(os, "O_CLOEXEC", 0)
        )
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            for component in relative.parts:
                next_fd = os.open(component, flags, dir_fd=current)
                os.close(current)
                current = next_fd
            return current
        except BaseException:
            os.close(current)
            raise

    def _is_excluded(self, path: Path) -> bool:
        try:
            relative = path.relative_to(self.root)
        except ValueError:
            return True
        return any(part in self.excluded_dirs for part in relative.parts)

    def _add_tree(
        self,
        directory: Path,
        *,
        root_required: bool = False,
        emit_existing: bool = False,
    ) -> None:
        pending = [directory]
        first = True
        while pending:
            current = pending.pop()
            if current != self.root and self._is_excluded(current):
                continue
            required = root_required and first
            first = False
            try:
                directory_fd = self._open_directory_fd(current)
            except OSError as exc:
                with self._data_lock:
                    self._watch_add_errors += 1
                self._emit("watch_error", current, True, 0, 0, synthetic=True)
                if required:
                    raise WorkspaceUnavailableError(
                        f"cannot securely open workspace root {current}: {exc}"
                    ) from exc
                continue
            try:
                added = self._add_watch(
                    current,
                    directory_fd=directory_fd,
                    required=required,
                )
                if not added:
                    continue
                with os.scandir(directory_fd) as entries:
                    children: list[Path] = []
                    discovered: list[tuple[Path, bool]] = []
                    for entry in entries:
                        if entry.name in self.excluded_dirs:
                            continue
                        entry_path = current / entry.name
                        is_directory = (
                            entry.is_dir(follow_symlinks=False)
                            and not entry.is_symlink()
                        )
                        if is_directory:
                            children.append(entry_path)
                        if emit_existing:
                            discovered.append((entry_path, is_directory))
            except OSError:
                with self._data_lock:
                    self._watch_add_errors += 1
                continue
            finally:
                os.close(directory_fd)
            for entry_path, is_directory in discovered:
                self._emit(
                    "create",
                    entry_path,
                    is_directory,
                    0,
                    IN_CREATE | (IN_ISDIR if is_directory else 0),
                    synthetic=True,
                )
            pending.extend(children)

    def _add_watch(
        self,
        directory: Path,
        *,
        directory_fd: int,
        required: bool,
    ) -> bool:
        if directory in self._path_to_wd:
            return True
        if self.max_watches is not None and len(self._wd_to_path) >= self.max_watches:
            with self._data_lock:
                self._watch_limit_errors += 1
            self._emit("watch_limit", directory, True, 0, 0, synthetic=True)
            raise WatchLimitError(
                f"configured watch limit ({self.max_watches}) reached at {directory}"
            )

        # inotify has no fd-native add-watch API.  The procfs descriptor link
        # resolves to the directory inode already opened with O_NOFOLLOW for
        # every workspace-relative component.  IN_DONT_FOLLOW is intentionally
        # removed here because the trusted /proc/self/fd entry is itself a
        # symlink; the opened target has already been verified as a directory.
        descriptor_path = os.fsencode(f"/proc/self/fd/{directory_fd}")
        wd = _LIBC.inotify_add_watch(
            self._fd,
            descriptor_path,
            _WATCH_MASK & ~IN_DONT_FOLLOW,
        )
        if wd < 0:
            error_number = ctypes.get_errno()
            if error_number in {errno.ENOSPC, errno.EMFILE, errno.ENFILE}:
                with self._data_lock:
                    self._watch_limit_errors += 1
                self._emit("watch_limit", directory, True, 0, 0, synthetic=True)
                raise WatchLimitError(
                    f"kernel inotify watch limit reached at {directory}: "
                    f"{os.strerror(error_number)}"
                )
            with self._data_lock:
                self._watch_add_errors += 1
            self._emit("watch_error", directory, True, 0, 0, synthetic=True)
            if required:
                raise WorkspaceUnavailableError(
                    f"cannot watch workspace root {directory}: {os.strerror(error_number)}"
                )
            return False

        old_path = self._wd_to_path.get(wd)
        if old_path is not None and old_path != directory:
            self._path_to_wd.pop(old_path, None)
        self._wd_to_path[wd] = directory
        self._path_to_wd[directory] = wd
        with self._data_lock:
            self._watches_added += 1
        return True

    def _run(self) -> None:
        selector = selectors.DefaultSelector()
        try:
            selector.register(self._fd, selectors.EVENT_READ, "inotify")
            selector.register(self._wake_read, selectors.EVENT_READ, "wake")
            while not self._stop_requested.is_set():
                for key, _mask in selector.select(timeout=_MOVE_EXPIRY_SECONDS):
                    if key.data == "wake":
                        try:
                            os.read(self._wake_read, 4096)
                        except (BlockingIOError, OSError):
                            pass
                        continue
                    self._read_ready()
                self._expire_pending_moves()
        except BaseException as exc:
            self._record_fatal(exc)
        finally:
            selector.close()
            self._close_resources()
            with self._state_lock:
                self._state = "stopped"

    def _read_ready(self) -> None:
        while True:
            try:
                data = os.read(self._fd, _READ_SIZE)
            except BlockingIOError:
                return
            if not data:
                return
            offset = 0
            data_length = len(data)
            while offset + _EVENT_HEADER.size <= data_length:
                wd, mask, cookie, name_length = _EVENT_HEADER.unpack_from(data, offset)
                offset += _EVENT_HEADER.size
                name_bytes = data[offset : offset + name_length]
                offset += name_length
                name = os.fsdecode(name_bytes.split(b"\0", 1)[0]) if name_length else ""
                with self._data_lock:
                    self._kernel_events += 1
                self._handle_record(wd, mask, cookie, name)

    def _handle_record(self, wd: int, mask: int, cookie: int, name: str) -> None:
        if mask & IN_Q_OVERFLOW:
            with self._data_lock:
                self._kernel_overflows += 1
            self._emit("queue_overflow", None, False, cookie, mask)
            if self.fail_on_overflow:
                self._record_fatal(
                    QueueOverflowError("the kernel inotify event queue overflowed")
                )
                self._stop_requested.set()
            return

        watched = self._wd_to_path.get(wd)
        if watched is None:
            return
        path = watched / name if name else watched
        is_dir = bool(mask & IN_ISDIR) or not name

        # A trace stored inside the workspace must not create a feedback loop
        # where writing one row produces another inotify row indefinitely.
        if self.jsonl_path is not None and path == self.jsonl_path:
            return

        if mask & IN_UNMOUNT:
            self._emit("unmount", path, is_dir, cookie, mask)
            self._record_fatal(
                WorkspaceUnavailableError("workspace filesystem unmounted")
            )
            self._stop_requested.set()

        if mask & IN_IGNORED:
            self._forget_wd(wd)
            if watched == self.root and not self._stop_requested.is_set():
                self._record_fatal(
                    WorkspaceUnavailableError("workspace root watch was removed")
                )
                self._stop_requested.set()
            return

        excluded = path != self.root and self._is_excluded(path)

        if is_dir and mask & IN_MOVED_FROM:
            if cookie:
                self._pending_moves[cookie] = (path, time.monotonic())
        if is_dir and mask & IN_MOVED_TO:
            pending = self._pending_moves.pop(cookie, None) if cookie else None
            if excluded:
                if pending is not None:
                    self._remove_subtree(pending[0])
            elif pending is not None:
                self._rename_subtree(pending[0], path)
            else:
                self._add_tree(path, emit_existing=True)
        elif is_dir and mask & IN_CREATE and not excluded:
            self._add_tree(path, emit_existing=True)
        elif is_dir and mask & IN_DELETE:
            self._remove_subtree(path)

        if mask & IN_DELETE_SELF and watched == self.root:
            self._record_fatal(WorkspaceUnavailableError("workspace root was deleted"))
            self._stop_requested.set()
        elif mask & IN_MOVE_SELF and watched == self.root:
            self._record_fatal(WorkspaceUnavailableError("workspace root was moved"))
            self._stop_requested.set()

        if excluded:
            return
        for bit, kind in _KIND_BY_MASK:
            if mask & bit:
                self._emit(kind, path, is_dir, cookie, mask)

    def _rename_subtree(self, old: Path, new: Path) -> None:
        updates: list[tuple[int, Path, Path]] = []
        for wd, current in tuple(self._wd_to_path.items()):
            try:
                suffix = current.relative_to(old)
            except ValueError:
                continue
            updates.append((wd, current, new / suffix))
        for wd, old_path, new_path in updates:
            self._path_to_wd.pop(old_path, None)
            self._wd_to_path[wd] = new_path
            self._path_to_wd[new_path] = wd
        if not updates:
            self._add_tree(new, emit_existing=True)

    def _expire_pending_moves(self) -> None:
        cutoff = time.monotonic() - _MOVE_EXPIRY_SECONDS
        expired = [
            cookie
            for cookie, (_path, observed_at) in self._pending_moves.items()
            if observed_at <= cutoff
        ]
        for cookie in expired:
            path, _observed_at = self._pending_moves.pop(cookie)
            self._remove_subtree(path)

    def _remove_subtree(self, prefix: Path) -> None:
        targets = [
            (wd, path)
            for wd, path in tuple(self._wd_to_path.items())
            if path == prefix or prefix in path.parents
        ]
        for wd, path in targets:
            self._wd_to_path.pop(wd, None)
            self._path_to_wd.pop(path, None)
            if self._fd >= 0:
                result = _LIBC.inotify_rm_watch(self._fd, wd)
                if result == 0:
                    with self._data_lock:
                        self._watches_removed += 1

    def _forget_wd(self, wd: int) -> None:
        path = self._wd_to_path.pop(wd, None)
        if path is not None:
            self._path_to_wd.pop(path, None)
            with self._data_lock:
                self._watches_removed += 1

    def _emit(
        self,
        kind: str,
        path: Path | None,
        is_dir: bool,
        cookie: int,
        mask: int,
        *,
        synthetic: bool = False,
        extra: Mapping[str, object] | None = None,
    ) -> None:
        event = self._new_event(
            kind,
            path,
            is_dir,
            cookie,
            mask,
            synthetic=synthetic,
            extra=extra,
        )
        self._append_event(event)
        persisted = self._write_jsonl_event(event)
        self._deliver_callback(event, persisted=persisted)

    def _new_event(
        self,
        kind: str,
        path: Path | None,
        is_dir: bool,
        cookie: int,
        mask: int,
        *,
        synthetic: bool,
        extra: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        self._seq += 1
        relative_path: str | None
        if path is None:
            relative_path = None
        else:
            try:
                relative_path = path.relative_to(self.root).as_posix()
            except ValueError:
                relative_path = None
        name_encoding_error = bool(
            relative_path
            and any(0xD800 <= ord(character) <= 0xDFFF for character in relative_path)
        )
        event: dict[str, object] = {
            "schema_version": SCHEMA_VERSION,
            "seq": self._seq,
            "backend": BACKEND_NAME,
            "wall_time_ns": time.time_ns(),
            "monotonic_ns": time.monotonic_ns(),
            "operation": kind,
            "path": relative_path,
            "is_dir": is_dir,
            "cookie": cookie,
            "mask": mask,
            "synthetic": synthetic,
            "name_encoding_error": name_encoding_error,
        }
        if extra:
            event.update(extra)
        return event

    def _append_event(self, event: dict[str, object]) -> None:
        with self._data_lock:
            if len(self._events) == self._events.maxlen:
                self._buffer_dropped += 1
            self._events.append(event)
            self._events_emitted += 1

    def _write_jsonl_event(
        self,
        event: Mapping[str, object],
        *,
        bypass_event_limit: bool = False,
    ) -> bool:
        if self._jsonl_fp is None:
            return True
        encoded = (
            json.dumps(event, ensure_ascii=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        within_event_limit = (
            bypass_event_limit
            or self.max_jsonl_events is None
            or self._jsonl_events < self.max_jsonl_events
        )
        if not within_event_limit or self._jsonl_bytes + len(encoded) > self.max_jsonl_bytes:
            with self._data_lock:
                self._jsonl_dropped += 1
            return False
        try:
            self._jsonl_fp.write(encoded)
            self._jsonl_bytes += len(encoded)
            self._jsonl_events += 1
            return True
        except OSError as exc:
            self._record_fatal(FswatchError(f"cannot write fswatch JSONL: {exc}"))
            self._stop_requested.set()
            return False

    def _invoke_callback(self, event: Mapping[str, object]) -> None:
        try:
            assert self.callback is not None
            self.callback(dict(event))
        except BaseException as exc:
            with self._data_lock:
                self._callback_errors += 1
                self._last_callback_error = exc

    def _deliver_callback(
        self,
        event: Mapping[str, object],
        *,
        persisted: bool,
    ) -> None:
        if self.callback is None:
            return
        if self.max_callback_events is None:
            with self._data_lock:
                self._callback_events += 1
            self._invoke_callback(event)
            return

        with self._data_lock:
            can_deliver = (
                persisted and self._callback_events < self.max_callback_events
            )
            if can_deliver:
                self._callback_events += 1
            else:
                self._callback_dropped += 1
            emit_marker = not can_deliver and not self._callback_limit_marker_emitted
            if emit_marker:
                self._callback_limit_marker_emitted = True
                self._callback_limit_markers += 1

        if can_deliver:
            self._invoke_callback(event)
            return
        if not emit_marker:
            return

        marker = self._new_event(
            "limit_reached",
            None,
            False,
            0,
            0,
            synthetic=True,
            extra={
                "reason": "callback_delivery_limit",
                "loss_scope": "callback",
                "callback_event_limit": self.max_callback_events,
            },
        )
        self._append_event(marker)
        # The diagnostic is allowed one extra row beyond the normal event
        # count so a persisted trace can explain the otherwise silent gap.
        self._write_jsonl_event(marker, bypass_event_limit=True)
        self._invoke_callback(marker)


    def _record_fatal(self, error: BaseException) -> None:
        with self._data_lock:
            if self._fatal_error is None:
                self._fatal_error = error

    def _close_resources(self) -> None:
        fp, self._jsonl_fp = self._jsonl_fp, None
        if fp is not None:
            try:
                fp.flush()
            finally:
                fp.close()
        for attribute in ("_fd", "_wake_read", "_wake_write", "_root_fd"):
            fd = getattr(self, attribute)
            setattr(self, attribute, -1)
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass


class InotifyWorkspaceObserver(WorkspaceWatcher):
    """Stable integration-facing name for the Linux filesystem observer.

    ``output_path`` receives bounded ``codexscope.filesystem.v1`` JSONL rows.
    ``max_events`` limits retained rows, ordinary written JSONL rows, and
    ordinary callback deliveries.  Once callback delivery is capped, at most
    one additional synthetic ``limit_reached`` callback explains the loss.
    Callers that need independent limits can use :class:`WorkspaceWatcher`
    directly.
    """

    def __init__(
        self,
        repo: str | Path,
        output_path: str | Path | None = None,
        *,
        max_events: int = 100_000,
        on_event: Callable[[dict[str, object]], None] | None = None,
        max_jsonl_bytes: int = 32 * 1024 * 1024,
        excluded_dirs: set[str] | frozenset[str] = DEFAULT_EXCLUDED_DIRS,
        max_watches: int | None = None,
        fail_on_overflow: bool = False,
    ) -> None:
        super().__init__(
            repo,
            callback=on_event,
            jsonl_path=output_path,
            max_buffered_events=max_events,
            max_jsonl_bytes=max_jsonl_bytes,
            max_jsonl_events=max_events,
            max_callback_events=max_events,
            excluded_dirs=excluded_dirs,
            max_watches=max_watches,
            fail_on_overflow=fail_on_overflow,
        )
