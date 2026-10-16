from __future__ import annotations

import json
import os
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator


def _secure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        path.parent.chmod(0o700)
    except OSError:
        pass


def atomic_json_dump(path: Path, data: Any) -> None:
    _secure_parent(path)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        # Linux permits arbitrary bytes in path names.  ``Path`` represents
        # undecodable bytes with surrogate escapes; writing those values with
        # a strict UTF-8 encoder would make one unusual file name abort the
        # entire normalization/report pipeline.  ``backslashreplace`` keeps
        # ordinary Unicode readable while serializing the surrogate as a JSON
        # escape that can be loaded again safely.
        with os.fdopen(fd, "w", encoding="utf-8", errors="backslashreplace") as fp:
            json.dump(data, fp, ensure_ascii=False, indent=2)
            fp.write("\n")
            fp.flush()
            os.fsync(fp.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def json_load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def iter_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    if not path.exists():
        return
    with path.open(encoding="utf-8") as fp:
        for line_number, line in enumerate(fp, start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSONL at {path}:{line_number}: {exc}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"Expected JSON object at {path}:{line_number}")
            yield value


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    _secure_parent(path)
    fd = os.open(path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", errors="backslashreplace") as fp:
        for row in rows:
            fp.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")


def append_jsonl_locked(path: Path, row: dict[str, Any]) -> None:
    """Append one JSON object safely across concurrent hook processes."""

    _secure_parent(path)
    flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
    # Close the lstat/open race in the hook collector.  O_NOFOLLOW is
    # available on the Unix platforms where fcntl locking is used; retaining
    # the fstat check also rejects non-regular descriptors portably.
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(f"refusing non-regular JSONL destination: {path}")
        try:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX)
        except ImportError:
            pass
        payload = (
            json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n"
        ).encode("utf-8", errors="backslashreplace")
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            view = view[written:]
    finally:
        os.close(fd)


@dataclass(frozen=True, slots=True)
class RunLayout:
    root: Path

    @classmethod
    def create(cls, root: Path, *, repo: Path | None = None) -> "RunLayout":
        resolved = root.expanduser().resolve()
        if repo is not None:
            repo_resolved = repo.expanduser().resolve()
            if resolved == repo_resolved or repo_resolved in resolved.parents:
                raise ValueError("The trace directory must be outside the observed repository")
        if resolved.exists():
            if not resolved.is_dir():
                raise NotADirectoryError(resolved)
            if any(resolved.iterdir()):
                raise FileExistsError(f"Trace directory is not empty: {resolved}")
        resolved.mkdir(parents=True, exist_ok=True, mode=0o700)
        resolved.chmod(0o700)
        for name in ("raw", "snapshots", "protocol"):
            child = resolved / name
            child.mkdir(mode=0o700)
        return cls(resolved)

    @classmethod
    def open(cls, root: Path) -> "RunLayout":
        resolved = root.expanduser().resolve()
        if not resolved.is_dir():
            raise FileNotFoundError(resolved)
        return cls(resolved)

    @property
    def appserver_raw(self) -> Path:
        return self.root / "raw" / "appserver.jsonl"

    @property
    def hooks_raw(self) -> Path:
        return self.root / "raw" / "hooks.jsonl"

    @property
    def functions_raw(self) -> Path:
        return self.root / "raw" / "functions.jsonl"

    @property
    def filesystem_raw(self) -> Path:
        return self.root / "raw" / "filesystem.jsonl"

    @property
    def os_audit_raw(self) -> Path:
        return self.root / "raw" / "os_audit.jsonl"

    @property
    def otel_trace_raw(self) -> Path:
        return self.root / "raw" / "otel_trace.jsonl"

    @property
    def function_trace_summary(self) -> Path:
        return self.root / "function_trace_summary.json"

    @property
    def file_audit_summary(self) -> Path:
        return self.root / "file_audit_summary.json"

    @property
    def os_audit_summary(self) -> Path:
        return self.root / "os_audit_summary.json"

    @property
    def otel_trace_summary(self) -> Path:
        return self.root / "otel_trace_summary.json"

    @property
    def appserver_stderr(self) -> Path:
        return self.root / "raw" / "appserver.stderr.log"

    @property
    def manifest(self) -> Path:
        return self.root / "manifest.json"

    @property
    def events(self) -> Path:
        return self.root / "events.jsonl"

    @property
    def enriched(self) -> Path:
        return self.root / "enriched.json"

    @property
    def graph(self) -> Path:
        return self.root / "provenance_graph.json"
