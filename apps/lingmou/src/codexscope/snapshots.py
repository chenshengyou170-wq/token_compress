from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Mapping

from .storage import atomic_json_dump
from .util import is_source_path


_SKIP_DIRS = {
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
_MAX_SNAPSHOT_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class _Entry:
    digest: str
    data: bytes | None
    kind: str


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        path.parent.chmod(0o700)
    except OSError:
        pass
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as fp:
            fp.write(data)
            fp.flush()
            os.fsync(fp.fileno())
    finally:
        os.close(fd)


class SnapshotManager:
    """Maintain safe, versioned workspace snapshots and a hash change journal.

    Baseline bytes come from Git objects, never from working-tree paths. This is
    important for tracked symlinks: following one while establishing the
    baseline could otherwise copy an arbitrary file outside the repository.
    Subsequent scans use ``lstat``/``O_NOFOLLOW`` and reconcile hashes after any
    completed tool item, which captures writes performed by shell and MCP tools
    even when App Server emits no ``fileChange`` item.
    """

    def __init__(
        self,
        repo: Path,
        run_dir: Path,
        *,
        baseline_source: str = "git",
    ) -> None:
        if baseline_source not in {"git", "workspace"}:
            raise ValueError("baseline_source must be 'git' or 'workspace'")
        self.repo = repo.expanduser().resolve()
        self.run_dir = run_dir.expanduser().resolve()
        self.baseline_source = baseline_source
        self.root = self.run_dir / "snapshots"
        self.baseline_root = self.root / "baseline"
        self.items_root = self.root / "items"
        self.index_path = self.root / "index.jsonl"
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.baseline_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.items_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        for directory in (self.root, self.baseline_root, self.items_root):
            try:
                directory.chmod(0o700)
            except OSError:
                pass
        self._index_fp = self.index_path.open(
            "w", encoding="utf-8", errors="backslashreplace", buffering=1
        )
        os.chmod(self.index_path, 0o600)
        self.latest: dict[str, str | None] = {}
        self._state: dict[str, _Entry] = {}
        self._stat_cache: dict[str, tuple[int, int, int, int, int, int]] = {}
        self._scan_count = 0
        self._files_seen = 0
        self._cache_hits = 0
        self._hashed_files = 0
        self._hashed_bytes = 0
        self._last_seq = 0
        self._last_capture: dict[str, Any] = {}
        self._baseline_captured = False
        self._closed = False
        self._workspace_uses_git_candidates = (
            baseline_source == "workspace" and self._is_git_worktree()
        )
        try:
            self._run_rel = self.run_dir.relative_to(self.repo).as_posix()
        except ValueError:
            self._run_rel = None

    def _is_git_worktree(self) -> bool:
        try:
            completed = subprocess.run(
                ["git", "rev-parse", "--is-inside-work-tree"],
                cwd=self.repo,
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return completed.stdout.strip() == "true"

    def _workspace_walk_candidates(self) -> list[str]:
        """Return safe candidates without requiring a Git worktree.

        Interactive monitoring must also work in dirty and non-Git folders.
        ``os.walk(..., followlinks=False)`` plus the normal lstat/open checks
        keeps the same no-symlink-following boundary used by incremental scans.
        """

        candidates: list[str] = []
        for root, directories, files in os.walk(self.repo, topdown=True, followlinks=False):
            root_path = Path(root)
            directories[:] = [
                name
                for name in directories
                if name not in _SKIP_DIRS
                and not (root_path / name).is_symlink()
                and self._tracked_path(
                    (root_path / name).relative_to(self.repo).as_posix()
                )
            ]
            for name in files:
                rel = (root_path / name).relative_to(self.repo).as_posix()
                if self._tracked_path(rel):
                    candidates.append(rel)
        candidates.extend(path for path in self._state if path not in candidates)
        return sorted(set(candidates))

    def _tracked_path(self, rel: str) -> bool:
        path = Path(rel)
        if path.is_absolute() or ".." in path.parts:
            return False
        if any(part in _SKIP_DIRS for part in path.parts):
            return False
        if self._run_rel and (rel == self._run_rel or rel.startswith(self._run_rel + "/")):
            return False
        return True

    def _git_tree(self) -> list[tuple[str, str, str]]:
        completed = subprocess.run(
            ["git", "ls-tree", "-r", "-z", "--full-tree", "HEAD"],
            cwd=self.repo,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        result: list[tuple[str, str, str]] = []
        for record in completed.stdout.split(b"\0"):
            if not record or b"\t" not in record:
                continue
            header, raw_path = record.split(b"\t", 1)
            parts = header.split()
            if len(parts) != 3 or parts[1] != b"blob":
                continue
            mode = parts[0].decode("ascii", errors="replace")
            oid = parts[2].decode("ascii", errors="replace")
            rel = os.fsdecode(raw_path).replace(os.sep, "/")
            if self._tracked_path(rel):
                result.append((rel, mode, oid))
        return result

    def _git_blob_stream(self, records: list[tuple[str, str, str]]) -> Iterator[tuple[str, str, str, bytes]]:
        process = subprocess.Popen(
            ["git", "cat-file", "--batch"],
            cwd=self.repo,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert process.stdin is not None and process.stdout is not None
        try:
            for rel, mode, oid in records:
                process.stdin.write(oid.encode("ascii") + b"\n")
                process.stdin.flush()
                header = process.stdout.readline().rstrip(b"\n")
                fields = header.split()
                if len(fields) != 3 or fields[1] != b"blob":
                    raise RuntimeError(f"Cannot read Git blob for {rel!r}: {header!r}")
                size = int(fields[2])
                data = process.stdout.read(size)
                delimiter = process.stdout.read(1)
                if len(data) != size or delimiter != b"\n":
                    raise RuntimeError(f"Truncated Git blob for {rel!r}")
                yield rel, mode, oid, data
        finally:
            process.stdin.close()
            return_code = process.wait(timeout=30)
            if return_code != 0:
                stderr = process.stderr.read().decode("utf-8", errors="replace") if process.stderr else ""
                raise RuntimeError(f"git cat-file failed: {stderr.strip()}")

    def capture_baseline(self) -> None:
        if self._baseline_captured:
            return
        if self.baseline_source == "workspace":
            self._capture_workspace_baseline()
            return
        records: list[dict[str, Any]] = []
        for rel, mode, oid, data in self._git_blob_stream(self._git_tree()):
            kind = "symlink" if mode == "120000" else "regular"
            keep = kind == "regular" and is_source_path(rel) and len(data) <= _MAX_SNAPSHOT_BYTES
            entry = _Entry(_sha256(data), data if keep else None, kind)
            self._state[rel] = entry
            snapshot_rel: str | None = None
            # Store code as an ordinary private file. Symlink Git blobs are kept
            # in metadata only and are never materialized as filesystem links.
            if kind == "regular" and is_source_path(rel) and entry.data is not None:
                destination = self.baseline_root / rel
                _write_private(destination, entry.data)
                snapshot_rel = destination.relative_to(self.root).as_posix()
            self.latest[rel] = snapshot_rel
            records.append(
                {
                    "path": rel,
                    "mode": mode,
                    "git_blob": oid,
                    "sha256": entry.digest,
                    "kind": kind,
                    "snapshot": snapshot_rel,
                }
            )
        try:
            head = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=self.repo,
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).stdout.strip()
        except (OSError, subprocess.CalledProcessError):
            head = None
        atomic_json_dump(
            self.root / "baseline_manifest.json",
            {
                "source": "git_head",
                "git_head": head,
                "file_count": len(records),
                "files": records,
            },
        )
        self._baseline_captured = True

    def _capture_workspace_baseline(self) -> None:
        current = self._scan_workspace()
        records: list[dict[str, Any]] = []
        for rel, entry in sorted(current.items()):
            snapshot_rel: str | None = None
            if entry.kind == "regular" and entry.data is not None:
                destination = self.baseline_root / rel
                _write_private(destination, entry.data)
                snapshot_rel = destination.relative_to(self.root).as_posix()
            self._state[rel] = entry
            self.latest[rel] = snapshot_rel
            records.append(
                {
                    "path": rel,
                    "mode": None,
                    "git_blob": None,
                    "sha256": entry.digest,
                    "kind": entry.kind,
                    "snapshot": snapshot_rel,
                }
            )
        atomic_json_dump(
            self.root / "baseline_manifest.json",
            {
                "source": "workspace",
                "git_head": None,
                "file_count": len(records),
                "files": records,
            },
        )
        self._baseline_captured = True

    @staticmethod
    def _stat_signature(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
        """Fields a normal write cannot preserve (ctime guards restored mtime)."""

        return (
            int(metadata.st_mode),
            int(metadata.st_dev),
            int(metadata.st_ino),
            int(metadata.st_size),
            int(metadata.st_mtime_ns),
            int(metadata.st_ctime_ns),
        )

    def _open_workspace_candidate(
        self, rel: str
    ) -> tuple[os.stat_result, int | None, bytes | None] | None:
        """Open one candidate without following any path-component symlink."""

        parts = Path(rel).parts
        if not parts:
            return None
        directory_flags = os.O_RDONLY
        directory_flags |= getattr(os, "O_DIRECTORY", 0)
        directory_flags |= getattr(os, "O_NOFOLLOW", 0)
        file_flags = (
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        opened_directories: list[int] = []
        file_fd: int | None = None
        try:
            current_fd = os.open(self.repo, directory_flags)
            opened_directories.append(current_fd)
            for component in parts[:-1]:
                current_fd = os.open(
                    component,
                    directory_flags,
                    dir_fd=current_fd,
                )
                opened_directories.append(current_fd)

            name = parts[-1]
            metadata = os.stat(name, dir_fd=current_fd, follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                link_data = os.fsencode(os.readlink(name, dir_fd=current_fd))
                return metadata, None, link_data
            if not stat.S_ISREG(metadata.st_mode):
                return None
            file_fd = os.open(name, file_flags, dir_fd=current_fd)
            verified = os.fstat(file_fd)
            if not stat.S_ISREG(verified.st_mode):
                return None
            result = (verified, file_fd, None)
            file_fd = None
            return result
        except OSError:
            return None
        finally:
            if file_fd is not None:
                os.close(file_fd)
            for directory_fd in reversed(opened_directories):
                os.close(directory_fd)

    def _workspace_entry(
        self,
        rel: str,
        metadata: os.stat_result,
        file_fd: int | None,
        link_data: bytes | None,
    ) -> _Entry | None:
        if stat.S_ISLNK(metadata.st_mode):
            if link_data is None:
                return None
            self._hashed_files += 1
            self._hashed_bytes += len(link_data)
            return _Entry(_sha256(link_data), link_data, "symlink")
        if not stat.S_ISREG(metadata.st_mode) or file_fd is None:
            return None
        digest = hashlib.sha256()
        keep = is_source_path(rel) and metadata.st_size <= _MAX_SNAPSHOT_BYTES
        chunks: list[bytes] | None = [] if keep else None
        bytes_read = 0
        try:
            while True:
                chunk = os.read(file_fd, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                bytes_read += len(chunk)
                if chunks is not None:
                    chunks.append(chunk)
        finally:
            os.close(file_fd)
        self._hashed_files += 1
        self._hashed_bytes += bytes_read
        return _Entry(digest.hexdigest(), b"".join(chunks) if chunks is not None else None, "regular")

    def _workspace_candidates(self) -> list[str]:
        if self.baseline_source == "workspace" and not self._workspace_uses_git_candidates:
            return self._workspace_walk_candidates()
        completed = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            cwd=self.repo,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        candidates = {
            os.fsdecode(raw).replace(os.sep, "/")
            for raw in completed.stdout.split(b"\0")
            if raw
        }
        # If a run edits .gitignore after a previously-untracked file was
        # observed, keep watching that file. This also makes deletion detection
        # independent of later candidate-policy changes.
        candidates.update(self._state)
        return sorted(path for path in candidates if self._tracked_path(path))

    def _scan_workspace(self) -> dict[str, _Entry]:
        result: dict[str, _Entry] = {}
        next_stat_cache: dict[str, tuple[int, int, int, int, int, int]] = {}
        self._scan_count += 1
        for rel in self._workspace_candidates():
            opened = self._open_workspace_candidate(rel)
            if opened is None:
                continue
            metadata, file_fd, link_data = opened
            self._files_seen += 1
            signature = self._stat_signature(metadata)
            next_stat_cache[rel] = signature
            # Content from the preceding scan remains valid when inode,
            # size, mtime and ctime are all unchanged. This preserves
            # deletion/rollback detection while avoiding repeated reads.
            if self._stat_cache.get(rel) == signature and rel in self._state:
                if file_fd is not None:
                    os.close(file_fd)
                result[rel] = self._state[rel]
                self._cache_hits += 1
                continue
            entry = self._workspace_entry(rel, metadata, file_fd, link_data)
            if entry is not None:
                result[rel] = entry
        self._stat_cache = next_stat_cache
        return result

    @property
    def scan_stats(self) -> dict[str, Any]:
        return {
            "candidate_policy": (
                "git_cached_and_nonignored_untracked_workspace_bytes"
                if self._workspace_uses_git_candidates
                else (
                    "workspace_walk_without_symlink_dirs"
                    if self.baseline_source == "workspace"
                    else "git_cached_and_nonignored_untracked"
                )
            ),
            "baseline_source": self.baseline_source,
            "scan_count": self._scan_count,
            "files_seen": self._files_seen,
            "stat_cache_hits": self._cache_hits,
            "hashed_files": self._hashed_files,
            "hashed_bytes": self._hashed_bytes,
        }

    @property
    def last_capture(self) -> dict[str, Any]:
        """Return timing/result metadata for the most recent serialized scan."""

        return dict(self._last_capture)

    def _event_item(self, event_or_item: Mapping[str, Any] | None) -> Mapping[str, Any]:
        value = event_or_item or {}
        payload = value.get("payload")
        if isinstance(payload, Mapping) and isinstance(payload.get("item"), Mapping):
            return payload["item"]  # type: ignore[index]
        return value

    def _declared_changes(self, event_or_item: Mapping[str, Any] | None) -> dict[str, Mapping[str, Any]]:
        item = self._event_item(event_or_item)
        result: dict[str, Mapping[str, Any]] = {}
        for change in item.get("changes") or []:
            if not isinstance(change, Mapping) or not change.get("path"):
                continue
            raw = Path(str(change["path"]))
            if raw.is_absolute():
                try:
                    rel = Path(os.path.normpath(os.fspath(raw))).relative_to(self.repo).as_posix()
                except ValueError:
                    continue
            else:
                rel = Path(os.path.normpath(os.fspath(raw))).as_posix()
            if self._tracked_path(rel):
                result[rel] = change
        return result

    def _item_identity(self, seq: int, event_or_item: Mapping[str, Any] | None) -> tuple[str, str]:
        value = event_or_item or {}
        item = self._event_item(value)
        item_id = value.get("item_id") or item.get("id") or value.get("event_id") or f"seq-{seq}"
        action_type = value.get("action_type") or item.get("type") or value.get("kind") or "workspace_scan"
        return str(item_id), str(action_type)

    @staticmethod
    def _safe_item_dir(item_id: str) -> str:
        readable = re.sub(r"[^A-Za-z0-9_.-]+", "-", item_id).strip("-.")[:48] or "item"
        suffix = hashlib.sha256(item_id.encode("utf-8", errors="replace")).hexdigest()[:10]
        return f"{readable}-{suffix}"

    def scan_after(self, seq: int, item: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
        if self._closed:
            raise RuntimeError("SnapshotManager is closed")
        if not self._baseline_captured:
            self.capture_baseline()
        self._last_seq = max(self._last_seq, int(seq))
        item_id, action_type = self._item_identity(seq, item)
        declared = self._declared_changes(item)
        capture_started_monotonic_ns = time.monotonic_ns()
        capture_started_wall_time_ns = time.time_ns()
        current = self._scan_workspace()
        capture_ended_monotonic_ns = time.monotonic_ns()
        capture_ended_wall_time_ns = time.time_ns()
        changed = sorted(
            path
            for path in self._state.keys() | current.keys()
            if self._state.get(path) is None
            or current.get(path) is None
            or self._state[path].digest != current[path].digest
            or self._state[path].kind != current[path].kind
        )
        item_value = item or {}
        attribution_ambiguous = bool(
            item_value.get("_codexscope_attribution_ambiguous")
        )
        candidate_item_ids = sorted(
            {
                str(value)
                for value in item_value.get(
                    "_codexscope_attribution_candidate_item_ids", []
                )
                if value is not None
            }
        )
        self._last_capture = {
            "seq": int(seq),
            "item_id": item_id,
            "action_type": action_type,
            "capture_started_monotonic_ns": capture_started_monotonic_ns,
            "capture_ended_monotonic_ns": capture_ended_monotonic_ns,
            "capture_started_wall_time_ns": capture_started_wall_time_ns,
            "capture_ended_wall_time_ns": capture_ended_wall_time_ns,
            "changed_count": len(changed),
        }
        rows: list[dict[str, Any]] = []
        for rel in changed:
            before_entry = self._state.get(rel)
            after_entry = current.get(rel)
            before = self.latest.get(rel)
            after_rel: str | None = None
            if after_entry is not None and after_entry.kind == "regular" and after_entry.data is not None:
                destination = self.items_root / f"{int(seq):08d}-{self._safe_item_dir(item_id)}" / rel
                _write_private(destination, after_entry.data)
                after_rel = destination.relative_to(self.root).as_posix()
            self.latest[rel] = after_rel
            if after_entry is None:
                self._state.pop(rel, None)
                change_kind = "delete"
            else:
                self._state[rel] = after_entry
                change_kind = "create" if before_entry is None else "update"
            declared_change = declared.get(rel)
            if declared_change is not None:
                capture_source = "app_server_file_change"
            elif action_type == "filesystem_observation":
                capture_source = "filesystem_event_window"
            elif attribution_ambiguous:
                capture_source = "concurrent_item_boundary"
            else:
                capture_source = "workspace_hash_scan"
            row = {
                "seq": int(seq),
                "item_id": item_id,
                "action_type": action_type,
                "path": rel,
                "before": before,
                "after": after_rel,
                "before_sha256": before_entry.digest if before_entry else None,
                "after_sha256": after_entry.digest if after_entry else None,
                "kind": str(declared_change.get("kind")) if declared_change else change_kind,
                "reported_by_app_server": declared_change is not None,
                "capture_source": capture_source,
                "snapshot_omitted": after_entry is not None and after_entry.data is None,
                "capture_started_monotonic_ns": capture_started_monotonic_ns,
                "capture_ended_monotonic_ns": capture_ended_monotonic_ns,
                "capture_started_wall_time_ns": capture_started_wall_time_ns,
                "capture_ended_wall_time_ns": capture_ended_wall_time_ns,
            }
            if capture_source == "concurrent_item_boundary":
                row["attribution_ambiguous"] = True
                row["attribution_candidate_item_ids"] = candidate_item_ids
            if action_type == "filesystem_observation":
                row.update(
                    {
                        "filesystem_window_id": item_id,
                        "filesystem_event_seq_start": item.get(
                            "filesystem_event_seq_start"
                        ),
                        "filesystem_event_seq_end": item.get(
                            "filesystem_event_seq_end"
                        ),
                        "observed_from_monotonic_ns": item.get(
                            "observed_from_monotonic_ns"
                        ),
                        "observed_to_monotonic_ns": item.get(
                            "observed_to_monotonic_ns"
                        ),
                        "observed_from_wall_time_ns": item.get(
                            "observed_from_wall_time_ns"
                        ),
                        "observed_to_wall_time_ns": item.get(
                            "observed_to_wall_time_ns"
                        ),
                    }
                )
            self._index_fp.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
            rows.append(row)
        return rows

    def capture_after(self, seq: int, item: Mapping[str, Any]) -> list[dict[str, Any]]:
        return self.scan_after(seq, item)

    def close(self) -> None:
        if self._closed:
            return
        try:
            if self._baseline_captured:
                # Last-resort reconciliation catches writes from callers that did
                # not yet invoke capture_after for every command/MCP completion.
                self.scan_after(self._last_seq + 1, {"id": "session-final", "type": "final_reconcile"})
        finally:
            atomic_json_dump(self.root / "reconciliation_summary.json", self.scan_stats)
            self._index_fp.close()
            self._closed = True
