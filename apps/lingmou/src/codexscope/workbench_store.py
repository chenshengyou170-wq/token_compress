"""Durable append-only event journal for the Lingmou web workbench.

The current process retains a rich live copy.  The JSONL replay copy always
scrubs credentials and, unless explicitly opted in, replaces conversation text
with hashes and lengths.  JSONL keeps the workbench usable on Python builds
that don't bundle the optional ``sqlite3`` extension.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import threading
import time
import uuid
from collections import deque
from pathlib import Path
from typing import Any, Mapping

from .investigation import (
    FileSnapshotter,
    HistoryUnavailable,
    ProjectHistoryIndex,
    run_id_for,
)
from .redaction import redact_event, RedactionLimits, DEFAULT_LIMITS
from .storage import append_jsonl_locked, atomic_json_dump


_CONVERSATION_KINDS = {
    "user_prompt",
    "agent_message",
    "agent_delta",
    "plan",
    "plan_delta",
    "reasoning_summary",
}
_TEXT_KEYS = frozenset({"text", "content", "delta", "message", "prompt"})


def _digest(value: str) -> dict[str, Any]:
    encoded = value.encode("utf-8", errors="replace")
    return {
        "omitted": True,
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "utf8_bytes": len(encoded),
        "characters": len(value),
    }


def _omit_conversation(value: Any, *, key: str | None = None) -> Any:
    if isinstance(value, str) and key in _TEXT_KEYS:
        return _digest(value)
    if isinstance(value, dict):
        return {
            str(item_key): _omit_conversation(item, key=str(item_key))
            for item_key, item in value.items()
        }
    if isinstance(value, list):
        return [_omit_conversation(item, key=key) for item in value]
    return value


class WorkbenchEventStore:
    """Private JSONL event stream plus an atomic small state document."""

    def __init__(
        self,
        path: Path | str,
        *,
        persist_conversation: bool = False,
        memory_events: int = 5_000,
        project_root: Path | str | None = None,
        history_path: Path | str | None = None,
        history_discovery: bool = True,
        run_id: str | None = None,
        forensic_key: bytes | None = None,
    ) -> None:
        if memory_events < 100:
            raise ValueError("memory_events must be at least 100")
        if persist_conversation and forensic_key is not None:
            raise ValueError(
                "persist_conversation and forensic_key are mutually exclusive; "
                "forensic mode keeps full context only in the encrypted capsule"
            )
        self.path = Path(path).expanduser().resolve()
        self.state_path = self.path.with_name("workbench_state.json")
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            self.path.parent.chmod(0o700)
        except OSError:
            pass
        self._validate_or_create(self.path)
        self.persist_conversation = persist_conversation
        self.forensic_mode = forensic_key is not None
        self.project_root = (
            Path(project_root).expanduser().resolve()
            if project_root is not None
            else None
        )
        self.history_discovery = bool(history_discovery)
        self.run_id = run_id or run_id_for(self.path.parent)
        self._snapshotter = (
            FileSnapshotter(self.project_root) if self.project_root is not None else None
        )
        self._history: ProjectHistoryIndex | None = None
        self._history_error: str | None = None
        self._lock = threading.RLock()
        self._memory: deque[dict[str, Any]] = deque(maxlen=memory_events)
        self._subscribers: set[Any] = set()
        self._persisted = self._load_events()
        self._event_ids = {
            str(event.get("event_id"))
            for event in self._persisted
            if event.get("event_id") is not None
        }
        self._last_seq = max(
            (int(event.get("seq") or 0) for event in self._persisted), default=0
        )
        self._state = self._load_state()
        self._closed = False
        if self.project_root is not None:
            try:
                self._history = ProjectHistoryIndex(
                    self.project_root,
                    path=history_path,
                    forensic_key=forensic_key,
                )
                self._history.register_run(
                    self.run_id,
                    self.path.parent,
                    journal_path=self.path,
                    manifest=self._load_manifest(),
                )
                self._history.ingest_run(
                    self.path.parent,
                    self._persisted,
                    run_id=self.run_id,
                )
                if self.history_discovery:
                    self._history.sync_discovered_runs(
                        current_run_dir=self.path.parent,
                    )
            except Exception as exc:
                self._history_error = str(exc)
                if self._history is not None:
                    try:
                        self._history.close()
                    except Exception:
                        pass
                self._history = None
                if forensic_key is not None:
                    raise

    @staticmethod
    def _validate_or_create(path: Path) -> None:
        if path.exists() or path.is_symlink():
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise OSError(f"refusing non-regular event journal: {path}")
            if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
                raise OSError(f"event journal is owned by another user: {path}")
            path.chmod(0o600)
            return
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, 0o600)
        os.close(descriptor)

    def _load_events(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        with self.path.open("r", encoding="utf-8", errors="replace") as source:
            lines = source.readlines()
        for index, line in enumerate(lines):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                # A power loss can leave only the final append incomplete.
                if index == len(lines) - 1:
                    break
                raise ValueError(f"invalid workbench journal line {index + 1}")
            if isinstance(value, dict) and type(value.get("seq")) is int:
                rows.append(value)
        rows.sort(key=lambda event: int(event["seq"]))
        return rows

    def _load_state(self) -> dict[str, Any]:
        if not self.state_path.exists():
            return {}
        if self.state_path.is_symlink() or not self.state_path.is_file():
            raise OSError(f"refusing non-regular workbench state: {self.state_path}")
        try:
            value = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return value if isinstance(value, dict) else {}

    def _load_manifest(self) -> dict[str, Any]:
        path = self.path.parent / "manifest.json"
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return value if isinstance(value, dict) else {}

    @property
    def last_seq(self) -> int:
        with self._lock:
            return self._last_seq

    def append(
        self,
        kind: str,
        *,
        title: str,
        summary: Any = "",
        payload: Any | None = None,
        explanation: Mapping[str, Any] | None = None,
        evidence: Mapping[str, Any] | None = None,
        step: Mapping[str, Any] | None = None,
        source: str = "codex_app_server",
        status: str = "info",
        thread_id: str | None = None,
        turn_id: str | None = None,
        item_id: str | None = None,
        event_id: str | None = None,
        occurred_at: float | None = None,
    ) -> dict[str, Any]:
        timestamp = time.time() if occurred_at is None else float(occurred_at)
        identifier = event_id or str(uuid.uuid4())
        live_summary = redact_event(summary)
        # Locally built trees are validated to <= 4096 predicate nodes / depth 16.
        # Keep those trees intact; untrusted hook events retain the smaller budget.
        trace_limits = RedactionLimits(max_depth=64, max_fields=100000, max_nodes=160000,
                                       max_list_items=512, max_string_bytes=8192)
        limits = trace_limits if kind in {"policy_evaluation", "policy_decision", "policy_block"} else DEFAULT_LIMITS
        live_payload = redact_event(payload if payload is not None else {}, limits=limits)
        live_explanation = redact_event(dict(explanation or {}))
        live_evidence = redact_event(dict(evidence or {}))
        live_step = redact_event(dict(step or {}))
        file_snapshots = (
            self._snapshotter.capture(
                explanation=live_explanation,
                evidence=live_evidence,
                payload=live_payload,
                kind=kind,
                status=status,
                observed_at=timestamp,
            )
            if self._snapshotter is not None
            else []
        )
        conversational = kind in _CONVERSATION_KINDS
        persisted_text = not conversational or self.persist_conversation
        persisted_summary = live_summary
        persisted_payload = live_payload
        if conversational and not self.persist_conversation:
            persisted_summary = (
                _digest(live_summary)
                if isinstance(live_summary, str)
                else _omit_conversation(live_summary)
            )
            persisted_payload = _omit_conversation(live_payload)

        with self._lock:
            if self._closed:
                raise RuntimeError("workbench event store is closed")
            if identifier in self._event_ids:
                raise ValueError(f"duplicate workbench event id: {identifier}")
            self._last_seq += 1
            common = {
                "seq": self._last_seq,
                "event_id": identifier,
                "occurred_at": timestamp,
                "kind": kind,
                "source": source,
                "status": status,
                "thread_id": thread_id,
                "turn_id": turn_id,
                "item_id": item_id,
                "title": str(redact_event(title)),
                "explanation": live_explanation,
                "evidence": live_evidence,
                "step": live_step,
                "file_snapshots": file_snapshots,
                "privacy": {
                    "credentials": "redacted",
                    "conversation_persisted": persisted_text,
                    "forensic_context_encrypted": self.forensic_mode,
                },
            }
            persisted = {
                **common,
                "summary": persisted_summary,
                "payload": persisted_payload,
            }
            append_jsonl_locked(self.path, persisted)
            self._persisted.append(persisted)
            self._event_ids.add(identifier)
            event = {**common, "summary": live_summary, "payload": live_payload}
            self._memory.append(event)
            forensic_events = (
                [
                    dict(candidate)
                    for candidate in self._memory
                    if candidate.get("thread_id") == thread_id
                    and candidate.get("turn_id") == turn_id
                    and candidate.get("kind") in _CONVERSATION_KINDS
                ]
                if self.forensic_mode
                and kind == "turn"
                and status in {"completed", "failed", "interrupted", "blocked"}
                and turn_id
                else None
            )
            subscribers = tuple(self._subscribers)

        if self._history is not None:
            try:
                self._history.index_event(
                    self.run_id,
                    persisted,
                    forensic_events=forensic_events,
                )
                self._history_error = None
            except Exception as exc:
                # The SQLite index is disposable.  A failure must never roll
                # back the append-only source journal or interrupt the Agent.
                self._history_error = str(exc)

        for queue in subscribers:
            try:
                queue.put_nowait(event)
            except Exception:
                try:
                    queue.get_nowait()
                    queue.put_nowait(event)
                except Exception:
                    pass
        return event

    def history_status(self) -> dict[str, Any]:
        history = self._history
        return {
            "available": history is not None,
            "run_id": self.run_id,
            "project_root": os.fspath(self.project_root) if self.project_root else None,
            "index_path": os.fspath(history.path) if history else None,
            "error": self._history_error,
            "source_of_truth": os.fspath(self.path),
            "scope": "project" if self.history_discovery else "run",
        }

    def history_runs(self, *, limit: int = 100) -> dict[str, Any]:
        if self._history is None:
            raise HistoryUnavailable(self._history_error or "project history is unavailable")
        return self._history.runs(limit=limit)

    def investigations(self, *, limit: int = 50) -> dict[str, Any]:
        if self._history is None:
            raise HistoryUnavailable(self._history_error or "project history is unavailable")
        return self._history.investigations(limit=limit)

    def investigation(self, investigation_id: str) -> dict[str, Any] | None:
        if self._history is None:
            raise HistoryUnavailable(self._history_error or "project history is unavailable")
        return self._history.investigation(investigation_id)

    def rebuild_history(self) -> dict[str, Any]:
        if self._history is None:
            raise HistoryUnavailable(self._history_error or "project history is unavailable")
        result = self._history.rebuild(
            current_run_dir=self.path.parent,
            discover_runs=self.history_discovery,
        )
        self._history_error = None
        return result

    def context_capsule(
        self,
        run_id: str,
        thread_id: str,
        turn_id: str,
        *,
        include_forensic: bool = False,
    ) -> dict[str, Any] | None:
        if self._history is None:
            raise HistoryUnavailable(self._history_error or "project history is unavailable")
        return self._history.context_capsule(
            run_id,
            thread_id,
            turn_id,
            include_forensic=include_forensic,
        )

    def events(self, *, after_seq: int = 0, limit: int = 1_000) -> list[dict[str, Any]]:
        if after_seq < 0:
            raise ValueError("after_seq cannot be negative")
        if not 1 <= limit <= 5_000:
            raise ValueError("limit must be between 1 and 5000")
        with self._lock:
            persisted = [
                event for event in self._persisted if int(event["seq"]) > after_seq
            ][:limit]
            rich = {int(event["seq"]): event for event in self._memory}
            return [dict(rich.get(int(event["seq"]), event)) for event in persisted]

    def contains_event_id(self, event_id: str) -> bool:
        with self._lock:
            return event_id in self._event_ids

    def set_state(self, key: str, value: Any) -> None:
        with self._lock:
            if self._closed:
                raise RuntimeError("workbench event store is closed")
            self._state[key] = redact_event(value)
            atomic_json_dump(self.state_path, self._state)

    def get_state(self, key: str, default: Any = None) -> Any:
        with self._lock:
            return self._state.get(key, default)

    def subscribe(self, *, maxsize: int = 512) -> Any:
        import asyncio

        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=maxsize)
        with self._lock:
            self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: Any) -> None:
        with self._lock:
            self._subscribers.discard(queue)

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._subscribers.clear()
            history = self._history
            self._history = None
        if history is not None:
            history.close()

    def __enter__(self) -> "WorkbenchEventStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


__all__ = ["WorkbenchEventStore"]
