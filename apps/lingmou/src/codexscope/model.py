from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any, Mapping


SCHEMA_VERSION = "1.2"


class EventSource(StrEnum):
    APP_SERVER = "app_server"
    HOOK = "hook"
    OTEL = "otel"
    OS = "os"
    RUNTIME = "runtime"
    DERIVED = "derived"


class EventPhase(StrEnum):
    POINT = "point"
    STARTED = "started"
    DELTA = "delta"
    COMPLETED = "completed"
    FAILED = "failed"
    INTERRUPTED = "interrupted"
    INCOMPLETE = "incomplete"


class EventStatus(StrEnum):
    UNKNOWN = "unknown"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    INTERRUPTED = "interrupted"
    CANCELLED = "cancelled"
    INCOMPLETE = "incomplete"
    DECLINED = "declined"
    BLOCKED = "blocked"


@dataclass(frozen=True, slots=True)
class FunctionRef:
    path: str
    name: str
    start_line: int | None = None
    end_line: int | None = None
    role: str | None = None
    confidence: float = 1.0
    evidence: str | None = None


@dataclass(slots=True)
class CanonicalEvent:
    """Versioned, source-agnostic representation of one observed action."""

    event_id: str
    seq: int
    source: EventSource
    source_event: str
    phase: EventPhase = EventPhase.POINT
    action_type: str = "unknown"
    actor: str = "main_agent"
    timestamp_start_ns: int | None = None
    timestamp_end_ns: int | None = None
    wall_time_start_ns: int | None = None
    wall_time_end_ns: int | None = None
    session_id: str | None = None
    thread_id: str | None = None
    turn_id: str | None = None
    item_id: str | None = None
    # App-server ``processId`` is a client-supplied, connection-scoped handle,
    # not an operating-system PID. Keep it opaque and separate from runtime
    # process identity.
    process_handle: str | None = None
    process_id: int | None = None
    process_id_verified: bool = False
    parent_process_id: int | None = None
    ancestor_process_ids: list[int] = field(default_factory=list)
    process_instance_id: str | None = None
    runtime_thread_id: int | None = None
    language: str | None = None
    call_id: str | None = None
    parent_call_id: str | None = None
    caller_event_id: str | None = None
    tool_use_id: str | None = None
    hook_run_id: str | None = None
    hook_event_name: str | None = None
    related_event_id: str | None = None
    correlation_kind: str | None = None
    correlation_evidence: str | None = None
    correlation_confidence: float | None = None
    parent_event_id: str | None = None
    tool: str | None = None
    operation: str | None = None
    cwd: str | None = None
    status: EventStatus = EventStatus.UNKNOWN
    approval: str | None = None
    exit_code: int | None = None
    duration_ms: float | None = None
    targets: list[str] = field(default_factory=list)
    affected_files: list[str] = field(default_factory=list)
    affected_functions: list[FunctionRef] = field(default_factory=list)
    executed_functions: list[FunctionRef] = field(default_factory=list)
    trigger: str | None = None
    trigger_confidence: float | None = None
    payload: dict[str, Any] = field(default_factory=dict)
    anomalies: list[str] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION

    def as_dict(self, *, include_payload: bool = True) -> dict[str, Any]:
        data = asdict(self)
        data["source"] = self.source.value
        data["phase"] = self.phase.value
        data["status"] = self.status.value
        if not include_payload:
            data.pop("payload", None)
        return data

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CanonicalEvent":
        data = dict(value)
        data["source"] = EventSource(data.get("source", EventSource.DERIVED))
        data["phase"] = EventPhase(data.get("phase", EventPhase.POINT))
        data["status"] = EventStatus(data.get("status", EventStatus.UNKNOWN))
        data["affected_functions"] = [
            item if isinstance(item, FunctionRef) else FunctionRef(**item)
            for item in data.get("affected_functions", [])
        ]
        data["executed_functions"] = [
            item if isinstance(item, FunctionRef) else FunctionRef(**item)
            for item in data.get("executed_functions", [])
        ]
        return cls(**data)
