from __future__ import annotations

import hashlib
import heapq
import re
from bisect import bisect_left, bisect_right
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from .function_trace import (
    correlate_function_events,
    normalize_function_rows,
    read_function_rows,
)
from .model import CanonicalEvent, EventPhase, EventSource, EventStatus
from .storage import RunLayout, atomic_json_dump, iter_jsonl, json_load, write_jsonl


_ITEM_TYPES = {
    "commandExecution": "command_execution",
    "fileChange": "file_change",
    "mcpToolCall": "mcp_tool_call",
    "dynamicToolCall": "dynamic_tool_call",
    "collabAgentToolCall": "collab_agent_tool_call",
    "collabToolCall": "collab_agent_tool_call",
    "subAgentActivity": "subagent_activity",
    "webSearch": "web_search",
    "contextCompaction": "context_compaction",
    "userMessage": "user_message",
    "agentMessage": "agent_message",
    "plan": "plan",
    "reasoning": "reasoning",
    "imageView": "image_view",
    "imageGeneration": "image_generation",
    "sleep": "sleep",
    "enteredReviewMode": "entered_review_mode",
    "exitedReviewMode": "exited_review_mode",
    "hookPrompt": "hook_prompt",
}

_ITEM_DELTA_METHODS = frozenset(
    {
        "item/agentMessage/delta",
        "item/plan/delta",
        "item/commandExecution/outputDelta",
        "item/fileChange/outputDelta",
        "item/reasoning/summaryTextDelta",
        "item/reasoning/textDelta",
    }
)
_ITEM_UPDATE_METHODS = _ITEM_DELTA_METHODS | frozenset(
    {
        "item/fileChange/patchUpdated",
        "item/reasoning/summaryPartAdded",
        "item/mcpToolCall/progress",
        "item/commandExecution/terminalInteraction",
    }
)
_OUTPUT_DELTA_METHODS = frozenset(
    {
        "item/commandExecution/outputDelta",
        "item/fileChange/outputDelta",
    }
)
_APPROVAL_REQUEST_METHODS = frozenset(
    {
        "item/commandExecution/requestApproval",
        "item/fileChange/requestApproval",
        "item/permissions/requestApproval",
        # Compatibility requests retained by app-server 0.144.1.
        "applyPatchApproval",
        "execCommandApproval",
    }
)

_TOOL_ACTION_TYPES = frozenset(
    {
        "command_execution",
        "file_change",
        "mcp_tool_call",
        "dynamic_tool_call",
        "collab_agent_tool_call",
        "image_view",
        "image_generation",
    }
)
_TOOL_SCOPED_HOOKS = frozenset(
    {"PreToolUse", "PermissionRequest", "PostToolUse"}
)
_FILESYSTEM_CORRELATION_TARGETS = frozenset(
    {
        "command_execution",
        "file_change",
        "mcp_tool_call",
        "dynamic_tool_call",
        "collab_agent_tool_call",
        "image_generation",
    }
)
_FILESYSTEM_GAP_OPERATIONS = frozenset(
    {
        "queue_overflow",
        "limit_reached",
        "watch_limit",
        "watch_error",
        "delete_self",
        "move_self",
        "unmount",
    }
)
_OS_AUDIT_SCHEMA = "codexscope.os_audit.v1"
_OS_AUDIT_GAP_MARKERS = frozenset(
    {
        "capture_error",
        "collector_error",
        "dropped",
        "event_limit",
        "limit_reached",
        "parse_error",
        "parse_gap",
        "queue_overflow",
        "truncated",
    }
)
_OS_AUDIT_TOOL_TARGETS = _FILESYSTEM_CORRELATION_TARGETS
_OTEL_TRACE_SCHEMA = "codexscope.otel.trace.v1"
_OS_READ_SYSCALLS = frozenset(
    {
        "read",
        "readv",
        "pread",
        "pread64",
        "preadv",
        "preadv2",
        "recv",
        "recvfrom",
        "recvmsg",
        "recvmmsg",
    }
)
_OS_WRITE_SYSCALLS = frozenset(
    {
        "write",
        "writev",
        "pwrite",
        "pwrite64",
        "pwritev",
        "pwritev2",
        "send",
        "sendto",
        "sendmsg",
        "sendmmsg",
        "truncate",
        "ftruncate",
        "rename",
        "renameat",
        "renameat2",
        "unlink",
        "unlinkat",
        "mkdir",
        "mkdirat",
        "rmdir",
        "link",
        "linkat",
        "symlink",
        "symlinkat",
    }
)
_HOOK_EVENT_NAMES = {
    "sessionstart": "SessionStart",
    "userpromptsubmit": "UserPromptSubmit",
    "pretooluse": "PreToolUse",
    "permissionrequest": "PermissionRequest",
    "posttooluse": "PostToolUse",
    "precompact": "PreCompact",
    "postcompact": "PostCompact",
    "subagentstart": "SubagentStart",
    "subagentstop": "SubagentStop",
    "stop": "Stop",
}

_TOKEN_USAGE_FIELDS = {
    "cachedInputTokens": "cached_input_tokens",
    "inputTokens": "input_tokens",
    "outputTokens": "output_tokens",
    "reasoningOutputTokens": "reasoning_output_tokens",
    "totalTokens": "total_tokens",
}

_RequestKey = tuple[str | None, str, int | str]
_ItemKey = tuple[str | None, str | None, str | None, str]


def _stable_id(prefix: str, *parts: object) -> str:
    material = "\x1f".join(str(part) for part in parts)
    digest = hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()[:20]
    return f"{prefix}:{digest}"


def _normalize_hook_name(value: object) -> str:
    text = str(value or "unknown")
    key = re.sub(r"[^a-z0-9]", "", text.casefold())
    return _HOOK_EVENT_NAMES.get(key, text)


def _tool_use_id(*values: object) -> str | None:
    """Return a tool correlation id from supported snake/camel-case fields."""

    for value in values:
        if not isinstance(value, dict):
            continue
        for key in ("tool_use_id", "toolUseId"):
            candidate = value.get(key)
            if candidate is not None and str(candidate):
                return str(candidate)
    return None


def _mono_ns(row: dict[str, Any]) -> int:
    return int(row.get("mono_ns") or row.get("monotonic_ns") or 0)


def _wall_ns(row: dict[str, Any]) -> int:
    if row.get("wall_time_ns") is not None:
        return int(row["wall_time_ns"])
    if row.get("wall_time") is not None:
        return int(float(row["wall_time"]) * 1_000_000_000)
    return 0


def _status(value: object) -> EventStatus:
    normalized = str(value or "unknown").replace("_", "").lower()
    return {
        "inprogress": EventStatus.RUNNING,
        "running": EventStatus.RUNNING,
        "completed": EventStatus.COMPLETED,
        "success": EventStatus.COMPLETED,
        "succeeded": EventStatus.COMPLETED,
        "failed": EventStatus.FAILED,
        "error": EventStatus.FAILED,
        "errored": EventStatus.FAILED,
        "interrupted": EventStatus.INTERRUPTED,
        "cancelled": EventStatus.CANCELLED,
        "canceled": EventStatus.CANCELLED,
        "declined": EventStatus.DECLINED,
        "denied": EventStatus.DECLINED,
        "blocked": EventStatus.BLOCKED,
        "stopped": EventStatus.INTERRUPTED,
        "aborted": EventStatus.CANCELLED,
        "timedout": EventStatus.CANCELLED,
    }.get(normalized, EventStatus.UNKNOWN)


def _terminal_phase(status: EventStatus) -> EventPhase:
    if status == EventStatus.FAILED:
        return EventPhase.FAILED
    if status in {EventStatus.INTERRUPTED, EventStatus.CANCELLED, EventStatus.DECLINED}:
        return EventPhase.INTERRUPTED
    if status == EventStatus.INCOMPLETE:
        return EventPhase.INCOMPLETE
    if status in {EventStatus.RUNNING, EventStatus.UNKNOWN}:
        return EventPhase.INCOMPLETE
    return EventPhase.COMPLETED


def _thread_turn(params: dict[str, Any], item: dict[str, Any] | None = None) -> tuple[str | None, str | None]:
    item = item or {}
    thread_id = params.get("threadId") or item.get("threadId")
    turn_id = params.get("turnId") or item.get("turnId")
    return (
        str(thread_id) if thread_id is not None else None,
        str(turn_id) if turn_id is not None else None,
    )


def _request_id_key(
    value: object, connection_id: object = None
) -> _RequestKey | None:
    # bool is an int subclass but is not a valid Codex RequestId.
    if type(value) is int:
        return (
            str(connection_id) if connection_id is not None else None,
            "int",
            value,
        )
    if isinstance(value, str):
        return (
            str(connection_id) if connection_id is not None else None,
            "str",
            value,
        )
    return None


def _item_key(
    row: dict[str, Any],
    params: dict[str, Any],
    item_id: object,
    item: dict[str, Any] | None = None,
) -> _ItemKey:
    thread_id, turn_id = _thread_turn(params, item)
    connection_id = row.get("connection_id")
    return (
        str(connection_id) if connection_id is not None else None,
        thread_id,
        turn_id,
        str(item_id),
    )


def _compatible_item_key(candidate: _ItemKey, observed: _ItemKey) -> bool:
    """Match partial routing scopes without ever crossing a connection."""

    if candidate[0] != observed[0] or candidate[3] != observed[3]:
        return False
    return all(
        left is None or right is None or left == right
        for left, right in zip(candidate[1:3], observed[1:3])
    )


def _resolve_item_key(
    observed: _ItemKey, *stores: dict[_ItemKey, Any]
) -> _ItemKey:
    if any(observed in store for store in stores):
        return observed
    candidates = {
        candidate
        for store in stores
        for candidate in store
        if _compatible_item_key(candidate, observed)
    }
    # A single partial-scope match is safe. Ambiguity is deliberately left
    # unresolved so two turns or threads can never consume each other's data.
    return next(iter(candidates)) if len(candidates) == 1 else observed


def _token_usage_breakdown(value: object) -> dict[str, int] | None:
    if not isinstance(value, dict):
        return None
    result: dict[str, int] = {}
    for source_key, target_key in _TOKEN_USAGE_FIELDS.items():
        count = value.get(source_key)
        if type(count) is not int or count < 0:
            return None
        result[target_key] = count
    return result


def _normalize_thread_token_usage(value: object) -> dict[str, Any] | None:
    """Validate and snake-case the stable token-usage protocol fields."""

    if not isinstance(value, dict):
        return None
    last = _token_usage_breakdown(value.get("last"))
    total = _token_usage_breakdown(value.get("total"))
    if last is None or total is None:
        return None
    result: dict[str, Any] = {"last": last, "total": total}
    if "modelContextWindow" in value:
        context_window = value["modelContextWindow"]
        if context_window is not None and (
            type(context_window) is not int or context_window < 0
        ):
            return None
        result["model_context_window"] = context_window
    return result


def _token_usage_summary(events: Iterable[CanonicalEvent]) -> dict[str, Any]:
    token_events = [event for event in events if event.action_type == "token_usage"]
    latest: dict[str, dict[str, Any]] = {}
    invalid_updates = 0
    for event in token_events:
        usage = event.payload.get("token_usage")
        if not isinstance(usage, dict):
            invalid_updates += 1
            continue
        # Thread ids are required by the app-server protocol.  Keeping a
        # per-event fallback avoids merging malformed records into one bucket.
        key = event.thread_id or f"unknown:{event.event_id}"
        latest[key] = {
            "thread_id": event.thread_id,
            "turn_id": event.turn_id,
            "event_id": event.event_id,
            **usage,
        }

    latest_rows = sorted(
        latest.values(), key=lambda item: (str(item.get("thread_id") or ""), item["event_id"])
    )
    aggregate_total: dict[str, int] | None = None
    if latest_rows:
        aggregate_total = {
            target_key: sum(
                int(item["total"][target_key]) for item in latest_rows
            )
            for target_key in _TOKEN_USAGE_FIELDS.values()
        }
    return {
        "updates": len(token_events),
        "valid_updates": len(token_events) - invalid_updates,
        "invalid_updates": invalid_updates,
        "latest_by_thread": latest_rows,
        "aggregate_total": aggregate_total,
        "aggregate_semantics": "sum_of_latest_cumulative_total_per_thread",
    }


def _otel_number(value: object) -> float | None:
    if type(value) in {int, float}:
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _otel_truth(value: object) -> bool | None:
    if type(value) is bool:
        return value
    normalized = str(value or "").casefold()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    return None


def _otel_event_status(name: str, attributes: dict[str, Any]) -> EventStatus:
    if name == "codex.tool_result":
        success = _otel_truth(attributes.get("success"))
        if success is True:
            return EventStatus.COMPLETED
        if success is False:
            return EventStatus.FAILED
    if name == "codex.sandbox_outcome":
        outcome = str(attributes.get("outcome") or "").casefold()
        if any(word in outcome for word in ("declin", "den", "block")):
            return EventStatus.DECLINED
        if any(word in outcome for word in ("fail", "error", "violation")):
            return EventStatus.FAILED
        if outcome:
            return EventStatus.COMPLETED
    if name == "codex.api_request":
        code = _otel_number(attributes.get("http.response.status_code"))
        if code is not None:
            return (
                EventStatus.COMPLETED
                if 200 <= code < 300
                else EventStatus.FAILED
            )
    kind = str(attributes.get("event.kind") or "").casefold()
    if any(word in kind for word in ("failed", "error", "cancel")):
        return EventStatus.FAILED
    return EventStatus.COMPLETED


def _otel_action_type(name: str, record_kind: str) -> str:
    if record_kind == "span":
        return "harness_span"
    return {
        "codex.api_request": "api_request",
        "codex.conversation_starts": "conversation_start",
        "codex.sandbox_outcome": "sandbox_outcome",
        "codex.sse_event": "model_stream_event",
        "codex.startup_phase": "startup_phase",
        "codex.tool_result": "tool_result",
        "codex.turn_ttft": "turn_ttft",
        "codex.user_prompt": "user_prompt",
        "codex.websocket_connect": "websocket_event",
        "codex.websocket_event": "websocket_event",
        "codex.websocket_request": "websocket_event",
    }.get(
        name,
        "plugin_event" if name.startswith("codex.plugin_install_") else "harness_event",
    )


def normalize_otel_rows(
    rows: Iterable[dict[str, Any]],
) -> tuple[list[CanonicalEvent], dict[str, Any]]:
    """Normalize the bounded trace-safe rows written by ``OtelTraceCollector``."""

    events: list[CanonicalEvent] = []
    raw_records = 0
    invalid_records = 0
    kind_counts: dict[str, int] = {}
    name_counts: dict[str, int] = {}
    for row_index, row in enumerate(rows, start=1):
        raw_records += 1
        if row.get("schema_version") != _OTEL_TRACE_SCHEMA:
            invalid_records += 1
            continue
        record_kind = str(row.get("record_kind") or "")
        if record_kind not in {"span", "event"}:
            invalid_records += 1
            continue
        name = str(row.get("name") or "unknown")
        attributes_value = row.get("attributes")
        attributes = (
            dict(attributes_value) if isinstance(attributes_value, dict) else {}
        )
        trace_id = str(row.get("trace_id") or "")
        span_id = str(row.get("span_id") or "")
        parent_span_id = str(row.get("parent_span_id") or "")
        if record_kind == "span":
            start_ns = row.get("start_time_unix_nano")
            end_ns = row.get("end_time_unix_nano")
            discriminator: object = "span"
        else:
            start_ns = row.get("time_unix_nano")
            end_ns = start_ns
            discriminator = row.get("event_index", row_index)
        if type(start_ns) is not int or start_ns < 0:
            start_ns = None
        if type(end_ns) is not int or end_ns < 0:
            end_ns = None

        event_id = (
            _stable_id("otel-span", trace_id, span_id)
            if record_kind == "span"
            else _stable_id(
                "otel-event", trace_id, span_id, discriminator, name
            )
        )
        status_value = row.get("status")
        otlp_status = dict(status_value) if isinstance(status_value, dict) else {}
        if record_kind == "span":
            code = str(otlp_status.get("code") or "").casefold()
            status = (
                EventStatus.FAILED
                if code in {"2", "error", "status_code_error"}
                else EventStatus.COMPLETED
            )
            phase = (
                EventPhase.FAILED
                if status == EventStatus.FAILED
                else EventPhase.COMPLETED
            )
        else:
            status = _otel_event_status(name, attributes)
            phase = (
                EventPhase.FAILED
                if status == EventStatus.FAILED
                else EventPhase.POINT
            )

        duration = _otel_number(attributes.get("duration_ms"))
        if duration is None and start_ns is not None and end_ns is not None:
            duration = max(0.0, (end_ns - start_ns) / 1_000_000)
        conversation_id = attributes.get("conversation.id")
        call_id = attributes.get("call_id")
        tool_name = attributes.get("tool_name")
        parent_event_id: str | None = None
        if record_kind == "event":
            parent_event_id = _stable_id("otel-span", trace_id, span_id)
        elif parent_span_id:
            parent_event_id = _stable_id("otel-span", trace_id, parent_span_id)

        events.append(
            CanonicalEvent(
                event_id=event_id,
                seq=row_index,
                source=EventSource.OTEL,
                source_event=name,
                phase=phase,
                action_type=_otel_action_type(name, record_kind),
                actor="codex_harness",
                wall_time_start_ns=start_ns,
                wall_time_end_ns=end_ns,
                session_id=(
                    str(conversation_id) if conversation_id is not None else None
                ),
                thread_id=(
                    str(conversation_id) if conversation_id is not None else None
                ),
                call_id=str(call_id) if call_id is not None else None,
                parent_event_id=parent_event_id,
                tool=str(tool_name) if tool_name is not None else None,
                operation=name,
                status=status,
                duration_ms=duration,
                payload={
                    "trace_id": trace_id or None,
                    "span_id": span_id or None,
                    "parent_span_id": parent_span_id or None,
                    "record_kind": record_kind,
                    "attributes": attributes,
                    "resource": (
                        dict(row["resource"])
                        if isinstance(row.get("resource"), dict)
                        else {}
                    ),
                    "scope": (
                        dict(row["scope"])
                        if isinstance(row.get("scope"), dict)
                        else {}
                    ),
                    "otlp_status": otlp_status,
                },
            )
        )
        kind_counts[record_kind] = kind_counts.get(record_kind, 0) + 1
        name_counts[name] = name_counts.get(name, 0) + 1
    return events, {
        "raw_records": raw_records,
        "valid_records": len(events),
        "invalid_records": invalid_records,
        "kind_counts": dict(sorted(kind_counts.items())),
        "name_counts": dict(sorted(name_counts.items())),
        "content_capture": False,
    }


def _targets_from_command_actions(item: dict[str, Any]) -> list[str]:
    found: list[str] = []
    for action in item.get("commandActions") or []:
        if not isinstance(action, dict):
            continue
        path = action.get("path")
        if path and str(path) not in found:
            found.append(str(path))
    return found


def _item_event(
    row: dict[str, Any],
    item: dict[str, Any],
    start_row: dict[str, Any] | None,
    output: str,
    updates: list[dict[str, Any]],
    parent_event_id: str | None,
) -> CanonicalEvent:
    params = (row.get("message") or {}).get("params") or {}
    item_id = str(item.get("id") or f"seq-{row.get('seq', 0)}")
    thread_id, turn_id = _thread_turn(params, item)
    item_type = str(item.get("type") or "unknown")
    action_type = _ITEM_TYPES.get(item_type, _camel_to_snake(item_type))
    has_status = "status" in item
    raw_status = _status(item.get("status"))
    status = raw_status if has_status else EventStatus.COMPLETED
    if status in {EventStatus.RUNNING, EventStatus.UNKNOWN}:
        status = EventStatus.INCOMPLETE
    start = start_row or row
    payload: dict[str, Any] = {"item": item, "_source_seq": row.get("seq")}
    start_params = ((start.get("message") or {}).get("params") or {})
    if isinstance(start_params, dict) and start_params.get("startedAtMs") is not None:
        payload["startedAtMs"] = start_params["startedAtMs"]
    if params.get("completedAtMs") is not None:
        payload["completedAtMs"] = params["completedAtMs"]
    if output and item.get("aggregatedOutput") is None:
        payload["output"] = output
    if output:
        payload["output_delta"] = output
    if updates:
        payload["updates"] = updates
    connection_id = row.get("connection_id")
    event_id = (
        f"item:{item_id}"
        if connection_id is None
        else _stable_id("item", connection_id, thread_id, turn_id, item_id)
    )
    event = CanonicalEvent(
        event_id=event_id,
        seq=int(row.get("seq") or 0),
        source=EventSource.APP_SERVER,
        source_event="item/completed",
        phase=_terminal_phase(status),
        action_type=action_type,
        timestamp_start_ns=_mono_ns(start),
        timestamp_end_ns=_mono_ns(row),
        wall_time_start_ns=_wall_ns(start),
        wall_time_end_ns=_wall_ns(row),
        thread_id=thread_id,
        turn_id=turn_id,
        item_id=item_id,
        parent_event_id=parent_event_id,
        status=status,
        duration_ms=item.get("durationMs"),
        payload=payload,
    )
    if start_row is None:
        event.anomalies.append("completion_without_start")
    if has_status and raw_status == EventStatus.RUNNING:
        event.anomalies.append("item_completed_with_running_status")
    elif has_status and raw_status == EventStatus.UNKNOWN:
        event.anomalies.append("unknown_item_status")

    _apply_item_semantics(event, item)
    return event


def _apply_item_semantics(event: CanonicalEvent, item: dict[str, Any]) -> None:
    item_type = str(item.get("type") or "unknown")
    if item_type == "commandExecution":
        command = str(item.get("command") or "")
        event.tool = "shell"
        event.operation = command
        event.cwd = str(item.get("cwd")) if item.get("cwd") is not None else None
        event.exit_code = item.get("exitCode")
        event.targets = _targets_from_command_actions(item)
        process_handle = item.get("processId")
        if process_handle is not None:
            event.process_handle = str(process_handle)
    elif item_type == "fileChange":
        changes = [change for change in item.get("changes") or [] if isinstance(change, dict)]
        event.tool = "apply_patch"
        event.operation = "file_change"
        event.affected_files = [str(change["path"]) for change in changes if change.get("path")]
        event.targets = list(event.affected_files)
    elif item_type == "mcpToolCall":
        server = str(item.get("server") or "")
        tool = str(item.get("tool") or "")
        event.tool = f"{server}::{tool}" if server else tool
        event.operation = tool
    elif item_type == "dynamicToolCall":
        namespace = str(item.get("namespace") or "")
        tool = str(item.get("tool") or "")
        event.tool = f"{namespace}::{tool}" if namespace else tool
        event.operation = tool
    elif item_type in {"collabAgentToolCall", "collabToolCall"}:
        event.actor = str(item.get("senderThreadId") or "main_agent")
        event.tool = "collaboration"
        event.operation = str(item.get("tool") or item_type)
        event.targets = [str(value) for value in item.get("receiverThreadIds") or []]
    elif item_type == "subAgentActivity":
        event.actor = str(item.get("agentThreadId") or "subagent")
        event.tool = "collaboration"
        event.operation = str(item.get("kind") or "subAgentActivity")
        if item.get("agentPath"):
            event.targets = [str(item["agentPath"])]
    elif item_type == "webSearch":
        event.tool = "web_search"
        event.operation = str(item.get("query") or "search")
    elif item_type == "imageView":
        event.tool = "image"
        event.operation = "view"
        if item.get("path"):
            event.targets = [str(item["path"])]
    elif item_type == "imageGeneration":
        event.tool = "image_generation"
        event.operation = "generate"
        if item.get("savedPath"):
            event.targets = [str(item["savedPath"])]
    elif item_type == "sleep":
        event.tool = "timer"
        event.operation = "sleep"
    elif item_type == "contextCompaction":
        event.tool = "context"
        event.operation = "compact"


def _camel_to_snake(value: str) -> str:
    value = value.replace("/", "_").replace("-", "_")
    return re.sub(r"(?<!^)(?=[A-Z])", "_", value).lower() or "unknown"


def _point_event(
    row: dict[str, Any],
    *,
    action_type: str,
    method: str,
    params: dict[str, Any],
    parent_event_id: str | None = None,
) -> CanonicalEvent:
    thread_id, turn_id = _thread_turn(params)
    return CanonicalEvent(
        event_id=_stable_id(action_type, thread_id, turn_id, row.get("seq"), method),
        seq=int(row.get("seq") or 0),
        source=EventSource.APP_SERVER,
        source_event=method,
        action_type=action_type,
        timestamp_start_ns=_mono_ns(row),
        timestamp_end_ns=_mono_ns(row),
        wall_time_start_ns=_wall_ns(row),
        wall_time_end_ns=_wall_ns(row),
        thread_id=thread_id,
        turn_id=turn_id,
        parent_event_id=parent_event_id,
        status=EventStatus.COMPLETED,
        payload={"params": params, "_source_seq": row.get("seq")},
    )


def _item_update(row: dict[str, Any], method: str, params: dict[str, Any]) -> dict[str, Any]:
    """Keep the schema-defined update fields without duplicating routing IDs."""

    update: dict[str, Any] = {"method": method, "_source_seq": row.get("seq")}
    for key, value in params.items():
        if key not in {"itemId", "threadId", "turnId"}:
            update[key] = value
    return update


def _approval_value(result: Any) -> str | None:
    if not isinstance(result, dict) or "decision" not in result:
        return None
    decision = result["decision"]
    if isinstance(decision, str):
        return decision
    if isinstance(decision, dict) and decision:
        # Structured approvals in 0.144.1 are tagged single-key objects, such
        # as acceptWithExecpolicyAmendment.
        return _camel_to_snake(str(next(iter(decision))))
    return None


def _request_result_status(
    action_type: str, response: dict[str, Any]
) -> tuple[EventStatus, str | None]:
    if "error" in response:
        return EventStatus.FAILED, None

    result = response.get("result")
    approval = _approval_value(result) if action_type == "approval_request" else None
    normalized = str(approval or "").replace("_", "").lower()
    if normalized in {"decline", "declined", "deny", "denied"}:
        return EventStatus.DECLINED, approval
    if normalized in {"cancel", "abort", "aborted", "timedout"}:
        return EventStatus.CANCELLED, approval
    if isinstance(result, dict) and result.get("success") is False:
        return EventStatus.FAILED, approval
    return EventStatus.COMPLETED, approval


def _server_request_event(
    request_row: dict[str, Any],
    *,
    request_id: int | str,
    method: str,
    params: dict[str, Any],
    end_row: dict[str, Any] | None,
    response: dict[str, Any] | None = None,
    resolution: dict[str, Any] | None = None,
    last_mono: int = 0,
    last_wall: int = 0,
) -> CanonicalEvent:
    action_type = (
        "approval_request" if method in _APPROVAL_REQUEST_METHODS else "server_request"
    )
    thread_id, turn_id = _thread_turn(params)
    if thread_id is None and params.get("conversationId") is not None:
        thread_id = str(params["conversationId"])
    end_mono = _mono_ns(end_row) if end_row is not None else last_mono
    end_wall = _wall_ns(end_row) if end_row is not None else last_wall
    start_mono = _mono_ns(request_row)
    start_wall = _wall_ns(request_row)

    if response is not None:
        status, approval = _request_result_status(action_type, response)
        phase = _terminal_phase(status)
    elif resolution is not None:
        status = EventStatus.COMPLETED
        approval = None
        phase = EventPhase.COMPLETED
    else:
        status = EventStatus.INCOMPLETE
        approval = None
        phase = EventPhase.INCOMPLETE

    payload: dict[str, Any] = {
        "request_id": request_id,
        "method": method,
        "params": params,
        "_source_seq": request_row.get("seq"),
    }
    if response is not None:
        payload["response"] = response
        payload["_response_seq"] = end_row.get("seq") if end_row else None
    if resolution is not None:
        payload["resolution"] = resolution
        payload["_resolution_seq"] = end_row.get("seq") if end_row else None

    item_id = (
        str(params.get("itemId") or params.get("callId"))
        if params.get("itemId") is not None or params.get("callId") is not None
        else None
    )
    event = CanonicalEvent(
        event_id=_stable_id(
            "server-request",
            type(request_id).__name__,
            request_id,
            request_row.get("seq"),
            method,
        ),
        seq=int((end_row or request_row).get("seq") or 0),
        source=EventSource.APP_SERVER,
        source_event=method,
        phase=phase,
        action_type=action_type,
        timestamp_start_ns=start_mono,
        timestamp_end_ns=end_mono or start_mono,
        wall_time_start_ns=start_wall,
        wall_time_end_ns=end_wall or start_wall,
        thread_id=thread_id,
        turn_id=turn_id,
        item_id=item_id,
        tool=method,
        operation=method,
        status=status,
        approval=approval,
        payload=payload,
    )
    if turn_id:
        event.parent_event_id = f"turn:{turn_id}"
    if start_mono and event.timestamp_end_ns is not None:
        event.duration_ms = max(0, event.timestamp_end_ns - start_mono) / 1_000_000
    if response is not None and "error" in response:
        event.anomalies.append("server_request_error")
    elif resolution is not None and response is None:
        event.anomalies.append("resolved_without_captured_response")
    elif response is None:
        event.anomalies.append("server_request_did_not_resolve")
    return event


def _turn_input_request_event(
    request_row: dict[str, Any],
    *,
    request_id: int | str | None,
    method: str,
    params: dict[str, Any],
    end_row: dict[str, Any] | None,
    response: dict[str, Any] | None = None,
    last_mono: int = 0,
    last_wall: int = 0,
) -> CanonicalEvent:
    """Represent a user turn input request, including a partial request."""

    if method not in {"turn/start", "turn/steer"}:
        raise ValueError(f"unsupported turn input request method: {method}")

    thread_id, _ = _thread_turn(params)
    result = response.get("result") if isinstance(response, dict) else None
    result = result if isinstance(result, dict) else {}
    if method == "turn/start":
        turn = result.get("turn")
        turn = turn if isinstance(turn, dict) else {}
        turn_value = turn.get("id")
    else:
        turn_value = result.get("turnId") or params.get("expectedTurnId")
    turn_id = str(turn_value) if turn_value is not None else None
    if response is None:
        status = EventStatus.INCOMPLETE
    elif "error" in response:
        status = EventStatus.FAILED
    else:
        status = EventStatus.COMPLETED
    start_mono = _mono_ns(request_row)
    start_wall = _wall_ns(request_row)
    end_mono = _mono_ns(end_row) if end_row is not None else last_mono
    end_wall = _wall_ns(end_row) if end_row is not None else last_wall
    connection_id = request_row.get("connection_id")
    payload: dict[str, Any] = {
        "request_id": request_id,
        "method": method,
        "params": params,
        "connection_id": connection_id,
        "_source_seq": request_row.get("seq"),
    }
    if response is not None:
        payload["response"] = response
        payload["_response_seq"] = end_row.get("seq") if end_row else None
    event = CanonicalEvent(
        event_id=_stable_id(
            "turn-request" if method == "turn/start" else "turn-steer",
            connection_id,
            type(request_id).__name__,
            request_id,
            request_row.get("seq"),
        ),
        seq=int((end_row or request_row).get("seq") or 0),
        source=EventSource.APP_SERVER,
        source_event=method,
        phase=_terminal_phase(status),
        action_type="turn_request" if method == "turn/start" else "turn_steer",
        actor="user",
        timestamp_start_ns=start_mono,
        timestamp_end_ns=end_mono or start_mono,
        wall_time_start_ns=start_wall,
        wall_time_end_ns=end_wall or start_wall,
        thread_id=thread_id,
        turn_id=turn_id,
        tool="codex_tui",
        operation=method,
        status=status,
        payload=payload,
    )
    if start_mono and event.timestamp_end_ns is not None:
        event.duration_ms = max(0, event.timestamp_end_ns - start_mono) / 1_000_000
    if response is None:
        event.anomalies.append(
            "turn_request_did_not_resolve"
            if method == "turn/start"
            else "turn_steer_did_not_resolve"
        )
    elif "error" in response:
        event.anomalies.append(
            "turn_request_error" if method == "turn/start" else "turn_steer_error"
        )
    return event


def normalize_appserver(rows: Iterable[dict[str, Any]]) -> list[CanonicalEvent]:
    started_items: dict[_ItemKey, dict[str, Any]] = {}
    item_outputs: dict[_ItemKey, list[str]] = {}
    item_text_fragments: dict[_ItemKey, list[str]] = {}
    item_updates: dict[_ItemKey, list[dict[str, Any]]] = {}
    started_hooks: dict[tuple[str | None, str | None, str], dict[str, Any]] = {}
    pending_requests: dict[
        _RequestKey, tuple[dict[str, Any], int | str, str, dict[str, Any]]
    ] = {}
    pending_turn_requests: dict[
        _RequestKey, tuple[dict[str, Any], int | str, str, dict[str, Any]]
    ] = {}
    request_events: dict[_RequestKey, CanonicalEvent] = {}
    events: list[CanonicalEvent] = []
    turn_parents: dict[str, str] = {}
    active_turn_events: dict[tuple[str | None, str], CanonicalEvent] = {}
    last_mono = 0
    last_wall = 0

    for row in rows:
        last_mono = max(last_mono, _mono_ns(row))
        last_wall = max(last_wall, _wall_ns(row))
        message = row.get("message") or {}
        if not isinstance(message, dict):
            continue

        direction = row.get("direction")
        request_key = _request_id_key(message.get("id"), row.get("connection_id"))
        if direction == "client_to_server":
            method_value = message.get("method")
            if isinstance(method_value, str) and method_value in {
                "turn/start",
                "turn/steer",
            }:
                params = message.get("params") or {}
                if not isinstance(params, dict):
                    params = {"value": params}
                if request_key is None:
                    events.append(
                        _turn_input_request_event(
                            row,
                            request_id=None,
                            method=method_value,
                            params=params,
                            end_row=None,
                            last_mono=_mono_ns(row),
                            last_wall=_wall_ns(row),
                        )
                    )
                else:
                    previous = pending_turn_requests.pop(request_key, None)
                    if previous is not None:
                        previous_row, previous_id, previous_method, previous_params = previous
                        duplicate = _turn_input_request_event(
                            previous_row,
                            request_id=previous_id,
                            method=previous_method,
                            params=previous_params,
                            end_row=None,
                            last_mono=_mono_ns(row),
                            last_wall=_wall_ns(row),
                        )
                        duplicate.anomalies.append("duplicate_client_request_id")
                        events.append(duplicate)
                    pending_turn_requests[request_key] = (
                        row,
                        message["id"],
                        method_value,
                        params,
                    )
                continue
            if (
                request_key is not None
                and "method" not in message
                and ("result" in message or "error" in message)
            ):
                pending = pending_requests.pop(request_key, None)
                if pending is not None:
                    request_row, request_id, request_method, request_params = pending
                    event = _server_request_event(
                        request_row,
                        request_id=request_id,
                        method=request_method,
                        params=request_params,
                        end_row=row,
                        response=message,
                    )
                    events.append(event)
                    request_events[request_key] = event
                elif request_key in request_events:
                    # A resolved notification can precede the captured client
                    # response when multiple app-server subscribers race.
                    event = request_events[request_key]
                    status, approval = _request_result_status(
                        event.action_type, message
                    )
                    event.status = status
                    event.phase = _terminal_phase(status)
                    event.approval = approval
                    event.seq = int(row.get("seq") or event.seq)
                    event.timestamp_end_ns = _mono_ns(row)
                    event.wall_time_end_ns = _wall_ns(row)
                    event.payload["response"] = message
                    event.payload["_response_seq"] = row.get("seq")
                    event.anomalies = [
                        value
                        for value in event.anomalies
                        if value != "resolved_without_captured_response"
                    ]
                    if "error" in message:
                        event.anomalies.append("server_request_error")
            continue

        if direction != "server_to_client":
            continue

        method_value = message.get("method")
        method = method_value if isinstance(method_value, str) else ""
        params = message.get("params") or {}
        if not isinstance(params, dict):
            params = {"value": params}

        if (
            request_key is not None
            and not method
            and ("result" in message or "error" in message)
        ):
            pending_turn = pending_turn_requests.pop(request_key, None)
            if pending_turn is not None:
                request_row, request_id, request_method, request_params = pending_turn
                events.append(
                    _turn_input_request_event(
                        request_row,
                        request_id=request_id,
                        method=request_method,
                        params=request_params,
                        end_row=row,
                        response=message,
                    )
                )
                continue

        if request_key is not None and method:
            previous = pending_requests.pop(request_key, None)
            if previous is not None:
                previous_row, previous_id, previous_method, previous_params = previous
                duplicate = _server_request_event(
                    previous_row,
                    request_id=previous_id,
                    method=previous_method,
                    params=previous_params,
                    end_row=None,
                    last_mono=_mono_ns(row),
                    last_wall=_wall_ns(row),
                )
                duplicate.anomalies.append("duplicate_server_request_id")
                events.append(duplicate)
            pending_requests[request_key] = (row, message["id"], method, params)
            continue

        if method == "serverRequest/resolved":
            resolved_key = _request_id_key(
                params.get("requestId"), row.get("connection_id")
            )
            if resolved_key is None:
                continue
            pending = pending_requests.pop(resolved_key, None)
            if pending is not None:
                request_row, request_id, request_method, request_params = pending
                event = _server_request_event(
                    request_row,
                    request_id=request_id,
                    method=request_method,
                    params=request_params,
                    end_row=row,
                    resolution=params,
                )
                events.append(event)
                request_events[resolved_key] = event
            elif resolved_key in request_events:
                event = request_events[resolved_key]
                event.payload["resolution"] = params
                event.payload["_resolution_seq"] = row.get("seq")
                event.seq = int(row.get("seq") or event.seq)
                event.timestamp_end_ns = _mono_ns(row)
                event.wall_time_end_ns = _wall_ns(row)
                if event.timestamp_start_ns:
                    event.duration_ms = max(
                        0, event.timestamp_end_ns - event.timestamp_start_ns
                    ) / 1_000_000
            continue

        if method == "turn/started":
            turn = params.get("turn") or {}
            if not isinstance(turn, dict):
                continue
            turn_id = str(turn.get("id") or params.get("turnId") or "")
            event = _point_event(row, action_type="turn", method=method, params=params)
            event.event_id = f"turn:{turn_id}" if turn_id else event.event_id
            event.turn_id = turn_id or event.turn_id
            event.phase = EventPhase.STARTED
            event.status = EventStatus.RUNNING
            if turn_id:
                turn_parents[turn_id] = event.event_id
                active_turn_events[(event.thread_id, turn_id)] = event
            events.append(event)
            continue

        if method == "turn/completed":
            turn = params.get("turn") or {}
            if not isinstance(turn, dict):
                continue
            turn_id = str(turn.get("id") or params.get("turnId") or "")
            status = _status(turn.get("status"))
            event = _point_event(row, action_type="turn", method=method, params=params)
            event.event_id = _stable_id("turn-terminal", turn_id, row.get("seq"))
            event.turn_id = turn_id or event.turn_id
            event.parent_event_id = turn_parents.get(turn_id)
            active_turn_events.pop((event.thread_id, turn_id), None)
            if status in {EventStatus.RUNNING, EventStatus.UNKNOWN}:
                event.status = EventStatus.INCOMPLETE
                event.phase = EventPhase.INCOMPLETE
                event.anomalies.append("turn_completed_with_nonterminal_status")
            else:
                event.status = status
                event.phase = _terminal_phase(status)
            event.duration_ms = turn.get("durationMs")
            if turn.get("error"):
                event.anomalies.append("turn_error")
            if turn_id and turn_id not in turn_parents:
                event.anomalies.append("turn_completion_without_start")
            events.append(event)
            continue

        if method == "item/started":
            item = params.get("item") or {}
            if not isinstance(item, dict):
                continue
            item_id = item.get("id")
            if item_id is not None:
                started_items[_item_key(row, params, item_id, item)] = row
            continue

        if method in _ITEM_UPDATE_METHODS:
            item_id = str(params.get("itemId") or "")
            delta = params.get("delta")
            if item_id:
                observed_key = _item_key(row, params, item_id)
                key = _resolve_item_key(
                    observed_key,
                    started_items,
                    item_updates,
                    item_outputs,
                    item_text_fragments,
                )
                item_updates.setdefault(key, []).append(
                    _item_update(row, method, params)
                )
                if method in _ITEM_DELTA_METHODS and delta is not None:
                    item_text_fragments.setdefault(key, []).append(str(delta))
                if method in _OUTPUT_DELTA_METHODS and delta is not None:
                    item_outputs.setdefault(key, []).append(str(delta))
            continue

        if method == "item/completed":
            item = params.get("item") or {}
            if not isinstance(item, dict):
                continue
            item_id = str(item.get("id") or f"seq-{row.get('seq', 0)}")
            turn_id = str(params.get("turnId") or item.get("turnId") or "")
            observed_key = _item_key(row, params, item_id, item)
            key = _resolve_item_key(
                observed_key,
                started_items,
                item_outputs,
                item_updates,
                item_text_fragments,
            )
            events.append(
                _item_event(
                    row,
                    item,
                    started_items.pop(key, None),
                    "".join(item_outputs.pop(key, [])),
                    item_updates.pop(key, []),
                    turn_parents.get(turn_id),
                )
            )
            item_text_fragments.pop(key, None)
            continue

        if method == "hook/started":
            run = params.get("run") or {}
            if not isinstance(run, dict):
                continue
            run_id = run.get("id")
            if run_id is not None:
                thread_id, turn_id = _thread_turn(params)
                started_hooks[(thread_id, turn_id, str(run_id))] = row
            continue

        if method == "hook/completed":
            run = params.get("run") or {}
            if not isinstance(run, dict):
                continue
            run_id = str(run.get("id") or f"seq-{row.get('seq', 0)}")
            thread_id, turn_id = _thread_turn(params)
            hook_key = (thread_id, turn_id, run_id)
            start = started_hooks.pop(hook_key, None)
            scope_fallback = False
            if start is None:
                matching_keys = [
                    key
                    for key in started_hooks
                    if key[2] == run_id
                    and (
                        thread_id is None
                        or key[0] is None
                        or thread_id == key[0]
                    )
                    and (
                        turn_id is None
                        or key[1] is None
                        or turn_id == key[1]
                    )
                ]
                if len(matching_keys) == 1:
                    start = started_hooks.pop(matching_keys[0])
                    scope_fallback = True
            start_params = ((start or {}).get("message") or {}).get("params") or {}
            if not isinstance(start_params, dict):
                start_params = {}
            start_run = start_params.get("run") or {}
            if not isinstance(start_run, dict):
                start_run = {}
            start_thread_id, start_turn_id = _thread_turn(start_params)
            thread_id = thread_id or start_thread_id
            turn_id = turn_id or start_turn_id
            status = _status(run.get("status"))
            if status in {EventStatus.RUNNING, EventStatus.UNKNOWN}:
                terminal_status = EventStatus.INCOMPLETE
            else:
                terminal_status = status
            hook_name = _normalize_hook_name(
                run.get("eventName") or start_run.get("eventName")
            )
            tool_use_id = _tool_use_id(params, run, start_params, start_run)
            payload: dict[str, Any] = {
                "run": run,
                "_source_seq": row.get("seq"),
            }
            if tool_use_id is not None:
                payload["_tool_use_id_evidence"] = "app_server.hook_run.tool_use_id"
            event = CanonicalEvent(
                event_id=_stable_id("hook", thread_id, turn_id, run_id),
                seq=int(row.get("seq") or 0),
                source=EventSource.APP_SERVER,
                source_event=method,
                phase=_terminal_phase(terminal_status),
                action_type="hook",
                timestamp_start_ns=_mono_ns(start or row),
                timestamp_end_ns=_mono_ns(row),
                wall_time_start_ns=_wall_ns(start or row),
                wall_time_end_ns=_wall_ns(row),
                thread_id=thread_id,
                turn_id=turn_id,
                tool_use_id=tool_use_id,
                hook_run_id=run_id,
                hook_event_name=hook_name,
                parent_event_id=turn_parents.get(turn_id or ""),
                tool=hook_name,
                operation=hook_name,
                status=terminal_status,
                duration_ms=run.get("durationMs"),
                payload=payload,
            )
            if start is None:
                event.anomalies.append("hook_completion_without_start")
            elif scope_fallback:
                event.anomalies.append("hook_scope_mismatch")
            if terminal_status == EventStatus.INCOMPLETE:
                event.anomalies.append("hook_completed_with_nonterminal_status")
            events.append(event)
            continue

        if method == "turn/plan/updated":
            turn_id = str(params.get("turnId") or "")
            events.append(
                _point_event(
                    row,
                    action_type="plan_update",
                    method=method,
                    params=params,
                    parent_event_id=turn_parents.get(turn_id),
                )
            )
            continue

        if method == "turn/diff/updated":
            turn_id = str(params.get("turnId") or "")
            events.append(
                _point_event(
                    row,
                    action_type="diff_update",
                    method=method,
                    params=params,
                    parent_event_id=turn_parents.get(turn_id),
                )
            )
            continue

        if method == "thread/tokenUsage/updated":
            raw_usage = params.get("tokenUsage")
            # Older traces may contain the literal redaction marker produced
            # before token-usage containers were recognized.  They carry no
            # recoverable counters and are intentionally ignored.
            if not isinstance(raw_usage, dict):
                continue
            turn_id = str(params.get("turnId") or "")
            event = _point_event(
                row,
                action_type="token_usage",
                method=method,
                params=params,
                parent_event_id=turn_parents.get(turn_id),
            )
            usage = _normalize_thread_token_usage(raw_usage)
            if usage is None:
                event.anomalies.append("invalid_token_usage")
            else:
                event.payload["token_usage"] = usage
            events.append(event)
            continue

        if method in {"thread/started", "thread/status/changed", "thread/closed"}:
            events.append(_point_event(row, action_type="thread", method=method, params=params))
            continue

    for item_key, start in started_items.items():
        item_id = item_key[3]
        message = start.get("message") or {}
        params = message.get("params") or {}
        item = params.get("item") or {}
        if not isinstance(params, dict) or not isinstance(item, dict):
            continue
        thread_id, turn_id = _thread_turn(params, item)
        output = "".join(item_outputs.get(item_key, []))
        text = "".join(item_text_fragments.get(item_key, []))
        payload: dict[str, Any] = {
            "item": item,
            "partial_output": output,
            "_source_seq": start.get("seq"),
        }
        if text and text != output:
            payload["partial_text"] = text
        if item_updates.get(item_key):
            payload["updates"] = item_updates[item_key]
        if params.get("startedAtMs") is not None:
            payload["startedAtMs"] = params["startedAtMs"]
        action_type = _ITEM_TYPES.get(
            str(item.get("type") or "unknown"),
            _camel_to_snake(str(item.get("type") or "unknown")),
        )
        connection_id = start.get("connection_id")
        event = CanonicalEvent(
            event_id=(
                f"item:{item_id}"
                if connection_id is None
                else _stable_id(
                    "item", connection_id, thread_id, turn_id, item_id
                )
            ),
            seq=int(start.get("seq") or 0),
            source=EventSource.APP_SERVER,
            source_event="item/started",
            phase=EventPhase.INCOMPLETE,
            action_type=action_type,
            timestamp_start_ns=_mono_ns(start),
            timestamp_end_ns=last_mono or _mono_ns(start),
            wall_time_start_ns=_wall_ns(start),
            wall_time_end_ns=last_wall or _wall_ns(start),
            thread_id=thread_id,
            turn_id=turn_id,
            item_id=item_id,
            parent_event_id=turn_parents.get(turn_id or ""),
            status=EventStatus.INCOMPLETE,
            duration_ms=item.get("durationMs"),
            payload=payload,
            anomalies=["item_did_not_complete"],
        )
        _apply_item_semantics(event, item)
        events.append(event)

    for (key_thread_id, key_turn_id, run_id), start in started_hooks.items():
        params = ((start.get("message") or {}).get("params") or {})
        run = params.get("run") or {}
        if not isinstance(params, dict) or not isinstance(run, dict):
            continue
        thread_id, turn_id = _thread_turn(params)
        thread_id = thread_id or key_thread_id
        turn_id = turn_id or key_turn_id
        hook_name = _normalize_hook_name(run.get("eventName"))
        tool_use_id = _tool_use_id(params, run)
        payload: dict[str, Any] = {
            "run": run,
            "_source_seq": start.get("seq"),
        }
        if tool_use_id is not None:
            payload["_tool_use_id_evidence"] = "app_server.hook_run.tool_use_id"
        events.append(
            CanonicalEvent(
                event_id=_stable_id("hook", thread_id, turn_id, run_id),
                seq=int(start.get("seq") or 0),
                source=EventSource.APP_SERVER,
                source_event="hook/started",
                phase=EventPhase.INCOMPLETE,
                action_type="hook",
                timestamp_start_ns=_mono_ns(start),
                timestamp_end_ns=last_mono or _mono_ns(start),
                wall_time_start_ns=_wall_ns(start),
                wall_time_end_ns=last_wall or _wall_ns(start),
                thread_id=thread_id,
                turn_id=turn_id,
                tool_use_id=tool_use_id,
                hook_run_id=run_id,
                hook_event_name=hook_name,
                parent_event_id=turn_parents.get(turn_id or ""),
                tool=hook_name,
                operation=hook_name,
                status=EventStatus.INCOMPLETE,
                payload=payload,
                anomalies=["hook_did_not_complete"],
            )
        )

    for event in active_turn_events.values():
        event.phase = EventPhase.INCOMPLETE
        event.status = EventStatus.INCOMPLETE
        event.timestamp_end_ns = last_mono or event.timestamp_start_ns
        event.wall_time_end_ns = last_wall or event.wall_time_start_ns
        if event.timestamp_start_ns and event.timestamp_end_ns is not None:
            event.duration_ms = max(
                0, event.timestamp_end_ns - event.timestamp_start_ns
            ) / 1_000_000
        event.anomalies.append("turn_did_not_complete")

    for request_row, request_id, method, params in pending_turn_requests.values():
        events.append(
            _turn_input_request_event(
                request_row,
                request_id=request_id,
                method=method,
                params=params,
                end_row=None,
                last_mono=last_mono,
                last_wall=last_wall,
            )
        )

    for request_row, request_id, method, params in pending_requests.values():
        events.append(
            _server_request_event(
                request_row,
                request_id=request_id,
                method=method,
                params=params,
                end_row=None,
                last_mono=last_mono,
                last_wall=last_wall,
            )
        )
    return events


def normalize_hooks(rows: Iterable[dict[str, Any]]) -> list[CanonicalEvent]:
    events: list[CanonicalEvent] = []
    for source_seq, row in enumerate(rows, start=1):
        payload = row.get("payload") or row.get("input") or row.get("hook_input") or {}
        if not isinstance(payload, dict):
            payload = {"value": payload}
        session_id = row.get("session_id") or payload.get("session_id")
        thread_id = row.get("thread_id") or payload.get("thread_id")
        turn_id = row.get("turn_id") or payload.get("turn_id")
        hook_name = _normalize_hook_name(
            row.get("hook_event_name")
            or row.get("hook_event")
            or payload.get("hook_event_name")
            or payload.get("hook_event")
        )
        tool_use_id = _tool_use_id(row, payload)
        hook_run_id_value = row.get("hook_run_id") or payload.get("hook_run_id")
        hook_run_id = (
            str(hook_run_id_value) if hook_run_id_value is not None else None
        )
        mono = int(row.get("monotonic_ns") or row.get("mono_ns") or 0)
        wall = int(row.get("wall_time_ns") or 0)
        event_id = str(
            row.get("event_id")
            or _stable_id(
                "hook-input",
                session_id,
                thread_id,
                turn_id,
                hook_name,
                tool_use_id,
                mono,
                source_seq,
            )
        )
        tool = payload.get("tool_name") or payload.get("tool") or payload.get("matcher")
        normalized_payload: dict[str, Any] = {
            "hook_input": payload,
            "_source_seq": source_seq,
        }
        if tool_use_id is not None:
            normalized_payload["_tool_use_id_evidence"] = "hook_input.tool_use_id"
        events.append(
            CanonicalEvent(
                event_id=event_id,
                seq=source_seq,
                source=EventSource.HOOK,
                source_event=str(hook_name),
                action_type="hook_input",
                timestamp_start_ns=mono,
                timestamp_end_ns=mono,
                wall_time_start_ns=wall,
                wall_time_end_ns=wall,
                session_id=str(session_id) if session_id is not None else None,
                thread_id=str(thread_id) if thread_id is not None else None,
                turn_id=str(turn_id) if turn_id is not None else None,
                tool_use_id=tool_use_id,
                hook_run_id=hook_run_id,
                hook_event_name=hook_name,
                tool=str(tool) if tool is not None else str(hook_name),
                operation=str(hook_name),
                cwd=str(payload.get("cwd")) if payload.get("cwd") is not None else None,
                status=EventStatus.COMPLETED,
                payload=normalized_payload,
            )
        )
    return events


def _filesystem_relative_path(value: object) -> str | None:
    """Accept only lexical POSIX paths relative to the observed workspace."""

    if not isinstance(value, str) or not value:
        return None
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts:
        return None
    parts = [part for part in path.parts if part not in {"", "."}]
    return "/".join(parts) if parts else "."


def normalize_filesystem_rows(
    rows: Iterable[dict[str, Any]], *, repo: Path | None = None
) -> tuple[list[CanonicalEvent], dict[str, Any]]:
    """Normalize bounded Linux filesystem notifications as observations.

    inotify reports that a watched inode/path changed; it does not report the
    responsible PID or prove that a Codex tool caused the change.  These rows
    therefore use an observer actor and are only correlated to tool windows by
    a separate, explicitly non-causal pass.
    """

    events: list[CanonicalEvent] = []
    operation_counts: dict[str, int] = {}
    paths: set[str] = set()
    raw_records = 0
    invalid_records = 0
    for source_seq, row in enumerate(rows, start=1):
        raw_records += 1
        raw_operations = row.get("operations")
        if isinstance(raw_operations, list):
            operations = [
                str(value)
                for value in raw_operations
                if isinstance(value, str) and value
            ]
        else:
            operation = row.get("operation") or row.get("event")
            operations = [str(operation)] if isinstance(operation, str) and operation else []
        operations = list(dict.fromkeys(operations))
        if not operations:
            invalid_records += 1
            continue

        try:
            mono = int(row.get("monotonic_ns") or row.get("mono_ns") or 0)
            wall = int(row.get("wall_time_ns") or 0)
            source_row_seq = int(row.get("seq") or source_seq)
            mask = int(row.get("mask") or 0)
            cookie = int(row.get("cookie") or 0)
        except (TypeError, ValueError):
            invalid_records += 1
            continue

        for operation in operations:
            operation_counts[operation] = operation_counts.get(operation, 0) + 1
        relative = _filesystem_relative_path(row.get("path"))
        if relative is not None:
            paths.add(relative)
        gap_operations = sorted(set(operations) & _FILESYSTEM_GAP_OPERATIONS)
        special = bool(gap_operations)
        synthetic = bool(row.get("synthetic"))
        anomalies: list[str] = []
        if row.get("path") is not None and relative is None:
            anomalies.append("filesystem_path_outside_workspace")
        if "queue_overflow" in operations:
            anomalies.append("filesystem_kernel_queue_overflow")
        if "limit_reached" in operations:
            anomalies.append("filesystem_capture_limit_reached")
        if "watch_limit" in operations:
            anomalies.append("filesystem_watch_limit_reached")
        if "watch_error" in operations:
            anomalies.append("filesystem_watcher_error")
        if "delete_self" in operations:
            anomalies.append("filesystem_watched_path_deleted")
        if "move_self" in operations:
            anomalies.append("filesystem_watched_path_moved")
        if "unmount" in operations:
            anomalies.append("filesystem_watched_filesystem_unmounted")
        if special:
            anomalies.append("filesystem_capture_incomplete")
        if synthetic:
            anomalies.append("filesystem_synthetic_discovery")
        if not mono:
            anomalies.append("filesystem_event_missing_monotonic_time")

        backend = str(row.get("backend") or "linux_inotify")
        event_id = str(
            row.get("event_id")
            or _stable_id(
                "filesystem",
                backend,
                source_row_seq,
                mono,
                cookie,
                relative,
                ",".join(operations),
            )
        )
        payload = {
            "_source_seq": source_row_seq,
            "backend": backend,
            "mask": mask,
            "cookie": cookie,
            "is_dir": bool(row.get("is_dir")),
            "operations": operations,
            "synthetic": synthetic,
        }
        if relative is not None and special:
            # Keep diagnostic context in the payload, but do not turn a loss or
            # watcher-lifecycle record into ordinary path-activity evidence.
            payload["diagnostic_path"] = relative
        if row.get("name_encoding_error"):
            payload["name_encoding_error"] = True
        targets = (
            [relative]
            if relative and relative != "." and not special
            else []
        )
        events.append(
            CanonicalEvent(
                event_id=event_id,
                seq=source_row_seq,
                source=EventSource.OS,
                source_event=f"inotify/{'+'.join(operations)}",
                action_type="filesystem_event",
                actor="filesystem_observer",
                timestamp_start_ns=mono,
                timestamp_end_ns=mono,
                wall_time_start_ns=wall,
                wall_time_end_ns=wall,
                tool=backend,
                operation=" + ".join(operations),
                cwd=str(repo) if repo is not None else None,
                status=(EventStatus.INCOMPLETE if special else EventStatus.COMPLETED),
                targets=targets,
                payload=payload,
                anomalies=anomalies,
            )
        )

    return events, {
        "raw_records": raw_records,
        "valid_records": len(events),
        "invalid_records": invalid_records,
        "operation_counts": dict(sorted(operation_counts.items())),
        "unique_paths": len(paths),
        "queue_overflows": operation_counts.get("queue_overflow", 0),
        "limit_reached_records": operation_counts.get("limit_reached", 0),
        "watch_limit_records": operation_counts.get("watch_limit", 0),
        "watch_error_records": operation_counts.get("watch_error", 0),
        "gap_records": sum(
            1
            for event in events
            if set(event.payload.get("operations") or [])
            & _FILESYSTEM_GAP_OPERATIONS
        ),
        "synthetic_records": sum(
            1 for event in events if bool(event.payload.get("synthetic"))
        ),
    }


def correlate_filesystem_events(events: Iterable[CanonicalEvent]) -> dict[str, int]:
    """Relate a path event to one unambiguous tool interval without causality."""

    all_events = list(events)
    observations = [
        event
        for event in all_events
        if event.source is EventSource.OS and event.action_type == "filesystem_event"
    ]
    targets = [
        event
        for event in all_events
        if event.source is EventSource.APP_SERVER
        and event.action_type in _FILESYSTEM_CORRELATION_TARGETS
        and event.timestamp_start_ns
        and event.timestamp_end_ns
    ]
    correlated = 0
    ambiguous = 0
    unscoped = 0
    non_path = 0
    synthetic_discoveries = 0
    for observation in observations:
        if observation.payload.get("synthetic"):
            # Synthetic rows are user-space discoveries made while installing
            # or repairing watches. Their timestamps are not kernel event
            # times, so matching them to a tool interval would be misleading.
            observation.anomalies.append(
                "filesystem_synthetic_discovery_not_temporally_correlated"
            )
            synthetic_discoveries += 1
            continue
        if not observation.targets:
            non_path += 1
            continue
        timestamp = observation.timestamp_start_ns or 0
        candidates = [
            target
            for target in targets
            if int(target.timestamp_start_ns or 0)
            <= timestamp
            <= int(target.timestamp_end_ns or 0)
        ]
        if len(candidates) == 1:
            target = candidates[0]
            observation.related_event_id = target.event_id
            observation.correlation_kind = "filesystem_event_to_tool_window"
            observation.correlation_evidence = (
                "inotify observation time within unique app-server item interval"
            )
            observation.correlation_confidence = 0.65
            correlated += 1
        elif candidates:
            observation.anomalies.append(
                "filesystem_event_overlaps_multiple_tool_windows"
            )
            observation.payload["candidate_event_ids"] = [
                candidate.event_id for candidate in candidates[:20]
            ]
            ambiguous += 1
        else:
            observation.anomalies.append("filesystem_event_outside_tool_windows")
            unscoped += 1
    return {
        "events": len(observations),
        "correlated_unique_tool_window": correlated,
        "ambiguous_overlapping_tool_windows": ambiguous,
        "outside_tool_windows": unscoped,
        "non_path_events": non_path,
        "synthetic_discoveries_not_correlated": synthetic_discoveries,
    }


def _os_access_flags(
    syscall: object, category: object, access: object
) -> tuple[bool, bool, bool]:
    """Classify only observable syscall I/O, never model reasoning content."""

    call = str(syscall or "").casefold()
    kind = str(category or "").casefold()
    mode = re.sub(r"[^a-z0-9]+", "_", str(access or "").casefold()).strip("_")
    mode_parts = set(mode.split("_")) if mode else set()
    reads = (
        call in _OS_READ_SYSCALLS
        or mode in {"read", "read_only", "readonly", "receive", "received"}
        or "read" in mode_parts
        or "receive" in mode_parts
        or "recv" in mode_parts
    )
    writes = (
        call in _OS_WRITE_SYSCALLS
        or mode in {"write", "write_only", "writeonly", "send", "sent"}
        or "write" in mode_parts
        or "send" in mode_parts
    )
    if mode in {"rw", "readwrite", "read_write", "write_read"}:
        reads = writes = True
    network = (
        kind in {"network", "socket", "net"}
        or call
        in {
            "socket",
            "socketpair",
            "connect",
            "accept",
            "accept4",
            "bind",
            "listen",
            "shutdown",
            "getsockname",
            "getpeername",
            "send",
            "sendto",
            "sendmsg",
            "sendmmsg",
            "recv",
            "recvfrom",
            "recvmsg",
            "recvmmsg",
        }
    )
    return reads, writes, network


def _os_gap_row(row: dict[str, Any], syscall: str, category: str) -> bool:
    values = {
        syscall.casefold(),
        category.casefold(),
        str(row.get("event") or "").casefold(),
        str(row.get("operation") or "").casefold(),
        str(row.get("status") or "").casefold(),
    }
    return bool(values & _OS_AUDIT_GAP_MARKERS) or bool(row.get("capture_incomplete"))


def _os_target_path(
    value: object, *, path_scope: object, repo: Path | None
) -> str | None:
    if not isinstance(value, str) or not value or "\x00" in value:
        return None
    path = PurePosixPath(value)
    scope = str(path_scope or "").casefold()
    if path.is_absolute() and repo is not None:
        try:
            path = path.relative_to(PurePosixPath(repo.as_posix()))
        except ValueError:
            pass
    if not path.is_absolute():
        relative = _filesystem_relative_path(path.as_posix())
        if relative is not None:
            return relative
        if scope in {"workspace", "repo", "repository", "relative"}:
            return None
    # External absolute paths remain visible as syscall evidence, but will not
    # be confused with an in-workspace inotify path during correlation.
    return path.as_posix()


def normalize_os_audit_rows(
    rows: Iterable[dict[str, Any]], *, repo: Path | None = None
) -> tuple[list[CanonicalEvent], dict[str, Any]]:
    """Normalize Linux syscall records with explicit, verified PID evidence.

    These records describe process-visible operating-system activity. They do
    not contain, reconstruct, or imply hidden model chain-of-thought.
    """

    events: list[CanonicalEvent] = []
    raw_records = 0
    invalid_records = 0
    syscalls: dict[str, int] = {}
    categories: dict[str, int] = {}
    accesses: dict[str, int] = {}
    processes: set[int] = set()
    read_records = 0
    write_records = 0
    network_records = 0
    failed_records = 0
    gap_records = 0

    for source_seq, row in enumerate(rows, start=1):
        raw_records += 1
        syscall_value = row.get("syscall") or row.get("operation") or row.get("event")
        category = str(row.get("category") or "unknown")
        if syscall_value is None and category.casefold() in _OS_AUDIT_GAP_MARKERS:
            syscall_value = category
        if not isinstance(syscall_value, str) or not syscall_value:
            invalid_records += 1
            continue
        syscall = syscall_value
        try:
            source_row_seq = int(row.get("seq") or source_seq)
            mono = int(row.get("monotonic_ns") or row.get("mono_ns") or 0)
            wall = int(row.get("wall_time_ns") or 0)
            duration_ns = max(0, int(row.get("duration_ns") or 0))
            pid = int(row["pid"]) if row.get("pid") is not None else None
            tid = int(row["tid"]) if row.get("tid") is not None else pid
            ppid = int(row["ppid"]) if row.get("ppid") is not None else None
            fd = int(row["fd"]) if row.get("fd") is not None else None
            byte_count = (
                int(row["bytes"]) if row.get("bytes") is not None else None
            )
        except (TypeError, ValueError, OverflowError):
            invalid_records += 1
            continue

        backend = str(row.get("backend") or "linux_strace")
        access = str(row.get("access") or "unknown")
        reads, writes, network = _os_access_flags(syscall, category, access)
        gap = _os_gap_row(row, syscall, category)
        synthetic = bool(row.get("synthetic"))
        schema_mismatch = row.get("schema_version") not in {None, _OS_AUDIT_SCHEMA}
        success_value = row.get("success")
        if isinstance(success_value, bool):
            success: bool | None = success_value
        elif type(success_value) is int and success_value in {0, 1}:
            success = bool(success_value)
        elif success_value is None:
            success = False if row.get("errno") not in {None, 0, "0", ""} else None
        else:
            success = None
            schema_mismatch = True

        path = _os_target_path(
            row.get("path"), path_scope=row.get("path_scope"), repo=repo
        )
        anomalies: list[str] = []
        if schema_mismatch:
            anomalies.append("os_audit_schema_mismatch")
        if row.get("path") is not None and path is None:
            anomalies.append("os_audit_invalid_or_outside_workspace_path")
        if gap:
            anomalies.extend(["os_audit_capture_gap", "os_audit_capture_incomplete"])
        if synthetic:
            anomalies.append("os_audit_synthetic_record")
        if not mono:
            anomalies.append("os_audit_event_missing_monotonic_time")
        if pid is None and not gap:
            anomalies.append("os_audit_syscall_missing_pid")

        syscalls[syscall] = syscalls.get(syscall, 0) + 1
        categories[category] = categories.get(category, 0) + 1
        accesses[access] = accesses.get(access, 0) + 1
        if pid is not None:
            processes.add(pid)
        read_records += int(reads and not gap)
        write_records += int(writes and not gap)
        network_records += int(network and not gap)
        failed_records += int(success is False and not gap)
        gap_records += int(gap or schema_mismatch)

        end_mono = mono + duration_ns if mono else mono
        end_wall = wall + duration_ns if wall else wall
        event_id = str(
            row.get("event_id")
            or _stable_id(
                "os-syscall",
                backend,
                source_row_seq,
                mono,
                pid,
                tid,
                syscall,
                path,
            )
        )
        payload: dict[str, Any] = {
            "_source_seq": source_row_seq,
            "schema_version": row.get("schema_version") or _OS_AUDIT_SCHEMA,
            "backend": backend,
            "pid": pid,
            "tid": tid,
            "ppid": ppid,
            "comm": row.get("comm"),
            "syscall": syscall,
            "category": category,
            "access": access,
            "path_scope": row.get("path_scope"),
            "fd": fd,
            "bytes": byte_count,
            "endpoint": row.get("endpoint"),
            "result": row.get("result"),
            "errno": row.get("errno"),
            "success": success,
            "duration_ns": duration_ns,
            "arguments": row.get("arguments"),
            "synthetic": synthetic,
            "is_read": reads,
            "is_write": writes,
            "is_network": network,
            "pid_evidence": "linux_strace.syscall" if pid is not None else None,
            "hidden_chain_of_thought_captured": False,
        }
        events.append(
            CanonicalEvent(
                event_id=event_id,
                seq=source_row_seq,
                source=EventSource.OS,
                source_event=f"{backend}/{syscall}",
                phase=(
                    EventPhase.INCOMPLETE
                    if gap or schema_mismatch
                    else EventPhase.FAILED
                    if success is False
                    else EventPhase.COMPLETED
                ),
                action_type="os_syscall",
                actor=f"process:{pid}" if pid is not None else "os_audit_collector",
                timestamp_start_ns=mono,
                timestamp_end_ns=end_mono,
                wall_time_start_ns=wall,
                wall_time_end_ns=end_wall,
                process_id=pid,
                process_id_verified=pid is not None,
                parent_process_id=ppid,
                runtime_thread_id=tid,
                tool=backend,
                operation=syscall,
                cwd=str(repo) if repo is not None else None,
                status=(
                    EventStatus.INCOMPLETE
                    if gap or schema_mismatch
                    else EventStatus.FAILED
                    if success is False
                    else EventStatus.COMPLETED
                ),
                duration_ms=duration_ns / 1_000_000 if duration_ns else None,
                targets=[path] if path is not None and not gap else [],
                payload=payload,
                anomalies=anomalies,
            )
        )

    return events, {
        "raw_records": raw_records,
        "valid_records": len(events),
        "invalid_records": invalid_records,
        "syscalls": len(events) - gap_records,
        "syscall_counts": dict(sorted(syscalls.items())),
        "category_counts": dict(sorted(categories.items())),
        "access_counts": dict(sorted(accesses.items())),
        "processes": len(processes),
        "reads": read_records,
        "writes": write_records,
        "network": network_records,
        "failed": failed_records,
        "read_records": read_records,
        "write_records": write_records,
        "network_records": network_records,
        "failed_records": failed_records,
        "gap_records": gap_records,
    }


def correlate_os_audit_events(events: Iterable[CanonicalEvent]) -> dict[str, int]:
    """Add temporal-only tool-window links to syscall evidence."""

    all_events = list(events)
    observations = [
        event for event in all_events if event.action_type == "os_syscall"
    ]
    targets = sorted(
        [
            event
            for event in all_events
            if event.source is EventSource.APP_SERVER
            and event.action_type in _OS_AUDIT_TOOL_TARGETS
            and event.timestamp_start_ns
            and event.timestamp_end_ns
        ],
        key=lambda event: int(event.timestamp_start_ns or 0),
    )
    point_events = sorted(
        [
            event
            for event in observations
            if event.timestamp_start_ns
            and event.status != EventStatus.INCOMPLETE
            and not event.payload.get("synthetic")
        ],
        key=lambda event: int(event.timestamp_start_ns or 0),
    )
    point_event_ids = {event.event_id for event in point_events}
    target_index = 0
    active: dict[str, CanonicalEvent] = {}
    endings: list[tuple[int, str]] = []
    correlated = ambiguous = outside = unscoped = 0
    for observation in observations:
        if observation.event_id not in point_event_ids:
            unscoped += 1
    for observation in point_events:
        timestamp = int(observation.timestamp_start_ns or 0)
        while (
            target_index < len(targets)
            and int(targets[target_index].timestamp_start_ns or 0) <= timestamp
        ):
            target = targets[target_index]
            active[target.event_id] = target
            heapq.heappush(
                endings, (int(target.timestamp_end_ns or 0), target.event_id)
            )
            target_index += 1
        while endings and endings[0][0] < timestamp:
            _end, event_id = heapq.heappop(endings)
            active.pop(event_id, None)
        candidates = list(active.values())
        if len(candidates) == 1:
            target = candidates[0]
            observation.related_event_id = target.event_id
            observation.correlation_kind = "os_syscall_to_tool_window"
            observation.correlation_evidence = (
                "linux_strace syscall time within unique app-server item interval; "
                "temporal correlation only, not causal attribution"
            )
            observation.correlation_confidence = 0.7
            observation.payload["tool_attribution"] = "temporal_only_not_causal"
            correlated += 1
        elif candidates:
            observation.anomalies.append(
                "os_syscall_overlaps_multiple_tool_windows"
            )
            observation.payload["candidate_event_ids"] = [
                candidate.event_id for candidate in candidates[:20]
            ]
            ambiguous += 1
        else:
            observation.anomalies.append("os_syscall_outside_tool_windows")
            outside += 1
    return {
        "events": len(observations),
        "correlated_unique_tool_window": correlated,
        "ambiguous_overlapping_tool_windows": ambiguous,
        "outside_tool_windows": outside,
        "diagnostic_or_unscoped_records": unscoped,
    }


def correlate_filesystem_syscalls(
    events: Iterable[CanonicalEvent], *, tolerance_ns: int = 500_000_000
) -> dict[str, int]:
    """Match one inotify path observation to one nearby successful write syscall."""

    all_events = list(events)
    by_path: dict[str, list[tuple[int, CanonicalEvent]]] = {}
    for event in all_events:
        if event.action_type != "os_syscall" or event.status != EventStatus.COMPLETED:
            continue
        if not event.payload.get("is_write") or len(event.targets) != 1:
            continue
        by_path.setdefault(event.targets[0], []).append(
            (int(event.timestamp_start_ns or 0), event)
        )
    indexed_paths: dict[str, tuple[list[int], list[tuple[int, CanonicalEvent]]]] = {}
    for path, rows in by_path.items():
        rows.sort(key=lambda item: item[0])
        indexed_paths[path] = ([item[0] for item in rows], rows)

    matched = ambiguous = unmatched = 0
    for observation in all_events:
        if (
            observation.action_type != "filesystem_event"
            or len(observation.targets) != 1
            or observation.payload.get("synthetic")
            or not observation.timestamp_start_ns
        ):
            continue
        times, rows = indexed_paths.get(observation.targets[0], ([], []))
        timestamp = int(observation.timestamp_start_ns)
        left = bisect_left(times, timestamp - tolerance_ns)
        right = bisect_right(times, timestamp + tolerance_ns)
        candidates = [event for _time, event in rows[left:right]]
        if len(candidates) == 1:
            syscall = candidates[0]
            observation.payload["os_syscall_event_id"] = syscall.event_id
            observation.payload["os_syscall_pid"] = syscall.process_id
            observation.payload["os_syscall_correlation_evidence"] = (
                "same normalized path and unique nearby successful write syscall"
            )
            syscall.payload.setdefault("filesystem_event_ids", []).append(
                observation.event_id
            )
            matched += 1
        elif candidates:
            observation.anomalies.append(
                "filesystem_event_matches_multiple_os_write_syscalls"
            )
            observation.payload["candidate_os_syscall_event_ids"] = [
                event.event_id for event in candidates[:20]
            ]
            ambiguous += 1
        else:
            unmatched += 1
    return {
        "matched_unique_write_syscall": matched,
        "ambiguous_write_syscalls": ambiguous,
        "unmatched_filesystem_events": unmatched,
        "tolerance_ns": tolerance_ns,
    }


def _same_hook_scope(hook: CanonicalEvent, tool: CanonicalEvent) -> bool:
    if (
        hook.turn_id is not None
        and tool.turn_id is not None
        and hook.turn_id != tool.turn_id
    ):
        return False
    if (
        hook.thread_id is not None
        and tool.thread_id is not None
        and hook.thread_id != tool.thread_id
    ):
        return False
    return True


def _observed_item_id(event: CanonicalEvent) -> str | None:
    """Return only source-observed item IDs, never synthetic event fallbacks."""

    payload = event.payload
    if event.action_type == "approval_request":
        params = payload.get("params")
        if isinstance(params, dict):
            value = params.get("itemId") or params.get("callId")
            return str(value) if value is not None else None
        return None

    item = payload.get("item")
    if isinstance(item, dict) and item.get("id") is not None:
        return str(item["id"])
    return None


def correlate_hook_events(events: list[CanonicalEvent]) -> dict[str, int]:
    """Correlate lifecycle-hook evidence to tool actions using exact IDs.

    Hook input ``tool_use_id`` is matched against the source-observed app-server
    item id. App-server hook run ids remain opaque and are never parsed.
    """

    turn_parents = {
        event.turn_id: event.event_id
        for event in events
        if event.action_type == "turn"
        and event.source_event == "turn/started"
        and event.turn_id is not None
    }
    hooks = [
        event for event in events if event.action_type in {"hook", "hook_input"}
    ]
    targets = [
        event
        for event in events
        if event.action_type in _TOOL_ACTION_TYPES | {"approval_request"}
        and _observed_item_id(event) is not None
    ]
    targets_by_item_id: dict[str, list[CanonicalEvent]] = {}
    for target in targets:
        item_id = _observed_item_id(target)
        assert item_id is not None
        targets_by_item_id.setdefault(item_id, []).append(target)

    for hook in hooks:
        if hook.parent_event_id is None and hook.turn_id in turn_parents:
            hook.parent_event_id = turn_parents[hook.turn_id]

        if hook.tool_use_id is None:
            continue
        candidates = [
            target
            for target in targets_by_item_id.get(hook.tool_use_id, [])
            if _same_hook_scope(hook, target)
        ]
        if hook.hook_event_name == "PermissionRequest":
            approval_candidates = [
                target
                for target in candidates
                if target.action_type == "approval_request"
            ]
            if approval_candidates:
                candidates = approval_candidates
            else:
                candidates = [
                    target
                    for target in candidates
                    if target.action_type in _TOOL_ACTION_TYPES
                ]
        else:
            candidates = [
                target
                for target in candidates
                if target.action_type in _TOOL_ACTION_TYPES
            ]
        if len(candidates) > 1:
            hook.anomalies.append("hook_tool_correlation_ambiguous")
            continue
        if not candidates:
            if hook.hook_event_name in _TOOL_SCOPED_HOOKS:
                hook.anomalies.append("hook_tool_event_not_observed")
            continue

        target = candidates[0]
        source_evidence = str(
            hook.payload.get("_tool_use_id_evidence") or "canonical_event.tool_use_id"
        )
        target_field = (
            "app_server.request.params.itemId"
            if target.action_type == "approval_request"
            else "app_server.item.id"
        )
        hook.related_event_id = target.event_id
        hook.correlation_kind = (
            "hook_to_approval"
            if target.action_type == "approval_request"
            else "hook_to_tool"
        )
        hook.correlation_evidence = f"{source_evidence} == {target_field}"
        hook.correlation_confidence = 1.0

        hook_time = hook.timestamp_start_ns or 0
        if (
            hook.source is EventSource.HOOK
            and hook.hook_event_name == "PreToolUse"
            and hook_time
            and target.timestamp_start_ns
            and hook_time > target.timestamp_start_ns
        ):
            hook.anomalies.append("pre_tool_hook_observed_after_tool_start")
        if (
            hook.source is EventSource.HOOK
            and hook.hook_event_name == "PostToolUse"
            and hook_time
            and target.timestamp_end_ns
            and hook_time < target.timestamp_end_ns
        ):
            hook.anomalies.append("post_tool_hook_observed_before_tool_end")

    targets_by_event_id = {target.event_id: target for target in targets}
    correlated_hooks = [
        hook
        for hook in hooks
        if hook.related_event_id is not None
        and hook.related_event_id in targets_by_event_id
    ]
    correlated_tool_ids = {
        str(hook.related_event_id)
        for hook in correlated_hooks
        if targets_by_event_id[str(hook.related_event_id)].action_type
        in _TOOL_ACTION_TYPES
    }
    correlated_approval_ids = {
        str(hook.related_event_id)
        for hook in correlated_hooks
        if targets_by_event_id[str(hook.related_event_id)].action_type
        == "approval_request"
    }
    spool_groups: dict[str, set[str]] = {}
    for hook in correlated_hooks:
        if hook.source is not EventSource.HOOK:
            continue
        target = str(hook.related_event_id)
        if targets_by_event_id[target].action_type not in _TOOL_ACTION_TYPES:
            continue
        spool_groups.setdefault(target, set()).add(
            str(hook.hook_event_name or hook.source_event)
        )

    complete_pairs = sum(
        1
        for names in spool_groups.values()
        if {"PreToolUse", "PostToolUse"}.issubset(names)
    )
    pre_only = sum(
        1
        for names in spool_groups.values()
        if "PreToolUse" in names and "PostToolUse" not in names
    )
    post_only = sum(
        1
        for names in spool_groups.values()
        if "PostToolUse" in names and "PreToolUse" not in names
    )
    tool_scoped_hooks = [
        hook for hook in hooks if hook.hook_event_name in _TOOL_SCOPED_HOOKS
    ]
    tool_hooks_with_id = [
        hook for hook in tool_scoped_hooks if hook.tool_use_id is not None
    ]
    spool_tool_hooks = [
        hook for hook in tool_scoped_hooks if hook.source is EventSource.HOOK
    ]
    return {
        "hook_events": len(hooks),
        "tool_scoped_hook_events": len(tool_scoped_hooks),
        "tool_hook_events_with_id": len(tool_hooks_with_id),
        "correlated_hook_events": len(correlated_hooks),
        "unmatched_hook_events_with_id": sum(
            1 for hook in tool_hooks_with_id if hook.related_event_id is None
        ),
        "spool_tool_hook_events": len(spool_tool_hooks),
        "correlated_spool_tool_hook_events": sum(
            1 for hook in spool_tool_hooks if hook.related_event_id is not None
        ),
        "tool_calls_with_hook_evidence": len(correlated_tool_ids),
        "approval_requests_with_hook_evidence": len(correlated_approval_ids),
        "complete_pre_post_pairs": complete_pairs,
        "pre_only_pairs": pre_only,
        "post_only_pairs": post_only,
    }


def normalize_run(run_dir: Path) -> list[dict[str, Any]]:
    layout = RunLayout.open(run_dir)
    events = normalize_appserver(iter_jsonl(layout.appserver_raw))
    events.extend(normalize_hooks(iter_jsonl(layout.hooks_raw)))
    otel_events, otel_raw = normalize_otel_rows(
        iter_jsonl(layout.otel_trace_raw)
    )
    events.extend(otel_events)
    function_rows, function_raw = read_function_rows(layout.functions_raw)
    process_instances = {
        str(row["process_instance_id"])
        for row in function_rows
        if row.get("process_instance_id") is not None
    }
    ended_instances = {
        str(row["process_instance_id"])
        for row in function_rows
        if row.get("kind") == "process_end"
        and row.get("process_instance_id") is not None
    }
    sender_drops: dict[str, int] = {}
    for row in function_rows:
        instance = row.get("process_instance_id")
        if instance is None:
            continue
        try:
            dropped = int(row.get("records_dropped") or row.get("dropped_before") or 0)
        except (TypeError, ValueError):
            continue
        sender_drops[str(instance)] = max(sender_drops.get(str(instance), 0), dropped)
    manifest = json_load(layout.manifest) if layout.manifest.exists() else {}
    repo_value = manifest.get("repo")
    if repo_value is None and isinstance(manifest.get("git"), dict):
        repo_value = manifest["git"].get("repo")
    if function_rows and repo_value is not None:
        events.extend(normalize_function_rows(function_rows, Path(str(repo_value))))
    elif function_rows:
        function_raw["invalid_records"] += len(function_rows)
        function_raw["valid_records"] = 0
    filesystem_events, filesystem_raw = normalize_filesystem_rows(
        iter_jsonl(layout.filesystem_raw),
        repo=Path(str(repo_value)) if repo_value is not None else None,
    )
    events.extend(filesystem_events)
    os_audit_events, os_audit_raw = normalize_os_audit_rows(
        iter_jsonl(layout.os_audit_raw),
        repo=Path(str(repo_value)) if repo_value is not None else None,
    )
    events.extend(os_audit_events)
    hook_correlation = correlate_hook_events(events)
    function_correlation = correlate_function_events(events)
    filesystem_correlation = correlate_filesystem_events(events)
    os_audit_correlation = correlate_os_audit_events(events)
    filesystem_syscall_correlation = correlate_filesystem_syscalls(events)
    events.sort(
        key=lambda event: (
            event.timestamp_start_ns if event.timestamp_start_ns is not None else 2**63,
            event.wall_time_start_ns if event.wall_time_start_ns is not None else 2**63,
            event.source.value,
            event.seq,
        )
    )
    rows: list[dict[str, Any]] = []
    for seq, event in enumerate(events, start=1):
        event.seq = seq
        rows.append(event.as_dict())
    write_jsonl(layout.events, rows)
    summary = {
        "schema_version": "1.2",
        "event_count": len(rows),
        "source_counts": {
            source.value: sum(1 for event in events if event.source == source)
            for source in EventSource
            if any(event.source == source for event in events)
        },
        "action_counts": {
            action_type: sum(1 for event in events if event.action_type == action_type)
            for action_type in sorted({event.action_type for event in events})
        },
        "token_usage": _token_usage_summary(events),
        "hook_correlation": hook_correlation,
        "harness_telemetry": {
            "raw": otel_raw,
            "collector": (
                json_load(layout.otel_trace_summary)
                if layout.otel_trace_summary.exists()
                else {}
            ),
        },
        "function_trace": {
            "raw": function_raw,
            "correlation": function_correlation,
            "languages": sorted(
                {
                    str(event.language)
                    for event in events
                    if event.action_type == "function_call" and event.language
                }
            ),
            "incomplete_calls": sum(
                1
                for event in events
                if event.action_type == "function_call"
                and event.status == EventStatus.INCOMPLETE
            ),
            "processes_observed": len(process_instances),
            "processes_without_end_record": len(process_instances - ended_instances),
            "sender_reported_dropped_records": sum(sender_drops.values()),
            "limit_reached_records": sum(
                1 for row in function_rows if row.get("kind") == "limit_reached"
            ),
            "backends": sorted(
                {
                    str(row["backend"])
                    for row in function_rows
                    if row.get("backend") is not None
                }
            ),
        },
        "file_audit": {
            "raw": filesystem_raw,
            "correlation": filesystem_correlation,
            "collector": (
                json_load(layout.file_audit_summary)
                if layout.file_audit_summary.exists()
                else {}
            ),
        },
        "os_audit": {
            "raw": os_audit_raw,
            "correlation": os_audit_correlation,
            "filesystem_correlation": filesystem_syscall_correlation,
            "collector": {},
        },
        "anomalies": [
            {"event_id": event.event_id, "anomalies": event.anomalies}
            for event in events
            if event.anomalies
        ],
    }
    os_collector: dict[str, Any] = {}
    if layout.os_audit_summary.exists():
        loaded_os_collector = json_load(layout.os_audit_summary)
        if isinstance(loaded_os_collector, dict):
            os_collector = dict(loaded_os_collector)
            nested_stats = loaded_os_collector.get("collector")
            if isinstance(nested_stats, dict):
                for key, value in nested_stats.items():
                    os_collector.setdefault(str(key), value)
    manifest_os_audit = manifest.get("os_audit")
    if isinstance(manifest_os_audit, dict):
        for key, value in manifest_os_audit.items():
            os_collector.setdefault(str(key), value)
    os_collector.setdefault(
        "status", "unknown" if os_audit_raw["raw_records"] else "disabled"
    )
    summary["os_audit"]["collector"] = os_collector
    atomic_json_dump(layout.root / "normalization_summary.json", summary)
    return rows
