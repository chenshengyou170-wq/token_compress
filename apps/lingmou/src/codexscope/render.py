from __future__ import annotations

import importlib.resources
import json
import math
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

from .storage import RunLayout, json_load


_MAX_DISPLAY_TEXT = 4_096
_MAX_ACTION_ROWS = 10_000
_MAX_HOOK_ROWS = 5_000
_MAX_RUNTIME_ROWS = 20_000
_MAX_OS_SYSCALL_ROWS = 5_000
_MAX_HOOK_EDGE_ROWS = 10_000
_TOKEN_USAGE_FIELDS = (
    "cached_input_tokens",
    "input_tokens",
    "output_tokens",
    "reasoning_output_tokens",
    "total_tokens",
)


def _token_breakdown(value: object) -> dict[str, int] | None:
    if not isinstance(value, dict):
        return None
    result: dict[str, int] = {}
    for key in _TOKEN_USAGE_FIELDS:
        count = value.get(key)
        if type(count) is not int or count < 0:
            return None
        result[key] = count
    return result


def _token_usage_event(action: dict[str, Any]) -> dict[str, Any] | None:
    """Extract only numeric, display-safe usage fields from a canonical event."""

    payload = _mapping(action.get("payload"))
    usage = _mapping(payload.get("token_usage"))
    last = _token_breakdown(usage.get("last"))
    total = _token_breakdown(usage.get("total"))
    if last is None or total is None:
        return None
    context_window = usage.get("model_context_window")
    if type(context_window) is not int or context_window < 0:
        context_window = None
    return {
        "event_id": _text(action.get("event_id") or action.get("action_id"), 1_024),
        "seq": action.get("seq"),
        "thread_id": _text(action.get("thread_id"), 512),
        "turn_id": _text(action.get("turn_id"), 512),
        "start_ns": action.get("timestamp_start_ns", action.get("start_mono_ns")),
        "wall_start_ns": action.get("wall_time_start_ns"),
        "model_context_window": context_window,
        "last": last,
        "total": total,
    }


def _display_live_token_data(
    value: object,
    full_reconciliation: object | None = None,
) -> dict[str, Any]:
    """Copy the bounded live estimator history without arbitrary protocol payloads."""

    live = _mapping(value)
    full = _mapping(full_reconciliation)
    reconciliation = (
        full
        if isinstance(full.get("history"), list)
        else _mapping(live.get("token_reconciliation"))
    )
    summary = _mapping(reconciliation.get("summary"))
    summary_keys = {
        "count",
        "retained_count",
        "output_error_sample_count",
        "p90_coverage_sample_count",
        "output_p50_mae_tokens",
        "output_p90_mae_tokens",
        "output_p50_mape_pct",
        "output_p50_mean_bias_tokens",
        "p90_coverage_pct",
    }
    history_keys = {
        "slice_index",
        "turn_id",
        "model",
        "completed_at",
        "active_elapsed_seconds",
        "observed_output_tokens",
        "observed_output_text_tokens",
        "observed_output_tool_argument_tokens",
        "observed_output_tool_argument_item_count",
        "observed_output_tool_argument_delta_count",
        "observed_output_source",
        "estimated_output_tokens_p50",
        "estimated_output_tokens_p90",
        "output_error_tokens_p50",
        "output_error_tokens_p90",
        "output_error_pct_p50",
        "output_error_pct_p90",
        "p90_interval_covered_official",
        "estimated_input_tokens_p50",
        "estimated_input_tokens_p90",
        "input_error_tokens_p50",
        "input_error_tokens_p90",
        "input_error_pct_p50",
        "input_error_pct_p90",
        "preflight_input_tokens",
        "preflight_input_residual_tokens",
        "input_estimate_source",
        "input_request_tokenizer_source",
        "input_request_component_tokens",
        "input_request_context_complete",
        "input_modality_counts",
        "input_text_tokens_exact",
        "input_multimodal_tokens_derived",
        "input_provider_count_latency_ms",
        "input_provider_count_status",
        "tool_context_tokens_estimated",
        "official_input_tokens",
        "official_output_tokens",
        "official_reasoning_output_tokens",
        "official_total_tokens",
        "hidden_or_framing_residual_tokens",
    }
    trend_keys = {
        "recorded_at",
        "turn_id",
        "slice_index",
        "activity",
        "quality",
        "session_tokens_lower_bound",
        "session_tokens_likely_p50",
        "session_tokens_likely_p90",
        "exact_total_tokens",
        "baseline_exact_total_tokens",
        "token_update_count",
    }

    def selected_rows(
        raw: object,
        keys: set[str],
        limit: int | None,
    ) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        if not isinstance(raw, list):
            return rows
        selected = raw if limit is None else raw[-limit:]
        for item in selected:
            if isinstance(item, dict):
                rows.append({key: item.get(key) for key in keys if key in item})
        return rows

    history = selected_rows(
        reconciliation.get("history"),
        history_keys,
        None if reconciliation is full else 512,
    )
    if not history:
        inflight = _mapping(live.get("inflight_token_estimate"))
        last_reconciliation = inflight.get("last_reconciliation")
        if isinstance(last_reconciliation, dict):
            history = selected_rows([last_reconciliation], history_keys, 1)
        if "count" not in summary and inflight.get("reconciliation_count") is not None:
            summary = {**summary, "count": inflight.get("reconciliation_count")}

    for row in history:
        official = row.get("official_output_tokens")
        p50 = row.get("estimated_output_tokens_p50")
        p90 = row.get("estimated_output_tokens_p90")
        observed = row.get("observed_output_tokens")
        if type(official) is int and type(p50) is int:
            row.setdefault("output_error_tokens_p50", p50 - official)
            if official > 0:
                row.setdefault(
                    "output_error_pct_p50",
                    round(100.0 * (p50 - official) / official, 2),
                )
        if type(official) is int and type(p90) is int:
            row.setdefault("output_error_tokens_p90", p90 - official)
            if official > 0:
                row.setdefault(
                    "output_error_pct_p90",
                    round(100.0 * (p90 - official) / official, 2),
                )
        if type(official) is int and type(p90) is int and type(observed) is int:
            row.setdefault(
                "p90_interval_covered_official",
                observed <= official <= p90,
            )

    def numeric_values(key: str) -> list[float]:
        return [
            float(row[key])
            for row in history
            if isinstance(row.get(key), (int, float))
            and not isinstance(row.get(key), bool)
        ]

    p50_errors = numeric_values("output_error_tokens_p50")
    p90_errors = numeric_values("output_error_tokens_p90")
    p50_percent_errors = numeric_values("output_error_pct_p50")
    covered = [
        row["p90_interval_covered_official"]
        for row in history
        if isinstance(row.get("p90_interval_covered_official"), bool)
    ]

    def mean(values: list[float], *, absolute: bool = False) -> float | None:
        if absolute:
            values = [abs(value) for value in values]
        return None if not values else round(sum(values) / len(values), 2)

    summary = {
        "retained_count": len(history),
        "output_error_sample_count": len(p50_errors),
        "p90_coverage_sample_count": len(covered),
        "output_p50_mae_tokens": mean(p50_errors, absolute=True),
        "output_p90_mae_tokens": mean(p90_errors, absolute=True),
        "output_p50_mape_pct": mean(p50_percent_errors, absolute=True),
        "output_p50_mean_bias_tokens": mean(p50_errors),
        "p90_coverage_pct": (
            None if not covered else round(100.0 * sum(covered) / len(covered), 2)
        ),
        **summary,
    }

    return {
        "updated_at": _text(live.get("updated_at"), 160),
        "reconciliation": {
            "summary": {key: summary.get(key) for key in summary_keys if key in summary},
            "history": history,
        },
        "trend": selected_rows(live.get("token_trend"), trend_keys, 3_600),
    }


def _text(value: object, limit: int = _MAX_DISPLAY_TEXT) -> str:
    rendered = "" if value is None else str(value)
    if len(rendered) > limit:
        return rendered[: limit - 1] + "…"
    return rendered


def _mapping(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _showcase_data(value: object) -> dict[str, Any]:
    """Keep only small, display-safe provenance metadata for composed reports."""

    raw = _mapping(value)
    sources: list[dict[str, Any]] = []
    for item in raw.get("sources") or []:
        if not isinstance(item, dict):
            continue
        sources.append(
            {
                "id": _text(item.get("id") or item.get("source_dataset"), 160),
                "aspect": _text(item.get("aspect"), 240),
                "label": _text(item.get("label"), 240),
                "path": _text(item.get("path"), 1_024),
                "kind": _text(item.get("kind"), 240),
                "count": item.get("count"),
                "description": _text(item.get("description"), 1_024),
            }
        )
        if len(sources) >= 20:
            break
    return {
        "combined": raw.get("combined") is True,
        "report_kind": _text(raw.get("report_kind"), 160),
        "warning": _text(raw.get("warning"), 2_048),
        "cross_component_correlation": raw.get("cross_component_correlation") is True,
        "sources": sources,
    }


def _function_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return {
            "path": _text(value.get("path"), 1_024),
            "name": _text(value.get("name"), 1_024),
            "role": _text(value.get("role"), 80),
            "start_line": value.get("start_line"),
            "end_line": value.get("end_line"),
            "confidence": value.get("confidence"),
            "evidence": _text(value.get("evidence"), 512),
        }
    return {"path": "", "name": _text(value), "role": ""}


def _time_key(action: dict[str, Any]) -> tuple[int, int, int, str]:
    value = action.get("timestamp_start_ns", action.get("start_mono_ns"))
    try:
        timestamp = int(value) if value is not None else 0
    except (TypeError, ValueError):
        timestamp = 0
    return (
        0 if timestamp else 1,
        timestamp,
        int(action.get("seq") or 0),
        str(action.get("event_id") or action.get("action_id") or ""),
    )


def _base_event(action: dict[str, Any]) -> dict[str, Any]:
    start = action.get("timestamp_start_ns", action.get("start_mono_ns"))
    end = action.get("timestamp_end_ns", action.get("end_mono_ns", start))
    wall_start = action.get("wall_time_start_ns")
    wall_end = action.get("wall_time_end_ns", wall_start)
    payload = _mapping(action.get("payload"))
    action_type = _text(action.get("action_type") or action.get("kind"), 100)
    return {
        "event_id": _text(action.get("event_id") or action.get("action_id"), 1_024),
        "seq": action.get("seq"),
        "source": _text(action.get("source"), 80),
        "source_event": _text(action.get("source_event"), 240),
        "action_type": action_type,
        "actor": _text(action.get("actor") or "main_agent", 512),
        "phase": _text(action.get("phase"), 80),
        "status": _text(action.get("status"), 80),
        "start_ns": start,
        "end_ns": end,
        "wall_start_ns": wall_start,
        "wall_end_ns": wall_end,
        "duration_ms": action.get("duration_ms"),
        "session_id": _text(action.get("session_id"), 512),
        "thread_id": _text(action.get("thread_id"), 512),
        "turn_id": _text(action.get("turn_id"), 512),
        "item_id": _text(action.get("item_id"), 512),
        "parent_event_id": _text(action.get("parent_event_id"), 1_024),
        "tool": _text(action.get("tool"), 512),
        "operation": _text(action.get("operation") or action.get("command"), 4_096),
        "cwd": _text(action.get("cwd"), 1_024),
        "approval": _text(action.get("approval"), 160),
        "exit_code": action.get("exit_code"),
        "targets": [_text(value, 1_024) for value in action.get("targets") or []],
        "affected_files": [
            _text(value, 1_024) for value in action.get("affected_files") or []
        ],
        "attempted_files": [
            _text(value, 1_024) for value in action.get("attempted_files") or []
        ],
        "affected_functions": [
            _function_dict(value) for value in action.get("affected_functions") or []
        ],
        "read_functions": [
            _function_dict(value) for value in action.get("read_functions") or []
        ],
        "executed_functions": [
            _function_dict(value) for value in action.get("executed_functions") or []
        ],
        "trigger": _text(action.get("trigger"), 1_024),
        "trigger_confidence": action.get("trigger_confidence"),
        "related_event_id": _text(action.get("related_event_id"), 1_024),
        "correlation_kind": _text(action.get("correlation_kind"), 240),
        "correlation_evidence": _text(action.get("correlation_evidence"), 2_048),
        "correlation_confidence": action.get("correlation_confidence"),
        "test_outcome": _text(action.get("test_outcome"), 80),
        "anomalies": [_text(value, 1_024) for value in action.get("anomalies") or []],
        "source_dataset": _text(
            action.get("source_dataset") or payload.get("source_dataset"), 512
        ),
        "pid": action.get("process_id", payload.get("pid")),
        "tid": action.get("runtime_thread_id", payload.get("tid")),
        "ppid": action.get("parent_process_id", payload.get("ppid")),
    }


def _display_event(action: dict[str, Any]) -> dict[str, Any]:
    event = _base_event(action)
    event["observation_only"] = event["action_type"] in {
        "filesystem_event",
        "workspace_reconcile",
        "os_syscall",
    }
    functions: dict[tuple[str, str, str], dict[str, Any]] = {}
    for role, key in (("write", "affected_functions"), ("read", "read_functions")):
        for function in event[key]:
            function = dict(function)
            function["role"] = function.get("role") or role
            identity = (
                str(function.get("path") or ""),
                str(function.get("name") or ""),
                str(function.get("role") or ""),
            )
            functions[identity] = function
    event["functions"] = list(functions.values())
    return event


def _hook_event(action: dict[str, Any]) -> dict[str, Any]:
    event = _base_event(action)
    event.update(
        {
            "hook_event_name": _text(
                action.get("hook_event_name") or action.get("source_event"), 240
            ),
            "hook_run_id": _text(action.get("hook_run_id"), 1_024),
            "tool_use_id": _text(action.get("tool_use_id"), 1_024),
            # Hook collector payloads are recursively credential-redacted and
            # size-bounded before they reach the run directory.  Keeping the
            # normalized payload here is intentional: this is the hook-detail
            # view requested by the operator.  Non-hook event payloads remain
            # excluded from the report.
            "payload": _mapping(action.get("payload")),
        }
    )
    return event


def _runtime_event(action: dict[str, Any]) -> dict[str, Any]:
    event = _base_event(action)
    payload = _mapping(action.get("payload"))
    event.update(
        {
            "process_handle": _text(action.get("process_handle"), 512),
            "process_id_verified": action.get("process_id_verified") is True,
            "process_instance_id": _text(action.get("process_instance_id"), 1_024),
            "ancestor_process_ids": list(action.get("ancestor_process_ids") or []),
            "language": _text(action.get("language"), 80),
            "backend": _text(payload.get("backend") or action.get("source_event"), 160),
            "call_id": _text(action.get("call_id"), 1_024),
            "parent_call_id": _text(action.get("parent_call_id"), 1_024),
            "caller_event_id": _text(action.get("caller_event_id"), 1_024),
            "outcome": _text(payload.get("outcome"), 80),
            "stack_relation": _text(payload.get("stack_relation"), 160),
            "code_kind": _text(payload.get("code_kind"), 160),
            "module": _text(payload.get("module"), 1_024),
            "function_address": _text(payload.get("function_address"), 160),
            "module_offset": _text(payload.get("module_offset"), 160),
            "enter_collector_seq": payload.get("enter_collector_seq"),
            "exit_collector_seq": payload.get("exit_collector_seq"),
        }
    )
    return event


def _runtime_tree(actions: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows = [_runtime_event(action) for action in actions]
    by_id = {row["event_id"]: row for row in rows if row["event_id"]}
    children: dict[str, list[dict[str, Any]]] = defaultdict(list)
    roots: list[dict[str, Any]] = []

    def scope(row: dict[str, Any]) -> tuple[str, str, object]:
        return (
            str(row.get("backend") or ""),
            str(row.get("process_instance_id") or ""),
            row.get("tid"),
        )

    calls_by_scope_and_id: dict[tuple[tuple[str, str, object], str], list[dict[str, Any]]] = (
        defaultdict(list)
    )
    for row in rows:
        call_id = str(row.get("call_id") or "")
        if call_id:
            calls_by_scope_and_id[(scope(row), call_id)].append(row)

    for row in rows:
        parent_id = str(row.get("caller_event_id") or "")
        if not parent_id and row.get("parent_call_id"):
            candidates = calls_by_scope_and_id.get(
                (scope(row), str(row.get("parent_call_id"))), []
            )
            if len(candidates) == 1 and candidates[0] is not row:
                parent_id = str(candidates[0].get("event_id") or "")
                row["tree_parent_source"] = "unique_parent_call_id_fallback"
            elif len(candidates) > 1:
                row["tree_anomaly"] = "parent_call_id_ambiguous"
            else:
                row["tree_anomaly"] = "parent_call_id_not_observed"
        elif parent_id:
            row["tree_parent_source"] = "caller_event_id"
        row["tree_parent_event_id"] = parent_id
        parent = by_id.get(parent_id)
        if parent is not None and parent is not row and scope(parent) == scope(row):
            children[parent_id].append(row)
        else:
            roots.append(row)
            if parent_id:
                row["tree_anomaly"] = "caller_missing_or_cross_scope"

    for values in children.values():
        values.sort(key=_display_time_key)
    roots.sort(key=lambda row: (scope(row), _display_time_key(row)))

    ordered: list[dict[str, Any]] = []
    visited: set[str] = set()

    def append_component(root: dict[str, Any], *, disconnected: bool = False) -> None:
        stack: list[tuple[dict[str, Any], int]] = [(root, 0)]
        while stack:
            row, depth = stack.pop()
            event_id = str(row.get("event_id") or "")
            if event_id and event_id in visited:
                continue
            if event_id:
                visited.add(event_id)
            row["depth"] = depth
            row["child_count"] = len(children.get(event_id, []))
            if disconnected and depth == 0 and not row.get("tree_anomaly"):
                row["tree_anomaly"] = "cycle_or_disconnected_component"
            ordered.append(row)
            for child in reversed(children.get(event_id, [])):
                stack.append((child, depth + 1))

    for root in roots:
        append_component(root)
    for row in sorted(rows, key=_display_time_key):
        event_id = str(row.get("event_id") or "")
        if not event_id or event_id not in visited:
            append_component(row, disconnected=True)

    process_instances = {
        str(row.get("process_instance_id"))
        for row in rows
        if row.get("process_instance_id")
    }
    threads = {
        (str(row.get("process_instance_id") or ""), row.get("tid")) for row in rows
    }
    functions = {
        (
            function.get("path"),
            function.get("name"),
            function.get("start_line"),
        )
        for row in rows
        for function in row.get("executed_functions") or []
    }
    return ordered, {
        "total": len(rows),
        "completed": sum(row.get("status") == "completed" for row in rows),
        "incomplete": sum(row.get("status") == "incomplete" for row in rows),
        "processes": len(process_instances),
        "threads": len(threads),
        "unique_functions": len(functions),
        "roots": sum(int(row.get("depth") or 0) == 0 for row in ordered),
        "max_depth": max((int(row.get("depth") or 0) for row in ordered), default=0),
        "matched_to_commands": sum(bool(row.get("related_event_id")) for row in rows),
    }


def _display_time_key(event: dict[str, Any]) -> tuple[int, int, int, str]:
    value = event.get("start_ns")
    try:
        timestamp = int(value) if value is not None else 0
    except (TypeError, ValueError):
        timestamp = 0
    return (
        0 if timestamp else 1,
        timestamp,
        int(event.get("seq") or 0),
        str(event.get("event_id") or ""),
    )


def _os_event(action: dict[str, Any]) -> dict[str, Any]:
    event = _base_event(action)
    payload = _mapping(action.get("payload"))
    event.update(
        {
            "backend": _text(payload.get("backend") or action.get("tool"), 160),
            "comm": _text(payload.get("comm"), 240),
            "syscall": _text(payload.get("syscall") or action.get("operation"), 240),
            "category": _text(payload.get("category"), 160),
            "access": _text(payload.get("access"), 160),
            "path_scope": _text(payload.get("path_scope"), 160),
            "fd": payload.get("fd"),
            "bytes": payload.get("bytes"),
            "endpoint": payload.get("endpoint"),
            "result": payload.get("result"),
            "errno": payload.get("errno"),
            "success": payload.get("success"),
            "duration_ns": payload.get("duration_ns"),
            "arguments": payload.get("arguments"),
            "synthetic": payload.get("synthetic") is True,
            "is_read": payload.get("is_read") is True,
            "is_write": payload.get("is_write") is True,
            "is_network": payload.get("is_network") is True,
            "pid_evidence": _text(payload.get("pid_evidence"), 240),
            "tool_attribution": _text(payload.get("tool_attribution"), 240),
            "candidate_event_ids": list(payload.get("candidate_event_ids") or []),
            "filesystem_event_ids": list(payload.get("filesystem_event_ids") or []),
        }
    )
    return event


def _os_report(rows: list[dict[str, Any]]) -> dict[str, Any]:
    process_map: dict[str, dict[str, Any]] = {}
    endpoint_map: dict[str, dict[str, Any]] = {}
    for row in rows:
        pid_key = str(row.get("pid") if row.get("pid") is not None else "unknown")
        process = process_map.setdefault(
            pid_key,
            {
                "pid": row.get("pid"),
                "ppid": row.get("ppid"),
                "comm": row.get("comm") or "",
                "syscalls": 0,
                "reads": 0,
                "writes": 0,
                "network": 0,
                "failed": 0,
            },
        )
        process["syscalls"] += 1
        process["reads"] += int(bool(row.get("is_read")))
        process["writes"] += int(bool(row.get("is_write")))
        process["network"] += int(bool(row.get("is_network")))
        process["failed"] += int(
            row.get("success") is False or row.get("status") == "failed"
        )
        endpoint_value = row.get("endpoint")
        if endpoint_value is not None:
            if isinstance(endpoint_value, (dict, list)):
                label = json.dumps(
                    endpoint_value,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
            else:
                label = str(endpoint_value)
            endpoint = endpoint_map.setdefault(
                label, {"endpoint": label, "events": 0, "pids": set()}
            )
            endpoint["events"] += 1
            endpoint["pids"].add(pid_key)

    processes = sorted(
        process_map.values(), key=lambda row: (-int(row["syscalls"]), str(row["pid"]))
    )
    endpoints = sorted(
        endpoint_map.values(),
        key=lambda row: (-int(row["events"]), str(row["endpoint"])),
    )
    for endpoint in endpoints:
        endpoint["pids"] = sorted(endpoint["pids"])
    return {
        "total": len(rows),
        "reads": sum(bool(row.get("is_read")) for row in rows),
        "writes": sum(bool(row.get("is_write")) for row in rows),
        "network": sum(bool(row.get("is_network")) for row in rows),
        "failed": sum(
            row.get("success") is False or row.get("status") == "failed" for row in rows
        ),
        "correlated": sum(bool(row.get("related_event_id")) for row in rows),
        "syscalls": dict(Counter(str(row.get("syscall") or "unknown") for row in rows)),
        "categories": dict(Counter(str(row.get("category") or "unknown") for row in rows)),
        "accesses": dict(Counter(str(row.get("access") or "unknown") for row in rows)),
        "processes": processes,
        "endpoints": endpoints,
    }


def _hook_report(rows: list[dict[str, Any]]) -> dict[str, Any]:
    collector_rows = [row for row in rows if row.get("source") == "hook"]
    pairs: dict[str, set[str]] = defaultdict(set)
    for row in collector_rows:
        target = str(row.get("related_event_id") or "")
        if target:
            pairs[target].add(str(row.get("hook_event_name") or row.get("source_event") or ""))
    return {
        "total": len(rows),
        "appserver": sum(row.get("source") == "app_server" for row in rows),
        "collector": len(collector_rows),
        "correlated": sum(bool(row.get("related_event_id")) for row in rows),
        "unmatched_with_tool_id": sum(
            bool(row.get("tool_use_id")) and not row.get("related_event_id") for row in rows
        ),
        "complete_pre_post_pairs": sum(
            {"PreToolUse", "PostToolUse"}.issubset(names) for names in pairs.values()
        ),
        "pre_only_pairs": sum(
            "PreToolUse" in names and "PostToolUse" not in names for names in pairs.values()
        ),
        "post_only_pairs": sum(
            "PostToolUse" in names and "PreToolUse" not in names for names in pairs.values()
        ),
        "event_names": dict(
            Counter(str(row.get("hook_event_name") or "unknown") for row in rows)
        ),
        "sources": dict(Counter(str(row.get("source") or "unknown") for row in rows)),
        "statuses": dict(Counter(str(row.get("status") or "unknown") for row in rows)),
    }


def _graph_report(graph: dict[str, Any], hook_ids: set[str]) -> dict[str, Any]:
    nodes = [node for node in graph.get("nodes") or [] if isinstance(node, dict)]
    edges = [edge for edge in graph.get("edges") or [] if isinstance(edge, dict)]
    hook_edges = [
        {
            key: edge.get(key)
            for key in (
                "source",
                "target",
                "type",
                "confidence",
                "evidence",
                "correlation_kind",
                "hook_event",
                "tool_use_id",
            )
        }
        for edge in edges
        if str(edge.get("source")) in hook_ids or str(edge.get("target")) in hook_ids
    ]
    hook_edge_total = len(hook_edges)
    hook_edges = _representative_sample(
        hook_edges,
        _MAX_HOOK_EDGE_ROWS,
        facet_fields=("type", "correlation_kind", "hook_event", "confidence"),
    )
    return {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "node_types": dict(Counter(str(node.get("type") or "unknown") for node in nodes)),
        "edge_types": dict(Counter(str(edge.get("type") or "unknown") for edge in edges)),
        "hook_edges": hook_edges,
        "hook_edge_total": hook_edge_total,
        "hook_edge_displayed": len(hook_edges),
        "hook_edge_omitted": max(0, hook_edge_total - len(hook_edges)),
    }


def _json_safe(value: Any) -> Any:
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


def _safe_json(value: Any) -> str:
    return (
        json.dumps(_json_safe(value), ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def _load_timeline_template() -> str:
    return (
        importlib.resources.files("codexscope")
        .joinpath("templates/timeline.html")
        .read_text(encoding="utf-8")
    )


def _load_optional_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    value = json_load(path)
    return value if isinstance(value, dict) else {}


def _representative_sample(
    rows: list[dict[str, Any]],
    limit: int,
    *,
    facet_fields: tuple[str, ...],
) -> list[dict[str, Any]]:
    """Keep deterministic coverage across facets, then fill uniformly in time/order."""

    if len(rows) <= limit:
        return rows
    selected: set[int] = {0, len(rows) - 1}
    for field in facet_fields:
        seen: set[str] = set()
        for index, row in enumerate(rows):
            raw = row.get(field)
            if isinstance(raw, (dict, list)):
                value = json.dumps(raw, ensure_ascii=False, sort_keys=True, default=str)
            else:
                value = str(raw)
            if value not in seen:
                seen.add(value)
                selected.add(index)
            if len(selected) >= limit:
                break
        if len(selected) >= limit:
            break
    seen_anomalies: set[str] = set()
    if len(selected) < limit:
        for index, row in enumerate(rows):
            for anomaly in row.get("anomalies") or []:
                value = str(anomaly)
                if value not in seen_anomalies:
                    seen_anomalies.add(value)
                    selected.add(index)
            if len(selected) >= limit:
                break
    if len(selected) < limit:
        slots = limit - len(selected)
        step = len(rows) / max(1, slots)
        for offset in range(slots):
            selected.add(min(len(rows) - 1, int(offset * step)))
            if len(selected) >= limit:
                break
    if len(selected) < limit:
        for index in range(len(rows)):
            selected.add(index)
            if len(selected) >= limit:
                break
    return [rows[index] for index in sorted(selected)[:limit]]


def render_timeline(run_dir: Path, actions: list[dict[str, Any]] | None = None) -> Path:
    layout = RunLayout.open(run_dir)
    if actions is None:
        if layout.enriched.exists():
            loaded = json_load(layout.enriched)
            actions = loaded if isinstance(loaded, list) else []
        else:
            from .storage import iter_jsonl

            actions = list(iter_jsonl(layout.events))
    actions = [action for action in actions if isinstance(action, dict)]
    actions.sort(key=_time_key)

    manifest = _load_optional_json(layout.manifest)
    summary = _load_optional_json(layout.root / "summary.json")
    normalization = _load_optional_json(layout.root / "normalization_summary.json")
    graph = _load_optional_json(layout.graph)
    live_token_data = _display_live_token_data(
        _load_optional_json(layout.root / "live_status.json"),
        _load_optional_json(layout.root / "token_reconciliation_history.json"),
    )
    function_transport = _load_optional_json(layout.function_trace_summary)
    file_audit_transport = _load_optional_json(layout.file_audit_summary)
    os_audit_transport = _load_optional_json(layout.os_audit_summary)

    hook_actions = [
        action
        for action in actions
        if (action.get("action_type") or action.get("kind")) in {"hook", "hook_input"}
    ]
    runtime_actions = [
        action
        for action in actions
        if (action.get("action_type") or action.get("kind")) == "function_call"
    ]
    os_actions = [
        action
        for action in actions
        if (action.get("action_type") or action.get("kind")) == "os_syscall"
    ]
    token_usage_events = [
        event
        for action in actions
        if (action.get("action_type") or action.get("kind")) == "token_usage"
        if (event := _token_usage_event(action)) is not None
    ]
    all_action_events = [
        _display_event(action)
        for action in actions
        if (action.get("action_type") or action.get("kind"))
        not in {"function_call", "os_syscall"}
    ]
    all_hooks = [_hook_event(action) for action in hook_actions]
    all_runtime_calls, runtime_report = _runtime_tree(runtime_actions)
    all_os_syscalls = [_os_event(action) for action in os_actions]
    all_os_syscalls.sort(key=_display_time_key)

    action_events = _representative_sample(
        all_action_events,
        _MAX_ACTION_ROWS,
        facet_fields=("action_type", "status", "source", "actor"),
    )
    hooks = _representative_sample(
        all_hooks,
        _MAX_HOOK_ROWS,
        facet_fields=(
            "hook_event_name",
            "source",
            "status",
            "correlation_kind",
            "tool",
        ),
    )
    runtime_calls = _representative_sample(
        all_runtime_calls,
        _MAX_RUNTIME_ROWS,
        facet_fields=(
            "backend",
            "process_instance_id",
            "tid",
            "language",
            "status",
            "tree_anomaly",
        ),
    )
    os_syscalls = _representative_sample(
        all_os_syscalls,
        _MAX_OS_SYSCALL_ROWS,
        facet_fields=(
            "syscall",
            "category",
            "access",
            "pid",
            "status",
            "path_scope",
            "is_network",
        ),
    )

    action_report = {
        "total": len(all_action_events),
        "displayed": len(action_events),
        "omitted": max(0, len(all_action_events) - len(action_events)),
        "types": dict(
            Counter(str(event.get("action_type") or "unknown") for event in all_action_events)
        ),
        "statuses": dict(
            Counter(str(event.get("status") or "unknown") for event in all_action_events)
        ),
    }
    hook_report = _hook_report(all_hooks)
    hook_report.update(
        {
            "displayed": len(hooks),
            "omitted": max(0, len(all_hooks) - len(hooks)),
        }
    )
    runtime_report.update(
        {
            "displayed": len(runtime_calls),
            "omitted": max(0, len(all_runtime_calls) - len(runtime_calls)),
        }
    )
    os_report = _os_report(all_os_syscalls)
    os_report.update(
        {
            "displayed": len(os_syscalls),
            "omitted": max(0, len(all_os_syscalls) - len(os_syscalls)),
        }
    )

    report_data = {
        "schema_version": "codexscope.unified-report.v2",
        "showcase": _showcase_data(manifest.get("showcase")),
        "manifest": {
            "run_id": manifest.get("run_id"),
            "status": manifest.get("status"),
            "codex_version": manifest.get("codex_version"),
            "model_requested": manifest.get("model_requested"),
            "model_resolved": manifest.get("model_resolved"),
            "git_head": manifest.get("git_head"),
            "git_branch": manifest.get("git_branch"),
            "prompt_sha256": manifest.get("prompt_sha256"),
            "started_at": manifest.get("started_at"),
            "completed_at": manifest.get("completed_at") or manifest.get("finished_at"),
            "error": _text(manifest.get("error"), 4_096),
            "repo": _text(manifest.get("repo"), 1_024),
            "function_trace": manifest.get("function_trace"),
            "file_audit": manifest.get("file_audit"),
            "os_audit": manifest.get("os_audit"),
        },
        "events": action_events,
        "hooks": hooks,
        "runtime_calls": runtime_calls,
        "os_syscalls": os_syscalls,
        "token_usage_events": token_usage_events,
        "token_reconciliation": live_token_data["reconciliation"],
        "token_trend": live_token_data["trend"],
        "summary": summary,
        "normalization": normalization,
        "reports": {
            "actions": action_report,
            "hooks": hook_report,
            "runtime": runtime_report,
            "os": os_report,
            "tokens": {
                "total": len(token_usage_events),
                "displayed": len(token_usage_events),
                "omitted": 0,
                "threads": len(
                    {
                        str(row.get("thread_id"))
                        for row in token_usage_events
                        if row.get("thread_id")
                    }
                ),
                "turns": len(
                    {
                        str(row.get("turn_id"))
                        for row in token_usage_events
                        if row.get("turn_id")
                    }
                ),
                "live_history_updated_at": live_token_data.get("updated_at"),
            },
            "graph": _graph_report(
                graph,
                {
                    str(row.get("event_id"))
                    for row in all_hooks
                    if row.get("event_id")
                },
            ),
        },
        "collector_summaries": {
            "function_trace": function_transport,
            "file_audit": file_audit_transport,
            "os_audit": os_audit_transport,
        },
        "safety": {
            "hook_payloads_included": True,
            "non_hook_payloads_included": False,
            "warning": (
                "本报告包含已采集的 Hook 详情、源码路径、命令、进程元数据、"
                "网络端点和运行时函数身份；即使在内网中也应按敏感资料处理。"
            ),
        },
    }
    output = layout.root / "timeline.html"
    html = _load_timeline_template().replace(
        "__CODEXSCOPE_TRACE_DATA__", _safe_json(report_data)
    )
    output.write_text(html, encoding="utf-8", errors="backslashreplace")
    return output


def render_comparison(out_dir: Path, comparison: dict[str, Any]) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = _safe_json(comparison)
    output = out_dir / "comparison.html"
    output.write_text(
        f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'"><title>CodexScope comparison</title>
<style>body{{font:14px/1.45 system-ui;margin:24px;color:#172033}}.warning{{background:#fff3cd;border:1px solid #e5c65c;padding:10px;margin:8px 0;border-radius:6px}}table{{border-collapse:collapse;width:100%;margin-top:18px}}td,th{{padding:7px;border:1px solid #ccd3df;text-align:left;vertical-align:top}}code{{overflow-wrap:anywhere}}</style></head><body>
<h1>CodexScope run comparison</h1><div id="warnings"></div><p id="summary"></p><table><thead><tr><th>Operation</th><th>Run A</th><th>Run B</th><th>Difference</th></tr></thead><tbody id="rows"></tbody></table>
<script id="comparison-data" type="application/json">{payload}</script><script>
const data=JSON.parse(document.getElementById('comparison-data').textContent);const warnings=document.getElementById('warnings');for(const value of data.warnings||[]){{const el=document.createElement('div');el.className='warning';el.textContent=value;warnings.append(el)}}
document.getElementById('summary').textContent=`A: ${{data.token_count_a??0}} actions · B: ${{data.token_count_b??0}} actions · first divergence: ${{data.first_divergence?.index??'none'}}`;
const body=document.getElementById('rows');for(const op of data.operations||[]){{const tr=document.createElement('tr');for(const value of [op.op,op.a?.label||op.a?.signature||'',op.b?.label||op.b?.signature||'',op.attribute_difference?'attributes differ':'']){{const td=document.createElement('td');const code=document.createElement('code');code.textContent=String(value);td.append(code);tr.append(td)}}body.append(tr)}}
</script></body></html>""",
        encoding="utf-8",
        errors="backslashreplace",
    )
    return output
