from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Iterable


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


def _digest(*parts: object) -> str:
    material = "\x1f".join(str(part) for part in parts)
    return hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()[:20]


def _action_id(action: dict[str, Any]) -> str:
    return str(action.get("event_id") or action.get("action_id") or f"event:seq-{action.get('seq', 0)}")


def _action_type(action: dict[str, Any]) -> str:
    value = str(action.get("action_type") or action.get("kind") or "unknown")
    return {
        "commandExecution": "command_execution",
        "fileChange": "file_change",
        "mcpToolCall": "mcp_tool_call",
    }.get(value, value)


def _function_node(function: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    path = str(function.get("path") or "<unknown>")
    name = str(function.get("name") or "<module/global>")
    start_line = function.get("start_line")
    node_id = f"function:{_digest(path, name, start_line)}"
    return node_id, {
        "id": node_id,
        "type": "function",
        "label": f"{path}::{name}",
        "path": path,
        "name": name,
        "start_line": start_line,
        "end_line": function.get("end_line"),
    }


def _temporal_key(action: dict[str, Any]) -> tuple[int, int, int, str]:
    value = action.get("timestamp_start_ns")
    try:
        timestamp = int(value) if value is not None else 0
    except (TypeError, ValueError):
        timestamp = 0
    return (
        0 if timestamp else 1,
        timestamp,
        int(action.get("seq") or 0),
        _action_id(action),
    )


def _workspace_observation_evidence(action: dict[str, Any]) -> str:
    payload = action.get("payload") or {}
    capture_source = payload.get("capture_source") if isinstance(payload, dict) else None
    evidence = {
        "filesystem_event_window": "filesystem_event_window_reconciliation",
        "concurrent_item_boundary": "concurrent_item_boundary_reconciliation",
    }.get(str(capture_source))
    if evidence is not None:
        return evidence
    if (
        action.get("source_event") == "snapshot/final_reconcile"
        or (isinstance(payload, dict) and payload.get("snapshot_action_type") == "final_reconcile")
    ):
        return "final_workspace_reconciliation"
    return "unattributed_workspace_reconciliation"


def _os_semantics(action: dict[str, Any]) -> tuple[bool, bool, bool, str, str]:
    payload = action.get("payload") or {}
    syscall = str(
        payload.get("syscall") if isinstance(payload, dict) else ""
        or action.get("operation")
        or ""
    ).casefold()
    access = str(payload.get("access") if isinstance(payload, dict) else "").casefold()
    category = str(
        payload.get("category") if isinstance(payload, dict) else ""
    ).casefold()
    normalized_access = re.sub(r"[^a-z0-9]+", "_", access).strip("_")
    parts = set(normalized_access.split("_")) if normalized_access else set()
    reads = bool(payload.get("is_read")) if isinstance(payload, dict) else False
    writes = bool(payload.get("is_write")) if isinstance(payload, dict) else False
    network = bool(payload.get("is_network")) if isinstance(payload, dict) else False
    reads = reads or syscall.startswith(("read", "pread", "recv")) or bool(
        parts & {"read", "receive", "recv"}
    )
    writes = writes or syscall.startswith(("write", "pwrite", "send")) or bool(
        parts & {"write", "send"}
    )
    if normalized_access in {"rw", "readwrite", "read_write", "write_read"}:
        reads = writes = True
    network = network or category in {"network", "socket", "net"} or syscall in {
        "socket",
        "socketpair",
        "connect",
        "accept",
        "accept4",
        "bind",
        "listen",
        "shutdown",
        "send",
        "sendto",
        "sendmsg",
        "sendmmsg",
        "recv",
        "recvfrom",
        "recvmsg",
        "recvmmsg",
    }
    return reads, writes, network, syscall, normalized_access


def _endpoint_label(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value or None
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        return str(value)


def _child_pid(result: object) -> int | None:
    if isinstance(result, dict):
        result = result.get("child_pid") or result.get("pid") or result.get("result")
    try:
        value = int(result)  # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError):
        return None
    return value if value > 0 else None


def build_provenance(actions: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a confidence-calibrated action provenance graph.

    Structural relationships reported by App Server receive confidence 1.0;
    syntax/AST mappings inherit their mapper confidence; causal edges inferred
    from a test transition are explicitly lower and carry their evidence. No
    temporal ordering edge is presented as causation.
    """

    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str, str, str], dict[str, Any]] = {}

    def add_node(node: dict[str, Any]) -> None:
        node_id = str(node["id"])
        if node_id not in nodes:
            nodes[node_id] = node
        else:
            nodes[node_id].update({key: value for key, value in node.items() if value is not None})

    def add_edge(
        source: str,
        target: str,
        edge_type: str,
        confidence: float,
        evidence: str,
        **attrs: Any,
    ) -> None:
        if source == target:
            return
        confidence = max(0.0, min(1.0, float(confidence)))
        key = (source, target, edge_type, evidence)
        value = {
            "source": source,
            "target": target,
            "type": edge_type,
            "confidence": round(confidence, 3),
            "evidence": evidence,
        }
        value.update(attrs)
        previous = edges.get(key)
        if previous is None or float(previous["confidence"]) < confidence:
            edges[key] = value

    ordered = sorted(actions, key=_temporal_key)
    known_ids = {_action_id(action) for action in ordered}
    previous_by_scope: dict[tuple[str, str], str] = {}
    last_failed_test_by_scope: dict[tuple[str, str], str] = {}

    for action in ordered:
        event_id = _action_id(action)
        action_type = _action_type(action)
        label = str(action.get("operation") or action.get("tool") or action_type)
        add_node(
            {
                "id": event_id,
                "type": action_type,
                "label": label,
                "status": action.get("status"),
                "seq": action.get("seq"),
                "timestamp_start_ns": action.get("timestamp_start_ns"),
                "timestamp_end_ns": action.get("timestamp_end_ns"),
                "actor": action.get("actor") or "main_agent",
                "tool_use_id": action.get("tool_use_id"),
                "hook_event_name": action.get("hook_event_name"),
                "related_event_id": action.get("related_event_id"),
                "language": action.get("language"),
                "process_id": action.get("process_id"),
                "runtime_thread_id": action.get("runtime_thread_id"),
                "call_id": action.get("call_id"),
            }
        )

        actor = str(action.get("actor") or "main_agent")
        if not (action_type == "os_syscall" and action.get("process_id") is not None):
            actor_id = f"actor:{_digest(actor)}"
            add_node({"id": actor_id, "type": "actor", "label": actor})
            add_edge(actor_id, event_id, "PERFORMS", 1.0, "canonical_event.actor")

        if action_type == "os_syscall" and action.get("process_id") is not None:
            pid = int(action["process_id"])
            process_id = f"process:{pid}"
            process_payload = action.get("payload") or {}
            add_node(
                {
                    "id": process_id,
                    "type": "process",
                    "label": str(
                        process_payload.get("comm")
                        if isinstance(process_payload, dict)
                        and process_payload.get("comm")
                        else process_id
                    ),
                    "pid": pid,
                    "ppid": action.get("parent_process_id"),
                    "comm": (
                        process_payload.get("comm")
                        if isinstance(process_payload, dict)
                        else None
                    ),
                }
            )
            add_edge(
                process_id,
                event_id,
                "PERFORMS",
                1.0,
                "linux_strace.syscall",
                pid=pid,
                tid=action.get("runtime_thread_id"),
            )

        parent = action.get("parent_event_id")
        if parent and str(parent) in known_ids:
            add_edge(str(parent), event_id, "CONTAINS", 1.0, "canonical_event.parent_event_id")

        payload = action.get("payload") or {}
        legacy_correlation = (
            payload.get("_hook_correlation")
            if isinstance(payload, dict)
            else None
        )
        target = action.get("related_event_id")
        evidence = action.get("correlation_evidence")
        confidence = action.get("correlation_confidence")
        correlation_kind = action.get("correlation_kind")
        if target is None and isinstance(legacy_correlation, dict):
            target = legacy_correlation.get("tool_event_id")
            evidence = legacy_correlation.get("evidence")
            confidence = legacy_correlation.get("confidence")
            correlation_kind = "hook_to_tool"
        if target and str(target) in known_ids:
            add_edge(
                event_id,
                str(target),
                "CORRELATES_WITH",
                1.0 if confidence is None else float(confidence),
                str(evidence or "canonical_event.tool_use_id"),
                correlation_kind=correlation_kind,
                hook_event=action.get("hook_event_name") or action.get("source_event"),
                tool_use_id=action.get("tool_use_id"),
            )
        if action_type == "filesystem_event" and isinstance(payload, dict):
            syscall_target = payload.get("os_syscall_event_id")
            if syscall_target and str(syscall_target) in known_ids:
                add_edge(
                    event_id,
                    str(syscall_target),
                    "CORRELATES_WITH",
                    0.9,
                    str(
                        payload.get("os_syscall_correlation_evidence")
                        or "same path and nearby linux_strace write syscall"
                    ),
                    correlation_kind="inotify_to_os_write_syscall",
                    pid=payload.get("os_syscall_pid"),
                )

        caller = action.get("caller_event_id")
        if caller and str(caller) in known_ids:
            add_edge(
                str(caller),
                event_id,
                "CALLS",
                1.0,
                "runtime.nearest_tracked_ancestor",
            )

        if action_type == "function_call":
            scope = (
                "runtime:" + str(action.get("process_instance_id") or ""),
                str(action.get("runtime_thread_id") or ""),
            )
        else:
            scope = (str(action.get("thread_id") or ""), str(action.get("turn_id") or ""))
        # A syscall stream may contain hundreds of thousands of points. A
        # PRECEDES edge between every pair adds no causal information and can
        # overwhelm the useful process/file/network evidence.
        if action_type != "os_syscall":
            previous = previous_by_scope.get(scope)
            if previous:
                add_edge(previous, event_id, "PRECEDES", 1.0, "canonical_event.temporal_order")
            previous_by_scope[scope] = event_id

        trigger = action.get("trigger")
        if trigger and str(trigger) in known_ids:
            add_edge(
                str(trigger),
                event_id,
                "TRIGGERS",
                float(action.get("trigger_confidence") or 0.7),
                "semantic_enrichment.trigger",
            )
        elif trigger == "previous_test_failure" and scope in last_failed_test_by_scope:
            add_edge(
                last_failed_test_by_scope[scope],
                event_id,
                "TRIGGERS",
                float(action.get("trigger_confidence") or 0.65),
                "nearest_failed_test_in_turn",
            )

        affected_files = list(action.get("affected_files") or [])
        for change in action.get("workspace_changes") or []:
            if isinstance(change, dict) and change.get("path"):
                affected_files.append(str(change["path"]))
        for path in sorted(set(str(path) for path in affected_files if path)):
            file_id = f"file:{_digest(path)}"
            add_node({"id": file_id, "type": "file", "label": path, "path": path})
            scan_only = any(
                isinstance(change, dict)
                and change.get("path") == path
                and not change.get("reported_by_app_server")
                for change in action.get("workspace_changes") or []
            )
            observer_only = action_type in {
                "workspace_reconcile",
                "filesystem_event",
            }
            add_edge(
                event_id,
                file_id,
                "OBSERVES_CHANGE" if observer_only else "WRITES",
                0.93 if scan_only else 1.0,
                (
                    _workspace_observation_evidence(action)
                    if action_type == "workspace_reconcile"
                    else "linux_inotify.path_event"
                    if action_type == "filesystem_event"
                    else "workspace_hash_scan"
                    if scan_only
                    else "app_server.affected_files"
                ),
            )

        operations = (
            set(payload.get("operations") or [])
            if isinstance(payload, dict)
            else set()
        )
        if action_type == "filesystem_event" and not (
            operations & _FILESYSTEM_GAP_OPERATIONS
        ):
            for path in sorted(
                set(str(path) for path in action.get("targets") or [] if path)
            ):
                file_id = f"file:{_digest(path)}"
                add_node(
                    {"id": file_id, "type": "file", "label": path, "path": path}
                )
                add_edge(
                    event_id,
                    file_id,
                    "OBSERVES_ACTIVITY",
                    1.0,
                    "linux_inotify.path_event",
                )

        if action_type == "os_syscall" and isinstance(payload, dict):
            reads, writes, network, syscall, access = _os_semantics(action)
            succeeded = payload.get("success") is not False and str(
                action.get("status") or ""
            ) != "failed"
            for path in sorted(
                set(str(path) for path in action.get("targets") or [] if path)
            ):
                file_id = f"file:{_digest(path)}"
                add_node({"id": file_id, "type": "file", "label": path, "path": path})
                if reads:
                    add_edge(
                        event_id,
                        file_id,
                        "READS" if succeeded else "ATTEMPTS_READ",
                        1.0,
                        "linux_strace.syscall",
                        pid=action.get("process_id"),
                        syscall=syscall,
                    )
                if writes:
                    add_edge(
                        event_id,
                        file_id,
                        "WRITES" if succeeded else "ATTEMPTS_WRITE",
                        1.0,
                        "linux_strace.syscall",
                        pid=action.get("process_id"),
                        syscall=syscall,
                    )
                if syscall in {"execve", "execveat"} or access in {
                    "exec",
                    "execute",
                }:
                    add_edge(
                        event_id,
                        file_id,
                        "EXECUTES_PROCESS" if succeeded else "ATTEMPTS_EXECUTE",
                        1.0,
                        "linux_strace.syscall",
                        pid=action.get("process_id"),
                        syscall=syscall,
                    )

            endpoint = _endpoint_label(payload.get("endpoint"))
            if network and endpoint:
                endpoint_id = f"endpoint:{_digest(endpoint)}"
                add_node(
                    {
                        "id": endpoint_id,
                        "type": "endpoint",
                        "label": endpoint,
                        "endpoint": endpoint,
                    }
                )
                if syscall in {"connect", "accept", "accept4"} or access in {
                    "connect",
                    "connection",
                }:
                    relation = "CONNECTS_TO"
                    attempted = "ATTEMPTS_CONNECT"
                elif syscall.startswith(("recv", "read")) or reads:
                    relation = "RECEIVES_FROM"
                    attempted = "ATTEMPTS_RECEIVE"
                else:
                    relation = "SENDS_TO"
                    attempted = "ATTEMPTS_SEND"
                add_edge(
                    event_id,
                    endpoint_id,
                    relation if succeeded else attempted,
                    1.0,
                    "linux_strace.syscall",
                    pid=action.get("process_id"),
                    syscall=syscall,
                    bytes=payload.get("bytes"),
                )

            if syscall in {"fork", "vfork", "clone", "clone3"}:
                child_pid = _child_pid(payload.get("result"))
                if child_pid is not None:
                    child_id = f"process:{child_pid}"
                    add_node(
                        {
                            "id": child_id,
                            "type": "process",
                            "label": child_id,
                            "pid": child_pid,
                            "ppid": action.get("process_id"),
                        }
                    )
                    add_edge(
                        event_id,
                        child_id,
                        "SPAWNS" if succeeded else "ATTEMPTS_SPAWN",
                        1.0,
                        "linux_strace.syscall",
                        pid=action.get("process_id"),
                        child_pid=child_pid,
                    )

        for path in sorted(
            set(str(path) for path in action.get("attempted_files") or [] if path)
        ):
            file_id = f"file:{_digest(path)}"
            add_node({"id": file_id, "type": "file", "label": path, "path": path})
            add_edge(
                event_id,
                file_id,
                "ATTEMPTS_WRITE",
                1.0,
                "failed_file_change.declared_patch",
            )

        for function in action.get("read_functions") or []:
            if not isinstance(function, dict):
                continue
            function_id, node = _function_node(function)
            add_node(node)
            add_edge(
                event_id,
                function_id,
                "READS",
                float(function.get("confidence") or 0.75),
                str(function.get("evidence") or "command_to_ast_range"),
            )

        for function in action.get("affected_functions") or []:
            if not isinstance(function, dict):
                continue
            function_id, node = _function_node(function)
            add_node(node)
            add_edge(
                event_id,
                function_id,
                (
                    "OBSERVES_MODIFICATION"
                    if action_type in {"workspace_reconcile", "filesystem_event"}
                    else "MODIFIES"
                ),
                float(function.get("confidence") or 0.85),
                str(function.get("evidence") or "diff_to_ast_range"),
                role=function.get("role"),
            )

        for function in action.get("executed_functions") or []:
            if not isinstance(function, dict):
                continue
            function_id, node = _function_node(function)
            add_node(node)
            add_edge(
                event_id,
                function_id,
                "EXECUTES",
                float(function.get("confidence") or 0.8),
                str(function.get("evidence") or "runtime_function_identity"),
                role=function.get("role"),
            )

        test_key = action.get("test_key")
        if test_key:
            test_id = f"test:{_digest(test_key)}"
            add_node(
                {
                    "id": test_id,
                    "type": "test",
                    "label": str(test_key),
                    "status": action.get("test_outcome"),
                }
            )
            add_edge(event_id, test_id, "RUNS_TEST", 1.0, "command_classifier")
            for function in action.get("test_functions") or []:
                if not isinstance(function, dict):
                    continue
                function_id, node = _function_node(function)
                add_node(node)
                add_edge(
                    test_id,
                    function_id,
                    "TESTS",
                    float(function.get("confidence") or 0.7),
                    str(function.get("evidence") or "test_output_location"),
                )
            if action.get("test_outcome") == "failed":
                last_failed_test_by_scope[scope] = event_id

        transition = action.get("test_transition")
        if isinstance(transition, dict):
            previous_test = transition.get("previous_test_action_id")
            if previous_test:
                add_edge(str(previous_test), event_id, "RETESTS", 1.0, "normalized_test_key")
            target_outcome = transition.get("to")
            relation = "FIXES" if target_outcome == "passed" else "CAUSES_FAILURE" if target_outcome == "failed" else "AFFECTS_TEST"
            for candidate in transition.get("candidate_changes") or []:
                if not isinstance(candidate, dict) or not candidate.get("action_id"):
                    continue
                add_edge(
                    str(candidate["action_id"]),
                    event_id,
                    relation,
                    float(candidate.get("confidence") or transition.get("confidence") or 0.5),
                    str(candidate.get("evidence") or "between_repeated_test_runs"),
                )

    action_rank = {
        _action_id(action): rank for rank, action in enumerate(ordered, start=1)
    }
    edge_values = sorted(
        edges.values(),
        key=lambda edge: (
            min(
                action_rank.get(str(edge["source"]), len(ordered) + 1),
                action_rank.get(str(edge["target"]), len(ordered) + 1),
            ),
            edge["type"],
            edge["source"],
            edge["target"],
        ),
    )

    def node_key(node: dict[str, Any]) -> tuple[int, int, int, str, str, str]:
        value = node.get("timestamp_start_ns")
        try:
            timestamp = int(value) if value is not None else 0
        except (TypeError, ValueError):
            timestamp = 0
        return (
            0 if timestamp else 1,
            timestamp,
            action_rank.get(str(node.get("id")), len(ordered) + 1),
            str(node.get("type")),
            str(node.get("label")),
            str(node["id"]),
        )

    node_values = sorted(
        nodes.values(),
        key=node_key,
    )
    return {
        "schema_version": "1.2",
        "nodes": node_values,
        "edges": edge_values,
        "summary": {
            "node_count": len(node_values),
            "edge_count": len(edge_values),
            "inferred_edge_count": sum(1 for edge in edge_values if float(edge["confidence"]) < 1.0),
        },
    }
