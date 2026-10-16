from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

from .commands import ReadSpec, classify_command
from .diffmap import (
    ChangedLines,
    changed_lines_between,
    changed_lines_from_unified_diff,
    semantic_diff_fingerprint,
    unified_diff,
)
from .provenance import build_provenance
from .storage import atomic_json_dump, iter_jsonl
from .symbols import Symbol, SymbolIndex
from .util import is_source_path, json_load


_SOURCE_LOCATION = re.compile(
    r"(?P<path>(?:[A-Za-z]:)?[^\s:\"']+\.(?:py|c|h|cc|cpp|cxx|hpp|hh|hxx)):(?P<line>\d+)(?::\d+)?"
)
_PYTHON_LOCATION = re.compile(r"File [\"'](?P<path>.+?)[\"'], line (?P<line>\d+)")
_PYTEST_SELECTOR = re.compile(r"(?P<path>[^\s]+\.py)::(?P<name>[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)")


def _load_snapshot_index(run_dir: Path) -> list[dict[str, Any]]:
    path = run_dir / "snapshots" / "index.jsonl"
    return list(iter_jsonl(path)) if path.exists() else []


def _load_actions(run_dir: Path) -> list[dict[str, Any]]:
    events_path = run_dir / "events.jsonl"
    if events_path.exists():
        return [dict(row) for row in iter_jsonl(events_path)]
    legacy = run_dir / "normalized.json"
    if legacy.exists():
        value = json_load(legacy)
        if not isinstance(value, list):
            raise ValueError(f"Expected a JSON array in {legacy}")
        return [dict(row) for row in value]
    raise FileNotFoundError(f"No events.jsonl or normalized.json in {run_dir}")


def _metadata(run_dir: Path) -> dict[str, Any]:
    for name in ("manifest.json", "meta.json"):
        path = run_dir / name
        if path.exists():
            value = json_load(path)
            if isinstance(value, dict):
                return value
    return {}


def _repository(run_dir: Path, actions: list[dict[str, Any]]) -> Path:
    metadata = _metadata(run_dir)
    candidates: list[Any] = [
        metadata.get("repo"),
        metadata.get("repo_path"),
        metadata.get("repository"),
        metadata.get("cwd"),
    ]
    if isinstance(metadata.get("workspace"), dict):
        candidates.extend(
            [metadata["workspace"].get("root"), metadata["workspace"].get("cwd")]
        )
    candidates.extend(action.get("cwd") for action in actions if action.get("cwd"))
    for candidate in candidates:
        if candidate:
            path = Path(str(candidate)).expanduser()
            if path.is_absolute():
                return path.resolve()
    raise ValueError("Run manifest does not identify the observed repository")


def _action_id(action: dict[str, Any]) -> str:
    return str(action.get("event_id") or action.get("action_id") or f"event:seq-{action.get('seq', 0)}")


def _action_type(action: dict[str, Any]) -> str:
    value = str(action.get("action_type") or action.get("kind") or "unknown")
    return {
        "commandExecution": "command_execution",
        "fileChange": "file_change",
        "mcpToolCall": "mcp_tool_call",
        "dynamicToolCall": "dynamic_tool_call",
    }.get(value, value)


def _item(action: Mapping[str, Any]) -> dict[str, Any]:
    payload = action.get("payload") or {}
    if isinstance(payload, Mapping) and isinstance(payload.get("item"), Mapping):
        return dict(payload["item"])
    return dict(action)


def _source_seq(action: Mapping[str, Any]) -> int:
    payload = action.get("payload") or {}
    if isinstance(payload, Mapping) and payload.get("_source_seq") is not None:
        return int(payload["_source_seq"])
    return int(action.get("source_seq") or action.get("seq") or 0)


def _safe_repo_rel(raw_path: str | Path, repo: Path, cwd: str | Path | None = None) -> str:
    path = Path(raw_path)
    if not path.is_absolute():
        base = Path(cwd) if cwd else repo
        if not base.is_absolute():
            base = repo / base
        path = base / path
    normalized = Path(os.path.abspath(os.path.normpath(os.fspath(path))))
    try:
        return normalized.relative_to(repo).as_posix()
    except ValueError as exc:
        raise ValueError(f"Path escapes repository: {raw_path}") from exc


def _safe_snapshot_path(snapshot_root: Path, relative: str | None) -> Path | None:
    if not relative:
        return None
    candidate = snapshot_root / relative
    normalized = Path(os.path.abspath(os.path.normpath(os.fspath(candidate))))
    try:
        normalized.relative_to(snapshot_root)
    except ValueError:
        return None
    try:
        metadata = normalized.lstat()
    except OSError:
        return None
    if not stat.S_ISREG(metadata.st_mode):
        return None
    return normalized


def _deduplicate_functions(functions: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    result: dict[tuple[Any, ...], dict[str, Any]] = {}
    for function in functions:
        key = (
            function.get("path"),
            function.get("name"),
            function.get("role"),
            function.get("start_line"),
            function.get("end_line"),
        )
        previous = result.get(key)
        if previous is None or float(function.get("confidence") or 0) > float(previous.get("confidence") or 0):
            result[key] = function
    return sorted(
        result.values(),
        key=lambda value: (
            str(value.get("path")),
            int(value.get("start_line") or 0),
            str(value.get("name")),
            str(value.get("role")),
        ),
    )


def _symbol_ref(
    rel: str,
    symbol: Symbol,
    *,
    role: str,
    confidence: float,
    evidence: str,
    read_spec: ReadSpec | None = None,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "path": rel,
        "name": symbol.name,
        "start_line": symbol.start_line,
        "end_line": symbol.end_line,
        "role": role,
        "confidence": round(max(0.0, min(1.0, confidence)), 3),
        "evidence": evidence,
    }
    if read_spec is not None:
        value["read_start_line"] = read_spec.start_line
        value["read_end_line"] = read_spec.end_line
        if read_spec.tail_lines is not None:
            value["read_tail_lines"] = read_spec.tail_lines
    return value


def _global_ref(rel: str, *, role: str, confidence: float, evidence: str) -> dict[str, Any]:
    return {
        "path": rel,
        "name": "<module/global>",
        "role": role,
        "confidence": round(confidence, 3),
        "evidence": evidence,
    }


def _declared_changes(action: Mapping[str, Any]) -> list[dict[str, Any]]:
    item = _item(action)
    return [dict(change) for change in item.get("changes") or [] if isinstance(change, Mapping)]


def _write_capable(action: Mapping[str, Any]) -> bool:
    return _action_type(dict(action)) in {
        "command_execution",
        "file_change",
        "mcp_tool_call",
        "dynamic_tool_call",
        "collab_agent_tool_call",
    }


def _assign_snapshot_rows(
    actions: list[dict[str, Any]], rows: list[dict[str, Any]]
) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, Any]]]:
    by_item: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for action in actions:
        if not _write_capable(action):
            continue
        item_id = action.get("item_id") or _item(action).get("id")
        if item_id is not None:
            by_item[str(item_id)].append(action)
    capable = sorted(
        [action for action in actions if _write_capable(action)],
        key=lambda action: (_source_seq(action), int(action.get("seq") or 0)),
    )
    result: dict[str, list[dict[str, Any]]] = defaultdict(list)
    unassigned: list[dict[str, Any]] = []
    for row in rows:
        if row.get("attribution_ambiguous"):
            unassigned.append(row)
            continue
        event_id: str | None = None
        item_id = row.get("item_id")
        row_seq = int(row.get("seq") or 0)
        if item_id is not None:
            candidates = by_item.get(str(item_id), [])
            exact = [
                action for action in candidates if _source_seq(action) == row_seq
            ]
            if len(exact) == 1:
                event_id = _action_id(exact[0])
            elif len(candidates) == 1:
                event_id = _action_id(candidates[0])
            elif candidates:
                # Reused item ids must not silently select the wrong turn.
                before = [
                    action for action in candidates if _source_seq(action) <= row_seq
                ]
                if before:
                    nearest_seq = max(_source_seq(action) for action in before)
                    nearest = [
                        action
                        for action in before
                        if _source_seq(action) == nearest_seq
                    ]
                    if len(nearest) == 1:
                        event_id = _action_id(nearest[0])
        else:
            # Legacy rows without an item identity can only use temporal
            # fallback. An explicit but unknown item id is positive evidence
            # that the row does not belong to the preceding tool.
            before = [action for action in capable if _source_seq(action) <= int(row.get("seq") or 0)]
            if before:
                event_id = _action_id(before[-1])
        if event_id is not None:
            result[event_id].append(row)
        else:
            unassigned.append(row)
    return result, unassigned


def _workspace_reconcile_actions(
    actions: list[dict[str, Any]], rows: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    """Keep unscoped hash changes without claiming that a tool caused them."""

    grouped: dict[tuple[int, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[
            (
                int(row.get("seq") or 0),
                str(row.get("item_id") or "unattributed"),
                str(row.get("action_type") or "workspace_scan"),
            )
        ].append(row)
    next_seq = max((int(action.get("seq") or 0) for action in actions), default=0)
    derived: list[dict[str, Any]] = []
    assigned: dict[str, list[dict[str, Any]]] = {}
    for offset, ((source_seq, item_id, source_action), group) in enumerate(
        sorted(grouped.items()), start=1
    ):
        digest = hashlib.sha256(
            f"{source_seq}\x1f{item_id}\x1f{source_action}".encode("utf-8")
        ).hexdigest()[:20]
        event_id = f"workspace-reconcile:{digest}"
        final_reconcile = source_action == "final_reconcile" or item_id == "session-final"
        filesystem_window = source_action == "filesystem_observation" or any(
            row.get("capture_source") == "filesystem_event_window" for row in group
        )
        concurrent_boundary = any(
            row.get("capture_source") == "concurrent_item_boundary" for row in group
        )
        sample = group[0]

        def group_time(*keys: str, latest: bool = False) -> int | None:
            values: list[int] = []
            for row in group:
                for key in keys:
                    value = row.get(key)
                    if value is None:
                        continue
                    try:
                        parsed = int(value)
                    except (TypeError, ValueError):
                        continue
                    if parsed:
                        values.append(parsed)
                        break
            if not values:
                return None
            return max(values) if latest else min(values)

        capture_start = group_time(
            "capture_started_monotonic_ns",
            "capture_start_monotonic_ns",
            "observed_to_monotonic_ns",
            "observed_from_monotonic_ns",
        )
        capture_end = group_time(
            "capture_ended_monotonic_ns",
            "capture_end_monotonic_ns",
            "observed_to_monotonic_ns",
            "observed_from_monotonic_ns",
            latest=True,
        )
        wall_start = group_time(
            "capture_started_wall_time_ns",
            "capture_start_wall_time_ns",
            "observed_to_wall_time_ns",
            "observed_from_wall_time_ns",
        )
        wall_end = group_time(
            "capture_ended_wall_time_ns",
            "capture_end_wall_time_ns",
            "observed_to_wall_time_ns",
            "observed_from_wall_time_ns",
            latest=True,
        )
        action = {
            "schema_version": "1.2",
            "event_id": event_id,
            "action_id": event_id,
            "seq": next_seq + offset,
            "source": "derived",
            "source_event": (
                "snapshot/final_reconcile"
                if final_reconcile
                else "snapshot/filesystem_reconcile"
                if filesystem_window
                else "snapshot/concurrent_item_reconcile"
                if concurrent_boundary
                else "snapshot/unattributed_change"
            ),
            "phase": "completed",
            "action_type": "workspace_reconcile",
            "actor": "workspace_observer",
            "item_id": item_id,
            "status": "completed",
            "timestamp_start_ns": capture_start,
            "timestamp_end_ns": capture_end or capture_start,
            "wall_time_start_ns": wall_start,
            "wall_time_end_ns": wall_end or wall_start,
            "operation": (
                "final workspace reconciliation"
                if final_reconcile
                else "filesystem event window reconciliation"
                if filesystem_window
                else "concurrent item boundary reconciliation"
                if concurrent_boundary
                else "unattributed workspace reconciliation"
            ),
            "payload": {
                "_source_seq": source_seq,
                "snapshot_action_type": source_action,
                "capture_source": sample.get("capture_source"),
                "filesystem_window_id": sample.get("filesystem_window_id"),
                "observed_from_monotonic_ns": sample.get(
                    "observed_from_monotonic_ns"
                ),
                "observed_to_monotonic_ns": sample.get(
                    "observed_to_monotonic_ns"
                ),
                "observed_from_wall_time_ns": sample.get(
                    "observed_from_wall_time_ns"
                ),
                "observed_to_wall_time_ns": sample.get(
                    "observed_to_wall_time_ns"
                ),
                "capture_started_monotonic_ns": capture_start,
                "capture_ended_monotonic_ns": capture_end,
                "capture_started_wall_time_ns": wall_start,
                "capture_ended_wall_time_ns": wall_end,
                "attribution_ambiguous": bool(
                    any(row.get("attribution_ambiguous") for row in group)
                ),
                "candidate_item_ids": sorted(
                    {
                        str(value)
                        for row in group
                        for value in (
                            row.get("attribution_candidate_item_ids")
                            or row.get("candidate_item_ids")
                            or []
                        )
                        if value is not None
                    }
                ),
            },
            "anomalies": (
                ["workspace_change_detected_at_final_reconcile"]
                if final_reconcile
                else ["workspace_change_observed_after_filesystem_event_window"]
                if filesystem_window
                else ["workspace_change_observed_after_concurrent_item_boundary"]
                if concurrent_boundary
                else ["snapshot_item_has_no_matching_action"]
            ),
        }
        derived.append(action)
        assigned[event_id] = group
    return derived, assigned


def _test_outcome(action: Mapping[str, Any]) -> str:
    exit_code = action.get("exit_code")
    if exit_code is not None:
        code = int(exit_code)
        if code == 0:
            return "passed"
        if code in {126, 127}:
            return "execution_error"
        output = str(action.get("output") or "").lower()
        if any(
            marker in output
            for marker in (
                "command not found",
                "no such file or directory",
                "failed to start",
                "could not find executable",
            )
        ):
            return "execution_error"
        return "failed"
    status = str(action.get("status") or "unknown")
    if status in {"failed", "blocked", "declined"}:
        return "failed"
    if status in {"interrupted", "cancelled", "incomplete"}:
        return status
    return "unknown"


def enrich_run(run_dir: Path) -> list[dict[str, Any]]:
    """Add function, workspace-write, test, and provenance semantics to a run."""

    run_dir = run_dir.expanduser().resolve()
    actions = _load_actions(run_dir)
    repo = _repository(run_dir, actions)
    snapshot_root = run_dir / "snapshots"
    snapshot_rows = _load_snapshot_index(run_dir)
    assigned_rows, unassigned_rows = _assign_snapshot_rows(actions, snapshot_rows)
    reconcile_actions, reconcile_rows = _workspace_reconcile_actions(
        actions, unassigned_rows
    )
    actions.extend(reconcile_actions)
    assigned_rows.update(reconcile_rows)

    versions: dict[str, list[tuple[int, str | None]]] = defaultdict(list)
    baseline_root = snapshot_root / "baseline"
    if baseline_root.exists():
        for path in baseline_root.rglob("*"):
            try:
                is_regular = stat.S_ISREG(path.lstat().st_mode)
            except OSError:
                is_regular = False
            if is_regular:
                rel = path.relative_to(baseline_root).as_posix()
                versions[rel].append((-1, path.relative_to(snapshot_root).as_posix()))
    for row in snapshot_rows:
        if row.get("path"):
            versions[str(row["path"])].append((int(row.get("seq") or 0), row.get("after")))
    for path_versions in versions.values():
        path_versions.sort(key=lambda value: value[0])

    bytes_cache: dict[str, bytes] = {}
    index_cache: dict[tuple[str, str], SymbolIndex] = {}

    def snapshot_bytes(relative: str | None) -> bytes | None:
        if not relative:
            return None
        if relative in bytes_cache:
            return bytes_cache[relative]
        path = _safe_snapshot_path(snapshot_root, relative)
        if path is None:
            return None
        data = path.read_bytes()
        bytes_cache[relative] = data
        return data

    def index_for(relative: str | None, rel: str) -> SymbolIndex | None:
        if not relative or not is_source_path(rel):
            return None
        key = (relative, Path(rel).suffix.lower())
        if key not in index_cache:
            data = snapshot_bytes(relative)
            if data is None:
                return None
            index_cache[key] = SymbolIndex.from_bytes(data, Path(rel).suffix)
        return index_cache[key]

    def version_at(rel: str, source_seq: int, *, strictly_before: bool = False) -> str | None:
        selected: str | None = None
        for version_seq, snapshot_relative in versions.get(rel, []):
            if version_seq < source_seq if strictly_before else version_seq <= source_seq:
                selected = snapshot_relative
            else:
                break
        return selected

    def live_index(rel: str) -> SymbolIndex | None:
        # A lower-confidence fallback for imported traces without snapshots. It
        # never follows a symlink outside the repository.
        path = repo / rel
        try:
            metadata = path.lstat()
        except OSError:
            return None
        if not stat.S_ISREG(metadata.st_mode) or not is_source_path(rel):
            return None
        return SymbolIndex.from_file(path)

    enriched: list[dict[str, Any]] = []
    for raw_action in actions:
        action = dict(raw_action)
        action["event_id"] = _action_id(action)
        action.setdefault("action_id", action["event_id"])
        action["action_type"] = _action_type(action)
        action.setdefault("kind", _item(action).get("type") or action["action_type"])
        action["affected_functions"] = list(action.get("affected_functions") or [])
        action["executed_functions"] = list(action.get("executed_functions") or [])
        action["read_functions"] = list(action.get("read_functions") or [])
        action["test_functions"] = list(action.get("test_functions") or [])
        action["workspace_changes"] = []
        action["attempted_files"] = list(action.get("attempted_files") or [])
        action_rows = assigned_rows.get(action["event_id"], [])
        declared = _declared_changes(action)
        item = _item(action)
        cwd = str(action.get("cwd") or item.get("cwd") or repo)
        source_seq = _source_seq(action)

        row_by_path = {str(row.get("path")): row for row in action_rows if row.get("path")}
        declared_by_path: dict[str, dict[str, Any]] = {}
        for change in declared:
            if not change.get("path"):
                continue
            try:
                rel = _safe_repo_rel(str(change["path"]), repo, cwd)
            except ValueError:
                continue
            declared_by_path[rel] = change

        if action["action_type"] == "file_change":
            # A failed/incomplete fileChange describes the proposed patch, not
            # proof that bytes reached the worktree.  Snapshot rows below still
            # preserve any partial side effect that actually occurred.
            if str(action.get("status")) != "completed":
                action["attempted_files"] = sorted(declared_by_path)
                action["affected_files"] = []
            else:
                action["attempted_files"] = []

        # Workspace scan rows are authoritative for side effects. Declared diffs
        # add semantic line evidence, but are not required for shell/MCP writes.
        trusted_declared = (
            action["action_type"] != "file_change"
            or str(action.get("status")) == "completed"
        )
        paths = sorted(
            set(row_by_path)
            | (set(declared_by_path) if trusted_declared else set())
        )
        write_refs: list[dict[str, Any]] = []
        for rel in paths:
            row = row_by_path.get(rel, {})
            change = declared_by_path.get(rel, {}) if trusted_declared else {}
            before_rel = row.get("before") or version_at(rel, source_seq, strictly_before=True)
            after_rel = row.get("after") if "after" in row else version_at(rel, source_seq)
            before_data = snapshot_bytes(before_rel)
            after_data = snapshot_bytes(after_rel)
            declared_diff = str(change.get("diff") or "")
            if declared_diff:
                line_info = changed_lines_from_unified_diff(declared_diff)
                diff = declared_diff
                mapping_confidence = 0.98 if row else 0.84
                evidence = "app_server_diff+snapshot_ast" if row else "app_server_diff+available_ast"
            else:
                line_info = changed_lines_between(before_data, after_data)
                diff = unified_diff(before_data, after_data, rel)
                mapping_confidence = 0.93 if (before_data is not None or after_data is not None) else 0.55
                evidence = "workspace_snapshot_diff+ast"

            side_symbols: dict[tuple[str, str], dict[str, Any]] = {}
            for side, relative, lines in (
                ("old", before_rel, line_info.old_lines),
                ("new", after_rel, line_info.new_lines),
            ):
                index = index_for(relative, rel)
                if index is None and side == "new":
                    index = live_index(rel)
                    side_confidence = min(mapping_confidence, 0.65)
                    side_evidence = evidence + "+live_fallback"
                else:
                    side_confidence = mapping_confidence
                    side_evidence = evidence
                if index is None:
                    continue
                for symbol in index.symbols_for_lines(lines):
                    key = (rel, symbol.name)
                    current = side_symbols.get(key)
                    if current is None:
                        side_symbols[key] = _symbol_ref(
                            rel,
                            symbol,
                            role=f"write_{side}",
                            confidence=side_confidence,
                            evidence=side_evidence,
                        )
                    elif current["role"] != f"write_{side}":
                        # Present on both sides: report one modification rather
                        # than inflating heatmaps with old/new duplicates.
                        preferred = symbol if side == "new" else Symbol(
                            str(current["name"]),
                            "function",
                            int(current.get("start_line") or symbol.start_line),
                            int(current.get("end_line") or symbol.end_line),
                        )
                        side_symbols[key] = _symbol_ref(
                            rel,
                            preferred,
                            role="write",
                            confidence=max(float(current.get("confidence") or 0), side_confidence),
                            evidence=side_evidence,
                        )
            if not side_symbols and (line_info.old_lines or line_info.new_lines) and is_source_path(rel):
                side_symbols[(rel, "<module/global>")] = _global_ref(
                    rel,
                    role="write",
                    confidence=max(0.4, mapping_confidence - 0.2),
                    evidence=evidence + ":no_enclosing_function",
                )
            write_refs.extend(side_symbols.values())
            if rel not in action.get("affected_files", []):
                action.setdefault("affected_files", []).append(rel)
            workspace_change = dict(row) if row else {
                "seq": source_seq,
                "item_id": action.get("item_id") or item.get("id"),
                "path": rel,
                "kind": change.get("kind"),
                "reported_by_app_server": True,
                "capture_source": "app_server_file_change",
            }
            workspace_change["semantic_diff_sha256"] = semantic_diff_fingerprint(diff)
            workspace_change["old_changed_ranges"] = [
                {"start": interval.start, "end": interval.end} for interval in line_info.old_ranges
            ]
            workspace_change["new_changed_ranges"] = [
                {"start": interval.start, "end": interval.end} for interval in line_info.new_ranges
            ]
            action["workspace_changes"].append(workspace_change)
        action["affected_functions"].extend(write_refs)
        if action["action_type"] == "workspace_reconcile":
            for function in action["affected_functions"]:
                role = str(function.get("role") or "write")
                if not role.startswith("observed_"):
                    function["role"] = f"observed_{role}"

        if action["action_type"] == "command_execution":
            command = str(action.get("operation") or action.get("command") or item.get("command") or "")
            output = str(
                item.get("aggregatedOutput")
                or (action.get("payload") or {}).get("output")
                or action.get("output")
                or ""
            )
            command_actions = [
                command_action
                for command_action in item.get("commandActions") or []
                if isinstance(command_action, Mapping)
            ]
            info = classify_command(
                command,
                output,
                command_actions=command_actions,
                cwd=cwd,
            )
            action["command"] = command
            action["output"] = output
            action["command_family"] = info.family
            action["command_actions_source"] = info.actions_source
            action["is_test"] = info.is_test
            action["test_key"] = info.test_key

            read_refs: list[dict[str, Any]] = []
            for spec in info.reads:
                try:
                    rel = _safe_repo_rel(spec.path, repo, cwd)
                except ValueError:
                    continue
                relative = version_at(rel, source_seq)
                index = index_for(relative, rel)
                confidence = spec.confidence
                evidence = spec.evidence or spec.source
                if index is None:
                    index = live_index(rel)
                    confidence = min(confidence, 0.62)
                    evidence += "+live_fallback"
                if index is None:
                    continue
                start = spec.start_line
                end = spec.end_line
                if spec.tail_lines is not None:
                    start = max(1, index.line_count - spec.tail_lines + 1)
                    end = index.line_count
                symbols = index.symbols_for_range(start, end)
                for symbol in symbols:
                    read_refs.append(
                        _symbol_ref(
                            rel,
                            symbol,
                            role="read",
                            confidence=confidence,
                            evidence=evidence,
                            read_spec=ReadSpec(
                                spec.path,
                                start,
                                end,
                                spec.tail_lines,
                                spec.source,
                                spec.confidence,
                                spec.evidence,
                            ),
                        )
                    )
                if not symbols and is_source_path(rel):
                    read_refs.append(
                        _global_ref(
                            rel,
                            role="read",
                            confidence=max(0.35, confidence - 0.2),
                            evidence=evidence + ":no_function_in_range",
                        )
                    )
            action["read_functions"].extend(read_refs)

            if info.is_test:
                action["test_outcome"] = _test_outcome(action)
                test_refs: list[dict[str, Any]] = []
                locations: set[tuple[str, int, str]] = set()
                for pattern, evidence_name in (
                    (_PYTHON_LOCATION, "python_traceback"),
                    (_SOURCE_LOCATION, "diagnostic_location"),
                ):
                    for match in pattern.finditer(output):
                        locations.add((match.group("path"), int(match.group("line")), evidence_name))
                for raw_path, line, evidence_name in sorted(locations):
                    try:
                        rel = _safe_repo_rel(raw_path, repo, cwd)
                    except ValueError:
                        continue
                    index = index_for(version_at(rel, source_seq), rel) or live_index(rel)
                    if index is None:
                        continue
                    for symbol in index.symbols_for_lines([line]):
                        test_refs.append(
                            _symbol_ref(
                                rel,
                                symbol,
                                role="test_evidence",
                                confidence=0.82,
                                evidence=evidence_name,
                            )
                        )
                for selector in _PYTEST_SELECTOR.finditer(command):
                    try:
                        rel = _safe_repo_rel(selector.group("path"), repo, cwd)
                    except ValueError:
                        continue
                    index = index_for(version_at(rel, source_seq), rel) or live_index(rel)
                    if index is None:
                        continue
                    wanted = selector.group("name").replace("::", ".")
                    for symbol in index.symbols:
                        if symbol.name == wanted or symbol.name.endswith("." + wanted) or symbol.name.endswith(wanted):
                            test_refs.append(
                                _symbol_ref(
                                    rel,
                                    symbol,
                                    role="test_evidence",
                                    confidence=0.95,
                                    evidence="pytest_node_selector",
                                )
                            )
                action["test_functions"].extend(test_refs)

        normalized_files: list[str] = []
        for affected_path in action.get("affected_files") or []:
            try:
                normalized_files.append(_safe_repo_rel(str(affected_path), repo, cwd))
            except ValueError:
                continue
        action["affected_functions"] = _deduplicate_functions(action["affected_functions"])
        action["executed_functions"] = _deduplicate_functions(action["executed_functions"])
        action["read_functions"] = _deduplicate_functions(action["read_functions"])
        action["test_functions"] = _deduplicate_functions(action["test_functions"])
        action["affected_files"] = sorted(set(normalized_files))
        enriched.append(action)

    # Test transitions and causal candidates require the complete enriched order.
    last_test: dict[tuple[str, str], dict[str, Any]] = {}
    writes: list[dict[str, Any]] = []
    last_failed_by_scope: dict[tuple[str, str], dict[str, Any]] = {}
    for action in sorted(enriched, key=lambda value: (int(value.get("seq") or 0), _action_id(value))):
        scope = (str(action.get("thread_id") or ""), str(action.get("turn_id") or ""))
        observation_only = action.get("action_type") in {
            "filesystem_event",
            "workspace_reconcile",
            "os_syscall",
        }
        if not observation_only and (
            action.get("affected_files") or action.get("affected_functions")
        ):
            failed = last_failed_by_scope.get(scope)
            if failed and not action.get("trigger"):
                action["trigger"] = failed["action_id"]
                action["trigger_confidence"] = 0.65
            writes.append(action)

        test_key = action.get("test_key")
        if not action.get("is_test") or not test_key:
            continue
        outcome = str(action.get("test_outcome") or "unknown")
        key = (scope[0] + "\x1f" + scope[1], str(test_key))
        previous = last_test.get(key)
        comparable_outcomes = {"passed", "failed"}
        if (
            previous
            and previous["outcome"] in comparable_outcomes
            and outcome in comparable_outcomes
            and previous["outcome"] != outcome
        ):
            candidates = [
                change
                for change in writes
                if previous["seq"] < int(change.get("seq") or 0) < int(action.get("seq") or 0)
                and (str(change.get("thread_id") or ""), str(change.get("turn_id") or "")) == scope
            ]
            candidate_count = max(1, len(candidates))
            candidate_rows: list[dict[str, Any]] = []
            test_function_keys = {
                (function.get("path"), function.get("name")) for function in action.get("test_functions") or []
            }
            for change in candidates:
                function_keys = {
                    (function.get("path"), function.get("name"))
                    for function in change.get("affected_functions") or []
                }
                overlap = bool(function_keys & test_function_keys)
                confidence = min(0.9, (0.82 if candidate_count == 1 else 0.58) + (0.12 if overlap else 0.0))
                candidate_rows.append(
                    {
                        "action_id": _action_id(change),
                        "seq": change.get("seq"),
                        "files": change.get("affected_files") or [],
                        "functions": change.get("affected_functions") or [],
                        "confidence": round(confidence, 3),
                        "evidence": "sole_change_between_tests" if candidate_count == 1 else "change_between_tests",
                    }
                )
            action["test_transition"] = {
                "from": previous["outcome"],
                "to": outcome,
                "previous_test_action_id": previous["action_id"],
                "candidate_changes": candidate_rows,
                "confidence": max((candidate["confidence"] for candidate in candidate_rows), default=0.0),
                "causality": "inferred_not_proven",
            }
        last_test[key] = {
            "outcome": outcome,
            "seq": int(action.get("seq") or 0),
            "action_id": _action_id(action),
        }
        if outcome == "failed":
            last_failed_by_scope[scope] = last_test[key]
        elif outcome == "passed":
            last_failed_by_scope.pop(scope, None)

    def temporal_key(action: Mapping[str, Any]) -> tuple[int, int, int, str]:
        value = action.get("timestamp_start_ns")
        try:
            timestamp = int(value) if value is not None else 0
        except (TypeError, ValueError):
            timestamp = 0
        return (
            0 if timestamp else 1,
            timestamp,
            int(action.get("seq") or 0),
            _action_id(dict(action)),
        )

    enriched.sort(key=temporal_key)
    graph = build_provenance(enriched)
    normalization_summary_path = run_dir / "normalization_summary.json"
    normalization_summary = (
        json_load(normalization_summary_path)
        if normalization_summary_path.exists()
        else {}
    )
    summary = {
        "schema_version": "1.2",
        "event_count": len(enriched),
        "commands": sum(1 for action in enriched if action["action_type"] == "command_execution"),
        "file_change_events": sum(1 for action in enriched if action["action_type"] == "file_change"),
        "workspace_writes": sum(
            len(action.get("workspace_changes") or [])
            for action in enriched
            if action.get("action_type")
            not in {"filesystem_event", "workspace_reconcile", "os_syscall"}
        ),
        "hash_scan_writes": sum(
            1
            for action in enriched
            if action.get("action_type")
            not in {"filesystem_event", "workspace_reconcile", "os_syscall"}
            for change in action.get("workspace_changes") or []
            if not change.get("reported_by_app_server")
        ),
        "workspace_observed_changes": sum(
            len(action.get("workspace_changes") or [])
            for action in enriched
            if action.get("action_type") == "workspace_reconcile"
        ),
        "function_reads": sum(len(action.get("read_functions") or []) for action in enriched),
        "function_modifications": sum(
            len(action.get("affected_functions") or [])
            for action in enriched
            if action.get("action_type")
            not in {"filesystem_event", "workspace_reconcile", "os_syscall"}
        ),
        "observed_function_modifications": sum(
            len(action.get("affected_functions") or [])
            for action in enriched
            if action.get("action_type") == "workspace_reconcile"
        ),
        "runtime_function_calls": sum(
            1 for action in enriched if action["action_type"] == "function_call"
        ),
        "runtime_incomplete_calls": sum(
            1
            for action in enriched
            if action["action_type"] == "function_call"
            and action.get("status") == "incomplete"
        ),
        "runtime_processes": len(
            {
                action.get("process_instance_id")
                for action in enriched
                if action["action_type"] == "function_call"
                and action.get("process_instance_id")
            }
        ),
        "runtime_threads": len(
            {
                (action.get("process_instance_id"), action.get("runtime_thread_id"))
                for action in enriched
                if action["action_type"] == "function_call"
            }
        ),
        "unique_executed_functions": len(
            {
                (
                    function.get("path"),
                    function.get("name"),
                    function.get("start_line"),
                )
                for action in enriched
                for function in action.get("executed_functions") or []
                if isinstance(function, dict)
            }
        ),
        "test_transitions": sum(1 for action in enriched if action.get("test_transition")),
        "attempted_file_changes": sum(
            len(action.get("attempted_files") or [])
            for action in enriched
            if action.get("action_type") == "file_change"
        ),
        "token_usage": normalization_summary.get("token_usage") or {
            "updates": 0,
            "valid_updates": 0,
            "invalid_updates": 0,
            "latest_by_thread": [],
            "aggregate_total": None,
        },
        "file_audit": normalization_summary.get("file_audit") or {
            "raw": {
                "raw_records": 0,
                "valid_records": 0,
                "invalid_records": 0,
                "operation_counts": {},
                "unique_paths": 0,
                "queue_overflows": 0,
                "limit_reached_records": 0,
            },
            "correlation": {
                "events": 0,
                "correlated_unique_tool_window": 0,
                "ambiguous_overlapping_tool_windows": 0,
                "outside_tool_windows": 0,
                "non_path_events": 0,
            },
            "collector": {},
        },
        "os_audit": normalization_summary.get("os_audit") or {
            "raw": {
                "raw_records": 0,
                "valid_records": 0,
                "invalid_records": 0,
                "syscalls": 0,
                "processes": 0,
                "reads": 0,
                "writes": 0,
                "network": 0,
                "failed": 0,
                "gap_records": 0,
            },
            "correlation": {
                "events": 0,
                "correlated_unique_tool_window": 0,
                "ambiguous_overlapping_tool_windows": 0,
                "outside_tool_windows": 0,
                "diagnostic_or_unscoped_records": 0,
            },
            "filesystem_correlation": {
                "matched_unique_write_syscall": 0,
                "ambiguous_write_syscalls": 0,
                "unmatched_filesystem_events": 0,
            },
            "collector": {"status": "disabled"},
        },
    }
    file_audit = dict(summary["file_audit"])
    file_audit["filesystem_reconciliations"] = sum(
        1
        for action in enriched
        if action.get("action_type") == "workspace_reconcile"
        and (action.get("payload") or {}).get("capture_source")
        == "filesystem_event_window"
    )
    file_audit["unattributed_workspace_changes"] = sum(
        len(action.get("workspace_changes") or [])
        for action in enriched
        if action.get("action_type") == "workspace_reconcile"
    )
    file_audit["observed_workspace_changes"] = summary[
        "workspace_observed_changes"
    ]
    file_audit["concurrent_boundary_reconciliations"] = sum(
        1
        for action in enriched
        if action.get("action_type") == "workspace_reconcile"
        and (action.get("payload") or {}).get("capture_source")
        == "concurrent_item_boundary"
    )
    summary["file_audit"] = file_audit
    atomic_json_dump(run_dir / "enriched.json", enriched)
    atomic_json_dump(run_dir / "summary.json", summary)
    atomic_json_dump(run_dir / "provenance_graph.json", graph)
    return enriched
