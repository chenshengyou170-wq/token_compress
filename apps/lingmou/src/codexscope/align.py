from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .diffmap import semantic_diff_fingerprint


@dataclass(frozen=True, slots=True)
class Token:
    signature: str
    action_id: str
    seq: int
    label: str
    attrs: dict[str, Any]


_VOLATILE_KEYS = {
    "id",
    "event_id",
    "item_id",
    "request_id",
    "session_id",
    "thread_id",
    "turn_id",
    "timestamp",
    "timestamp_ns",
    "created_at",
    "updated_at",
    "duration_ms",
}


def _digest(value: Any) -> str:
    material = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()[:24]


def semantic_fingerprint(action_type: str, semantic_arguments: Any) -> str:
    """Return a stable, versioned action signature."""

    return f"{action_type.upper()}:v1:{_digest(semantic_arguments)}"


def _normalize_path(value: str, cwd: str | None) -> str:
    normalized = os.path.normpath(value).replace("\\", "/")
    if cwd:
        root = os.path.normpath(cwd).replace("\\", "/").rstrip("/")
        if normalized == root:
            return "$CWD"
        if normalized.startswith(root + "/"):
            return "$CWD/" + normalized[len(root) + 1 :]
    normalized = re.sub(r"^/tmp/(?:tmp[^/]+|codex[^/]*)", "$TMP", normalized)
    return normalized


def _canonicalize(value: Any, cwd: str | None = None, key: str | None = None) -> Any:
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for child_key in sorted(value, key=str):
            normalized_key = str(child_key)
            if normalized_key.lower() in _VOLATILE_KEYS:
                continue
            result[normalized_key] = _canonicalize(value[child_key], cwd, normalized_key)
        return result
    if isinstance(value, (list, tuple)):
        return [_canonicalize(item, cwd, key) for item in value]
    if isinstance(value, str):
        if key and key.lower() in {"command", "cmd", "shell_command"}:
            return _normalize_command(value, cwd)
        if key and any(marker in key.lower() for marker in ("path", "file", "cwd", "root")):
            return _normalize_path(value, cwd)
        return value.replace("\r\n", "\n")
    if isinstance(value, float):
        return round(value, 9)
    return value


def _normalize_command(command: str, cwd: str | None) -> list[str]:
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        tokens = command.split()
    normalized: list[str] = []
    for token in tokens:
        if cwd and (token.startswith(cwd) or token.startswith(("/", "./", "../"))):
            normalized.append(_normalize_path(token, cwd))
        else:
            normalized.append(token.replace("\\", "/"))
    return normalized


def _event_id(action: dict[str, Any]) -> str:
    return str(action.get("event_id") or action.get("action_id") or f"seq-{action.get('seq', 0)}")


def _action_type(action: dict[str, Any]) -> str:
    value = str(action.get("action_type") or action.get("kind") or "unknown")
    return {
        "commandExecution": "command_execution",
        "fileChange": "file_change",
        "mcpToolCall": "mcp_tool_call",
        "dynamicToolCall": "dynamic_tool_call",
    }.get(value, value)


def _item(action: dict[str, Any]) -> dict[str, Any]:
    payload = action.get("payload") or {}
    if isinstance(payload, dict) and isinstance(payload.get("item"), dict):
        return payload["item"]
    return action


def _base_attrs(action: dict[str, Any]) -> dict[str, Any]:
    actor = str(action.get("actor") or "main_agent")
    if actor != "main_agent":
        # Runtime agent identifiers are volatile across otherwise equivalent
        # runs. Preserve the behavioral role without aligning on the UUID/name.
        actor = "subagent"
    return {
        "status": action.get("status"),
        "actor": actor,
    }


def _patch_hashes(action: dict[str, Any], cwd: str | None) -> dict[str, str]:
    result: dict[str, str] = {}
    for change in _item(action).get("changes") or []:
        if isinstance(change, dict) and change.get("path"):
            path = _normalize_path(str(change["path"]), cwd)
            result[path] = semantic_diff_fingerprint(str(change.get("diff") or ""))
    for change in action.get("workspace_changes") or []:
        if not isinstance(change, dict) or not change.get("path"):
            continue
        path = _normalize_path(str(change["path"]), cwd)
        if change.get("semantic_diff_sha256"):
            result[path] = str(change["semantic_diff_sha256"])
        elif change.get("after_sha256"):
            result[path] = str(change["after_sha256"])
    return result


def _patch_for_path(patch_hashes: Mapping[str, str], path: str) -> str:
    if path in patch_hashes:
        return patch_hashes[path]
    suffix = "/" + path.lstrip("/")
    for candidate, fingerprint in patch_hashes.items():
        if candidate.endswith(suffix) or path.endswith("/" + candidate.lstrip("/")):
            return fingerprint
    return "unknown"


def tokens_from_actions(actions: list[dict[str, Any]]) -> list[Token]:
    """Project enriched events into stable semantic alignment tokens."""

    tokens: list[Token] = []
    for action in sorted(actions, key=lambda value: (int(value.get("seq") or 0), _event_id(value))):
        action_type = _action_type(action)
        action_id = _event_id(action)
        seq = int(action.get("seq") or 0)
        cwd = str(action.get("cwd")) if action.get("cwd") else None
        base_attrs = _base_attrs(action)

        patch_hashes = _patch_hashes(action, cwd)
        has_write_evidence = bool(
            action.get("affected_functions")
            or action.get("workspace_changes")
            or action.get("affected_files")
        )
        if has_write_evidence:
            functions = action.get("affected_functions") or []
            seen: set[tuple[str, str]] = set()
            for function in functions:
                if not isinstance(function, dict):
                    continue
                path = _normalize_path(str(function.get("path") or "<unknown>"), cwd)
                name = str(function.get("name") or "<module/global>")
                key = (path, name)
                if key in seen:
                    continue
                seen.add(key)
                patch = _patch_for_path(patch_hashes, path)
                semantic = {"path": path, "function": name, "patch": patch}
                label = f"MODIFY:{path}::{name}"
                tokens.append(Token(semantic_fingerprint("modify", semantic), action_id, seq, label, dict(base_attrs)))
            if not seen:
                files = action.get("affected_files") or list(patch_hashes) or ["<unknown>"]
                for path_value in sorted(set(str(path) for path in files)):
                    path = _normalize_path(path_value, cwd)
                    semantic = {"path": path, "patch": _patch_for_path(patch_hashes, path)}
                    label = f"MODIFY:{path}"
                    tokens.append(Token(semantic_fingerprint("modify", semantic), action_id, seq, label, dict(base_attrs)))
        if action_type == "file_change":
            if not has_write_evidence:
                attempted = sorted(
                    _normalize_path(str(path), cwd)
                    for path in action.get("attempted_files") or []
                )
                semantic = {"paths": attempted, "status": action.get("status")}
                tokens.append(
                    Token(
                        semantic_fingerprint("file_change_attempt", semantic),
                        action_id,
                        seq,
                        "ATTEMPT_MODIFY:" + (", ".join(attempted) or "<unknown>"),
                        dict(base_attrs),
                    )
                )
            continue

        if action_type == "command_execution":
            for function in action.get("read_functions") or []:
                if not isinstance(function, dict):
                    continue
                path = _normalize_path(str(function.get("path") or "<unknown>"), cwd)
                name = str(function.get("name") or "<module/global>")
                interval = [function.get("read_start_line"), function.get("read_end_line")]
                semantic = {"path": path, "function": name, "interval": interval}
                label = f"READ:{path}::{name}"
                tokens.append(Token(semantic_fingerprint("read", semantic), action_id, seq, label, dict(base_attrs)))

            if action.get("is_test"):
                test_key = str(action.get("test_key") or "<unknown>")
                semantic = {"test": _normalize_command(test_key, cwd)}
                attrs = dict(base_attrs)
                attrs["outcome"] = action.get("test_outcome")
                label = f"TEST:{test_key}"
                tokens.append(Token(semantic_fingerprint("test", semantic), action_id, seq, label, attrs))
            else:
                command = str(action.get("operation") or action.get("command") or _item(action).get("command") or "")
                semantic = {
                    "tool": action.get("tool") or "shell",
                    "argv": _normalize_command(command, cwd),
                    "targets": sorted(_normalize_path(str(path), cwd) for path in action.get("targets") or []),
                }
                family = action.get("command_family") or (Path(semantic["argv"][0]).name if semantic["argv"] else "command")
                label = f"COMMAND:{family} {' '.join(semantic['argv'][1:])}".rstrip()
                tokens.append(Token(semantic_fingerprint("command", semantic), action_id, seq, label, dict(base_attrs)))
            continue

        if action_type in {"mcp_tool_call", "dynamic_tool_call"}:
            item = _item(action)
            tool = str(action.get("tool") or item.get("tool") or "unknown")
            arguments = item.get("arguments") if "arguments" in item else action.get("arguments")
            semantic = {"tool": tool, "arguments": _canonicalize(arguments, cwd)}
            prefix = "MCP" if action_type == "mcp_tool_call" else "TOOL"
            label = f"{prefix}:{tool}"
            tokens.append(Token(semantic_fingerprint(prefix, semantic), action_id, seq, label, dict(base_attrs)))
            continue

        # Retain other semantically meaningful canonical events without allowing
        # timestamps or IDs to destabilize their signatures.
        if action_type not in {"turn", "thread", "agent_message", "reasoning"}:
            semantic = {
                "type": action_type,
                "tool": action.get("tool"),
                "operation": action.get("operation"),
                "targets": _canonicalize(action.get("targets") or [], cwd),
            }
            tokens.append(
                Token(
                    semantic_fingerprint(action_type, semantic),
                    action_id,
                    seq,
                    f"{action_type.upper()}:{action.get('operation') or action.get('tool') or ''}".rstrip(":"),
                    dict(base_attrs),
                )
            )
    return tokens


def _token_dict(token: Token) -> dict[str, Any]:
    return {
        "signature": token.signature,
        "action_id": token.action_id,
        "seq": token.seq,
        "label": token.label,
        "attrs": token.attrs,
    }


def align_tokens(a: list[Token], b: list[Token]) -> dict[str, Any]:
    """Align semantic traces without allocating an O(n*m) DP matrix."""

    matcher = difflib.SequenceMatcher(
        None,
        [token.signature for token in a],
        [token.signature for token in b],
        autojunk=False,
    )
    operations: list[dict[str, Any]] = []
    first_divergence: dict[str, Any] | None = None
    matched = 0

    def append(operation: dict[str, Any]) -> None:
        nonlocal first_divergence
        operation["index"] = len(operations)
        operations.append(operation)
        if first_divergence is None and (
            operation["op"] != "match" or operation.get("attribute_difference")
        ):
            first_divergence = operation

    for tag, a_start, a_end, b_start, b_end in matcher.get_opcodes():
        if tag == "equal":
            for offset in range(a_end - a_start):
                left = a[a_start + offset]
                right = b[b_start + offset]
                matched += 1
                append(
                    {
                        "op": "match",
                        "a": _token_dict(left),
                        "b": _token_dict(right),
                        "attribute_difference": left.attrs != right.attrs,
                    }
                )
            continue
        if tag == "replace":
            paired = min(a_end - a_start, b_end - b_start)
            for offset in range(paired):
                append(
                    {
                        "op": "replace",
                        "a": _token_dict(a[a_start + offset]),
                        "b": _token_dict(b[b_start + offset]),
                        "attribute_difference": True,
                    }
                )
            for index in range(a_start + paired, a_end):
                append({"op": "only_a", "a": _token_dict(a[index]), "b": None})
            for index in range(b_start + paired, b_end):
                append({"op": "only_b", "a": None, "b": _token_dict(b[index])})
        elif tag == "delete":
            for index in range(a_start, a_end):
                append({"op": "only_a", "a": _token_dict(a[index]), "b": None})
        elif tag == "insert":
            for index in range(b_start, b_end):
                append({"op": "only_b", "a": None, "b": _token_dict(b[index])})

    denominator = max(len(a), len(b), 1)
    return {
        "algorithm": "sequence_matcher_v1",
        "token_count_a": len(a),
        "token_count_b": len(b),
        # Compatibility name retained for existing consumers; this is the number
        # of ordered matching tokens found by the non-matrix matcher.
        "lcs_length": matched,
        "matched_token_count": matched,
        "semantic_similarity": round(matched / denominator, 6),
        "first_divergence": first_divergence,
        "operations": operations,
    }
