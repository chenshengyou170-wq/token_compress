from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .redaction import redact_event


def run_checked(argv: list[str], *, cwd: Path | None = None, timeout: float = 60.0) -> str:
    completed = subprocess.run(
        argv,
        cwd=os.fspath(cwd) if cwd else None,
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return completed.stdout.strip()


def git_metadata(repo: Path, *, require_clean: bool = True) -> dict[str, Any]:
    repo = repo.resolve()
    top = Path(run_checked(["git", "rev-parse", "--show-toplevel"], cwd=repo)).resolve()
    if top != repo:
        raise ValueError(f"--repo must be the Git worktree root ({top})")
    status = run_checked(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=repo)
    if require_clean and status:
        raise RuntimeError(
            "Observed repository is not clean; use a disposable clean clone/worktree:\n" + status
        )
    return {
        "repo": os.fspath(repo),
        "git_head": run_checked(["git", "rev-parse", "HEAD"], cwd=repo),
        "git_branch": run_checked(["git", "branch", "--show-current"], cwd=repo),
        "git_status_before": status,
    }


def codex_version(codex_bin: str) -> str:
    try:
        return run_checked([codex_bin, "--version"], timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"Cannot execute {codex_bin!r}; install/configure Codex CLI first") from exc


def capture_protocol_schema(codex_bin: str, output_dir: Path) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        subprocess.run(
            [codex_bin, "app-server", "generate-json-schema", "--out", os.fspath(output_dir)],
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"captured": False, "error": str(exc)}

    digest = hashlib.sha256()
    files = sorted(path for path in output_dir.rglob("*.json") if path.is_file())
    for path in files:
        relative = path.relative_to(output_dir).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        content = path.read_bytes()
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
        try:
            path.chmod(0o600)
        except OSError:
            pass
    return {
        "captured": True,
        "file_count": len(files),
        "sha256": digest.hexdigest(),
    }


def runtime_metadata() -> dict[str, Any]:
    return {
        "codexscope_version": __version__,
        "python": sys.version,
        "python_executable": sys.executable,
        "platform": platform.platform(),
        "machine": platform.machine(),
    }


def hash_json(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


_CONVERSATION_DELTA_METHODS = frozenset(
    {
        "item/agentMessage/delta",
        "item/plan/delta",
        "item/reasoning/summaryTextDelta",
        "item/reasoning/textDelta",
        "thread/realtime/transcript/delta",
    }
)


def _omit_string_field(value: dict[str, Any], key: str) -> None:
    text = value.get(key)
    if not isinstance(text, str):
        return
    if text == "[OMITTED]" and f"{key}Sha256" in value:
        return
    value[key] = "[OMITTED]"
    value[f"{key}Sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
    value[f"{key}Length"] = len(text)


def _omit_string_list_field(value: dict[str, Any], key: str) -> None:
    items = value.get(key)
    if not isinstance(items, list):
        return
    if f"{key}Sha256s" in value and all(
        not isinstance(item, str) or item == "[OMITTED]" for item in items
    ):
        return
    hashes: list[str | None] = []
    lengths: list[int | None] = []
    changed = False
    sanitized: list[Any] = []
    for item in items:
        if isinstance(item, str):
            sanitized.append("[OMITTED]")
            hashes.append(hashlib.sha256(item.encode("utf-8")).hexdigest())
            lengths.append(len(item))
            changed = True
        else:
            sanitized.append(item)
            hashes.append(None)
            lengths.append(None)
    if changed:
        value[key] = sanitized
        value[f"{key}Count"] = len(items)
        value[f"{key}Sha256s"] = hashes
        value[f"{key}Lengths"] = lengths


def _sanitize_user_input(value: dict[str, Any]) -> None:
    text = value.get("text")
    if isinstance(text, str) and not (
        text == "[OMITTED]" and "text_sha256" in value
    ):
        value["text"] = "[OMITTED]"
        # Preserve the original snake-case metadata names used by run traces.
        value["text_sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
        value["text_length"] = len(text)
    # TextElement.placeholder is UI-rendered prompt text associated with a span
    # (for example, a mention).  Keeping it would bypass the default omission
    # policy even after the parent text was removed.
    elements = value.get("text_elements")
    if isinstance(elements, list):
        for element in elements:
            if isinstance(element, dict):
                _omit_string_field(element, "placeholder")


def _sanitize_thread_item(item: dict[str, Any]) -> None:
    item_type = item.get("type")
    if item_type == "userMessage":
        content = item.get("content")
        if isinstance(content, list):
            for part in content:
                if isinstance(part, dict):
                    _sanitize_user_input(part)
        _omit_string_list_field(item, "content")
        # Compatibility with older protocol payloads that used a scalar field.
        _omit_string_field(item, "text")
    elif item_type == "hookPrompt":
        fragments = item.get("fragments")
        if isinstance(fragments, list):
            for fragment in fragments:
                if isinstance(fragment, dict):
                    _omit_string_field(fragment, "text")
        _omit_string_list_field(item, "fragments")
    elif item_type in {"agentMessage", "plan"}:
        _omit_string_field(item, "text")
        _omit_string_field(item, "content")
        _omit_string_field(item, "summary")
        _omit_string_list_field(item, "content")
        _omit_string_list_field(item, "summary")
    elif item_type == "reasoning":
        _omit_string_field(item, "text")
        _omit_string_field(item, "content")
        _omit_string_field(item, "summary")
        _omit_string_list_field(item, "content")
        _omit_string_list_field(item, "summary")
        for key in ("content", "summary"):
            parts = item.get(key)
            if isinstance(parts, list):
                for part in parts:
                    if isinstance(part, dict):
                        _omit_string_field(part, "text")
    elif item_type in {"collabAgentToolCall", "collabToolCall"}:
        _omit_string_field(item, "prompt")
        states = item.get("agentsStates")
        if isinstance(states, dict):
            for state in states.values():
                if isinstance(state, dict):
                    _omit_string_field(state, "message")
    elif item_type == "imageGeneration":
        _omit_string_field(item, "revisedPrompt")
    elif item_type in {"enteredReviewMode", "exitedReviewMode"}:
        _omit_string_field(item, "review")


def _sanitize_turn(turn: dict[str, Any]) -> None:
    items = turn.get("items")
    if not isinstance(items, list):
        return
    for item in items:
        if isinstance(item, dict):
            _sanitize_thread_item(item)


def _looks_like_thread(value: dict[str, Any]) -> bool:
    return (
        isinstance(value.get("id"), str)
        and "turns" in value
        and ("preview" in value or "sessionId" in value or "modelProvider" in value)
    )


def _sanitize_thread(thread: dict[str, Any]) -> None:
    _omit_string_field(thread, "name")
    _omit_string_field(thread, "preview")
    turns = thread.get("turns")
    if isinstance(turns, list):
        for turn in turns:
            if isinstance(turn, dict):
                _sanitize_turn(turn)


def _sanitize_realtime_item(value: Any) -> None:
    """Remove textual fields from an experimental realtime conversation item."""

    if isinstance(value, list):
        for item in value:
            _sanitize_realtime_item(item)
        return
    if not isinstance(value, dict):
        return
    for key in ("text", "delta", "transcript", "content"):
        _omit_string_field(value, key)
    for nested in value.values():
        if isinstance(nested, (dict, list)):
            _sanitize_realtime_item(nested)


def _sanitize_protocol_tree(value: Any) -> None:
    """Find Thread/Turn/ThreadItem payloads in method-less JSON-RPC replies."""

    if isinstance(value, list):
        for item in value:
            _sanitize_protocol_tree(item)
        return
    if not isinstance(value, dict):
        return

    if _looks_like_thread(value):
        _sanitize_thread(value)

    thread = value.get("thread")
    if isinstance(thread, dict):
        _sanitize_thread(thread)
    turn = value.get("turn")
    if isinstance(turn, dict):
        _sanitize_turn(turn)
    item = value.get("item")
    if isinstance(item, dict):
        _sanitize_thread_item(item)
    goal = value.get("goal")
    if isinstance(goal, dict):
        _omit_string_field(goal, "objective")

    for nested in value.values():
        if isinstance(nested, (dict, list)):
            _sanitize_protocol_tree(nested)


def capture_transform(message: dict[str, Any], *, include_sensitive: bool = False) -> dict[str, Any]:
    """Redact credentials and optionally omit user-authored conversation text."""

    transformed = redact_event(message)
    if not isinstance(transformed, dict):
        return {"redacted": transformed}
    if include_sensitive:
        return transformed

    method = transformed.get("method")
    params = transformed.get("params")
    if method in {"turn/start", "turn/steer"} and isinstance(params, dict):
        inputs = params.get("input")
        if isinstance(inputs, list):
            for item in inputs:
                if isinstance(item, dict):
                    _sanitize_user_input(item)

    if method in {"item/started", "item/completed"} and isinstance(params, dict):
        item = params.get("item")
        if isinstance(item, dict):
            _sanitize_thread_item(item)

    if method in _CONVERSATION_DELTA_METHODS and isinstance(params, dict):
        _omit_string_field(params, "delta")
    elif method == "thread/realtime/transcript/done" and isinstance(params, dict):
        _omit_string_field(params, "text")
    elif method == "thread/realtime/item/added" and isinstance(params, dict):
        _sanitize_realtime_item(params.get("item"))
    elif method == "thread/injectItems" and isinstance(params, dict):
        _sanitize_realtime_item(params.get("items"))
    elif method == "thread/name/set" and isinstance(params, dict):
        _omit_string_field(params, "name")
    elif method == "thread/name/updated" and isinstance(params, dict):
        _omit_string_field(params, "threadName")
    elif method == "thread/goal/set" and isinstance(params, dict):
        _omit_string_field(params, "objective")
    elif method == "turn/plan/updated" and isinstance(params, dict):
        _omit_string_field(params, "explanation")
        plan = params.get("plan")
        if isinstance(plan, list):
            for step in plan:
                if isinstance(step, dict):
                    _omit_string_field(step, "step")
    elif method in {"hook/started", "hook/completed"} and isinstance(params, dict):
        run = params.get("run")
        entries = run.get("entries") if isinstance(run, dict) else None
        if isinstance(entries, list):
            for entry in entries:
                if isinstance(entry, dict):
                    _omit_string_field(entry, "text")
    elif method in {
        "item/autoApprovalReview/started",
        "item/autoApprovalReview/completed",
    } and isinstance(params, dict):
        review = params.get("review")
        if isinstance(review, dict):
            _omit_string_field(review, "rationale")

    # JSON-RPC responses don't repeat the request method.  Walk recognized
    # protocol shapes so thread/read, thread/list, thread/resume, rollback, and
    # fork replies cannot bypass the default conversation-text policy.
    _sanitize_protocol_tree(transformed)
    return transformed
