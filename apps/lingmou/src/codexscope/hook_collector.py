from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import time
from pathlib import Path
from typing import Any, Sequence, TextIO

from .redaction import DEFAULT_LIMITS, TRUNCATED, redact_event
from .storage import append_jsonl_locked


HOOK_SCHEMA = "codexscope.hook.v1"
HOOK_SOURCE = "hook"
SPOOL_ENV = "CODEXSCOPE_HOOK_SPOOL"
INCLUDE_SENSITIVE_ENV = "CODEXSCOPE_INCLUDE_SENSITIVE"
MAX_INPUT_BYTES = 1_048_576
MAX_OUTPUT_BYTES = 262_144

_LIFTED_FIELDS = (
    "session_id",
    "thread_id",
    "turn_id",
    "hook_event",
    "hook_event_name",
    "tool_use_id",
    "toolUseId",
)


class HookCollectionError(RuntimeError):
    pass


def _is_conversation_key(key: str) -> bool:
    normalized = "".join(character for character in key.casefold() if character.isalnum())
    return (
        normalized in {"messages", "messagebody", "reasoning", "reasoningsummary"}
        or normalized.endswith("prompt")
        or normalized.endswith("message")
    )


def _omit_all_strings(value: Any) -> Any:
    if isinstance(value, str):
        return "[OMITTED]"
    if isinstance(value, list):
        return [_omit_all_strings(item) for item in value]
    if isinstance(value, dict):
        return {key: _omit_all_strings(item) for key, item in value.items()}
    return value


def _omit_conversation_field(container: dict[str, Any], key: str) -> None:
    value = container.get(key)
    if not isinstance(value, (str, list, dict)):
        return
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        length = len(value)
    else:
        encoded = json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        length = len(encoded)
    container[key] = _omit_all_strings(value)
    container[f"{key}_sha256"] = hashlib.sha256(encoded).hexdigest()
    container[f"{key}_length"] = length


def _omit_conversation_text(value: Any) -> None:
    if isinstance(value, list):
        for item in value:
            _omit_conversation_text(item)
        return
    if not isinstance(value, dict):
        return
    # Iterate over the pre-transform fields so metadata added below cannot be
    # mistaken for another prompt-shaped field in this pass.
    for raw_key, item in list(value.items()):
        key = str(raw_key)
        if _is_conversation_key(key):
            _omit_conversation_field(value, key)
        elif isinstance(item, (dict, list)):
            _omit_conversation_text(item)


def _include_sensitive_from_environment() -> bool:
    value = os.environ.get(INCLUDE_SENSITIVE_ENV, "")
    return value.strip().casefold() in {"1", "true", "yes", "on"}


def _read_stdin(stdin: TextIO) -> dict[str, Any]:
    buffer = getattr(stdin, "buffer", None)
    if buffer is not None:
        raw = buffer.read(MAX_INPUT_BYTES + 1)
    else:
        text = stdin.read(MAX_INPUT_BYTES + 1)
        raw = text.encode("utf-8")
    if len(raw) > MAX_INPUT_BYTES:
        raise HookCollectionError(f"hook input exceeds {MAX_INPUT_BYTES} bytes")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HookCollectionError(f"invalid hook JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise HookCollectionError("hook input must be one JSON object")
    return value


def build_record(
    payload: dict[str, Any], *, include_sensitive: bool = False
) -> dict[str, Any]:
    """Create the bounded, source-labelled record written to the hook spool."""

    redacted = redact_event(payload, limits=DEFAULT_LIMITS)
    assert isinstance(redacted, dict)
    if not include_sensitive:
        _omit_conversation_text(redacted)
    record: dict[str, Any] = {
        "schema": HOOK_SCHEMA,
        "source": HOOK_SOURCE,
        "wall_time_ns": time.time_ns(),
        "monotonic_ns": time.monotonic_ns(),
    }
    # Keep correlation keys cheap to query while retaining the complete,
    # redacted source object in payload.  Nesting avoids clobbering the
    # SessionStart input field also named ``source``.
    for key in _LIFTED_FIELDS:
        if key in redacted:
            record[key] = redacted[key]
    record["payload"] = redacted

    encoded = _encode(record)
    if len(encoded) <= MAX_OUTPUT_BYTES:
        return record

    # The normal redaction budgets keep records well below this ceiling.  This
    # final guard protects against future policy changes and exotic encoders.
    record["payload"] = {
        "_truncated": f"{TRUNCATED}: encoded record exceeded {MAX_OUTPUT_BYTES} bytes",
        "original_field_count": len(payload),
    }
    if len(_encode(record)) > MAX_OUTPUT_BYTES:
        raise HookCollectionError("hook metadata exceeds output size limit")
    return record


def _encode(record: dict[str, Any]) -> bytes:
    return (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


def _validate_spool(path: Path) -> Path:
    path = path.expanduser().absolute()
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise HookCollectionError(f"refusing symlink hook spool: {path}")
        if not stat.S_ISREG(info.st_mode):
            raise HookCollectionError(f"hook spool is not a regular file: {path}")
        path.chmod(0o600)
    return path


def collect_once(
    path: Path, payload: dict[str, Any], *, include_sensitive: bool = False
) -> None:
    spool = _validate_spool(path)
    append_jsonl_locked(
        spool, build_record(payload, include_sensitive=include_sensitive)
    )
    # append_jsonl_locked creates new files with 0600.  Re-apply it for an
    # existing spool whose mode may have been changed between hook runs.
    spool.chmod(0o600)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m codexscope.hook_collector",
        description="Record one Codex lifecycle hook event without emitting hook output.",
    )
    parser.add_argument("--out", type=Path, help=f"JSONL spool (overrides ${SPOOL_ENV})")
    parser.add_argument(
        "--default-out",
        type=Path,
        help=f"fallback JSONL spool used only when --out and ${SPOOL_ENV} are unset",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="return non-zero on collection failure (unsafe for normal Codex hooks)",
    )
    return parser


def main(argv: Sequence[str] | None = None, *, stdin: TextIO | None = None) -> int:
    args = _parser().parse_args(argv)
    source = stdin if stdin is not None else sys.stdin
    try:
        configured = (
            args.out
            or (Path(value) if (value := os.environ.get(SPOOL_ENV)) else None)
            or args.default_out
        )
        if configured is None:
            raise HookCollectionError(f"set ${SPOOL_ENV} or pass --out")
        collect_once(
            configured,
            _read_stdin(source),
            include_sensitive=_include_sensitive_from_environment(),
        )
    except Exception as exc:
        # A telemetry failure must not alter the agent's control flow.  Strict
        # mode exists for installation checks and automated tests only.
        if args.strict:
            print(f"codexscope hook collector: {exc}", file=sys.stderr)
            return 1
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
