from __future__ import annotations

import difflib
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Iterable

HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


@dataclass(frozen=True, slots=True)
class LineInterval:
    start: int
    end: int


@dataclass(frozen=True, slots=True)
class ChangedLines:
    old_lines: tuple[int, ...]
    new_lines: tuple[int, ...]
    old_ranges: tuple[LineInterval, ...] = ()
    new_ranges: tuple[LineInterval, ...] = ()


def _intervals(lines: Iterable[int]) -> tuple[LineInterval, ...]:
    ordered = sorted(set(lines))
    if not ordered:
        return ()
    result: list[LineInterval] = []
    start = previous = ordered[0]
    for line in ordered[1:]:
        if line != previous + 1:
            result.append(LineInterval(start, previous))
            start = line
        previous = line
    result.append(LineInterval(start, previous))
    return tuple(result)


def _result(old_lines: Iterable[int], new_lines: Iterable[int]) -> ChangedLines:
    old = tuple(sorted(set(old_lines)))
    new = tuple(sorted(set(new_lines)))
    return ChangedLines(old, new, _intervals(old), _intervals(new))


def changed_lines_from_unified_diff(diff: str) -> ChangedLines:
    """Return one-based changed line numbers from one or more unified hunks."""

    old_changed: list[int] = []
    new_changed: list[int] = []
    old_line = new_line = 0
    in_hunk = False

    for raw in diff.splitlines():
        match = HUNK_RE.match(raw)
        if match:
            old_line = int(match.group(1))
            new_line = int(match.group(3))
            in_hunk = True
            continue
        if raw.startswith(("diff --git ", "--- ", "+++ ")):
            if raw.startswith("diff --git "):
                in_hunk = False
            continue
        if not in_hunk or raw.startswith("\\ No newline"):
            continue
        if raw.startswith("+"):
            new_changed.append(new_line)
            new_line += 1
        elif raw.startswith("-"):
            old_changed.append(old_line)
            old_line += 1
        elif raw.startswith(" "):
            old_line += 1
            new_line += 1
        else:
            # A malformed line should not make subsequent file headers look like
            # source content.
            in_hunk = False

    return _result(old_changed, new_changed)


def changed_lines_between(before: str | bytes | None, after: str | bytes | None) -> ChangedLines:
    """Compute changed line coordinates when an event did not include a diff."""

    def decode(value: str | bytes | None) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return value

    old = decode(before).splitlines()
    new = decode(after).splitlines()
    matcher = difflib.SequenceMatcher(a=old, b=new, autojunk=False)
    old_changed: list[int] = []
    new_changed: list[int] = []
    for tag, old_start, old_end, new_start, new_end in matcher.get_opcodes():
        if tag == "equal":
            continue
        old_changed.extend(range(old_start + 1, old_end + 1))
        new_changed.extend(range(new_start + 1, new_end + 1))
    return _result(old_changed, new_changed)


def semantic_diff_fingerprint(diff: str) -> str:
    """Hash patch semantics while ignoring paths and hunk line-number drift."""

    changes: list[tuple[str, str]] = []
    for raw in diff.splitlines():
        if raw.startswith(("+++", "---", "@@", "diff --git", "index ", "\\ No newline")):
            continue
        if raw.startswith(("+", "-")):
            # Whitespace runs are presentation noise, but addition/deletion and
            # token order remain part of the semantic fingerprint.
            normalized = " ".join(raw[1:].strip().split())
            changes.append((raw[0], normalized))
    material = json.dumps(changes, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()


def unified_diff(before: str | bytes | None, after: str | bytes | None, path: str = "file") -> str:
    """Create a deterministic unified diff for snapshot-only file writes."""

    def lines(value: str | bytes | None) -> list[str]:
        if value is None:
            return []
        text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value
        return text.splitlines(keepends=True)

    return "".join(
        difflib.unified_diff(
            lines(before),
            lines(after),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
            lineterm="\n",
        )
    )
