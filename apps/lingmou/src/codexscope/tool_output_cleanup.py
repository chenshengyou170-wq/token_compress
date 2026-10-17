"""Deterministic terminal-output normalization for newly arrived tool results.

Only presentation noise is removed: ANSI control sequences, Windows line endings,
carriage-return progress frames and long runs of identical lines (replaced by an
explicit repeat count). Characters that carry content are not rewritten, so the
same input always produces the same output and can be replayed in later requests.
"""
from __future__ import annotations

import re

_ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]')
_MIN_REPEAT = 3


def _final_frame(line: str) -> str:
    # "50%\r75%\r100%" is rendered by a terminal as its last non-empty frame.
    frames = [frame for frame in line.split('\r') if frame]
    return frames[-1] if frames else ''


def clean_tool_text(text: str) -> str:
    if not text:
        return text
    text = _ANSI.sub('', text).replace('\r\n', '\n')
    lines = [(_final_frame(line) if '\r' in line else line) for line in text.split('\n')]
    result: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        end = index + 1
        while end < len(lines) and lines[end] == line:
            end += 1
        run = end - index
        if run >= _MIN_REPEAT and line.strip():
            result.append(line)
            result.append(f'[previous line repeated {run - 1} more times]')
        elif run >= _MIN_REPEAT:
            result.extend([line] * 2)  # Keep paragraph breaks, drop blank padding.
        else:
            result.extend(lines[index:end])
        index = end
    return '\n'.join(result)
