"""Explicit data regions. Instruction roles and unmarked conversation stay exact."""
from __future__ import annotations

import re
from typing import Callable

REFERENCE_START = '<lingmou-reference>'
REFERENCE_END = '</lingmou-reference>'
_REFERENCE = re.compile(re.escape(REFERENCE_START) + r'(.*?)' + re.escape(REFERENCE_END), re.S)


def reference_text(text: str) -> str:
    """Mark material at the caller/host boundary, never inferred from its prose."""
    if REFERENCE_START in text or REFERENCE_END in text:
        raise ValueError('nested reference delimiters are not supported')
    return REFERENCE_START + text + REFERENCE_END


def transform_data(text: str, role: str, transform: Callable[[str], str]) -> str:
    if role == 'tool_output':
        return transform(text)
    if role != 'user':
        return text
    matches = list(_REFERENCE.finditer(text))
    # Ambiguous/nested/unclosed markers fail closed, including mixed good/bad blocks.
    if (len(matches) != text.count(REFERENCE_START)
            or len(matches) != text.count(REFERENCE_END)
            or any(REFERENCE_START in m[1] for m in matches)):
        return text
    return _REFERENCE.sub(lambda m: REFERENCE_START + transform(m[1]) + REFERENCE_END, text)


def task_from_body(body: dict) -> str:
    """Only the latest user's task, with reference material excluded from routing."""
    inputs = body.get('messages', body.get('input'))
    if isinstance(inputs, str):
        return _REFERENCE.sub('', inputs).strip()
    if not isinstance(inputs, list):
        return ''
    for item in reversed(inputs):
        if not isinstance(item, dict) or item.get('role') != 'user':
            continue
        content = item.get('content')
        if isinstance(content, str):
            return _REFERENCE.sub('', content).strip()
        if isinstance(content, list):
            return '\n'.join(_REFERENCE.sub('', p['text']) for p in content
                if isinstance(p, dict) and p.get('type') in {'text', 'input_text'}
                and isinstance(p.get('text'), str)).strip()
    return ''
