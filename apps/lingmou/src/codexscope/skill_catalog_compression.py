"""Defer only skill-catalog descriptions, keeping every name and source path."""
from __future__ import annotations

import re

from .reference_selection import words

_BLOCK = re.compile(r'(<skills_instructions>)(.*?)(</skills_instructions>)', re.S)
_ENTRY = re.compile(r'^- (?P<name>\S+): (?P<description>.+?) \(file: (?P<path>[^\n()]+)\)$')
_HEADER = '### Available skills\n'


def defer_skill_descriptions(text, task, store, count):
    """Only recognize the explicit host catalog; other instructions stay exact.

    This is retrieval, not semantic equivalence: descriptions can affect skill
    selection. Explicitly named skills and the best lexical matches stay full;
    every other skill remains discoverable by name/path and the archived index.
    """
    deferred = 0
    def replace(block):
        nonlocal deferred
        value = block[2]
        if value.count(_HEADER) != 1:
            return block[0]
        prefix, catalog = value.split(_HEADER)
        lines = catalog.strip().splitlines()
        entries = [_ENTRY.fullmatch(line) for line in lines]
        if len(entries) < 8 or not all(entries):
            return block[0]
        query = words(task)
        scores = [(len(query & words(e['name'] + ' ' + e['description'])), i)
                  for i, e in enumerate(entries)]
        keep = {i for score, i in sorted(scores, reverse=True)[:6] if score >= 2}
        keep.update(i for i, e in enumerate(entries) if re.search(
            r'(?<![\w:-])\$?' + re.escape(e['name']) + r'(?![\w:-])', task, re.I))
        if len(keep) == len(entries):
            return block[0]
        try:
            source_id = store.put(catalog)
        except (ValueError, OSError):
            return block[0]
        notice = ('Some descriptions are deferred; all skill names and paths remain available. '
                  'If applicability is unclear, read the skill file or the full catalog with '
                  f'lingmou_source_read(source_id="{source_id}", start_line=1, '
                  f'end_line={min(500, len(catalog.splitlines()))}).\n')
        compact = '\n'.join(line if i in keep else f"- {e['name']}: (file: {e['path']})"
                            for i, (line, e) in enumerate(zip(lines, entries)))
        candidate = block[1] + prefix + _HEADER + notice + compact + '\n' + block[3]
        if count(candidate) >= count(block[0]):
            return block[0]
        deferred += len(entries) - len(keep)
        return candidate
    return _BLOCK.sub(replace, text), deferred
