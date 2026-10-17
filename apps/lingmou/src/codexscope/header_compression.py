"""Recoverable abbreviation of long tool documentation and style-only instructions.

Used by the opt-in `max` desktop mode. Both live in the request header, which a
conversation ledger freezes after the first request, so the abbreviation does
not change between requests. The complete original text is stored first; every
abbreviated section names the exact line range to reread.
"""
from __future__ import annotations

import re

_SECTION = re.compile(r'(?m)^(?=#{1,3} )')
_FENCE = re.compile(r'```[a-zA-Z]*\n(.*?)```', re.S)
_COMMENT = re.compile(r'(?m)^[ \t]*//.*\n')
# Codex prompt sections about tone, progress messages and answer formatting.
# Task, safety, sandbox, AGENTS.md and tool rules are never matched.
STYLE_HEADINGS = re.compile(r'(?i)^#+\s*(?:Personality|Responsiveness|Preamble messages|Sharing progress updates|'
                            r'Ambition vs\.? precision|Presenting your work(?: and final message)?|'
                            r'Final answer structure and style guidelines)\s*$')


def _reader(source_id, start, end):
    return f'lingmou_source_read(source_id="{source_id}",start_line={start},end_line={end})'


def _sections(text):
    """Split at markdown headings; return (heading level, text, first line number)."""
    parts, line = [], 1
    for part in _SECTION.split(text):
        if part:
            level = len(part) - len(part.lstrip('#')) if part.startswith('#') else 0
            parts.append((level, part, line))
            line += part.count('\n')
    return parts


def abbreviate_tool_description(text, *, store, count, keep_chars=600):
    """Keep the preamble and short sections; shorten long nested-tool sections.

    A long section keeps its heading, first sentence and TypeScript declaration
    without comment lines; prose-only sections keep their heading and a pointer.
    """
    if len(text) < 3000 or '$lingmou' in text or 'lingmou_source_read' in text:
        return text
    parts = _sections(text)
    if len(parts) < 3:
        return text
    try:
        source_id = store.put(text)
    except (ValueError, OSError):
        return text
    result = [parts[0][1]] if parts[0][0] == 0 else []
    for level, part, start in parts[1 if parts[0][0] == 0 else 0:]:
        if len(part) <= keep_chars:
            result.append(part)
            continue
        end = start + part.count('\n') - (1 if part.endswith('\n') else 0)
        heading, _, body = part.partition('\n')
        first = re.split(r'(?<=[.!?。])\s', body.strip(), maxsplit=1)[0][:240]
        fences = [_COMMENT.sub('', match[1]).rstrip() for match in _FENCE.finditer(part)]
        lines = [heading, first]
        lines += [f'```ts\n{fence}\n```' for fence in fences if fence]
        lines.append(f'[Abbreviated by Lingmou; full section: {_reader(source_id, start, end)}]\n')
        result.append('\n'.join(lines) + '\n')
    candidate = ''.join(result)
    return candidate if count(candidate) < count(text) * .85 else text


def compact_tool_definitions(tools, *, store, count):
    """Mutate long tool descriptions in place; the source reader is never touched."""
    changed = 0
    for tool in tools if isinstance(tools, list) else []:
        if not isinstance(tool, dict):
            continue
        name = str(tool.get('name', ''))
        if 'lingmou' in name:
            continue
        if tool.get('type') == 'namespace':
            changed += compact_tool_definitions(tool.get('tools'), store=store, count=count)
        target = tool.get('function') if isinstance(tool.get('function'), dict) else tool
        if isinstance(target.get('description'), str):
            compact = abbreviate_tool_description(target['description'], store=store, count=count)
            if compact != target['description']:
                target['description'] = compact
                changed += 1
    return changed


def defer_style_sections(text, *, store, count):
    """Replace matched style sections (with their subsections) by reread pointers."""
    parts = _sections(text)
    if not any(STYLE_HEADINGS.match(part.partition('\n')[0]) for level, part, _ in parts if level):
        return text
    try:
        source_id = store.put(text)
    except (ValueError, OSError):
        return text
    result, skip_level = [], None
    for index, (level, part, start) in enumerate(parts):
        if skip_level is not None and level and level > skip_level:
            continue
        skip_level = None
        heading = part.partition('\n')[0]
        if level and STYLE_HEADINGS.match(heading):
            end = start + part.count('\n') - 1
            for later_level, later, later_start in parts[index + 1:]:
                if later_level and later_level <= level:
                    break
                end = later_start + later.count('\n') - 1
            result.append(f'{heading}\n[Style guidance deferred by Lingmou; read with {_reader(source_id, start, end)} '
                          'before writing progress updates or the final answer.]\n\n')
            skip_level = level
            continue
        result.append(part)
    candidate = ''.join(result)
    return candidate if count(candidate) < count(text) else text
