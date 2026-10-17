"""Page old completed tool output out of a long turn, with exact source recovery.

Calls, IDs, instructions, opaque reasoning and media are never removed or edited.
This policy only runs in full mode with an available source reader.
"""
from __future__ import annotations

import json
import re
from collections import Counter

_RESULTS = {'function_call_output', 'custom_tool_call_output'}
_PINNED_READ = re.compile(r'lingmou_source_read|(?<![A-Za-z0-9])(?:AGENTS|SKILL)\.md\b', re.I)
_FAILURE = re.compile(r'(?im)(?:Traceback \(most recent call last\)|'
                      r'Process exited with code [1-9]\d*\b|'
                      r'(?:exit_code|exit code)\s*[:=]\s*[1-9]\d*\b)')


def _texts(item):
    field = 'content' if item.get('role') == 'tool' else 'output'
    content = item.get(field)
    if isinstance(content, str):
        yield item, field
    elif isinstance(content, list):
        for part in content:
            if isinstance(part, dict) and part.get('type') in {'text', 'input_text'} and isinstance(part.get('text'), str):
                yield part, 'text'


def _failed(text, depth=0):
    if depth > 6:
        return True  # Do not page unfamiliar deeply nested failure wrappers.
    if _FAILURE.search(text):
        return True
    # Preserve explicit failure metadata in the common execution/MCP wrappers.
    try:
        value = json.loads(text)
    except (ValueError, RecursionError):
        return False
    if isinstance(value, dict):
        if (value.get('isError') is True or value.get('error') not in (None, False, '')
                or value.get('exit_code') not in (None, 0)
                or value.get('status') in ('failed', 'error')):
            return True
        for key in ('output', 'content', 'text', 'result'):
            child = value.get(key)
            if isinstance(child, (dict, list)):
                child = json.dumps(child)
            if isinstance(child, str) and _failed(child, depth + 1):
                return True
    elif isinstance(value, list):
        return any(_failed(v if isinstance(v, str) else json.dumps(v), depth + 1) for v in value)
    return False


def compact_tool_outputs(body, *, budget, keep_results, count, store):
    """Mutate old output text only; return the number of archived text fields.

    The budget is a target for tool output, not for instructions or the entire
    request. Recent results, failed commands, instruction reads and source
    rereads stay full even if they exceed it. Original strings are stored before
    replacement, and a quota/readability failure leaves the original intact.
    """
    items = body.get('messages', body.get('input'))
    if not budget or not isinstance(items, list):
        return 0
    calls, counts, results = {}, Counter(), []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        definitions = [(item.get('call_id'), item)] if item.get('type') in {'function_call', 'custom_tool_call'} else []
        for call in item.get('tool_calls', []) or []:
            if isinstance(call, dict):
                definitions.append((call.get('id'), call.get('function', {})))
        for call_id, call in definitions:
            if isinstance(call_id, str) and call_id and isinstance(call, dict):
                counts[call_id] += 1
                signature = '\n'.join(str(call.get(k, '')) for k in ('name', 'arguments', 'input'))
                calls[call_id] = (index, bool(_PINNED_READ.search(signature)))
        if item.get('type') in _RESULTS or item.get('role') == 'tool':
            results.append((index, item, list(_texts(item))))
    output_ids = Counter(item.get('call_id', item.get('tool_call_id')) for _, item, _ in results)
    total = sum(count(container[field]) for _, _, slots in results for container, field in slots)
    if total <= budget:
        return 0
    changed = 0
    for index, item, slots in results[:-keep_results] if keep_results else results:
        if total <= budget:
            break
        call_id = item.get('call_id', item.get('tool_call_id'))
        call = calls.get(call_id)
        if (not call or counts[call_id] != 1 or output_ids[call_id] != 1
                or call[0] >= index or call[1] or item.get('status') in {'failed', 'in_progress'}):
            continue
        if any(_failed(container[field]) for container, field in slots):
            continue
        for container, field in slots:
            if total <= budget:
                break
            text = container[field]
            # Never reinterpret supplied envelopes or create recursive sources.
            if '$lingmou' in text or len(text) < 1600:
                continue
            lines = text.splitlines(keepends=True)
            if not lines or any(len(line) > 250_000 for line in lines):
                continue  # Every original line must fit the source reader.
            before = count(text)
            notice = {
                '$lingmou': 'tool-output/v1',
                'source_id': '0' * 64,
                'total_lines': len(lines),
                'read_more': 'Earlier tool output is archived, not summarized. Use '
                    'lingmou_source_read(source_id,start_line,end_line) before relying on omitted '
                    'facts, numbers, requirements or code. Read small line ranges; do not guess.',
                'head': text[:600], 'tail': text[-400:],
            }
            candidate = json.dumps(notice, ensure_ascii=False, separators=(',', ':'))
            if before - count(candidate) < max(256, before * .25):
                continue
            try:
                notice['source_id'] = store.put(text)
            except (ValueError, OSError):
                continue
            candidate = json.dumps(notice, ensure_ascii=False, separators=(',', ':'))
            after = count(candidate)
            if before - after < max(256, before * .25):
                continue
            container[field] = candidate
            total -= before - after
            changed += 1
    return changed
