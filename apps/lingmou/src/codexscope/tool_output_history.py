"""Page old completed tool output out of a long turn, with exact source recovery.

Calls, IDs, instructions, opaque reasoning and media are never removed or edited.
This policy only runs in full mode with an available source reader.
"""
from __future__ import annotations

import json
import re
from collections import Counter

_RESULTS = {'function_call_output', 'custom_tool_call_output'}
PINNED_READ = re.compile(r'lingmou_source_read|(?<![A-Za-z0-9])(?:AGENTS|SKILL)\.md\b', re.I)
_FAILURE = re.compile(r'(?im)(?:Traceback \(most recent call last\)|'
                      r'Process exited with code [1-9]\d*\b|'
                      r'(?:exit_code|exit code)\s*[:=]\s*[1-9]\d*\b)')


def tool_text_slots(item):
    field = 'content' if item.get('role') == 'tool' else 'output'
    content = item.get(field)
    if isinstance(content, str):
        yield item, field
    elif isinstance(content, list):
        for part in content:
            if isinstance(part, dict) and part.get('type') in {'text', 'input_text'} and isinstance(part.get('text'), str):
                yield part, 'text'


def failed_output(text, depth=0):
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
            if isinstance(child, str) and failed_output(child, depth + 1):
                return True
    elif isinstance(value, list):
        return any(failed_output(v if isinstance(v, str) else json.dumps(v), depth + 1) for v in value)
    return False


_SALIENT = re.compile(r'(?i)(?:\b(?:error|errors|failed|failure|fatal|exception|traceback|warning|'
                      r'assert(?:ion)?(?:error)?|panic|denied|not found|FAIL)\b|✗|❌)')
_MAX_SALIENT = 12


def archived(text):
    return text.startswith(('{"$lingmou":"tool-output/v1"', '{"$lingmou":"superseded/v1"'))


def archive_notice(text, *, store, count, notice_kind='tool-output/v1', extra=None, min_ratio=.25,
                   min_saved=256, head_chars=600, tail_chars=400, current_tokens=None):
    """Exact-original archive with head, tail and error-like lines kept visible.

    Returns None when the original cannot be stored and fully reread, or when
    the notice would not save at least max(min_saved, min_ratio * current) tokens.
    `current_tokens` is the size of what is sent now, which may already be a
    lossless envelope of `text`.
    """
    lines = text.splitlines(keepends=True)
    if not lines or any(len(line) > 250_000 for line in lines):
        return None  # Every original line must fit the source reader.
    before = count(text) if current_tokens is None else current_tokens
    head, tail = text[:head_chars], text[-tail_chars:] if tail_chars else ''
    salient = []
    shown = len(head.splitlines())
    hidden_tail = len(lines) - len(tail.splitlines()) if tail else len(lines)
    for number, line in enumerate(lines, 1):
        if shown < number <= hidden_tail and _SALIENT.search(line):
            salient.append([number, line.rstrip('\r\n')[:200]])
            if len(salient) >= _MAX_SALIENT:
                break
    notice = {
        '$lingmou': notice_kind,
        'source_id': '0' * 64,
        'total_lines': len(lines),
        **(extra or {}),
        'read_more': 'Earlier tool output is archived, not summarized. Use '
            'lingmou_source_read(source_id,start_line,end_line) before relying on omitted '
            'facts, numbers, requirements or code. Read small line ranges; do not guess.',
        'head': head, 'tail': tail,
    }
    if salient:
        notice['salient_lines'] = salient
    if before - count(json.dumps(notice, ensure_ascii=False, separators=(',', ':'))) < max(min_saved, before * min_ratio):
        return None
    try:
        notice['source_id'] = store.put(text)
    except (ValueError, OSError):
        return None
    return json.dumps(notice, ensure_ascii=False, separators=(',', ':'))


def compact_tool_outputs(body, *, budget, keep_results, count, store, sources=None,
                         min_chars=1600, head_chars=600, tail_chars=400, min_saved=256):
    """Mutate old output text only; return the number of archived text fields.

    The budget is a target for tool output, not for instructions or the entire
    request. Recent results, failed commands, instruction reads and source
    rereads stay full even if they exceed it. Original strings are stored before
    replacement, and a quota/readability failure leaves the original intact.
    `sources` maps (id(container), field) to the exact original when the sent
    text is already a lossless envelope; the archive always stores the original.
    """
    sources = sources or {}
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
                calls[call_id] = (index, bool(PINNED_READ.search(signature)))
        if item.get('type') in _RESULTS or item.get('role') == 'tool':
            results.append((index, item, list(tool_text_slots(item))))
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
        if any(failed_output(sources.get((id(container), field), container[field])) for container, field in slots):
            continue
        for container, field in slots:
            if total <= budget:
                break
            current = container[field]
            text = sources.get((id(container), field), current)
            # Never reinterpret supplied envelopes or create recursive sources.
            if '$lingmou' in text or len(text) < min_chars or archived(current):
                continue
            before = count(current)
            candidate = archive_notice(text, store=store, count=count, current_tokens=before,
                                       head_chars=head_chars, tail_chars=tail_chars, min_saved=min_saved)
            if candidate is None:
                continue
            after = count(candidate)
            container[field] = candidate
            total -= before - after
            changed += 1
    return changed
