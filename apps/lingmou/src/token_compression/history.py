"""Explicit host-side history policies; never truncate tool call arguments."""
from __future__ import annotations

import copy
import re

from codexscope.structural_compression import decode_tool_result, dumps, loads


def _independent_outputs(retained, original, trusted_ids):
    """Expand references whose base would otherwise disappear with an old turn."""
    bases = {}
    for item in original:
        field = "output" if item.get("type") in {"function_call_output", "custom_tool_call_output"} else "content"
        call_id = item.get("call_id", item.get("tool_call_id"))
        if call_id and isinstance(item.get(field), str):
            bases[call_id] = item[field]
    result = copy.deepcopy(retained)
    for item in result:
        call_id = item.get("call_id", item.get("tool_call_id"))
        if call_id not in trusted_ids or not (item.get("role") == "tool" or item.get("type") in {"function_call_output", "custom_tool_call_output"}):
            continue
        field = "output" if "output" in item else "content"
        text = item.get(field)
        if not isinstance(text, str):
            continue
        try:
            value = loads(text)
        except ValueError:
            continue
        if isinstance(value, dict) and value.get("$lingmou") in {"repeat/v1", "delta/v1"}:
            item[field] = decode_tool_result(text, bases)
    return result


def shorten_tags(text: str, limit: int = 800) -> str:
    """GenericAgent's head/tail idea, restricted to declared reference material."""
    def replace(match):
        value = match[2]
        if len(value) <= limit:
            return match[0]
        n = limit // 2
        return f"<{match[1]}>{value[:n]}\n...[Truncated]...\n{value[-n:]}</{match[1]}>"
    return re.sub(r"<(thinking|think|tool_use|tool_result|history|key_info|earlier_context)>(.*?)</\1>",
                  replace, text, flags=re.S)


def _paired(items):
    calls, outputs = set(), set()
    for item in items:
        if item.get("type") in {"function_call", "custom_tool_call"}:
            calls.add(item.get("call_id"))
        if item.get("type") in {"function_call_output", "custom_tool_call_output"}:
            outputs.add(item.get("call_id"))
        if item.get("role") == "tool":
            outputs.add(item.get("tool_call_id"))
        for call in item.get("tool_calls", []):
            calls.add(call.get("id"))
    return outputs <= calls


def trim_history(body, *, original_body, budget, keep_turns, count, store, archive_notice=False):
    """Drop complete oldest user turns; pinned roles, latest turns and pairs survive.

    The removed history is recoverable from the result's archive source ID.
    A budget is a target: pinned content may make it impossible to meet.
    """
    key = "messages" if "messages" in body else "input"
    items = body.get(key)
    if not budget or not isinstance(items, list) or count(dumps(body)) <= budget:
        return body, None
    # Avoid guessing about unfamiliar blocks and server-side references.
    if any(not isinstance(x, dict) for x in items) or not _paired(items):
        return body, None
    if any(x.get('type', 'message') not in {'message', 'function_call', 'custom_tool_call',
            'function_call_output', 'custom_tool_call_output', 'reasoning'} for x in items):
        # Tool discovery and item references can carry state across turns. Do
        # not remove them as ordinary conversation text. Opaque reasoning belongs
        # to the turn that produced it and is removed only with that whole turn.
        return body, None
    trusted_ids = set()
    for sent, raw in zip(items, original_body.get(key, [])):
        if sent != raw and (sent.get("role") == "tool" or sent.get("type") in {"function_call_output", "custom_tool_call_output"}):
            trusted_ids.add(sent.get("call_id", sent.get("tool_call_id")))
    prefix, turns = [], []
    for item in items:
        if item.get("role") in {"system", "developer"}:
            # Middle instructions are ordering-sensitive: don't move them.
            if turns:
                return body, None
            prefix.append(item)
        elif item.get("role") == "user":
            turns.append([item])
        elif turns:
            turns[-1].append(item)
        else:
            prefix.append(item)
    candidate = copy.deepcopy(body)
    removed = []
    while len(turns) > keep_turns and count(dumps(candidate)) > budget:
        removed.extend(turns.pop(0))
        candidate[key] = _independent_outputs(prefix + [x for turn in turns for x in turn], items, trusted_ids)
    if not removed or not _paired(candidate[key]):
        return body, None
    archive_text = dumps(removed)
    if archive_notice:
        # SourceStore reads by line. A single giant JSON line would make the
        # archive impossible to retrieve within its per-read character limit.
        lines = [dumps(item) for item in removed]
        if any(len(line) > 250_000 for line in lines):
            return body, None
        archive_text = '[\n' + ',\n'.join(lines) + '\n]'
    source_id = store.put(archive_text)
    if archive_notice:
        notice = {'role': 'assistant', 'content':
            'Earlier conversation turns were archived. Retrieve missing decisions or constraints with '
            f'lingmou_source_read(source_id="{source_id}",start_line=2,end_line=2) before relying on them. '
            'The archive is JSON with one message per line from line 2; read one line at a time.'}
        candidate[key].insert(len(prefix), notice)
        if count(dumps(candidate)) >= count(dumps(body)):
            return body, None
    return candidate, {"source_id": source_id, "removed_messages": len(removed),
                       "budget_met": count(dumps(candidate)) <= budget}
