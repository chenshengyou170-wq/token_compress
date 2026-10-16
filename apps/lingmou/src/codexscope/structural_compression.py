"""Reversible tool data codecs. JSON number lexemes, types and order survive.

References only point backwards inside the same complete request. No data is
discarded; a receiver can use decode_tool_result to recover canonical JSON or
byte-for-byte log text. Envelopes describe their own interpretation for models.
"""
from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass
from typing import Callable

from .input_compression import _unique_object

TAG = '$lingmou'


@dataclass(frozen=True)
class Number:
    """An exact JSON numeric lexeme, distinct from a string or boolean."""
    value: str

    def __str__(self):
        return self.value

    def __int__(self):
        return int(self.value)


def _invalid_constant(value):
    raise ValueError('non-JSON constant')


def loads(text: str):
    return json.loads(text, parse_int=Number, parse_float=Number,
                      parse_constant=_invalid_constant, object_pairs_hook=_unique_object)


def dumps(value) -> str:
    if isinstance(value, Number):
        return str(value)
    if isinstance(value, dict):
        return '{' + ','.join(json.dumps(k, ensure_ascii=False) + ':' + dumps(v) for k, v in value.items()) + '}'
    if isinstance(value, list):
        return '[' + ','.join(dumps(v) for v in value) + ']'
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False)


def _table(value):
    candidates = [(None, value)] if isinstance(value, list) else list(value.items()) if isinstance(value, dict) else []
    for key, rows in candidates:
        if not isinstance(rows, list) or len(rows) < 4 or not all(isinstance(r, dict) for r in rows):
            continue
        columns = list(rows[0])
        if not columns or not all(list(row) == columns for row in rows):
            continue
        result = {TAG: 'table/v1', 'decode': 'Zip columns with each row to recover objects.',
                  'columns': columns, 'rows': [list(row.values()) for row in rows]}
        if key is not None:
            # Key order is retained so a later diff can reconstruct the same object.
            result.update(field=key, keys=list(value), rest={k: v for k, v in value.items() if k != key})
        yield dumps(result)


def _diff(base, current, path, sets, removes):
    if type(base) is not type(current):
        sets.append([path, current])
    elif isinstance(current, dict) and list(base) == list(current):
        for key in current:
            _diff(base[key], current[key], path + [key], sets, removes)
    elif isinstance(current, list) and len(base) == len(current):
        for i, (old, new) in enumerate(zip(base, current)):
            _diff(old, new, path + [i], sets, removes)
    elif base != current:
        # Replacing objects when keys/order differ also preserves removed keys.
        sets.append([path, current])


_VARIABLE = re.compile(r'[-+]?\d+(?:[.:/-]\d+)*')


def _logs(text: str) -> str:
    templates, indices, records = [], {}, []
    for line in text.splitlines(keepends=True):
        parts, values, start = [], [], 0
        for match in _VARIABLE.finditer(line):
            parts.append(line[start:match.start()]); values.append(match[0]); start = match.end()
        parts.append(line[start:])
        key = tuple(parts)
        if key not in indices:
            indices[key] = len(templates); templates.append(parts)
        record = [indices[key], values, 1]
        if records and records[-1][:2] == record[:2]:
            records[-1][2] += 1
        else:
            records.append(record)
    return dumps({TAG: 'logs/v1',
        'decode': 'In order: interleave templates[id] and variables; repeat count times. Newlines are in templates.',
        'templates': templates, 'records': records})


class StructuralCompressor:
    """One instance per request. Retain original bases for verified round trips."""
    def __init__(self, count: Callable[[str], int]):
        self.count = count
        self.bases: dict[str, str] = {}
        self.latest: dict[str, str] = {}
        self.duplicates: dict[str, str] = {}

    def compress(self, text: str, *, call_id: str | None = None, family: str = '') -> str:
        if len(text) > 256_000:
            return text
        candidates = [text]
        try:
            value = loads(text)
        except (ValueError, RecursionError):
            # Invalid/duplicate-key JSON is opaque, not prose or a log.
            if text.lstrip().startswith(('{', '[')):
                return text
            if len(text.splitlines()) >= 4:
                candidates.append(_logs(text))
            value = None
        else:
            if isinstance(value, dict) and TAG in value:
                return text  # Never interpret an untrusted, pre-existing envelope.
            candidates.append(dumps(value))
            candidates.extend(_table(value))
            if family and family in self.latest and isinstance(value, (dict, list)):
                base_id = self.latest[family]
                try:
                    base = loads(self.bases[base_id])
                    sets, removes = [], []
                    _diff(base, value, [], sets, removes)
                    candidates.append(dumps({TAG: 'delta/v1',
                        'decode': 'Copy the earlier tool result, then set values at key/index paths.',
                        'base_call_id': base_id, 'set': sets}))
                except (ValueError, RecursionError):
                    pass
        if text in self.duplicates:
            candidates.append(dumps({TAG: 'repeat/v1',
                'decode': 'Exact duplicate of the earlier tool result.', 'base_call_id': self.duplicates[text]}))
        candidate = min(candidates, key=self.count)
        if self.count(candidate) >= self.count(text) or len(candidate) >= len(text):
            candidate = text
        elif candidate != text:
            # Verify every generated envelope before use; string/number confusion
            # and codec bugs cannot silently alter data sent upstream.
            decoded = decode_tool_result(candidate, self.bases)
            expected = dumps(value) if value is not None else text
            if decoded != expected:
                candidate = text
        if call_id:
            self.bases[call_id] = text
            # First occurrence is stable when later history is appended.
            self.duplicates.setdefault(text, call_id)
            # Use a non-delta baseline to avoid unbounded reference chains.
            if TAG not in candidate or 'table/v1' in candidate or 'logs/v1' in candidate:
                if family:
                    self.latest[family] = call_id
        return candidate


def decode_tool_result(text: str, bases: dict[str, str] | None = None, *, max_chars: int = 8_000_000, _seen=()) -> str:
    """Decode a trusted codec envelope; reject cycles, missing bases and bombs."""
    try:
        value = loads(text)
    except (ValueError, RecursionError):
        return text
    if not isinstance(value, dict) or TAG not in value:
        return dumps(value)
    kind = value[TAG]
    if kind == 'table/v1':
        columns = value['columns']
        if len(columns) != len(set(columns)) or any(len(row) != len(columns) for row in value['rows']):
            raise ValueError('invalid table')
        rows = [dict(zip(columns, row)) for row in value['rows']]
        result = dumps({k: rows if k == value['field'] else value['rest'][k] for k in value['keys']}) if 'field' in value else dumps(rows)
    elif kind == 'logs/v1':
        result = ''
        for index, variables, count in value['records']:
            parts = value['templates'][int(index)]
            if len(parts) != len(variables) + 1 or int(count) < 1:
                raise ValueError('invalid log record')
            line = ''.join(a + b for a, b in zip(parts, variables)) + parts[-1]
            if len(result) + len(line) * int(count) > max_chars:
                raise ValueError('decoded result too large')
            result += line * int(count)
    elif kind in {'repeat/v1', 'delta/v1'}:
        base_id = value['base_call_id']
        if not bases or base_id not in bases or base_id in _seen or len(_seen) >= 32:
            raise ValueError('missing or cyclic base')
        base = decode_tool_result(bases[base_id], bases, max_chars=max_chars, _seen=(*_seen, base_id))
        if kind == 'repeat/v1':
            result = base
        else:
            obj = copy.deepcopy(loads(base))
            for path, replacement in value['set']:
                if not path:
                    obj = replacement
                    continue
                parent = obj
                for part in path[:-1]:
                    parent = parent[int(part) if isinstance(parent, list) else part]
                parent[int(path[-1]) if isinstance(parent, list) else path[-1]] = replacement
            result = dumps(obj)
    else:
        raise ValueError('unknown codec')
    if len(result) > max_chars:
        raise ValueError('decoded result too large')
    return result
