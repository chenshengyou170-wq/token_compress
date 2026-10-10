"""Data-only request compression, reversible structures and recoverable excerpts.

System/developer instructions, tasks, format requirements and tool definitions
are never rewritten. Model-selected excerpts are copied from original sources.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from collections import OrderedDict
from typing import Callable, Iterator

from .input_compression import (
    CompressionObservation, ResponsesInputCompressor, _CODE_LINE, _INLINE,
    _MAX_BODY_BYTES, _text_slots, _unique_object, compress_prose,
)
from .proxy_usage import default_token_counter
from .compression_boundary import transform_data, task_from_body
from .structural_compression import StructuralCompressor, loads, dumps
from .reference_selection import SourceStore, extract_source

_MARKER = re.compile(r'⟦KEEP_\d+⟧')
_CONSTRAINT = re.compile(
    r'\b(?:no|not|never|cannot|unless|without|only|must|shall|if|except|at least|at most|no more than)\b'
    r'|不得|禁止|不可|不能|不允许|未授权|未经|只有|仅限|除非|如果|否则|至少|至多|不超过|必须', re.I)
_FACT = re.compile(r'(?<!\w)[+-]?\d+(?:[.,:/_-]\d+)*(?:%|[A-Za-z]+)?\b|\b[A-Z][A-Z0-9_-]*\d[A-Z0-9_-]*\b')


def protect_text(text: str) -> tuple[str, list[tuple[str, str]]]:
    """Mask executable/literal material and explicit constraints before rewriting."""
    if '⟦KEEP_' in text:
        return '', []  # User-supplied placeholder syntax is never interpreted.
    protected: list[tuple[str, str]] = []
    def mask(value: str) -> str:
        marker = f'⟦KEEP_{len(protected)}⟧'
        protected.append((marker, value))
        return marker
    # Work line by line so fenced/indented code cannot be mistaken for prose.
    lines, fence = [], None
    for line in text.splitlines(keepends=True):
        mark = re.match(r'^\s*(`{3,}|~{3,})', line)
        if fence:
            lines.append(mask(line))
            if mark and mark[1][0] == fence[0] and len(mark[1]) >= fence[1]:
                fence = None
            continue
        if mark:
            fence = (mark[1][0], len(mark[1]))
            lines.append(mask(line))
            continue
        if _CODE_LINE.search(line):
            lines.append(mask(line))
            continue
        # Preserve complete conditional/prohibitive clauses, not just negation words.
        parts = re.split(r'(?<=[.!?。！？])(?=\s|[\u3400-\u9fff])', line)
        rewritten = []
        for part in parts:
            if _CONSTRAINT.search(part):
                rewritten.append(mask(part))
                continue
            # Inline code spans require paired backtick handling rather than one token.
            # Reuse the bounded literal scanner; an unclosed backtick protects
            # the rest of the line instead of triggering regex backtracking.
            chunks, offset = [], 0
            while (match := _INLINE.search(part, offset)) is not None:
                chunks.append(part[offset:match.start()])
                end = match.end()
                if match[0].startswith('`'):
                    closing = part.find(match[0], end)
                    end = len(part) if closing < 0 else closing + len(match[0])
                chunks.append(mask(part[match.start():end]))
                offset = end
            chunks.append(part[offset:])
            protected_part = ''.join(chunks)
            # Exclude already-generated markers when masking numeric facts.
            pieces = re.split(r'(⟦KEEP_\d+⟧)', protected_part)
            rewritten.append(''.join(p if _MARKER.fullmatch(p) else _FACT.sub(lambda m: mask(m[0]), p) for p in pieces))
        lines.append(''.join(rewritten))
    masked = ''.join(lines)
    protected.sort(key=lambda pair: masked.index(pair[0]))
    return masked, protected


def restore_text(candidate: str, protected: list[tuple[str, str]]) -> str | None:
    # Every protected item must survive, in order, without duplication.
    if _MARKER.findall(candidate) != [key for key, _ in protected]:
        return None
    for marker, original in protected:
        candidate = candidate.replace(marker, original)
    return candidate if '⟦KEEP_' not in candidate else None


def chat_text_slots(body: dict) -> Iterator[tuple[dict, str, str]]:
    for message in body.get('messages', []):
        if not isinstance(message, dict) or message.get('role') not in {'system','developer','user','assistant','tool'}:
            continue
        role = 'tool_output' if message['role'] == 'tool' else message['role']
        content = message.get('content')
        if isinstance(content, str):
            yield message, 'content', role
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and part.get('type') == 'text' and isinstance(part.get('text'), str):
                    yield part, 'text', role


class HybridInputCompressor(ResponsesInputCompressor):
    supports_chat_completions = True

    def __init__(self, *, rewriter: Callable[[str], str] | None = None,
                 selector=None, source_store: SourceStore | None = None, mode: str = "hybrid", **kwargs):
        super().__init__(**kwargs)
        self.rewriter = rewriter
        self._stats['mode'] = mode
        self.selector, self.source_store = selector, source_store
        self._process_lock = threading.Lock()
        self._selection_cache: OrderedDict[str, str] = OrderedDict()
        self._cache: OrderedDict[str, str] = OrderedDict()
        self._failed_until: OrderedDict[str, float] = OrderedDict()
        self._rewrite_lock = threading.Lock()

    def _rewrite(self, text: str) -> tuple[str, int, int, int]:
        key = hashlib.sha256(text.encode()).hexdigest()
        # Serialize cache misses: shared request prefixes should only incur one call.
        with self._rewrite_lock:
            if key in self._cache:
                self._cache.move_to_end(key)
                return self._cache[key], 0, 1, 0
            if self._failed_until.get(key, 0) > time.monotonic():
                return text, 0, 1, 1
            masked, protected = protect_text(text)
            if not masked or len(_MARKER.sub('', masked).strip()) < 160:
                return text, 0, 0, 0
            try:
                result = restore_text(self.rewriter(masked), protected)
            except Exception:
                result = None
            if result is None or not result.strip():
                # Avoid repeatedly stalling every turn on the same rejected or
                # timing-out prefix. Only hashes and expiry times are retained.
                self._failed_until[key] = time.monotonic() + 300
                self._failed_until.move_to_end(key)
                while len(self._failed_until) > 128:
                    self._failed_until.popitem(last=False)
                return text, 1, 0, 1
            self._failed_until.pop(key, None)
            self._cache[key] = result
            while len(self._cache) > 128 or sum(map(len, self._cache.values())) > 2_000_000:
                self._cache.popitem(last=False)
            return result, 1, 0, 0

    def _compress(self, raw: bytes) -> tuple[bytes, CompressionObservation]:
        # Cache accounting and one model's inference stay associated with one request.
        with self._process_lock:
            return self._compress_request(raw)

    def _compress_request(self, raw: bytes) -> tuple[bytes, CompressionObservation]:
        def skip(reason):
            return raw, CompressionObservation('skipped', reason)
        if not raw or len(raw) > _MAX_BODY_BYTES:
            return skip('body_size')
        try:
            body = loads(raw)
        except (ValueError, UnicodeDecodeError, RecursionError):
            return skip('invalid_json')
        if not isinstance(body, dict):
            return skip('unsupported_input')
        if any(body.get(k) is not None for k in ('previous_response_id', 'conversation', 'prompt')):
            return skip('server_managed_context')
        if isinstance(body.get('messages'), list):
            slots = list(chat_text_slots(body))
        elif isinstance(body.get('input'), (str, list)):
            slots = list(_text_slots(body))
        else:
            return skip('unsupported_input')
        count, source = (self.token_counter, 'custom-tokenizer-est') if self.token_counter else default_token_counter(str(body.get('model','')))
        full_before = count(dumps(body))
        before = after = changed = calls = hits = rejected = lossy = 0
        call_records = []
        roles: set[str] = set()
        codec = StructuralCompressor(count)
        task = task_from_body(body)
        # A delta is only proposed for repeated calls to the same named tool with
        # identical arguments. Calls and their arguments themselves stay exact.
        families = {}
        items = body.get('messages', body.get('input', []))
        if isinstance(items, list):
            for item in items:
                if not isinstance(item, dict):
                    continue
                if item.get('type') == 'function_call':
                    families[item.get('call_id')] = dumps([item.get('name'), item.get('arguments')])
                elif item.get('type') == 'custom_tool_call':
                    families[item.get('call_id')] = dumps([item.get('name'), item.get('input')])
                for call in item.get('tool_calls', []) if isinstance(item.get('tool_calls'), list) else []:
                    if isinstance(call, dict):
                        families[call.get('id')] = dumps(call.get('function'))
        ids = [container.get('call_id', container.get('tool_call_id')) for container, _, role in slots if role == 'tool_output']
        for container, key, role in slots:
            original = container[key]
            n = count(original)
            field_lossy = False
            call_id = container.get('call_id', container.get('tool_call_id'))
            if not isinstance(call_id, str) or ids.count(call_id) != 1:
                call_id = None

            def process(text):
                nonlocal calls, hits, rejected, field_lossy
                candidate = codec.compress(text, call_id=call_id, family=families.get(call_id, ''))
                # Structured data is always handled losslessly. Do not let a
                # text selector turn JSON types/enum values into prose.
                if text.lstrip().startswith(('{', '[')) or '$lingmou' in candidate:
                    return candidate
                if self.source_store is None or calls >= 4:
                    return candidate
                if self.selector is not None:
                    cache_key = hashlib.sha256((task + '\0' + text).encode()).hexdigest()
                    if cache_key in self._selection_cache:
                        selected = self._selection_cache[cache_key]
                        self._selection_cache.move_to_end(cache_key)
                        hits += 1
                    elif self._failed_until.get(cache_key, 0) > time.monotonic():
                        selected = text
                        hits += 1
                    else:
                        try:
                            selected, records = extract_source(text, task, self.selector, self.source_store)
                            call_records.extend(records)
                            calls += len(records)
                            if any(r.get('status') != 'completed' for r in records):
                                rejected += 1
                                self._failed_until[cache_key] = time.monotonic() + 300
                                while len(self._failed_until) > 128:
                                    self._failed_until.popitem(last=False)
                        except Exception:
                            selected = text
                            rejected += 1
                        if selected != text:
                            self._selection_cache[cache_key] = selected
                            while len(self._selection_cache) > 128 or sum(map(len, self._selection_cache.values())) > 2_000_000:
                                self._selection_cache.popitem(last=False)
                    if count(selected) < count(candidate) and len(selected) < len(candidate):
                        field_lossy = True
                        return selected
                elif self.rewriter is not None and n >= 120 and len(text) <= 100_000:
                    # LLMLingua-2 acts on masked reference prose only. A source
                    # remains available for reread; code/conditions stay exact.
                    rewritten, used, hit, bad = self._rewrite(text)
                    calls += used; hits += hit; rejected += bad
                    if rewritten != text:
                        source_id = self.source_store.put(text)
                        selected = dumps({'$lingmou': 'lossy/v1', 'source_id': source_id,
                            'read_more': 'lingmou_source_read(source_id,start_line,end_line)', 'text': rewritten})
                        if count(selected) < count(candidate) and len(selected) < len(candidate):
                            field_lossy = True
                            return selected
                return candidate

            candidate = transform_data(original, role, process)
            m = count(candidate)
            before += n
            if candidate.strip() and m < n and len(candidate) < len(original):
                container[key] = candidate
                changed += 1; roles.add(role); after += m; lossy += int(field_lossy)
                if field_lossy and call_id:
                    codec.bases.pop(call_id, None)
                    codec.latest = {k: v for k, v in codec.latest.items() if v != call_id}
                    codec.duplicates = {k: v for k, v in codec.duplicates.items() if v != call_id}
            else:
                after += n
        output = dumps(body).encode()
        full_after = count(output.decode())
        if full_after >= full_before:
            output, changed, after, roles, lossy, full_after = raw, 0, before, set(), 0, full_before
        ob = CompressionObservation(status='compressed' if changed else 'skipped',
            reason='data_regions_only' if changed else 'no_savings', text_tokens_before_estimate=before,
            text_tokens_after_estimate=after, changed_fields=changed, changed_roles=tuple(sorted(roles)),
            tokenizer_source=source, compression_model_calls=len(call_records), cache_hits=hits, rejected_fields=rejected,
            full_request_tokens_before_estimate=full_before, full_request_tokens_after_estimate=full_after,
            compression_calls=tuple(call_records), local_model_calls=calls - len(call_records), lossy_fields=lossy)
        return (output if changed else raw), ob


COMPRESSION_MODES = ('off', 'caveman', 'hybrid', 'structure', 'extract', 'jev', 'kimi', 'llmlingua2')


def make_input_compressor(mode: str, *, source_store: SourceStore | None = None) -> ResponsesInputCompressor | None:
    if mode == 'off':
        return None
    if mode == 'caveman':
        return ResponsesInputCompressor()
    if mode in {'hybrid', 'structure'}:
        return HybridInputCompressor(mode=mode)
    if mode in {'extract', 'jev', 'kimi'}:
        from .reference_selection import LexicalSelector, JevSelector, KimiSelector
        selector = {'extract': LexicalSelector, 'jev': JevSelector, 'kimi': KimiSelector}[mode]()
        return HybridInputCompressor(selector=selector, source_store=source_store, mode=mode)
    if mode == 'llmlingua2':
        from .llmlingua_compression import LLMLingua2Rewriter
        return HybridInputCompressor(rewriter=LLMLingua2Rewriter(), source_store=source_store, mode=mode)
    raise ValueError('Unknown input compression mode')
