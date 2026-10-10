"""Conservative context compaction plus optional, guarded Kimi rewriting.

Inspired by Caveman's terse prose and GenericAgent's redundant-context removal.
No FIFO eviction: recent goals and tool protocol objects remain in the request.
This is lossy prose rewriting, not a semantic-equivalence guarantee.
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

    def __init__(self, *, rewriter: Callable[[str], str] | None = None, **kwargs):
        super().__init__(**kwargs)
        self.rewriter = rewriter
        self._stats['mode'] = 'kimi' if rewriter else 'hybrid'
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
        def skip(reason):
            return raw, CompressionObservation('skipped', reason)
        if not raw or len(raw) > _MAX_BODY_BYTES:
            return skip('body_size')
        try:
            body = json.loads(raw, object_pairs_hook=_unique_object)
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
        before = after = changed = calls = hits = rejected = 0
        roles: set[str] = set()
        # Replace older, identical tool results with explicit references to the retained result.
        latest: dict[str, tuple[int, str]] = {}
        for i, (container, key, role) in enumerate(slots):
            call_id = container.get('call_id', container.get('tool_call_id'))
            if role == 'tool_output' and len(container[key]) >= 512 and isinstance(call_id, str) and call_id:
                latest[container[key]] = (i, call_id)
        # Spend the bounded LLM-call allowance on task material before fixed
        # system/developer scaffolding. JSON message order is never changed.
        ordered_slots = sorted(enumerate(slots), key=lambda entry:
            {'tool_output': 0, 'user': 1, 'assistant': 2}.get(entry[1][2], 3))
        for i, (container, key, role) in ordered_slots:
            original = container[key]
            n = count(original)
            candidate = original
            duplicate = role == 'tool_output' and original in latest and latest[original][0] != i
            if duplicate:
                retained_id = json.dumps(latest[original][1], ensure_ascii=False)
                candidate = f'[Exact duplicate tool result; identical data is retained in the later result for tool call {retained_id}.]'
            else:
                try:
                    structured = json.loads(original, object_pairs_hook=_unique_object)
                except (ValueError, RecursionError):
                    # Invalid/duplicate-key JSON may be meaningful tool data.
                    if not original.lstrip().startswith(('{', '[')):
                        masked, protected = protect_text(original)
                        candidate = (restore_text(compress_prose(masked), protected) or original) if masked else original
                        if self.rewriter and n >= 120 and len(original) <= 100_000 and calls < 4:
                            candidate, used, hit, bad = self._rewrite(original)
                            calls += used; hits += hit; rejected += bad
                else:
                    if role == 'tool_output':
                        # Remove JSON whitespace only: preserve decimal literals,
                        # escape sequences and ordering byte-for-byte.
                        candidate = re.sub(r'"(?:\\.|[^"\\])*"|\s+',
                            lambda match: match[0] if match[0].startswith('"') else '', original)
            m = count(candidate)
            before += n
            if candidate.strip() and m < n and len(candidate) < len(original):
                container[key] = candidate
                changed += 1; roles.add(role); after += m
            else:
                after += n
        ob = CompressionObservation(status='compressed' if changed else 'skipped',
            reason='shorter_text' if changed else 'no_savings', text_tokens_before_estimate=before,
            text_tokens_after_estimate=after, changed_fields=changed, changed_roles=tuple(sorted(roles)),
            tokenizer_source=source, compression_model_calls=calls, cache_hits=hits, rejected_fields=rejected)
        return (json.dumps(body, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode() if changed else raw), ob


def make_input_compressor(mode: str) -> ResponsesInputCompressor | None:
    if mode == 'off':
        return None
    if mode == 'caveman':
        return ResponsesInputCompressor()
    if mode == 'hybrid':
        return HybridInputCompressor()
    if mode == 'kimi':
        from .compression_models import KimiTextRewriter
        return HybridInputCompressor(rewriter=KimiTextRewriter())
    raise ValueError('Unknown input compression mode')
