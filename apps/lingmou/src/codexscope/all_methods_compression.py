"""Opt-in worker rewrite comparison. Every candidate starts from the original.

Only validated winners enter the request; model work is bounded and reusable.
The default desktop pipeline remains unchanged without a configured worker.
"""
from __future__ import annotations

import re
import time
from dataclasses import replace

from .context_compression import restore_text
from .full_compression import FullCompressionPipeline, protect_text, _MARKERS
from .input_compression import compress_prose
from token_compression.backends import protected_rewrite


def restore_candidate(candidate, protected):
    # Token deletion can join a forced marker directly to a neighbouring word.
    # Restore word boundaries before literal and semantic validation.
    candidate = re.sub(r'(?<=\w)(?=⟦KEEP_)|(?<=⟧)(?=\w)', ' ', candidate)
    return restore_text(candidate, protected)


class AllMethodsPipeline(FullCompressionPipeline):
    max_new_segments = 1
    max_segment_tokens = 1200

    def _verification_pair(self, original, candidate, role, task):
        pair = super()._verification_pair(original, candidate, role, task)
        if pair is not None:
            # Reformatting sentences can change the masker's allocation order.
            # Align IDs by verified source order in one substitution pass.
            before = protect_text(original)[1]
            after = protect_text(candidate)[1]
            aliases = {new[0]: old[0] for old, new in zip(before, after)}
            pair['short'] = _MARKERS.sub(lambda m: aliases[m[0]], pair['short'])
        return pair

    def compress(self, raw):
        with self._lock:
            self._method_observations = []
            start = time.monotonic()
            output, observation = super().compress(raw)
            return output, replace(observation,
                latency_ms=round((time.monotonic() - start) * 1000, 3),
                method_observations=tuple(self._method_observations))

    def _transform_texts(self, slots, calls, *, task=''):
        pending, cache_hits = {}, 0
        for container, field, role in slots:
            if role == 'user':
                continue
            for piece in self._pieces(container[field], role):
                key = self._cache_key(role, piece, task)
                if key in self._cache:
                    cache_hits += 1
                else:
                    pending.setdefault(key, (piece, role))
        # Recent task material is a better use of token-dropping models than
        # long instruction lists. Instructions only use rules/Kimi + validation.
        pending = sorted(pending.items(), key=lambda row:
            (row[1][1] not in {'tool_output', 'reference'}, -self.count(row[1][0])))
        local_calls, processed, chosen = 0, 0, {}
        deadline = time.monotonic() + 75
        for key, (piece, role) in pending:
            if processed >= self.max_new_segments or time.monotonic() >= deadline:
                break
            masked, protected = protect_text(piece)
            tokens = self.count(piece)
            if (not self.config.max_remote_calls or self._remote_limit <= 0 or not masked
                    or not self.config.min_model_tokens <= tokens <= self.max_segment_tokens
                    or len(_MARKERS.sub('', masked).strip()) < 160):
                continue
            # Reserve headroom for Kimi and at least one semantic judgment.
            if self.count(masked) * 4 + 1024 > self._remote_limit - self._remote_tokens:
                continue
            try:
                self.store.put(piece)
            except (ValueError, OSError):
                continue
            processed += 1
            options = []
            methods = ['caveman']
            if role in {'tool_output', 'reference', 'assistant'}:
                methods += ['llmlingua2', 'caveman_nlp', 'caveman_mlm', 'headroom']
            methods.append('kimi')
            for method in methods:
                record = {'method': method, 'component': role, 'before': tokens,
                          'status': 'started', 'latency_ms': 0}
                self._method_observations.append(record)
                if method == 'caveman_mlm' and len(masked) > 400:
                    record['status'] = 'skipped_length_limit'
                    continue
                if time.monotonic() >= deadline:
                    record['status'] = 'skipped_latency_budget'
                    continue
                started = time.monotonic()
                if method != 'kimi':
                    self._note(method, attempted=1)
                try:
                    if method == 'caveman':
                        candidate = protected_rewrite(piece, lambda value:
                            compress_prose(re.sub(r'[ \t]+', ' ', value)))
                    elif method == 'kimi':
                        rewritten = self._rewrite_batch({key: {'text': masked, 'component': role,
                            'task': task if role in {'tool_output', 'reference'} else ''}}, calls).get(key)
                        candidate = restore_candidate(rewritten, protected) if rewritten is not None else None
                    else:
                        backend = self._backend(method)
                        local_calls += 1
                        candidate = (backend.compress(piece, context=task, question=task or None).compressed
                            if method == 'headroom' else protected_rewrite(piece, backend)
                            if method.startswith('caveman_') else restore_candidate(backend(masked), protected))
                    if candidate is None:
                        record['status'] = 'unavailable_or_budget'
                        continue
                    record['after'] = self.count(candidate)
                    record['saved'] = tokens - record['after']
                    if not self._worthwhile(piece, candidate):
                        record['status'] = 'insufficient_saving'
                        continue
                    pair = self._verification_pair(piece, candidate, role, task)
                    if pair is None:
                        record['status'] = 'rejected_literal_change'
                        self._note(method, rejected=1)
                        continue
                    record['status'] = 'candidate'
                    options.append((candidate, method, pair, record))
                except Exception as exc:
                    record.update(status='unavailable', error_type=type(exc).__name__)
                    self._note(method, unavailable=1)
                finally:
                    record['latency_ms'] = round((time.monotonic() - started) * 1000, 3)
            # Validate shortest first, then try the next candidate if rejected.
            # No extra paid judgments once a shortest valid candidate is known.
            checked = {}
            for candidate, method, pair, record in sorted(options, key=lambda item: self.count(item[0])):
                if key in chosen or time.monotonic() >= deadline:
                    record['status'] = 'not_validated'
                    continue
                if candidate in checked:
                    accepted = checked[candidate]
                else:
                    prior = len(calls)
                    accepted = key in self._verify_batch({key: pair}, calls)
                    if len(calls) == prior and self.verifier is None:
                        record['status'] = 'validation_budget_exhausted'
                        continue
                    checked[candidate] = accepted
                if accepted:
                    record['status'] = 'selected'
                    chosen[key] = candidate, method
                    self._cache[key] = candidate
                else:
                    record['status'] = 'rejected_semantics'
                    self._note(method, rejected=1)
            # Cache completed negative judgments as well as wins. Do not retry
            # an identical rejected instruction on every model request.
            if key not in chosen and checked:
                self._cache[key] = piece
        changed, roles = 0, set()
        for container, field, role in slots:
            if role == 'user':
                continue
            original = container[field]
            candidate = ''.join(self._cache.get(self._cache_key(role, p, task), p)
                                for p in self._pieces(original, role))
            if candidate != original and self.count(candidate) < self.count(original):
                self.store.put(original)
                container[field] = candidate
                changed += 1
                roles.add(role)
                for piece in self._pieces(original, role):
                    key = self._cache_key(role, piece, task)
                    if key in chosen:
                        text, method = chosen[key]
                        self._note(method, accepted=1, saved=self.count(piece) - self.count(text))
        while len(self._cache) > 2048:
            self._cache.popitem(last=False)
        return changed, roles, local_calls, cache_hits
