"""Per-request numeric estimates and authoritative provider usage, kept separate."""
from __future__ import annotations

import threading
import copy
import re
import json
import hashlib
from collections import OrderedDict
from typing import Callable

from .compression_models import normalize_usage

ACCOUNTING_HEADERS = {'x-lingmou-task-id', 'x-lingmou-purpose', 'x-lingmou-attempt'}


def request_accounting(headers) -> dict:
    """Optional host labels are metadata only and are stripped before forwarding."""
    task = headers.get('X-Lingmou-Task-Id', '')
    purpose = headers.get('X-Lingmou-Purpose', '')
    attempt = headers.get('X-Lingmou-Attempt', '')
    labelled = bool(re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', task)
                    and purpose in {'generation', 'reread', 'retry'}
                    and re.fullmatch(r'[1-9][0-9]{0,3}', attempt))
    return {'task_id': task if labelled else 'run', 'purpose': purpose if labelled else 'unclassified',
            'attempt': int(attempt) if labelled else 1, 'accounting_labelled': labelled}


def _codex_metadata(headers, body: dict) -> dict:
    metadata = body.get('client_metadata')
    metadata = metadata if isinstance(metadata, dict) else {}
    encoded = metadata.get('x-codex-turn-metadata', headers.get('x-codex-turn-metadata', ''))
    if isinstance(encoded, str) and len(encoded) < 100_000:
        try:
            nested = json.loads(encoded)
            if isinstance(nested, dict):
                metadata = {**metadata, **nested}
        except ValueError:
            pass
    return metadata


def _identity(value) -> str | None:
    return value if isinstance(value, str) and 0 < len(value) <= 128 else None


def _conversation_accounting(headers, body: dict, metadata: dict) -> dict:
    thread = _identity(metadata.get('thread_id')) or _identity(metadata.get('session_id'))
    parent = _identity(metadata.get('parent_thread_id', metadata.get('x-codex-parent-thread-id')))
    subagent = metadata.get('subagent_kind') or metadata.get('x-openai-subagent') or headers.get('x-openai-subagent')
    kind = metadata.get('request_kind', 'turn')
    kind = kind if kind in ('turn', 'prewarm', 'compaction', 'memory') else 'unknown'
    if body.get('generate') is False:
        kind = 'prewarm'
    # Forked conversations use their own thread, never forked_from_thread_id.
    # Child agents may contribute to their parent but cannot select the UI scope.
    owner = parent or thread
    turn = _identity(metadata.get('turn_id'))
    started = metadata.get('turn_started_at_unix_ms')
    return {
        'conversation_id': 'codex-' + hashlib.sha256(owner.encode()).hexdigest()[:32] if owner else None,
        'conversation_turn_id': hashlib.sha256((thread + ':' + turn).encode()).hexdigest()[:32] if thread and turn else None,
        'conversation_foreground': bool(thread and turn
                                        and kind == 'turn' and not subagent and not parent
                                        and metadata.get('thread_source') in (None, 'user')),
        'request_kind': kind,
        'turn_started_at_unix_ms': started if type(started) is int and started >= 0 else None,
    }


class RequestAccountingTracker:
    """Correlate Codex turns without storing task content or routing tokens.

    Host-supplied labels take precedence. Repeated request bodies are explicitly
    labelled an inference, since a caller may deliberately replay a request.
    """
    def __init__(self):
        self._attempts: OrderedDict[tuple[str, str], int] = OrderedDict()
        self._lock = threading.Lock()

    def observe(self, headers, body: dict) -> dict:
        metadata = _codex_metadata(headers, body)
        result = {**request_accounting(headers), **_conversation_accounting(headers, body, metadata)}
        if result['accounting_labelled']:
            return {**result, 'task_source': 'host', 'attempt_source': 'host', 'purpose_source': 'host'}
        turn, thread = metadata.get('turn_id'), metadata.get('thread_id', metadata.get('session_id'))
        if all(isinstance(v, str) and 0 < len(v) <= 128 for v in (turn, thread)):
            result.update(task_id='codex-' + hashlib.sha256((thread + ':' + turn).encode()).hexdigest()[:32],
                          task_source='codex_turn_metadata', accounting_labelled=True)
        else:
            result['task_source'] = 'unattributed_run'
        result.update(purpose='generation', purpose_source='request', attempt_source='repeated_body_inference')
        items = body.get('input', body.get('messages'))
        if isinstance(items, list):
            calls = {}
            code_rereads = set()
            for item in items:
                if not isinstance(item, dict): continue
                if item.get('type') == 'function_call': calls[item.get('call_id')] = item.get('name', '')
                if (item.get('type') == 'custom_tool_call' and item.get('name') in {'exec', 'functions.exec'}
                        and isinstance(item.get('input'), str)
                        and re.search(r'\btools\.(?:[A-Za-z_]\w*__)?lingmou_source_read\s*\(', item['input'])):
                    code_rereads.add(item.get('call_id'))
                for call in item.get('tool_calls', []) if isinstance(item.get('tool_calls'), list) else []:
                    if isinstance(call, dict) and isinstance(call.get('function'), dict):
                        calls[call.get('id')] = call['function'].get('name', '')
            # Only pending tool results at the end indicate the next request is
            # consuming a reread. Older rereads remain history, not new charges.
            for item in reversed(items):
                if not isinstance(item, dict): break
                if item.get('type') not in {'function_call_output', 'custom_tool_call_output'} and item.get('role') != 'tool': break
                call_id = item.get('call_id', item.get('tool_call_id'))
                name = calls.get(call_id, '')
                if isinstance(name, str) and name.endswith('lingmou_source_read'):
                    result.update(purpose='reread', purpose_source='source_tool_result')
                elif call_id in code_rereads:
                    result.update(purpose='reread', purpose_source='code_tool_call_inference')
        stable = {k: v for k, v in body.items() if k != 'client_metadata'}
        fingerprint = hashlib.sha256(json.dumps(stable, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
        key = result['task_id'], fingerprint
        with self._lock:
            attempt = self._attempts.get(key, 0) + 1
            self._attempts[key] = attempt
            self._attempts.move_to_end(key)
            while len(self._attempts) > 1024:
                self._attempts.popitem(last=False)
        result['attempt'] = attempt
        return result


class RequestUsageLedger:
    def __init__(self, *, on_record: Callable[[dict], None] | None = None):
        self._lock = threading.Lock()
        self.records: list[dict] = []
        self.totals = {'requests': 0, 'requests_with_official_usage': 0,
                       'official_input_tokens': 0, 'official_output_tokens': 0,
                       'official_total_tokens': 0}
        self.task_totals: dict[str, dict] = {}
        self.on_record = on_record

    def append(self, record: dict) -> None:
        with self._lock:
            record = copy.deepcopy(record)
            record['official_usage'] = normalize_usage(record.get('official_usage'))
            self.records.append(record)
            self.records = self.records[-200:]
            self.totals['requests'] += 1
            if usage := record.get('official_usage'):
                self.totals['requests_with_official_usage'] += 1
                for key in ('input_tokens', 'output_tokens', 'total_tokens'):
                    self.totals['official_' + key] += usage[key]
            task_id = record.get('task_id', 'run')
            summary = self.task_totals.setdefault(task_id, _empty_task())
            _add_request(summary, record)
        if self.on_record:
            try:
                self.on_record(dict(record))
            except Exception:
                pass

    def snapshot(self) -> dict:
        with self._lock:
            return {'totals': dict(self.totals), 'recent_requests': copy.deepcopy(self.records),
                    'recent_request_limit': 200,
                    'tasks': {key: _finish_task(copy.deepcopy(value)) for key, value in self.task_totals.items()}}


def _empty_usage() -> dict:
    return {'calls': 0, 'calls_with_usage': 0, 'input_tokens': 0, 'output_tokens': 0,
            'total_tokens': 0, 'known_cached_input_tokens': 0, 'calls_with_cache_detail': 0}


def _empty_task() -> dict:
    return {'requests': 0, 'failed_requests': 0, 'local_model_calls': 0,
            'inferred_retry_requests': 0,
            'unlabelled_requests': 0, 'input_tokens_before_estimate': 0, 'input_tokens_after_estimate': 0,
            'downstream': _empty_usage(), 'compression': _empty_usage(),
            'reread': _empty_usage(), 'retry': _empty_usage()}


def _add_usage(bucket: dict, raw) -> None:
    bucket['calls'] += 1
    usage = normalize_usage(raw)
    if usage is None:
        return
    bucket['calls_with_usage'] += 1
    for key in ('input_tokens', 'output_tokens', 'total_tokens'):
        bucket[key] += usage[key]
    if usage['cached_input_tokens'] is not None:
        bucket['known_cached_input_tokens'] += usage['cached_input_tokens']
        bucket['calls_with_cache_detail'] += 1


def _add_request(summary: dict, record: dict) -> None:
    summary['requests'] += 1
    summary['failed_requests'] += int(record.get('status') != 'completed')
    _add_usage(summary['downstream'], record.get('official_usage'))
    purpose = record.get('purpose')
    attempt = record.get('attempt', 1)
    if purpose == 'reread':
        _add_usage(summary['reread'], record.get('official_usage'))
    if purpose == 'retry' or type(attempt) is int and attempt > 1:
        _add_usage(summary['retry'], record.get('official_usage'))
        summary['inferred_retry_requests'] += int(record.get('attempt_source') == 'repeated_body_inference')
    if not record.get('accounting_labelled', False):
        summary['unlabelled_requests'] += 1
    for key in ('input_tokens_before_estimate', 'input_tokens_after_estimate'):
        value = record.get(key)
        if type(value) is int and value >= 0:
            summary[key] += value
    compression = record.get('compression') or {}
    summary['local_model_calls'] += compression.get('local_model_calls', 0)
    for call in compression.get('compression_calls', []):
        _add_usage(summary['compression'], call.get('official_usage'))


def _finish_task(summary: dict, checks: dict[str, bool] | None = None) -> dict:
    for key in ('downstream', 'compression', 'reread', 'retry'):
        bucket = summary[key]
        bucket['usage_complete'] = bucket['calls'] == bucket['calls_with_usage']
        bucket['missing_usage_calls'] = bucket['calls'] - bucket['calls_with_usage']
        bucket['official_total_tokens'] = bucket['total_tokens'] if bucket['usage_complete'] else None
        bucket['cached_input_tokens'] = bucket['known_cached_input_tokens'] if bucket['calls_with_cache_detail'] == bucket['calls'] else None
    complete = summary['requests'] > 0 and all(summary[k]['usage_complete'] for k in ('downstream', 'compression'))
    summary['usage_complete'] = complete
    summary['known_official_total_tokens'] = sum(summary[k]['total_tokens'] for k in ('downstream', 'compression'))
    summary['official_total_tokens'] = summary['known_official_total_tokens'] if complete else None
    summary['checks'] = checks or {}
    summary['quality_passed'] = all(v is True for v in checks.values()) if checks else None
    summary['breakdown_note'] = 'reread/retry are overlapping subsets of downstream; local model inference has no provider token charge; unknown usage is never zero.'
    return summary


def summarize_task(records: list[dict], *, checks: dict[str, bool] | None = None) -> dict:
    if len({r.get('task_id', 'run') for r in records}) > 1:
        raise ValueError('select a single task_id before comparing tasks')
    summary = _empty_task()
    for record in records:
        _add_request(summary, record)
    return _finish_task(summary, checks)


def compare_tasks(baseline: list[dict], candidate: list[dict], *, baseline_checks=None, candidate_checks=None) -> dict:
    before = summarize_task(baseline, checks=baseline_checks)
    after = summarize_task(candidate, checks=candidate_checks)
    complete = before['usage_complete'] and after['usage_complete']
    saved = before['official_total_tokens'] - after['official_total_tokens'] if complete else None
    return {'baseline': before, 'candidate': after,
        'official_net_total_tokens_saved': saved,
        'official_net_savings_percent': round(saved / before['official_total_tokens'] * 100, 3)
            if complete and before['official_total_tokens'] else None,
        'downstream_input_tokens_saved': before['downstream']['input_tokens'] - after['downstream']['input_tokens']
            if before['downstream']['usage_complete'] and after['downstream']['usage_complete'] else None,
        'downstream_output_tokens_growth': after['downstream']['output_tokens'] - before['downstream']['output_tokens']
            if before['downstream']['usage_complete'] and after['downstream']['usage_complete'] else None,
        'verified_task_savings': bool(complete and saved > 0 and before['quality_passed'] is True and after['quality_passed'] is True),
        'scope': 'whole task; all downstream attempts plus remote compression calls; token counts are not prices'}


def provider_usage(data: dict) -> tuple[dict | None, str | None]:
    response = data.get('response')
    if isinstance(response, dict):
        return normalize_usage(response.get('usage')), response.get('model')
    return normalize_usage(data.get('usage')), data.get('model')
