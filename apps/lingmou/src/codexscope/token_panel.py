"""Content-free usage projection for the product UI; estimates never become usage."""
from __future__ import annotations

from pathlib import Path

from .component_usage import COMPONENTS
from .storage import json_load


def _read(path: Path) -> dict:
    try:
        value = json_load(path)
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def _number(value):
    return value if type(value) in (int, float) and 0 <= value < 10**15 else None


def _component_rows(measurement: dict, *, latest=False, full=False):
    indexed = {row['id']: row for row in measurement.get('components', []) if row.get('id') in COMPONENTS}
    rows = []
    for key, (label, protected) in COMPONENTS.items():
        if full and key not in {'output_format', 'other'}:
            protected = False
        source = indexed.get(key, {})
        before, after = _number(source.get('before')), _number(source.get('after'))
        rows.append({'id': key, 'label': label, 'protected': protected,
                     'before': before, 'after': after,
                     'saved': before - after if before is not None and after is not None else None,
                     'requests': int(bool(source)) if latest else source.get('requests', 0),
                     'compressed_requests': int(before > after) if latest and before is not None and after is not None else source.get('compressed_requests', 0)})
    return rows


def _tool_rows(measurement: dict):
    rows = []
    for source in measurement.get('tools', []):
        before, after = _number(source.get('before')), _number(source.get('after'))
        rows.append({'name': str(source.get('name', 'unknown'))[:128],
                     'before': before, 'after': after,
                     'saved': before - after if before is not None and after is not None else None,
                     **{part + '_' + stage: _number(source.get(part + '_' + stage))
                        for part in ('definition', 'call', 'result') for stage in ('before', 'after')}})
    return sorted(rows, key=lambda row: (-(row['saved'] or 0), -(row['before'] or 0), row['name']))


def token_panel_snapshot(run_dir: Path, *, provider_snapshot: dict | None = None,
                         allow_usage_fallback: bool = True) -> dict:
    live = _read(run_dir / 'live_status.json')
    manifest = _read(run_dir / 'manifest.json')
    tap = live.get('request_token_tap') or manifest.get('request_token_tap') or {}
    # WorkBuddy owns the same relay in-process and supplies its current counters.
    if provider_snapshot is not None:
        tap = provider_snapshot
    stats = tap.get('input_compression') or {}
    components = tap.get('component_usage') or {}
    # Prefer actual sent requests over attempted compressor calls (e.g. fail-open).
    if components.get('requests') and 'request_before' in components:
        stats = {**stats, 'requests': components['requests'],
                 'compressed_requests': components.get('compressed_requests', 0),
                 'full_request_tokens_before_estimate': components['request_before'],
                 'full_request_tokens_after_estimate': components['request_after']}
    ledger = tap.get('usage_ledger') or {}
    tasks = list((ledger.get('tasks') or {}).values())
    totals = ledger.get('totals') or {}
    requests = totals.get('requests', 0)
    measured = totals.get('requests_with_official_usage', 0)
    compression_calls = sum((t.get('compression') or {}).get('calls', 0) for t in tasks)
    measured_compression = sum((t.get('compression') or {}).get('calls_with_usage', 0) for t in tasks)
    compression_tokens = sum((t.get('compression') or {}).get('total_tokens', 0) for t in tasks)
    cache_complete = bool(measured and tasks) and all((t.get('downstream') or {}).get('cached_input_tokens') is not None for t in tasks)
    official = {
        'source': 'request_usage' if measured else 'unavailable',
        'input_tokens': totals.get('official_input_tokens') if measured else None,
        'output_tokens': totals.get('official_output_tokens') if measured else None,
        'total_tokens': totals.get('official_total_tokens') if measured else None,
        'cached_input_tokens': sum((t.get('downstream') or {}).get('cached_input_tokens', 0) for t in tasks) if cache_complete else None,
        'compression_tokens': compression_tokens if compression_calls == measured_compression else None,
        'known_compression_tokens': compression_tokens,
        'missing_compression_calls': compression_calls - measured_compression,
        'measured_requests': measured, 'missing_requests': requests - measured,
        'complete': bool(requests) and requests == measured and compression_calls == measured_compression,
    }
    if not requests and allow_usage_fallback:
        usage = live.get('token_usage') or manifest.get('last_token_usage') or _read(run_dir / 'workbench_token_usage.json')
        total = usage.get('total') or {}
        if total:
            def get(snake, camel):
                return _number(total.get(snake, total.get(camel)))
            official.update(source='app_server', input_tokens=get('input_tokens', 'inputTokens'),
                output_tokens=get('output_tokens', 'outputTokens'), total_tokens=get('total_tokens', 'totalTokens'),
                cached_input_tokens=get('cached_input_tokens', 'cachedInputTokens'), complete=False)
    before = _number(stats.get('full_request_tokens_before_estimate'))
    after = _number(stats.get('full_request_tokens_after_estimate'))
    if not stats.get('requests'):
        before = after = None
    saved = max(0, before - after) if before is not None and after is not None else None
    mode = stats.get('mode') or tap.get('input_compression_mode') or 'off'
    settings = _read(run_dir / 'compression_settings.json')
    requested_mode = settings.get('mode', mode)
    # The legacy CLI name selects the same engine as structure in the UI.
    mode = 'structure' if mode == 'hybrid' else mode
    requested_mode = 'structure' if requested_mode == 'hybrid' else requested_mode
    recent = []
    for row in (ledger.get('recent_requests') or [])[-20:]:
        compression = row.get('compression') or {}
        sent = row.get('component_usage') or {}
        usage = row.get('official_usage') or {}
        recent.append({
            'request_id': str(row.get('request_id', ''))[:128],
            'status': str(row.get('status', 'unknown'))[:32],
            'before': _number(sent.get('request_before', compression.get('full_request_tokens_before_estimate', row.get('input_tokens_before_estimate')))),
            'after': _number(sent.get('request_after', compression.get('full_request_tokens_after_estimate', row.get('input_tokens_after_estimate')))),
            'official_input': _number(usage.get('input_tokens')),
            'official_output': _number(usage.get('output_tokens')),
        })
    inflight = live.get('inflight_token_estimate') or {}
    latest = components.get('latest') or {}
    relay_enabled = bool(tap.get('running', tap.get('enabled', False)))
    return {
        'schema_version': 'lingmou.token-panel.v2',
        'relay_enabled': relay_enabled,
        'capture_state': 'live' if relay_enabled else 'finished' if components.get('requests') or requests or stats.get('requests') else 'not_connected',
        'configurable': bool(tap.get('configurable', False)),
        'mode': mode, 'requested_mode': requested_mode,
        'local': {'before': before, 'after': after, 'saved': saved,
            'savings_percent': round(100 * saved / before, 1) if before and saved is not None else None,
            'requests': stats.get('requests', 0), 'compressed_requests': stats.get('compressed_requests', 0),
            'current_input': _number(inflight.get('input_tokens_estimated')) if inflight.get('active') else None,
            'current_input_quality': inflight.get('input_quality', 'estimated')},
        'official': official, 'recent_requests': recent,
        'methods': stats.get('methods', []),
        'processing': bool(stats.get('processing', False)),
        'output': {**stats.get('output', {}), 'source': 'post_generation', 'billing_reduction': False},
        'breakdown': {
            'source': 'outbound_request' if components.get('requests') else 'unavailable',
            'requests': components.get('requests', 0),
            'incomplete_requests': components.get('incomplete_requests', 0),
            'components': _component_rows(components, full=mode == 'full'), 'tools': _tool_rows(components),
            'latest': {'request_id': latest.get('request_id'), 'tokenizer': latest.get('tokenizer'),
                       'complete': latest.get('complete', False),
                       'components': _component_rows(latest, latest=True, full=mode == 'full'), 'tools': _tool_rows(latest)},
        },
    }
