"""Per-request numeric estimates and authoritative provider usage, kept separate."""
from __future__ import annotations

import threading
from typing import Callable

from .compression_models import normalize_usage


class RequestUsageLedger:
    def __init__(self, *, on_record: Callable[[dict], None] | None = None):
        self._lock = threading.Lock()
        self.records: list[dict] = []
        self.totals = {'requests': 0, 'requests_with_official_usage': 0,
                       'official_input_tokens': 0, 'official_output_tokens': 0,
                       'official_total_tokens': 0}
        self.on_record = on_record

    def append(self, record: dict) -> None:
        with self._lock:
            self.records.append(record)
            self.records = self.records[-200:]
            self.totals['requests'] += 1
            if usage := record.get('official_usage'):
                self.totals['requests_with_official_usage'] += 1
                for key in ('input_tokens', 'output_tokens', 'total_tokens'):
                    self.totals['official_' + key] += usage[key]
        if self.on_record:
            try:
                self.on_record(dict(record))
            except Exception:
                pass

    def snapshot(self) -> dict:
        with self._lock:
            return {'totals': dict(self.totals), 'recent_requests': list(self.records),
                    'recent_request_limit': 200}


def provider_usage(data: dict) -> tuple[dict | None, str | None]:
    response = data.get('response')
    if isinstance(response, dict):
        return normalize_usage(response.get('usage')), response.get('model')
    return normalize_usage(data.get('usage')), data.get('model')
