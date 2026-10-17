"""A desktop display window beginning with a foreground Codex request.

Global relay diagnostics remain intact. Only numeric observations from the
selected conversation enter this window; no historical totals are imported.
"""
from __future__ import annotations

import threading
from collections import OrderedDict

from .component_usage import ComponentUsageLedger
from .request_usage_ledger import RequestUsageLedger


class ConversationUsage:
    def __init__(self):
        self._lock = threading.Lock()
        self._epoch = 0
        self._turns: OrderedDict[str, int] = OrderedDict()
        self._latest_turn_time = 0
        self._reset(None, None)

    def _reset(self, identity, started_at):
        self._identity = identity
        self._started_at = started_at
        self._requests = self._active = 0
        self._usage = RequestUsageLedger()
        self._components = ComponentUsageLedger()

    def begin(self, record: dict) -> int | None:
        identity = record.get('conversation_id')
        kind = record.get('request_kind')
        if not identity or kind not in {'turn', 'compaction'}:
            return None
        with self._lock:
            turn = record.get('conversation_turn_id')
            if record.get('conversation_foreground'):
                epoch = self._turns.get(turn)
                if epoch is not None:
                    # Continued tool calls/retries from an old turn cannot
                    # switch the display back after another conversation starts.
                    if epoch != self._epoch:
                        return None
                else:
                    started = record.get('turn_started_at_unix_ms') or 0
                    if identity != self._identity:
                        if started and started < self._latest_turn_time:
                            return None
                        self._epoch += 1
                        self._reset(identity, record.get('started_at'))
                    self._latest_turn_time = max(self._latest_turn_time, started)
                    self._turns[turn] = self._epoch
                    while len(self._turns) > 2048:
                        self._turns.popitem(last=False)
            elif identity != self._identity or self._turns.get(turn, self._epoch) != self._epoch:
                return None
            self._requests += 1
            self._active += 1
            return self._epoch

    def sent(self, epoch: int | None, record: dict) -> None:
        with self._lock:
            if epoch != self._epoch:
                return
            if measurement := record.get('component_usage'):
                self._components.append(record['request_id'], measurement)

    def finish(self, epoch: int | None, record: dict) -> None:
        with self._lock:
            if epoch != self._epoch:
                return
            self._usage.append(record)
            self._active -= 1

    def snapshot(self) -> dict:
        with self._lock:
            return {
                'scope': {'kind': 'conversation', 'id': self._identity,
                          'started': self._identity is not None, 'started_at': self._started_at,
                          'requests': self._requests, 'active_requests': self._active},
                'usage_ledger': self._usage.snapshot(),
                'component_usage': self._components.snapshot(),
            }
