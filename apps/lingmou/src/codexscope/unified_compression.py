"""Adapt the unified compression engine to Lingmou's measured request relay."""
from __future__ import annotations

import os
import threading
from pathlib import Path

from .input_compression import CompressionObservation, ResponsesInputCompressor
from .reference_selection import SourceStore
from .storage import json_load


UI_MODES = ('off', 'structure', 'extract', 'auto', 'full')


class UnifiedInputCompressor(ResponsesInputCompressor):
    supports_chat_completions = True

    def __init__(self, mode='structure', *, source_store: SourceStore | None = None,
                 settings_path: Path | None = None, full_config=None, **kwargs):
        super().__init__(**kwargs)
        self.mode = mode
        self.source_store = source_store
        self.settings_path = settings_path
        self.full_config = full_config
        self._engine = None
        self._engine_key = None
        self._full_pipeline = None
        self._process_lock = threading.Lock()
        self._stats.update(mode=mode, engine='token_compression.v0.2')

    def stats(self):
        result = super().stats()
        if self._full_pipeline is not None:
            result.update(self._full_pipeline.snapshot())
        return result

    def compress_output(self, text):
        if self._full_pipeline is not None and self.stats().get('mode') == 'full':
            return self._full_pipeline.compress_output(text)
        return None, []

    def _compress(self, raw: bytes):
        from token_compression import CompressionConfig, TokenCompressor
        from .structural_compression import loads

        with self._process_lock:
            mode = self.mode
            if self.settings_path:
                try:
                    settings = json_load(self.settings_path)
                    if isinstance(settings, dict) and settings.get('mode') in UI_MODES:
                        mode = settings['mode']
                except (OSError, ValueError, TypeError):
                    pass
            with self._lock:
                self._stats['mode'] = mode
            # Excerpts must be readable through the registered source MCP tool.
            effective = mode if self.source_store is not None or mode in {'off', 'structure', 'hybrid'} else 'structure'
            try:
                body = loads(raw)
                model = body.get('model', 'gpt-4o') if isinstance(body, dict) else 'gpt-4o'
            except (ValueError, UnicodeError, RecursionError):
                return raw, CompressionObservation('skipped', 'invalid_json')
            key = (effective, model)
            if effective == 'full':
                from .full_compression import FullCompressionPipeline
                if self._full_pipeline is None or self._engine_key != key:
                    self._full_pipeline = FullCompressionPipeline(source_store=self.source_store,
                        token_counter=self.token_counter, model=model, config=self.full_config)
                    self._engine_key = key
                return self._full_pipeline.compress(raw)
            if self._engine_key != key:
                self._engine = TokenCompressor(
                    CompressionConfig(method=effective, model=model,
                        model_path=os.environ.get('LINGMOU_LLMLINGUA_MODEL'),
                        reference_path=os.environ.get('LINGMOU_CAVEMAN_PATH'),
                        mlm_model_path=os.environ.get('LINGMOU_MLM_MODEL'),
                        spacy_model=os.environ.get('LINGMOU_SPACY_MODEL', 'en_core_web_sm')),
                    source_store=self.source_store, token_counter=self.token_counter,
                )
                self._engine_key = key
            output, result = self._engine.compress_bytes(raw)
            if result is None:
                return raw, CompressionObservation('skipped', 'unsupported_input')
            return output, CompressionObservation(
                status='compressed' if result.status == 'compressed' else 'skipped',
                reason='source_tool_unavailable' if effective != mode and mode != 'hybrid' else
                    ','.join(result.issues) or ('disabled' if mode == 'off' else 'data_regions_only' if result.tokens_saved else 'no_savings'),
                full_request_tokens_before_estimate=result.tokens_before,
                full_request_tokens_after_estimate=result.tokens_after,
                changed_fields=result.changed_fields, changed_roles=tuple(result.changed_roles),
                tokenizer_source=result.tokenizer, compression_calls=tuple(result.calls),
                compression_model_calls=len(result.calls), cache_hits=result.cache_hits,
                local_model_calls=max(0, result.backend_attempts - len(result.calls)),
                lossy_fields=int(result.lossy), rejected_fields=len(result.issues),
            )
