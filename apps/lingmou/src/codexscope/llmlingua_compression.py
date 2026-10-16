"""Optional local LLMLingua-2 baseline. Loading is explicit, offline and lazy."""
from __future__ import annotations

import os
import re
import threading
from pathlib import Path


class LLMLingua2Rewriter:
    def __init__(self, *, model_path: str | None = None, rate: float = 0.6,
                 device: str = 'cpu', engine=None):
        if not 0 < rate < 1:
            raise ValueError('LLMLingua-2 rate must be between zero and one')
        self.model_path = model_path or os.environ.get('LINGMOU_LLMLINGUA_MODEL')
        self.rate, self.device, self.engine = rate, device, engine
        self._lock = threading.Lock()

    def __call__(self, masked: str) -> str:
        markers = re.findall(r'⟦KEEP_\d+⟧', masked)
        if len(markers) > 100:
            raise ValueError('too many protected regions')
        with self._lock:
            if self.engine is None:
                if not self.model_path or not Path(self.model_path).is_dir():
                    raise ValueError('set LINGMOU_LLMLINGUA_MODEL to downloaded LLMLingua-2 weights')
                # Some deployed Python builds omit the sqlite extension. NLTK
                # imports it even for token classification; use our existing
                # packaged compatibility driver only on those builds.
                try:
                    import sqlite3  # noqa: F401
                except ModuleNotFoundError as exc:
                    if exc.name != '_sqlite3':
                        raise
                    import sys
                    import pysqlite3
                    sys.modules['sqlite3'] = pysqlite3
                from llmlingua import PromptCompressor
                self.engine = PromptCompressor(model_name=self.model_path, device_map=self.device,
                    use_llmlingua2=True, model_config={'local_files_only': True, 'trust_remote_code': False})
            result = self.engine.compress_prompt(masked, rate=self.rate,
                force_tokens=markers + ['\n'] if len(markers) < 100 else markers,
                drop_consecutive=False, use_context_level_filter=False)
        value = result['compressed_prompt']
        if not isinstance(value, str):
            raise ValueError('invalid LLMLingua-2 result')
        return value
