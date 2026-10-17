"""Authenticated loopback compression offload, normally reached over SSH.

The worker receives request bodies, never the upstream Authorization header.
Referenced originals are imported before a rewritten request can be forwarded.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import fields, replace
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from .input_compression import CompressionObservation


class CompressionWorkerClient:
    def __init__(self, config):
        url = config.get('url', '').rstrip('/')
        parsed = urlsplit(url)
        if (parsed.scheme != 'http' or parsed.hostname not in {'127.0.0.1', '::1', 'localhost'}
                or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment):
            raise ValueError('Compression worker must use an explicit loopback HTTP endpoint')
        token, namespace = config.get('token'), config.get('namespace')
        if not isinstance(token, str) or len(token) < 32 or not isinstance(namespace, str) or not namespace:
            raise ValueError('Worker token and namespace are required')
        self.url, self.token, self.namespace = url, token, namespace

    @classmethod
    def from_file(cls, path: Path):
        if not path.is_file():
            return None
        return cls(json.loads(path.read_text(encoding='utf-8-sig')))

    def compress(self, raw, store):
        known = [p.stem for p in store.root.glob('*.txt')] if store.root else list(store._memory)
        observation = None
        try:
            with httpx.Client(timeout=httpx.Timeout(150, connect=3), trust_env=False,
                              follow_redirects=False) as client:
                response = client.post(self.url + '/compress',
                    headers={'Authorization': 'Bearer ' + self.token},
                    json={'request_id': uuid.uuid4().hex, 'namespace': self.namespace,
                          'body': raw.decode('utf-8'), 'known_sources': known})
                response.raise_for_status()
                value = response.json()
            allowed = {f.name for f in fields(CompressionObservation)}
            observation = CompressionObservation(**{k: v for k, v in value['observation'].items() if k in allowed})
            output = value['body'].encode('utf-8')
            # Persist originals first. A broken reference must never reach Codex.
            for source_id, text in value.get('sources', {}).items():
                if hashlib.sha256(text.encode('utf-8')).hexdigest() != source_id or store.put(text) != source_id:
                    raise ValueError('Worker source digest mismatch')
            return output, observation
        except Exception:
            if observation is not None:
                return raw, replace(observation, status='error', reason='worker_source_import_failed',
                    changed_fields=0, changed_roles=(), lossy_fields=0,
                    full_request_tokens_after_estimate=observation.full_request_tokens_before_estimate)
            return raw, CompressionObservation('error', 'compression_worker_unavailable')
