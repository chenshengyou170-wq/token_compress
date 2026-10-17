"""Private loopback compression service intended for an SSH reverse tunnel.

Run with ``python -m codexscope.compression_worker --config /private/worker.json``.
Config/keys remain outside the checkout. Logs contain metrics, never payloads.
"""
from __future__ import annotations

import argparse
import hmac
import json
import threading
import time
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .all_methods_compression import AllMethodsPipeline
from .compression_models import KimiClient
from .full_compression import FullCompressionConfig
from .input_compression import _MAX_BODY_BYTES
from .reference_selection import SourceStore


class CompressionWorker:
    def __init__(self, config, *, pipeline=None):
        self.token = config['token']
        self.namespace = config['namespace']
        if not isinstance(self.token, str) or len(self.token) < 32 or not self.namespace:
            raise ValueError('Private worker token and namespace required')
        self.root = Path(config['state_dir'])
        self.root.mkdir(parents=True, mode=0o700, exist_ok=True)
        self.pipeline = pipeline or AllMethodsPipeline(
            source_store=SourceStore(self.root / 'sources'), client=KimiClient(timeout_s=30),
            config=FullCompressionConfig(max_remote_calls=5, max_remote_tokens=16000,
                startup_remote_tokens=6000, output_rewrite=False))
        self.lock = threading.Lock()
        self.requests = 0
        self.last = None

    def compress(self, value):
        if value.get('namespace') != self.namespace:
            raise ValueError('unknown namespace')
        raw = value['body'].encode('utf-8')
        if len(raw) > _MAX_BODY_BYTES:
            raise ValueError('request too large')
        known = value.get('known_sources', [])
        if not isinstance(known, list) or len(known) > 10000:
            raise ValueError('invalid source inventory')
        known = set(known)
        with self.lock:
            output, observation = self.pipeline.compress(raw)
            store = self.pipeline.store
            identities = [p.stem for p in store.root.glob('*.txt')] if store.root else list(store._memory)
            sources = {identity: store.get(identity) for identity in identities if identity not in known}
            self.requests += 1
            self.last = {'sequence': self.requests, 'timestamp': time.time(),
                         'request_id': value.get('request_id'), 'observation': asdict(observation),
                         'stages': self.pipeline.snapshot()['stages'], 'source_count': len(sources)}
            with (self.root / 'metrics.jsonl').open('a', encoding='utf-8') as stream:
                stream.write(json.dumps(self.last, ensure_ascii=False) + '\n')
            return {'body': output.decode('utf-8'), 'observation': asdict(observation), 'sources': sources}


def create_server(worker, port=0):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, status, value):
            raw = json.dumps(value, ensure_ascii=False).encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def authorized(self):
            return hmac.compare_digest(self.headers.get('Authorization', ''), 'Bearer ' + worker.token)

        def do_GET(self):
            if not self.authorized():
                return self.reply(401, {'error': 'unauthorized'})
            if self.path != '/status':
                return self.reply(404, {'error': 'not_found'})
            self.reply(200, {'requests': worker.requests, 'last': worker.last,
                             'pipeline': worker.pipeline.snapshot()})

        def do_POST(self):
            if not self.authorized():
                return self.reply(401, {'error': 'unauthorized'})
            if self.path != '/compress':
                return self.reply(404, {'error': 'not_found'})
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= _MAX_BODY_BYTES * 2 + 1024 * 1024:
                    return self.reply(413, {'error': 'body_limit'})
                self.connection.settimeout(15)
                value = json.loads(self.rfile.read(length))
                result = worker.compress(value)
            except (ValueError, KeyError, TypeError):
                return self.reply(400, {'error': 'invalid_request'})
            except Exception:
                return self.reply(500, {'error': 'compression_failed'})
            self.reply(200, result)
    server = ThreadingHTTPServer(('127.0.0.1', port), Handler)
    server.daemon_threads = True
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_text(encoding='utf-8'))
    worker = CompressionWorker(config)
    if config.get('preload', True):
        for method in ('llmlingua2', 'caveman_nlp', 'caveman_mlm', 'headroom'):
            worker.pipeline._backend(method)
    with create_server(worker, config.get('port', 47831)) as server:
        print(json.dumps({'status': 'ready', 'port': server.server_port}), flush=True)
        server.serve_forever()


if __name__ == '__main__':
    main()
