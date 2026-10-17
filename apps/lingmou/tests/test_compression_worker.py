import hashlib
import json
import threading
from types import SimpleNamespace

import httpx
import pytest

from codexscope.all_methods_compression import AllMethodsPipeline, restore_candidate
from codexscope.compression_worker import CompressionWorker, create_server
from codexscope.compression_worker_client import CompressionWorkerClient
from codexscope.desktop_companion import DesktopCompressor
from codexscope.full_compression import FullCompressionConfig
from codexscope.input_compression import CompressionObservation
from codexscope.reference_selection import SourceStore


LONG = ('The purpose of this report is to describe the available inventory in detail. '
        'Inventory contains widgets, which need to be counted before dispatch. ' * 2)
SHORT = 'Count inventory widgets before dispatch.'


def make_pipeline(**kwargs):
    class Kimi:
        def chat(self, messages, **kwargs):
            return {'text': json.dumps({k: SHORT for k in json.loads(messages[-1]['content'])}),
                    'finish_reason': 'stop', 'model': 'fake',
                    'usage': {'input_tokens': 20, 'output_tokens': 10, 'total_tokens': 30}}
    return AllMethodsPipeline(source_store=SourceStore(), token_counter=len,
        client=Kimi(), verifier=kwargs.pop('verifier', lambda pairs, calls: set(pairs)),
        local_backends=kwargs.pop('local_backends', {}),
        config=FullCompressionConfig(min_model_tokens=50, min_saved_tokens=20,
            max_remote_tokens=100000, allow_unfunded_remote=True), **kwargs)


def test_candidates_start_from_original_reject_loss_and_reuse_winner():
    seen = []
    def neural(text):
        seen.append(text)
        return 'dispatch'  # Drops a prerequisite.
    pipeline = make_pipeline(local_backends={
        'llmlingua2': neural, 'caveman_nlp': neural, 'caveman_mlm': neural,
        'headroom': SimpleNamespace(compress=lambda text, **kw: SimpleNamespace(compressed=text))},
        verifier=lambda pairs, calls: {k for k, p in pairs.items() if p['short'] == SHORT})
    raw = json.dumps({'input': [{'role': 'assistant', 'content': LONG}]}).encode()
    output, obs = pipeline.compress(raw)
    assert json.loads(output)['input'][0]['content'] == SHORT
    assert seen and all(text == LONG for text in seen)
    assert {r['method'] for r in obs.method_observations} == {
        'caveman', 'llmlingua2', 'caveman_nlp', 'caveman_mlm', 'headroom', 'kimi'}
    assert any(r['status'] == 'rejected_semantics' for r in obs.method_observations)
    assert next(r for r in obs.method_observations if r['method'] == 'kimi')['status'] == 'selected'
    second, cached = pipeline.compress(raw)
    assert second == output and cached.cache_hits == 1
    assert cached.compression_model_calls == cached.local_model_calls == 0


def test_user_and_execution_literals_never_enter_rewrite():
    pipeline = make_pipeline()
    body = {'input': [{'role': 'user', 'content': LONG},
        {'type': 'function_call', 'call_id': 'c1', 'name': 'dispatch', 'arguments': '{"ok":false}'}]}
    out, obs = pipeline.compress(json.dumps(body).encode())
    assert json.loads(out) == body and not obs.method_observations


def test_http_auth_and_imported_originals_are_readable(tmp_path):
    pipeline = make_pipeline()
    worker = CompressionWorker({'token': 'a' * 40, 'namespace': 'windows', 'state_dir': str(tmp_path)}, pipeline=pipeline)
    server = create_server(worker)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f'http://127.0.0.1:{server.server_port}'
    client = CompressionWorkerClient({'url': url, 'token': 'a' * 40, 'namespace': 'windows'})
    try:
        assert httpx.get(url + '/status', trust_env=False).status_code == 401
        assert httpx.post(url + '/compress', json={}, trust_env=False).status_code == 401
        raw = json.dumps({'instructions': LONG}).encode()
        store = SourceStore(tmp_path / 'windows_sources')
        out, obs = client.compress(raw, store)
        assert json.loads(out)['instructions'] == SHORT
        assert obs.compression_model_calls == 1
        assert store.read(hashlib.sha256(LONG.encode()).hexdigest())['text'] == LONG
        assert LONG not in (tmp_path / 'metrics.jsonl').read_text()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_source_quota_failure_forwards_original_and_keeps_incurred_cost(tmp_path):
    pipeline = make_pipeline()
    worker = CompressionWorker({'token': 'a' * 40, 'namespace': 'windows', 'state_dir': str(tmp_path)}, pipeline=pipeline)
    server = create_server(worker)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = CompressionWorkerClient({'url': f'http://127.0.0.1:{server.server_port}',
                                         'token': 'a' * 40, 'namespace': 'windows'})
        raw = json.dumps({'instructions': LONG}).encode()
        out, obs = client.compress(raw, SourceStore(max_bytes=1))
        assert out == raw and obs.reason == 'worker_source_import_failed'
        assert obs.compression_calls[0]['official_usage']['total_tokens'] == 30
        assert obs.full_request_tokens_before_estimate == obs.full_request_tokens_after_estimate
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize('remote,reader,mode,expected', [
    (True, True, 'full', True), (False, True, 'full', False),
    (True, False, 'full', False), (True, True, 'structure', False)])
def test_desktop_requires_opt_in_and_source_reader(remote, reader, mode, expected):
    calls = []
    def compress(raw, store):
        calls.append(raw)
        return raw, CompressionObservation('skipped', 'test_worker')
    compressor = DesktopCompressor(mode, SourceStore(), 'test', remote_enabled=remote,
                                   worker=SimpleNamespace(compress=compress))
    raw = json.dumps({'input': 'Task', 'tools': [{'type': 'function',
        'name': 'mcp__test__lingmou_source_read'}] if reader else []}).encode()
    compressor.compress_observed(raw)
    assert bool(calls) == expected


def test_worker_client_rejects_non_loopback_endpoint():
    with pytest.raises(ValueError):
        CompressionWorkerClient({'url': 'http://example.com', 'token': 'a' * 40, 'namespace': 'test'})


def test_forced_literals_do_not_merge_with_adjacent_words():
    from token_compression.backends import protected_rewrite
    assert restore_candidate('data⟦KEEP_0⟧BBH', [('⟦KEEP_0⟧', 'GSM8K')]) == 'data GSM8K BBH'
    value = protected_rewrite('Data GSM8K, BBH.', lambda text: text.strip(' ,'))
    assert value == 'Data GSM8K BBH.'


def test_semantic_pairs_align_literal_ids_after_sentence_reformatting():
    import re
    pipeline = make_pipeline()
    pair = pipeline._verification_pair('Value 100 and `alpha`. Value 200 and `beta`.',
                                      '100 `alpha`, 200 `beta`.', 'tool_output', 'Read values')
    assert pair is not None
    assert re.findall(r'⟦KEEP_\d+⟧', pair['original']) == re.findall(r'⟦KEEP_\d+⟧', pair['short'])
