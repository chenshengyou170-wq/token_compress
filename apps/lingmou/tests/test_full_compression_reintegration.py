import json
from types import SimpleNamespace

import pytest

from codexscope.full_compression import FullCompressionConfig, FullCompressionPipeline
from codexscope.reference_selection import SourceStore
from codexscope.structural_compression import decode_tool_result, dumps, loads
from codexscope.unified_compression import UnifiedInputCompressor


def local(**options):
    return FullCompressionPipeline(source_store=options.pop('source_store', SourceStore()),
        local_backends={}, config=FullCompressionConfig(max_remote_calls=0, **options))


def run(compressor, body):
    out, obs = compressor.compress(json.dumps(body, ensure_ascii=False).encode())
    assert obs.status != 'error'
    return json.loads(out), obs


def pair(call_id, text, arguments='{}', name='read'):
    return [{'type': 'function_call', 'call_id': call_id, 'name': name, 'arguments': arguments},
            {'type': 'function_call_output', 'call_id': call_id, 'output': text}]


def material():
    unrelated = '\n\n'.join(f'Landscape region {chr(65+i)}: The valley scenery and mountains are beautiful. ' * 30 for i in range(16))
    return ('Refund requires an unused product and the original receipt within 7 days.\n\n'
            'Exception: damaged packaging is not eligible, even within that time.\n\n' + unrelated
            + '\n\nHiking departure is at 06:30 from Pine Valley.\n\nBring warm clothes for the trail.')


def test_long_material_drops_irrelevant_facts_but_preserves_conditions_and_sources():
    source = material()
    assert len(source) > 16000
    compressor = local()
    body = {'instructions': 'Never issue a refund without permission.',
            'input': [{'role': 'user', 'content': 'What are the refund conditions?'}] + pair('c', source)}
    got, obs = run(compressor, body)
    excerpt = json.loads(got['input'][-1]['output'])
    assert excerpt['$lingmou'] == 'extract/v1'
    retained = ''.join(x['text'] for x in excerpt['excerpts'])
    assert '7 days' in retained and 'damaged packaging is not eligible' in retained
    assert '06:30' not in retained
    assert all(source[x['start']:x['end']] == x['text'] for x in excerpt['excerpts'])
    assert compressor.store.get(excerpt['source_id']) == source
    assert got['instructions'] == body['instructions'] and got['input'][0] == body['input'][0]
    assert obs.full_request_tokens_after_estimate < .5 * obs.full_request_tokens_before_estimate
    assert not obs.compression_calls


def test_same_material_different_task_uses_new_excerpt():
    compressor = local()
    source = material()
    def ask(task):
        return run(compressor, {'input': [{'role': 'user', 'content': task}] + pair('c', source)})[0]
    refund = ask('What are the refund conditions?')
    hiking = ask('When is the hiking departure?')
    assert refund != hiking
    assert '06:30' in hiking['input'][-1]['output']
    assert compressor._cache_key('tool_output', source, 'refund') != compressor._cache_key('tool_output', source, 'hiking')
    assert compressor._cache_key('instructions', source, 'refund') == compressor._cache_key('instructions', source, 'hiking')


def test_explicit_references_use_task_extraction_without_rewriting_user_instructions():
    body = {'input': 'List refund conditions.\n<lingmou-reference>' + material() + '</lingmou-reference>\nAnswer in Chinese.'}
    got, obs = run(local(), body)
    assert got['input'].startswith('List refund conditions.\n<lingmou-reference>')
    assert got['input'].endswith('</lingmou-reference>\nAnswer in Chinese.')
    assert 'extract/v1' in got['input'] and 'reference' in obs.changed_roles


def test_all_matching_conditions_survive_beyond_top_four():
    source = '\n\n'.join([f'Refund condition {i}: only item group G{i} is eligible.' for i in range(8)]
                          + ['The scenery is pleasant. ' * 100 for _ in range(12)])
    got, _ = run(local(), {'input': [{'role': 'user', 'content': 'List refund conditions'}] + pair('x', source)})
    retained = got['input'][-1]['output']
    for i in range(8):
        assert f'group G{i}' in retained


@pytest.mark.parametrize('chat', [False, True])
def test_repeated_results_and_snapshot_delta_round_trip(chat):
    base = json.dumps({f'field_{i}': 'long stable value ' * 8 for i in range(70)})
    updated = json.loads(base)
    updated['field_22'] = 'changed'
    texts = [base, base, json.dumps(updated)]
    items = []
    for i, text in enumerate(texts):
        if chat:
            items.extend([{'role': 'assistant', 'tool_calls': [{'id': f'c{i}', 'type': 'function',
                'function': {'name': 'status', 'arguments': '{}'}}]},
                {'role': 'tool', 'tool_call_id': f'c{i}', 'content': text}])
        else:
            items.extend(pair(f'c{i}', text, name='status'))
    key, field = ('messages', 'content') if chat else ('input', 'output')
    got, obs = run(local(), {key: [{'role': 'user', 'content': 'Check status.'}] + items})
    outputs = [got[key][i][field] for i in (2, 4, 6)]
    assert json.loads(outputs[1])['$lingmou'] == 'repeat/v1'
    assert json.loads(outputs[2])['$lingmou'] == 'delta/v1'
    bases = {f'c{i}': output for i, output in enumerate(outputs)}
    for i, output in enumerate(outputs):
        assert decode_tool_result(output, bases) == dumps(loads(texts[i]))
    assert not obs.compression_calls


def test_referenced_base_is_not_rewritten_or_excerpted():
    source = material()
    got, _ = run(local(), {'input': [{'role': 'user', 'content': 'Refund conditions?'}]
                         + pair('a', source) + pair('b', source)})
    first, second = got['input'][2]['output'], got['input'][4]['output']
    assert json.loads(second)['$lingmou'] == 'repeat/v1'
    assert decode_tool_result(first) == source
    assert decode_tool_result(second, {'a': first}) == source


def test_duplicate_call_ids_never_create_self_references():
    text = json.dumps({'description': 'unchanged ' * 200})
    got, _ = run(local(), {'input': pair('x', text) + pair('x', text)})
    assert all('base_call_id' not in x['output'] for x in got['input'] if 'output' in x)


def test_history_trims_whole_turns_keeps_latest_pairs_and_retrievable_archive():
    compressor = local(history_max_tokens=1200, history_keep_turns=2)
    items = [{'role': 'system', 'content': 'Never delete files.'}]
    for i in range(6):
        items += [{'role': 'user', 'content': f'Task {i}'}] + pair(f'c{i}', f'Old evidence {i}. ' * 200)
    got, obs = run(compressor, {'input': items})
    archive = compressor.snapshot()['stages'][0]['archive']
    assert archive['removed_messages'] == 12
    assert json.loads(compressor.store.get(archive['source_id'])) == items[1:13]
    assert got['input'][0] == items[0]
    assert 'lingmou_source_read' in got['input'][1]['content']
    assert [x['content'] for x in got['input'] if x.get('role') == 'user'] == ['Task 4', 'Task 5']
    calls = {x['call_id'] for x in got['input'] if x.get('type') == 'function_call'}
    outputs = {x['call_id'] for x in got['input'] if x.get('type') == 'function_call_output'}
    assert calls == outputs == {'c4', 'c5'}
    assert obs.lossy_fields > 0 and not obs.compression_calls


def test_history_keeps_middle_developer_and_tool_discovery_items():
    for pinned in ({'role': 'developer', 'content': 'New constraint.'},
                   {'type': 'additional_tools', 'role': 'developer', 'tools': []}):
        body = {'input': [{'role': 'user', 'content': 'Old task.'}, pinned,
                          {'role': 'assistant', 'content': 'Old answer. ' * 300},
                          {'role': 'user', 'content': 'New task.'}]}
        got, _ = run(local(history_max_tokens=20, history_keep_turns=1), body)
        assert got == body


def test_nested_json_and_schema_data_literals_remain_exact():
    literal = {'description': 'The purpose of this explanation is to describe the current inventory in a detailed manner.'}
    schema = {'type': 'object', 'const': literal, 'enum': [literal], 'examples': [literal]}
    body = {'input': [{'role': 'user', 'content': 'Inspect data.'}],
            'tools': [{'type': 'function', 'name': 'f', 'parameters': schema}]}
    got, _ = run(local(), body)
    assert got['tools'][0]['parameters'] == schema
    # Duplicate-key JSON must not be treated as prose by a permissive validator.
    body['input'] += pair('bad', '{"approved":false,"approved":true}')
    got, _ = run(local(), body)
    assert got['input'][-1]['output'] == body['input'][-1]['output']


@pytest.mark.parametrize('multipart', [False, True])
def test_source_rereads_bypass_compression(multipart):
    source = material()
    content = [{'type': 'input_text', 'text': source}] if multipart else source
    body = {'input': [{'role': 'user', 'content': 'Refund conditions?'}]
            + pair('r', content, name='mcp__sources__lingmou_source_read')}
    got, _ = run(local(), body)
    assert got == body


def test_hosted_search_defers_tools_without_deleting_schemas_or_claiming_local_savings():
    schema = {'type': 'object', 'properties': {'id': {'type': 'string'}}, 'required': ['id']}
    body = {'input': 'Read records.', 'tools': [{'type': 'tool_search'},
        {'type': 'function', 'name': 'read_record', 'parameters': schema},
        {'type': 'function', 'name': 'lingmou_source_read', 'parameters': schema},
        {'type': 'function', 'name': 'resident', 'parameters': schema, 'defer_loading': False}]}
    got, obs = run(local(), body)
    assert got['tools'][1] == {**body['tools'][1], 'defer_loading': True}
    assert got['tools'][2:] == body['tools'][2:]
    assert obs.reason == 'tool_loading_deferred'
    assert obs.full_request_tokens_after_estimate >= obs.full_request_tokens_before_estimate
    for search in ([], [{'type': 'tool_search', 'execution': 'client'}]):
        other = {**body, 'tools': search + body['tools'][1:]}
        assert run(local(), other)[0] == other
    forced = {**body, 'tool_choice': {'type': 'function', 'name': 'read_record'}}
    assert run(local(), forced)[0] == forced


def test_defaults_skip_short_remote_rewrites_and_post_generation_spend():
    class Forbidden:
        def chat(self, *args, **kwargs):
            pytest.fail('A short segment/output must not incur a model call')
    compressor = FullCompressionPipeline(source_store=SourceStore(), client=Forbidden(), local_backends={})
    body = {'input': 'Explain current inventory in a detailed manner.'}
    assert run(compressor, body)[0] == body
    result, calls = compressor.compress_output('Long final answer. ' * 1000)
    assert result['saved'] == 0 and not calls and not result['billing_reduction']


def test_component_specific_jev_contract_and_thresholds(monkeypatch):
    captured = []
    class Client:
        def __init__(self, **kwargs): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def post(self, url, **kwargs):
            captured.append(kwargs['json'])
            return SimpleNamespace(raise_for_status=lambda: None, json=lambda: {
                'model': 'test-jev', 'answers': {k: {'type': 'noul', 'noul': .8}
                for k in kwargs['json']['questions']}, 'usage': {'input_tokens': 30, 'output_tokens': 2}})
    monkeypatch.setenv('TYPESAFE_API_KEY', 'test-only')
    monkeypatch.setattr('codexscope.full_compression.httpx.Client', Client)
    compressor = FullCompressionPipeline(source_store=SourceStore(), local_backends={})
    pairs = {role: {'original': 'source', 'short': 'short', 'component': role, 'task': 'refund'}
             for role in ('tool_output', 'reference', 'instructions', 'user')}
    calls = []
    assert compressor._verify_batch(pairs, calls) == {'tool_output', 'reference'}
    questions = list(captured[0]['questions'].values())
    assert 'Unrelated facts' in questions[0]['instructions']
    assert 'all facts' in questions[2]['instructions']
    assert calls[0]['official_usage']['total_tokens'] == 32


def test_remote_budget_caps_calls_and_failures_are_measured(monkeypatch):
    requests = []
    class Client:
        def __init__(self, **kwargs): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def post(self, url, **kwargs):
            requests.append(kwargs)
            raise TimeoutError('test timeout')
    monkeypatch.setenv('TYPESAFE_API_KEY', 'test-only')
    monkeypatch.setattr('codexscope.full_compression.httpx.Client', Client)
    compressor = FullCompressionPipeline(source_store=SourceStore(), local_backends={},
        config=FullCompressionConfig(max_remote_calls=1))
    calls = []
    pair = {'x': {'original': 'original', 'short': 'short', 'component': 'tool_output', 'task': 'task'}}
    for _ in range(4):
        assert not compressor._verify_batch(pair, calls)
    assert len(requests) == len(calls) == 1
    assert calls[0]['status'] == 'failed' and calls[0]['official_usage'] is None


def test_environment_config_reaches_real_adapter(monkeypatch, tmp_path):
    monkeypatch.setenv('LINGMOU_FULL_HISTORY_MAX_TOKENS', '800')
    monkeypatch.setenv('LINGMOU_FULL_HISTORY_KEEP_TURNS', '1')
    monkeypatch.setenv('LINGMOU_FULL_MAX_REMOTE_CALLS', '0')
    compressor = UnifiedInputCompressor('full', source_store=SourceStore(tmp_path))
    body = {'input': [{'role': 'user', 'content': 'First task'},
                      {'role': 'assistant', 'content': 'Earlier response. ' * 2000},
                      {'role': 'user', 'content': 'Latest task'}]}
    sent, obs = compressor.compress_observed(json.dumps(body).encode())
    assert obs.status == 'compressed'
    assert compressor._full_pipeline.config.history_keep_turns == 1
    assert 'First task' not in sent.decode()
    assert 'Latest task' in sent.decode()


def test_no_local_savings_means_no_remote_work_even_for_long_prose():
    class Forbidden:
        def chat(self, *args, **kwargs):
            pytest.fail('Remote work must have a budget funded by local savings')
    compressor = FullCompressionPipeline(source_store=SourceStore(), client=Forbidden(), local_backends={},
        verifier=lambda *args: pytest.fail('No unfunded validation'),
        config=FullCompressionConfig(startup_remote_tokens=0))
    body = {'input': 'The purpose of this explanation is to describe the current inventory in a detailed manner. ' * 40}
    got, obs = run(compressor, body)
    assert got == body and not obs.compression_calls
    assert compressor.snapshot()['stages'][-2]['remote_budget_estimate'] == 0


@pytest.mark.parametrize('usage', [100, 30000])
def test_startup_allowance_is_run_scoped_and_rejected_rewrites_are_cached(monkeypatch, usage):
    requests = []
    class Client:
        def __init__(self, **kwargs): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def post(self, url, **kwargs):
            requests.append(kwargs['json'])
            return SimpleNamespace(raise_for_status=lambda: None, json=lambda: {
                'model': 'test-jev', 'answers': {k: {'type': 'noul', 'noul': .1}
                for k in kwargs['json']['questions']}, 'usage': {'input_tokens': usage, 'output_tokens': 0}})
    monkeypatch.setenv('TYPESAFE_API_KEY', 'test-only')
    monkeypatch.delenv('KIMI_API_KEY', raising=False)
    monkeypatch.delenv('MOONSHOT_API_KEY', raising=False)
    monkeypatch.delenv('KIMI_API_KEY_FILE', raising=False)
    monkeypatch.setattr('codexscope.full_compression.httpx.Client', Client)
    source = 'In order to describe the current inventory, please provide a detailed explanation. ' * 10
    compressor = FullCompressionPipeline(source_store=SourceStore(), token_counter=len, local_backends={},
        config=FullCompressionConfig(startup_remote_tokens=10000, max_remote_tokens=10000))
    body = {'instructions': source, 'input': 'Check inventory.'}
    for _ in range(5):
        got, _ = run(compressor, body)
        assert got == body
    assert len(requests) == 1  # A denied candidate must not be billed repeatedly.
    run(compressor, {**body, 'instructions': source.replace('inventory', 'warehouse')})
    assert len(requests) == (1 if usage == 30000 else 2)


def test_additional_tool_descriptions_enter_rewrite_but_protocol_schema_stays_exact():
    class Rewriter:
        def chat(self, messages, **kwargs):
            segments = json.loads(messages[-1]['content'])
            return {'text': json.dumps({k: 'Describe inventory.' for k in segments}),
                    'model': 'test', 'usage': {'total_tokens': 25}, 'finish_reason': 'stop'}
    description = 'The purpose of this explanation is to describe the current inventory in a detailed manner. '
    definition = {'type': 'custom', 'name': 'exec', 'description': description,
                  'format': {'type': 'grammar', 'syntax': 'lark', 'definition': 'start: /.+/'}}
    body = {'input': [{'type': 'additional_tools', 'role': 'developer', 'tools': [definition]},
                      {'role': 'user', 'content': 'Show inventory.'}]}
    compressor = FullCompressionPipeline(source_store=SourceStore(), client=Rewriter(), local_backends={},
        verifier=lambda pairs, calls: set(pairs),
        config=FullCompressionConfig(min_model_tokens=0, min_saved_tokens=1, allow_unfunded_remote=True))
    got, obs = run(compressor, body)
    assert obs.status == 'compressed'
    changed = got['input'][0]['tools'][0]
    assert len(changed['description']) < len(description)
    assert {**changed, 'description': description} == definition


def test_proxy_forwards_excerpts_and_preserves_provider_stream(monkeypatch, tmp_path):
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import httpx
    from codexscope.request_token_tap import RequestTokenTap
    monkeypatch.setenv('LINGMOU_FULL_MAX_REMOTE_CALLS', '0')
    received = []
    wire = b'data: {"type":"response.completed","response":{"usage":{"input_tokens":123,"output_tokens":4,"total_tokens":127}}}\n\n'
    class Upstream(BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def do_POST(self):
            received.append(json.loads(self.rfile.read(int(self.headers['Content-Length']))))
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Content-Length', str(len(wire)))
            self.end_headers()
            self.wfile.write(wire)
    server = ThreadingHTTPServer(('127.0.0.1', 0), Upstream)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    store = SourceStore(tmp_path / 'sources')
    compressor = UnifiedInputCompressor('full', source_store=store)
    tap = RequestTokenTap(f'http://127.0.0.1:{server.server_port}/v1', input_compressor=compressor).start()
    body = {'model': 'test', 'input': [{'role': 'user', 'content': 'Refund conditions?'}] + pair('c', material())}
    try:
        response = httpx.post(tap.local_base_url + '/responses', json=body, trust_env=False)
        assert response.content == wire
        excerpt = json.loads(received[0]['input'][-1]['output'])
        assert excerpt['$lingmou'] == 'extract/v1'
        assert store.get(excerpt['source_id']) == material()
        assert received[0]['input'][:-1] == body['input'][:-1]
    finally:
        tap.stop()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
