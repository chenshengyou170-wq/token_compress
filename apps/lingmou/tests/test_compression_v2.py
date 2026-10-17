import copy
import json
import os
import random
from concurrent.futures import ThreadPoolExecutor

import pytest

from codexscope.compression_boundary import reference_text, transform_data
from codexscope.context_compression import HybridInputCompressor, make_input_compressor
from codexscope.context_tools import SOURCE_READ_TOOL, source_mcp_arguments
from codexscope.deferred_tools import DeferredToolRegistry, with_prompt_cache_key
from codexscope.llmlingua_compression import LLMLingua2Rewriter
from codexscope.reference_selection import SourceStore, Selection, source_spans, extract_source, LexicalSelector, KimiSelector, JevSelector
from codexscope.request_usage_ledger import compare_tasks, summarize_task, RequestUsageLedger, RequestAccountingTracker
from codexscope.structural_compression import StructuralCompressor, loads, dumps, decode_tool_result


def table(n=100):
    return [{'record_identifier': i, 'status': 'needs_review', 'approved': False,
             'amount': 20, 'reason': None} for i in range(n)]


def document():
    return '\n\n'.join(f'Archive section {chr(65+i)}. ' + 'An unrelated background narrative about scenery. ' * 35 for i in range(18))


@pytest.mark.parametrize('mode', ['caveman', 'structure', 'hybrid', 'extract', 'jev', 'kimi', 'llmlingua2'])
@pytest.mark.parametrize('chat', [False, True])
def test_instruction_roles_current_task_formats_and_protocols_immutable(mode, chat):
    marked = reference_text('Please rewrite this paragraph in order to make it shorter. ' * 20)
    protected = [
        {'role': 'system', 'content': marked}, {'role': 'developer', 'content': marked},
        {'role': 'user', 'content': 'Please return JSON {"approved":false,"action":"needs_review"}; 不得修改枚举或布尔类型。'},
        {'role': 'assistant', 'content': 'Please retain the preceding answer.', 'phase': 'commentary'}]
    data = {'role': 'user', 'content': '请输出精确枚举。' + reference_text(json.dumps(table())) + 'Return valid JSON only.'}
    body = {'model': 'test', 'instructions': marked,
            'messages' if chat else 'input': protected + [data],
            'tools': [SOURCE_READ_TOOL], 'text': {'format': {'type': 'json_schema', 'schema': {'enum': ['needs_review'], 'const': False}}}}
    raw = json.dumps(body, ensure_ascii=False).encode()
    compressor = make_input_compressor(mode)
    got = json.loads(compressor.compress(raw))
    field = 'messages' if chat else 'input'
    assert got[field][:4] == protected
    for key in ('tools', 'text', 'instructions'):
        assert got[key] == body[key]
    assert got[field][4]['content'].startswith('请输出精确枚举。<lingmou-reference>')
    assert got[field][4]['content'].endswith('</lingmou-reference>Return valid JSON only.')


@pytest.mark.parametrize('text', ['<lingmou-reference>unclosed', '</lingmou-reference>orphan',
    '<lingmou-reference>A<lingmou-reference>B</lingmou-reference>',
    '<lingmou-reference>A</lingmou-reference><lingmou-reference>B'])
def test_ambiguous_reference_markers_do_not_grant_rewriting(text):
    assert transform_data(text, 'user', lambda _: 'changed') == text


def test_exact_number_literals_and_json_value_types_roundtrip():
    row = '{"a_very_long_amount_field":123456789.123456789,"bool":false,"str":"false","none":null,"negative_zero":-0,"exp":1e+09}'
    source = '[' + ','.join([row] * 50) + ']'
    candidate = StructuralCompressor(len).compress(source)
    assert 'table/v1' in candidate
    decoded = decode_tool_result(candidate)
    assert decoded == source
    body = b'{"input":[{"type":"function_call_output","output":' + json.dumps(source).encode() + b'}],"tools":[{"parameters":{"const":123456789.123456789}}]}'
    result = HybridInputCompressor(token_counter=len).compress(body)
    assert b'"const":123456789.123456789' in result


def test_property_json_tables_and_wrappers_are_reversible():
    rng = random.Random(42)
    for _ in range(60):
        rows = [{'identifier_long': i, 'nullable_value': rng.choice([True, False, None, 100, '100', {'nested': ['中', 2]}])} for i in range(50)]
        value = rng.choice([rows, {'before': False, 'records': rows, 'after': 'a'}])
        text = json.dumps(value, ensure_ascii=False)
        result = StructuralCompressor(len).compress(text)
        assert loads(decode_tool_result(result)) == loads(text)


def test_log_template_variable_counts_order_and_crlf_roundtrip():
    text = ''.join(f'2026-10-09 INFO worker={i} checked shipment={i + 10}\r\n' * 3 for i in range(100)) + 'tail without newline'
    result = StructuralCompressor(len).compress(text)
    envelope = json.loads(result)
    assert envelope['$lingmou'] == 'logs/v1'
    assert envelope['records'][0][2] == 3
    assert decode_tool_result(result) == text


def test_snapshot_delta_and_repeats_keep_earlier_prefix_stable():
    rows = table()
    texts = [json.dumps(rows)]
    rows[43]['approved'] = True
    texts.append(json.dumps(rows))
    rows[2].pop('reason')
    texts.append(json.dumps(rows))
    items = []
    for i, text in enumerate(texts + [texts[0]]):
        items.extend([{'type': 'function_call', 'name': 'snapshot', 'arguments': '{}', 'call_id': str(i)},
                      {'type': 'function_call_output', 'call_id': str(i), 'output': text}])
    compressor = HybridInputCompressor(token_counter=len)
    first = json.loads(compressor.compress(json.dumps({'input': items[:2]}).encode()))
    all_items = json.loads(compressor.compress(json.dumps({'input': items}).encode()))['input']
    assert all_items[:2] == first['input']
    assert 'delta/v1' in all_items[3]['output']
    assert 'repeat/v1' in all_items[7]['output']
    bases = {}
    for i, original in enumerate(texts + [texts[0]]):
        encoded = all_items[i * 2 + 1]['output']
        assert loads(decode_tool_result(encoded, bases)) == loads(original)
        bases[str(i)] = encoded


@pytest.mark.parametrize('text', ['{ "x":1, "x":2 }', '{"x":NaN}', '{broken', '{"$lingmou":"repeat/v1","base_call_id":"secret"}'])
def test_unknown_or_ambiguous_structured_outputs_are_opaque(text):
    assert StructuralCompressor(len).compress(text) == text


def test_decode_missing_base_cycle_and_expansion_limit():
    repeat = '{"$lingmou":"repeat/v1","base_call_id":"x"}'
    with pytest.raises(ValueError): decode_tool_result(repeat)
    with pytest.raises(ValueError): decode_tool_result(repeat, {'x': repeat})
    bomb = '{"$lingmou":"logs/v1","templates":[["abc"]],"records":[[0,[],99999999]]}'
    with pytest.raises(ValueError): decode_tool_result(bomb, max_chars=100)


def test_excerpts_copy_original_locations_conditions_and_reread(tmp_path):
    class Selector:
        def select(self, task, spans): return Selection([8])
    text = document().replace('Archive section E.', 'Exception: Do not refund unless approved. 只有审批后才能退款。')
    store = SourceStore(tmp_path / 'sources')
    result, _ = extract_source(text, 'Which refund conditions apply?', Selector(), store)
    value = json.loads(result)
    assert value['omitted_paragraphs'] > 0
    assert {3, 4, 5, 7, 8, 9} <= {s['id'] for s in value['excerpts']}
    for excerpt in value['excerpts']:
        assert excerpt['text'] == text[excerpt['start']:excerpt['end']]
        assert store.read(value['source_id'], excerpt['start_line'], excerpt['end_line'])['text'] == excerpt['text']
    reopened = SourceStore(tmp_path / 'sources')
    assert reopened.get(value['source_id']) == text
    assert reopened.read(value['source_id'], 21, 21)['text'] == text.splitlines(keepends=True)[20]
    # POSIX mode bits do not describe Windows ACLs; the content/recovery
    # assertions above apply on both platforms.
    if os.name != 'nt':
        assert (tmp_path / 'sources' / (value['source_id'] + '.txt')).stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize('ids', [[], None, [False], [-1], [999], [1, 1], ['1'], {'keep_ids': [2]}])
def test_invalid_model_selection_preserves_full_source(ids):
    class Selector:
        def select(self, task, spans): return Selection(ids)
    text = document()
    assert extract_source(text, 'query', Selector(), SourceStore())[0] == text


def test_source_reader_paths_tampering_quota_and_newlines(tmp_path):
    store = SourceStore(tmp_path / 'sources', max_bytes=100)
    text = 'a\r\nb\n末尾'
    source_id = store.put(text)
    assert store.read(source_id, 1, 3)['text'] == text
    with pytest.raises(ValueError): store.get('../secret')
    with pytest.raises(ValueError): store.read(source_id, True, 2)
    with pytest.raises(ValueError): store.read(source_id, 1, 4)
    with pytest.raises(ValueError): store.put('x' * 100)
    (tmp_path / 'sources' / (source_id + '.txt')).write_text('tampered')
    with pytest.raises(ValueError): store.get(source_id)


def test_source_spans_keep_python_functions_and_fences_whole():
    text = '@decorator\ndef pay(x):\n    """Pay after approval."""\n\n    if x:\n        return 2\n\ndef refuse():\n    return False\n'
    spans = source_spans(text)
    assert spans[0].text.startswith('@decorator') and 'return 2' in spans[0].text
    fenced = 'Before\n\n```python\nx = 1\n\ny = 2\n```\n\nAfter'
    assert any('x = 1\n\ny = 2' in s.text for s in source_spans(fenced))


def test_selection_cache_is_task_specific_and_concurrent():
    class Selector:
        def __init__(self): self.calls = 0
        def select(self, task, spans):
            self.calls += 1
            return Selection([8 if 'first' in task else 14])
    selector = Selector()
    compressor = HybridInputCompressor(selector=selector, source_store=SourceStore(), token_counter=len)
    raw = json.dumps({'input': 'first task\n' + reference_text(document())}).encode()
    with ThreadPoolExecutor(4) as pool:
        outputs = list(pool.map(compressor.compress, [raw] * 8))
    assert len(set(outputs)) == 1 and selector.calls == 1
    other = compressor.compress(raw.replace(b'first task', b'second task'))
    assert other != outputs[0] and selector.calls == 2


def test_no_reread_store_or_unmatched_query_keeps_full_reference():
    text = document()
    raw = json.dumps({'input': 'zebra\n' + reference_text(text)}).encode()
    assert make_input_compressor('extract').compress(raw) == raw
    assert make_input_compressor('extract', source_store=SourceStore()).compress(raw) == raw


def test_llmlingua_adapter_forces_markers_and_rejects_damage():
    class Engine:
        def compress_prompt(self, text, **kwargs):
            assert kwargs['force_tokens'] == ['⟦KEEP_0⟧', '\n']
            assert kwargs['drop_consecutive'] is False
            return {'compressed_prompt': 'summary ⟦KEEP_0⟧'}
    assert LLMLingua2Rewriter(engine=Engine())('text ⟦KEEP_0⟧') == 'summary ⟦KEEP_0⟧'
    raw = json.dumps({'input': reference_text('Do not send unless approved. ' + 'Background explanation. ' * 100)}).encode()
    compressor = HybridInputCompressor(rewriter=lambda text: 'send now', source_store=SourceStore(), token_counter=len)
    assert compressor.compress(raw) == raw


def test_kimi_only_returns_ids_and_retains_usage_for_invalid_answers():
    class Client:
        def chat(self, messages, **kwargs):
            assert 'Do not rewrite' in messages[0]['content']
            data = json.loads(messages[1]['content'])
            assert data['task'] == 'query' and data['paragraphs'][0]['id'] == 0
            return {'text': '{"text":"model rewrote the data"}', 'finish_reason': 'stop',
                    'usage': {'input_tokens': 30, 'output_tokens': 5}, 'model': 'kimi-test'}
    result = KimiSelector(Client()).select('query', source_spans(document()))
    assert result.ids is None
    assert result.calls[0]['official_usage']['input_tokens'] == 30
    assert result.calls[0]['status'] == 'failed'


def test_jev_batches_nouls_and_keeps_uncertain_spans(monkeypatch):
    import httpx
    payloads = []
    def handler(request):
        payload = json.loads(request.content)
        payloads.append(payload)
        answers = {key: {'type': 'noul', 'noul': 0.01} for key in payload['questions']}
        answers['8']['noul'] = 0.95
        answers['12']['noul'] = 0.5
        return httpx.Response(200, json={'answers': answers, 'model': 'jev-test', 'usage': {'input_tokens': 100, 'output_tokens': 20}})
    client_type = httpx.Client
    monkeypatch.setattr(httpx, 'Client', lambda **kw: client_type(transport=httpx.MockTransport(handler), **kw))
    monkeypatch.setenv('TYPESAFE_API_KEY', 'test-key-never-logged')
    result = JevSelector().select('退款何时允许', source_spans(document()))
    assert result.ids == [8, 12] and len(payloads) == 1
    assert isinstance(payloads[0]['questions']['0']['criteria'], dict)
    assert result.calls[0]['official_usage']['total_tokens'] == 120
    assert 'test-key' not in json.dumps(result.calls)


def test_source_store_quota_does_not_spend_selection_calls():
    class Selector:
        def select(self, *_): raise AssertionError('must not spend model tokens')
    raw = json.dumps({'input': 'query\n' + reference_text(document())}).encode()
    compressor = HybridInputCompressor(selector=Selector(), source_store=SourceStore(max_bytes=1), token_counter=len)
    output, observation = compressor.compress_observed(raw)
    assert output == raw and observation.compression_model_calls == 0


def test_mcp_rereads_omitted_source_over_stdio(tmp_path):
    import asyncio
    import sys
    from mcp import Client
    from mcp.client.stdio import StdioServerParameters, stdio_client
    store = SourceStore(tmp_path / 'sources')
    source_id = store.put('first\nsecond\nthird\n')
    async def exercise():
        transport = stdio_client(StdioServerParameters(command=sys.executable,
            args=['-m', 'codexscope.context_tools', 'serve', '--store', str(store.root)]))
        async with Client(transport) as client:
            listing = await client.list_tools()
            annotations = listing.tools[0].annotations
            assert annotations.read_only_hint is True and annotations.destructive_hint is False
            result = await client.call_tool('lingmou_source_read', {'source_id': source_id, 'start_line': 2, 'end_line': 2})
            assert not result.is_error
            assert result.structured_content['text'] == 'second\n'
    asyncio.run(exercise())


def test_tool_discovery_loads_exact_schemas_and_preserves_existing_search():
    tools = [SOURCE_READ_TOOL, {'type': 'function', 'name': 'status', 'description': 'Service status', 'parameters': {'type': 'object'}}]
    registry = DeferredToolRegistry(tools)
    initial = registry.responses_tools()
    assert len(initial) == 1 and initial[0]['type'] == 'tool_search'
    assert all('parameters' not in row for row in registry.catalog())
    loaded = registry.handle_search({'type': 'tool_search_call', 'execution': 'client', 'call_id': 'call1', 'arguments': {'names': ['lingmou_source_read']}})
    assert loaded['tools'] == [{**SOURCE_READ_TOOL, 'defer_loading': True}]
    assert registry.responses_tools(initial) == initial
    assert registry.load(['status'])[0] == tools[1]
    with pytest.raises(ValueError): registry.load(['made_up_tool'])
    assert source_mcp_arguments(__import__('pathlib').Path('/tmp/a'))[1].startswith('mcp_servers.lingmou_sources=')


def test_packaged_reader_uses_the_sidecar_cli(monkeypatch, tmp_path):
    import sys
    monkeypatch.setattr(sys, 'frozen', True, raising=False)
    config = source_mcp_arguments(tmp_path)[1]
    assert 'args=["context","serve"' in config


def test_cache_key_changes_only_with_stable_prefix_and_preserves_explicit_key():
    body = {'model': 'example', 'instructions': 'Fixed', 'tools': [SOURCE_READ_TOOL], 'input': 'variable'}
    first = with_prompt_cache_key(body, namespace='tenant1')
    assert body == {k: v for k, v in first.items() if k != 'prompt_cache_key'}
    second = with_prompt_cache_key({**body, 'input': 'other'}, namespace='tenant1')
    assert first['prompt_cache_key'] == second['prompt_cache_key']
    assert first['prompt_cache_key'] != with_prompt_cache_key(body, namespace='tenant2')['prompt_cache_key']
    assert with_prompt_cache_key({**body, 'prompt_cache_key': 'custom'}, namespace='x')['prompt_cache_key'] == 'custom'


def usage_record(inp, out, **kw):
    return {'status': 'completed', 'official_usage': {'input_tokens': inp, 'output_tokens': out}, **kw}


def test_whole_task_usage_includes_rereads_retries_and_compression_cost():
    before = [usage_record(1000, 100)]
    after = [usage_record(500, 150, compression={'compression_calls': [{'official_usage': {'input_tokens': 100, 'output_tokens': 10}}]}),
             usage_record(200, 20, purpose='reread', attempt=2)]
    result = compare_tasks(before, after, baseline_checks={'correct': True}, candidate_checks={'correct': True})
    assert result['official_net_total_tokens_saved'] == 120
    assert result['downstream_output_tokens_growth'] == 70
    assert result['candidate']['reread']['total_tokens'] == 220
    assert result['candidate']['retry']['total_tokens'] == 220
    assert result['candidate']['compression']['total_tokens'] == 110
    assert result['verified_task_savings'] is True
    after.append({'status': 'failed', 'official_usage': None})
    assert compare_tasks(before, after)['official_net_total_tokens_saved'] is None
    assert summarize_task(after)['known_official_total_tokens'] == 980
    after.pop()
    after[0]['compression']['compression_calls'].append({'official_usage': None, 'status': 'failed'})
    assert compare_tasks(before, after)['official_net_total_tokens_saved'] is None


def test_ledger_task_totals_survive_recent_record_cap_and_quality_is_not_assumed():
    ledger = RequestUsageLedger()
    for _ in range(205): ledger.append(usage_record(10, 5, task_id='a'))
    ledger.append(usage_record(20, 5, task_id='b'))
    snapshot = ledger.snapshot()
    assert len(snapshot['recent_requests']) == 200
    assert snapshot['tasks']['a']['official_total_tokens'] == 3075
    assert snapshot['tasks']['b']['quality_passed'] is None
    with pytest.raises(ValueError): summarize_task(snapshot['recent_requests'])


def test_codex_turn_grouping_rereads_and_repeated_request_inference():
    tracker = RequestAccountingTracker()
    body = {'client_metadata': {'thread_id': 'threadA', 'turn_id': 'turnA'}, 'input': [
        {'type': 'function_call', 'call_id': 'r', 'name': 'mcp__sources__lingmou_source_read'},
        {'type': 'function_call_output', 'call_id': 'r', 'output': 'source lines'}]}
    first = tracker.observe({}, body)
    second = tracker.observe({}, body)
    assert first['purpose'] == 'reread' and first['attempt'] == 1
    assert second['attempt'] == 2 and second['attempt_source'] == 'repeated_body_inference'
    body['client_metadata']['turn_id'] = 'turnB'
    third = tracker.observe({}, body)
    assert third['task_id'] != first['task_id'] and third['attempt'] == 1
    body['input'].append({'role': 'user', 'content': 'Next instruction'})
    assert tracker.observe({}, body)['purpose'] == 'generation'
    explicit = tracker.observe({'X-Lingmou-Task-Id': 'mine', 'X-Lingmou-Purpose': 'retry', 'X-Lingmou-Attempt': '3'}, body)
    assert explicit['task_id'] == 'mine' and explicit['attempt_source'] == 'host'
    assert 'source lines' not in json.dumps(first)


def test_codex_custom_tool_results_compress_but_call_code_and_images_do_not():
    call = {'type': 'custom_tool_call', 'call_id': 'c', 'name': 'exec', 'input': 'text(await tools.read({path:"exact-path"}));'}
    image = {'type': 'input_image', 'image_url': 'data:image/png;base64,ABCD'}
    body = {'input': [call, {'type': 'custom_tool_call_output', 'call_id': 'c', 'output': json.dumps(table())},
                      {'type': 'function_call_output', 'call_id': 'd', 'output': [{'type': 'input_text', 'text': json.dumps(table())}, image]}]}
    got = json.loads(HybridInputCompressor().compress(json.dumps(body).encode()))
    assert got['input'][0] == call
    assert loads(decode_tool_result(got['input'][1]['output'])) == loads(json.dumps(table()))
    assert got['input'][2]['output'][1] == image
    assert loads(decode_tool_result(got['input'][2]['output'][0]['text'], {'c': got['input'][1]['output']})) == loads(json.dumps(table()))


def test_code_tool_reread_classification_does_not_count_discovery_queries():
    tracker = RequestAccountingTracker()
    call = {'type': 'custom_tool_call', 'call_id': 'c', 'name': 'exec',
            'input': 'text(await tools.mcp__lingmou_sources__lingmou_source_read({source_id:"hash",start_line:1}));'}
    body = {'input': [call, {'type': 'custom_tool_call_output', 'call_id': 'c', 'output': 'lines'}]}
    assert tracker.observe({}, body)['purpose'] == 'reread'
    call['input'] = 'await tools.tool_search({query:"lingmou_source_read"});'
    assert tracker.observe({}, body)['purpose'] == 'generation'


def test_relay_host_labels_full_attempts_and_strips_accounting_headers():
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import httpx
    from codexscope.request_token_tap import RequestTokenTap
    received, records = [], []
    done = threading.Event()
    class Upstream(BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def do_POST(self):
            received.append((dict(self.headers), json.loads(self.rfile.read(int(self.headers['Content-Length'])))))
            index = len(received)
            payload = {'model': 'test', 'usage': {'input_tokens': 100 * index, 'output_tokens': 10}} if index < 3 else {'error': 'temporary_failure'}
            raw = json.dumps(payload).encode()
            self.send_response(200 if index < 3 else 503)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers(); self.wfile.write(raw)
    upstream = ThreadingHTTPServer(('127.0.0.1', 0), Upstream)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    def on_record(record):
        records.append(record)
        if len(records) == 3: done.set()
    compressor = HybridInputCompressor(token_counter=len)
    tap = RequestTokenTap(f'http://127.0.0.1:{upstream.server_port}/v1', input_compressor=compressor, on_request_usage=on_record).start()
    body = {'model': 'test', 'instructions': 'Return boolean false.',
            'input': 'Current task stays exact.\n' + reference_text(json.dumps(table()))}
    try:
        for purpose, attempt in [('generation', '1'), ('reread', '1'), ('retry', '2')]:
            httpx.post(tap.local_base_url + '/responses', json=body, headers={
                'X-Lingmou-Task-Id': 'taskA', 'X-Lingmou-Purpose': purpose, 'X-Lingmou-Attempt': attempt})
        assert done.wait(3)
        assert all(not any(k.lower().startswith('x-lingmou-') for k in h) for h, _ in received)
        assert all(b['instructions'] == body['instructions'] for _, b in received)
        assert all(r['input_tokens_after_estimate'] < r['input_tokens_before_estimate'] for r in records)
        summary = summarize_task(records)
        assert summary['requests'] == 3 and summary['unlabelled_requests'] == 0
        assert summary['known_official_total_tokens'] == 320
        assert summary['official_total_tokens'] is None
        assert summary['reread']['total_tokens'] == 210
        assert summary['retry']['missing_usage_calls'] == 1
    finally:
        tap.stop(); upstream.shutdown(); upstream.server_close()
