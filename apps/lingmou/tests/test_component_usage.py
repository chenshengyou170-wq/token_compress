from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx

from codexscope.component_usage import ComponentUsageLedger, measure_components
from codexscope.compression_boundary import reference_text
from codexscope.reference_selection import SourceStore
from codexscope.request_token_tap import RequestTokenTap
from codexscope.token_panel import token_panel_snapshot
from codexscope.unified_compression import UnifiedInputCompressor


def test_codex_additional_tools_are_measured_as_definitions_not_instructions():
    definitions = [{'type': 'custom', 'name': 'exec', 'description': 'NeverStoreToolDocs',
                    'format': {'type': 'grammar', 'syntax': 'lark', 'definition': 'start: /.+/'}}]
    body = {'input': [{'type': 'additional_tools', 'role': 'developer', 'tools': definitions},
                      {'type': 'message', 'role': 'developer', 'content': 'Keep instructions'}]}
    result = measure_components(body, body, token_counter=len)
    components = {row['id']: row for row in result['components']}
    assert components['tool_definitions']['before'] > 0
    assert result['tools'][0]['name'] == 'exec'
    assert result['tools'][0]['definition_before'] == components['tool_definitions']['before']
    assert components['instructions']['before'] < components['tool_definitions']['before']
    assert 'NeverStoreToolDocs' not in json.dumps(result)


def test_components_follow_actual_content_and_never_store_source_text(tmp_path):
    rows = json.dumps([{'record_identifier': i, 'status': 'pending', 'amount': 10} for i in range(80)])
    original = {'model': 'test', 'instructions': 'NeverStoreInstruction',
        'tools': [{'type': 'function', 'name': 'read_orders', 'parameters': {'type': 'object'}}],
        'input': [
            {'role': 'user', 'content': 'PreviousTask'},
            {'role': 'assistant', 'content': 'PreviousReply'},
            {'role': 'user', 'content': 'CurrentTask' + reference_text(rows)},
            {'type': 'function_call', 'name': 'read_orders', 'call_id': 'c1', 'arguments': '{"file":"NeverStorePath"}'},
            {'type': 'function_call_output', 'call_id': 'c1', 'output': rows},
        ]}
    compressor = UnifiedInputCompressor('structure', source_store=SourceStore(tmp_path), token_counter=len)
    forwarded = json.loads(compressor.compress(json.dumps(original).encode()))
    measurement = measure_components(original, forwarded, token_counter=len)
    rows_by_id = {row['id']: row for row in measurement['components']}
    for name in ('instructions', 'user', 'history', 'tool_definitions', 'tool_calls'):
        assert rows_by_id[name]['before'] == rows_by_id[name]['after']
    for name in ('references', 'tool_results'):
        assert rows_by_id[name]['before'] > rows_by_id[name]['after']
    tool = measurement['tools'][0]
    assert tool['name'] == 'read_orders'
    assert tool['definition_before'] == tool['definition_after'] > 0
    assert tool['call_before'] == tool['call_after'] > 0
    assert tool['result_before'] > tool['result_after']
    for secret in ('NeverStore', 'record_identifier', 'PreviousTask', 'CurrentTask'):
        assert secret not in json.dumps(measurement)
    ledger = ComponentUsageLedger()
    ledger.append('tap-1', measurement)
    ledger.append('tap-2', measure_components(original, original, token_counter=len))
    panel = token_panel_snapshot(tmp_path, provider_snapshot={'component_usage': ledger.snapshot()})
    assert panel['breakdown']['requests'] == 2
    assert panel['breakdown']['latest']['request_id'] == 'tap-2'
    assert next(row for row in panel['breakdown']['components'] if row['id'] == 'tool_results')['compressed_requests'] == 1
    assert panel['breakdown']['latest']['tools'][0]['saved'] == 0
    assert panel['capture_state'] == 'finished'


def test_chat_tool_linkage_and_invisible_context_are_explicit():
    body = {'model': 'test', 'previous_response_id': 'server-side', 'messages': [
        {'role': 'developer', 'content': 'Instruction'},
        {'role': 'user', 'content': 'Question'},
        {'role': 'assistant', 'tool_calls': [{'id': 'c1', 'type': 'function', 'function': {'name': 'query', 'arguments': '{}'}}]},
        {'role': 'tool', 'tool_call_id': 'c1', 'content': 'NeverStoreResult'},
        {'type': 'reasoning', 'encrypted_content': 'opaque-private-value'},
    ]}
    result = measure_components(body, body, token_counter=len)
    assert result['complete'] is False
    assert result['tools'][0]['name'] == 'query'
    assert result['tools'][0]['result_before'] == result['tools'][0]['result_after'] > 0
    assert all(row['before'] == row['after'] for row in result['components'])
    assert 'opaque-private-value' not in json.dumps(result)
    assert 'NeverStoreResult' not in json.dumps(result)
    assert all(row['before'] < len(json.dumps(body)) for row in result['components'])


def test_component_totals_do_not_depend_on_recent_request_limit():
    ledger = ComponentUsageLedger()
    measurement = measure_components({'input': '123456'}, {'input': '123'}, token_counter=len)
    for i in range(240):
        ledger.append(f'tap-{i}', measurement)
    snapshot = ledger.snapshot()
    assert snapshot['requests'] == 240
    assert snapshot['components'][0]['before'] == 1440
    assert snapshot['components'][0]['after'] == 720
    assert snapshot['latest']['request_id'] == 'tap-239'


def test_live_component_usage_is_available_before_upstream_finishes(tmp_path):
    received, release = threading.Event(), threading.Event()
    class Upstream(BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def do_POST(self):
            self.rfile.read(int(self.headers['Content-Length']))
            received.set()
            release.wait(3)
            body = b'{"usage":{"input_tokens":123,"output_tokens":4}}'
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    server = ThreadingHTTPServer(('127.0.0.1', 0), Upstream)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    compressor = UnifiedInputCompressor('structure', source_store=SourceStore(tmp_path / 'sources'))
    tap = RequestTokenTap(f'http://127.0.0.1:{server.server_port}/v1', input_compressor=compressor).start()
    responses = []
    request = {'model': 'test', 'input': [
        {'role': 'user', 'content': 'Summarize'},
        {'type': 'function_call', 'call_id': 'c1', 'name': 'read_file', 'arguments': '{}'},
        {'type': 'function_call_output', 'call_id': 'c1', 'output': json.dumps([{'record_identifier': i, 'status': 'pending'} for i in range(100)])}]}
    client = threading.Thread(target=lambda: responses.append(httpx.post(tap.local_base_url + '/responses', json=request, trust_env=False)), daemon=True)
    try:
        client.start()
        assert received.wait(2)
        deadline = time.monotonic() + 2
        while not tap.stats_dict()['component_usage']['requests'] and time.monotonic() < deadline:
            time.sleep(.01)
        panel = token_panel_snapshot(tmp_path, provider_snapshot=tap.stats_dict())
        assert panel['breakdown']['requests'] == 1
        assert panel['breakdown']['tools'][0]['saved'] > 0
        assert panel['official']['total_tokens'] is None
        release.set()
        client.join(3)
        assert responses[0].status_code == 200
    finally:
        release.set()
        client.join(3)
        tap.stop(); server.shutdown(); server.server_close(); thread.join(2)


def test_old_run_has_no_fabricated_component_values(tmp_path):
    panel = token_panel_snapshot(tmp_path, provider_snapshot={'input_compression': {'requests': 2,
        'full_request_tokens_before_estimate': 100, 'full_request_tokens_after_estimate': 50}})
    assert panel['local']['saved'] == 50
    assert panel['breakdown']['source'] == 'unavailable'
    assert panel['breakdown']['tools'] == []
    assert all(row['before'] is None and row['after'] is None for row in panel['breakdown']['components'])


def test_fail_open_sent_measurements_override_attempted_compression(tmp_path):
    actual = measure_components({'input': 'KeepOriginal'}, {'input': 'KeepOriginal'}, token_counter=len)
    ledger = ComponentUsageLedger()
    ledger.append('tap-1', actual)
    attempted = {'full_request_tokens_before_estimate': 100, 'full_request_tokens_after_estimate': 20}
    panel = token_panel_snapshot(tmp_path, provider_snapshot={
        'input_compression': {'requests': 1, 'compressed_requests': 1, **attempted},
        'component_usage': ledger.snapshot(),
        'usage_ledger': {'recent_requests': [{'request_id': 'tap-1',
            'compression': attempted, 'component_usage': actual}]}})
    assert panel['local']['saved'] == panel['local']['compressed_requests'] == 0
    assert panel['recent_requests'][0]['before'] == panel['recent_requests'][0]['after'] == actual['request_before']
    assert panel['breakdown']['latest']['components'][1]['saved'] == 0
