import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from codexscope.full_compression import FullCompressionConfig, FullCompressionPipeline
from codexscope.reference_selection import SourceStore
from codexscope.request_token_tap import RequestTokenTap
from codexscope.token_panel import token_panel_snapshot
from codexscope.unified_compression import UnifiedInputCompressor


LONG = 'The purpose of this explanation is to describe the current inventory in a detailed manner.'
SHORT = 'Describe current inventory.'


class Rewriter:
    def __init__(self): self.calls = 0
    def chat(self, messages, **kwargs):
        self.calls += 1
        texts = json.loads(messages[-1]['content'])
        return {'text': json.dumps({k: v['text'].replace(LONG, SHORT) for k, v in texts.items()}),
                'finish_reason': 'stop', 'model': 'test',
                'usage': {'input_tokens': 12, 'output_tokens': 3, 'total_tokens': 15}}


def pipeline(**kwargs):
    return FullCompressionPipeline(source_store=SourceStore(), token_counter=len,
        client=kwargs.pop('client', Rewriter()), verifier=kwargs.pop('verifier', lambda pairs, calls: set(pairs)),
        config=kwargs.pop('config', FullCompressionConfig(min_model_tokens=0, min_saved_tokens=16,
            min_saved_ratio=.2, max_remote_calls=100, max_remote_tokens=1000000,
            allow_unfunded_remote=True, output_rewrite=True)),
        local_backends=kwargs.pop('local_backends', {}), **kwargs)


def test_text_components_compress_while_user_task_and_execution_stay_exact():
    body = {'model': 'test', 'instructions': LONG + '\nNever upload the secret.\n',
        'tools': [{'type': 'function', 'name': 'query', 'description': LONG,
                   'parameters': {'type': 'object', 'properties': {'limit': {'type': 'integer', 'description': LONG}}, 'required': ['limit']}}],
        'text': {'format': {'type': 'json_schema', 'schema': {'const': False}}},
        'input': [{'role': 'user', 'content': LONG}, {'role': 'assistant', 'content': LONG},
            {'type': 'function_call', 'call_id': 'c1', 'name': 'query', 'arguments': '{ "limit" : 100, "approved" : false }'},
            {'type': 'function_call_output', 'call_id': 'c1', 'output': json.dumps({'content': [{'type': 'text', 'text': LONG}], 'exit_code': 0})}]}
    out, observation = pipeline().compress(json.dumps(body).encode())
    got = json.loads(out)
    assert observation.status == 'compressed'
    assert got['instructions'] == SHORT + '\nNever upload the secret.\n'
    assert got['input'][0]['content'] == LONG
    assert got['input'][1]['content'] == SHORT
    assert got['tools'][0]['description'] == SHORT
    assert got['tools'][0]['parameters']['properties']['limit']['description'] == SHORT
    assert got['tools'][0]['name'] == 'query' and got['tools'][0]['parameters']['required'] == ['limit']
    assert got['input'][2]['call_id'] == got['input'][3]['call_id'] == 'c1'
    assert json.loads(got['input'][2]['arguments']) == {'limit': 100, 'approved': False}
    assert json.loads(got['input'][3]['output']) == {'content': [{'type': 'text', 'text': SHORT}], 'exit_code': 0}
    assert got['text'] == body['text']


def test_new_tool_outputs_are_not_starved_by_repeated_short_history():
    rewriter = Rewriter()
    compressor = pipeline(client=rewriter)
    items = [{'type': 'function_call_output', 'call_id': str(i), 'output': 'OK'} for i in range(20)]
    compressor.compress(json.dumps({'input': items}).encode())
    items.append({'type': 'function_call_output', 'call_id': 'new', 'output': LONG})
    first, _ = compressor.compress(json.dumps({'input': items}).encode())
    second, _ = compressor.compress(json.dumps({'input': items}).encode())
    assert json.loads(first)['input'][-1]['output'] == SHORT
    assert first == second and rewriter.calls == 1


def test_nested_mcp_json_is_compacted_and_prose_is_compressed_without_changing_facts():
    payload = {'inventory': 100, 'approved': False, 'content': LONG}
    wrapped = {'content': [{'type': 'text', 'text': json.dumps(payload, indent=4)}]}
    raw = json.dumps({'input': [{'type': 'function_call_output', 'call_id': 'x', 'output': json.dumps(wrapped)}]}).encode()
    output, observation = pipeline().compress(raw)
    tool = json.loads(json.loads(output)['input'][0]['output'])
    assert json.loads(tool['content'][0]['text']) == {**payload, 'content': SHORT}
    assert observation.status == 'compressed'


def test_rejected_semantic_candidate_preserves_request_and_reports_spend():
    raw = json.dumps({'instructions': LONG}).encode()
    output, observation = pipeline(verifier=lambda pairs, calls: set()).compress(raw)
    assert output == raw and observation.status == 'skipped'
    assert observation.compression_calls[0]['official_usage']['total_tokens'] == 15


def test_shortest_bad_candidate_does_not_hide_valid_model_candidate():
    def verify(pairs, calls):
        return {key for key, pair in pairs.items() if pair['short'] == SHORT}
    compressor = pipeline(verifier=verify, local_backends={'llmlingua2': lambda text: 'bad'})
    output, _ = compressor.compress(json.dumps({'input': [{'role': 'assistant', 'content': LONG}]}).encode())
    assert json.loads(output)['input'][0]['content'] == SHORT
    assert compressor.snapshot()['methods'][5]['rejected'] == 1


def test_blank_lines_and_fenced_code_survive_without_valid_rewrite():
    text = '\n\nKeep this.\n\n\n```python\nx = 100\n\nreturn False\n```\n\n\n'
    raw = json.dumps({'input': text}).encode()
    assert pipeline().compress(raw)[0] == raw


def test_literal_validation_handles_marker_digits_repeats_and_substrings():
    compressor = pipeline()
    text = 'GSM8K has 20x compression in example 1, cited in 2022 and 2022.'
    assert compressor._verification_pair(text, text, 'tool_output', 'Explain') is not None
    assert compressor._verification_pair(text, text.replace('20x', '10x'), 'tool_output', 'Explain') is None
    assert compressor._verification_pair(text, text.replace('and 2022', 'and 2023'), 'tool_output', 'Explain') is None


@pytest.mark.parametrize('compact_completion', [False, True, 'named_event'])
def test_output_reduction_is_separate_from_original_provider_stream_and_usage(tmp_path, compact_completion):
    source_store = SourceStore(tmp_path / 'sources')
    compressor = UnifiedInputCompressor('full', source_store=source_store, token_counter=len)
    compressor._full_pipeline = pipeline()
    compressor._engine_key = ('full', 'test')
    payload = {'type': 'response.completed', 'response': {'model': 'test',
        'usage': {'input_tokens': 123, 'output_tokens': 45, 'total_tokens': 168},
        'output': [{'type': 'message', 'phase': 'final_answer', 'content': [{'type': 'output_text', 'text': LONG}]}]}}
    item = payload['response']['output'][0]
    if compact_completion:
        payload['response'].pop('output')
    completed_item = {'type': 'response.output_item.done', 'item': item}
    def encode(event):
        if compact_completion == 'named_event':
            event = dict(event)
            return 'event: ' + event.pop('type') + '\ndata: ' + json.dumps(event) + '\n\n'
        return 'data: ' + json.dumps(event) + '\n\n'
    wire = (encode(completed_item) + encode(payload)).encode()
    class Upstream(BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def do_POST(self):
            self.rfile.read(int(self.headers['Content-Length']))
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Content-Length', str(len(wire)))
            self.end_headers()
            self.wfile.write(wire)
    server = ThreadingHTTPServer(('127.0.0.1', 0), Upstream)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    recorded = threading.Event()
    tap = RequestTokenTap(f'http://127.0.0.1:{server.server_port}/v1', input_compressor=compressor,
                          on_request_usage=lambda _: recorded.set()).start()
    try:
        response = httpx.post(tap.local_base_url + '/responses', json={'model': 'test', 'input': LONG, 'stream': True}, trust_env=False)
        assert response.content == wire and recorded.wait(2)
        panel = token_panel_snapshot(tmp_path, provider_snapshot=tap.stats_dict())
        assert panel['output']['before'] == len(LONG) and panel['output']['after'] == len(SHORT)
        assert panel['output']['responses'] == 1
        assert panel['output']['billing_reduction'] is False
        assert panel['official']['total_tokens'] == 168 and panel['official']['output_tokens'] == 45
        assert panel['official']['compression_tokens'] == 15  # Only the explicitly enabled output rewrite.
        assert panel['local']['saved'] == 0  # Output cleanup is not input saving.
    finally:
        tap.stop(); server.shutdown(); server.server_close(); thread.join(timeout=2)
