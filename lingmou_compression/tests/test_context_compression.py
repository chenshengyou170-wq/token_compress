import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from codexscope.context_compression import HybridInputCompressor, protect_text, restore_text
from codexscope.compression_models import normalize_usage
from codexscope.request_token_tap import RequestTokenTap
from codexscope.reference_selection import SourceStore
from codexscope.compression_boundary import reference_text


def test_protected_constraints_literals_and_numeric_order_survive():
    text = ('The invoice includes 27 items at "fixed" cost, stored in /tmp/orders.json. '
            'Do not submit payments unless approved. 不得重放支付。\n'
            '```python\namount = 2700\n```\n' + 'This is a detailed explanatory paragraph about the operations. '*8)
    masked, spans = protect_text(text)
    assert 'Do not submit' not in masked
    assert 'amount = 2700' not in masked
    assert restore_text(masked, spans) == text
    assert restore_text(masked.replace(spans[0][0], ''), spans) is None
    assert restore_text(masked + spans[0][0], spans) is None


def test_kimi_failure_or_lost_constraints_falls_back_and_does_not_leak():
    text = 'You must not transfer funds. ' + 'Background information about the service. '*20
    for rewriter in (lambda x: 'Transfer funds.', lambda x: (_ for _ in ()).throw(RuntimeError('secret'))):
        c = HybridInputCompressor(rewriter=rewriter, source_store=SourceStore(), token_counter=len)
        raw = json.dumps({'model':'test', 'input':reference_text(text)}).encode()
        assert c.compress(raw) == raw
        assert c.stats()['rejected_fields'] == 1
        assert 'secret' not in json.dumps(c.stats())


def test_structured_tool_data_and_duplicates_keep_protocol_and_latest():
    result = json.dumps({'unique_fact': 'P1004', 'rows': list(range(200))}, indent=2)
    calls = [{'type':'function_call','name':'read','call_id':str(i),'arguments':'{"path":"/tmp/data"}'} for i in range(2)]
    body = {'input':[calls[0], {'type':'function_call_output','call_id':'0','output':result},
                     calls[1], {'type':'function_call_output','call_id':'1','output':result}],
            'tools':[{'type':'function','name':'read'}], 'model':'gpt-6-astra'}
    c = HybridInputCompressor()
    got = json.loads(c.compress(json.dumps(body).encode()))
    assert got['input'][0] == calls[0] and got['input'][2] == calls[1]
    assert got['tools'] == body['tools']
    assert json.loads(got['input'][1]['output']) == json.loads(result)
    assert json.loads(got['input'][3]['output'])['base_call_id'] == '0'


def test_cached_kimi_rewrite_and_chat_opaque_fields():
    calls = []
    text = 'This is redundant explanatory scaffolding. '*20
    def rewrite(masked):
        calls.append(masked)
        return 'Explanatory scaffolding.'
    c = HybridInputCompressor(rewriter=rewrite, source_store=SourceStore(), token_counter=len)
    body = {'messages':[{'role':'user','content':reference_text(text)}, {'role':'assistant','content':'',
        'tool_calls':[{'id':'one','function':{'arguments':'{"n":42}'}}]}], 'model':'kimi-for-coding'}
    first = c.compress(json.dumps(body).encode())
    second = c.compress(json.dumps(body).encode())
    assert first == second and len(calls) == 1
    assert json.loads(first)['messages'][1] == body['messages'][1]
    assert c.stats()['cache_hits'] == 1


def test_task_text_gets_llm_budget_before_fixed_prefix_and_failed_retry_backs_off():
    calls = []
    def failed(text):
        calls.append(text)
        raise TimeoutError('service unavailable')
    c = HybridInputCompressor(rewriter=failed, source_store=SourceStore(), token_counter=len)
    body = {'instructions': 'Fixed instructions with verbose explanations. '*20,
            'input': reference_text('Task material with verbose explanations. '*20)}
    raw = json.dumps(body).encode()
    assert c.compress(raw) == raw
    assert calls[0].startswith('Task material')
    assert c.compress(raw) == raw and len(calls) == 1
    assert c.stats()['cache_hits'] == 1


def test_usage_normalization_distinguishes_missing_details_and_bad_totals():
    u = normalize_usage({'prompt_tokens':100,'completion_tokens':12,'total_tokens':112})
    assert u['reasoning_output_tokens'] is None and u['cached_input_tokens'] is None
    assert normalize_usage({'input_tokens':True,'output_tokens':12}) is None
    assert normalize_usage({'input_tokens':100,'output_tokens':12,'total_tokens':1}) is None
    assert normalize_usage({'input_tokens':100,'output_tokens':12,'input_tokens_details':{'cached_tokens':101}}) is None
    assert normalize_usage({'input_tokens':100,'output_tokens':12,'input_tokens_details':['broken']}) is None


def test_structured_tool_data_preserves_decimal_literals_and_duplicate_keys():
    values = ['{ "amount": 123456789.123456789, "note": " keep spaces " }',
              '{ "amount": 1, "amount": 2 }']
    body = {'input':[{'type':'function_call_output','call_id':str(i),'output':v} for i,v in enumerate(values)]}
    got = json.loads(HybridInputCompressor(token_counter=len).compress(json.dumps(body).encode()))
    assert got['input'][0]['output'] == '{"amount":123456789.123456789,"note":" keep spaces "}'
    assert got['input'][1]['output'] == values[1]


@pytest.mark.parametrize(('stream', 'has_content_type'), [(False, True), (True, True), (True, False)])
def test_chat_relay_records_official_usage_once_with_estimates(stream, has_content_type):
    received, records = [], []
    ready = threading.Event()
    usage = {'prompt_tokens':100,'completion_tokens':20,'total_tokens':120}
    class Upstream(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_POST(self):
            received.append(json.loads(self.rfile.read(int(self.headers['Content-Length']))))
            data = {'object':'chat.completion.chunk' if stream else 'chat.completion',
                    'model':'kimi-for-coding','usage':usage}
            raw = ('data: '+json.dumps(data)+'\n\n') * 2 + 'data: [DONE]\n\n' if stream else json.dumps(data)
            raw = raw.encode()
            self.send_response(200)
            if has_content_type:
                self.send_header('Content-Type','text/event-stream' if stream else 'application/json')
            self.send_header('Content-Length',str(len(raw)))
            self.end_headers(); self.wfile.write(raw)
    upstream = ThreadingHTTPServer(('127.0.0.1',0), Upstream)
    threading.Thread(target=upstream.serve_forever,daemon=True).start()
    def on_record(record): records.append(record); ready.set()
    tap = RequestTokenTap(f'http://127.0.0.1:{upstream.server_port}/v1',
        input_compressor=HybridInputCompressor(), on_request_usage=on_record).start()
    try:
        raw = {'model':'kimi-for-coding','messages':[{'role':'user','content':reference_text(json.dumps([{'record_identifier':i,'approved':False} for i in range(100)]))}], 'stream':stream}
        r = httpx.post(tap.local_base_url+'/chat/completions', json=raw)
        assert r.status_code == 200 and ready.wait(2)
        assert received[0]['messages'][0]['content'] != raw['messages'][0]['content']
        assert len(records) == 1
        assert records[0]['official_usage']['total_tokens'] == 120
        assert records[0]['input_tokens_after_estimate'] < records[0]['input_tokens_before_estimate']
        snapshot = tap.stats_dict()['usage_ledger']
        assert snapshot['totals']['official_total_tokens'] == 120
        assert 'Please read' not in json.dumps(snapshot)
    finally:
        tap.stop(); upstream.shutdown(); upstream.server_close()
