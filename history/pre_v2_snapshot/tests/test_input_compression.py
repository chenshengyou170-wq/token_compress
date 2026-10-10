from __future__ import annotations

import json

import pytest

from codexscope.input_compression import ResponsesInputCompressor, compress_prose


def test_prose_preserves_conditions_negations_quantities_and_literals():
    text = (
        'Please read the report in order to check the payment. '
        'You must not retry the payment if verification fails; only refund after approval. '
        'At least 20 people, no more than 30, $12.50. '
        'Keep "the exact output" and `a = "the result"` unchanged. '
        'Read https://example.test/the/a and /tmp/the/a. '
        'The Hague and a is the variable name. '
        '请你进行一下核对，不得删除原始数据；只有审批后才允许上传。'
    )
    result = compress_prose(text)
    assert len(result) < len(text)
    for fragment in (
        'must not retry payment if verification fails',
        'only refund after approval', 'At least 20 people', 'no more than 30', '$12.50',
        '"the exact output"', '`a = "the result"`', 'https://example.test/the/a', '/tmp/the/a',
        'The Hague', 'a is variable name', '不得删除原始数据；只有审批后才允许上传',
    ):
        assert fragment in result


@pytest.mark.parametrize('text', [
    '```python\na = "Please read the file"\nif a: print(a)\n```\n',
    '~~~text\nPlease do not remove the line.\n~~~\n',
    '```\nPlease keep the unclosed fence',
    '    print("Please read the file")\n',
    'curl --data "the exact payload" https://example.test/the/api\n',
    '| the key | a value |\n',
    '2026-10-08T12:00:00 ERROR: Please keep the original log\n',
    '{"value": "Please read the original text"}',
    '["the result", "a value"]',
    'Keep ``the ` literal`` intact.',
    'Keep `the unclosed literal',
    'Keep ' + '`' * 20_000 + ' the unclosed literal',
])
def test_code_and_structured_content_are_exact(text):
    assert compress_prose(text) == text


def test_responses_structure_multimodal_tool_arguments_and_reasoning_preserved():
    opaque = [
        {'type': 'function_call', 'name': 'run', 'call_id': 'call-1', 'arguments': '{"cmd":"echo the original"}'},
        {'type': 'function_call_output', 'call_id': 'call-1', 'output': '{"a":"the original"}'},
        {'type': 'reasoning', 'id': 'rs_1', 'encrypted_content': 'Please the a opaque', 'summary': []},
        {'type': 'item_reference', 'id': 'item_1'},
        {'type': 'future', 'text': 'Please keep the unknown item'},
    ]
    image = {'type': 'input_image', 'image_url': 'data:image/png;base64,AAAA', 'detail': 'high'}
    body = {
        'model': 'test', 'instructions': 'Please read the instructions in order to act.',
        'input': [
            {'type': 'message', 'role': 'developer', 'content': [{'type': 'input_text', 'text': 'Please read the policy. Do not remove the approval.'}]},
            {'type': 'message', 'role': 'user', 'content': [{'type': 'input_text', 'text': 'Please check the report.'}, image]},
            {'type': 'message', 'role': 'assistant', 'id': 'm1', 'phase': 'commentary', 'content': [{'type': 'output_text', 'text': 'I read the report.', 'annotations': []}]},
            *opaque,
            {'type': 'function_call_output', 'call_id': 'call-2', 'output': 'Please read the report in order to check the status.'},
        ],
        'tools': [{'type': 'function', 'name': 'run', 'description': 'Please keep the tool schema.', 'parameters': {'type': 'object'}}],
        'text': {'format': {'type': 'json_schema', 'schema': {'title': 'the exact schema'}}},
        'reasoning': {'effort': 'low'}, 'stream': True, 'metadata': {'label': 'the exact metadata'},
    }
    raw = json.dumps(body).encode()
    observations = []
    compressor = ResponsesInputCompressor(token_counter=len, on_observation=observations.append)
    changed = json.loads(compressor.compress(raw))
    assert changed['instructions'] != body['instructions']
    assert changed['input'][3:3 + len(opaque)] == opaque
    assert changed['input'][1]['content'][1] == image
    assert changed['input'][2]['phase'] == 'commentary'
    assert changed['input'][2]['id'] == 'm1'
    for key in ('tools', 'text', 'reasoning', 'stream', 'metadata', 'model'):
        assert changed[key] == body[key]
    assert body['input'][1]['content'][0]['text'] == 'Please check the report.'
    assert observations[0].changed_fields == 5
    assert set(observations[0].changed_roles) == {'instructions', 'developer', 'user', 'assistant', 'tool_output'}
    assert compressor.stats()['compression_model_calls'] == 0
    assert 'report' not in json.dumps(compressor.stats())


@pytest.mark.parametrize('reference', ['previous_response_id', 'conversation', 'prompt'])
def test_server_managed_history_is_not_rewritten(reference):
    raw = json.dumps({'input': 'Please read the report.', reference: 'server_ref'}).encode()
    compressor = ResponsesInputCompressor(token_counter=len)
    assert compressor.compress(raw) == raw
    assert compressor.stats()['skipped_requests'] == 1


@pytest.mark.parametrize('raw', [b'{broken', b'[]', b'null', b'{"input":42}', b'{"input":"first","input":"Please read the report"}', b'\xff'])
def test_unknown_invalid_and_duplicate_key_payloads_forward_exact_bytes(raw):
    assert ResponsesInputCompressor(token_counter=len).compress(raw) == raw


def test_token_growth_and_empty_candidates_forward_original_bytes():
    raw = b'{ "input": "Please read the report." }'
    counter = lambda text: 1 if text.startswith('Please') else 100
    assert ResponsesInputCompressor(token_counter=counter).compress(raw) == raw
    empty = b'{ "input": "Please " }'
    assert ResponsesInputCompressor(token_counter=len).compress(empty) == empty


def test_compressor_and_observer_failure_do_not_block_generation():
    def fail(*_args):
        raise RuntimeError('failure without content')

    raw = b'{"input":"Please read the report."}'
    compressor = ResponsesInputCompressor(token_counter=fail)
    assert compressor.compress(raw) == raw
    assert compressor.stats()['error_requests'] == 1
    compressor = ResponsesInputCompressor(token_counter=len, on_observation=fail)
    assert json.loads(compressor.compress(raw))['input'] == 'read report.'
