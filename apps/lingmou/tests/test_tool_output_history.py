import copy
import json

import pytest

from codexscope.full_compression import FullCompressionConfig, FullCompressionPipeline
from codexscope.reference_selection import SourceStore
from codexscope.tool_output_history import compact_tool_outputs
from codexscope.unified_compression import UnifiedInputCompressor


def result(number, *, name='exec', text=None, chat=False):
    text = text or '\n'.join(f'Page {number}, row {i}: measured value {i * 17}, preserve original evidence.' for i in range(100))
    identity = f'call-{number}'
    if chat:
        return [{'role': 'assistant', 'tool_calls': [{'id': identity, 'type': 'function',
            'function': {'name': name, 'arguments': '{}'}}]},
            {'role': 'tool', 'tool_call_id': identity, 'content': text}]
    return [{'type': 'custom_tool_call', 'call_id': identity, 'name': name, 'input': 'text(await tools.exec_command({cmd:"read paper"}));'},
            {'type': 'custom_tool_call_output', 'call_id': identity, 'output': text}]


@pytest.mark.parametrize('chat', [False, True])
def test_long_single_turn_archives_old_outputs_and_recovers_exact_original(chat):
    key, field = ('messages', 'content') if chat else ('input', 'output')
    items = [{'role': 'developer', 'content': 'Do not change numbers or task requirements.'},
             {'role': 'user', 'content': 'Make a paper PPT.'}]
    for n in range(7):
        items += result(n, chat=chat)
    if not chat:
        items.insert(2, {'type': 'reasoning', 'encrypted_content': 'opaque-state'})
        items.insert(3, {'type': 'additional_tools', 'tools': [{'type': 'function', 'name': 'source'}]})
    body = {key: items, 'tools': [{'type': 'function', 'name': 'exec', 'parameters': {'type': 'object'}}]}
    original = copy.deepcopy(body)
    store = SourceStore()
    changed = compact_tool_outputs(body, budget=14000, keep_results=2, count=len, store=store)
    assert changed == 5
    for index, (before, after) in enumerate(zip(original[key], body[key])):
        if before == after:
            continue
        assert {k: v for k, v in before.items() if k != field} == {k: v for k, v in after.items() if k != field}
        envelope = json.loads(after[field])
        assert envelope['$lingmou'] == 'tool-output/v1'
        recovered = store.read(envelope['source_id'], 1, envelope['total_lines'])
        assert recovered['text'] == before[field]
        assert before[field].startswith(envelope['head']) and before[field].endswith(envelope['tail'])
    assert body[key][-4:] == original[key][-4:]
    assert body['tools'] == original['tools']
    assert len(json.dumps(body)) < len(json.dumps(original)) * .5
    second = copy.deepcopy(body)
    compact_tool_outputs(second, budget=14000, keep_results=2, count=len, store=store)
    assert second == body


def test_pin_instruction_reads_failures_and_source_rereads():
    items = []
    for n, name in enumerate(('read_AGENTS.md', 'read_SKILL.md', 'lingmou_source_read', 'exec', 'exec')):
        items += result(n, name=name)
    items[7]['output'] = 'Process exited with code 1\n' + items[7]['output']
    body = {'input': items}
    original = copy.deepcopy(body)
    assert compact_tool_outputs(body, budget=1, keep_results=1, count=len, store=SourceStore()) == 0
    assert body == original


def test_multipart_keeps_images_exact_and_never_changes_pending_calls():
    body = {'input': result(0) + result(1) + [{'type': 'custom_tool_call', 'call_id': 'pending', 'name': 'exec', 'input': 'run()'}]}
    image = {'type': 'input_image', 'image_url': 'data:image/png;base64,AAAB', 'detail': 'high'}
    source = body['input'][1]['output']
    body['input'][1]['output'] = [{'type': 'input_text', 'text': source}, image]
    before = copy.deepcopy(body)
    assert compact_tool_outputs(body, budget=1, keep_results=1, count=len, store=SourceStore()) == 1
    assert body['input'][1]['output'][1] == image
    assert body['input'][0] == before['input'][0] and body['input'][-1] == before['input'][-1]
    assert body['input'][2:4] == before['input'][2:4]


@pytest.mark.parametrize('variant', ['quota', 'long_line', 'duplicate_id', 'unpaired', 'envelope', 'json_failure', 'nested_failure'])
def test_unrecoverable_or_ambiguous_outputs_stay_original(variant):
    body = {'input': result(0) + result(1)}
    store = SourceStore(max_bytes=1) if variant == 'quota' else SourceStore()
    if variant == 'long_line':
        body['input'][1]['output'] = 'x' * 250001
    elif variant == 'duplicate_id':
        body['input'][2]['call_id'] = body['input'][3]['call_id'] = 'call-0'
    elif variant == 'unpaired':
        body['input'][0]['call_id'] = 'other'
    elif variant == 'envelope':
        body['input'][1]['output'] = json.dumps({'$lingmou': 'supplied', 'text': 'x' * 8000})
    elif variant == 'json_failure':
        body['input'][1]['output'] = json.dumps({'exit_code': 1, 'output': 'x' * 8000})
    elif variant == 'nested_failure':
        body['input'][1]['output'] = json.dumps({'content': [{'type': 'text', 'text': json.dumps({'exit_code': 1, 'output': 'x' * 8000})}]})
    original = copy.deepcopy(body)
    assert compact_tool_outputs(body, budget=1, keep_results=1, count=len, store=store) == 0
    assert body == original


def test_full_pipeline_with_opaque_reasoning_pages_old_outputs_without_remote_calls():
    body = {'input': [{'role': 'user', 'content': 'Make a paper PPT.'},
                      {'type': 'reasoning', 'encrypted_content': 'opaque'}]}
    for n in range(8):
        body['input'] += result(n)
    config = FullCompressionConfig(tool_history_max_tokens=14000, tool_history_keep_results=2,
        max_remote_calls=0, max_remote_tokens=0)
    store = SourceStore()
    pipeline = FullCompressionPipeline(source_store=store, token_counter=len, local_backends={}, config=config)
    raw = json.dumps(body).encode()
    output, observation = pipeline.compress(raw)
    got = json.loads(output)
    assert observation.status == 'compressed' and observation.lossy_fields >= 6
    assert not observation.compression_calls
    assert got['input'][:2] == body['input'][:2]
    envelope = json.loads(got['input'][3]['output'])
    assert store.get(envelope['source_id']) == body['input'][3]['output']
    assert pipeline.snapshot()['stages'][1]['archived_outputs'] == 6
    # No source reader means full mode must not introduce unreadable references.
    plain, _ = UnifiedInputCompressor('full', token_counter=len).compress_observed(raw)
    assert 'tool-output/v1' not in plain.decode()


def test_disabled_budget_and_invalid_retention_setting():
    body = {'input': result(0) + result(1)}
    assert compact_tool_outputs(body, budget=0, keep_results=1, count=len, store=SourceStore()) == 0
    with pytest.raises(ValueError):
        FullCompressionConfig(tool_history_keep_results=0)
