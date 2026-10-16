"""Numeric attribution of actual outbound requests; no message bodies are retained."""
from __future__ import annotations

import copy
import re
import threading
from collections import defaultdict

from .compression_boundary import transform_data
from .proxy_usage import default_token_counter
from .structural_compression import dumps


COMPONENTS = {
    'instructions': ('系统与开发者指令', True),
    'user': ('当前用户消息', True),
    'history': ('对话历史', True),
    'tool_definitions': ('工具定义', True),
    'tool_calls': ('工具调用参数', True),
    'tool_results': ('工具返回', False),
    'references': ('显式参考材料', False),
    'output_format': ('输出格式', True),
    'other': ('其他请求字段', True),
}
_TOOL_LIMIT = 128


def _tool_name(value):
    return value if isinstance(value, str) and re.fullmatch(r'[\w.:/-]{1,128}', value) else 'unknown'


def _tool_calls(body):
    result = {}
    items = body.get('messages', body.get('input'))
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        if item.get('type') in {'function_call', 'custom_tool_call'}:
            result[item.get('call_id')] = _tool_name(item.get('name'))
        for call in item.get('tool_calls', []) or []:
            if isinstance(call, dict):
                result[call.get('id')] = _tool_name((call.get('function') or {}).get('name'))
    return result


def measure_components(before: dict, after: dict, *, token_counter=None, incomplete=False) -> dict:
    """Inputs have binary media stripped by the relay. Counts are local estimates.

    Each component is tokenized independently. Framing and tokenizer boundaries
    mean component sums need not equal serialized whole-request estimates.
    """
    count, tokenizer = (token_counter, 'custom') if token_counter else default_token_counter(before.get('model', 'unknown-model'))
    names = {**_tool_calls(before), **_tool_calls(after)}
    opaque = False

    def partition(body):
        components, tools = defaultdict(int), {}

        def strip_opaque(value):
            nonlocal opaque
            if isinstance(value, list):
                return [strip_opaque(item) for item in value]
            if not isinstance(value, dict):
                return value
            result = {}
            for key, item in value.items():
                if key == 'encrypted_content':
                    opaque = True
                else:
                    result[key] = strip_opaque(item)
            return result

        def add(kind, value, tool=None, part=None):
            value = strip_opaque(value)
            tokens = int(count(value if isinstance(value, str) else dumps(value)))
            if tokens < 0:
                raise ValueError('invalid token count')
            components[kind] += tokens
            if tool is not None:
                if tool not in tools and len(tools) >= _TOOL_LIMIT:
                    tool = '__other_tools__'
                row = tools.setdefault(tool, {'definition': 0, 'call': 0, 'result': 0})
                row[part] += tokens

        def user_content(value):
            if isinstance(value, str):
                def reference(text):
                    add('references', text)
                    return ''
                return transform_data(value, 'user', reference)
            if isinstance(value, list):
                return [user_content(item) for item in value]
            if isinstance(value, dict) and value.get('type') in {'text', 'input_text'}:
                return {**value, 'text': user_content(value.get('text', ''))}
            return value

        if 'instructions' in body:
            add('instructions', body['instructions'])
        for key in ('tools', 'functions'):
            definitions = body.get(key)
            if isinstance(definitions, list):
                for definition in definitions:
                    if isinstance(definition, dict):
                        function = definition.get('function') or definition
                        add('tool_definitions', definition, _tool_name(function.get('name')), 'definition')
                    else:
                        add('tool_definitions', definition)
        for key in ('input', 'messages'):
            items = body.get(key)
            if isinstance(items, str):
                add('user', user_content(items))
                continue
            if not isinstance(items, list):
                continue
            latest_user = max((i for i, item in enumerate(items) if isinstance(item, dict) and item.get('role') == 'user'), default=-1)
            for index, item in enumerate(items):
                if not isinstance(item, dict):
                    add('other', item)
                    continue
                kind, role = item.get('type'), item.get('role')
                if kind == 'additional_tools' and isinstance(item.get('tools'), list):
                    for definition in item['tools']:
                        if isinstance(definition, dict):
                            function = definition.get('function') or definition
                            add('tool_definitions', definition, _tool_name(function.get('name')), 'definition')
                        else:
                            add('tool_definitions', definition)
                    add('other', {k: v for k, v in item.items() if k != 'tools'})
                elif kind in {'function_call', 'custom_tool_call'}:
                    add('tool_calls', item, _tool_name(item.get('name')), 'call')
                elif kind in {'function_call_output', 'custom_tool_call_output'} or role in {'tool', 'function'}:
                    tool = names.get(item.get('call_id', item.get('tool_call_id')), _tool_name(item.get('name')))
                    add('tool_results', item, tool, 'result')
                elif role in {'system', 'developer'}:
                    add('instructions', item)
                elif role == 'user':
                    add('user' if index == latest_user else 'history', {**item, 'content': user_content(item.get('content', ''))})
                else:
                    for call in item.get('tool_calls', []) or []:
                        if isinstance(call, dict):
                            add('tool_calls', call, _tool_name((call.get('function') or {}).get('name')), 'call')
                    rest = {k: v for k, v in item.items() if k != 'tool_calls'}
                    if rest:
                        add('history' if role == 'assistant' or kind == 'reasoning' else 'other', rest)
        if 'response_format' in body:
            add('output_format', body['response_format'])
        text = body.get('text')
        if isinstance(text, dict) and 'format' in text:
            add('output_format', text['format'])
        excluded = {'instructions', 'input', 'messages', 'tools', 'functions', 'response_format'}
        other = {k: v for k, v in body.items() if k not in excluded}
        if isinstance(other.get('text'), dict):
            other['text'] = {k: v for k, v in other['text'].items() if k != 'format'}
            if not other['text']:
                del other['text']
        if other:
            add('other', other)
        return components, tools

    before_components, before_tools = partition(before)
    after_components, after_tools = partition(after) if after != before else (before_components, before_tools)
    components = [{'id': key, 'before': before_components.get(key, 0), 'after': after_components.get(key, 0)}
                  for key in COMPONENTS if key in before_components or key in after_components]
    tools = []
    for name in sorted(before_tools.keys() | after_tools.keys()):
        row = {'name': name}
        for part in ('definition', 'call', 'result'):
            row[part + '_before'] = before_tools.get(name, {}).get(part, 0)
            row[part + '_after'] = after_tools.get(name, {}).get(part, 0)
        row['before'] = sum(row[part + '_before'] for part in ('definition', 'call', 'result'))
        row['after'] = sum(row[part + '_after'] for part in ('definition', 'call', 'result'))
        tools.append(row)
    return {'components': components, 'tools': tools, 'tokenizer': tokenizer,
            'request_before': int(count(dumps(before))), 'request_after': int(count(dumps(after))),
            'complete': not (incomplete or opaque or any(before.get(key) for key in ('previous_response_id', 'conversation', 'prompt')))}


class ComponentUsageLedger:
    """Accumulate once per successfully forwarded request, including live streams."""
    def __init__(self):
        self._lock = threading.Lock()
        self.requests = 0
        self.incomplete_requests = 0
        self.request_before = 0
        self.request_after = 0
        self.compressed_requests = 0
        self.components = {}
        self.tools = {}
        self.latest = None

    def append(self, request_id: str, measurement: dict):
        with self._lock:
            self.requests += 1
            self.incomplete_requests += int(not measurement['complete'])
            self.request_before += measurement['request_before']
            self.request_after += measurement['request_after']
            self.compressed_requests += int(measurement['request_before'] > measurement['request_after'])
            for kind, key in (('components', 'id'), ('tools', 'name')):
                target = getattr(self, kind)
                observed, changed = set(), set()
                for incoming in measurement[kind]:
                    identity = incoming[key]
                    if kind == 'tools' and identity not in target and len(target) >= _TOOL_LIMIT:
                        identity = '__other_tools__'
                    row = target.setdefault(identity, {key: identity, 'requests': 0, 'compressed_requests': 0})
                    row['requests'] += int(identity not in observed)
                    if incoming['before'] > incoming['after'] and identity not in changed:
                        row['compressed_requests'] += 1
                        changed.add(identity)
                    observed.add(identity)
                    for name, value in incoming.items():
                        if name != key:
                            row[name] = row.get(name, 0) + value
            self.latest = {'request_id': request_id, **copy.deepcopy(measurement)}

    def snapshot(self):
        with self._lock:
            return {'requests': self.requests, 'incomplete_requests': self.incomplete_requests,
                    'request_before': self.request_before, 'request_after': self.request_after,
                    'compressed_requests': self.compressed_requests,
                    'components': copy.deepcopy(list(self.components.values())),
                    'tools': copy.deepcopy(list(self.tools.values())), 'latest': copy.deepcopy(self.latest)}
