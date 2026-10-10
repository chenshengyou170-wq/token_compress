"""Host-side tool discovery. The HTTP compressor never deletes tool definitions."""
from __future__ import annotations

import copy
import hashlib
import json


class DeferredToolRegistry:
    def __init__(self, definitions: list[dict]):
        self._definitions = {}
        for tool in definitions:
            name = tool.get('name')
            if (tool.get('type') != 'function' or not isinstance(name, str) or not name
                    or not isinstance(tool.get('parameters'), dict) or name in self._definitions):
                raise ValueError('unique trusted function definitions required')
            self._definitions[name] = copy.deepcopy(tool)

    def catalog(self) -> list[dict]:
        return [{'name': name, 'description': tool.get('description', '')}
                for name, tool in self._definitions.items()]

    def load(self, names: list[str]) -> list[dict]:
        if (not isinstance(names, list) or not names or len(names) > 10
                or any(not isinstance(n, str) or n not in self._definitions for n in names)
                or len(set(names)) != len(names)):
            raise ValueError('load 1 to 10 known tool names')
        return [copy.deepcopy(self._definitions[name]) for name in names]

    def responses_tools(self, existing: list[dict] | None = None) -> list[dict]:
        """Use only in a host that handles tool_search_call. Preserve existing search."""
        result = copy.deepcopy(existing or [])
        if any(t.get('type') == 'tool_search' for t in result):
            return result
        result.append({'type': 'tool_search', 'execution': 'client',
            'description': 'Load tool definitions from this catalog: ' + json.dumps(self.catalog(), ensure_ascii=False),
            'parameters': {'type': 'object', 'properties': {'names': {'type': 'array', 'items': {'type': 'string', 'enum': list(self._definitions)}, 'minItems': 1, 'maxItems': 10}},
                           'required': ['names'], 'additionalProperties': False}})
        return result

    def handle_search(self, call: dict) -> dict:
        if call.get('type') != 'tool_search_call' or call.get('execution') != 'client' or not isinstance(call.get('call_id'), str):
            raise ValueError('client tool_search_call required')
        arguments = call.get('arguments')
        if not isinstance(arguments, dict) or set(arguments) != {'names'}:
            raise ValueError('invalid tool search arguments')
        definitions = self.load(arguments['names'])
        return {'type': 'tool_search_output', 'execution': 'client', 'call_id': call['call_id'],
                'status': 'completed', 'tools': [{**tool, 'defer_loading': True} for tool in definitions]}


def with_prompt_cache_key(body: dict, *, namespace: str) -> dict:
    """Host opt-in: stable cache routing without reordering instructions/tools.

    A cache key does not reduce input length or guarantee a provider cache hit.
    Never call this implicitly from the byte-forwarding proxy.
    """
    if not namespace:
        raise ValueError('cache namespace required')
    result = copy.deepcopy(body)
    if 'prompt_cache_key' not in result:
        stable = {k: body[k] for k in ('model', 'instructions', 'tools', 'text', 'response_format') if k in body}
        messages = body.get('messages')
        if isinstance(messages, list):
            prefix = []
            for message in messages:
                if message.get('role') not in {'system', 'developer'}:
                    break
                prefix.append(message)
            stable['messages'] = prefix
        digest = hashlib.sha256((namespace + '\0' + json.dumps(stable, ensure_ascii=False, sort_keys=True)).encode()).hexdigest()
        result['prompt_cache_key'] = 'lingmou-' + digest[:48]
    return result
