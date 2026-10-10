#!/usr/bin/env python3
"""Minimal host loop for deferred tools and source rereads.

Default: deterministic local transport. --live uses OPENAI_API_KEY and the
official Responses API; this example never reads Codex login credentials.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Callable

import httpx

from codexscope.compression_models import normalize_usage
from codexscope.context_tools import SOURCE_READ_TOOL
from codexscope.deferred_tools import DeferredToolRegistry, with_prompt_cache_key
from codexscope.reference_selection import SourceStore
from codexscope.request_usage_ledger import summarize_task


def run_task(send: Callable[[dict], dict], store: SourceStore, prompt: str, *, model: str) -> dict:
    registry = DeferredToolRegistry([SOURCE_READ_TOOL])
    tools = registry.responses_tools()
    inputs = [{'role': 'user', 'content': prompt}]
    loaded = set()
    records, trace = [], []
    purpose = 'generation'
    for _ in range(8):
        body = with_prompt_cache_key({'model': model, 'input': inputs, 'tools': tools}, namespace='lingmou-example')
        response = None
        for attempt in (1, 2):
            record = {'task_id': 'source-demo', 'purpose': purpose, 'attempt': attempt, 'attempt_source': 'host',
                      'accounting_labelled': True, 'official_usage': None, 'status': 'failed'}
            try:
                response = send(body)
                record.update(status='completed', official_usage=normalize_usage(response.get('usage')))
                break
            except (httpx.HTTPError, TimeoutError):
                if attempt == 2: raise
            finally:
                records.append(record)
        output = response.get('output', [])
        inputs.extend(output)
        purpose = 'generation'
        handled = False
        for item in output:
            if item.get('type') == 'tool_search_call':
                result = registry.handle_search(item)
                loaded.update(t['name'] for t in result['tools'])
                inputs.append(result)
                trace.append({'event': 'load', 'names': sorted(loaded)})
                handled = True
            elif item.get('type') == 'function_call':
                if item.get('name') not in loaded or item['name'] != 'lingmou_source_read':
                    raise ValueError('tool must be discovered before execution')
                arguments = json.loads(item['arguments'])
                result = store.read(**arguments)
                inputs.append({'type': 'function_call_output', 'call_id': item['call_id'],
                               'output': json.dumps(result, ensure_ascii=False)})
                trace.append({'event': 'reread', 'start_line': result['start_line'], 'end_line': result['end_line']})
                purpose = 'reread'
                handled = True
        if not handled:
            texts = [part.get('text', '') for item in output if item.get('type') == 'message'
                     for part in item.get('content', []) if part.get('type') == 'output_text']
            return {'text': '\n'.join(texts), 'trace': trace, 'requests': records, 'usage': summarize_task(records)}
    raise RuntimeError('example exceeded its turn limit')


def simulated_transport(source_id: str):
    step = 0
    def send(body):
        nonlocal step
        step += 1
        if step == 1:
            assert all(t['type'] != 'function' for t in body['tools'])
            output = [{'type': 'tool_search_call', 'execution': 'client', 'call_id': 'search1',
                       'status': 'completed', 'arguments': {'names': ['lingmou_source_read']}}]
        elif step == 2:
            assert body['input'][-1]['tools'][0]['parameters'] == SOURCE_READ_TOOL['parameters']
            output = [{'type': 'function_call', 'name': 'lingmou_source_read', 'call_id': 'read1',
                       'arguments': json.dumps({'source_id': source_id, 'start_line': 2, 'end_line': 2})}]
        else:
            source = json.loads(body['input'][-1]['output'])
            output = [{'type': 'message', 'role': 'assistant', 'content': [{'type': 'output_text', 'text': source['text']}]}]
        return {'output': output}  # Local simulation has no official provider usage.
    return send


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--store', type=Path, required=True)
    parser.add_argument('--live', action='store_true')
    parser.add_argument('--model', default='gpt-6-astra')
    args = parser.parse_args()
    store = SourceStore(args.store)
    source_id = store.put('Reference header.\nApproval is required before refund.\nEnd.\n')
    if args.live:
        key = os.environ.get('OPENAI_API_KEY')
        if not key: parser.error('OPENAI_API_KEY required for --live')
        def send(body):
            with httpx.Client(timeout=90, follow_redirects=False) as client:
                response = client.post('https://api.openai.com/v1/responses', json=body, headers={'Authorization': 'Bearer ' + key})
                response.raise_for_status()
                return response.json()
    else:
        send = simulated_transport(source_id)
    result = run_task(send, store, f'Use the source reader to return exact original line 2 from source_id={source_id}.', model=args.model)
    print(json.dumps({'simulated': not args.live, **result}, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
