#!/usr/bin/env python3
"""Official-usage A/B for a labelled synthetic duplicate tool-history fixture.

This isolates local structure compaction; it is not a real long-horizon agent run.
"""
import argparse
import json
import time
from pathlib import Path

from codexscope.compression_models import KimiClient
from codexscope.context_compression import HybridInputCompressor
from codexscope.request_token_tap import RequestTokenTap
from benchmark_input_compression import write_json
from compare_prompt_compression import read_object


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--models', nargs='+', default=['kimi-for-coding', 'k3'])
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    data = {'rows': [{'id': f'P{i:04d}', 'amount': 10000+i, 'status': 'settled'} for i in range(1, 301)],
            'retry_authorized': False, 'footer_sha': 'END300'}
    result = json.dumps(data, ensure_ascii=False, indent=2)
    messages = [{'role': 'user', 'content': 'Read two snapshots of the same payment dataset.'}]
    for i in range(2):
        messages.extend([
            {'role': 'assistant', 'content': None, 'tool_calls': [
                {'id': f'snapshot_{i}', 'type': 'function',
                 'function': {'name': 'read_snapshot', 'arguments': '{}'}}]},
            {'role': 'tool', 'tool_call_id': f'snapshot_{i}', 'content': result},
        ])
    messages.append({'role': 'user', 'content': 'The tool results are two snapshots of the same dataset. Do not sum '
        'the two snapshots. Return exactly JSON with keys row_count (number of rows in one snapshot), '
        'first_id, last_id, last_amount, retry_authorized (boolean), footer_sha. No tools or explanation.'})
    expected = {'row_count': 300, 'first_id': 'P0001', 'last_id': 'P0300', 'last_amount': 10300,
                'retry_authorized': False, 'footer_sha': 'END300'}
    write_json(args.out/'fixture.json', {'source': 'synthetic duplicate tool-history fixture; no tool was actually executed',
                                        'messages': messages, 'expected': expected})
    records = []
    compressor = HybridInputCompressor()
    for model in args.models:
        for repeat in range(2):
            for mode in (['off', 'hybrid'] if repeat == 0 else ['hybrid', 'off']):
                path = args.out/f'{model}.r{repeat}.{mode}.json'
                if path.exists():
                    records.append(json.loads(path.read_text())); continue
                started = time.monotonic(); observed = []
                record = {'model': model, 'repeat': repeat, 'mode': mode, 'status': 'error'}
                client = KimiClient(model=model, timeout_s=120)
                tap = RequestTokenTap(client.base_url, on_request_usage=observed.append,
                    input_compressor=compressor if mode == 'hybrid' else None).start()
                client.base_url = tap.local_base_url
                try:
                    response = client.chat(messages)
                    record.update(usage=response['usage'], raw_usage=response['raw_usage'], response=response['text'])
                    answer = read_object(response['text'])
                    checks = {k: type(answer.get(k)) is type(v) and answer.get(k) == v for k,v in expected.items()}
                    record.update(status='completed', quality_passed=all(checks.values()) and set(answer)==set(expected), checks=checks)
                except Exception as exc:
                    record['error_type'] = type(exc).__name__
                finally:
                    tap.stop()
                record.update(latency_s=round(time.monotonic()-started,3), request_usage=observed)
                write_json(path, record); records.append(record)
                write_json(args.out/'results.json', {'fixture':'synthetic duplicate tool history', 'records':records})
                print(json.dumps({k:record.get(k) for k in ('model','repeat','mode','status','quality_passed','usage','latency_s')},ensure_ascii=False),flush=True)


if __name__ == '__main__':
    main()
