#!/usr/bin/env python3
"""Compare identical Codex inputs with the local request compressor off/on."""

from __future__ import annotations

import argparse
import json
import tempfile
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from codexscope.context_compression import make_input_compressor
from compare_prompt_compression import Provider, read_object, write_json


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--model', default='gpt-6-astra')
    parser.add_argument('--compression-mode', choices=['caveman', 'hybrid', 'kimi'], default='caveman')
    parser.add_argument('--fixtures', type=Path, default=ROOT / 'evidence/token_compression_20261008/comparison')
    parser.add_argument('--tool-probe-only', action='store_true', help='verify one real read-only printf tool round-trip, off/on')
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    helper = ROOT / 'scripts/codex_usage_probe.py'
    report = {
        'schema_version': 'lingmou.codex-input-compression-ab.v1',
        'started_at': datetime.now(UTC).isoformat(), 'model': args.model,
        'method': f'{args.compression_mode} in RequestTokenTap, after Codex assembles the complete request',
        'usage_source': 'codex_exec_turn_completed',
        'cases': [],
        'limitations': [
            'Two fixtures and fixed-answer retention checks are not general semantic-equivalence evidence.',
            'Official input_tokens includes cached_input_tokens; these are token counts, not monetary costs.',
            'Local compressor counters are labelled estimates and never substitute for official usage.',
        ],
    }
    with tempfile.TemporaryDirectory(prefix='lingmou-input-compression-') as workspace:
        provider = Provider(helper, args.model, Path(workspace), args.out)
        report['codex_version'] = provider.version
        for index, case_id in enumerate(() if args.tool_probe_only else ('english_api', 'chinese_bank')):
            case = json.loads((args.fixtures / f'{case_id}.fixture.json').read_text())
            write_json(args.out / f'{case_id}.fixture.json', case)
            prompt = (
                'Use the supplied material only. No tools. Return the requested JSON object.\n\n'
                + '<task>\n' + case['prompt'] + '\n</task>\n<context>\n' + case['context'] + '\n</context>'
            )
            (args.out / f'{case_id}.input.txt').write_text(prompt)
            row = {'id': case_id, 'label': case['label'], 'variants': {}}
            order = ('off', args.compression_mode) if index == 0 else (args.compression_mode, 'off')
            row['execution_order'] = list(order)
            for mode in order:
                observations = []
                provider.input_compressor = make_input_compressor(mode)
                if provider.input_compressor:
                    provider.input_compressor.on_observation = observations.append
                record = provider.call(f'{case_id}.{mode}', prompt)
                answer = read_object(record['response'])
                checks = {
                    key: type(answer.get(key)) is type(value) and answer.get(key) == value
                    for key, value in case['expected'].items()
                }
                row['variants'][mode] = {
                    'usage': record['usage'], 'latency_s': record['latency_s'],
                    'checks': checks, 'passed': sum(checks.values()), 'total': len(checks),
                    'exact_keys': set(answer) == set(case['expected']), 'answer': answer,
                    'caller_prompt_sha256': record['prompt_sha256'],
                    'compression_observations': [asdict(item) for item in observations],
                }
                if mode != 'off' and not any(item.status == 'compressed' for item in observations):
                    raise RuntimeError('compressor did not rewrite the actual model request')
            base = row['variants']['off']['usage']
            changed = row['variants'][args.compression_mode]['usage']
            row['input_tokens_saved'] = base['input_tokens'] - changed['input_tokens']
            row['input_reduction_percent'] = round(row['input_tokens_saved'] / base['input_tokens'] * 100, 3)
            row['total_tokens_saved'] = base['input_tokens'] + base['output_tokens'] - changed['input_tokens'] - changed['output_tokens']
            assert row['variants']['off']['caller_prompt_sha256'] == row['variants'][args.compression_mode]['caller_prompt_sha256']
            report['cases'].append(row)
            write_json(args.out / 'results.json', report)
        if args.tool_probe_only:
            marker = 'CODEX_INPUT_COMPRESSION_OK_20261008'
            prompt = (
                "This is a read-only tool protocol test. Use the local command tool exactly once "
                f"to run `printf '%s\\n' '{marker}'`. Do not call any other tools, read files, "
                "write files or access the network. After the command completes, reply with "
                "exactly its output line, without explanation. Do not answer before running it."
            )
            (args.out / 'tool_roundtrip.input.txt').write_text(prompt)
            provider.allow_tool_calls = True
            records = {}
            for mode in ('off', args.compression_mode):
                observations = []
                provider.input_compressor = make_input_compressor(mode)
                if provider.input_compressor:
                    provider.input_compressor.on_observation = observations.append
                record = provider.call(f'tool_roundtrip.{mode}', prompt)
                items = record.get('tool_items', [])
                passed = (
                    record['response'].strip() == marker and len(items) == 1
                    and items[0].get('type') == 'command_execution'
                    and items[0].get('exit_code') == 0
                    and items[0].get('aggregated_output', '').strip() == marker
                )
                records[mode] = {
                    'usage': record['usage'], 'passed': passed,
                    'observed_request_count': record['observed_request_count'],
                    'caller_prompt_sha256': record['prompt_sha256'],
                    'compression_observations': [asdict(item) for item in observations],
                    'request_usage': record['tap_stats'].get('usage_ledger'),
                }
                write_json(args.out / 'tool_roundtrip_checks.json', records)
                if not passed:
                    raise RuntimeError(f'tool round-trip failed: {mode}')
            report['tool_roundtrip'] = records
    report['completed_at'] = datetime.now(UTC).isoformat()
    write_json(args.out / 'results.json', report)
    print(str(args.out / 'results.json'), flush=True)


if __name__ == '__main__':
    main()
