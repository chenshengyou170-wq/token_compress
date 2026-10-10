#!/usr/bin/env python3
"""Task-level off/on acceptance, with existing ChatGPT login or local invariants.

Every upstream attempt and remote selector call remains in the result, including
failures. Local estimates, task correctness and provider usage are separate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
import time
from dataclasses import asdict
from pathlib import Path

from codexscope.compression_boundary import reference_text
from codexscope.context_compression import make_input_compressor, COMPRESSION_MODES
from codexscope.context_tools import source_mcp_arguments
from codexscope.reference_selection import SourceStore
from codexscope.request_token_tap import RequestTokenTap
from codexscope.request_usage_ledger import compare_tasks

from codex_usage_probe import _provider_arguments, _usage_from_codex_jsonl, _UPSTREAM

ROOT = Path(__file__).resolve().parents[1]


def cases():
    rows = [{'order_identifier': f'ORD-{i:04d}', 'status': 'needs_review', 'approved': False,
             'amount_cents': 12300 + i, 'currency': 'CNY'} for i in range(120)]
    background = [f'Archive topic {chr(65+i)}: ' + ('A scenic account of hills and landscapes. ' * 25) for i in range(18)]
    background[6] = '退款演练：订单 B42 的状态为 needs_review，approved 为 false，金额是 2700 分。\n只有双人审批通过后才允许退款；未审批时不得执行退款。'
    source = '\n\n'.join(background)
    code = '\n\n'.join(f'def unrelated_{chr(97+i)}():\n    """' + 'A helper for background exports. ' * 20 + f'"""\n    return {i}' for i in range(16))
    code += '\n\ndef refund_allowed(approved: bool, locked: bool) -> bool:\n    return approved and not locked\n'
    return {
        'table_en': {'source': json.dumps(rows, ensure_ascii=False, indent=2),
            'query': 'From order ORD-0043 return exactly a JSON object with keys status, approved (boolean), amount_cents (integer), currency. No other text.',
            'expected': {'status': 'needs_review', 'approved': False, 'amount_cents': 12343, 'currency': 'CNY'}},
        'reference_zh': {'source': source,
            'query': '核对订单 B42 的退款演练。只输出 JSON：status（原文枚举），approved（布尔值），amount_cents（整数），can_refund_without_approval（布尔值）。',
            'expected': {'status': 'needs_review', 'approved': False, 'amount_cents': 2700, 'can_refund_without_approval': False}},
        'code': {'source': code,
            'query': 'Evaluate refund_allowed for approved=true, locked=true. Return JSON with allowed as a boolean, and function as the exact function name. Do not execute code.',
            'expected': {'allowed': False, 'function': 'refund_allowed'}},
        'reread': {'source': source + '\n\nOriginal audit marker: "AUDIT-Z83".\n',
            'query': '核对 B42 退款。必须用 lingmou_source_read 从 source_id={source_id} 读取第 38 行，核实 audit_marker。只输出 JSON：approved（布尔值）、audit_marker（字符串）。',
            'expected': {'approved': False, 'audit_marker': 'AUDIT-Z83'}, 'tools': True},
    }


def quality(text: str, expected: dict) -> dict[str, bool]:
    try:
        value = json.loads(text)
    except ValueError:
        return {'json_object': False, **{k: False for k in expected}}
    return {'exact_fields': isinstance(value, dict) and set(value) == set(expected),
        **{k: isinstance(value, dict) and type(value.get(k)) is type(v) and value.get(k) == v for k, v in expected.items()}}


def run_codex(prompt: str, *, mode: str, model: str, workspace: Path, store: SourceStore, task_id: str, with_tools: bool) -> dict:
    records = []
    observations = []
    compressor = make_input_compressor(mode, source_store=store)
    if compressor:
        compressor.on_observation = lambda value: observations.append(asdict(value))
    version = subprocess.check_output(['codex', '--version'], text=True).strip().split()[-1]
    tap = RequestTokenTap(_UPSTREAM, input_compressor=compressor, on_request_usage=records.append, timeout_s=240).start()
    command = ['codex', 'exec', '--ephemeral', '--ignore-user-config', '--ignore-rules', '--json', '--skip-git-repo-check',
        '--sandbox', 'read-only', '--cd', str(workspace), '--model', model,
        '--disable', 'shell_tool', '--disable', 'apps', '--disable', 'hooks', '--disable', 'multi_agent', '--disable', 'remote_plugin',
        '-c', 'web_search="disabled"', '-c', 'model_reasoning_effort="low"',
        *_provider_arguments(tap.local_base_url, version),
        *(source_mcp_arguments(store.root) if with_tools or mode in {'extract', 'jev', 'kimi', 'llmlingua2'} else []), '-']
    started = time.monotonic()
    stdout, returncode, error = '', None, None
    try:
        process = subprocess.run(command, input=prompt, text=True, capture_output=True, timeout=300)
        stdout, returncode = process.stdout, process.returncode
        if returncode:
            error = 'codex_nonzero_exit'
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ''
        if isinstance(stdout, bytes): stdout = stdout.decode(errors='replace')
        error = 'codex_timeout'
    finally:
        tap.stop()
    events = []
    for line in stdout.splitlines():
        try: events.append(json.loads(line))
        except ValueError: pass
    items = [e.get('item', {}) for e in events if e.get('type') == 'item.completed']
    finals = [i.get('text', '') for i in items if i.get('type') == 'agent_message']
    for record in records:
        record['task_id'] = task_id
    result = {'provider': 'codex_chatgpt', 'mode': mode, 'model': model, 'returncode': returncode,
        'error': error, 'latency_s': round(time.monotonic() - started, 3),
        'response': finals[-1] if finals else '', 'requests': records, 'compression_observations': observations,
        'tool_items': [i for i in items if i.get('type') not in {'agent_message', 'reasoning'}],
        'codex_usage': _usage_from_codex_jsonl(stdout), 'prompt_sha256': hashlib.sha256(prompt.encode()).hexdigest()}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--provider', choices=['local', 'codex'], default='local')
    parser.add_argument('--model', default='gpt-6-astra')
    parser.add_argument('--modes', nargs='+', choices=COMPRESSION_MODES, default=['structure', 'extract'])
    parser.add_argument('--cases', nargs='+', choices=list(cases()), default=list(cases()))
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    config = {'provider': args.provider, 'model': args.model, 'cases': args.cases, 'modes': args.modes,
              'fixtures_sha256': hashlib.sha256(json.dumps(cases(), sort_keys=True).encode()).hexdigest()}
    config_path = args.out / 'run_config.json'
    if config_path.exists() and json.loads(config_path.read_text()) != config:
        parser.error('existing output directory belongs to a different evaluation; use a new directory')
    config_path.write_text(json.dumps(config, indent=2) + '\n')
    if args.provider == 'codex':
        status = subprocess.run(['codex', 'login', 'status'], text=True, capture_output=True)
        if status.returncode or 'ChatGPT' not in status.stdout + status.stderr:
            parser.error('existing ChatGPT login required')
    summaries = []
    # Keep sources next to numeric evidence for a reproducible, synthetic-only test.
    store = SourceStore(args.out / 'sources')
    with tempfile.TemporaryDirectory(prefix='lingmou-context-', dir=args.out.resolve()) as workspace:
        for name in args.cases:
            case = cases()[name]
            source_id = store.put(case['source'])
            query = case['query'].replace('{source_id}', source_id)
            prompt = query + '\n\n' + reference_text(case['source'])
            variants = {}
            for mode in dict.fromkeys(['off', *args.modes]):
                path = args.out / f'{name}.{mode}.json'
                if path.exists():
                    result = json.loads(path.read_text())
                elif args.provider == 'codex':
                    result = run_codex(prompt, mode=mode, model=args.model, workspace=Path(workspace), store=store,
                                       task_id=name, with_tools=case.get('tools', False))
                    result['checks'] = quality(result['response'], case['expected'])
                    if case.get('tools'):
                        result['checks']['source_tool_called'] = any('lingmou_source_read' in json.dumps(i) for i in result['tool_items'])
                    path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
                else:
                    compressor = make_input_compressor(mode, source_store=store)
                    body = {'model': args.model, 'instructions': 'Preserve exact output types and field names.', 'input': prompt}
                    raw = json.dumps(body, ensure_ascii=False).encode()
                    output, observation = compressor.compress_observed(raw) if compressor else (raw, None)
                    result = {'provider': 'local_only', 'mode': mode,
                        'observation': asdict(observation) if observation else None,
                        'request_sha256': hashlib.sha256(output).hexdigest(),
                        'protected_instructions_exact': json.loads(output)['instructions'] == body['instructions'],
                        'official_usage': None, 'quality_passed': None}
                    path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
                variants[mode] = result
                print(json.dumps({'case': name, 'mode': mode, 'provider': args.provider, 'checks': result.get('checks'),
                                  'observation': result.get('observation')}, ensure_ascii=False), flush=True)
            if args.provider == 'codex':
                for mode in args.modes:
                    before, after = variants['off'], variants[mode]
                    summaries.append({'case': name, 'mode': mode,
                        **compare_tasks(before['requests'], after['requests'], baseline_checks=before['checks'], candidate_checks=after['checks'])})
    report = {'provider': args.provider, 'comparisons': summaries, 'cases': args.cases,
        'limits': ['Synthetic fixtures; no daily-workload savings claim.',
                   'Missing provider usage disables net savings claims; no failed request is dropped.',
                   'Codex transport requests are counted in full; unlabelled retry/reread subcategories are not guessed.',
                   'LLMLingua-2 is a local lossy baseline; optional weights and dependency are required.']}
    (args.out / 'results.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')


if __name__ == '__main__':
    main()
