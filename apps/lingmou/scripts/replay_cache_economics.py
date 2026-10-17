"""Replay a conversation's growing request prefixes and price them under a prefix cache.

Each variant runs in its own process so an older source tree (for example a
backup of the previous release) can be compared with the current one:

    .venv/bin/python scripts/replay_cache_economics.py REPLAY.json \
        --variant before=/path/to/old/src --variant after=src --output report.json

REPLAY.json holds {"items": [...], "checkpoints": [n1, n2, ...]}; request k sends
items[:n_k]. The cache model is an idealized provider prefix cache: a request's
cached tokens are the tokens of the longest item-level prefix it shares with the
previous request of the conversation (header first). This is an offline
estimate, not provider usage, and has no answer-quality measurement.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

SERVER = 'lingmou_src_replay'
READER = {'type': 'namespace', 'name': 'mcp__' + SERVER, 'tools': [
    {'type': 'function', 'name': 'lingmou_source_read', 'description': 'Read archived source lines.',
     'parameters': {'type': 'object', 'properties': {'source_id': {'type': 'string'},
                    'start_line': {'type': 'integer'}, 'end_line': {'type': 'integer'}}}}]}

WORKER = r'''
import json, sys, tempfile
from pathlib import Path
spec = json.load(sys.stdin)
sys.path.insert(0, spec['src'])
from codexscope.desktop_companion import DesktopCompressor
from codexscope.reference_selection import SourceStore
assert Path(sys.modules['codexscope'].__file__).resolve().is_relative_to(Path(spec['src']))
store = SourceStore(Path(tempfile.mkdtemp(prefix='lingmou-replay-')))
compressor = DesktopCompressor(spec['mode'], store, spec['server'])
sent = []
for body in spec['bodies']:
    raw = json.dumps(body, ensure_ascii=False).encode()
    output, observation = compressor.compress_observed(raw)
    sent.append(json.loads(output))
    usage = spec['usage']
    if hasattr(compressor, 'observe_response'):
        compressor.observe_response({'compression': {'cache_prefix': observation.cache_prefix or {}},
                                     'official_usage': usage})
json.dump(sent, sys.stdout, ensure_ascii=False)
'''


def extend(replay, count, size=1200):
    """Continue the conversation with small synthetic tool turns after the replay.

    Checkpoints pay a one-time cache break that later requests repay; a replay
    that stops at a checkpoint shows only the cost.
    """
    items, checkpoints = list(replay['items']), list(replay['checkpoints'])
    for n in range(count):
        identity = f'extend-{n}'
        text = '\n'.join(f'check {n}.{i}: status ok, value {i * 13}' for i in range(size // 32))
        items += [{'type': 'custom_tool_call', 'call_id': identity, 'name': 'exec',
                   'input': f'text(await tools.exec_command({{cmd:"python check.py --step {n}"}}))'},
                  {'type': 'custom_tool_call_output', 'call_id': identity, 'output': text}]
        checkpoints.append(len(items))
    return {**replay, 'items': items, 'checkpoints': checkpoints}


def bodies(replay, model):
    metadata = {'x-codex-turn-metadata': json.dumps({'thread_id': 'replay-thread', 'turn_id': 'replay-turn'})}
    header = {'model': model, 'tools': list(replay.get('tools', [])) + [READER], 'client_metadata': metadata}
    if replay.get('instructions'):
        header['instructions'] = replay['instructions']
    prefix = list(replay.get('prefix_items', []))
    return [{**header, 'input': prefix + replay['items'][:end]} for end in replay['checkpoints']]


def run_variant(src, requests, mode):
    spec = {'src': str(Path(src).resolve()), 'mode': mode, 'server': SERVER, 'bodies': requests,
            # Report caching to the ledger so its checkpoint economics are active.
            'usage': {'input_tokens': 1000, 'cached_input_tokens': 900}}
    done = subprocess.run([sys.executable, '-I', '-c', WORKER], input=json.dumps(spec, ensure_ascii=False),
                          capture_output=True, text=True, check=True)
    return json.loads(done.stdout)


def price(sent, count, ratio):
    import re
    opaque = re.compile(r'"data:[A-Za-z0-9.+/-]+;base64,[A-Za-z0-9+/=\\]*"|("encrypted_content":\s*)"[^"]*"')
    def tokens(value):
        return count(opaque.sub(lambda m: (m[1] or '') + '""', json.dumps(value, ensure_ascii=False, separators=(',', ':'))))
    rows, previous = [], None
    for body in sent:
        header = {k: body.get(k) for k in ('tools', 'instructions') if k in body}
        items = body['input']
        digests = [hashlib.sha256(json.dumps(i, sort_keys=True).encode()).hexdigest() for i in items]
        item_tokens = [tokens(i) for i in items]
        total = tokens(header) + sum(item_tokens)
        cached = 0
        if previous and previous[0] == header:
            cached = tokens(header)
            for old, new, size in zip(previous[1], digests, item_tokens):
                if old != new:
                    break
                cached += size
        rows.append({'input': total, 'cached': cached, 'uncached': total - cached,
                     'effective': round(total - cached + cached * ratio)})
        previous = (header, digests)
    totals = {key: sum(row[key] for row in rows) for key in ('input', 'cached', 'uncached', 'effective')}
    return {'requests': rows, 'totals': totals}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('replay', type=Path)
    parser.add_argument('--variant', action='append', required=True, help='name=SRC_DIR[@MODE]')
    parser.add_argument('--mode', default='full')
    parser.add_argument('--model', default='gpt-5')
    parser.add_argument('--cache-price-ratio', type=float, default=.1)
    parser.add_argument('--extend', type=int, default=0, help='append N small synthetic tool requests')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    from codexscope.proxy_usage import default_token_counter
    count, tokenizer = default_token_counter(args.model)
    replay = json.loads(args.replay.read_text())
    replay = extend(replay, args.extend) if args.extend else replay
    requests = bodies(replay, args.model)
    report = {'replay': str(args.replay), 'requests': len(requests), 'synthetic_extension_requests': args.extend, 'mode': args.mode, 'tokenizer': tokenizer,
              'cache_price_ratio': args.cache_price_ratio,
              'cache_model': 'item-level prefix shared with the previous request; offline estimate',
              'variants': {'uncompressed': price(requests, count, args.cache_price_ratio)}}
    for variant in args.variant:
        name, _, src = variant.partition('=')
        src, _, mode = src.partition('@')
        report['variants'][name] = price(run_variant(src, requests, mode or args.mode), count, args.cache_price_ratio)
    summary = {name: value['totals'] for name, value in report['variants'].items()}
    report['summary'] = summary
    if args.output:
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
