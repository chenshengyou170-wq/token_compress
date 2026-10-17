"""Convert a local Codex rollout into a replay for scripts/replay_cache_economics.py.

The rollout stores the conversation items Codex sends (messages, reasoning,
tool calls and outputs) but not tool definitions; pass a captured request body
with --header to reuse its `tools` and `instructions`. Only the history before
the first Codex compaction (or the segment chosen with --segment) is used.
A request is emitted after each user message and after each completed batch
of tool outputs, matching when Codex calls the model.

Rollouts contain private conversation data. Keep the replay file local.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

_ITEMS = {'message', 'reasoning', 'function_call', 'function_call_output',
          'custom_tool_call', 'custom_tool_call_output'}
_OUTPUTS = {'function_call_output', 'custom_tool_call_output'}


def segments(path: Path):
    current = []
    for line in path.open(encoding='utf-8'):
        record = json.loads(line)
        if record.get('type') == 'compacted':
            yield current
            current = []
        elif record.get('type') == 'response_item' and isinstance(record.get('payload'), dict):
            if record['payload'].get('type') in _ITEMS:
                current.append(record['payload'])
    yield current


def checkpoints(items):
    points = []
    for index, item in enumerate(items):
        following = items[index + 1] if index + 1 < len(items) else None
        user = item.get('type') == 'message' and item.get('role') == 'user'
        output_batch_end = item.get('type') in _OUTPUTS and (following is None or following.get('type') not in _OUTPUTS)
        if (user and (following is None or following.get('role') != 'user')) or output_batch_end:
            points.append(index + 1)
    return points


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('rollout', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--header', type=Path, help='JSON or JSONL capture whose first body supplies tools')
    parser.add_argument('--segment', type=int, default=0)
    parser.add_argument('--max-requests', type=int, default=0)
    args = parser.parse_args(argv)
    items = list(segments(args.rollout))[args.segment]
    points = checkpoints(items)
    if args.max_requests:
        points = points[:args.max_requests]
        items = items[:points[-1]]
    replay = {'scope': 'local Codex rollout; private; visible history plus captured header',
              'items': items, 'checkpoints': points}
    if args.header:
        text = args.header.read_text(encoding='utf-8')
        first = json.loads(text.splitlines()[0]) if args.header.suffix == '.jsonl' else json.loads(text)
        body = first.get('body', first)
        replay['tools'] = body.get('tools', [])
        if body.get('instructions'):
            replay['instructions'] = body['instructions']
        # Codex puts its base and skills prompts in leading developer messages.
        replay['prefix_items'] = [item for item in body.get('input', [])
                                  if item.get('type', 'message') == 'message' and item.get('role') == 'developer']
    args.output.write_text(json.dumps(replay, ensure_ascii=False))
    print(json.dumps({'items': len(items), 'requests': len(points),
                      'prefix_items': len(replay.get('prefix_items', []))}))


if __name__ == '__main__':
    main()
