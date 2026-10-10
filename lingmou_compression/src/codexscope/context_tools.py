"""CLI and stdio MCP reader for a single run's retained reference sources."""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .reference_selection import SourceStore

SOURCE_READ_TOOL = {'type': 'function', 'name': 'lingmou_source_read',
    'description': 'Read original source lines omitted by Lingmou compression. Use the source_id and line positions in the excerpt; paginate until required evidence is available.',
    'parameters': {'type': 'object', 'properties': {'source_id': {'type': 'string'},
        'start_line': {'type': 'integer', 'minimum': 1}, 'end_line': {'type': ['integer', 'null']}},
        'required': ['source_id', 'start_line', 'end_line'], 'additionalProperties': False}, 'strict': True}


def build_source_server(store: SourceStore):
    from mcp.server import MCPServer
    from mcp.types import ToolAnnotations
    server = MCPServer('Lingmou retained sources', instructions='Read omitted source evidence before guessing. The source reader returns exact original lines.')

    @server.tool(annotations=ToolAnnotations(read_only_hint=True, destructive_hint=False,
                                           open_world_hint=False, idempotent_hint=True))
    def lingmou_source_read(source_id: str, start_line: int = 1, end_line: int | None = None) -> dict[str, Any]:
        """Read up to 500 original source lines by the source_id in a compressed excerpt."""
        return store.read(source_id, start_line, end_line)
    return server


def source_mcp_arguments(root: Path) -> list[str]:
    import sys
    # An absolute installed module path is important when Codex runs in another cwd.
    entry = ['context'] if getattr(sys, 'frozen', False) else ['-m', 'codexscope.context_tools']
    config = ('mcp_servers.lingmou_sources={command=' + json.dumps(sys.executable)
        + ',args=[' + ','.join(json.dumps(s) for s in [*entry, 'serve', '--store', str(root.resolve())])
        + '],startup_timeout_sec=20}')
    return ['-c', config]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    for command in ('serve', 'read', 'compress'):
        child = sub.add_parser(command)
        child.add_argument('--store', type=Path, required=True)
        if command == 'read':
            child.add_argument('source_id')
            child.add_argument('--start-line', type=int, default=1)
            child.add_argument('--end-line', type=int)
        elif command == 'compress':
            from .context_compression import COMPRESSION_MODES
            child.add_argument('request', type=Path)
            child.add_argument('--mode', choices=COMPRESSION_MODES, default='structure')
            child.add_argument('--output', type=Path, required=True)
    report = sub.add_parser('report')
    report.add_argument('ledger', type=Path)
    report.add_argument('--baseline', type=Path)
    report.add_argument('--task-id')
    report.add_argument('--checks', type=Path, help='JSON object of candidate correctness checks')
    report.add_argument('--baseline-checks', type=Path)
    args = parser.parse_args(argv)
    if args.command == 'report':
        from .request_usage_ledger import summarize_task, compare_tasks
        records = [json.loads(line) for line in args.ledger.read_text().splitlines() if line.strip()]
        if args.task_id:
            records = [r for r in records if r.get('task_id', 'run') == args.task_id]
        checks = json.loads(args.checks.read_text()) if args.checks else None
        result = summarize_task(records, checks=checks)
        if args.baseline:
            baseline = [json.loads(line) for line in args.baseline.read_text().splitlines() if line.strip()]
            if args.task_id:
                baseline = [r for r in baseline if r.get('task_id', 'run') == args.task_id]
            baseline_checks = json.loads(args.baseline_checks.read_text()) if args.baseline_checks else None
            result = compare_tasks(baseline, records, baseline_checks=baseline_checks, candidate_checks=checks)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    store = SourceStore(args.store)
    if args.command == 'serve':
        build_source_server(store).run(transport='stdio')
    elif args.command == 'read':
        print(json.dumps(store.read(args.source_id, args.start_line, args.end_line), ensure_ascii=False))
    else:
        from .context_compression import make_input_compressor
        compressor = make_input_compressor(args.mode, source_store=store)
        raw = args.request.read_bytes()
        output, observation = compressor.compress_observed(raw) if compressor else (raw, None)
        args.output.write_bytes(output)
        print(json.dumps(asdict(observation) if observation else {'status': 'off'}, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
