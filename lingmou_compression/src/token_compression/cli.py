"""File/stdin CLI. Diagnostics go to stderr; compressed requests go to stdout."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engine import CompressionConfig, TokenCompressor
from .methods import ALIASES, METHODS, available_methods
from codexscope.reference_selection import SourceStore


def main(argv=None):
    parser = argparse.ArgumentParser(prog="token-compress")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("methods", help="List algorithms and optional requirements")
    compress = commands.add_parser("compress", help="Compress a Responses/Chat JSON request")
    compress.add_argument("input", nargs="?", default="-", help="JSON request, or - for stdin")
    compress.add_argument("--output", type=Path)
    compress.add_argument("--report", type=Path)
    compress.add_argument("--method", choices=[*METHODS, *ALIASES], default="structure")
    compress.add_argument("--store", type=Path, help="Persistent original sources for lossy methods")
    compress.add_argument("--model", default="gpt-4o", help="Local tokenizer model")
    compress.add_argument("--model-path")
    compress.add_argument("--reference-path")
    compress.add_argument("--mlm-model-path")
    compress.add_argument("--spacy-model", default="en_core_web_sm")
    compress.add_argument("--device", default="cpu")
    compress.add_argument("--rate", type=float, default=0.6)
    compress.add_argument("--history-max-tokens", type=int)
    compress.add_argument("--history-keep-turns", type=int, default=2)
    read = commands.add_parser("read", help="Read an original source by hash and line range")
    read.add_argument("source_id")
    read.add_argument("--store", type=Path, required=True)
    read.add_argument("--start-line", type=int, default=1)
    read.add_argument("--end-line", type=int)
    serve = commands.add_parser("serve", help="Expose lingmou_source_read via MCP stdio")
    serve.add_argument("--store", type=Path, required=True)
    bench = commands.add_parser("benchmark", help="Run reproducible synthetic comparisons")
    bench.add_argument("--out", type=Path, required=True)
    bench.add_argument("--methods", nargs="+", choices=list(METHODS), default=["off", "structure", "caveman", "extract", "auto", "generic_agent"])
    bench.add_argument("--repeats", type=int, default=3)
    bench.add_argument("--model-path")
    bench.add_argument("--reference-path")
    bench.add_argument("--cases", nargs="+")
    bench.add_argument("--mlm-model-path")
    bench.add_argument("--spacy-model", default="en_core_web_sm")
    bench.add_argument("--live", action="store_true", help="Allow remote compressor calls on synthetic data")
    args = parser.parse_args(argv)
    try:
        if args.command == "methods":
            print(json.dumps(available_methods(), ensure_ascii=False, indent=2))
        elif args.command == "read":
            print(json.dumps(SourceStore(args.store).read(args.source_id, args.start_line, args.end_line), ensure_ascii=False))
        elif args.command == "serve":
            from codexscope.context_tools import build_source_server
            build_source_server(SourceStore(args.store)).run(transport="stdio")
        elif args.command == "benchmark":
            from .experiment import run_benchmark
            run_benchmark(args.out, methods=args.methods, repeats=args.repeats, model_path=args.model_path,
                          reference_path=args.reference_path, live=args.live, cases=args.cases,
                          mlm_model_path=args.mlm_model_path, spacy_model=args.spacy_model)
        else:
            config = CompressionConfig(**{k: getattr(args, k) for k in (
                "method", "model", "model_path", "reference_path", "mlm_model_path", "spacy_model", "device",
                "rate", "history_max_tokens", "history_keep_turns")})
            if (METHODS[config.method].lossy or config.history_max_tokens) and not args.store:
                parser.error("--store is required to retain sources for lossy compression")
            raw = sys.stdin.buffer.read() if args.input == "-" else Path(args.input).read_bytes()
            output, result = TokenCompressor(config, source_store=SourceStore(args.store)).compress_bytes(raw)
            if result is None:
                parser.error("input must be an unambiguous JSON request object under 8 MiB")
            if args.output:
                args.output.write_bytes(output)
            else:
                sys.stdout.buffer.write(output + b"\n")
            report = result.to_dict()
            report.pop("body")
            if args.report:
                args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
            else:
                print(json.dumps(report, ensure_ascii=False), file=sys.stderr)
        return 0
    except (ValueError, OSError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
