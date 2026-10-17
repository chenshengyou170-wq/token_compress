"""Deterministic synthetic coding loop for scripts/replay_cache_economics.py.

Synthetic data: file reads, edits that make earlier reads stale, repeated test
and git-status runs, colored progress output and one failing test run. It is
designed to exercise the policies, not to estimate real-world savings.
"""
import json
import sys
from pathlib import Path

items = [{'role': 'user', 'content': 'Fix the failing invoice tests and keep the API unchanged.'}]
checkpoints = []


def call(identity, command, output, name='exec'):
    items.extend([{'type': 'reasoning', 'encrypted_content': 'opaque' * 80, 'summary': []},
                  {'type': 'custom_tool_call', 'call_id': identity, 'name': name, 'input': command},
                  {'type': 'custom_tool_call_output', 'call_id': identity, 'output': output}])
    checkpoints.append(len(items))


def source(path, version, lines=220):
    return '\n'.join(f'{i:4d}  def {path.split("/")[-1][:-3]}_{i}(x): return x * {i + version}  # v{version}'
                     for i in range(lines))


def tests(failing):
    progress = '\r'.join(f'\x1b[32m{p}%\x1b[0m' for p in range(0, 101, 5))
    passed = '\n'.join(f'tests/test_invoice.py::test_case_{i} \x1b[32mPASSED\x1b[0m' for i in range(160))
    fail = '\nFAILED tests/test_invoice.py::test_rounding - AssertionError: 10.01 != 10.00' if failing else ''
    return progress + '\n' + passed + fail + f'\n{"1 failed, " if failing else ""}160 passed\nProcess exited with code {1 if failing else 0}'


n = 0
for round_ in range(6):
    for path in ('src/invoice.py', 'src/rounding.py', 'src/api.py'):
        n += 1
        call(f'r{n}', f'text(await tools.exec_command({{cmd:"cat {path}"}}))', source(path, round_))
    n += 1
    call(f't{n}', 'text(await tools.exec_command({cmd:"pytest -q"}))', tests(failing=round_ < 5))
    n += 1
    call(f's{n}', 'text(await tools.exec_command({cmd:"git status"}))',
         '\n'.join(f' M src/file_{i}.py' for i in range(40)))
    n += 1
    patch = f'*** Begin Patch\n*** Update File: src/rounding.py\n@@\n-    return round(x, 2)\n+    return quantize(x, {round_})\n*** End Patch'
    call(f'p{n}', patch, 'Success. Updated the following files:\nM src/rounding.py', name='apply_patch')
items.append({'role': 'assistant', 'content': 'Fixed rounding; all invoice tests pass.'})
checkpoints.append(len(items))
Path(sys.argv[1]).write_text(json.dumps({'scope': 'synthetic coding loop', 'items': items,
                                         'checkpoints': checkpoints}, ensure_ascii=False) + '\n')
