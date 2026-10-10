#!/usr/bin/env python3
"""Verify the collected files against the recorded snapshot, without network access."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parent
    manifest = json.loads((root / 'MANIFEST.json').read_text())
    errors = []
    total = 0
    for entry in manifest['files']:
        path = root / entry['path']
        if root not in path.resolve().parents or path.is_symlink() or not path.is_file():
            errors.append({'path': entry['path'], 'reason': 'missing, symlink or outside collection'})
            continue
        content = path.read_bytes()
        total += len(content)
        if hashlib.sha256(content).hexdigest() != entry['sha256'] or len(content) != entry['bytes']:
            errors.append({'path': entry['path'], 'reason': 'content differs from recorded snapshot'})
    print(json.dumps({'copied_files': len(manifest['files']), 'bytes': total,
                      'verified': not errors, 'errors': errors}, ensure_ascii=False, indent=2))
    return 1 if errors else 0


if __name__ == '__main__':
    raise SystemExit(main())
