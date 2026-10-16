"""Collect native Windows build output with stable download names and checksums."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
from datetime import UTC, datetime


def collect(desktop: Path) -> Path:
    version = json.loads((desktop / 'package.json').read_text(encoding='utf-8'))['version']
    tag = os.environ.get('GITHUB_REF_NAME', '')
    if os.environ.get('GITHUB_REF_TYPE') == 'tag' and tag != f'lingmou-v{version}':
        raise ValueError('Release tag must match desktop/package.json')
    installer = desktop / 'out/make/squirrel.windows/x64/Lingmou-Setup.exe'
    archives = list((desktop / 'out/make/zip/win32/x64').glob('*.zip'))
    if not installer.is_file() or len(archives) != 1:
        raise ValueError('Expected one Windows x64 installer and one portable ZIP')
    output = desktop / 'out/release'
    output.mkdir(parents=True, exist_ok=True)
    assets = []
    for source, name in ((installer, 'Lingmou-Setup.exe'), (archives[0], 'Lingmou-win-x64.zip')):
        target = output / name
        shutil.copyfile(source, target)
        with target.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        assets.append({'name': name, 'bytes': target.stat().st_size, 'sha256': digest})
    (output / 'SHA256SUMS.txt').write_text(
        ''.join(f'{asset["sha256"]}  {asset["name"]}\n' for asset in assets), encoding='utf-8')
    (output / 'release-manifest.json').write_text(json.dumps({
        'product': 'Lingmou', 'version': version, 'target': 'win32-x64',
        'commit': os.environ.get('GITHUB_SHA'), 'built_at': datetime.now(UTC).isoformat(),
        'signed': bool(os.environ.get('WINDOWS_CERTIFICATE_FILE')), 'assets': assets,
        'native_windows_ui': 'not_automatically_verified',
        'real_chatgpt_upstream': 'not_automatically_verified',
    }, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return output


if __name__ == '__main__':
    print(collect(Path(__file__).resolve().parents[1]))
