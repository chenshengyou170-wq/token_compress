#!/bin/sh
# Invoked inside Docker with /work containing an isolated build tree.
# No application sessions or model requests are started here.
set -eu

export PATH="/opt/node/bin:$PATH"
export WINEPREFIX=/work/wineprefix
export WINEARCH=win64
export WINEDEBUG=-all
export WINEDLLOVERRIDES='mscoree,mshtml='
export PYTHONUTF8=1

mkdir -p "$WINEPREFIX"
wineboot --init
wine reg add 'HKCU\Software\Wine' /v Version /t REG_SZ /d win10 /f

cd /work/project
if [ "${LINGMOU_SKIP_BACKEND:-0}" != "1" ]; then
wine /work/python/tools/python.exe -X utf8 desktop/scripts/prepare-assets.py
PYTHONPATH='Z:\work\project\src' wine /work/python/tools/python.exe -X utf8 -m PyInstaller \
  --noconfirm --clean \
  --distpath 'Z:\work\project\desktop\dist\backend' \
  --workpath 'Z:\work\project\desktop\build\pyinstaller' \
  'Z:\work\project\desktop\lingmou-backend.spec'
fi

# Import/startup check of the frozen entry point only; does not start a relay.
wine /work/project/desktop/dist/backend/lingmou-backend/lingmou-backend.exe compression-companion --help

cd /work/project/desktop
# The bundled Squirrel-Mono helper looks up the legacy 7z.exe name, while
# recent electron-winstaller packages ship architecture-qualified filenames.
vendor=node_modules/electron-winstaller/vendor
if [ ! -f "$vendor/7z.exe" ]; then
  cp "$vendor/7z-x64.exe" "$vendor/7z.exe"
  cp "$vendor/7z-x64.dll" "$vendor/7z.dll"
fi
node node_modules/@electron-forge/cli/dist/electron-forge.js make --platform=win32 --arch=x64
