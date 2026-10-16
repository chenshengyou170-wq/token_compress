# Build only: no test suite and no calls to a model provider.
$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
if (-not [Environment]::Is64BitProcess) { throw 'Please use x64 PowerShell, Node.js and Python.' }
if ($env:OS -ne 'Windows_NT') { throw 'Run this build on Windows.' }
Push-Location $ProjectRoot
try {
    uv sync --locked --extra desktop
    if ($LASTEXITCODE -ne 0) { throw 'Python dependencies could not be installed.' }
    npm ci --prefix web
    if ($LASTEXITCODE -ne 0) { throw 'Web dependencies could not be installed.' }
    npm ci --prefix desktop
    if ($LASTEXITCODE -ne 0) { throw 'Desktop dependencies could not be installed.' }
    npm --prefix desktop run make:windows
    if ($LASTEXITCODE -ne 0) { throw 'Windows packaging failed.' }
} finally {
    Pop-Location
}
