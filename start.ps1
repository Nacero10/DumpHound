$ROOT = $PSScriptRoot
$activate = Join-Path $ROOT "backend\.venv\Scripts\Activate.ps1"
if (Test-Path $activate) { & $activate } else { Write-Warning "venv not found at $activate - run setup first" }
$env:VOL_FRONTEND_DIST = Join-Path $ROOT "frontend\dist"
$env:VOL_IMAGE_DIR = Join-Path $ROOT "images"
$env:VOL_SYMBOL_DIR = Join-Path $ROOT "symbols"
$env:VOL_RULES_DIR = Join-Path $ROOT "backend\rules"
New-Item -ItemType Directory -Force $env:VOL_IMAGE_DIR, $env:VOL_SYMBOL_DIR | Out-Null
Write-Host "serving UI from $env:VOL_FRONTEND_DIST"
Write-Host "open http://127.0.0.1:8799/  (Ctrl+C to stop)"
python (Join-Path $ROOT "backend\run.py")
