param(
    [switch]$SkipBrowserInstall
)

$ErrorActionPreference = "Stop"

Write-Host "AKHA XSS Windows setup" -ForegroundColor Cyan

$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Error "Python was not found. Install Python 3.9+ from https://www.python.org/downloads/windows/ and enable 'Add python.exe to PATH'."
}

$versionText = python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
$parts = $versionText.Split(".")
if ([int]$parts[0] -lt 3 -or ([int]$parts[0] -eq 3 -and [int]$parts[1] -lt 9)) {
    Write-Error "Python 3.9+ is required. Detected Python $versionText."
}

if (-not (Test-Path ".venv")) {
    Write-Host "Creating virtual environment..." -ForegroundColor Yellow
    python -m venv .venv
}

$venvPython = Join-Path (Resolve-Path ".venv") "Scripts\python.exe"

Write-Host "Upgrading pip..." -ForegroundColor Yellow
& $venvPython -m pip install --upgrade pip

Write-Host "Installing AKHA dependencies..." -ForegroundColor Yellow
& $venvPython -m pip install -r requirements.txt
& $venvPython -m pip install -e .

if (-not $SkipBrowserInstall) {
    Write-Host "Installing Playwright Chromium runtime..." -ForegroundColor Yellow
    & $venvPython -m playwright install chromium
}

Write-Host ""
Write-Host "Setup complete." -ForegroundColor Green
Write-Host "Activate: .\.venv\Scripts\Activate.ps1"
Write-Host "Health check: akha-xss doctor"
Write-Host "Presets: akha-xss presets"
