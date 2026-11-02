# ATLAS local setup (Windows PowerShell)
# Usage:  powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1
# Optional demo data: $env:ATLAS_APP_ENV="demo"; $env:ATLAS_SEED_DEMO_DATA="true"; .\scripts\setup.ps1

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host "ATLAS setup" -ForegroundColor Cyan

if (-not (Test-Path ".env")) {
  Copy-Item ".env.example" ".env"
  Write-Host "Created .env from .env.example. Update ATLAS_SECRET_KEY before production use." -ForegroundColor Yellow
}

if (-not (Test-Path "backend\.venv")) {
  Write-Host "Creating Python virtual environment..."
  python -m venv backend\.venv
}

Write-Host "Installing backend dependencies..."
& ".\backend\.venv\Scripts\python.exe" -m pip install --upgrade pip --quiet
& ".\backend\.venv\Scripts\python.exe" -m pip install -r backend\requirements.txt --quiet

Write-Host "Applying database migrations..."
Push-Location backend
& ".\.venv\Scripts\python.exe" -m alembic upgrade head
if ($LASTEXITCODE -ne 0) {
  Pop-Location
  throw "Database migration failed. Fix the error above and re-run setup."
}
Pop-Location

Write-Host "Installing frontend dependencies..."
Push-Location frontend
npm install
if ($LASTEXITCODE -ne 0) {
  Pop-Location
  throw "Frontend dependency installation failed."
}
Pop-Location

Write-Host ""
Write-Host "Setup complete." -ForegroundColor Green
Write-Host "Start the API:      cd backend; .\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000"
Write-Host "Start the UI:       cd frontend; npm run dev"
Write-Host "Open:               http://localhost:5173"
Write-Host ""
Write-Host "First run: the login screen offers workspace bootstrap (first organization + super administrator)."
if ($env:ATLAS_APP_ENV -eq "demo") {
  Write-Host "Demo mode enabled. Accounts: admin@atlas.demo / AtlasDemo!2026" -ForegroundColor Yellow
}
