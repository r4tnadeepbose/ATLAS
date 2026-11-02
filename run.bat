@echo off
setlocal
cd /d "%~dp0"

echo Starting ATLAS...
echo.

where py >nul 2>nul
if not errorlevel 1 (
  py run.py %*
) else (
  where python >nul 2>nul
  if not errorlevel 1 (
    python run.py %*
  ) else (
    echo Python was not found. Install Python 3.12 or newer from https://www.python.org/downloads/
  )
)

echo.
echo ATLAS launcher finished. Press any key to close this window.
pause >nul
