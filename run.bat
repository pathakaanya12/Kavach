@echo off
setlocal
echo === KAVACH STARTUP (Windows) ===

cd /d "%~dp0"

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python is required but not found in PATH.
    pause
    exit /b 1
)

if not exist ".venv" (
    echo [INFO] Creating virtual environment .venv...
    python -m venv .venv
)

if not exist "web\tailwind.js" (
    echo [INFO] Downloading dashboard styles for offline use - one time...
    powershell -Command "try { Invoke-WebRequest -Uri https://cdn.tailwindcss.com -OutFile web\tailwind.js } catch { Write-Host 'Could not download now; CDN will be used when online.' }"
)

if not exist ".env" (
    if exist ".env.example" (
        copy .env.example .env >nul
    )
)

if not exist "data\files" (
    mkdir data\files
)

echo [INFO] Starting Kavach Server on http://127.0.0.1:8000...
echo [INFO] Open your browser at http://localhost:8000
echo.
.venv\Scripts\python.exe -m uvicorn server.main:app --host 127.0.0.1 --port 8000 --reload
