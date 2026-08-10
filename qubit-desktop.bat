@echo off
REM ============================================================================
REM  QUBIT desktop (native) launcher - Windows
REM
REM  Runs the API + dashboard NATIVELY on your machine (one process), so the
REM  scanner can read local paths (X:\...) AND clone git repos - which the
REM  container build could not do. Docker + Ollama are still used BY this native
REM  API for the migration sandbox and the LLM patch tier.
REM
REM  Double-click this file. It will:
REM    1. install Python deps (first run only),
REM    2. build the dashboard (first run only),
REM    3. start the native API serving the dashboard at http://127.0.0.1:8787,
REM    4. open it in an app window.
REM  Close the console window to stop it.
REM ============================================================================
setlocal
cd /d "%~dp0"
title QUBIT desktop

set "PORT=8787"
set "URL=http://127.0.0.1:%PORT%"
set "DIST=%CD%\dashboard\dist"
REM The dashboard bundle's default token; keep in sync with QUBIT_API_TOKEN below.
set "QUBIT_API_TOKEN=dev_token"
set "QUBIT_DASHBOARD_DIST=%DIST%"

echo(
echo   QUBIT - Quantum Upgrade Bridge ^& Inventory Tool  (native desktop)
echo   ----------------------------------------------------------------

REM --- 1. Python deps (uv) -----------------------------------------------------
where uv >nul 2>&1
if errorlevel 1 (
  echo   ERROR: `uv` not found. Install it: https://docs.astral.sh/uv/  then re-run.
  pause & exit /b 1
)
if not exist ".venv" (
  echo   [1/4] Installing Python packages (first run - a few minutes)...
  call uv sync --all-packages
) else (
  echo   [1/4] Python packages present.
)

REM --- 2. Dashboard build ------------------------------------------------------
if not exist "%DIST%\index.html" (
  echo   [2/4] Building the dashboard (first run)...
  pushd dashboard
  if not exist "node_modules" ( call npm install )
  set "VITE_API_BASE=/api/v1"
  set "VITE_API_TOKEN=dev_token"
  call npm run build
  popd
) else (
  echo   [2/4] Dashboard build present.
)

REM --- 3. Optional: note Docker/Ollama (used by migration + LLM tiers) ---------
docker info >nul 2>&1
if errorlevel 1 (
  echo   Note: Docker not running - migration sandbox validation will be limited.
) else (
  echo   Docker is available (used for migration sandbox).
)
curl -s -o nul --max-time 3 http://localhost:11434/api/tags
if errorlevel 1 (
  echo   Note: Ollama not detected - LLM patches need it; template patches still work.
)

REM --- 4. Start the native API (serves the dashboard too) ----------------------
echo   [3/4] Starting QUBIT at %URL% ...
start "QUBIT API" /min cmd /c "uv run uvicorn qubit_api.main:app --host 127.0.0.1 --port %PORT%"

echo   [4/4] Waiting for it to be ready...
set /a _t=0
:wait
timeout /t 1 >nul
curl -s -o nul --max-time 2 %URL%/api/v1/health
if not errorlevel 1 goto ready
set /a _t+=1
if %_t% geq 40 ( echo   WARNING: startup slow - opening anyway. & goto open )
goto wait
:ready
echo   Ready.

:open
REM Prefer an app-mode window (no browser chrome); fall back to the default browser.
set "EDGE=%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"
set "CHROME=%ProgramFiles%\Google\Chrome\Application\chrome.exe"
if exist "%EDGE%" ( start "" "%EDGE%" --app=%URL% ) ^
else if exist "%CHROME%" ( start "" "%CHROME%" --app=%URL% ) ^
else ( start "" %URL% )

echo(
echo   QUBIT is running at %URL%
echo   The scanner runs natively - you can scan any local path (e.g. X:\projects\...)
echo   or paste a git repo URL. Close this window to stop QUBIT.
echo(
pause
endlocal
