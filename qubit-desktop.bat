@echo off
REM ============================================================================
REM  QUBIT one-click launcher (Windows)
REM  Double-click this file. It will:
REM    1. make sure Docker Desktop is running (start it + wait if not),
REM    2. check for a local Ollama (optional — only the LLM patch tier needs it),
REM    3. bring up the full stack (API + dashboard) with `docker compose up`,
REM    4. wait until the API is healthy,
REM    5. open the dashboard in your browser.
REM  Close this window (or run `docker compose down`) to stop everything.
REM ============================================================================
setlocal
cd /d "%~dp0"
title QUBIT

echo(
echo   QUBIT - Quantum Upgrade Bridge ^& Inventory Tool
echo   ------------------------------------------------

REM --- 1. Docker ---------------------------------------------------------------
echo   [1/5] Checking Docker...
docker info >nul 2>&1
if errorlevel 1 (
  echo         Docker not running - starting Docker Desktop...
  if exist "%ProgramFiles%\Docker\Docker\Docker Desktop.exe" (
    start "" "%ProgramFiles%\Docker\Docker\Docker Desktop.exe"
  ) else (
    echo         ERROR: Docker Desktop not found. Install it from https://www.docker.com/products/docker-desktop
    pause
    exit /b 1
  )
  echo         Waiting for Docker to be ready ^(up to ~90s^)...
  set /a _tries=0
  :waitdocker
  timeout /t 3 >nul
  docker info >nul 2>&1
  if not errorlevel 1 goto dockerready
  set /a _tries+=1
  if %_tries% geq 30 (
    echo         ERROR: Docker did not become ready. Open Docker Desktop manually, then re-run.
    pause
    exit /b 1
  )
  goto waitdocker
)
:dockerready
echo         Docker is ready.

REM --- 2. Ollama (optional) ----------------------------------------------------
echo   [2/5] Checking Ollama ^(optional - only the LLM patch tier uses it^)...
curl -s -o nul --max-time 3 http://localhost:11434/api/tags
if errorlevel 1 (
  echo         Ollama not detected. Template migrations still work; for LLM patches run: ollama serve
) else (
  echo         Ollama is up.
)

REM --- 3. Bring up the stack ---------------------------------------------------
echo   [3/5] Starting the QUBIT stack ^(first run builds images - may take a few minutes^)...
docker compose up -d --build
if errorlevel 1 (
  echo         ERROR: `docker compose up` failed. See the output above.
  pause
  exit /b 1
)

REM --- 4. Wait for the API to be healthy ---------------------------------------
echo   [4/5] Waiting for the API to be healthy...
set /a _tries=0
:waitapi
timeout /t 2 >nul
curl -s -o nul --max-time 3 http://localhost:8080/api/v1/health
if not errorlevel 1 goto apiready
set /a _tries+=1
if %_tries% geq 30 (
  echo         WARNING: API health check timed out. The dashboard may still be starting.
  goto openui
)
goto waitapi
:apiready
echo         API is healthy.

REM --- 5. Open the dashboard ---------------------------------------------------
:openui
echo   [5/5] Opening the dashboard...
start "" http://localhost:8080
echo(
echo   QUBIT is running at http://localhost:8080
echo   To stop it: docker compose down   ^(or close Docker Desktop^)
echo(
pause
endlocal
