#!/usr/bin/env bash
# ============================================================================
#  QUBIT one-click launcher (macOS / Linux / WSL)
#  Run: ./qubit-desktop.sh   — brings up Docker + the stack, opens the dashboard.
#  Stop: docker compose down
# ============================================================================
set -euo pipefail
cd "$(dirname "$0")"

echo
echo "  QUBIT — Quantum Upgrade Bridge & Inventory Tool"
echo "  ------------------------------------------------"

open_url() {
  if command -v open >/dev/null 2>&1; then open "$1"          # macOS
  elif command -v xdg-open >/dev/null 2>&1; then xdg-open "$1" # Linux
  elif command -v wslview >/dev/null 2>&1; then wslview "$1"   # WSL
  else echo "  Open $1 in your browser."; fi
}

# --- 1. Docker ---------------------------------------------------------------
echo "  [1/5] Checking Docker..."
if ! docker info >/dev/null 2>&1; then
  echo "        Docker not running. Start Docker Desktop (or the docker daemon), then re-run."
  exit 1
fi
echo "        Docker is ready."

# --- 2. Ollama (optional) ----------------------------------------------------
echo "  [2/5] Checking Ollama (optional — only the LLM patch tier uses it)..."
if curl -s -o /dev/null --max-time 3 http://localhost:11434/api/tags; then
  echo "        Ollama is up."
else
  echo "        Ollama not detected. Template migrations still work; for LLM patches run: ollama serve"
fi

# --- 3. Bring up the stack ---------------------------------------------------
echo "  [3/5] Starting the QUBIT stack (first run builds images — may take a few minutes)..."
docker compose up -d --build

# --- 4. Wait for the API to be healthy ---------------------------------------
echo "  [4/5] Waiting for the API to be healthy..."
for _ in $(seq 1 30); do
  if curl -s -o /dev/null --max-time 3 http://localhost:8080/api/v1/health; then
    echo "        API is healthy."; break
  fi
  sleep 2
done

# --- 5. Open the dashboard ---------------------------------------------------
echo "  [5/5] Opening the dashboard..."
open_url http://localhost:8080
echo
echo "  QUBIT is running at http://localhost:8080"
echo "  To stop it: docker compose down"
echo
