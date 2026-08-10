# QUBIT Desktop App

QUBIT ships two ways to run as a desktop app. Both run the engine **natively** on your machine, so
the scanner can read local paths (`X:\projects\...`) and clone git repos — which the Docker build
could not do. Docker + Ollama are still used *by* the native engine for the migration sandbox and the
LLM patch tier (both optional; template migrations work without them).

## Option A — works today, no extra installs

**`qubit-desktop.bat`** (repo root) launches the native API (which also serves the dashboard) and
opens it in an app-mode window. Or, from a terminal:

```
uv run qubit run                     # interactive: prompts for a path OR a git URL, scans, scores, migrates
uv run qubit run X:\projects\MyApp   # scan a local folder
uv run qubit run https://github.com/org/repo.git   # clone + scan a repo
```

## Option B — native Tauri window (a real installable .exe)

A Tauri shell (`dashboard/src-tauri/`) that opens the dashboard in a native window and spawns the
QUBIT API as a child process on startup. **Built + verified on Windows** (2026-08-10): the build
produces `qubit-desktop.exe` and an NSIS installer `QUBIT_0.1.0_x64-setup.exe`; on launch it opens
the window, spawns the native API on `127.0.0.1:8787`, and the dashboard loads (health → 200).

### One-time prerequisites

1. **Rust** (already installed): https://rustup.rs
2. **MSVC C++ Build Tools** — Rust's `x86_64-pc-windows-msvc` target links with `link.exe`, which
   comes from Visual Studio's C++ tools. Install once, in an **Administrator** terminal:

   ```
   winget install Microsoft.VisualStudio.2022.BuildTools --override "--quiet --wait --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
   ```

   (WebView2, which Tauri renders in, is already present on Windows 11.)

### Build

```
cd dashboard
npm install
npm run tauri:build     # produces dashboard/src-tauri/target/release/bundle/nsis/*.exe (installer)
# or for a dev run without packaging:
npm run tauri:dev
```

The Rust entry (`src-tauri/src/main.rs`) spawns `uv run uvicorn qubit_api.main:app` on
`127.0.0.1:8787` with `QUBIT_DASHBOARD_DIST` set (so the API serves the dashboard), and kills it when
the window closes. `uv` must be on PATH.

### Architecture note

The engine stays Python (the real scanner / risk model / migration orchestrator); Tauri only provides
the native window + process lifecycle. That keeps the scanner able to see the host filesystem and use
git/Docker/Ollama, while giving you a true desktop app rather than a browser tab.
