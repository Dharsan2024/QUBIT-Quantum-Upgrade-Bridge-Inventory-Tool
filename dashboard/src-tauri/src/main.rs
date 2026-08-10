// QUBIT desktop (Tauri).
//
// The window loads the bundled dashboard (frontendDist). On startup we spawn the QUBIT API
// NATIVELY as a child process (`uv run uvicorn qubit_api.main:app` on 127.0.0.1:8787) so the
// scanner runs on this machine — able to read local paths (X:\...) and clone git repos, which the
// Docker build could not. The dashboard talks to that API at 127.0.0.1:8787/api/v1. The child is
// killed when the app exits.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::process::{Child, Command};
use std::sync::Mutex;
use tauri::Manager;

struct ApiProcess(Mutex<Option<Child>>);

/// True if `dir` is the QUBIT monorepo root.
fn is_repo_root(dir: &std::path::Path) -> bool {
    dir.join("pyproject.toml").exists() && dir.join("packages").is_dir()
}

/// Path to the persisted config that remembers the repo root (survives an install to AppData).
fn config_path() -> Option<std::path::PathBuf> {
    let base = std::env::var("APPDATA")
        .ok()
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var("HOME").ok().map(std::path::PathBuf::from))?;
    Some(base.join("QUBIT").join("repo_root.txt"))
}

fn read_saved_root() -> Option<std::path::PathBuf> {
    let p = config_path()?;
    let content = std::fs::read_to_string(p).ok()?;
    let dir = std::path::PathBuf::from(content.trim());
    if is_repo_root(&dir) {
        Some(dir)
    } else {
        None
    }
}

fn save_root(root: &std::path::Path) {
    if let Some(p) = config_path() {
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(p, root.to_string_lossy().as_bytes());
    }
}

/// Find the monorepo root (the dir containing `pyproject.toml` + `packages/`).
///
/// Resolution order:
///   1. `QUBIT_REPO_ROOT` env override,
///   2. a saved config file (%APPDATA%\QUBIT\repo_root.txt) — this is how an INSTALLED copy in
///      AppData (outside the source tree) finds the project after a first in-tree run,
///   3. searching up from the exe's own path, then the cwd.
///
/// A GUI-launched .exe's working dir is System32, and an installed exe lives outside the repo — so
/// neither cwd nor exe-path find it once installed. When (3) does find it (e.g. running the
/// freshly-built exe from target/release inside the tree), we persist it via (2) for next time.
fn repo_root() -> Option<std::path::PathBuf> {
    if let Ok(p) = std::env::var("QUBIT_REPO_ROOT") {
        let p = std::path::PathBuf::from(p);
        if is_repo_root(&p) {
            save_root(&p);
            return Some(p);
        }
    }
    if let Some(p) = read_saved_root() {
        return Some(p);
    }
    let mut starts: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            starts.push(parent.to_path_buf());
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        starts.push(cwd);
    }
    for start in starts {
        let mut dir = start;
        loop {
            if is_repo_root(&dir) {
                save_root(&dir);
                return Some(dir);
            }
            match dir.parent() {
                Some(p) => dir = p.to_path_buf(),
                None => break,
            }
        }
    }
    None
}

fn spawn_api(root: &std::path::Path) -> std::io::Result<Child> {
    let dist = root.join("dashboard").join("dist");
    Command::new("uv")
        .current_dir(root)
        .args([
            "run", "uvicorn", "qubit_api.main:app",
            "--host", "127.0.0.1", "--port", "8787",
        ])
        // Serve the dashboard from the API too (single origin) + keep the bundle's default token.
        .env("QUBIT_DASHBOARD_DIST", dist)
        .env("QUBIT_API_TOKEN", "dev_token")
        .spawn()
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(ApiProcess(Mutex::new(None)))
        .setup(|app| {
            match repo_root() {
                Some(root) => match spawn_api(&root) {
                    Ok(child) => {
                        *app.state::<ApiProcess>().0.lock().unwrap() = Some(child);
                    }
                    Err(e) => {
                        eprintln!(
                            "QUBIT: failed to start the API from {}: {e}. Is `uv` on PATH?",
                            root.display()
                        );
                    }
                },
                None => {
                    eprintln!(
                        "QUBIT: could not locate the project root (pyproject.toml + packages/). \
                         Set QUBIT_REPO_ROOT to the repo path and relaunch."
                    );
                }
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // Kill the API child when the last window closes.
            if let tauri::WindowEvent::Destroyed = event {
                if let Some(child) = window
                    .state::<ApiProcess>()
                    .0
                    .lock()
                    .unwrap()
                    .take()
                    .as_mut()
                {
                    let _ = child.kill();
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running QUBIT desktop");
}
