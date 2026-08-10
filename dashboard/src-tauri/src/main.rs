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

/// Find the monorepo root (the dir containing `pyproject.toml` + `packages/`).
///
/// A GUI-launched .exe's *current working directory* is NOT its own folder (Windows sets it to
/// System32 or the shortcut's target), so walking up from `current_dir()` fails — that was the
/// "Failed to fetch" bug: `uv run` launched in the wrong dir and the API never bound. We therefore
/// search up from the EXE's own path first (`current_exe()`), then the cwd, and finally honor an
/// explicit `QUBIT_REPO_ROOT` override.
fn repo_root() -> Option<std::path::PathBuf> {
    if let Ok(p) = std::env::var("QUBIT_REPO_ROOT") {
        let p = std::path::PathBuf::from(p);
        if p.join("pyproject.toml").exists() {
            return Some(p);
        }
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
            if dir.join("pyproject.toml").exists() && dir.join("packages").is_dir() {
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
