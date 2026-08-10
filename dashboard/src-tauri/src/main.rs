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

/// Locate the monorepo root: two levels up from src-tauri (dashboard/src-tauri -> repo root),
/// overridable with QUBIT_REPO_ROOT for a packaged install.
fn repo_root() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("QUBIT_REPO_ROOT") {
        return std::path::PathBuf::from(p);
    }
    // At dev/build time the exe runs from target/…; fall back to the current dir's ancestors that
    // contain pyproject.toml + a `packages` dir.
    let mut dir = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    loop {
        if dir.join("pyproject.toml").exists() && dir.join("packages").is_dir() {
            return dir;
        }
        match dir.parent() {
            Some(p) => dir = p.to_path_buf(),
            None => return std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from(".")),
        }
    }
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
            let root = repo_root();
            match spawn_api(&root) {
                Ok(child) => {
                    *app.state::<ApiProcess>().0.lock().unwrap() = Some(child);
                }
                Err(e) => {
                    eprintln!("QUBIT: failed to start the API ({e}). Is `uv` installed and on PATH?");
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
