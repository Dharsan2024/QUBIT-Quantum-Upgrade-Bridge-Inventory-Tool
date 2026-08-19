// QUBIT desktop (Tauri).
//
// The window loads the bundled dashboard (frontendDist). On startup we spawn the QUBIT API
// NATIVELY as a child process so the scanner runs on this machine — able to read local paths
// (X:\...) and clone git repos, which the Docker build could not. The child is killed on exit.
//
// The port is CHOSEN AT RUNTIME, not hardcoded. 8787 used to be baked in here and in the dashboard
// bundle, and it is not always bindable: Windows reserves port blocks for Hyper-V/WSL/Docker, and on
// a machine where 8695-8794 is reserved (`netsh int ipv4 show excludedportrange protocol=tcp`)
// binding 8787 fails with WinError 10013 even though nothing is listening. The API then never came
// up and the window sat on "Starting the engine…" forever.
//
// Because the window loads the BUNDLED frontend from tauri.localhost — not from the API — the
// front-end cannot learn the port from the page it was served (that mechanism only exists for
// `qubit serve`). So it asks, via the `api_base` command below.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::process::{Child, Command};
use std::sync::Mutex;
use tauri::Manager;

struct ApiProcess(Mutex<Option<Child>>);

/// The port the API child was actually started on, for the `api_base` command to report.
struct ApiPort(u16);

/// 8787 first (the documented default), then memorable alternatives, then whatever the OS gives.
const PORT_CANDIDATES: [u16; 5] = [8787, 8080, 8099, 9797, 17870];

/// True if something already accepts connections on this port.
///
/// Defence in depth, not a fix for an observed failure — worth being precise about. A bind test alone
/// can be insufficient on Windows, where a second socket may join a port another process is already
/// listening on depending on the options that first socket set (SO_REUSEADDR / SO_EXCLUSIVEADDRUSE).
/// A connect probe answers the question the bind cannot: is anything actually serving here.
///
/// The concrete failure that prompted this check turned out to be a misreading on my part: an
/// apparently orphaned uvicorn holding the port was in fact the venv's `uvicorn.exe` stub's own
/// python child, i.e. this app's API working correctly. Kept regardless, because it is cheap and it
/// makes port selection agree with reality rather than with one syscall's opinion of it.
fn port_in_use(port: u16) -> bool {
    use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
    let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
    TcpStream::connect_timeout(&addr.into(), std::time::Duration::from_millis(350)).is_ok()
}

/// First port on 127.0.0.1 this machine will actually let us bind.
///
/// Two checks, deliberately: nothing may answer a connect, AND a bind must succeed. A free port is
/// not the same as a bindable port on Windows (see the note at the top of this file), and a bindable
/// port is not necessarily an unused one (see `port_in_use`). The listener is dropped immediately,
/// which leaves a small race before the child binds it; that is unavoidable in any pre-flight
/// selection and is why the connect check matters more than the bind.
fn pick_port() -> u16 {
    for candidate in PORT_CANDIDATES {
        if port_in_use(candidate) {
            continue;
        }
        if std::net::TcpListener::bind(("127.0.0.1", candidate)).is_ok() {
            return candidate;
        }
    }
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .and_then(|listener| listener.local_addr())
        .map(|addr| addr.port())
        .unwrap_or(PORT_CANDIDATES[0])
}

/// Where the dashboard should send its API requests. Invoked by the front-end at boot.
#[tauri::command]
fn api_base(port: tauri::State<ApiPort>) -> String {
    format!("http://127.0.0.1:{}/api/v1", port.0)
}

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

fn spawn_api(root: &std::path::Path, port: u16) -> std::io::Result<Child> {
    let dist = root.join("dashboard").join("dist");
    let port_str = port.to_string();
    let args = [
        "qubit_api.main:app",
        "--host",
        "127.0.0.1",
        "--port",
        port_str.as_str(),
    ];

    // Prefer the venv's uvicorn directly: it removes the `uv run` resolution layer and two extra
    // process hops, which measurably shortens cold start (the app previously took ~26s to bind vs
    // ~3s warm). Fall back to `uv run` when there's no venv (fresh clone).
    let venv_uvicorn = root.join(".venv").join("Scripts").join("uvicorn.exe");
    let venv_uvicorn_nix = root.join(".venv").join("bin").join("uvicorn");
    let mut cmd = if venv_uvicorn.is_file() {
        let mut c = Command::new(venv_uvicorn);
        c.args(args);
        c
    } else if venv_uvicorn_nix.is_file() {
        let mut c = Command::new(venv_uvicorn_nix);
        c.args(args);
        c
    } else {
        let mut c = Command::new("uv");
        c.arg("run").arg("uvicorn").args(args);
        c
    };

    cmd.current_dir(root)
        // Serve the dashboard from the API too (single origin) + keep the bundle's default token.
        .env("QUBIT_DASHBOARD_DIST", dist)
        .env("QUBIT_API_TOKEN", "dev_token")
        .spawn()
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .manage(ApiProcess(Mutex::new(None)))
        .manage(ApiPort(pick_port()))
        .invoke_handler(tauri::generate_handler![api_base])
        .setup(|app| {
            let port = app.state::<ApiPort>().0;
            match repo_root() {
                Some(root) => match spawn_api(&root, port) {
                    Ok(child) => {
                        *app.state::<ApiProcess>().0.lock().unwrap() = Some(child);
                    }
                    Err(e) => {
                        eprintln!(
                            "QUBIT: failed to start the API from {} on port {port}: {e}.                              Is `uv` on PATH?",
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
