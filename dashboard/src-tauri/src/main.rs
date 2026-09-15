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

use std::fs::OpenOptions;
use std::process::{Child, Command, Stdio};
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

/// `%APPDATA%\QUBIT\api.log`, next to `repo_root.txt` (see `config_path`).
fn log_path() -> Option<std::path::PathBuf> {
    let base = std::env::var("APPDATA")
        .ok()
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var("HOME").ok().map(std::path::PathBuf::from))?;
    Some(base.join("QUBIT").join("api.log"))
}

fn desktop_api_token(configured: Option<String>) -> String {
    // A configured credential must never be replaced by a published development token.
    configured.unwrap_or_else(|| "dev_token".to_owned())
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

    // Run the venv interpreter directly, not the Windows `uvicorn.exe` console-script wrapper.
    // That wrapper starts a second Python process and then exits, so killing the `Child` stored by
    // Tauri can leave the real API process listening after the desktop window closes. `python -m
    // uvicorn` gives the app ownership of the actual server process and also avoids the `uv run`
    // resolution layer on normal installs. Fall back to `uv run` for a fresh clone without a venv.
    let venv_python = root.join(".venv").join("Scripts").join("python.exe");
    let venv_python_nix = root.join(".venv").join("bin").join("python");
    let mut cmd = if venv_python.is_file() {
        let mut c = Command::new(venv_python);
        c.arg("-m").arg("uvicorn").args(args);
        c
    } else if venv_python_nix.is_file() {
        let mut c = Command::new(venv_python_nix);
        c.arg("-m").arg("uvicorn").args(args);
        c
    } else {
        let mut c = Command::new("uv");
        c.arg("run").arg("uvicorn").args(args);
        c
    };

    cmd.current_dir(root)
        // Serve the dashboard from the API too (single origin). Honor an operator's token;
        // the dashboard Login page accepts the matching credential when one is configured.
        .env("QUBIT_DASHBOARD_DIST", dist)
        .env(
            "QUBIT_API_TOKEN",
            desktop_api_token(std::env::var("QUBIT_API_TOKEN").ok()),
        )
        // A release build carries `windows_subsystem = "windows"` (no console), so this process's
        // own stdio handles are invalid. `Command::spawn` INHERITS by default, and uvicorn writes
        // its startup banner to stdout before it ever binds a socket -- so the child blocked on
        // that first write and never got as far as listening. Measured: the child process existed,
        // held 0 CPU time indefinitely, and no port was ever bound. Explicit stdio, even to a file
        // that fails to open, is what stops that -- `Stdio::null()` alone would have fixed the
        // hang with no way to see why a future failure happened, which is what made this one take
        // a live process inspection to find in the first place.
        .stdin(Stdio::null());
    match open_log_file() {
        Some((out, err)) => {
            cmd.stdout(Stdio::from(out)).stderr(Stdio::from(err));
        }
        None => {
            cmd.stdout(Stdio::null()).stderr(Stdio::null());
        }
    }
    cmd.spawn()
}

/// Two independent handles on the same log file (one per stream), or `None` if it could not be
/// opened -- the caller falls back to `Stdio::null()` rather than failing the whole launch over a
/// log file.
fn open_log_file() -> Option<(std::fs::File, std::fs::File)> {
    let path = log_path()?;
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let out = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .ok()?;
    let err = out.try_clone().ok()?;
    Some((out, err))
}

/// Point the window at the API's own copy of the dashboard once the API answers.
///
/// The window starts on `frontendDist` -- the copy compiled INTO this exe. That copy is frozen at
/// build time, which made every dashboard change require a full `tauri build` plus a reinstall
/// before it could be seen, and a stale window looked identical to a broken one. The API already
/// serves the dashboard from `dashboard/dist` (that is what `QUBIT_DASHBOARD_DIST` is for, and how
/// `qubit-desktop.bat` has always run it), so navigating there instead makes `npm run build` the
/// only step a UI change needs.
///
/// Same-origin is the point, not a side effect: the page then comes from the API, so
/// `_mount_dashboard` injects `__QUBIT_API_BASE__` and the front-end talks to the port it was
/// actually served from rather than guessing one.
///
/// Polls rather than navigating immediately -- uvicorn takes a moment, and a webview pointed at a
/// dead port renders a browser error page instead of the app's own "starting the engine" state.
/// Gives up after ~30s and leaves the bundled copy on screen, which still works.
fn serve_ui_from_api(handle: tauri::AppHandle, port: u16) {
    std::thread::spawn(move || {
        let address = format!("http://127.0.0.1:{port}/");
        for _ in 0..120 {
            if port_in_use(port) {
                if let (Some(window), Ok(url)) =
                    (handle.get_webview_window("main"), address.parse())
                {
                    let _ = window.navigate(url);
                }
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        eprintln!("QUBIT: the API never came up on {port}; showing the bundled dashboard instead.");
    });
}

/// Keep the API child alive for as long as the window is open.
///
/// The child was spawned once at setup and never looked at again. When uvicorn exited -- killed by
/// something else on the machine, or dying on its own -- nothing noticed: the window stayed open
/// showing whatever it had last loaded, and every request from then on failed with
/// `Failed to fetch`. `BootGate` cannot help, because it only runs once before the app renders.
/// Observed directly: `qubit-desktop.exe` running with no `uvicorn` process at all and nothing
/// listening on the port, while the UI still displayed a populated dashboard.
///
/// Restarts are rate-limited rather than unbounded. A child that cannot bind its port, or dies on
/// an unmigrated database, would otherwise be respawned forever, and a hot loop of failing starts
/// is worse than an app that stops and says so -- the log is where the reason lives either way.
fn supervise_api(handle: tauri::AppHandle, root: std::path::PathBuf, port: u16) {
    std::thread::spawn(move || {
        const MAX_RESTARTS: u32 = 5;
        let mut restarts = 0u32;
        loop {
            std::thread::sleep(std::time::Duration::from_secs(2));

            // `try_wait` reaps without blocking. Holding the lock only long enough to ask keeps
            // window teardown -- which takes the same lock to kill the child -- from deadlocking
            // against this thread.
            let exited = {
                let state = handle.state::<ApiProcess>();
                let mut slot = match state.0.lock() {
                    Ok(slot) => slot,
                    Err(_) => return,
                };
                match slot.as_mut() {
                    // Taken by the window-close handler: the app is going away, so stop watching.
                    None => return,
                    Some(child) => match child.try_wait() {
                        Ok(Some(status)) => Some(status),
                        Ok(None) => None,
                        // The handle is unusable; another poll would report the same thing.
                        Err(_) => return,
                    },
                }
            };

            let Some(status) = exited else { continue };
            if restarts >= MAX_RESTARTS {
                eprintln!(
                    "QUBIT: the API exited ({status}) and has already been restarted \
                     {MAX_RESTARTS} times; not restarting again. See the API log."
                );
                return;
            }
            restarts += 1;
            eprintln!(
                "QUBIT: the API exited ({status}); restarting it (attempt {restarts} of \
                 {MAX_RESTARTS})."
            );
            match spawn_api(&root, port) {
                Ok(child) => {
                    if let Ok(mut slot) = handle.state::<ApiProcess>().0.lock() {
                        *slot = Some(child);
                    }
                }
                Err(e) => eprintln!("QUBIT: could not restart the API on port {port}: {e}"),
            }
        }
    });
}

/// Stop the server process *and* every wrapper/worker it started.
///
/// On Windows, a venv Python launcher may hand work to the uv-managed interpreter and exit later;
/// `Child::kill()` only reaches that immediate launcher. `taskkill /T` is the platform-provided
/// process-tree operation, so the API cannot survive the Tauri window that owns it. On Unix the
/// venv interpreter execs the server, making the direct child kill sufficient.
fn stop_api(child: &mut Child) {
    #[cfg(windows)]
    {
        let pid = child.id().to_string();
        let _ = Command::new("taskkill")
            .args(["/PID", pid.as_str(), "/T", "/F"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    #[cfg(not(windows))]
    {
        let _ = child.kill();
    }
    let _ = child.wait();
}

fn main() {
    tauri::Builder::default()
        // One instance, always. Each launch spawns its own uvicorn against the SAME SQLite file, so
        // a second window is not a second workspace -- it is two writers on one database, which
        // surfaced as `database is locked` mid-migration and as a window whose own API had died on
        // `WinError 10048` (port already bound) while still showing the last data it had loaded.
        // A relaunch now raises the window that already exists.
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.unminimize();
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
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
                        serve_ui_from_api(app.handle().clone(), port);
                        supervise_api(app.handle().clone(), root.clone(), port);
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
                    stop_api(child);
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running QUBIT desktop");
}

#[cfg(test)]
mod security_tests {
    use super::desktop_api_token;

    #[test]
    fn desktop_preserves_configured_token() {
        assert_eq!(
            desktop_api_token(Some("operator-test-value".into())),
            "operator-test-value"
        );
    }

    #[test]
    fn desktop_only_defaults_when_token_is_absent() {
        assert_eq!(desktop_api_token(None), "dev_token");
        assert_eq!(desktop_api_token(Some(String::new())), "");
    }
}
