#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod lifecycle;

use serde::Deserialize;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
    thread,
    time::Duration,
};
use tauri::{Manager, RunEvent};
use tauri_plugin_shell::{process::CommandChild, ShellExt};

const READINESS_ATTEMPTS: usize = 160;
const READINESS_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Default)]
struct BackendState {
    child: Mutex<Option<CommandChild>>,
    lifecycle_path: Mutex<Option<PathBuf>>,
}

#[derive(Deserialize)]
struct Readiness {
    status: String,
    url: String,
}

fn startup_error(window: &tauri::WebviewWindow, detail: &str) {
    let message = serde_json::to_string(detail).unwrap_or_else(|_| "\"Unknown startup error\"".into());
    let script = format!(
        "document.getElementById('startup-status').innerHTML = '<h1>nScout could not start</h1><p></p>'; document.querySelector('#startup-status p').textContent = {message};"
    );
    let _ = window.eval(&script);
}

fn stop_backend(app: &tauri::AppHandle, lifecycle_path: &Path, reason: &str) {
    let child = app
        .state::<BackendState>()
        .child
        .lock()
        .expect("backend state lock")
        .take();

    if let Some(child) = child {
        match child.kill() {
            Ok(()) => {
                let _ = lifecycle::record(lifecycle_path, "backend_stopped", Some(reason));
            }
            Err(_) => {
                let _ = lifecycle::record(lifecycle_path, "backend_stop_failed", Some(reason));
            }
        }
    }
}

fn wait_for_backend(app: tauri::AppHandle, readiness_path: PathBuf, lifecycle_path: PathBuf) {
    thread::spawn(move || {
        for _ in 0..READINESS_ATTEMPTS {
            if let Ok(payload) = fs::read_to_string(&readiness_path) {
                match serde_json::from_str::<Readiness>(&payload) {
                    Ok(readiness) if readiness.status == "ready" && readiness.url.starts_with("http://127.0.0.1:") => {
                        let _ = lifecycle::record(&lifecycle_path, "backend_ready", Some("loopback"));
                        if let Some(window) = app.get_webview_window("main") {
                            let url = serde_json::to_string(&readiness.url).unwrap();
                            let _ = window.eval(&format!("window.location.replace({url});"));
                        }
                        let _ = fs::remove_file(&readiness_path);
                        return;
                    }
                    Ok(_) | Err(_) => {
                        let _ = lifecycle::record(&lifecycle_path, "startup_invalid_readiness", None);
                        if let Some(window) = app.get_webview_window("main") {
                            startup_error(&window, "The local backend returned an invalid readiness response. Close nScout and try again.");
                        }
                        stop_backend(&app, &lifecycle_path, "invalid_readiness");
                        return;
                    }
                }
            }
            thread::sleep(READINESS_INTERVAL);
        }
        let _ = lifecycle::record(&lifecycle_path, "startup_timeout", None);
        if let Some(window) = app.get_webview_window("main") {
            startup_error(&window, "The local backend did not become ready within 40 seconds. Close nScout and try again.");
        }
        stop_backend(&app, &lifecycle_path, "startup_timeout");
    });
}

fn main() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Ok(app_data) = app.path().app_data_dir() {
                let _ = lifecycle::record(
                    &app_data.join("desktop-lifecycle.jsonl"),
                    "second_instance_focus",
                    None,
                );
            }
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.unminimize();
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_shell::init())
        .manage(BackendState::default())
        .setup(|app| {
            let app_data = app.path().app_data_dir()?;
            fs::create_dir_all(&app_data)?;
            let lifecycle_path = app_data.join("desktop-lifecycle.jsonl");
            let _ = lifecycle::record(&lifecycle_path, "shell_start", None);
            *app.state::<BackendState>()
                .lifecycle_path
                .lock()
                .expect("lifecycle state lock") = Some(lifecycle_path.clone());

            let readiness_path = app_data.join("backend-ready.json");
            let _ = fs::remove_file(&readiness_path);

            let readiness_arg = readiness_path.to_string_lossy().into_owned();
            let sidecar = app
                .shell()
                .sidecar("nscout-backend")?
                .args(vec![
                    "--no-browser".to_string(),
                    "--readiness-file".to_string(),
                    readiness_arg,
                ]);
            let (_events, child) = match sidecar.spawn() {
                Ok(spawned) => spawned,
                Err(error) => {
                    let _ = lifecycle::record(&lifecycle_path, "backend_spawn_failed", None);
                    return Err(error.into());
                }
            };
            let _ = lifecycle::record(&lifecycle_path, "backend_spawned", None);
            *app.state::<BackendState>()
                .child
                .lock()
                .expect("backend state lock") = Some(child);

            wait_for_backend(app.handle().clone(), readiness_path, lifecycle_path);
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("failed to build nScout desktop shell");

    app.run(|app_handle, event| {
        if matches!(event, RunEvent::ExitRequested { .. } | RunEvent::Exit) {
            let lifecycle_path = app_handle
                .state::<BackendState>()
                .lifecycle_path
                .lock()
                .expect("lifecycle state lock")
                .clone();
            if let Some(lifecycle_path) = lifecycle_path {
                stop_backend(app_handle, &lifecycle_path, "application_exit");
            }
        }
    });
}
