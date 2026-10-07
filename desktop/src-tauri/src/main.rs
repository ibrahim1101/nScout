#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::Deserialize;
use std::{
    fs,
    path::PathBuf,
    sync::Mutex,
    thread,
    time::Duration,
};
use tauri::{Manager, RunEvent};
use tauri_plugin_shell::{process::CommandChild, ShellExt};

const READINESS_ATTEMPTS: usize = 160;
const READINESS_INTERVAL: Duration = Duration::from_millis(250);

struct BackendState(Mutex<Option<CommandChild>>);

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

fn wait_for_backend(app: tauri::AppHandle, readiness_path: PathBuf) {
    thread::spawn(move || {
        for _ in 0..READINESS_ATTEMPTS {
            if let Ok(payload) = fs::read_to_string(&readiness_path) {
                match serde_json::from_str::<Readiness>(&payload) {
                    Ok(readiness) if readiness.status == "ready" && readiness.url.starts_with("http://127.0.0.1:") => {
                        if let Some(window) = app.get_webview_window("main") {
                            let url = serde_json::to_string(&readiness.url).unwrap();
                            let _ = window.eval(&format!("window.location.replace({url});"));
                        }
                        let _ = fs::remove_file(&readiness_path);
                        return;
                    }
                    Ok(_) => {}
                    Err(error) => {
                        if let Some(window) = app.get_webview_window("main") {
                            startup_error(&window, &format!("Invalid backend readiness response: {error}"));
                        }
                        return;
                    }
                }
            }
            thread::sleep(READINESS_INTERVAL);
        }
        if let Some(window) = app.get_webview_window("main") {
            startup_error(&window, "The local backend did not become ready within 40 seconds. Close nScout and try again.");
        }
    });
}

fn main() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(BackendState(Mutex::new(None)))
        .setup(|app| {
            let app_data = app.path().app_data_dir()?;
            fs::create_dir_all(&app_data)?;
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
            let (_events, child) = sidecar.spawn()?;
            *app.state::<BackendState>().0.lock().expect("backend state lock") = Some(child);

            wait_for_backend(app.handle().clone(), readiness_path);
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("failed to build nScout desktop shell");

    app.run(|app_handle, event| {
        if matches!(event, RunEvent::ExitRequested { .. } | RunEvent::Exit) {
            if let Some(child) = app_handle
                .state::<BackendState>()
                .0
                .lock()
                .expect("backend state lock")
                .take()
            {
                let _ = child.kill();
            }
        }
    });
}
