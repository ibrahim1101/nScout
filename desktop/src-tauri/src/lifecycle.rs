use serde::Serialize;
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_LOG_BYTES: u64 = 256 * 1024;

#[derive(Serialize)]
struct LifecycleEvent<'a> {
    timestamp_ms: u64,
    event: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<&'a str>,
}

fn previous_log_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("desktop-lifecycle.jsonl");
    path.with_file_name(format!("{file_name}.previous"))
}

fn rotate_if_needed(path: &Path) -> io::Result<()> {
    let Ok(metadata) = fs::metadata(path) else {
        return Ok(());
    };
    if metadata.len() < MAX_LOG_BYTES {
        return Ok(());
    }

    let previous = previous_log_path(path);
    match fs::remove_file(&previous) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    fs::rename(path, previous)
}

pub fn record(path: &Path, event: &str, detail: Option<&str>) -> io::Result<()> {
    rotate_if_needed(path)?;
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX);
    let entry = LifecycleEvent {
        timestamp_ms,
        event,
        detail,
    };

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    serde_json::to_writer(&mut file, &entry).map_err(io::Error::other)?;
    file.write_all(b"\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_directory() -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "nscout-lifecycle-{}-{suffix}",
            std::process::id()
        ))
    }

    #[test]
    fn writes_json_lines_and_rotates_bounded_log() {
        let directory = test_directory();
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("desktop-lifecycle.jsonl");

        record(&path, "shell_start", None).unwrap();
        let first_line = fs::read_to_string(&path).unwrap();
        let first_event: serde_json::Value = serde_json::from_str(first_line.trim()).unwrap();
        assert_eq!(first_event["event"], "shell_start");
        assert!(first_event.get("detail").is_none());

        fs::write(&path, vec![b'x'; MAX_LOG_BYTES as usize]).unwrap();
        record(&path, "backend_ready", Some("loopback")).unwrap();

        let rotated = previous_log_path(&path);
        assert_eq!(fs::metadata(rotated).unwrap().len(), MAX_LOG_BYTES);
        let current = fs::read_to_string(&path).unwrap();
        let current_event: serde_json::Value = serde_json::from_str(current.trim()).unwrap();
        assert_eq!(current_event["event"], "backend_ready");
        assert_eq!(current_event["detail"], "loopback");

        fs::remove_dir_all(directory).unwrap();
    }
}
