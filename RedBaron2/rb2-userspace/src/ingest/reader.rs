use anyhow::Context;
use chrono::SecondsFormat;
use log::trace;
use serde_json::{Value, json};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};

#[derive(Debug, Clone)]
pub struct LogRecord {
    pub log_type: &'static str,
    pub record: Value,
}

/// Get the offset file path for a log file (hidden dot-file)
/// If log_file has no usable parent component, places it in the CWD
pub fn offset_path(log_file: &Path, forwarder_name: Option<&str>) -> PathBuf {
    let parent = log_file
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    let name = log_file
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("log");

    forwarder_name.map_or_else(
        || parent.join(format!(".{name}.offset")),
        |forwarder_name| parent.join(format!(".{name}.{forwarder_name}.offset")),
    )
}

/// Read the last offset from the offset file
pub async fn get_offset(offset_path: &Path) -> io::Result<u64> {
    match fs::read_to_string(offset_path).await {
        Ok(content) => content
            .trim()
            .parse::<u64>()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(e),
    }
}

/// Save the current offset to the offset file
pub async fn save_offset(offset_path: &Path, offset: u64) -> io::Result<()> {
    fs::write(offset_path, offset.to_string()).await
}

/// Read new log lines from path starting at start_offset, pushing records into all_records
/// Returns the new offset.
pub async fn read_from_offset_into(
    path: &Path,
    log_type: &'static str,
    start_offset: u64,
    end_offset: Option<u64>,
    max_records: Option<usize>,
    all_records: &mut Vec<Arc<LogRecord>>,
) -> anyhow::Result<u64> {
    let metadata = fs::metadata(path)
        .await
        .with_context(|| format!("Failed to get metadata for {}", path.display()))?;

    let file_size = metadata.len();
    let mut start = start_offset;

    if start > file_size {
        trace!(
            "Offset {} past file size {} for {}, clamping to 0",
            start,
            file_size,
            path.display()
        );
        start = 0;
    }

    let mut file = fs::File::open(path)
        .await
        .with_context(|| format!("Failed to open {}", path.display()))?;

    file.seek(std::io::SeekFrom::Start(start))
        .await
        .with_context(|| format!("Failed to seek to offset {} in {}", start, path.display()))?;

    let mut reader = BufReader::new(file);
    let mut current_offset = start;
    let mut line = String::new();

    let mut records_read = 0usize;

    loop {
        if let Some(limit) = end_offset
            && current_offset >= limit
        {
            break;
        }
        line.clear();
        let bytes_read = reader.read_line(&mut line).await?;
        if bytes_read == 0 {
            break; // EOF
        }

        if let Some(limit) = end_offset {
            let next_offset = current_offset + bytes_read as u64;
            if next_offset > limit {
                break;
            }
        }

        current_offset += bytes_read as u64;

        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            continue;
        }

        let record = match log_type {
            "firewall" | "yara" | "process" | "scan" | "fim" | "alerts" | "auth" | "health"
            | "network" | "audit" => parse_log_line(trimmed, log_type)?,
            _ => json!({
                "_timestamp": chrono::Local::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                "log_type": log_type,
                "message": trimmed,
            }),
        };

        all_records.push(Arc::new(LogRecord { log_type, record }));
        records_read += 1;
        if let Some(limit) = max_records
            && records_read >= limit
        {
            break;
        }
    }

    Ok(current_offset)
}

/// Parse a log string into json
/// Adds `log_type` and normalises `timestamp` -> `_timestamp`.
pub fn parse_log_line(line: &str, log_type: &str) -> anyhow::Result<Value> {
    if let Ok(mut value) = serde_json::from_str::<Value>(line) {
        if let Some(obj) = value.as_object_mut() {
            obj.insert("log_type".to_string(), json!(log_type));

            if !obj.contains_key("_timestamp") {
                if let Some(ts) = obj.remove("timestamp") {
                    obj.insert("_timestamp".to_string(), ts);
                } else {
                    let ts = chrono::Local::now().to_rfc3339_opts(SecondsFormat::Millis, true);
                    obj.insert("_timestamp".to_string(), json!(ts));
                }
            }
        }
        return Ok(value);
    }

    Ok(json!({
        "_timestamp": chrono::Local::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        "log_type": log_type,
        "message": line,
    }))
}

/// Read new log lines from a file since the last offset into all_records Vec
pub async fn read_logs(
    log_file: &Path,
    log_type: &'static str,
    _rollover_size: u64,
    all_records: &mut Vec<Arc<LogRecord>>,
) -> anyhow::Result<()> {
    let offset_file = offset_path(log_file, None);

    // If log file doesn't exist, delete the offset file and return
    if !log_file.exists() {
        let _ = fs::remove_file(&offset_file).await;
        return Ok(());
    }

    let mut start_offset = get_offset(&offset_file)
        .await
        .with_context(|| format!("Failed to read offset from {}", offset_file.display()))?;

    // When log4rs rotates the file start reading from the beginning again
    let file_metadata = fs::metadata(log_file)
        .await
        .with_context(|| format!("Failed to get metadata for {}", log_file.display()))?;
    let file_size = file_metadata.len();

    if start_offset > file_size {
        trace!("File offset past file size, rebuilding offset file");
        let _ = fs::remove_file(&offset_file).await;
        start_offset = 0;
    }

    // Read current file
    let new_offset =
        read_from_offset_into(log_file, log_type, start_offset, None, None, all_records).await?;

    save_offset(&offset_file, new_offset)
        .await
        .with_context(|| format!("Failed to save offset to {}", offset_file.display()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("rb2-{name}-{nanos}.log"))
    }

    #[test]
    fn offset_path_is_namespaced_per_forwarder() {
        let path = Path::new("/tmp/rb2_process");
        assert_eq!(
            offset_path(path, Some("openobserve")),
            PathBuf::from("/tmp/.rb2_process.openobserve.offset")
        );
        assert_eq!(
            offset_path(path, Some("splunk")),
            PathBuf::from("/tmp/.rb2_process.splunk.offset")
        );
    }

    #[test]
    fn parse_log_line_normalizes_timestamp() {
        let parsed = parse_log_line(r#"{"timestamp":"2024-01-01T00:00:00Z","a":1}"#, "process")
            .expect("parse ok");

        assert_eq!(parsed["_timestamp"], "2024-01-01T00:00:00Z");
        assert!(parsed.get("timestamp").is_none());
        assert_eq!(parsed["log_type"], "process");
    }

    #[test]
    fn parse_log_line_preserves_existing_timestamp() {
        let parsed = parse_log_line(
            r#"{"_timestamp":"2024-01-01T00:00:00Z","timestamp":"old"}"#,
            "health",
        )
        .expect("parse ok");

        assert_eq!(parsed["_timestamp"], "2024-01-01T00:00:00Z");
        assert_eq!(parsed["timestamp"], "old");
        assert_eq!(parsed["log_type"], "health");
    }

    #[test]
    fn parse_log_line_wraps_plain_text() {
        let parsed = parse_log_line("hello world", "scan").expect("parse ok");

        assert_eq!(parsed["message"], "hello world");
        assert_eq!(parsed["log_type"], "scan");
        assert!(parsed.get("_timestamp").is_some());
    }

    #[test]
    fn parse_log_line_handles_auth_json() {
        let parsed =
            parse_log_line(r#"{"stage":"pam_authenticate","rc":0}"#, "auth").expect("parse ok");

        assert_eq!(parsed["stage"], "pam_authenticate");
        assert_eq!(parsed["rc"], 0);
        assert_eq!(parsed["log_type"], "auth");
        assert!(parsed.get("_timestamp").is_some());
    }

    #[test]
    fn parse_log_line_handles_network_dns_json() {
        let parsed = parse_log_line(
            r#"{"protocol":"dns","query_name":"example.com","query_type":"A","transaction_id":4660}"#,
            "network",
        )
        .expect("parse ok");

        assert_eq!(parsed["protocol"], "dns");
        assert_eq!(parsed["query_name"], "example.com");
        assert_eq!(parsed["query_type"], "A");
        assert_eq!(parsed["transaction_id"], 4660);
        assert_eq!(parsed["log_type"], "network");
        assert!(parsed.get("_timestamp").is_some());
    }

    #[test]
    fn parse_log_line_handles_network_http_json() {
        let parsed = parse_log_line(
            r#"{"protocol":"http","method":"GET","path":"/","request_line":"GET / HTTP/1.1"}"#,
            "network",
        )
        .expect("parse ok");

        assert_eq!(parsed["protocol"], "http");
        assert_eq!(parsed["method"], "GET");
        assert_eq!(parsed["path"], "/");
        assert_eq!(parsed["request_line"], "GET / HTTP/1.1");
        assert_eq!(parsed["log_type"], "network");
        assert!(parsed.get("_timestamp").is_some());
    }

    #[test]
    fn parse_log_line_handles_network_https_json() {
        let parsed = parse_log_line(
            r#"{"protocol":"https","method":"GET","path":"/secure","request_line":"GET /secure HTTP/1.1","tls_library":"openssl"}"#,
            "network",
        )
        .expect("parse ok");

        assert_eq!(parsed["protocol"], "https");
        assert_eq!(parsed["method"], "GET");
        assert_eq!(parsed["path"], "/secure");
        assert_eq!(parsed["request_line"], "GET /secure HTTP/1.1");
        assert_eq!(parsed["tls_library"], "openssl");
        assert_eq!(parsed["log_type"], "network");
        assert!(parsed.get("_timestamp").is_some());
    }

    #[tokio::test]
    async fn read_from_offset_into_honors_end_offset_and_max_records() {
        let path = unique_temp_path("reader-bounds");
        fs::write(&path, b"{\"msg\":1}\n{\"msg\":2}\n{\"msg\":3}\n")
            .await
            .expect("write temp log");

        let first_limit = b"{\"msg\":1}\n{\"msg\":2}\n".len() as u64;
        let mut records = Vec::new();

        let offset = read_from_offset_into(
            &path,
            "process",
            0,
            Some(first_limit),
            Some(1),
            &mut records,
        )
        .await
        .expect("read ok");

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].record["msg"], 1);
        assert_eq!(offset, b"{\"msg\":1}\n".len() as u64);

        let mut second_records = Vec::new();
        let second_offset = read_from_offset_into(
            &path,
            "process",
            offset,
            Some(first_limit),
            Some(10),
            &mut second_records,
        )
        .await
        .expect("read second ok");

        assert_eq!(second_records.len(), 1);
        assert_eq!(second_records[0].record["msg"], 2);
        assert_eq!(second_offset, first_limit);

        let _ = fs::remove_file(&path).await;
    }

    #[test]
    fn parse_log_line_normalizes_fim_timestamp() {
        let line = r#"{"timestamp":"2026-03-29T12:00:00.000Z","path":"/etc/passwd","pid":1234,"ops":["modify"]}"#;

        let record = parse_log_line(line, "fim").expect("fim json parses");

        assert_eq!(record["log_type"], "fim");
        assert_eq!(record["path"], "/etc/passwd");
        assert_eq!(record["pid"], 1234);
        assert_eq!(record["ops"], json!(["modify"]));
        assert_eq!(record["_timestamp"], "2026-03-29T12:00:00.000Z");
        assert!(record.get("timestamp").is_none());
    }
}
