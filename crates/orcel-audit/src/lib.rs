use orcel_contracts::RequestEnvelope;
use orcel_platform::paths;
pub use orcel_platform::PlatformError;
use serde::Serialize;
use std::borrow::Cow;
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct AuditLogger {
    path: PathBuf,
    /// Whether the next record first checks for a torn last line: set when the log was torn
    /// when this logger was made, and after a failed write. The check reads the log, and a read
    /// that overlaps another writer's append can see it half done, so it runs only when there
    /// is reason to; checking every record would also add a read open per request.
    check_tail: Arc<AtomicBool>,
}

/// The longest client-supplied field a record keeps, and the longest target. The client chooses
/// these values, so without a bound one request could make one record, and the log, any size.
pub const MAX_FIELD_CHARS: usize = 256;
pub const MAX_TARGET_CHARS: usize = 1024;
const TRUNCATED: &str = "…[truncated]";

#[derive(Debug, Serialize)]
struct AuditEvent<'a> {
    timestamp_ms: u128,
    request_id: Cow<'a, str>,
    client_session_id: Cow<'a, str>,
    workspace_id: Cow<'a, str>,
    capability: Cow<'a, str>,
    operation: Cow<'a, str>,
    target: Option<Cow<'a, str>>,
    policy_revision: &'a str,
    outcome: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    caller: Option<CallerEvent<'a>>,
}

/// The local process that called a method outside the kernel request path (F4 slice 5: the
/// app API's `task.stop`), as the kernel identified its peer. The audit log keeps it so every
/// stop attempt names who asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditCaller {
    pub pid: u32,
    /// The process start generation the kernel read for the peer, and how it was read.
    pub start_generation: u64,
    pub generation_source: String,
    /// The caller's executable path, or why it could not be read.
    pub executable: Result<String, String>,
}

#[derive(Debug, Serialize)]
struct CallerEvent<'a> {
    pid: u32,
    start_generation: u64,
    generation_source: Cow<'a, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    executable: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    executable_unavailable: Option<Cow<'a, str>>,
}

impl<'a> CallerEvent<'a> {
    fn of(caller: &'a AuditCaller) -> Self {
        Self {
            pid: caller.pid,
            start_generation: caller.start_generation,
            generation_source: bounded(&caller.generation_source, MAX_FIELD_CHARS),
            executable: caller
                .executable
                .as_deref()
                .ok()
                .map(|path| bounded(path, MAX_TARGET_CHARS)),
            executable_unavailable: caller
                .executable
                .as_ref()
                .err()
                .map(|reason| bounded(reason, MAX_FIELD_CHARS)),
        }
    }
}

/// `value`, or its first `max` characters marked as cut.
fn bounded(value: &str, max: usize) -> Cow<'_, str> {
    match value.char_indices().nth(max) {
        None => Cow::Borrowed(value),
        Some((end, _)) => Cow::Owned(format!("{}{TRUNCATED}", &value[..end])),
    }
}

/// Whether the log ends in the middle of a line, as a crash or a full disk during an earlier
/// write can leave it. The next record then starts on a line of its own, so it isn't glued onto
/// the broken one.
fn ends_mid_line(path: &Path) -> bool {
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    if file.seek(SeekFrom::End(-1)).is_err() {
        return false;
    }
    let mut last = [0u8; 1];
    file.read_exact(&mut last).is_ok() && last[0] != b'\n'
}

impl AuditLogger {
    pub fn new(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Made once at start, before this process writes anything.
        let torn = ends_mid_line(&path);
        Ok(Self {
            path,
            check_tail: Arc::new(AtomicBool::new(torn)),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn record(
        &self,
        request: &RequestEnvelope,
        policy_revision: &str,
        outcome: &str,
    ) -> io::Result<()> {
        self.write(request, policy_revision, outcome, None)
    }

    /// [`Self::record`], naming the local process that called (F4 slice 5).
    pub fn record_with_caller(
        &self,
        request: &RequestEnvelope,
        policy_revision: &str,
        outcome: &str,
        caller: &AuditCaller,
    ) -> io::Result<()> {
        self.write(request, policy_revision, outcome, Some(caller))
    }

    fn write(
        &self,
        request: &RequestEnvelope,
        policy_revision: &str,
        outcome: &str,
        caller: Option<&AuditCaller>,
    ) -> io::Result<()> {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();

        let event = AuditEvent {
            timestamp_ms,
            request_id: bounded(&request.request_id, MAX_FIELD_CHARS),
            client_session_id: bounded(&request.client_session_id, MAX_FIELD_CHARS),
            workspace_id: bounded(&request.workspace_id, MAX_FIELD_CHARS),
            capability: bounded(&request.capability, MAX_FIELD_CHARS),
            operation: bounded(&request.operation, MAX_FIELD_CHARS),
            target: request
                .target
                .as_deref()
                .map(|target| bounded(target, MAX_TARGET_CHARS)),
            policy_revision,
            outcome,
            caller: caller.map(CallerEvent::of),
        };

        // One whole line in one write. Several orcelds (one per client session) append to the
        // same log, and an append-mode write lands at the end in one piece; written in parts, as
        // `to_writer` does, two records could interleave.
        let mut line = if self.check_tail.swap(false, Ordering::AcqRel) && ends_mid_line(&self.path)
        {
            vec![b'\n']
        } else {
            Vec::new()
        };
        serde_json::to_writer(&mut line, &event)?;
        line.push(b'\n');
        let written = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .and_then(|mut file| file.write_all(&line).and_then(|()| file.flush()));
        if written.is_err() {
            // A failed write may have left part of the line.
            self.check_tail.store(true, Ordering::Release);
        }
        written
    }
}

/// `ORCEL_AUDIT_PATH`, else `audit.jsonl` in the private per-user Orcel state
/// root. Fails closed when the override is empty, relative or not in a private
/// directory, or when the root cannot be resolved or is not private; it never
/// falls back to the shared temp directory.
pub fn default_audit_path() -> Result<PathBuf, PlatformError> {
    default_audit_path_from(&|name| std::env::var_os(name))
}

/// [`default_audit_path`] with the environment read through `lookup`.
pub fn default_audit_path_from(
    lookup: &dyn Fn(&str) -> Option<OsString>,
) -> Result<PathBuf, PlatformError> {
    if let Some(path) = lookup("ORCEL_AUDIT_PATH") {
        return paths::private_file_override(path);
    }
    let root = paths::state_root_from(lookup)?;
    paths::ensure_private_dir(&root)?;
    Ok(orcel_platform::stores::AUDIT.path(&root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use orcel_contracts::RequestEnvelope;
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn next_temp_sequence() -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        // macOS clocks tick in microseconds, so a timestamp alone can repeat
        // across parallel tests in one process.
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    }

    #[test]
    fn writes_structured_event_without_arguments() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let suffix = format!("{suffix}-{}", next_temp_sequence());
        let path = std::env::temp_dir()
            .join(format!("orcel-audit-{suffix}"))
            .join("audit.jsonl");
        let logger = AuditLogger::new(&path).expect("audit");
        let req = RequestEnvelope {
            version: 1,
            request_id: "r".into(),
            client_session_id: "s".into(),
            workspace_id: "w".into(),
            capability: "fs.search".into(),
            operation: "search".into(),
            target: Some(".".into()),
            arguments: json!({"query":"TOP-SECRET-VALUE"}),
        };
        logger.record(&req, "p1", "SUCCESS").expect("record");
        let text = std::fs::read_to_string(&path).expect("read audit");
        assert!(!text.contains("TOP-SECRET-VALUE"));
        assert!(text.contains("\"capability\":\"fs.search\""));
        let _ = std::fs::remove_dir_all(path.parent().expect("parent"));
    }

    /// Writers appending at once, as several orcelds do, never interleave: every line is one
    /// whole record.
    #[test]
    fn concurrent_records_stay_whole_lines() {
        let base = sandbox("concurrent");
        let path = base.join("audit.jsonl");
        // Every logger is made before any writes, as each orceld makes its own at start.
        let loggers: Vec<AuditLogger> = (0..8)
            .map(|_| AuditLogger::new(&path).expect("audit"))
            .collect();
        let writers: Vec<_> = loggers
            .into_iter()
            .enumerate()
            .map(|(writer, logger)| {
                std::thread::spawn(move || {
                    for index in 0..200 {
                        let req = RequestEnvelope {
                            version: 1,
                            request_id: format!("w{writer}-{index}-{}", "x".repeat(300)),
                            client_session_id: format!("session-{writer}"),
                            workspace_id: "w".into(),
                            capability: "fs.search".into(),
                            operation: "search".into(),
                            target: Some("some/longer/target/path".into()),
                            arguments: json!({}),
                        };
                        logger.record(&req, "p1", "SUCCESS").expect("record");
                    }
                })
            })
            .collect();
        for writer in writers {
            writer.join().expect("writer");
        }
        let text = std::fs::read_to_string(&path).expect("read audit");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 8 * 200);
        for line in lines {
            let record: serde_json::Value = serde_json::from_str(line).expect("a whole record");
            assert_eq!(record["outcome"], "SUCCESS");
        }
        let _ = std::fs::remove_dir_all(base);
    }

    fn request(request_id: String, target: Option<String>) -> RequestEnvelope {
        RequestEnvelope {
            version: 1,
            request_id,
            client_session_id: "s".into(),
            workspace_id: "w".into(),
            capability: "fs.search".into(),
            operation: "search".into(),
            target,
            arguments: json!({}),
        }
    }

    /// F4 slice 5: a record can name its caller; the executable path or the reason it is
    /// unavailable is bounded like the client's fields, and a plain record has no caller.
    #[test]
    fn a_caller_is_recorded_bounded_and_only_when_given() {
        let base = sandbox("caller");
        let path = base.join("audit.jsonl");
        let logger = AuditLogger::new(&path).expect("audit");
        let read = AuditCaller {
            pid: 42,
            start_generation: 7,
            generation_source: "test".into(),
            executable: Ok("p".repeat(100_000)),
        };
        let unreadable = AuditCaller {
            executable: Err("r".repeat(100_000)),
            ..read.clone()
        };
        logger
            .record_with_caller(&request("a".into(), None), "p1", "SUCCESS", &read)
            .expect("record");
        logger
            .record_with_caller(
                &request("b".into(), None),
                "p1",
                "TARGET_STALE",
                &unreadable,
            )
            .expect("record");
        logger
            .record(&request("c".into(), None), "p1", "SUCCESS")
            .expect("record");
        let text = std::fs::read_to_string(&path).expect("read audit");
        let records: Vec<serde_json::Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).expect("a record"))
            .collect();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0]["caller"]["pid"], 42);
        assert_eq!(records[0]["caller"]["start_generation"], 7);
        let executable = records[0]["caller"]["executable"].as_str().unwrap();
        assert!(executable.ends_with(TRUNCATED));
        assert_eq!(
            executable.chars().count(),
            MAX_TARGET_CHARS + TRUNCATED.chars().count()
        );
        assert!(records[0]["caller"].get("executable_unavailable").is_none());
        let reason = records[1]["caller"]["executable_unavailable"]
            .as_str()
            .unwrap();
        assert_eq!(
            reason.chars().count(),
            MAX_FIELD_CHARS + TRUNCATED.chars().count()
        );
        assert!(records[1]["caller"].get("executable").is_none());
        assert!(records[2].get("caller").is_none());
        let _ = std::fs::remove_dir_all(base);
    }

    /// A client chooses its ids and target, so a record keeps at most a bounded part of each.
    #[test]
    fn client_fields_are_bounded() {
        let base = sandbox("bounded");
        let path = base.join("audit.jsonl");
        let logger = AuditLogger::new(&path).expect("audit");
        logger
            .record(
                &request("é".repeat(100_000), Some("t".repeat(100_000))),
                "p1",
                "DENIED",
            )
            .expect("record");
        let text = std::fs::read_to_string(&path).expect("read audit");
        assert!(text.len() < 8 * 1024, "{} bytes", text.len());
        let record: serde_json::Value = serde_json::from_str(text.trim()).expect("record");
        let id = record["request_id"].as_str().unwrap();
        assert_eq!(
            id.chars().count(),
            MAX_FIELD_CHARS + TRUNCATED.chars().count()
        );
        assert!(id.ends_with(TRUNCATED));
        let target = record["target"].as_str().unwrap();
        assert_eq!(
            target.chars().count(),
            MAX_TARGET_CHARS + TRUNCATED.chars().count()
        );
        assert_eq!(bounded("short", MAX_FIELD_CHARS), "short");
        let _ = std::fs::remove_dir_all(base);
    }

    /// A log left mid-line by an earlier crash keeps its next record on a line of its own.
    #[test]
    fn a_record_never_joins_a_torn_last_line() {
        let base = sandbox("torn");
        let path = base.join("audit.jsonl");
        std::fs::write(&path, "{\"timestamp_ms\":1,\"request_id\":\"torn").expect("torn log");
        let logger = AuditLogger::new(&path).expect("audit");
        logger
            .record(&request("after".into(), None), "p1", "SUCCESS")
            .expect("record");
        let text = std::fs::read_to_string(&path).expect("read audit");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");
        let record: serde_json::Value = serde_json::from_str(lines[1]).expect("whole record");
        assert_eq!(record["request_id"], "after");
        // A whole log gains no blank line.
        logger
            .record(&request("next".into(), None), "p1", "SUCCESS")
            .expect("record");
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 3);
        let _ = std::fs::remove_dir_all(base);
    }

    fn lookup(vars: Vec<(&'static str, OsString)>) -> impl Fn(&str) -> Option<OsString> {
        move |name| {
            vars.iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.clone())
        }
    }

    fn sandbox(label: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let suffix = format!("{suffix}-{}", next_temp_sequence());
        let dir = std::env::temp_dir().join(format!("orcel-audit-{label}-{suffix}"));
        std::fs::create_dir_all(&dir).expect("sandbox");
        // Independent of the umask, so the ancestor checks see a private base.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .expect("chmod sandbox");
        }
        dir
    }

    #[test]
    fn audit_path_override_is_kept() {
        let base = sandbox("override");
        let custom = base.join("custom-audit.jsonl");
        let path = default_audit_path_from(&lookup(vec![(
            "ORCEL_AUDIT_PATH",
            custom.clone().into_os_string(),
        )]));
        assert_eq!(path, Ok(custom));
        let _ = std::fs::remove_dir_all(base);
    }

    /// XP-01B: an override gets the default location's guarantees, so a
    /// parent directory other users can reach is refused.
    #[cfg(unix)]
    #[test]
    fn override_in_a_shared_directory_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let base = sandbox("shared-override");
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755))
            .expect("chmod shared");
        let error = default_audit_path_from(&lookup(vec![(
            "ORCEL_AUDIT_PATH",
            base.join("audit.jsonl").into_os_string(),
        )]))
        .expect_err("shared parent");
        assert!(
            matches!(error, PlatformError::InsecureMode { .. }),
            "{error:?}"
        );
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn empty_or_relative_audit_override_is_refused() {
        for value in ["", "custom-audit.jsonl", "logs/audit.jsonl"] {
            let path =
                default_audit_path_from(&lookup(vec![("ORCEL_AUDIT_PATH", OsString::from(value))]));
            assert_eq!(
                path,
                Err(PlatformError::NotAbsolute(PathBuf::from(value))),
                "{value:?}"
            );
        }
    }

    #[test]
    fn audit_path_without_a_state_root_is_an_error_never_temp() {
        let error = default_audit_path_from(&lookup(Vec::new())).expect_err("no root");
        assert!(matches!(error, PlatformError::StateRootUnavailable(_)));
    }

    #[test]
    fn audit_log_is_written_under_the_private_state_root() {
        let base = sandbox("root");
        #[cfg(windows)]
        let env = vec![("USERPROFILE", base.clone().into_os_string())];
        #[cfg(not(windows))]
        let env = vec![("HOME", base.clone().into_os_string())];
        let lookup = lookup(env);
        let root = paths::state_root_from(&lookup).expect("root");
        let path = default_audit_path_from(&lookup).expect("audit path");
        assert_eq!(path, root.join("audit.jsonl"));
        assert!(path.starts_with(&base));
        #[cfg(windows)]
        assert_eq!(path, base.join(".orcel").join("audit.jsonl"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&root).expect("root").permissions().mode();
            assert_eq!(mode & 0o077, 0);
        }
        let logger = AuditLogger::new(&path).expect("audit");
        let req = RequestEnvelope {
            version: 1,
            request_id: "r".into(),
            client_session_id: "s".into(),
            workspace_id: "w".into(),
            capability: "fs.search".into(),
            operation: "search".into(),
            target: None,
            arguments: json!({}),
        };
        logger.record(&req, "p1", "SUCCESS").expect("record");
        assert!(std::fs::read_to_string(&path)
            .expect("read audit")
            .contains("\"request_id\":\"r\""));
        let _ = std::fs::remove_dir_all(base);
    }
}
