use orcel_contracts::RequestEnvelope;
use orcel_platform::paths;
pub use orcel_platform::PlatformError;
use serde::Serialize;
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct AuditLogger {
    path: PathBuf,
}

#[derive(Debug, Serialize)]
struct AuditEvent<'a> {
    timestamp_ms: u128,
    request_id: &'a str,
    client_session_id: &'a str,
    workspace_id: &'a str,
    capability: &'a str,
    operation: &'a str,
    target: Option<&'a str>,
    policy_revision: &'a str,
    outcome: &'a str,
}

impl AuditLogger {
    pub fn new(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        Ok(Self { path })
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
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();

        let event = AuditEvent {
            timestamp_ms,
            request_id: &request.request_id,
            client_session_id: &request.client_session_id,
            workspace_id: &request.workspace_id,
            capability: &request.capability,
            operation: &request.operation,
            target: request.target.as_deref(),
            policy_revision,
            outcome,
        };

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        serde_json::to_writer(&mut file, &event)?;
        file.write_all(b"\n")?;
        file.flush()
    }
}

/// `ORCEL_AUDIT_PATH`, else `audit.jsonl` in the private per-user Orcel
/// state root. Fails closed when the root cannot be resolved or is not
/// private; it never falls back to the shared temp directory.
pub fn default_audit_path() -> Result<PathBuf, PlatformError> {
    default_audit_path_from(&|name| std::env::var_os(name))
}

fn default_audit_path_from(
    lookup: &dyn Fn(&str) -> Option<OsString>,
) -> Result<PathBuf, PlatformError> {
    if let Some(path) = lookup("ORCEL_AUDIT_PATH") {
        return Ok(PathBuf::from(path));
    }
    let root = paths::state_root_from(lookup)?;
    paths::ensure_private_dir(&root)?;
    Ok(root.join("audit.jsonl"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use orcel_contracts::RequestEnvelope;
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn writes_structured_event_without_arguments() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
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
        let dir = std::env::temp_dir().join(format!("orcel-audit-{label}-{suffix}"));
        std::fs::create_dir_all(&dir).expect("sandbox");
        dir
    }

    #[test]
    fn audit_path_override_is_kept() {
        let path = default_audit_path_from(&lookup(vec![(
            "ORCEL_AUDIT_PATH",
            OsString::from("custom-audit.jsonl"),
        )]));
        assert_eq!(path, Ok(PathBuf::from("custom-audit.jsonl")));
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
        let env = vec![("LOCALAPPDATA", base.clone().into_os_string())];
        #[cfg(not(windows))]
        let env = vec![("HOME", base.clone().into_os_string())];
        let lookup = lookup(env);
        let root = paths::state_root_from(&lookup).expect("root");
        let path = default_audit_path_from(&lookup).expect("audit path");
        assert_eq!(path, root.join("audit.jsonl"));
        assert!(path.starts_with(&base));
        #[cfg(windows)]
        assert_eq!(path, base.join("Orcel").join("audit.jsonl"));
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
