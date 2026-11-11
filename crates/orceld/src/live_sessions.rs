//! Live client sessions, for display only.
//!
//! Each local MCP session starts its own orceld, and only one orceld per user serves the app
//! API, so no orceld sees the others. On its session's `session.hello`, an orceld writes one
//! small record into a private per-user folder and deletes it when it exits. A reader counts a
//! record only while the process it names is the same process instance (pid and start time),
//! and deletes the record of a process that is gone.
//!
//! A record grants nothing and nothing reads one as permission. The client's name and version
//! are what the client said about itself: bounded, stripped of control and direction characters,
//! and marked unverified.

use orcel_contracts::{FailureCode, RemoteRequestEnvelope, RequestEnvelope, ResponseEnvelope};
use orcel_platform::process::{self, ProcessGeneration};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};

pub(crate) const SESSION_CAPABILITY: &str = "session";
pub(crate) const HELLO_OPERATION: &str = "hello";
const RECORD_VERSION: u32 = 1;
/// Directory entries a listing scans, record files it reads, and the largest record it reads.
const MAX_SCANNED: usize = 4096;
const MAX_ENTRIES: usize = 256;
const MAX_RECORD_BYTES: u64 = 4096;
const MAX_NAME_CHARS: usize = 64;
const MAX_VERSION_CHARS: usize = 32;
const MAX_WORKSPACE_CHARS: usize = 128;
const TRANSPORTS: [&str; 3] = ["stdio", "loopback_http", "tunnel"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ClientInfo {
    pub name: Option<String>,
    pub version: Option<String>,
    /// Always false: the client said this about itself.
    pub verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SessionRecord {
    pub v: u32,
    pub pid: u32,
    pub generation: u64,
    pub boot_id: Option<String>,
    pub source: String,
    pub started_at_ms: u64,
    pub transport: String,
    pub workspace_id: Option<String>,
    pub client: ClientInfo,
}

impl SessionRecord {
    fn file_name(&self) -> String {
        format!("{}-{}.json", self.pid, self.generation)
    }

    fn instance(&self) -> Option<ProcessGeneration> {
        let boot_id = match &self.boot_id {
            Some(text) => Some(text.parse::<u128>().ok()?),
            None => None,
        };
        // The source must be one this build reports, so a record can't name an arbitrary one.
        let source = process::current_instance().ok()?.source;
        (self.source == source).then_some(ProcessGeneration {
            pid: self.pid,
            generation: self.generation,
            boot_id,
            source,
        })
    }
}

/// The folder of live session records.
pub(crate) struct Registry {
    dir: PathBuf,
}

/// This session's record: deleted when dropped.
pub(crate) struct Published {
    path: PathBuf,
}

impl Drop for Published {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Registry {
    /// The registry in `dir`, which must already be a private folder.
    pub(crate) fn at(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// Writes this process's record. A failure leaves the session uncounted, never miscounted.
    pub(crate) fn publish(&self, record: &SessionRecord) -> io::Result<Published> {
        let bytes = serde_json::to_vec(record).map_err(io::Error::other)?;
        let path = self.dir.join(record.file_name());
        orcel_platform::files::write_private_atomic(&path, &bytes)?;
        Ok(Published { path })
    }

    /// The records of sessions still running, newest first, at most `max`, and whether more
    /// were left out. Records of processes that are gone are deleted.
    pub(crate) fn list(&self, max: usize) -> io::Result<(Vec<SessionRecord>, bool)> {
        let mut live = Vec::new();
        // Only names shaped like records count toward the cap, so leftovers can't hide them.
        let candidates = std::fs::read_dir(&self.dir)?
            .take(MAX_SCANNED)
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter_map(|path| record_name(&path).map(|parts| (path, parts)))
            .take(MAX_ENTRIES);
        for (path, (pid, generation)) in candidates {
            let Some(record) = read_record(&path, pid, generation) else {
                continue;
            };
            match record
                .instance()
                .map(|instance| process::is_same_instance(&instance))
            {
                Some(Ok(true)) => live.push(record),
                Some(Ok(false)) => {
                    let _ = std::fs::remove_file(&path);
                }
                // Unreadable now, or not a process this build can check: not counted.
                Some(Err(_)) | None => {}
            }
        }
        live.sort_by_key(|record| std::cmp::Reverse(record.started_at_ms));
        let truncated = live.len() > max;
        live.truncate(max);
        Ok((live, truncated))
    }

    /// Deletes the records of processes that are gone.
    pub(crate) fn sweep(&self) {
        let _ = self.list(MAX_ENTRIES);
    }
}

/// The pid and generation of a name shaped `<pid>-<generation>.json`.
fn record_name(path: &Path) -> Option<(u32, u64)> {
    let name = path.file_name()?.to_str()?;
    let (pid, generation) = name.strip_suffix(".json")?.split_once('-')?;
    let digits = |text: &str| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit());
    if !digits(pid) || !digits(generation) {
        return None;
    }
    Some((pid.parse().ok()?, generation.parse().ok()?))
}

/// A record file this registry wrote: a plain file (never followed through a link), small,
/// owned by this user on Unix, and naming the same pid and generation inside as its name.
fn read_record(path: &Path, pid: u32, generation: u64) -> Option<SessionRecord> {
    let file = open_no_follow(path).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_RECORD_BYTES {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        // SAFETY: geteuid has no preconditions and cannot fail.
        if metadata.uid() != unsafe { libc::geteuid() } {
            return None;
        }
    }
    let mut bytes = Vec::new();
    file.take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return None;
    }
    let record: SessionRecord = serde_json::from_slice(&bytes).ok()?;
    (record.v == RECORD_VERSION && record.pid == pid && record.generation == generation)
        .then_some(record)
}

/// Opens `path` itself: a link or reparse point is opened as itself and then fails the
/// plain-file check, and on Unix a FIFO can't block the open.
fn open_no_follow(path: &Path) -> io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path)
}

/// Client text for display: control, line and direction characters removed, trimmed, and at
/// most `max` characters. Empty text is none.
pub(crate) fn sanitize(text: &str, max: usize) -> Option<String> {
    let cleaned: String = text
        .chars()
        .filter(|c| !c.is_control() && !is_format_hazard(*c))
        .collect();
    let bounded: String = cleaned.trim().chars().take(max).collect();
    let bounded = bounded.trim_end().to_owned();
    (!bounded.is_empty()).then_some(bounded)
}

fn is_format_hazard(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'..='\u{200F}'
            | '\u{061C}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{2069}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
    )
}

pub(crate) fn is_hello(request: &RequestEnvelope) -> bool {
    request.capability == SESSION_CAPABILITY
}

/// One session's hello: the first one publishes its record, a second is refused. It never
/// reaches policy or dispatch, because it grants and does nothing. A remote connection is
/// refused: its lease is checked only on the dispatch path, so it isn't shown as a session.
pub(crate) struct Hello {
    registry: Option<Registry>,
    /// Held so the record is deleted when this session's orceld exits.
    _published: Option<Published>,
    answered: bool,
}

impl Hello {
    pub(crate) fn new(registry: Option<Registry>) -> Self {
        Self {
            registry,
            _published: None,
            answered: false,
        }
    }

    pub(crate) fn handle(
        &mut self,
        envelope: RemoteRequestEnvelope,
        policy_revision: &str,
    ) -> ResponseEnvelope {
        let RemoteRequestEnvelope {
            request, remote, ..
        } = envelope;
        if request.operation != HELLO_OPERATION {
            return ResponseEnvelope::failure(
                request.request_id,
                FailureCode::InvalidRequest,
                "unknown session operation",
            );
        }
        if remote.is_some() {
            return ResponseEnvelope::failure(
                request.request_id,
                FailureCode::CapabilityDenied,
                "a remote connection is not recorded as a local session",
            );
        }
        if self.answered {
            return ResponseEnvelope::failure(
                request.request_id,
                FailureCode::InvalidRequest,
                "this session has already said hello",
            );
        }
        self.answered = true;
        let text = |key: &str, max: usize| {
            request
                .arguments
                .get(key)
                .and_then(|value| value.as_str())
                .and_then(|value| sanitize(value, max))
        };
        let transport = text("transport", 16)
            .filter(|value| TRANSPORTS.contains(&value.as_str()))
            .unwrap_or_else(|| "unknown".to_owned());
        let record = process::current_instance()
            .ok()
            .map(|instance| SessionRecord {
                v: RECORD_VERSION,
                pid: instance.pid,
                generation: instance.generation,
                boot_id: instance.boot_id.map(|id| id.to_string()),
                source: instance.source.to_owned(),
                started_at_ms: now_ms(),
                transport,
                workspace_id: sanitize(&request.workspace_id, MAX_WORKSPACE_CHARS),
                client: ClientInfo {
                    name: text("client_name", MAX_NAME_CHARS),
                    version: text("client_version", MAX_VERSION_CHARS),
                    verified: false,
                },
            });
        let published = match (&self.registry, record) {
            (Some(registry), Some(record)) => match registry.publish(&record) {
                Ok(published) => Some(published),
                Err(error) => {
                    eprintln!("orceld live sessions: record not written: {error}");
                    None
                }
            },
            _ => None,
        };
        let registered = published.is_some();
        self._published = published;
        ResponseEnvelope::success(
            &request,
            json!({ "registered": registered }),
            policy_revision,
        )
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use orcel_contracts::INTERNAL_PROTOCOL_VERSION;
    use serde_json::Value;

    fn temp_registry(label: &str) -> (Registry, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "orcel-live-sessions-{label}-{}-{}",
            std::process::id(),
            now_ms()
        ));
        orcel_platform::paths::ensure_private_dir(&dir).expect("private dir");
        (Registry::at(dir.clone()), dir)
    }

    fn envelope(operation: &str, arguments: Value) -> RemoteRequestEnvelope {
        serde_json::from_value(json!({
            "version": INTERNAL_PROTOCOL_VERSION,
            "request_id": "r1",
            "client_session_id": "s1",
            "workspace_id": "ws\u{202E}1",
            "capability": SESSION_CAPABILITY,
            "operation": operation,
            "arguments": arguments,
        }))
        .expect("envelope")
    }

    #[test]
    fn client_text_is_bounded_and_stripped() {
        assert_eq!(
            sanitize("  Claude\nCode\u{202E} ", 64).as_deref(),
            Some("ClaudeCode")
        );
        assert_eq!(
            sanitize("a\u{0000}b\u{2066}c\u{FEFF}", 64).as_deref(),
            Some("abc")
        );
        assert_eq!(
            sanitize(&"x".repeat(200), 64).map(|s| s.chars().count()),
            Some(64)
        );
        assert_eq!(sanitize(" \u{200F}\t", 64), None);
        assert_eq!(sanitize("Café ✓", 64).as_deref(), Some("Café ✓"));
    }

    #[test]
    fn a_hello_publishes_one_live_record_and_drop_removes_it() {
        let (registry, dir) = temp_registry("hello");
        let mut hello = Hello::new(Some(Registry::at(dir.clone())));
        let response = hello.handle(
            envelope(
                "hello",
                json!({ "client_name": "claude-ai\u{202E}", "client_version": "1.2", "transport": "stdio" }),
            ),
            "rev",
        );
        assert!(response.ok, "{response:?}");
        assert_eq!(response.result.unwrap()["registered"], true);
        let (live, truncated) = registry.list(32).expect("list");
        assert!(!truncated);
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].pid, std::process::id());
        assert_eq!(live[0].client.name.as_deref(), Some("claude-ai"));
        assert_eq!(live[0].client.version.as_deref(), Some("1.2"));
        assert!(!live[0].client.verified);
        assert_eq!(live[0].transport, "stdio");
        assert_eq!(live[0].workspace_id.as_deref(), Some("ws1"));

        // A second hello is refused and leaves the record alone.
        let again = hello.handle(envelope("hello", json!({ "client_name": "other" })), "rev");
        assert!(!again.ok);
        assert_eq!(
            registry.list(32).unwrap().0[0].client.name.as_deref(),
            Some("claude-ai")
        );

        drop(hello);
        assert!(registry.list(32).unwrap().0.is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn transport_is_from_a_fixed_set_and_remote_is_refused() {
        let (registry, dir) = temp_registry("transport");
        let mut hello = Hello::new(Some(Registry::at(dir.clone())));
        hello.handle(
            envelope("hello", json!({ "transport": "carrier-pigeon" })),
            "rev",
        );
        assert_eq!(registry.list(32).unwrap().0[0].transport, "unknown");
        drop(hello);

        let mut remote = envelope("hello", json!({ "transport": "stdio" }));
        remote.remote = Some(
            serde_json::from_value(json!({
                "principal": "p", "remoteConnectionId": "rc", "connectionId": "c",
                "deviceId": "d", "deviceEpoch": 1, "providerKind": "chatgpt",
                "clientProfileId": "cp", "clientProfileRevision": 1,
                "toolSurfaceProfile": "default", "scopes": []
            }))
            .expect("remote context"),
        );
        let mut hello = Hello::new(Some(Registry::at(dir.clone())));
        assert!(!hello.handle(remote, "rev").ok);
        assert!(registry.list(32).unwrap().0.is_empty());
        drop(hello);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn unknown_operations_are_refused() {
        let mut hello = Hello::new(None);
        assert!(!hello.handle(envelope("goodbye", json!({})), "rev").ok);
        // Without a registry, a hello still answers, unregistered.
        let response = hello.handle(envelope("hello", json!({})), "rev");
        assert!(response.ok);
        assert_eq!(response.result.unwrap()["registered"], false);
    }

    #[test]
    fn dead_forged_and_odd_entries_are_not_counted() {
        let (registry, dir) = temp_registry("filter");
        let me = process::current_instance().expect("instance");
        let record = |pid: u32, generation: u64| SessionRecord {
            v: RECORD_VERSION,
            pid,
            generation,
            boot_id: me.boot_id.map(|id| id.to_string()),
            source: me.source.to_owned(),
            started_at_ms: 1,
            transport: "stdio".to_owned(),
            workspace_id: None,
            client: ClientInfo {
                name: None,
                version: None,
                verified: false,
            },
        };
        // This process with the wrong start generation: a reused pid. Deleted.
        let stale = record(me.pid, me.generation.wrapping_add(1));
        let stale_path = dir.join(stale.file_name());
        let stale_guard = registry.publish(&stale).unwrap();
        std::mem::forget(stale_guard);
        // A record whose file name disagrees with what it says inside.
        let live = record(me.pid, me.generation);
        std::fs::write(dir.join("1-2.json"), serde_json::to_vec(&live).unwrap()).unwrap();
        // A foreign name, an oversized file and a folder.
        std::fs::write(dir.join("notes.txt"), b"x").unwrap();
        std::fs::write(
            dir.join(format!("{}-{}.json", me.pid, me.generation)),
            vec![b' '; 5000],
        )
        .unwrap();
        std::fs::create_dir(dir.join("3-4.json")).unwrap();

        let (listed, _) = registry.list(32).unwrap();
        assert!(listed.is_empty(), "{listed:?}");
        assert!(!stale_path.exists(), "a dead record is deleted");
        assert!(
            dir.join("notes.txt").exists(),
            "a foreign file is left alone"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_listing_is_bounded_and_says_so() {
        let (registry, dir) = temp_registry("bound");
        let mut hello = Hello::new(Some(Registry::at(dir.clone())));
        hello.handle(envelope("hello", json!({})), "rev");
        let (listed, truncated) = registry.list(0).unwrap();
        assert!(listed.is_empty() && truncated);
        drop(hello);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_failed_write_leaves_the_session_unregistered() {
        let missing =
            std::env::temp_dir().join(format!("orcel-live-sessions-missing-{}", now_ms()));
        let mut hello = Hello::new(Some(Registry::at(missing.join("not-there"))));
        let response = hello.handle(envelope("hello", json!({})), "rev");
        assert!(response.ok);
        assert_eq!(response.result.unwrap()["registered"], false);
    }
}
