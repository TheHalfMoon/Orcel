// SPDX-License-Identifier: FSL-1.1-MIT
// Portions copyright (c) 2026 Cua AI, Inc.; modifications copyright Orcel.

//! CR-01: the read-only local app API, `orcel-app-api/1`.
//!
//! orceld serves one private, per-user endpoint that the Control Room (and
//! any other local client of the same user) reads daemon state from:
//!
//! - Windows: the named pipe `\\.\pipe\orcel-<user SID>-app`, created with a
//!   protected DACL that grants the current user's SID and nobody else, and
//!   an explicit Medium mandatory label (`D:P(A;;GA;;;<sid>)S:(ML;;NWNR;;;ME)`,
//!   #375 item 2), `FILE_FLAG_FIRST_PIPE_INSTANCE` so no other server can
//!   already hold the name, and `PIPE_REJECT_REMOTE_CLIENTS`.
//! - macOS and Linux: the Unix domain socket `app-api.sock`, mode 0600, in a
//!   0700 `orcel` directory of a short per-user runtime directory (#381):
//!   macOS's `confstr(_CS_DARWIN_USER_TEMP_DIR)`, Linux's `$XDG_RUNTIME_DIR`.
//!   Without one it falls back to `run/` in the XP-01 state root. An
//!   advisory lock file next to the socket, held for as long as the socket
//!   is served, makes the endpoint single-instance per user (#375 item 3).
//!
//! No TCP listener exists. Every connection is identified from the kernel
//! before any byte is read from it, and a peer that is not this user's live
//! process is dropped unread:
//!
//! - Unix: `orcel_platform::peer::unix_peer_credentials` (XP-03) gives the
//!   peer's uid and its process instance; the uid must equal ours. The
//!   Linux `linux-so-peercred` fallback source (pre-6.5 kernels, pid-reuse
//!   race) is refused (#367 item 2). `PlatformError::ProcessGone`, pid 0
//!   included, only ever means "refuse this connection" (#367 item 1): it
//!   never cleans up, revokes or records anything about the process.
//! - Windows: the pipe client pid (`GetNamedPipeClientProcessId`, never 0),
//!   its session (must equal ours), its token user (must equal ours, a second
//!   check behind the DACL) and its start generation; the pipe must still be
//!   connected after these reads, so an exited client is refused.
//!
//! Each connection is bound to the peer instance it was admitted as: before
//! every request, and at least every [`PEER_RECHECK`] while it streams
//! events (#375 item 5), the instance is read again, and a connection whose
//! peer has exited or whose pid now names another process is closed
//! unanswered.
//!
//! The API is read-only. Its methods (`status.get`, `capabilities.get`,
//! `events.subscribe`, and SG-000126's `task.list` and `task.get`) read
//! daemon facts, the event log and the report task registry; nothing reaches
//! the request dispatcher, the policy engine or the approval broker, so no
//! client can submit work or mint an approval through it. Frames are JSON
//! lines of at most [`MAX_FRAME_BYTES`]; concurrent clients, the event ring
//! and the per-client event rate are bounded, and writes time out, so a
//! slow client never blocks orceld's request loop: [`EventLog::publish`]
//! only takes a short lock, and a client that falls behind the ring gets a
//! `snapshot` event and must resubscribe. See
//! `docs/orcel/implementation-readiness/protocol/ORCEL_APP_API_1.md`.
//!
//! Provenance (transplant rows T-CUA-25 and T-CUA-26): the Windows pipe
//! security descriptor (`D:P(A;;GA;;;<sid>)` from the token user's SID),
//! first-instance and remote-client rejection, the token-user comparison of
//! the pipe client, and the Unix stale-socket rule (remove only after a
//! connect attempt finds no live server) are adapted from
//! cua@a802eaf26ca97616a6bf0de6a29729a9346fbb1f
//! `libs/cua/crates/cua-keyvault/src/winpipe.rs` (blob
//! 5e0b1e4c4a584f9147c15297c50a497f6d38b27c), `winpeer.rs` (blob
//! cbf138941874ec84045a8433f5403e7fc3c8cdf2) and `ipc.rs` `bind` (blob
//! 1fd6f75b4101faac8910e9441683ecbdec2f942a), FSL-1.1-MIT, used under
//! FD-04; notice in `docs/orcel/notices/cua-FSL-1.1-MIT.txt`. The kernel
//! peer identity that
//! `caller.rs` (blob 16c562b91464aa6086d3ee38e8d31f5ba1c02f27) provides
//! upstream comes from XP-03's `orcel_platform::peer` here. Modifications:
//! blocking std threads and overlapped Win32 I/O instead of tokio; the pipe
//! client's session and start generation and a still-connected check; the
//! symlink, file-type and owner checks before a stale socket is removed;
//! Authenticode and code-signature requirements are not imported (see the
//! protocol document, "Code identity").

use crate::report_task::TaskRegistry;
use orcel_platform::process::{self, ProcessGeneration};
use orcel_platform::PlatformError;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::fmt;
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The protocol version every frame carries in `v`.
pub(crate) const PROTOCOL: &str = "orcel-app-api/1";
/// The largest frame either side may send, newline included.
pub(crate) const MAX_FRAME_BYTES: usize = 64 * 1024;
/// Event `data` larger than this is replaced by a truncation marker.
const MAX_EVENT_DATA_BYTES: usize = 16 * 1024;
const MAX_ID_CHARS: usize = 128;
/// Events read from the ring per wake-up of a subscriber.
const EVENT_BATCH: usize = 64;
/// How long the endpoint thread waits before trying again to take an
/// endpoint that another live orceld holds.
const REBIND_INTERVAL: Duration = Duration::from_secs(5);
/// How often a streaming subscription reads its peer's instance again.
const PEER_RECHECK: Duration = Duration::from_secs(1);

/// The methods this revision serves. All of them only read.
pub(crate) const METHODS: &[&str] = &[
    "status.get",
    "capabilities.get",
    "events.subscribe",
    "task.list",
    "task.get",
];
/// Read-only methods the protocol reserves; this revision answers
/// `METHOD_UNAVAILABLE` for them.
pub(crate) const RESERVED_METHODS: &[&str] = &["devices.list"];

/// The bounds of one endpoint.
#[derive(Debug, Clone)]
pub(crate) struct Limits {
    pub max_clients: usize,
    pub ring_capacity: usize,
    pub max_events_per_second: u32,
    pub write_timeout: Duration,
    pub idle_timeout: Duration,
    pub heartbeat: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_clients: 8,
            ring_capacity: 1024,
            max_events_per_second: 1_000,
            write_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(60),
            heartbeat: Duration::from_secs(15),
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Event log
// ---------------------------------------------------------------------------

/// One daemon event. `seq` grows by one per event within an epoch.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Event {
    pub seq: u64,
    pub at_ms: u64,
    pub kind: String,
    pub run_id: Option<String>,
    pub step_id: Option<String>,
    pub data: Value,
}

impl Event {
    fn to_json(&self, epoch: &str) -> Value {
        json!({
            "seq": self.seq,
            "epoch": epoch,
            "run_id": self.run_id,
            "step_id": self.step_id,
            "kind": self.kind,
            "at_ms": self.at_ms,
            "data": self.data,
        })
    }
}

/// A bounded ring of the most recent events. Publishing never waits for a
/// subscriber: it takes the lock, appends, drops the oldest event when the
/// ring is full and wakes subscribers. Each subscriber keeps its own cursor.
pub(crate) struct EventLog {
    epoch: String,
    capacity: usize,
    ring: Mutex<Ring>,
    changed: Condvar,
}

struct Ring {
    events: VecDeque<Event>,
    /// The last sequence number handed out; 0 before the first event.
    head: u64,
}

impl Ring {
    fn oldest(&self) -> u64 {
        self.events
            .front()
            .map(|event| event.seq)
            .unwrap_or(self.head + 1)
    }
}

/// What a subscriber gets for its cursor.
#[derive(Debug, PartialEq)]
enum Batch {
    Events(Vec<Event>),
    /// The cursor is outside what the ring holds: events after it were
    /// dropped, or it is ahead of the head (a cursor from another epoch).
    Gap {
        head: u64,
        oldest: u64,
    },
    /// Nothing new within the wait.
    Idle {
        head: u64,
    },
}

impl EventLog {
    pub(crate) fn new(capacity: usize, epoch: String) -> Self {
        Self {
            epoch,
            capacity: capacity.max(1),
            ring: Mutex::new(Ring {
                events: VecDeque::new(),
                head: 0,
            }),
            changed: Condvar::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Ring> {
        self.ring
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn epoch(&self) -> &str {
        &self.epoch
    }

    /// Appends one event and returns its sequence number.
    pub(crate) fn publish(&self, kind: &str, data: Value) -> u64 {
        self.publish_run(kind, None, None, data)
    }

    /// Appends one event of a task run (SG-000126): `run_id` is the task id
    /// and `step_id` the step.
    pub(crate) fn publish_run(
        &self,
        kind: &str,
        run_id: Option<&str>,
        step_id: Option<&str>,
        data: Value,
    ) -> u64 {
        let data = bounded_data(data);
        let mut ring = self.lock();
        ring.head += 1;
        let seq = ring.head;
        ring.events.push_back(Event {
            seq,
            at_ms: now_ms(),
            kind: kind.to_owned(),
            run_id: run_id.map(str::to_owned),
            step_id: step_id.map(str::to_owned),
            data,
        });
        while ring.events.len() > self.capacity {
            ring.events.pop_front();
        }
        drop(ring);
        self.changed.notify_all();
        seq
    }

    pub(crate) fn head(&self) -> u64 {
        self.lock().head
    }

    fn oldest(&self) -> u64 {
        self.lock().oldest()
    }

    /// Up to `max` events after `after`, waiting at most `wait` for one.
    fn next_after(&self, after: u64, max: usize, wait: Duration) -> Batch {
        let deadline = Instant::now() + wait;
        let mut ring = self.lock();
        loop {
            let oldest = ring.oldest();
            if after > ring.head || after + 1 < oldest {
                return Batch::Gap {
                    head: ring.head,
                    oldest,
                };
            }
            if after < ring.head {
                let skip = usize::try_from(after + 1 - oldest).unwrap_or(usize::MAX);
                return Batch::Events(ring.events.iter().skip(skip).take(max).cloned().collect());
            }
            let now = Instant::now();
            if now >= deadline {
                return Batch::Idle { head: ring.head };
            }
            ring = self
                .changed
                .wait_timeout(ring, deadline - now)
                .map(|(guard, _)| guard)
                .unwrap_or_else(|poisoned| poisoned.into_inner().0);
        }
    }
}

fn bounded_data(data: Value) -> Value {
    let size = serde_json::to_vec(&data)
        .map(|bytes| bytes.len())
        .unwrap_or(usize::MAX);
    if size <= MAX_EVENT_DATA_BYTES {
        data
    } else {
        json!({ "truncated": true, "bytes": size })
    }
}

// ---------------------------------------------------------------------------
// Daemon facts and shared state
// ---------------------------------------------------------------------------

/// Facts orceld hands the endpoint at startup.
#[derive(Debug, Clone)]
pub(crate) struct DaemonFacts {
    pub mode: &'static str,
    pub policy_revision: String,
    pub internal_protocol_version: String,
    /// `capabilities.get` rows: `{id, state, reason}`.
    pub capabilities: Vec<Value>,
}

struct Shared {
    facts: DaemonFacts,
    log: Arc<EventLog>,
    /// SG-000126 report tasks, read for `task.list` and `task.get`.
    tasks: Arc<TaskRegistry>,
    limits: Limits,
    started: Instant,
    started_at_ms: u64,
    active: AtomicUsize,
    endpoint: String,
    /// Set the first time the endpoint was found held (#375 item 1).
    wait: Mutex<Option<EndpointWait>>,
}

/// Why and since when this orceld waited for an endpoint another server
/// held, as `status.get` reports it in `endpoint_wait`.
#[derive(Debug, Clone)]
struct EndpointWait {
    since_ms: u64,
    reason: String,
    attempts: u64,
}

impl Shared {
    fn new(
        facts: DaemonFacts,
        log: Arc<EventLog>,
        tasks: Arc<TaskRegistry>,
        limits: Limits,
        endpoint: String,
    ) -> Self {
        Self {
            facts,
            log,
            tasks,
            limits,
            started: Instant::now(),
            started_at_ms: now_ms(),
            active: AtomicUsize::new(0),
            endpoint,
            wait: Mutex::new(None),
        }
    }

    /// Records one attempt that found the endpoint held. Returns true the
    /// first time, so the caller logs the reason once rather than every
    /// [`REBIND_INTERVAL`].
    fn note_in_use(&self, reason: &str) -> bool {
        let mut wait = self
            .wait
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match wait.as_mut() {
            Some(wait) => {
                wait.attempts += 1;
                false
            }
            None => {
                *wait = Some(EndpointWait {
                    since_ms: now_ms(),
                    reason: reason.to_owned(),
                    attempts: 1,
                });
                true
            }
        }
    }

    fn endpoint_wait(&self) -> Value {
        let wait = self
            .wait
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match wait.as_ref() {
            None => Value::Null,
            Some(wait) => json!({
                "since_ms": wait.since_ms,
                "reason": wait.reason,
                "attempts": wait.attempts,
            }),
        }
    }
}

/// One of the bounded client slots, released on drop.
struct Slot(Arc<Shared>);

impl Slot {
    fn acquire(shared: &Arc<Shared>) -> Option<Self> {
        let max = shared.limits.max_clients;
        shared
            .active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < max).then_some(active + 1)
            })
            .ok()
            .map(|_| Self(Arc::clone(shared)))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
    }
}

// ---------------------------------------------------------------------------
// Peer admission
// ---------------------------------------------------------------------------

/// The process instance a connection was admitted as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PeerInfo {
    pub process: ProcessGeneration,
    /// How the identity was read, for example `"linux-so-peerpidfd"`.
    pub source: &'static str,
}

/// Why a connection was dropped before any byte was read from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The peer's process is gone or no longer named (pid 0). This refuses
    /// the connection and nothing else.
    PeerGone(u32),
    /// The peer runs as another user, or in another login session.
    OtherUser(String),
    /// The identity came from a source too weak for this endpoint (Unix).
    #[cfg_attr(windows, allow(dead_code))]
    WeakIdentity(&'static str),
    /// The peer could not be identified.
    Unavailable(String),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PeerGone(pid) => write!(f, "peer process {pid} is gone"),
            Self::OtherUser(detail) => write!(f, "peer is not this user: {detail}"),
            Self::WeakIdentity(source) => {
                write!(f, "peer identity source {source} is not accepted")
            }
            Self::Unavailable(detail) => write!(f, "peer identity unavailable: {detail}"),
        }
    }
}

fn refusal_from(error: PlatformError) -> Refusal {
    match error {
        // #367: gone, pid 0 included, refuses this connection only.
        PlatformError::ProcessGone(pid) => Refusal::PeerGone(pid),
        PlatformError::PeerRefused { .. } => Refusal::OtherUser(error.to_string()),
        other => Refusal::Unavailable(other.to_string()),
    }
}

/// The Linux pre-6.5 source, whose pid binding can race with pid reuse
/// (`orcel_platform::peer` module docs). Refused (#367 item 2).
#[cfg(unix)]
const LINUX_SO_PEERCRED: &str = "linux-so-peercred";

/// Admits a Unix peer read by `orcel_platform::peer::unix_peer_credentials`.
#[cfg(unix)]
fn admit_unix(
    read: Result<orcel_platform::PeerIdentity, PlatformError>,
    our_uid: Option<u32>,
) -> Result<PeerInfo, Refusal> {
    let identity = read.map_err(refusal_from)?;
    let our_uid =
        our_uid.ok_or_else(|| Refusal::Unavailable("the effective uid is unreadable".into()))?;
    let identity =
        orcel_platform::peer::require_same_user(identity, our_uid).map_err(refusal_from)?;
    if identity.source == LINUX_SO_PEERCRED {
        return Err(Refusal::WeakIdentity(LINUX_SO_PEERCRED));
    }
    Ok(PeerInfo {
        process: identity.process,
        source: identity.source,
    })
}

/// What the pipe server read about its client, before admission.
#[cfg(any(windows, test))]
#[derive(Debug)]
struct PipeClientFacts {
    pid: u32,
    session: Option<u32>,
    our_session: Option<u32>,
    /// Whether the client's token user is ours.
    same_account: Result<bool, PlatformError>,
    process: Result<ProcessGeneration, PlatformError>,
    /// Whether the pipe was still connected after the reads above.
    still_connected: bool,
}

#[cfg(any(windows, test))]
const WIN32_PIPE_CLIENT: &str = "win32-named-pipe-client";

#[cfg(any(windows, test))]
fn admit_pipe(facts: PipeClientFacts) -> Result<PeerInfo, Refusal> {
    if facts.pid == 0 {
        return Err(Refusal::PeerGone(0));
    }
    match (facts.session, facts.our_session) {
        (Some(theirs), Some(ours)) if theirs == ours => {}
        (Some(theirs), Some(ours)) => {
            return Err(Refusal::OtherUser(format!(
                "client session {theirs} is not this session {ours}"
            )))
        }
        _ => {
            return Err(Refusal::Unavailable(
                "pipe client session unreadable".into(),
            ))
        }
    }
    if !facts.same_account.map_err(refusal_from)? {
        return Err(Refusal::OtherUser(format!(
            "process {} runs as another account",
            facts.pid
        )));
    }
    let process = facts.process.map_err(refusal_from)?;
    if !facts.still_connected {
        return Err(Refusal::PeerGone(facts.pid));
    }
    Ok(PeerInfo {
        process,
        source: WIN32_PIPE_CLIENT,
    })
}

/// Whether the admitted instance still runs. Anything but a definite yes
/// closes the connection.
fn still_same_instance(peer: &PeerInfo) -> bool {
    matches!(process::is_same_instance(&peer.process), Ok(true))
}

// ---------------------------------------------------------------------------
// Frames and methods
// ---------------------------------------------------------------------------

fn ok_frame(id: &Value, result: Value) -> Value {
    json!({ "v": PROTOCOL, "id": id, "ok": true, "result": result })
}

fn error_frame(id: &Value, code: &str, message: impl Into<String>) -> Value {
    json!({
        "v": PROTOCOL,
        "id": id,
        "ok": false,
        "error": { "code": code, "message": message.into() },
    })
}

fn event_frame(id: &Value, event: Value) -> Value {
    json!({ "v": PROTOCOL, "id": id, "event": event })
}

fn heartbeat_frame(id: &Value, head: u64) -> Value {
    json!({ "v": PROTOCOL, "id": id, "heartbeat": { "head_seq": head } })
}

#[derive(Debug, Default)]
struct FrameReader {
    buf: Vec<u8>,
}

#[derive(Debug)]
enum FrameError {
    TooLarge,
    /// The server ends the connection on any read error, idle timeouts
    /// included; only the tests' client looks at the error itself.
    Io(#[cfg_attr(not(test), allow(dead_code))] io::Error),
}

impl FrameReader {
    /// The next frame without its newline, `None` at end of stream. Never
    /// holds more than [`MAX_FRAME_BYTES`] of unread input.
    fn next(&mut self, source: &mut impl Read) -> Result<Option<Vec<u8>>, FrameError> {
        loop {
            if let Some(end) = self.buf.iter().position(|byte| *byte == b'\n') {
                if end + 1 > MAX_FRAME_BYTES {
                    return Err(FrameError::TooLarge);
                }
                let mut frame: Vec<u8> = self.buf.drain(..=end).collect();
                frame.pop();
                if frame.last() == Some(&b'\r') {
                    frame.pop();
                }
                return Ok(Some(frame));
            }
            if self.buf.len() >= MAX_FRAME_BYTES {
                return Err(FrameError::TooLarge);
            }
            let mut chunk = [0u8; 8192];
            let room = (MAX_FRAME_BYTES - self.buf.len()).min(chunk.len());
            match source.read(&mut chunk[..room]) {
                Ok(0) => return Ok(None),
                Ok(read) => self.buf.extend_from_slice(&chunk[..read]),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(FrameError::Io(error)),
            }
        }
    }
}

fn write_frame(sink: &mut impl Write, frame: &Value) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(frame).map_err(io::Error::other)?;
    if bytes.len() + 1 > MAX_FRAME_BYTES {
        let id = frame.get("id").cloned().unwrap_or(Value::Null);
        bytes = serde_json::to_vec(&error_frame(
            &id,
            "INTERNAL",
            "the response exceeds the frame bound",
        ))
        .map_err(io::Error::other)?;
    }
    bytes.push(b'\n');
    sink.write_all(&bytes)?;
    sink.flush()
}

#[derive(Debug, PartialEq)]
enum Reply {
    Frame(Value),
    Subscribe {
        id: Value,
        after_seq: u64,
        epoch: Option<String>,
    },
}

fn handle_frame(shared: &Shared, peer: &PeerInfo, bytes: &[u8]) -> Reply {
    let request: Value = match serde_json::from_slice(bytes) {
        Ok(value) => value,
        Err(error) => {
            return Reply::Frame(error_frame(
                &Value::Null,
                "INVALID_REQUEST",
                format!("frame is not JSON: {error}"),
            ))
        }
    };
    let Some(request) = request.as_object() else {
        return Reply::Frame(error_frame(
            &Value::Null,
            "INVALID_REQUEST",
            "frame is not a JSON object",
        ));
    };
    let id = match request.get("id") {
        None | Some(Value::Null) => Value::Null,
        Some(Value::String(text)) if text.chars().count() <= MAX_ID_CHARS => {
            Value::String(text.clone())
        }
        Some(Value::Number(number)) => Value::Number(number.clone()),
        Some(_) => {
            return Reply::Frame(error_frame(
                &Value::Null,
                "INVALID_REQUEST",
                "id must be a number or a string of at most 128 characters",
            ))
        }
    };
    if request.get("v").and_then(Value::as_str) != Some(PROTOCOL) {
        return Reply::Frame(error_frame(
            &id,
            "UNSUPPORTED_VERSION",
            format!("this endpoint speaks v = {PROTOCOL}"),
        ));
    }
    let Some(method) = request.get("method").and_then(Value::as_str) else {
        return Reply::Frame(error_frame(&id, "INVALID_REQUEST", "method is missing"));
    };
    let params = match request.get("params") {
        None | Some(Value::Null) => serde_json::Map::new(),
        Some(Value::Object(params)) => params.clone(),
        Some(_) => {
            return Reply::Frame(error_frame(
                &id,
                "INVALID_REQUEST",
                "params must be an object",
            ))
        }
    };
    match method {
        "status.get" => Reply::Frame(ok_frame(&id, status(shared, Some(peer)))),
        "capabilities.get" => Reply::Frame(ok_frame(&id, capabilities(shared))),
        "events.subscribe" => subscribe_request(id, &params),
        "task.list" => match params.keys().next() {
            Some(key) => Reply::Frame(error_frame(
                &id,
                "INVALID_REQUEST",
                format!("task.list has no parameter {key}"),
            )),
            None => Reply::Frame(ok_frame(&id, shared.tasks.list())),
        },
        "task.get" => Reply::Frame(task_get(shared, &id, &params)),
        method if RESERVED_METHODS.contains(&method) => Reply::Frame(error_frame(
            &id,
            "METHOD_UNAVAILABLE",
            format!("{method} is reserved and not served by this revision"),
        )),
        method => Reply::Frame(error_frame(
            &id,
            "UNKNOWN_METHOD",
            format!("{method} is not a method of {PROTOCOL}; the API is read-only"),
        )),
    }
}

/// `task.get {task_id}`: one task of this daemon run or, read-only, of an
/// exited run the report task journal kept (SG-000120 RJ-02).
fn task_get(shared: &Shared, id: &Value, params: &serde_json::Map<String, Value>) -> Value {
    if let Some(key) = params.keys().find(|key| key.as_str() != "task_id") {
        return error_frame(
            id,
            "INVALID_REQUEST",
            format!("task.get has no parameter {key}"),
        );
    }
    let Some(task_id) = params.get("task_id").and_then(Value::as_str) else {
        return error_frame(id, "INVALID_REQUEST", "task.get requires a string task_id");
    };
    match shared.tasks.get(task_id) {
        Some(task) => ok_frame(id, task),
        None => error_frame(
            id,
            "UNKNOWN_TASK",
            "orceld has no such task (this run, or the earlier runs its journal kept)",
        ),
    }
}

fn subscribe_request(id: Value, params: &serde_json::Map<String, Value>) -> Reply {
    if let Some(key) = params
        .keys()
        .find(|key| !matches!(key.as_str(), "after_seq" | "epoch"))
    {
        return Reply::Frame(error_frame(
            &id,
            "INVALID_REQUEST",
            format!("events.subscribe has no parameter {key}"),
        ));
    }
    let after_seq = match params.get("after_seq") {
        None => 0,
        Some(value) => match value.as_u64() {
            Some(after) => after,
            None => {
                return Reply::Frame(error_frame(
                    &id,
                    "INVALID_REQUEST",
                    "after_seq must be a non-negative integer",
                ))
            }
        },
    };
    let epoch = match params.get("epoch") {
        None | Some(Value::Null) => None,
        Some(Value::String(epoch)) if epoch.len() <= MAX_ID_CHARS => Some(epoch.clone()),
        Some(_) => {
            return Reply::Frame(error_frame(
                &id,
                "INVALID_REQUEST",
                "epoch must be a string of at most 128 bytes",
            ))
        }
    };
    // #375 item 4: a cursor names a position in one daemon run, so resuming
    // needs the run's epoch; otherwise a cursor from an earlier run could
    // silently receive this run's events.
    if after_seq > 0 && epoch.is_none() {
        return Reply::Frame(error_frame(
            &id,
            "INVALID_REQUEST",
            "epoch is required when after_seq is greater than 0",
        ));
    }
    Reply::Subscribe {
        id,
        after_seq,
        epoch,
    }
}

fn status(shared: &Shared, peer: Option<&PeerInfo>) -> Value {
    let mut value = json!({
        "name": "orceld",
        "version": env!("CARGO_PKG_VERSION"),
        "app_api": PROTOCOL,
        "read_only": true,
        "internal_protocol_version": shared.facts.internal_protocol_version,
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "pid": std::process::id(),
        "mode": shared.facts.mode,
        "policy_revision": shared.facts.policy_revision,
        "started_at_ms": shared.started_at_ms,
        "uptime_ms": u64::try_from(shared.started.elapsed().as_millis()).unwrap_or(u64::MAX),
        "endpoint": shared.endpoint,
        "endpoint_wait": shared.endpoint_wait(),
        "events": {
            "epoch": shared.log.epoch(),
            "head_seq": shared.log.head(),
            "oldest_seq": shared.log.oldest(),
            "ring_capacity": shared.log.capacity,
        },
        "clients": {
            "active": shared.active.load(Ordering::Acquire),
            "max": shared.limits.max_clients,
        },
    });
    if let Some(peer) = peer {
        value["peer"] = json!({
            "pid": peer.process.pid,
            "source": peer.source,
        });
    }
    value
}

fn capabilities(shared: &Shared) -> Value {
    json!({
        "os": std::env::consts::OS,
        "read_only": true,
        "methods": METHODS,
        "reserved_methods": RESERVED_METHODS,
        "capabilities": shared.facts.capabilities,
    })
}

// ---------------------------------------------------------------------------
// Connections
// ---------------------------------------------------------------------------

/// A connected byte stream with per-direction timeouts.
trait Transport: Read + Write {
    fn set_timeouts(&mut self, read: Option<Duration>, write: Option<Duration>) -> io::Result<()>;
    /// Ends the connection after the last frame was written.
    fn finish(&mut self);
    /// Reads and discards what the peer still sends, for a bounded time and
    /// size, after [`Transport::finish`]. Closing a socket with unread input
    /// makes some kernels (macOS) reset the connection, which can destroy the
    /// last frame before the peer reads it (#400).
    fn linger(&mut self) {}
}

fn serve_connection(mut conn: impl Transport, peer: PeerInfo, shared: &Shared) {
    if conn
        .set_timeouts(
            Some(shared.limits.idle_timeout),
            Some(shared.limits.write_timeout),
        )
        .is_err()
    {
        return;
    }
    let mut reader = FrameReader::default();
    loop {
        let frame = match reader.next(&mut conn) {
            Ok(Some(frame)) => frame,
            Ok(None) | Err(FrameError::Io(_)) => return,
            Err(FrameError::TooLarge) => {
                let _ = write_frame(
                    &mut conn,
                    &error_frame(
                        &Value::Null,
                        "FRAME_TOO_LARGE",
                        format!("frames are limited to {MAX_FRAME_BYTES} bytes"),
                    ),
                );
                conn.finish();
                conn.linger();
                return;
            }
        };
        if frame.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        if !still_same_instance(&peer) {
            eprintln!(
                "orceld app api: closed a connection whose peer {} is no longer the admitted instance",
                peer.process.pid
            );
            return;
        }
        match handle_frame(shared, &peer, &frame) {
            Reply::Frame(frame) => {
                if write_frame(&mut conn, &frame).is_err() {
                    return;
                }
            }
            Reply::Subscribe {
                id,
                after_seq,
                epoch,
            } => {
                stream_events(&mut conn, shared, &peer, &id, after_seq, epoch.as_deref());
                conn.finish();
                return;
            }
        }
    }
}

fn snapshot_event(shared: &Shared, reason: &str, head: u64, oldest: u64) -> Value {
    json!({
        "seq": head,
        "epoch": shared.log.epoch(),
        "run_id": null,
        "step_id": null,
        "kind": "snapshot",
        "at_ms": now_ms(),
        "data": {
            "reason": reason,
            "head_seq": head,
            "oldest_seq": oldest,
            "status": status(shared, None),
            "resubscribe": { "after_seq": head, "epoch": shared.log.epoch() },
        },
    })
}

/// Streams events after `after_seq` until the client falls behind, a write
/// fails or times out, or the peer is no longer the admitted instance (read
/// again at least every [`PEER_RECHECK`], whether events flow or not). Ends
/// with a `snapshot` event when the cursor cannot be served; the client then
/// resubscribes from the snapshot's head.
fn stream_events(
    conn: &mut impl Transport,
    shared: &Shared,
    peer: &PeerInfo,
    id: &Value,
    after_seq: u64,
    epoch: Option<&str>,
) {
    let log = &shared.log;
    let ack = ok_frame(
        id,
        json!({ "epoch": log.epoch(), "head_seq": log.head(), "after_seq": after_seq }),
    );
    if write_frame(conn, &ack).is_err() {
        return;
    }
    if epoch.is_some_and(|epoch| epoch != log.epoch()) {
        let event = snapshot_event(shared, "epoch", log.head(), log.oldest());
        let _ = write_frame(conn, &event_frame(id, event));
        return;
    }
    let rate = u64::from(shared.limits.max_events_per_second.max(1));
    let mut window = Instant::now();
    let mut sent_in_window = 0u64;
    let mut cursor = after_seq;
    // serve_connection read the instance just before this request.
    let mut checked = Instant::now();
    // #398 item 2: wait for events at most PEER_RECHECK at a time, so an
    // idle stream re-reads its peer every second too, and send a heartbeat
    // only once nothing was written for a whole heartbeat interval.
    let wait = shared.limits.heartbeat.min(PEER_RECHECK);
    let mut written = Instant::now();
    let peer_left = || {
        let left = !still_same_instance(peer);
        if left {
            eprintln!(
                "orceld app api: closed a subscription whose peer {} is no longer the admitted instance",
                peer.process.pid
            );
        }
        left
    };
    loop {
        let batch = log.next_after(cursor, EVENT_BATCH, wait);
        let due = matches!(batch, Batch::Idle { .. }) || checked.elapsed() >= PEER_RECHECK;
        if due {
            if peer_left() {
                return;
            }
            checked = Instant::now();
        }
        match batch {
            Batch::Events(events) => {
                for event in events {
                    if sent_in_window >= rate {
                        let elapsed = window.elapsed();
                        if elapsed < Duration::from_secs(1) {
                            std::thread::sleep(Duration::from_secs(1) - elapsed);
                        }
                        window = Instant::now();
                        sent_in_window = 0;
                    }
                    if write_frame(conn, &event_frame(id, event.to_json(log.epoch()))).is_err() {
                        return;
                    }
                    cursor = event.seq;
                    sent_in_window += 1;
                    written = Instant::now();
                }
            }
            Batch::Gap { head, oldest } => {
                let event = snapshot_event(shared, "gap", head, oldest);
                let _ = write_frame(conn, &event_frame(id, event));
                return;
            }
            Batch::Idle { head } => {
                if written.elapsed() >= shared.limits.heartbeat {
                    if write_frame(conn, &heartbeat_frame(id, head)).is_err() {
                        return;
                    }
                    written = Instant::now();
                }
            }
        }
    }
}

/// Runs an admitted connection on its own thread, or answers `BUSY` when
/// every slot is taken. A refused peer is dropped without a read or write.
fn dispatch_connection<T>(mut conn: T, admitted: Result<PeerInfo, Refusal>, shared: &Arc<Shared>)
where
    T: Transport + Send + 'static,
{
    let peer = match admitted {
        Ok(peer) => peer,
        Err(refusal) => {
            eprintln!("orceld app api: refused a connection: {refusal}");
            return;
        }
    };
    let Some(slot) = Slot::acquire(shared) else {
        if conn
            .set_timeouts(None, Some(shared.limits.write_timeout))
            .is_ok()
        {
            let _ = write_frame(
                &mut conn,
                &error_frame(
                    &Value::Null,
                    "BUSY",
                    format!(
                        "the endpoint serves at most {} clients",
                        shared.limits.max_clients
                    ),
                ),
            );
            conn.finish();
        }
        return;
    };
    let worker = Arc::clone(shared);
    let spawned = std::thread::Builder::new()
        .name("orcel-app-api-conn".into())
        .spawn(move || {
            let _slot = slot;
            serve_connection(conn, peer, &worker);
        });
    if let Err(error) = spawned {
        eprintln!("orceld app api: could not start a connection thread: {error}");
    }
}

// ---------------------------------------------------------------------------
// Endpoint startup
// ---------------------------------------------------------------------------

/// Why the endpoint could not be taken.
#[derive(Debug, PartialEq, Eq)]
enum StartError {
    /// Another live server holds the endpoint; try again later. The text
    /// says who holds it, as far as this process can tell.
    InUse(String),
    /// The endpoint location is unsafe or unusable; never retried.
    Refused(String),
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InUse(reason) | Self::Refused(reason) => f.write_str(reason),
        }
    }
}

/// The running app API, as orceld's request loop sees it.
pub(crate) struct AppApi {
    log: Option<Arc<EventLog>>,
    #[cfg(unix)]
    bound: Arc<Mutex<Option<unix::Bound>>>,
}

impl AppApi {
    fn disabled() -> Self {
        Self {
            log: None,
            #[cfg(unix)]
            bound: Arc::new(Mutex::new(None)),
        }
    }

    /// Records one event for subscribers. Never blocks on a client.
    pub(crate) fn publish(&self, kind: &str, data: Value) {
        if let Some(log) = &self.log {
            log.publish(kind, data);
        }
    }
}

#[cfg(unix)]
impl Drop for AppApi {
    fn drop(&mut self) {
        // Remove the socket orceld bound, and only that inode.
        let bound = self
            .bound
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        drop(bound);
    }
}

/// `ORCEL_APP_API_INSTANCE`: an optional suffix so tests and side-by-side
/// installs get endpoints of their own; 1 to 32 of `a-z`, `0-9` and `-`.
fn instance_suffix(value: Option<std::ffi::OsString>) -> Result<String, String> {
    let Some(value) = value else {
        return Ok(String::new());
    };
    let value = value
        .into_string()
        .map_err(|_| "ORCEL_APP_API_INSTANCE is not UTF-8".to_owned())?;
    let valid = !value.is_empty()
        && value.len() <= 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if valid {
        Ok(format!("-{value}"))
    } else {
        Err("ORCEL_APP_API_INSTANCE must be 1-32 characters of a-z, 0-9 and -".into())
    }
}

fn new_epoch() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    format!("{:x}-{:x}", std::process::id(), nanos)
}

/// Starts the endpoint on a background thread. Never fails orceld: when the
/// endpoint cannot be taken the reason goes to stderr and the request loop
/// runs as before. `ORCEL_APP_API=off` disables it.
pub(crate) fn start(facts: DaemonFacts, tasks: Arc<TaskRegistry>) -> AppApi {
    if std::env::var_os("ORCEL_APP_API").is_some_and(|value| value == "off") {
        eprintln!("orceld app api: disabled by ORCEL_APP_API=off");
        return AppApi::disabled();
    }
    let suffix = match instance_suffix(std::env::var_os("ORCEL_APP_API_INSTANCE")) {
        Ok(suffix) => suffix,
        Err(reason) => {
            eprintln!("orceld app api: unavailable: {reason}");
            return AppApi::disabled();
        }
    };
    let limits = Limits::default();
    let log = Arc::new(EventLog::new(limits.ring_capacity, new_epoch()));
    log.publish(
        "daemon.started",
        json!({ "pid": std::process::id(), "mode": facts.mode }),
    );
    let api = AppApi {
        log: Some(Arc::clone(&log)),
        #[cfg(unix)]
        bound: Arc::new(Mutex::new(None)),
    };
    #[cfg(unix)]
    let endpoint = unix::default_path(&suffix).map(|path| (path.display().to_string(), path));
    #[cfg(windows)]
    let endpoint = win::pipe_name(&suffix).map(|name| (name.clone(), name));
    let (label, endpoint) = match endpoint {
        Ok(endpoint) => endpoint,
        Err(reason) => {
            eprintln!("orceld app api: unavailable: {reason}");
            return AppApi::disabled();
        }
    };
    tasks.attach_events(Arc::clone(&log));
    let shared = Arc::new(Shared::new(facts, log, tasks, limits, label));
    #[cfg(unix)]
    let bound = Arc::clone(&api.bound);
    let spawned = std::thread::Builder::new()
        .name("orcel-app-api".into())
        .spawn(move || loop {
            #[cfg(unix)]
            let taken = unix::bind(&endpoint).map(|(listener, guard)| {
                *bound
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(guard);
                listener
            });
            #[cfg(windows)]
            let taken = win::create_first(&endpoint);
            match taken {
                Ok(listener) => {
                    if let Some(wait) = shared
                        .wait
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .as_ref()
                    {
                        eprintln!(
                            "orceld app api: took over the endpoint after {} attempts; it was held: {}",
                            wait.attempts, wait.reason
                        );
                    }
                    eprintln!("orceld app api: listening on {}", shared.endpoint);
                    #[cfg(unix)]
                    {
                        let reason = match unix::serve_watched(
                            listener,
                            &shared,
                            &bound,
                            unix::ENDPOINT_CHECK,
                            unix::ENDPOINT_TOUCH,
                        ) {
                            unix::Watched::Lost(reason) => reason,
                            // `AppApi::drop` took the binding: orceld is shutting
                            // down, so do not bind again (#419).
                            unix::Watched::Released => return,
                        };
                        // Remove our socket if the path still names it and
                        // release the lock, then take both again (#398).
                        let released = bound
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .take();
                        drop(released);
                        eprintln!(
                            "orceld app api: {reason}; binding {} again",
                            shared.endpoint
                        );
                        shared
                            .log
                            .publish("app_api.endpoint_lost", json!({ "reason": reason }));
                    }
                    #[cfg(windows)]
                    {
                        win::serve(&endpoint, listener, &shared);
                        return;
                    }
                }
                Err(StartError::InUse(reason)) => {
                    // #375 item 1: once, with the reason, so a squatted pipe
                    // name or a second daemon is visible; status.get of the
                    // orceld that finally takes the endpoint reports it too.
                    if shared.note_in_use(&reason) {
                        eprintln!(
                            "orceld app api: waiting for {}: {reason}; retrying every {} s",
                            shared.endpoint,
                            REBIND_INTERVAL.as_secs()
                        );
                        shared
                            .log
                            .publish("app_api.endpoint_in_use", json!({ "reason": reason }));
                    }
                    std::thread::sleep(REBIND_INTERVAL);
                }
                Err(error) => {
                    eprintln!(
                        "orceld app api: unavailable at {}: {error}",
                        shared.endpoint
                    );
                    return;
                }
            }
        });
    if let Err(error) = spawned {
        eprintln!("orceld app api: could not start: {error}");
    }
    api
}

// ---------------------------------------------------------------------------
// Unix domain socket
// ---------------------------------------------------------------------------

#[cfg(unix)]
mod unix {
    use super::{admit_unix, dispatch_connection, Shared, StartError, Transport};
    use orcel_platform::paths::StateLayout;
    use std::ffi::OsString;
    use std::fs::File;
    use std::io::{self, Read as _};
    use std::net::Shutdown;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    /// How often [`serve_watched`] checks that the socket and lock paths
    /// still name the files this process bound and locked (#398 item 1).
    pub(super) const ENDPOINT_CHECK: Duration = Duration::from_secs(5);
    /// How often it sets their access and modification times to now. The
    /// XDG Base Directory spec lets `$XDG_RUNTIME_DIR` be cleaned of files
    /// not touched for 6 hours, and macOS's dirhelper purges files under
    /// `DARWIN_USER_TEMP_DIR` that were not accessed for about 3 days.
    pub(super) const ENDPOINT_TOUCH: Duration = Duration::from_secs(60 * 60);

    /// Longest and largest drain after a refused frame; see [`Transport::linger`].
    const LINGER_MAX: Duration = Duration::from_secs(2);
    const LINGER_MAX_BYTES: usize = 1024 * 1024;

    /// `sun_path` holds 104 bytes on macOS and 108 on Linux, NUL included.
    pub(super) const MAX_SOCKET_PATH: usize = 100;

    impl Transport for UnixStream {
        fn set_timeouts(
            &mut self,
            read: Option<Duration>,
            write: Option<Duration>,
        ) -> io::Result<()> {
            self.set_read_timeout(read)?;
            self.set_write_timeout(write)
        }

        fn finish(&mut self) {
            let _ = self.shutdown(Shutdown::Write);
        }

        fn linger(&mut self) {
            let deadline = Instant::now() + LINGER_MAX;
            let mut drained = 0usize;
            let mut buffer = [0u8; 8192];
            while drained < LINGER_MAX_BYTES {
                let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                    return;
                };
                if self.set_read_timeout(Some(remaining)).is_err() {
                    return;
                }
                match self.read(&mut buffer) {
                    Ok(0) | Err(_) => return,
                    Ok(read) => drained += read,
                }
            }
        }
    }

    /// `<socket dir>/app-api<suffix>.sock`; see [`socket_dir`].
    pub(super) fn default_path(suffix: &str) -> Result<PathBuf, String> {
        let layout = StateLayout::current()
            .ok_or_else(|| "the app API has no socket location on this OS".to_owned())?;
        let dir = socket_dir(
            layout,
            &|name| std::env::var_os(name),
            orcel_platform::paths::macos_per_user_runtime_dir(),
            &runtime_dir_is_private,
        )?;
        Ok(dir.join(format!("app-api{suffix}.sock")))
    }

    /// The directory the socket lives in (#381). A `sun_path` holds about
    /// 100 bytes, too few for a socket below a long home, so the socket
    /// goes to a short per-user runtime directory when the OS has one:
    ///
    /// - macOS: `<DARWIN_USER_TEMP_DIR>/orcel`, the per-user
    ///   `/var/folders/<xx>/<id>/T/` that `confstr` names (`darwin_temp`);
    /// - Linux: `$XDG_RUNTIME_DIR/orcel` when it is set to an absolute path
    ///   (normally `/run/user/<uid>`, where XP-17's `orceld.socket` puts its
    ///   own socket too).
    ///
    /// Without one it is `<state root>/run`, as in CR-01. It is also the
    /// state root when the runtime directory is not this user's private
    /// directory (`private_runtime`, #398 item 3): an `XDG_RUNTIME_DIR` set
    /// to a shared sticky directory such as `/tmp` would let another user
    /// pre-create `orcel` there and keep the endpoint off. Either way
    /// [`bind`] holds the directory to XP-01's private directory rules
    /// (0700, this user, no symlink, no ancestor another user can modify)
    /// before it takes the lock.
    /// `HOME` never decides the location when a runtime directory exists.
    pub(super) fn socket_dir(
        layout: StateLayout,
        lookup: &dyn Fn(&str) -> Option<OsString>,
        darwin_temp: Option<PathBuf>,
        private_runtime: &dyn Fn(&Path) -> bool,
    ) -> Result<PathBuf, String> {
        let runtime = match layout {
            StateLayout::MacOs => darwin_temp,
            StateLayout::Xdg => {
                orcel_platform::paths::absolute_var(layout, lookup, "XDG_RUNTIME_DIR")
            }
            StateLayout::Windows => None,
        };
        if let Some(runtime) = runtime.filter(|runtime| private_runtime(runtime)) {
            return Ok(runtime.join("orcel"));
        }
        orcel_platform::paths::state_root_for(layout, lookup)
            .map(|root| root.join("run"))
            .map_err(|error| error.to_string())
    }

    /// Whether `dir` is a runtime directory as the XDG Base Directory spec
    /// requires one: a real directory (not a link) owned by this user, with
    /// no access for group or others. `/run/user/<uid>` and macOS's
    /// per-user temp directory are; a shared sticky `/tmp` is not.
    pub(super) fn runtime_dir_is_private(dir: &Path) -> bool {
        let Some(our_uid) = orcel_platform::session::effective_uid() else {
            return false;
        };
        std::fs::symlink_metadata(dir).is_ok_and(|meta| {
            meta.file_type().is_dir() && meta.uid() == our_uid && meta.mode() & 0o077 == 0
        })
    }

    /// The lock file of the socket at `path`: `app-api<suffix>.lock`.
    pub(super) fn lock_path(path: &Path) -> PathBuf {
        path.with_extension("lock")
    }

    /// Takes the advisory lock that makes the endpoint single-instance per
    /// user (#375 item 3). Whoever holds it is the only process that may
    /// inspect, remove or bind the socket, so two orcelds that both find a
    /// stale socket can never unlink each other's live one. The lock is
    /// `flock`, tied to this open file and released by the kernel when the
    /// process exits however it exits, so a crashed holder never leaves the
    /// endpoint locked. The file itself is never removed: unlinking a lock
    /// file lets two processes lock two different inodes.
    pub(super) fn take_lock(path: &Path, our_uid: u32) -> Result<File, StartError> {
        match std::fs::symlink_metadata(path) {
            Ok(meta) if !meta.file_type().is_file() => {
                return Err(StartError::Refused(format!(
                    "the lock path {} is not a regular file; it was left in place",
                    path.display()
                )))
            }
            _ => {}
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)
            .map_err(|error| io_refused("open the lock file", error))?;
        let meta = file
            .metadata()
            .map_err(|error| io_refused("inspect the lock file", error))?;
        if !meta.is_file() || meta.uid() != our_uid {
            return Err(StartError::Refused(format!(
                "the lock file {} is not this user's regular file; it was left in place",
                path.display()
            )));
        }
        match orcel_platform::paths::try_lock_exclusive(&file) {
            Ok(true) => Ok(file),
            Ok(false) => Err(StartError::InUse(format!(
                "another orceld of this user holds the lock {}",
                path.display()
            ))),
            Err(error) => Err(io_refused("lock the endpoint", error)),
        }
    }

    /// What occupies the socket path now, read without following links.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum Existing {
        Missing,
        Symlink,
        NotSocket,
        Socket { owner: u32 },
    }

    pub(super) fn existing(path: &Path) -> io::Result<Existing> {
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Existing::Missing),
            Err(error) => Err(error),
            Ok(meta) if meta.file_type().is_symlink() => Ok(Existing::Symlink),
            Ok(meta) if !meta.file_type().is_socket() => Ok(Existing::NotSocket),
            Ok(meta) => Ok(Existing::Socket { owner: meta.uid() }),
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    pub(super) enum Stale {
        Bind,
        RemoveThenBind,
    }

    /// Whether the path may be bound, and whether a socket there must be
    /// removed first. Only a socket this user owns, that no live server
    /// answers on, is ever removed; anything else is left in place.
    pub(super) fn stale_decision(
        existing: Existing,
        our_uid: u32,
        live: impl FnOnce() -> bool,
    ) -> Result<Stale, StartError> {
        match existing {
            Existing::Missing => Ok(Stale::Bind),
            Existing::Symlink => Err(StartError::Refused(
                "the socket path is a symbolic link; it was left in place".into(),
            )),
            Existing::NotSocket => Err(StartError::Refused(
                "the socket path is not a socket; it was left in place".into(),
            )),
            Existing::Socket { owner } if owner != our_uid => Err(StartError::Refused(format!(
                "the socket at the path is owned by uid {owner}, not {our_uid}; it was left in place"
            ))),
            Existing::Socket { .. } if live() => Err(StartError::InUse(
                "a live server of this user answers on the socket".into(),
            )),
            Existing::Socket { .. } => Ok(Stale::RemoveThenBind),
        }
    }

    /// The socket this process bound; dropping it removes the socket if the
    /// path still names the same inode, and only then releases the lock.
    pub(super) struct Bound {
        path: PathBuf,
        dev: u64,
        ino: u64,
        /// The lock file's identity, so a removed or replaced lock file is
        /// noticed: a lock on an unlinked inode no longer keeps a second
        /// orceld out.
        lock_dev: u64,
        lock_ino: u64,
        /// Dropped after `drop` ran, so the socket is gone before another
        /// orceld can take the lock.
        _lock: File,
    }

    impl Bound {
        /// `Ok` while the socket path and the lock path still name the
        /// socket this process bound and the file it locked; otherwise the
        /// reason. Links are never followed.
        pub(super) fn intact(&self) -> Result<(), String> {
            let same = |path: &Path, dev: u64, ino: u64| {
                std::fs::symlink_metadata(path)
                    .map(|meta| meta.dev() == dev && meta.ino() == ino)
                    .unwrap_or(false)
            };
            if !same(&self.path, self.dev, self.ino) {
                return Err(format!(
                    "the socket {} was removed or replaced",
                    self.path.display()
                ));
            }
            let lock = lock_path(&self.path);
            if !same(&lock, self.lock_dev, self.lock_ino) {
                return Err(format!(
                    "the lock file {} was removed or replaced",
                    lock.display()
                ));
            }
            Ok(())
        }

        /// Sets the access and modification times of the socket and the
        /// lock file to now, without following links, so periodic clean-up
        /// of the runtime directory keeps them.
        pub(super) fn touch(&self) -> io::Result<()> {
            touch_nofollow(&self.path)?;
            touch_nofollow(&lock_path(&self.path))
        }
    }

    fn touch_nofollow(path: &Path) -> io::Result<()> {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path holds a NUL byte"))?;
        // SAFETY: `path` is a NUL-terminated string that outlives the call.
        // A null `times` sets both times to now, and AT_SYMLINK_NOFOLLOW
        // makes the call act on a link itself, never on its target.
        let result = unsafe {
            libc::utimensat(
                libc::AT_FDCWD,
                path.as_ptr(),
                std::ptr::null(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    impl Drop for Bound {
        fn drop(&mut self) {
            let same = std::fs::symlink_metadata(&self.path)
                .map(|meta| meta.dev() == self.dev && meta.ino() == self.ino)
                .unwrap_or(false);
            if same {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }

    fn io_refused(what: &str, error: io::Error) -> StartError {
        StartError::Refused(format!("{what}: {error}"))
    }

    pub(super) fn bind(path: &Path) -> Result<(UnixListener, Bound), StartError> {
        let parent = path
            .parent()
            .ok_or_else(|| StartError::Refused("the socket path has no parent".into()))?;
        // XP-01: 0700, owned by us, no symlink, no ancestor others can write.
        orcel_platform::paths::ensure_private_dir(parent)
            .map_err(|error| StartError::Refused(error.to_string()))?;
        let length = path.as_os_str().len();
        if length > MAX_SOCKET_PATH {
            // Never truncated or retried: the endpoint stays off and this
            // reason reaches stderr once (CR-02 review).
            return Err(StartError::Refused(format!(
                "the socket path is {length} bytes, longer than the {MAX_SOCKET_PATH} \
                 a Unix socket allows; set XDG_RUNTIME_DIR (Linux), or use a shorter \
                 HOME or XDG_STATE_HOME"
            )));
        }
        let our_uid = orcel_platform::session::effective_uid()
            .ok_or_else(|| StartError::Refused("the effective uid is unreadable".into()))?;
        // Everything below runs under the lock, so no other orceld inspects,
        // removes or binds the socket meanwhile.
        let lock = take_lock(&lock_path(path), our_uid)?;
        let found = existing(path).map_err(|error| io_refused("inspect the socket path", error))?;
        // The private parent keeps other users from swapping the entry
        // between this check and the removal. The live probe still matters
        // under the lock: a server that does not take it (an older orceld)
        // keeps its socket.
        if stale_decision(found, our_uid, || UnixStream::connect(path).is_ok())?
            == Stale::RemoveThenBind
        {
            std::fs::remove_file(path)
                .map_err(|error| io_refused("remove the stale socket", error))?;
        }
        let listener = match UnixListener::bind(path) {
            Ok(listener) => listener,
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                return Err(StartError::InUse(
                    "another server bound the socket path first".into(),
                ))
            }
            Err(error) => return Err(io_refused("bind the socket", error)),
        };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| io_refused("restrict the socket", error))?;
        let meta = std::fs::symlink_metadata(path)
            .map_err(|error| io_refused("inspect the bound socket", error))?;
        if !meta.file_type().is_socket() || meta.uid() != our_uid {
            return Err(StartError::Refused(
                "the bound socket path does not name this user's socket".into(),
            ));
        }
        let lock_meta = lock
            .metadata()
            .map_err(|error| io_refused("inspect the lock file", error))?;
        let bound = Bound {
            path: path.to_path_buf(),
            dev: meta.dev(),
            ino: meta.ino(),
            lock_dev: lock_meta.dev(),
            lock_ino: lock_meta.ino(),
            _lock: lock,
        };
        Ok((listener, bound))
    }

    /// Serves `listener` without endpoint upkeep; the tests' in-process
    /// servers own their binding themselves. orceld uses [`serve_watched`].
    #[cfg(test)]
    pub(super) fn serve(listener: UnixListener, shared: &Arc<Shared>) {
        let our_uid = orcel_platform::session::effective_uid();
        // Bounded by the process lifetime: one iteration per accepted peer.
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => admit_and_dispatch(stream, our_uid, shared),
                Err(error) => {
                    eprintln!("orceld app api: accept failed: {error}");
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
    }

    fn admit_and_dispatch(stream: UnixStream, our_uid: Option<u32>, shared: &Arc<Shared>) {
        let admitted = admit_unix(
            orcel_platform::peer::unix_peer_credentials(&stream),
            our_uid,
        );
        dispatch_connection(stream, admitted, shared);
    }

    /// Why [`serve_watched`] stopped.
    #[derive(Debug, PartialEq, Eq)]
    pub(super) enum Watched {
        /// The socket or lock path no longer names our binding; bind again.
        Lost(String),
        /// `AppApi::drop` took the binding during shutdown; do not bind again.
        Released,
    }

    /// [`serve`] for the endpoint `bound` describes, which also keeps that
    /// endpoint alive (#398 item 1): at least every `check` it confirms that
    /// the socket and lock paths still name what this process bound and
    /// locked, and every `touch` it refreshes their times. It returns the
    /// reason as soon as either was removed or replaced (a runtime directory
    /// clean-up, or a user), so the caller releases the binding and binds
    /// again under a fresh lock instead of serving an endpoint no client
    /// can reach while a second orceld binds beside it.
    pub(super) fn serve_watched(
        listener: UnixListener,
        shared: &Arc<Shared>,
        bound: &Mutex<Option<Bound>>,
        check: Duration,
        touch: Duration,
    ) -> Watched {
        let our_uid = orcel_platform::session::effective_uid();
        if let Err(error) = listener.set_nonblocking(true) {
            return Watched::Lost(format!("the listener could not be polled: {error}"));
        }
        let mut touched = Instant::now();
        loop {
            match wait_readable(&listener, check) {
                Ok(true) => match listener.accept() {
                    // macOS hands out accepted sockets with the listener's
                    // O_NONBLOCK; connections are served blocking.
                    Ok((stream, _)) => match stream.set_nonblocking(false) {
                        Ok(()) => admit_and_dispatch(stream, our_uid, shared),
                        Err(error) => eprintln!("orceld app api: accept failed: {error}"),
                    },
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) => {}
                    Err(error) => {
                        eprintln!("orceld app api: accept failed: {error}");
                        std::thread::sleep(Duration::from_millis(50));
                    }
                },
                Ok(false) => {}
                Err(error) => {
                    eprintln!("orceld app api: poll failed: {error}");
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
            let guard = bound
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let Some(current) = guard.as_ref() else {
                return Watched::Released;
            };
            if let Err(reason) = current.intact() {
                return Watched::Lost(reason);
            }
            if touched.elapsed() >= touch {
                if let Err(error) = current.touch() {
                    eprintln!("orceld app api: could not refresh the endpoint files: {error}");
                }
                touched = Instant::now();
            }
        }
    }

    /// Waits up to `timeout` for a pending connection on `listener`.
    fn wait_readable(listener: &UnixListener, timeout: Duration) -> io::Result<bool> {
        use std::os::fd::AsRawFd;
        let mut entry = libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let millis = libc::c_int::try_from(timeout.as_millis()).unwrap_or(libc::c_int::MAX);
        // SAFETY: `entry` is one valid `pollfd` that outlives the call, and
        // its descriptor stays open while `listener` is borrowed.
        match unsafe { libc::poll(&mut entry, 1, millis) } {
            0 => Ok(false),
            ready if ready > 0 => Ok(true),
            _ => {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    Ok(false)
                } else {
                    Err(error)
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Windows named pipe
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod win {
    use super::{
        admit_pipe, dispatch_connection, PipeClientFacts, Shared, StartError, Transport,
        MAX_FRAME_BYTES,
    };
    use orcel_platform::PlatformError;
    use std::ffi::c_void;
    use std::io;
    use std::sync::Arc;
    use std::time::Duration;
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, LocalFree, ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE,
        ERROR_INVALID_PARAMETER, ERROR_IO_PENDING, ERROR_NO_DATA, ERROR_PIPE_BUSY,
        ERROR_PIPE_CONNECTED, GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        EqualSid, GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
        OPEN_EXISTING, PIPE_ACCESS_DUPLEX, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
        GetNamedPipeClientSessionId, GetNamedPipeServerProcessId, PeekNamedPipe,
        PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES,
        PIPE_WAIT,
    };
    use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    use windows_sys::Win32::System::Threading::{
        CreateEventW, GetCurrentProcess, OpenProcess, OpenProcessToken, WaitForSingleObject,
        INFINITE, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

    /// Bytes the system buffers in each direction of one pipe instance.
    const PIPE_BUFFER: u32 = MAX_FRAME_BYTES as u32;

    /// A handle closed exactly once.
    pub(super) struct Owned(pub(super) HANDLE);

    impl Drop for Owned {
        fn drop(&mut self) {
            if self.0 != 0 && self.0 != INVALID_HANDLE_VALUE {
                // SAFETY: the handle was opened by this module and is closed once.
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    pub(super) fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// A process token's `TOKEN_USER`, in memory aligned for the struct.
    pub(super) struct TokenUserBuf(Vec<u64>);

    impl TokenUserBuf {
        /// The account's SID; valid while `self` is.
        pub(super) fn sid(&self) -> *mut c_void {
            // SAFETY: the buffer was filled by GetTokenInformation(TokenUser)
            // and is aligned for TOKEN_USER.
            unsafe { (*(self.0.as_ptr() as *const TOKEN_USER)).User.Sid }
        }
    }

    /// The account `process` (a handle with query rights) runs as.
    pub(super) fn token_user(process: HANDLE) -> io::Result<TokenUserBuf> {
        let mut token: HANDLE = 0;
        // SAFETY: `process` is a live process handle; `token` receives a
        // handle that `Owned` closes.
        if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = Owned(token);
        let mut len = 0u32;
        // SAFETY: the first call only asks how much room the answer needs.
        unsafe { GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut len) };
        if len == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        // SAFETY: `buf` holds at least `len` bytes, aligned for TOKEN_USER.
        if unsafe {
            GetTokenInformation(token.0, TokenUser, buf.as_mut_ptr().cast(), len, &mut len)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(TokenUserBuf(buf))
    }

    /// This account's SID as `S-1-5-...`.
    pub(super) fn current_user_sid() -> io::Result<String> {
        // SAFETY: the pseudo handle of this process needs no closing.
        let user = token_user(unsafe { GetCurrentProcess() })?;
        let mut text: *mut u16 = std::ptr::null_mut();
        // SAFETY: the SID is valid while `user` is; `text` receives a
        // LocalAlloc'd string freed below.
        if unsafe { ConvertSidToStringSidW(user.sid(), &mut text) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `text` is a NUL-terminated UTF-16 string we free once.
        let sid = unsafe {
            let mut len = 0;
            while *text.add(len) != 0 {
                len += 1;
            }
            let sid = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
            LocalFree(text.cast());
            sid
        };
        Ok(sid)
    }

    /// `\\.\pipe\orcel-<sid>-app<suffix>`.
    pub(super) fn pipe_name(suffix: &str) -> Result<String, String> {
        let sid = current_user_sid().map_err(|error| format!("the user SID: {error}"))?;
        Ok(format!(r"\\.\pipe\orcel-{sid}-app{suffix}"))
    }

    /// Generic-all for this account, nobody else, not inherited; and an
    /// explicit Medium mandatory label (#375 item 2), so a Low-integrity
    /// process of this account (a sandboxed renderer, say) cannot open the
    /// pipe whatever the DACL says, rather than relying on the implicit
    /// label of an unlabeled object. The label carries no-read-up as well as
    /// no-write-up: no-write-up alone would still let a Low process open the
    /// pipe read-only and hold a client slot.
    pub(super) fn sddl(sid: &str) -> String {
        format!("D:P(A;;GA;;;{sid})S:(ML;;NWNR;;;ME)")
    }

    /// One end of a pipe opened for overlapped I/O, so every read, write and
    /// connect can time out.
    pub(super) struct Pipe {
        pub(super) handle: Owned,
        event: Owned,
        read_timeout: Option<Duration>,
        write_timeout: Option<Duration>,
    }

    fn millis(timeout: Option<Duration>) -> u32 {
        timeout
            .map(|timeout| u32::try_from(timeout.as_millis()).unwrap_or(INFINITE - 1))
            .unwrap_or(INFINITE)
    }

    impl Pipe {
        pub(super) fn from_handle(handle: HANDLE) -> io::Result<Self> {
            let handle = Owned(handle);
            // SAFETY: a manual-reset, unnamed event with default security.
            let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
            if event == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                handle,
                event: Owned(event),
                read_timeout: None,
                write_timeout: None,
            })
        }

        fn raw(&self) -> HANDLE {
            self.handle.0
        }

        /// Waits for the overlapped operation `ov` to finish, cancelling it
        /// after `timeout`.
        fn complete(&self, ov: &OVERLAPPED, timeout: Option<Duration>) -> io::Result<u32> {
            // SAFETY: `self.event` is the live event `ov` signals.
            let waited = unsafe { WaitForSingleObject(self.event.0, millis(timeout)) };
            let mut transferred = 0u32;
            if waited != WAIT_OBJECT_0 {
                let error = if waited == windows_sys::Win32::Foundation::WAIT_TIMEOUT {
                    io::Error::new(io::ErrorKind::TimedOut, "pipe operation timed out")
                } else {
                    io::Error::last_os_error()
                };
                // SAFETY: `ov` is the pending operation on this handle; after
                // cancelling, wait for it so `ov` and the buffer outlive it.
                unsafe {
                    CancelIoEx(self.raw(), ov);
                    GetOverlappedResult(self.raw(), ov, &mut transferred, 1);
                }
                return Err(error);
            }
            // SAFETY: the operation has completed; `ov` is still live.
            if unsafe { GetOverlappedResult(self.raw(), ov, &mut transferred, 0) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(transferred)
        }

        fn overlapped(&self) -> OVERLAPPED {
            // SAFETY: an all-zero OVERLAPPED is the documented initial value.
            let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
            ov.hEvent = self.event.0;
            ov
        }

        /// Waits for a client of this server instance.
        pub(super) fn connect(&self) -> io::Result<()> {
            let mut ov = self.overlapped();
            // SAFETY: `ov` lives until `complete` returns.
            if unsafe { ConnectNamedPipe(self.raw(), &mut ov) } != 0 {
                return Ok(());
            }
            // SAFETY: plain read of this thread's last error.
            match unsafe { GetLastError() } {
                ERROR_PIPE_CONNECTED => Ok(()),
                ERROR_IO_PENDING => self.complete(&ov, None).map(|_| ()),
                error => Err(io::Error::from_raw_os_error(error as i32)),
            }
        }

        fn transfer(&self, buf: *mut u8, len: usize, write: bool) -> io::Result<usize> {
            let len = u32::try_from(len).unwrap_or(u32::MAX);
            let mut ov = self.overlapped();
            // SAFETY: `buf` holds `len` bytes and, like `ov`, outlives the
            // operation: `complete` waits for it even after a cancel.
            let started = unsafe {
                if write {
                    WriteFile(self.raw(), buf, len, std::ptr::null_mut(), &mut ov)
                } else {
                    ReadFile(self.raw(), buf, len, std::ptr::null_mut(), &mut ov)
                }
            };
            if started == 0 {
                // SAFETY: plain read of this thread's last error.
                let error = unsafe { GetLastError() };
                if !write && error == ERROR_BROKEN_PIPE {
                    return Ok(0);
                }
                if error != ERROR_IO_PENDING {
                    return Err(io::Error::from_raw_os_error(error as i32));
                }
            }
            let timeout = if write {
                self.write_timeout
            } else {
                self.read_timeout
            };
            match self.complete(&ov, timeout) {
                Ok(transferred) => Ok(transferred as usize),
                Err(error) if !write && error.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) => {
                    Ok(0)
                }
                Err(error) => Err(error),
            }
        }

        /// Whether the other end still holds the pipe.
        fn still_connected(&self) -> bool {
            // SAFETY: a zero-byte peek with no output buffers.
            unsafe {
                PeekNamedPipe(
                    self.raw(),
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                ) != 0
            }
        }
    }

    impl io::Read for Pipe {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.transfer(buf.as_mut_ptr(), buf.len(), false)
        }
    }

    impl io::Write for Pipe {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            // WriteFile only reads from the buffer.
            self.transfer(buf.as_ptr().cast_mut(), buf.len(), true)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Transport for Pipe {
        fn set_timeouts(
            &mut self,
            read: Option<Duration>,
            write: Option<Duration>,
        ) -> io::Result<()> {
            self.read_timeout = read;
            self.write_timeout = write;
            Ok(())
        }

        fn finish(&mut self) {
            // Nothing to do: closing the server handle keeps what was
            // written readable by the client until its end is closed, and
            // waiting for the client here could stall the accept thread.
        }
    }

    /// A new server instance of `name` with this user's DACL.
    pub(super) fn create_instance(name: &str, first: bool) -> io::Result<Pipe> {
        let sid = current_user_sid()?;
        let sddl = wide(&sddl(&sid));
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `sddl` is NUL-terminated UTF-16; `descriptor` receives a
        // LocalAlloc'd descriptor freed below.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let mut open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
        if first {
            open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
        }
        let name = wide(name);
        // SAFETY: `name` is NUL-terminated; `attributes` and its descriptor
        // live through the call, which copies the descriptor.
        let handle = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                open_mode,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                PIPE_BUFFER,
                PIPE_BUFFER,
                0,
                &attributes,
            )
        };
        let created = if handle == INVALID_HANDLE_VALUE {
            Err(io::Error::last_os_error())
        } else {
            Pipe::from_handle(handle)
        };
        // SAFETY: the descriptor is freed once, after the system copied it.
        unsafe { LocalFree(descriptor.cast()) };
        created
    }

    /// The first instance: fails when any server already holds the name.
    pub(super) fn create_first(name: &str) -> Result<Pipe, StartError> {
        create_instance(name, true).map_err(|error| {
            let code = error.raw_os_error().map(|code| code as u32);
            if code == Some(ERROR_ACCESS_DENIED) || code == Some(ERROR_PIPE_BUSY) {
                StartError::InUse(format!(
                    "the pipe name already exists ({error}); {}",
                    describe_holder(name)
                ))
            } else {
                StartError::Refused(format!("create the pipe: {error}"))
            }
        })
    }

    /// Who holds `name`, for the one log line and `endpoint_wait` (#375
    /// item 1): a pipe another account created first (squatting) and a
    /// second orceld of this user read differently. Opens the pipe as a
    /// client with identification-only impersonation and reads the server's
    /// pid and account; it sends nothing and closes at once.
    pub(super) fn describe_holder(name: &str) -> String {
        let wide = wide(name);
        // SAFETY: `wide` is NUL-terminated; `Owned` closes the handle.
        let handle = Owned(unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                0,
            )
        });
        if handle.0 == INVALID_HANDLE_VALUE {
            let error = io::Error::last_os_error();
            return match error.raw_os_error().map(|code| code as u32) {
                Some(ERROR_ACCESS_DENIED) => format!(
                    "its security refuses this account, so another account created it first \
                     (the name is squatted): {error}"
                ),
                Some(ERROR_PIPE_BUSY) => {
                    "its server has no free instance, so its holder is unknown".to_owned()
                }
                _ => format!("its holder could not be opened: {error}"),
            };
        }
        let mut pid = 0u32;
        // SAFETY: `pid` receives the id; a failure leaves it 0.
        if unsafe { GetNamedPipeServerProcessId(handle.0, &mut pid) } == 0 || pid == 0 {
            return "its server process could not be read".to_owned();
        }
        match same_account(pid) {
            Ok(true) => {
                format!("it is held by process {pid}, which runs as this account (another orceld?)")
            }
            Ok(false) => format!(
                "it is held by process {pid}, which runs as another account (the name is squatted)"
            ),
            Err(error) => format!("it is held by process {pid}, whose account is unknown: {error}"),
        }
    }

    fn own_session() -> Option<u32> {
        let mut session = 0u32;
        // SAFETY: `session` receives the id.
        (unsafe { ProcessIdToSessionId(std::process::id(), &mut session) } != 0).then_some(session)
    }

    /// What an `OpenProcess` failure with `code` means for `pid` (#375 item
    /// 6). Every failure refuses the connection; only a pid that names no
    /// process (`ERROR_INVALID_PARAMETER`) is reported as gone, and a denied
    /// open says so instead of claiming the process exited.
    pub(super) fn open_process_failure(pid: u32, code: u32) -> PlatformError {
        match code {
            ERROR_INVALID_PARAMETER => PlatformError::ProcessGone(pid),
            ERROR_ACCESS_DENIED => PlatformError::IdentityUnavailable(format!(
                "OpenProcess({pid}) was denied (ERROR_ACCESS_DENIED)"
            )),
            code => PlatformError::IdentityUnavailable(format!(
                "OpenProcess({pid}) failed with Win32 error {code}"
            )),
        }
    }

    /// Whether `pid` runs as this account.
    fn same_account(pid: u32) -> Result<bool, PlatformError> {
        // SAFETY: plain call; `Owned` closes the handle.
        let process = Owned(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) });
        if process.0 == 0 {
            // SAFETY: plain read of this thread's last error.
            return Err(open_process_failure(pid, unsafe { GetLastError() }));
        }
        let unavailable = |error: io::Error| PlatformError::IdentityUnavailable(error.to_string());
        let theirs = token_user(process.0).map_err(unavailable)?;
        // SAFETY: the pseudo handle of this process needs no closing.
        let ours = token_user(unsafe { GetCurrentProcess() }).map_err(unavailable)?;
        // SAFETY: both SIDs live in their buffers through the call.
        Ok(unsafe { EqualSid(theirs.sid(), ours.sid()) } != 0)
    }

    /// Everything the server reads about the client of `pipe`.
    pub(super) fn client_facts(pipe: &Pipe) -> PipeClientFacts {
        let mut pid = 0u32;
        // SAFETY: `pid` receives the id; a failure leaves it 0.
        unsafe { GetNamedPipeClientProcessId(pipe.raw(), &mut pid) };
        let mut session = 0u32;
        // SAFETY: `session` receives the id.
        let session = (unsafe { GetNamedPipeClientSessionId(pipe.raw(), &mut session) } != 0)
            .then_some(session);
        let same_account = if pid == 0 {
            Err(PlatformError::ProcessGone(0))
        } else {
            same_account(pid)
        };
        let process = orcel_platform::process::start_generation(pid);
        PipeClientFacts {
            pid,
            session,
            our_session: own_session(),
            same_account,
            process,
            // The client's handle is closed when it exits; while it is
            // still open its pid cannot have been reused.
            still_connected: pipe.still_connected(),
        }
    }

    pub(super) fn serve(name: &str, first: Pipe, shared: &Arc<Shared>) {
        let mut listening = first;
        // Bounded by the process lifetime: one iteration per client.
        loop {
            if let Err(error) = listening.connect() {
                // SAFETY: resets this instance for the next client.
                unsafe { DisconnectNamedPipe(listening.raw()) };
                if error.raw_os_error() != Some(ERROR_NO_DATA as i32) {
                    eprintln!("orceld app api: connect failed: {error}");
                    std::thread::sleep(Duration::from_millis(50));
                }
                continue;
            }
            // The next instance exists before this one is handed off, so
            // the name is never free for another server to take.
            let next = match create_instance(name, false) {
                Ok(next) => next,
                Err(error) => {
                    eprintln!("orceld app api: cannot create the next pipe instance: {error}");
                    // SAFETY: drops this client and resets the instance.
                    unsafe { DisconnectNamedPipe(listening.raw()) };
                    std::thread::sleep(Duration::from_millis(200));
                    continue;
                }
            };
            let accepted = std::mem::replace(&mut listening, next);
            let admitted = admit_pipe(client_facts(&accepted));
            dispatch_connection(accepted, admitted, shared);
        }
    }
}

#[cfg(test)]
mod tests;
