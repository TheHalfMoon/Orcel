//! SG-000096 T03: bounded interactive Full User shell sessions.
//!
//! A session is one child launched exactly as [`crate::shell::run_one_shot`]
//! launches it (same owner, pinning and pre-resume checks), but with a stdin
//! pipe and kept running under supervision. The registry is server-owned:
//! session IDs are random and minted here, a caller never names a PID, and
//! every mutation carries the session generation it was approved against.
//!
//! - Output: stdout and stderr each go into an [`OutputRing`]. Offsets are
//!   absolute and only grow. When the ring is full the oldest bytes are
//!   evicted and counted, and a read from an evicted offset reports the gap.
//!   A stream is `closed` only once its end was observed.
//! - Input: a write is accepted into a bounded queue and delivered by a
//!   writer thread. `stdin_accepted_bytes` and `stdin_delivered_bytes` are
//!   reported separately; a write is never reported delivered before the
//!   pipe took it. A queue that is full refuses the write (`InputBusy`); it is
//!   never dropped or retried.
//! - End: exit, timeout or lease expiry (`expires_at`), terminate, revoke,
//!   or a lost runtime owner. Each ends the whole Job and proves it empty.
//!   A supervisor error ends the Job and reports `OutcomeUnknown`. No end
//!   state is inferred from output or a prompt.
//!
//! The kernel (orceld) checks the Full User lease and a fresh SOFT approval
//! before each start, write, close and terminate. This module only refuses
//! what does not match and supervises what it starts. Not a sandbox.
//!
//! The ring and pagination mechanics follow the bounded terminal-session
//! behaviour of the pinned Desktop Commander `terminal-manager.ts` as a
//! design reference only; no donor source is copied.

use crate::shell::{ExpectedNativeOwner, NativeProcessIdentity, ShellCommand, ShellFailure};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

pub const MAX_STDIN_FRAME_BYTES: usize = 64 * 1024;
pub const MAX_STDIN_TOTAL_BYTES: u64 = 16 * 1024 * 1024;
/// Bytes accepted but not yet delivered, at most this many frames' worth.
pub const STDIN_PENDING_FRAMES: usize = 4;
pub const MAX_READ_BYTES: usize = 1024 * 1024;
pub const MAX_LIVE_SESSIONS: usize = 8;
pub const MAX_RETAINED_SESSIONS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    Stdout,
    Stderr,
}

/// A bounded byte ring with absolute, monotonic offsets.
#[derive(Debug, Clone)]
pub struct OutputRing {
    capacity: usize,
    data: VecDeque<u8>,
    start: u64,
    closed: bool,
}

/// One page of a stream. `offset` is where `bytes` starts; when the caller
/// asked for an evicted offset, `evicted_before` counts the bytes it missed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputPage {
    pub offset: u64,
    pub bytes: Vec<u8>,
    pub next_offset: u64,
    pub evicted_before: u64,
    /// The ring's end when the page was read.
    pub end_offset: u64,
    /// True only when the stream ended and this page reaches its end.
    pub end_of_stream: bool,
}

impl OutputRing {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            data: VecDeque::new(),
            start: 0,
            closed: false,
        }
    }

    pub fn push(&mut self, bytes: &[u8]) {
        if bytes.len() >= self.capacity {
            let skipped = (self.data.len() + bytes.len() - self.capacity) as u64;
            self.data.clear();
            self.data.extend(&bytes[bytes.len() - self.capacity..]);
            self.start += skipped;
            return;
        }
        let overflow = (self.data.len() + bytes.len()).saturating_sub(self.capacity);
        self.data.drain(..overflow);
        self.start += overflow as u64;
        self.data.extend(bytes);
    }

    pub fn close(&mut self) {
        self.closed = true;
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Offset of the first byte still held; everything before was evicted.
    pub fn start_offset(&self) -> u64 {
        self.start
    }

    pub fn end_offset(&self) -> u64 {
        self.start + self.data.len() as u64
    }

    pub fn read(&self, from: u64, max: usize) -> Result<OutputPage, SessionFailure> {
        let end = self.end_offset();
        if from > end {
            return Err(SessionFailure::OffsetBeyondEnd { end });
        }
        let max = max.clamp(1, MAX_READ_BYTES);
        let begin = from.max(self.start);
        let skip = (begin - self.start) as usize;
        let bytes: Vec<u8> = self.data.iter().skip(skip).take(max).copied().collect();
        let next_offset = begin + bytes.len() as u64;
        Ok(OutputPage {
            offset: begin,
            evicted_before: begin - from,
            end_of_stream: self.closed && next_offset == end,
            next_offset,
            end_offset: end,
            bytes,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionLimits {
    /// Session lifetime, ring sizes and process count, as for a one-shot.
    /// The ring sizes bound memory; older output is evicted, never grown.
    pub stdin_frame_bytes: usize,
    pub stdin_total_bytes: u64,
}

pub fn validate_session_limits(limits: &SessionLimits) -> Result<(), SessionFailure> {
    if !(1..=MAX_STDIN_FRAME_BYTES).contains(&limits.stdin_frame_bytes)
        || !(1..=MAX_STDIN_TOTAL_BYTES).contains(&limits.stdin_total_bytes)
    {
        return Err(SessionFailure::Shell(ShellFailure::Invalid(
            "session stdin limits are out of bounds".into(),
        )));
    }
    Ok(())
}

/// How a session ended. `Running` is the only non-final state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    Running,
    Exited {
        exit_code: u32,
    },
    /// The session lifetime or the lease expiry passed.
    TimedOut,
    /// An approved terminate ended it.
    Terminated,
    /// Authority was withdrawn (lease revoked or expired, owner lost).
    Revoked {
        reason: String,
    },
    /// Supervision failed after the child ran; effects are unknown.
    OutcomeUnknown {
        reason: String,
    },
    /// The Job could not be proven empty.
    TerminationUnverified,
}

impl SessionState {
    pub fn is_running(&self) -> bool {
        matches!(self, Self::Running)
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Exited { .. } => "exited",
            Self::TimedOut => "timed_out",
            Self::Terminated => "terminated",
            Self::Revoked { .. } => "revoked",
            Self::OutcomeUnknown { .. } => "outcome_unknown",
            Self::TerminationUnverified => "termination_unverified",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamStatus {
    pub start_offset: u64,
    pub end_offset: u64,
    pub closed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionStatus {
    pub session_id: String,
    /// Bumped by every accepted mutation. A mutation approved against an
    /// older generation is refused.
    pub generation: u64,
    pub process: NativeProcessIdentity,
    pub state: SessionState,
    pub stdout: StreamStatus,
    pub stderr: StreamStatus,
    pub stdin_accepted_bytes: u64,
    pub stdin_delivered_bytes: u64,
    /// A close was accepted. The pipe closes (and the child sees end of
    /// input) once the writer has delivered every frame queued before it.
    pub stdin_closed: bool,
    pub stdin_error: Option<String>,
    pub descendants_terminated: bool,
    pub remaining: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionFailure {
    /// The launch, or a native step, failed (see [`ShellFailure`]).
    Shell(ShellFailure),
    /// No session with this ID exists in this registry.
    UnknownSession,
    /// The session changed since the operation was approved.
    StaleGeneration { current: u64 },
    /// The session already ended; it accepts no input or terminate.
    NotRunning { state: String },
    /// Too many live or retained sessions.
    RegistryFull,
    /// The stdin frame or the session's stdin total is out of bounds.
    InputLimit,
    /// The stdin queue is full; nothing was accepted.
    InputBusy,
    /// stdin was closed or failed; nothing was accepted.
    InputClosed,
    /// A read asked for an offset past the stream's end.
    OffsetBeyondEnd { end: u64 },
}

impl SessionFailure {
    pub fn message(&self) -> String {
        match self {
            Self::Shell(failure) => failure.message().to_owned(),
            Self::UnknownSession => "unknown shell session".into(),
            Self::StaleGeneration { current } => {
                format!("shell session changed since approval (now generation {current})")
            }
            Self::NotRunning { state } => format!("shell session is not running ({state})"),
            Self::RegistryFull => "too many shell sessions".into(),
            Self::InputLimit => "stdin frame or session stdin total is out of bounds".into(),
            Self::InputBusy => "stdin queue is full; nothing was written".into(),
            Self::InputClosed => "stdin is closed".into(),
            Self::OffsetBeyondEnd { end } => format!("read offset is past the stream end {end}"),
        }
    }
}

impl From<ShellFailure> for SessionFailure {
    fn from(failure: ShellFailure) -> Self {
        Self::Shell(failure)
    }
}

/// The server-owned session catalog. orceld keeps one for its lifetime;
/// dropping it ends every session's Job.
pub struct SessionRegistry {
    #[cfg(windows)]
    inner: crate::windows_contained_launch::shell_session::Registry,
}

impl Default for SessionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self {
            #[cfg(windows)]
            inner: crate::windows_contained_launch::shell_session::Registry::default(),
        }
    }

    /// Launches `command` as a session that ends no later than `expires_at`
    /// (orceld passes the lease expiry) or the command's timeout.
    pub fn start(
        &self,
        command: &ShellCommand,
        limits: &SessionLimits,
        owner: &ExpectedNativeOwner,
        expires_at: Instant,
    ) -> Result<SessionStatus, SessionFailure> {
        crate::shell::validate_command(command)?;
        validate_session_limits(limits)?;
        #[cfg(windows)]
        {
            self.inner.start(command, limits, owner, expires_at)
        }
        #[cfg(not(windows))]
        {
            let _ = (owner, expires_at);
            Err(SessionFailure::Shell(ShellFailure::Unavailable(
                "SG-000096 Full User shells are Windows-only; this host keeps the Safe and contained tiers"
                    .into(),
            )))
        }
    }

    pub fn status(&self, session_id: &str) -> Result<SessionStatus, SessionFailure> {
        #[cfg(windows)]
        {
            self.inner.status(session_id)
        }
        #[cfg(not(windows))]
        {
            let _ = session_id;
            Err(SessionFailure::UnknownSession)
        }
    }

    pub fn list(&self) -> Vec<SessionStatus> {
        #[cfg(windows)]
        {
            self.inner.list()
        }
        #[cfg(not(windows))]
        {
            Vec::new()
        }
    }

    pub fn read(
        &self,
        session_id: &str,
        stream: Stream,
        from: u64,
        max: usize,
    ) -> Result<OutputPage, SessionFailure> {
        #[cfg(windows)]
        {
            self.inner.read(session_id, stream, from, max)
        }
        #[cfg(not(windows))]
        {
            let _ = (session_id, stream, from, max);
            Err(SessionFailure::UnknownSession)
        }
    }

    pub fn write_stdin(
        &self,
        session_id: &str,
        expected_generation: u64,
        bytes: &[u8],
    ) -> Result<SessionStatus, SessionFailure> {
        #[cfg(windows)]
        {
            self.inner
                .write_stdin(session_id, expected_generation, bytes)
        }
        #[cfg(not(windows))]
        {
            let _ = (session_id, expected_generation, bytes);
            Err(SessionFailure::UnknownSession)
        }
    }

    pub fn close_stdin(
        &self,
        session_id: &str,
        expected_generation: u64,
    ) -> Result<SessionStatus, SessionFailure> {
        #[cfg(windows)]
        {
            self.inner.close_stdin(session_id, expected_generation)
        }
        #[cfg(not(windows))]
        {
            let _ = (session_id, expected_generation);
            Err(SessionFailure::UnknownSession)
        }
    }

    /// Ends a running session's whole Job and waits for the final state.
    pub fn terminate(
        &self,
        session_id: &str,
        expected_generation: u64,
    ) -> Result<SessionStatus, SessionFailure> {
        #[cfg(windows)]
        {
            self.inner.terminate(session_id, expected_generation)
        }
        #[cfg(not(windows))]
        {
            let _ = (session_id, expected_generation);
            Err(SessionFailure::UnknownSession)
        }
    }

    /// Removes an ended session and its output. A running one is refused.
    pub fn remove(
        &self,
        session_id: &str,
        expected_generation: u64,
    ) -> Result<SessionStatus, SessionFailure> {
        #[cfg(windows)]
        {
            self.inner.remove(session_id, expected_generation)
        }
        #[cfg(not(windows))]
        {
            let _ = (session_id, expected_generation);
            Err(SessionFailure::UnknownSession)
        }
    }

    /// Ends every running session as `Revoked`. orceld calls this when the
    /// Full User lease is revoked or expires, or the runtime owner changes.
    pub fn revoke_all(&self, reason: &str) -> Vec<SessionStatus> {
        #[cfg(windows)]
        {
            self.inner.revoke_all(reason)
        }
        #[cfg(not(windows))]
        {
            let _ = reason;
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sg000096_t03_ring_offsets_are_monotonic_and_eviction_is_counted() {
        let mut ring = OutputRing::new(8);
        ring.push(b"abcdef");
        assert_eq!(ring.end_offset(), 6);
        let page = ring.read(0, 100).unwrap();
        assert_eq!(page.bytes, b"abcdef");
        assert_eq!(
            (page.offset, page.next_offset, page.evicted_before),
            (0, 6, 0)
        );
        assert!(!page.end_of_stream);

        ring.push(b"ghij");
        assert_eq!(ring.start_offset(), 2);
        assert_eq!(ring.end_offset(), 10);
        let page = ring.read(0, 100).unwrap();
        assert_eq!(page.offset, 2);
        assert_eq!(page.evicted_before, 2);
        assert_eq!(page.bytes, b"cdefghij");

        // Paging: small reads advance exactly.
        let first = ring.read(2, 3).unwrap();
        assert_eq!(first.bytes, b"cde");
        let second = ring.read(first.next_offset, 3).unwrap();
        assert_eq!(second.bytes, b"fgh");
        assert_eq!(second.offset, 5);

        // A push larger than the ring keeps only its tail.
        ring.push(b"0123456789AB");
        assert_eq!(ring.end_offset(), 22);
        assert_eq!(ring.start_offset(), 14);
        assert_eq!(ring.read(14, 100).unwrap().bytes, b"456789AB");

        assert!(matches!(
            ring.read(23, 1),
            Err(SessionFailure::OffsetBeyondEnd { end: 22 })
        ));
        let at_end = ring.read(22, 10).unwrap();
        assert!(at_end.bytes.is_empty() && !at_end.end_of_stream);
        ring.close();
        assert!(ring.read(22, 10).unwrap().end_of_stream);
        assert!(!ring.read(14, 2).unwrap().end_of_stream);
    }

    #[test]
    fn sg000096_t03_ring_holds_binary_and_split_utf8_bytes_exactly() {
        let mut ring = OutputRing::new(64);
        let text = "\u{2713}\u{65e5}".as_bytes();
        ring.push(&text[..2]);
        ring.push(&text[2..]);
        ring.push(&[0, 0xff]);
        let mut expected = text.to_vec();
        expected.extend_from_slice(&[0, 0xff]);
        assert_eq!(ring.read(0, 64).unwrap().bytes, expected);
    }

    #[test]
    fn sg000096_t03_read_size_is_bounded() {
        let mut ring = OutputRing::new(MAX_READ_BYTES * 2);
        ring.push(&vec![1u8; MAX_READ_BYTES + 10]);
        assert_eq!(
            ring.read(0, usize::MAX).unwrap().bytes.len(),
            MAX_READ_BYTES
        );
        assert_eq!(ring.read(0, 0).unwrap().bytes.len(), 1);
    }

    #[test]
    fn sg000096_t03_stdin_limits_are_bounded() {
        let ok = SessionLimits {
            stdin_frame_bytes: 4096,
            stdin_total_bytes: 1 << 20,
        };
        assert!(validate_session_limits(&ok).is_ok());
        for bad in [
            SessionLimits {
                stdin_frame_bytes: 0,
                ..ok.clone()
            },
            SessionLimits {
                stdin_frame_bytes: MAX_STDIN_FRAME_BYTES + 1,
                ..ok.clone()
            },
            SessionLimits {
                stdin_total_bytes: 0,
                ..ok.clone()
            },
            SessionLimits {
                stdin_total_bytes: MAX_STDIN_TOTAL_BYTES + 1,
                ..ok.clone()
            },
        ] {
            assert!(validate_session_limits(&bad).is_err());
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn sg000096_t03_sessions_are_unavailable_off_windows() {
        let registry = SessionRegistry::new();
        assert!(registry.list().is_empty());
        assert_eq!(
            registry.status("sh_00000000000000000000000000000000"),
            Err(SessionFailure::UnknownSession)
        );
        assert!(registry.revoke_all("test").is_empty());
    }
}
