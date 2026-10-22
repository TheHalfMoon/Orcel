//! SG-000096 T03 Windows supervision of interactive Full User sessions.
//!
//! Each session has two threads. The supervisor owns the child, its Job and
//! the output pipes: it pumps output into the rings, checks exit, deadline,
//! end requests and the runtime owner, and ends the whole Job. The writer
//! owns the stdin pipe and delivers queued frames. Registry calls only touch
//! the shared state under its lock; they never block on the child.
use super::shell::{
    end_job, launch_verified, pump, settled_remainder, Fault, OwnerProcess, PinnedLaunch,
    PumpState, READ_CHUNK_BYTES,
};
use super::{
    last_error, ChildProcess, GetExitCodeProcess, Handle, JobObject, OwnedHandle, Sleep,
    WaitForSingleObject, POST_EXIT_DRAIN_TIMEOUT_MS, POST_TERMINATION_DRAIN_TIMEOUT_MS,
    QUIESCENCE_POLL_MS, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use crate::shell::{
    CapturedStream, ExpectedNativeOwner, NativeProcessIdentity, ShellCommand, ShellFailure,
};
use crate::shell_session::{
    OutputPage, OutputRing, SessionFailure, SessionLimits, SessionState, SessionStatus, Stream,
    StreamStatus, MAX_LIVE_SESSIONS, MAX_RETAINED_SESSIONS, STDIN_PENDING_FRAMES,
};
use std::os::windows::io::AsRawHandle;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// How long `terminate` and `revoke_all` wait for the final state. The
/// supervisor needs at most the Job quiescence bound plus the drain.
const END_WAIT: Duration = Duration::from_secs(20);
/// How long an ended session's stdin writer is cancelled before it is left.
const WRITER_CANCEL_BOUND: Duration = Duration::from_secs(5);
const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;

#[link(name = "bcrypt")]
unsafe extern "system" {
    fn BCryptGenRandom(algorithm: Handle, buffer: *mut u8, length: u32, flags: u32) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn WriteFile(
        file: Handle,
        buffer: *const u8,
        length: u32,
        written: *mut u32,
        overlapped: *mut core::ffi::c_void,
    ) -> i32;
    fn CancelSynchronousIo(thread: Handle) -> i32;
}

/// Moves native handles to the one thread that uses them from then on.
struct Owned<T>(T);
// SAFETY: Windows kernel handles may be used from any thread. Each `Owned`
// value is moved whole into a single thread, which alone uses and drops it.
// The impls are limited to the two handle-owning types moved this way.
unsafe impl Send for Owned<Supervision> {}
// SAFETY: as above; the stdin write handle is moved whole to the writer.
unsafe impl Send for Owned<OwnedHandle> {}

impl<T> Owned<T> {
    /// Takes the value out. A method call moves the whole wrapper into a
    /// closure; a destructuring pattern would capture only the field.
    fn into_inner(self) -> T {
        self.0
    }
}

fn session_id() -> Result<String, ShellFailure> {
    let mut bytes = [0u8; 16];
    // SAFETY: `bytes` is a writable 16-byte buffer; a null algorithm handle
    // is valid with BCRYPT_USE_SYSTEM_PREFERRED_RNG.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status != 0 {
        return Err(ShellFailure::Unavailable(format!(
            "BCryptGenRandom failed with NTSTATUS 0x{status:08X}"
        )));
    }
    Ok(format!(
        "sh_{}",
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum EndRequest {
    Terminate,
    Revoke(String),
}

enum StdinMessage {
    Data(Vec<u8>),
    Close,
}

struct Inner {
    generation: u64,
    state: SessionState,
    stdout: OutputRing,
    stderr: OutputRing,
    stdin_accepted: u64,
    stdin_delivered: u64,
    stdin_closed: bool,
    stdin_error: Option<String>,
    end_request: Option<EndRequest>,
    descendants_terminated: bool,
    deadline: Instant,
}

struct Threads {
    supervisor: JoinHandle<()>,
    writer: JoinHandle<()>,
}

struct Session {
    id: String,
    process: NativeProcessIdentity,
    limits: SessionLimits,
    shared: Arc<Mutex<Inner>>,
    stdin: Mutex<Option<Sender<StdinMessage>>>,
    threads: Mutex<Option<Threads>>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panicking holder leaves consistent plain data; keep serving it.
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl Session {
    fn status(&self) -> SessionStatus {
        let inner = lock(&self.shared);
        SessionStatus {
            session_id: self.id.clone(),
            generation: inner.generation,
            process: self.process.clone(),
            state: inner.state.clone(),
            stdout: StreamStatus {
                start_offset: inner.stdout.start_offset(),
                end_offset: inner.stdout.end_offset(),
                closed: inner.stdout.is_closed(),
            },
            stderr: StreamStatus {
                start_offset: inner.stderr.start_offset(),
                end_offset: inner.stderr.end_offset(),
                closed: inner.stderr.is_closed(),
            },
            stdin_accepted_bytes: inner.stdin_accepted,
            stdin_delivered_bytes: inner.stdin_delivered,
            stdin_closed: inner.stdin_closed,
            stdin_error: inner.stdin_error.clone(),
            descendants_terminated: inner.descendants_terminated,
            remaining: inner.deadline.saturating_duration_since(Instant::now()),
        }
    }

    fn is_running(&self) -> bool {
        lock(&self.shared).state.is_running()
    }

    /// Checks a mutation against the live state and the approved generation.
    fn mutable<'a>(
        &'a self,
        expected_generation: u64,
    ) -> Result<MutexGuard<'a, Inner>, SessionFailure> {
        let inner = lock(&self.shared);
        if !inner.state.is_running() {
            return Err(SessionFailure::NotRunning {
                state: inner.state.label().into(),
            });
        }
        if inner.generation != expected_generation {
            return Err(SessionFailure::StaleGeneration {
                current: inner.generation,
            });
        }
        Ok(inner)
    }

    fn wait_until_ended(&self) -> Result<SessionStatus, SessionFailure> {
        let deadline = Instant::now() + END_WAIT;
        loop {
            let status = self.status();
            if !status.state.is_running() {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(SessionFailure::Shell(ShellFailure::OutcomeUnknown(
                    "an end was requested but the session has not reached a final state".into(),
                )));
            }
            std::thread::sleep(Duration::from_millis(QUIESCENCE_POLL_MS));
        }
    }

    /// Joins both threads of an ended session. A writer blocked on a pipe
    /// that something outside the Job still holds is cancelled first.
    fn finish_threads(&self) {
        let Some(threads) = lock(&self.threads).take() else {
            return;
        };
        let _ = threads.supervisor.join();
        lock(&self.stdin).take();
        // Cancel until the writer finishes: a single cancel can land between
        // its `recv` and its next `WriteFile` and have no effect. If it still
        // has not finished after the bound, it is left detached (its pipe's
        // child side is gone with the Job, so it holds no live process).
        let deadline = Instant::now() + WRITER_CANCEL_BOUND;
        while !threads.writer.is_finished() && Instant::now() < deadline {
            // SAFETY: the writer's JoinHandle is alive, so its thread handle
            // is valid; cancelling a thread with no pending I/O does nothing.
            unsafe {
                CancelSynchronousIo(threads.writer.as_raw_handle() as Handle);
            }
            std::thread::sleep(Duration::from_millis(QUIESCENCE_POLL_MS));
        }
        if threads.writer.is_finished() {
            let _ = threads.writer.join();
        }
    }
}

#[derive(Default)]
pub(crate) struct Registry {
    sessions: Mutex<Vec<Arc<Session>>>,
}

impl Drop for Registry {
    fn drop(&mut self) {
        let _ = self.revoke_all("the session registry was dropped");
        for session in lock(&self.sessions).drain(..) {
            session.finish_threads();
        }
    }
}

impl Registry {
    fn find(&self, session_id: &str) -> Result<Arc<Session>, SessionFailure> {
        lock(&self.sessions)
            .iter()
            .find(|session| session.id == session_id)
            .cloned()
            .ok_or(SessionFailure::UnknownSession)
    }

    pub(crate) fn start(
        &self,
        command: &ShellCommand,
        limits: &SessionLimits,
        expected: &ExpectedNativeOwner,
        expires_at: Instant,
    ) -> Result<SessionStatus, SessionFailure> {
        self.start_with(command, limits, expected, expires_at, Fault::None)
    }

    pub(crate) fn start_with(
        &self,
        command: &ShellCommand,
        limits: &SessionLimits,
        expected: &ExpectedNativeOwner,
        expires_at: Instant,
        fault: Fault,
    ) -> Result<SessionStatus, SessionFailure> {
        if expires_at <= Instant::now() {
            return Err(SessionFailure::Shell(ShellFailure::Denied(
                "the Full User authority for this session has already expired".into(),
            )));
        }
        let mut sessions = lock(&self.sessions);
        if sessions
            .iter()
            .filter(|session| session.is_running())
            .count()
            >= MAX_LIVE_SESSIONS
        {
            return Err(SessionFailure::RegistryFull);
        }
        if sessions.len() >= MAX_RETAINED_SESSIONS {
            let Some(oldest) = sessions.iter().position(|session| !session.is_running()) else {
                return Err(SessionFailure::RegistryFull);
            };
            sessions.remove(oldest).finish_threads();
        }
        let id = session_id()?;
        let owner = OwnerProcess::open(expected)?;
        let pinned = PinnedLaunch::open(command)?;
        let job = JobObject::kill_on_close_with_process_limit(Some(command.limits.max_processes))
            .map_err(|error| ShellFailure::Unavailable(error.message))?;
        // Eviction and the owner and pin checks take time: check the expiry
        // again immediately before creating anything.
        if expires_at <= Instant::now() {
            return Err(SessionFailure::Shell(ShellFailure::Denied(
                "the Full User authority for this session has already expired".into(),
            )));
        }
        let started = Instant::now();
        let (child, stdio, process) =
            launch_verified(command, expected, &owner, &pinned, &job, true, fault)?;
        // The child runs from here; nothing below relaunches it.
        drop(pinned);
        let deadline = (started + command.limits.timeout).min(expires_at);
        let shared = Arc::new(Mutex::new(Inner {
            generation: 1,
            state: SessionState::Running,
            stdout: OutputRing::new(command.limits.stdout_bytes),
            stderr: OutputRing::new(command.limits.stderr_bytes),
            stdin_accepted: 0,
            stdin_delivered: 0,
            stdin_closed: false,
            stdin_error: None,
            end_request: None,
            descendants_terminated: false,
            deadline,
        }));
        let super::shell::ChildStdio {
            stdout,
            stderr,
            stdin,
        } = stdio;
        let stdin = stdin.ok_or_else(|| {
            ShellFailure::Unavailable("an interactive session has no stdin pipe".into())
        });
        let (sender, receiver) = channel();
        let writer = {
            let shared = Arc::clone(&shared);
            let pipe = stdin.map(Owned);
            std::thread::Builder::new()
                .name("orcel-shell-stdin".into())
                .spawn(move || match pipe {
                    Ok(pipe) => write_stdin(pipe, receiver, &shared),
                    Err(failure) => {
                        let mut inner = lock(&shared);
                        inner.stdin_closed = true;
                        inner.stdin_error = Some(failure.message().to_owned());
                    }
                })
        };
        let supervision = Owned(Supervision {
            child,
            job,
            stdout,
            stderr,
            owner,
            expected: expected.clone(),
        });
        let supervisor = {
            let shared = Arc::clone(&shared);
            std::thread::Builder::new()
                .name("orcel-shell-supervisor".into())
                .spawn(move || {
                    let supervision = supervision.into_inner();
                    // A panic drops the supervision, and with it the
                    // kill-on-close Job, so the tree ends; the state must not
                    // stay `Running`.
                    let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        supervision.run(&shared);
                    }));
                    if run.is_err() {
                        let mut inner = lock(&shared);
                        if inner.state.is_running() {
                            inner.state = SessionState::OutcomeUnknown {
                                reason: "the session supervisor failed; its Job was closed".into(),
                            };
                        }
                    }
                })
        };
        let (supervisor, writer) = match (supervisor, writer) {
            (Ok(supervisor), Ok(writer)) => (supervisor, writer),
            (supervisor, writer) => {
                // A thread could not start. The supervision value (and with
                // it the child and its kill-on-close Job) was dropped with
                // the failed closure, or ends once the supervisor sees this.
                lock(&shared).end_request = Some(EndRequest::Revoke(
                    "a session thread could not be started".into(),
                ));
                if let Ok(handle) = supervisor {
                    let _ = handle.join();
                }
                drop(sender);
                if let Ok(handle) = writer {
                    let _ = handle.join();
                }
                return Err(SessionFailure::Shell(ShellFailure::OutcomeUnknown(
                    "the session started but could not be supervised; it was ended".into(),
                )));
            }
        };
        let session = Arc::new(Session {
            id,
            process,
            limits: limits.clone(),
            shared,
            stdin: Mutex::new(Some(sender)),
            threads: Mutex::new(Some(Threads { supervisor, writer })),
        });
        let status = session.status();
        sessions.push(session);
        Ok(status)
    }

    pub(crate) fn status(&self, session_id: &str) -> Result<SessionStatus, SessionFailure> {
        Ok(self.find(session_id)?.status())
    }

    pub(crate) fn list(&self) -> Vec<SessionStatus> {
        lock(&self.sessions)
            .iter()
            .map(|session| session.status())
            .collect()
    }

    pub(crate) fn read(
        &self,
        session_id: &str,
        stream: Stream,
        from: u64,
        max: usize,
    ) -> Result<OutputPage, SessionFailure> {
        let session = self.find(session_id)?;
        let inner = lock(&session.shared);
        match stream {
            Stream::Stdout => inner.stdout.read(from, max),
            Stream::Stderr => inner.stderr.read(from, max),
        }
    }

    pub(crate) fn write_stdin(
        &self,
        session_id: &str,
        expected_generation: u64,
        bytes: &[u8],
    ) -> Result<SessionStatus, SessionFailure> {
        let session = self.find(session_id)?;
        let limits = &session.limits;
        {
            let mut inner = session.mutable(expected_generation)?;
            if inner.stdin_closed || inner.stdin_error.is_some() {
                return Err(SessionFailure::InputClosed);
            }
            if bytes.is_empty() || bytes.len() > limits.stdin_frame_bytes {
                return Err(SessionFailure::InputLimit);
            }
            let total = inner.stdin_accepted.saturating_add(bytes.len() as u64);
            if total > limits.stdin_total_bytes {
                return Err(SessionFailure::InputLimit);
            }
            let pending = inner.stdin_accepted - inner.stdin_delivered;
            let pending_cap = (limits.stdin_frame_bytes * STDIN_PENDING_FRAMES) as u64;
            if pending + bytes.len() as u64 > pending_cap {
                return Err(SessionFailure::InputBusy);
            }
            let sender = lock(&session.stdin);
            let sent = sender
                .as_ref()
                .map(|sender| sender.send(StdinMessage::Data(bytes.to_vec())).is_ok())
                .unwrap_or(false);
            if !sent {
                return Err(SessionFailure::InputClosed);
            }
            inner.stdin_accepted = total;
            inner.generation += 1;
        }
        Ok(session.status())
    }

    pub(crate) fn close_stdin(
        &self,
        session_id: &str,
        expected_generation: u64,
    ) -> Result<SessionStatus, SessionFailure> {
        let session = self.find(session_id)?;
        {
            let mut inner = session.mutable(expected_generation)?;
            if inner.stdin_closed {
                return Err(SessionFailure::InputClosed);
            }
            if let Some(sender) = lock(&session.stdin).as_ref() {
                // The writer closes the pipe after delivering what came before.
                let _ = sender.send(StdinMessage::Close);
            }
            inner.stdin_closed = true;
            inner.generation += 1;
        }
        Ok(session.status())
    }

    pub(crate) fn terminate(
        &self,
        session_id: &str,
        expected_generation: u64,
    ) -> Result<SessionStatus, SessionFailure> {
        let session = self.find(session_id)?;
        {
            let mut inner = session.mutable(expected_generation)?;
            inner.end_request = Some(EndRequest::Terminate);
            inner.generation += 1;
        }
        session.wait_until_ended()
    }

    pub(crate) fn remove(
        &self,
        session_id: &str,
        expected_generation: u64,
    ) -> Result<SessionStatus, SessionFailure> {
        let session = self.find(session_id)?;
        let status = session.status();
        if status.state.is_running() {
            return Err(SessionFailure::NotRunning {
                state: "running; terminate it first".into(),
            });
        }
        if status.generation != expected_generation {
            return Err(SessionFailure::StaleGeneration {
                current: status.generation,
            });
        }
        session.finish_threads();
        lock(&self.sessions).retain(|candidate| candidate.id != session_id);
        Ok(status)
    }

    pub(crate) fn revoke_all(&self, reason: &str) -> Vec<SessionStatus> {
        let sessions: Vec<Arc<Session>> = lock(&self.sessions).clone();
        let mut revoked = Vec::new();
        for session in &sessions {
            let mut inner = lock(&session.shared);
            if inner.state.is_running() {
                inner.end_request = Some(EndRequest::Revoke(reason.to_owned()));
                inner.generation += 1;
                revoked.push(Arc::clone(session));
            }
        }
        revoked
            .iter()
            .map(|session| {
                session
                    .wait_until_ended()
                    .unwrap_or_else(|_| session.status())
            })
            .collect()
    }
}

/// Delivers queued stdin frames in order. A write is counted as delivered
/// only after the pipe took all of it; on any failure stdin is marked failed
/// and nothing further is written.
fn write_stdin(pipe: Owned<OwnedHandle>, receiver: Receiver<StdinMessage>, shared: &Mutex<Inner>) {
    let pipe = pipe.into_inner();
    while let Ok(message) = receiver.recv() {
        let bytes = match message {
            StdinMessage::Data(bytes) => bytes,
            StdinMessage::Close => break,
        };
        let mut offset = 0usize;
        while offset < bytes.len() {
            let mut written = 0u32;
            let chunk = &bytes[offset..];
            // SAFETY: `chunk` is valid for `chunk.len()` bytes and the pipe
            // handle is owned by this thread; the write is synchronous.
            let ok = unsafe {
                WriteFile(
                    pipe.raw(),
                    chunk.as_ptr(),
                    chunk.len().min(u32::MAX as usize) as u32,
                    &mut written,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 || written == 0 {
                let error = last_error("WriteFile(stdin)").message;
                let mut inner = lock(shared);
                inner.stdin_delivered += offset as u64;
                inner.stdin_error = Some(format!(
                    "{error}; {} of {} bytes of this frame were delivered",
                    offset,
                    bytes.len()
                ));
                inner.stdin_closed = true;
                return;
            }
            offset += written as usize;
        }
        lock(shared).stdin_delivered += bytes.len() as u64;
    }
    // Dropping the handle here closes the pipe: the child sees end of input.
}

struct Supervision {
    child: ChildProcess,
    job: JobObject,
    stdout: super::PrivatePipe,
    stderr: super::PrivatePipe,
    owner: OwnerProcess,
    expected: ExpectedNativeOwner,
}

enum Ending {
    Exited(u32),
    TimedOut,
    Terminated,
    Revoked(String),
    Unknown(String),
}

impl Supervision {
    fn run(mut self, shared: &Mutex<Inner>) {
        let mut scratch = vec![0u8; READ_CHUNK_BYTES];
        let mut closed = (false, false);
        let ending = loop {
            if let Err(reason) = self.pump_once(shared, &mut scratch, &mut closed) {
                break Ending::Unknown(reason);
            }
            let (request, deadline) = {
                let inner = lock(shared);
                (inner.end_request.clone(), inner.deadline)
            };
            match request {
                Some(EndRequest::Terminate) => break Ending::Terminated,
                Some(EndRequest::Revoke(reason)) => break Ending::Revoked(reason),
                None => {}
            }
            if let Err(failure) = self.owner.check_live(&self.expected) {
                break Ending::Revoked(failure.message().to_owned());
            }
            // SAFETY: the process handle is owned by `self.child`.
            match unsafe { WaitForSingleObject(self.child.process.raw(), 0) } {
                WAIT_OBJECT_0 => {
                    let mut exit_code = 0u32;
                    // SAFETY: `exit_code` is a valid out-pointer.
                    if unsafe { GetExitCodeProcess(self.child.process.raw(), &mut exit_code) } == 0
                    {
                        break Ending::Unknown(last_error("GetExitCodeProcess").message);
                    }
                    self.child.completed = true;
                    break Ending::Exited(exit_code);
                }
                WAIT_TIMEOUT => {}
                _ => {
                    break Ending::Unknown(last_error("WaitForSingleObject(session)").message);
                }
            }
            if Instant::now() >= deadline {
                break Ending::TimedOut;
            }
            // SAFETY: Sleep takes no pointers.
            unsafe { Sleep(QUIESCENCE_POLL_MS as u32) };
        };

        let mut descendants = false;
        let ended = match &ending {
            Ending::Exited(_) => {
                self.drain(
                    shared,
                    &mut scratch,
                    &mut closed,
                    POST_EXIT_DRAIN_TIMEOUT_MS,
                );
                match settled_remainder(&self.job) {
                    Ok(0) if closed.0 && closed.1 => Ok(()),
                    Ok(count) => {
                        descendants = count > 0;
                        end_job(&self.job)
                    }
                    Err(_) => {
                        // Unknown whether anything was left; it is ended.
                        descendants = true;
                        end_job(&self.job)
                    }
                }
            }
            _ => {
                descendants = true;
                end_job(&self.job)
            }
        };
        if ended.is_ok() {
            self.child.completed = true;
        }
        self.drain(
            shared,
            &mut scratch,
            &mut closed,
            POST_TERMINATION_DRAIN_TIMEOUT_MS,
        );
        let mut inner = lock(shared);
        inner.descendants_terminated = descendants;
        inner.state = match (ended, ending) {
            (Err(_), _) => SessionState::TerminationUnverified,
            (Ok(()), Ending::Exited(exit_code)) => SessionState::Exited { exit_code },
            (Ok(()), Ending::TimedOut) => SessionState::TimedOut,
            (Ok(()), Ending::Terminated) => SessionState::Terminated,
            (Ok(()), Ending::Revoked(reason)) => SessionState::Revoked { reason },
            (Ok(()), Ending::Unknown(reason)) => SessionState::OutcomeUnknown { reason },
        };
    }

    /// One bounded pump of each stream into its ring.
    fn pump_once(
        &self,
        shared: &Mutex<Inner>,
        scratch: &mut [u8],
        closed: &mut (bool, bool),
    ) -> Result<(), String> {
        for (index, pipe) in [&self.stdout, &self.stderr].into_iter().enumerate() {
            let is_closed = if index == 0 { closed.0 } else { closed.1 };
            if is_closed {
                continue;
            }
            let mut chunk = CapturedStream::default();
            let state = pump(pipe, &mut chunk, usize::MAX, scratch)?;
            let mut inner = lock(shared);
            let ring = if index == 0 {
                &mut inner.stdout
            } else {
                &mut inner.stderr
            };
            ring.push(&chunk.bytes);
            if let PumpState::Closed = state {
                ring.close();
                if index == 0 {
                    closed.0 = true;
                } else {
                    closed.1 = true;
                }
            }
        }
        Ok(())
    }

    fn drain(
        &self,
        shared: &Mutex<Inner>,
        scratch: &mut [u8],
        closed: &mut (bool, bool),
        budget_ms: u64,
    ) {
        let deadline = Instant::now() + Duration::from_millis(budget_ms);
        while !(closed.0 && closed.1) && Instant::now() < deadline {
            if self.pump_once(shared, scratch, closed).is_err() {
                return;
            }
            // SAFETY: Sleep takes no pointers.
            unsafe { Sleep(QUIESCENCE_POLL_MS as u32) };
        }
    }
}

#[cfg(test)]
#[path = "shell_session_tests.rs"]
mod tests;
