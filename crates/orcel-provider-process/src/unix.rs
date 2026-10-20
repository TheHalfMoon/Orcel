//! XP-13b: the Safe tier for registered executables on Linux and macOS.
//!
//! This is the Unix counterpart of the Windows Job Object launch in `lib.rs`:
//! the same plan, the same output bounds and the same typed failures, with
//! the process tree owned and cleaned up. It is not the contained tier
//! (`contained.rs`): a registered executable may fork, so there is no
//! Landlock, seccomp or Seatbelt here.
//!
//! - **Process group.** The child is the leader of a new process group, set
//!   before `exec`. The leader is never reaped until the whole group has been
//!   sent `SIGKILL` and every member has been seen dead, so the group id
//!   cannot be reused while it is being killed.
//! - **cgroup v2, when delegated (Linux).** If this process's own cgroup is
//!   delegated to it (systemd `Delegate=yes`), the child joins a fresh child
//!   cgroup before `exec`. A descendant that leaves the process group
//!   (`setsid`, `setpgid`) stays in the cgroup, and `cgroup.kill` ends it. A
//!   cgroup that was chosen and then cannot be joined fails the launch.
//! - **Exit notification.** A pidfd (Linux 5.3 or later; without it the
//!   launch is refused) or a kqueue `EVFILT_PROC`/`NOTE_EXIT` (macOS) wakes
//!   the loop when the leader exits, without reaping it.
//! - **Parent death (Linux).** `PR_SET_PDEATHSIG(SIGKILL)` is set before
//!   `exec`, and the child refuses to continue if its parent already changed.
//! - **rlimits.** No core dumps; CPU time is capped just above the timeout.
//! - **Exact executable.** The file is refused when another local user could
//!   replace it (it or an ancestor directory is group- or world-writable, or
//!   owned by someone other than the user or root; root's sticky `/tmp` is
//!   the one exception). It is opened once and, when the plan carries the
//!   registered digest, hashed through that descriptor. Linux then executes
//!   that same descriptor (`/proc/self/fd/N`). macOS has no `fexecve`, so it
//!   re-reads the path's device, inode, size, mode and modification time
//!   immediately before launch and refuses any difference from the open
//!   file; a swap inside that last window is the remaining macOS residual.
//! - **Descriptors.** Every descriptor above stderr is marked close-on-exec
//!   in the child before `exec` (`close_range(CLOSE_RANGE_CLOEXEC)` on Linux,
//!   `fcntl` on each otherwise), so nothing of orceld's leaks into it.
//! - **Cleanup.** After the leader exits, after a timeout or an output limit,
//!   and on drop, the whole tree is sent `SIGKILL` and must be seen gone
//!   within five seconds, or the run is `TerminationUnverified`.
//!
//! Residual risks (documented, not closed here):
//! - The cgroup is best effort against a cooperative child: a delegated
//!   subtree belongs to the user, so a child running as the user can move
//!   itself to another cgroup in it before `cgroup.kill`.
//! - Without a delegated cgroup, a descendant that calls `setsid` or
//!   `setpgid` leaves the process group and outlives the run. Under the
//!   packaged `orceld@.service` the unit's own cgroup and
//!   `KillMode=control-group` still end it when orceld stops. macOS has no
//!   equivalent: such a descendant survives.
//! - If orceld is killed hard on macOS, the child is not signalled (there is
//!   no `PR_SET_PDEATHSIG`); it keeps running until it exits. On Linux only
//!   the leader receives the signal; the rest of the group survives unless a
//!   cgroup or the systemd unit ends it.
//! - The child runs with the user's own authority, like the Windows Safe
//!   tier's executable outside its AppContainer grants: the registered
//!   executable, its argv grammar and its digest are the boundary.

#![deny(clippy::undocumented_unsafe_blocks)]

#[cfg(target_os = "linux")]
use std::ffi::c_long;
use std::ffi::{c_int, c_void};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, ChildStderr, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use super::{ExecutionPlan, OutputStream, PrivateExecutionFailure, PrivateExecutionResult};

const SIGKILL: c_int = 9;
const ESRCH: i32 = 3;
const POLLIN: i16 = 0x1;
const POLLERR: i16 = 0x8;
const POLLHUP: i16 = 0x10;
const POLLNVAL: i16 = 0x20;
const RLIMIT_CPU: c_int = 0;
const RLIMIT_CORE: c_int = 4;
const RLIM_INFINITY: u64 = u64::MAX;

const POLL_SLICE_MS: u64 = 50;
const QUIESCENCE_POLL_MS: u64 = 10;
const QUIESCENCE_TIMEOUT_MS: u64 = 5_000;
const POST_EXIT_DRAIN_TIMEOUT_MS: u64 = 500;
const POST_TERMINATION_DRAIN_TIMEOUT_MS: u64 = 1_000;
const READ_CHUNK: usize = 64 * 1024;

#[repr(C)]
struct PollFd {
    fd: c_int,
    events: i16,
    revents: i16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Rlimit {
    current: u64,
    maximum: u64,
}

/// `nfds_t`.
#[cfg(target_os = "linux")]
type PollCount = std::ffi::c_ulong;
#[cfg(target_os = "macos")]
type PollCount = std::ffi::c_uint;

const F_SETFD: c_int = 2;
const FD_CLOEXEC: c_int = 1;
#[cfg(target_os = "linux")]
const RLIMIT_NOFILE: c_int = 7;
#[cfg(target_os = "macos")]
const RLIMIT_NOFILE: c_int = 8;
/// Descriptors above this are not walked one by one (the limit can be huge).
const MAX_DESCRIPTOR_WALK: u64 = 65_536;
/// The registry's own size bound for a registered executable.
const MAX_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;

extern "C" {
    fn poll(fds: *mut PollFd, count: PollCount, timeout_ms: c_int) -> c_int;
    fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
    fn geteuid() -> u32;
    fn kill(pid: c_int, signal: c_int) -> c_int;
    fn getppid() -> c_int;
    fn getrlimit(resource: c_int, limit: *mut Rlimit) -> c_int;
    fn setrlimit(resource: c_int, limit: *const Rlimit) -> c_int;
}

#[cfg(target_os = "linux")]
extern "C" {
    fn syscall(number: c_long, ...) -> c_long;
    fn prctl(option: c_int, ...) -> c_int;
    fn write(fd: c_int, buffer: *const c_void, count: usize) -> isize;
}

#[cfg(target_os = "linux")]
const SYS_PIDFD_OPEN: c_long = 434;
#[cfg(target_os = "linux")]
const SYS_CLOSE_RANGE: c_long = 436;
#[cfg(target_os = "linux")]
const CLOSE_RANGE_CLOEXEC: std::ffi::c_uint = 1 << 2;
#[cfg(target_os = "linux")]
const PR_SET_PDEATHSIG: c_int = 1;

/// How the tree was owned, for the tests (and the provider's own evidence).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TreeOwnership {
    ProcessGroup,
    ProcessGroupAndCgroup,
}

pub(crate) fn execute(
    plan: ExecutionPlan,
) -> Result<PrivateExecutionResult, PrivateExecutionFailure> {
    execute_reporting(plan).map(|(result, _)| result)
}

pub(crate) fn execute_reporting(
    plan: ExecutionPlan,
) -> Result<(PrivateExecutionResult, TreeOwnership), PrivateExecutionFailure> {
    plan.limits
        .validate()
        .map_err(|error| PrivateExecutionFailure::InvalidPlan(error.message))?;
    let mut tree = ProcessTree::spawn(&plan)?;
    let ownership = tree.ownership();
    let result = tree.run(&plan)?;
    Ok((result, ownership))
}

enum Event {
    Timeout,
    OutputLimit(OutputStream),
}

fn classify(event: Event, verified: bool) -> PrivateExecutionFailure {
    if !verified {
        return PrivateExecutionFailure::TerminationUnverified;
    }
    match event {
        Event::Timeout => PrivateExecutionFailure::ProcessTimeout,
        Event::OutputLimit(stream) => PrivateExecutionFailure::OutputLimit(stream),
    }
}

/// The child, its process group, its optional cgroup and its exit watcher.
/// Dropping it kills the tree and reaps the leader.
struct ProcessTree {
    child: Option<Child>,
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
    pgid: c_int,
    exit_watch: OwnedFd,
    cgroup: Option<cgroup::Cgroup>,
}

impl ProcessTree {
    fn spawn(plan: &ExecutionPlan) -> Result<Self, PrivateExecutionFailure> {
        let provider = |message: String| PrivateExecutionFailure::Provider(message);
        let cgroup = cgroup::Cgroup::create_if_delegated().map_err(provider)?;
        let cgroup_procs: Option<RawFd> = cgroup.as_ref().map(cgroup::Cgroup::procs_fd);
        let limits = child_rlimits(plan.limits.timeout).map_err(provider)?;
        let descriptors = descriptor_walk_limit();
        let parent = std::process::id() as c_int;
        // Held open until spawn returns: on Linux the child executes it.
        let executable = open_verified_executable(plan)?;

        let mut command = launch_command(plan, &executable)?;
        command
            .args(&plan.argv)
            .env_clear()
            .envs(&plan.env)
            .current_dir(&plan.cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let prepare = move || prepare_child(parent, cgroup_procs, &limits, descriptors);
        // SAFETY: `prepare_child` runs in the forked child before exec and only makes
        // async-signal-safe calls (prctl, getppid, write, setrlimit, close_range, fcntl) on values
        // captured by copy; it allocates nothing and takes no lock.
        unsafe {
            command.pre_exec(prepare);
        }
        let mut child = command
            .spawn()
            .map_err(|error| provider(format!("process spawn failed: {error}")))?;
        drop(executable);
        let pgid = child.id() as c_int;
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let exit_watch = match watch_exit(pgid) {
            Ok(watch) => watch,
            Err(message) => {
                kill_group(pgid);
                if let Some(cgroup) = &cgroup {
                    cgroup.kill();
                }
                let _ = child.wait();
                return Err(provider(message));
            }
        };
        Ok(Self {
            child: Some(child),
            stdout,
            stderr,
            pgid,
            exit_watch,
            cgroup,
        })
    }

    fn ownership(&self) -> TreeOwnership {
        if self.cgroup.is_some() {
            TreeOwnership::ProcessGroupAndCgroup
        } else {
            TreeOwnership::ProcessGroup
        }
    }

    fn run(
        &mut self,
        plan: &ExecutionPlan,
    ) -> Result<PrivateExecutionResult, PrivateExecutionFailure> {
        let limits = &plan.limits;
        let started = Instant::now();
        let mut output = Output::default();
        let mut exited = false;
        while !exited {
            let Some(remaining) = limits.timeout.checked_sub(started.elapsed()) else {
                return Err(self.terminate(Event::Timeout));
            };
            let slice = remaining.min(Duration::from_millis(POLL_SLICE_MS));
            let ready = self.wait_ready(slice, true)?;
            if let Some(stream) = self.read_ready(&ready, &mut output, plan)? {
                return Err(self.terminate(Event::OutputLimit(stream)));
            }
            exited = ready.exit;
        }

        // The leader has exited and is not reaped. Collect what it and any
        // descendant still holding its pipes wrote, for a bounded time.
        match self.drain(&mut output, plan, POST_EXIT_DRAIN_TIMEOUT_MS)? {
            Drain::Complete => {}
            Drain::OutputLimit(stream) => return Err(self.terminate(Event::OutputLimit(stream))),
            Drain::Deadline => {
                // A descendant kept the pipes open: end the tree, then read
                // what is left in them.
                if !self.kill_and_verify() {
                    return Err(PrivateExecutionFailure::TerminationUnverified);
                }
                match self.drain(&mut output, plan, POST_TERMINATION_DRAIN_TIMEOUT_MS)? {
                    Drain::Complete => {}
                    Drain::OutputLimit(stream) => {
                        return Err(classify(Event::OutputLimit(stream), true))
                    }
                    Drain::Deadline => return Err(PrivateExecutionFailure::TerminationUnverified),
                }
            }
        }
        // Owned cleanup: nothing the run started outlives it.
        if !self.kill_and_verify() {
            return Err(PrivateExecutionFailure::TerminationUnverified);
        }
        let status = self.reap()?;
        let exit_code = match (status.code(), status.signal()) {
            (Some(code), _) => code as u32,
            (None, Some(signal)) => 128 + signal as u32,
            (None, None) => u32::MAX,
        };
        Ok(PrivateExecutionResult {
            exit_code,
            stdout: output.stdout,
            stderr: output.stderr,
            appcontainer_verified: false,
            assigned_to_job_before_resume: true,
            job_quiescent: true,
        })
    }

    fn terminate(&mut self, event: Event) -> PrivateExecutionFailure {
        let verified = self.kill_and_verify();
        classify(event, verified)
    }

    /// Wait at most `timeout` for a pipe to become readable or (when
    /// `watch_exit` is set) the leader to exit.
    fn wait_ready(
        &self,
        timeout: Duration,
        watch_exit: bool,
    ) -> Result<Ready, PrivateExecutionFailure> {
        let fd_of = |pipe: Option<RawFd>| pipe.unwrap_or(-1);
        let mut fds = [
            PollFd {
                fd: fd_of(self.stdout.as_ref().map(AsRawFd::as_raw_fd)),
                events: POLLIN,
                revents: 0,
            },
            PollFd {
                fd: fd_of(self.stderr.as_ref().map(AsRawFd::as_raw_fd)),
                events: POLLIN,
                revents: 0,
            },
            PollFd {
                fd: if watch_exit {
                    self.exit_watch.as_raw_fd()
                } else {
                    -1
                },
                events: POLLIN,
                revents: 0,
            },
        ];
        let timeout_ms = timeout.as_millis().min(c_int::MAX as u128) as c_int;
        // SAFETY: `fds` is a live array of three pollfd structs and its length is passed with
        // it; negative descriptors are ignored by poll.
        let ready = unsafe { poll(fds.as_mut_ptr(), fds.len() as PollCount, timeout_ms) };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(PrivateExecutionFailure::Provider(format!(
                    "poll failed: {error}"
                )));
            }
            return Ok(Ready::default());
        }
        let hit = |entry: &PollFd| {
            entry.fd >= 0 && entry.revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL) != 0
        };
        Ok(Ready {
            stdout: hit(&fds[0]),
            stderr: hit(&fds[1]),
            exit: hit(&fds[2]),
        })
    }

    /// Read once from each ready pipe (a single read after readiness never
    /// blocks). Returns the stream whose bound was crossed, if any.
    fn read_ready(
        &mut self,
        ready: &Ready,
        output: &mut Output,
        plan: &ExecutionPlan,
    ) -> Result<Option<OutputStream>, PrivateExecutionFailure> {
        if ready.stdout
            && read_once(
                &mut self.stdout,
                &mut output.stdout,
                plan.limits.stdout_bytes,
            )?
        {
            return Ok(Some(OutputStream::Stdout));
        }
        if ready.stderr
            && read_once(
                &mut self.stderr,
                &mut output.stderr,
                plan.limits.stderr_bytes,
            )?
        {
            return Ok(Some(OutputStream::Stderr));
        }
        Ok(None)
    }

    fn drain(
        &mut self,
        output: &mut Output,
        plan: &ExecutionPlan,
        budget_ms: u64,
    ) -> Result<Drain, PrivateExecutionFailure> {
        let deadline = Instant::now() + Duration::from_millis(budget_ms);
        loop {
            if self.stdout.is_none() && self.stderr.is_none() {
                return Ok(Drain::Complete);
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Ok(Drain::Deadline);
            };
            let ready =
                self.wait_ready(remaining.min(Duration::from_millis(POLL_SLICE_MS)), false)?;
            if let Some(stream) = self.read_ready(&ready, output, plan)? {
                return Ok(Drain::OutputLimit(stream));
            }
        }
    }

    /// Send `SIGKILL` to the whole tree and wait until no member is alive.
    /// The signal is repeated on every poll, so a member forked while the
    /// first one was in flight is caught too.
    fn kill_and_verify(&self) -> bool {
        let deadline = Instant::now() + Duration::from_millis(QUIESCENCE_TIMEOUT_MS);
        loop {
            if let Some(cgroup) = &self.cgroup {
                cgroup.kill();
            }
            kill_group(self.pgid);
            let cgroup_empty = self.cgroup.as_ref().is_none_or(cgroup::Cgroup::is_empty);
            if cgroup_empty && group_is_dead(self.pgid) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(QUIESCENCE_POLL_MS));
        }
    }

    fn reap(&mut self) -> Result<std::process::ExitStatus, PrivateExecutionFailure> {
        let mut child = self
            .child
            .take()
            .ok_or_else(|| PrivateExecutionFailure::Provider("process already reaped".into()))?;
        child.wait().map_err(|error| {
            PrivateExecutionFailure::Provider(format!("process wait failed: {error}"))
        })
    }
}

impl Drop for ProcessTree {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            // The leader is still unreaped here, so the group id is still
            // ours to signal.
            let _ = self.kill_and_verify();
            let _ = child.wait();
        }
        if let Some(cgroup) = self.cgroup.take() {
            cgroup.remove();
        }
    }
}

#[derive(Default)]
struct Ready {
    stdout: bool,
    stderr: bool,
    exit: bool,
}

#[derive(Default)]
struct Output {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

enum Drain {
    Complete,
    OutputLimit(OutputStream),
    Deadline,
}

/// One read from a ready pipe: appends within the bound, or drops the pipe
/// at end of file. Returns true when the bound was crossed.
fn read_once(
    pipe: &mut Option<impl Read>,
    buffer: &mut Vec<u8>,
    limit: usize,
) -> Result<bool, PrivateExecutionFailure> {
    let Some(reader) = pipe.as_mut() else {
        return Ok(false);
    };
    let mut chunk = vec![0_u8; READ_CHUNK];
    match reader.read(&mut chunk) {
        Ok(0) => {
            *pipe = None;
            Ok(false)
        }
        Ok(read) if buffer.len() + read > limit => Ok(true),
        Ok(read) => {
            buffer.extend_from_slice(&chunk[..read]);
            Ok(false)
        }
        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => Ok(false),
        Err(error) => Err(PrivateExecutionFailure::Provider(format!(
            "process output read failed: {error}"
        ))),
    }
}

/// Limits applied in the child before exec: no core file, and a CPU-time
/// ceiling one second above the wall-clock timeout (`SIGXCPU`, then
/// `SIGKILL` a second later). Neither is ever raised above the current hard
/// limit.
fn child_rlimits(timeout: Duration) -> Result<[(c_int, Rlimit); 2], String> {
    let current = |resource: c_int| -> Result<Rlimit, String> {
        let mut limit = Rlimit {
            current: 0,
            maximum: 0,
        };
        // SAFETY: `limit` is a live, writable rlimit struct of the platform's 64-bit layout.
        if unsafe { getrlimit(resource, &mut limit) } != 0 {
            return Err(format!(
                "getrlimit failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(limit)
    };
    let lowered = |hard: u64, wanted: u64| {
        if hard == RLIM_INFINITY {
            wanted
        } else {
            hard.min(wanted)
        }
    };
    let cpu = current(RLIMIT_CPU)?;
    let soft = timeout.as_secs().saturating_add(1);
    let cpu_hard = lowered(cpu.maximum, soft.saturating_add(1));
    Ok([
        (
            RLIMIT_CORE,
            Rlimit {
                current: 0,
                maximum: 0,
            },
        ),
        (
            RLIMIT_CPU,
            Rlimit {
                current: soft.min(cpu_hard),
                maximum: cpu_hard,
            },
        ),
    ])
}

/// Refuse an executable another local user could replace, open it, and
/// check the open file against the registered digest. See the module header.
fn open_verified_executable(
    plan: &ExecutionPlan,
) -> Result<std::fs::File, PrivateExecutionFailure> {
    use std::os::unix::fs::MetadataExt;
    check_owned_location(&plan.executable).map_err(PrivateExecutionFailure::ExecutableRejected)?;
    let file = std::fs::File::open(&plan.executable).map_err(|error| {
        PrivateExecutionFailure::Provider(format!("the executable cannot be opened: {error}"))
    })?;
    let metadata = file.metadata().map_err(|error| {
        PrivateExecutionFailure::Provider(format!("the executable cannot be inspected: {error}"))
    })?;
    if !metadata.is_file() || metadata.mode() & 0o022 != 0 {
        return Err(PrivateExecutionFailure::IdentityChanged);
    }
    if let Some(expected) = &plan.registered_sha256 {
        if metadata.len() > MAX_EXECUTABLE_BYTES {
            return Err(PrivateExecutionFailure::IdentityChanged);
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        (&file).read_to_end(&mut bytes).map_err(|error| {
            PrivateExecutionFailure::Provider(format!("the executable cannot be read: {error}"))
        })?;
        if crate::contained::sha256_hex(&bytes) != *expected {
            return Err(PrivateExecutionFailure::IdentityChanged);
        }
    }
    Ok(file)
}

/// Linux: execute the open, checked file itself.
#[cfg(target_os = "linux")]
fn launch_command(
    plan: &ExecutionPlan,
    executable: &std::fs::File,
) -> Result<Command, PrivateExecutionFailure> {
    let mut command = Command::new(format!("/proc/self/fd/{}", executable.as_raw_fd()));
    command.arg0(&plan.executable);
    Ok(command)
}

/// macOS: no `fexecve`; the path must still name the open, checked file.
#[cfg(target_os = "macos")]
fn launch_command(
    plan: &ExecutionPlan,
    executable: &std::fs::File,
) -> Result<Command, PrivateExecutionFailure> {
    use std::os::unix::fs::MetadataExt;
    let open = executable
        .metadata()
        .map_err(|_| PrivateExecutionFailure::IdentityChanged)?;
    let named = std::fs::symlink_metadata(&plan.executable)
        .map_err(|_| PrivateExecutionFailure::IdentityChanged)?;
    let identity = |m: &std::fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.size(),
            m.mode(),
            m.mtime(),
            m.mtime_nsec(),
        )
    };
    if identity(&open) != identity(&named) {
        return Err(PrivateExecutionFailure::IdentityChanged);
    }
    Ok(Command::new(&plan.executable))
}

/// The same rule as `orcel_platform::paths::check_owned_executable_location`
/// (this crate takes no dependency): the file and every ancestor owned by
/// the user or root and not group- or world-writable, except a root-owned
/// sticky directory.
fn check_owned_location(path: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid takes no arguments and cannot fail.
    let uid = unsafe { geteuid() };
    let trusted = |metadata: &std::fs::Metadata| metadata.uid() == uid || metadata.uid() == 0;
    let file = std::fs::symlink_metadata(path)
        .map_err(|error| format!("{} cannot be inspected: {error}", path.display()))?;
    if !file.file_type().is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    if !trusted(&file) || file.mode() & 0o022 != 0 {
        return Err(format!(
            "{} could be replaced by another user (owner or mode)",
            path.display()
        ));
    }
    for ancestor in path.ancestors().skip(1) {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        let directory = std::fs::metadata(ancestor)
            .map_err(|error| format!("{} cannot be inspected: {error}", ancestor.display()))?;
        let shared_sticky = directory.mode() & 0o1000 != 0 && directory.uid() == 0;
        if !trusted(&directory) || (directory.mode() & 0o022 != 0 && !shared_sticky) {
            return Err(format!(
                "{} could be changed by another user (owner or mode)",
                ancestor.display()
            ));
        }
    }
    Ok(())
}

/// How many descriptors the child walks when `close_range` is unavailable.
fn descriptor_walk_limit() -> c_int {
    let mut limit = Rlimit {
        current: 0,
        maximum: 0,
    };
    // SAFETY: `limit` is a live, writable rlimit struct of the platform's 64-bit layout.
    let known = unsafe { getrlimit(RLIMIT_NOFILE, &mut limit) } == 0;
    let count = if known {
        limit.current
    } else {
        MAX_DESCRIPTOR_WALK
    };
    count.min(MAX_DESCRIPTOR_WALK) as c_int
}

/// Mark every descriptor above stderr close-on-exec. Runs in the child.
fn close_inherited_descriptors(walk_limit: c_int) {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: close_range(first, last, flags) takes three integers; with
        // CLOSE_RANGE_CLOEXEC it only sets a flag on each open descriptor.
        let marked = unsafe {
            syscall(
                SYS_CLOSE_RANGE,
                3 as std::ffi::c_uint,
                std::ffi::c_uint::MAX,
                CLOSE_RANGE_CLOEXEC,
            )
        };
        if marked == 0 {
            return;
        }
    }
    for fd in 3..walk_limit {
        // SAFETY: fcntl(F_SETFD) on a descriptor number only changes that descriptor's flag,
        // or fails with EBADF when it is not open.
        unsafe { fcntl(fd, F_SETFD, FD_CLOEXEC) };
    }
}

/// Runs in the forked child, before exec. Only async-signal-safe calls.
fn prepare_child(
    parent: c_int,
    cgroup_procs: Option<RawFd>,
    limits: &[(c_int, Rlimit); 2],
    descriptor_walk_limit: c_int,
) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: prctl(PR_SET_PDEATHSIG, signal) takes one integer argument and touches no
        // memory.
        if unsafe { prctl(PR_SET_PDEATHSIG, SIGKILL as std::ffi::c_ulong) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if let Some(procs) = cgroup_procs {
            // Writing "0" moves the writing process, this child, into the cgroup.
            // SAFETY: the buffer is a static one-byte slice and `procs` is a descriptor the
            // parent opened for writing and keeps open across the fork.
            if unsafe { write(procs, b"0".as_ptr().cast(), 1) } != 1 {
                return Err(std::io::Error::last_os_error());
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = cgroup_procs;
    // SAFETY: getppid has no arguments and cannot fail.
    if unsafe { getppid() } != parent {
        // The parent died before the death signal was armed.
        return Err(std::io::Error::from_raw_os_error(ESRCH));
    }
    for (resource, limit) in limits {
        // SAFETY: `limit` points to a live rlimit struct copied into this closure.
        if unsafe { setrlimit(*resource, limit) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    close_inherited_descriptors(descriptor_walk_limit);
    Ok(())
}

fn kill_group(pgid: c_int) {
    // SAFETY: kill takes two integers. A negative pid addresses the process group whose leader
    // is our own unreaped child, so the group id cannot belong to anyone else.
    let _ = unsafe { kill(-pgid, SIGKILL) };
}

/// A descriptor that becomes readable when `pid` (our unreaped child) exits.
#[cfg(target_os = "linux")]
fn watch_exit(pid: c_int) -> Result<OwnedFd, String> {
    // SAFETY: pidfd_open(pid, flags) takes two integers and returns a new descriptor or -1.
    let fd = unsafe { syscall(SYS_PIDFD_OPEN, pid as c_long, 0 as c_long) };
    if fd < 0 {
        return Err(format!(
            "pidfd_open is unavailable (Linux 5.3 or later is required): {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: the syscall returned a fresh descriptor that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

#[cfg(target_os = "macos")]
fn watch_exit(pid: c_int) -> Result<OwnedFd, String> {
    #[repr(C)]
    struct Kevent {
        ident: usize,
        filter: i16,
        flags: u16,
        fflags: u32,
        data: isize,
        udata: *mut c_void,
    }
    extern "C" {
        fn kqueue() -> c_int;
        fn kevent(
            kq: c_int,
            changes: *const Kevent,
            change_count: c_int,
            events: *mut Kevent,
            event_count: c_int,
            timeout: *const c_void,
        ) -> c_int;
    }
    const EVFILT_PROC: i16 = -5;
    const EV_ADD: u16 = 0x1;
    const NOTE_EXIT: u32 = 0x8000_0000;

    // SAFETY: kqueue takes no arguments and returns a new descriptor or -1.
    let kq = unsafe { kqueue() };
    if kq < 0 {
        return Err(format!(
            "kqueue failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: kqueue returned a fresh descriptor that nothing else owns.
    let kq = unsafe { OwnedFd::from_raw_fd(kq) };
    let change = Kevent {
        ident: pid as usize,
        filter: EVFILT_PROC,
        flags: EV_ADD,
        fflags: NOTE_EXIT,
        data: 0,
        udata: std::ptr::null_mut(),
    };
    // SAFETY: one live change record is passed with count 1, no event buffer and a null
    // timeout (registration does not wait).
    let registered = unsafe {
        kevent(
            kq.as_raw_fd(),
            &change,
            1,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
        )
    };
    if registered < 0 {
        let error = std::io::Error::last_os_error();
        // The pid is our unreaped child, so ESRCH can only mean it already
        // exited: report that through a descriptor that is readable now.
        if error.raw_os_error() == Some(ESRCH) {
            return already_readable();
        }
        return Err(format!("kevent EVFILT_PROC failed: {error}"));
    }
    Ok(kq)
}

/// A pipe whose write end is closed: always readable (end of file).
#[cfg(target_os = "macos")]
fn already_readable() -> Result<OwnedFd, String> {
    extern "C" {
        fn pipe(fds: *mut c_int) -> c_int;
    }
    let mut fds = [-1 as c_int; 2];
    // SAFETY: `fds` is a live array of two descriptors for pipe to fill.
    if unsafe { pipe(fds.as_mut_ptr()) } != 0 {
        return Err(format!("pipe failed: {}", std::io::Error::last_os_error()));
    }
    for fd in fds {
        // SAFETY: fcntl(F_SETFD) only sets the close-on-exec flag on a descriptor pipe just
        // created.
        unsafe { fcntl(fd, F_SETFD, FD_CLOEXEC) };
    }
    // SAFETY: pipe returned two fresh descriptors that nothing else owns; the write end is
    // closed at once.
    let (reader, writer) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    drop(writer);
    Ok(reader)
}

/// True when no member of the process group is alive. Zombies count as
/// dead: they run nothing, and the leader stays a zombie until it is reaped.
#[cfg(target_os = "linux")]
fn group_is_dead(pgid: c_int) -> bool {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return false;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|name| name.parse::<c_int>().ok()) else {
            continue;
        };
        let stat = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(stat) => stat,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) if error.raw_os_error() == Some(ESRCH) => continue,
            Err(_) => return false,
        };
        // pid (comm) state ppid pgrp ...; comm may contain spaces or ')'.
        let Some(after) = stat.rfind(')').map(|index| &stat[index + 1..]) else {
            return false;
        };
        let mut fields = after.split_whitespace();
        let state = fields.next();
        let pgrp = fields.nth(1).and_then(|pgrp| pgrp.parse::<c_int>().ok());
        if pgrp == Some(pgid) && !matches!(state, Some("Z") | Some("X")) {
            return false;
        }
    }
    true
}

#[cfg(target_os = "macos")]
fn group_is_dead(pgid: c_int) -> bool {
    extern "C" {
        fn proc_listpids(kind: u32, info: u32, buffer: *mut c_void, size: c_int) -> c_int;
        fn proc_pidinfo(
            pid: c_int,
            flavor: c_int,
            arg: u64,
            buffer: *mut c_void,
            size: c_int,
        ) -> c_int;
    }
    const PROC_PGRP_ONLY: u32 = 2;
    const PROC_PIDTBSDINFO: c_int = 3;
    /// `sizeof(struct proc_bsdinfo)`.
    const BSDINFO_SIZE: usize = 136;
    /// `pbi_status` is the second 32-bit field; `SZOMB` is 5.
    const SZOMB: u32 = 5;

    let mut pids = vec![0 as c_int; 4096];
    let size = (pids.len() * std::mem::size_of::<c_int>()) as c_int;
    // SAFETY: `pids` is a live, writable buffer of exactly `size` bytes.
    let filled =
        unsafe { proc_listpids(PROC_PGRP_ONLY, pgid as u32, pids.as_mut_ptr().cast(), size) };
    if filled < 0 || filled >= size {
        // An error, or a group too large to list in one call: not verified.
        return false;
    }
    let count = filled as usize / std::mem::size_of::<c_int>();
    for &pid in &pids[..count] {
        if pid == 0 {
            continue;
        }
        let mut info = [0_u64; BSDINFO_SIZE / 8];
        // SAFETY: `info` is a live, writable, 8-byte aligned buffer of exactly BSDINFO_SIZE
        // bytes, the size of proc_bsdinfo.
        let copied = unsafe {
            proc_pidinfo(
                pid,
                PROC_PIDTBSDINFO,
                0,
                info.as_mut_ptr().cast(),
                BSDINFO_SIZE as c_int,
            )
        };
        if copied <= 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(ESRCH) {
                continue;
            }
            return false;
        }
        if copied as usize != BSDINFO_SIZE {
            return false;
        }
        let status = (info[0] >> 32) as u32;
        if status != SZOMB {
            return false;
        }
    }
    true
}

#[cfg(target_os = "linux")]
mod cgroup {
    use std::fs::OpenOptions;
    use std::os::fd::{AsRawFd, RawFd};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    /// A child cgroup of this process's own, delegated cgroup v2 node.
    pub(super) struct Cgroup {
        dir: PathBuf,
        procs: std::fs::File,
    }

    impl Cgroup {
        /// `Ok(None)` when this process's cgroup is not delegated to it (the
        /// common case outside a `Delegate=yes` unit). An error only when a
        /// delegated cgroup was found but the child cgroup could not be set
        /// up after it was created.
        pub(super) fn create_if_delegated() -> Result<Option<Self>, String> {
            let Ok(membership) = std::fs::read_to_string("/proc/self/cgroup") else {
                return Ok(None);
            };
            let Some(path) = membership.lines().find_map(|line| line.strip_prefix("0::")) else {
                return Ok(None);
            };
            if path == "/" || path.contains("..") || !path.starts_with('/') {
                return Ok(None);
            }
            let base = PathBuf::from(format!("/sys/fs/cgroup{path}"));
            // cgroup.kill needs Linux 5.14; moving needs write access to the
            // shared ancestor's cgroup.procs, which delegation grants.
            if !base.join("cgroup.kill").is_file()
                || OpenOptions::new()
                    .write(true)
                    .open(base.join("cgroup.procs"))
                    .is_err()
            {
                return Ok(None);
            }
            let name = format!(
                "orcel-exec-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            );
            let dir = base.join(name);
            if std::fs::create_dir(&dir).is_err() {
                return Ok(None);
            }
            match OpenOptions::new()
                .write(true)
                .open(dir.join("cgroup.procs"))
            {
                Ok(procs) => Ok(Some(Self { dir, procs })),
                Err(error) => {
                    let _ = std::fs::remove_dir(&dir);
                    Err(format!("delegated cgroup cannot be joined: {error}"))
                }
            }
        }

        pub(super) fn procs_fd(&self) -> RawFd {
            self.procs.as_raw_fd()
        }

        pub(super) fn kill(&self) {
            let _ = std::fs::write(self.dir.join("cgroup.kill"), b"1");
        }

        pub(super) fn is_empty(&self) -> bool {
            std::fs::read_to_string(self.dir.join("cgroup.events"))
                .map(|events| events.lines().any(|line| line == "populated 0"))
                .unwrap_or(false)
        }

        /// Remove the (now empty) cgroup; it may take a moment after the
        /// last member exits.
        pub(super) fn remove(self) {
            drop(self.procs);
            for _ in 0..50 {
                if std::fs::remove_dir(&self.dir).is_ok() {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    }
}

#[cfg(target_os = "macos")]
mod cgroup {
    use std::os::fd::RawFd;

    /// macOS has no cgroups: the process group is the only tree boundary.
    pub(super) enum Cgroup {}

    impl Cgroup {
        pub(super) fn create_if_delegated() -> Result<Option<Self>, String> {
            Ok(None)
        }

        pub(super) fn procs_fd(&self) -> RawFd {
            match *self {}
        }

        pub(super) fn kill(&self) {
            match *self {}
        }

        pub(super) fn is_empty(&self) -> bool {
            match *self {}
        }

        pub(super) fn remove(self) {
            match self {}
        }
    }
}

#[cfg(test)]
#[path = "unix_tests.rs"]
mod tests;
