// SPDX-License-Identifier: MIT
// Portions copyright (c) 2025 Cua AI, Inc.; modifications copyright Orcel.

//! Containment pieces shared by the Unix platforms.
//!
//! Provenance (T-CUA-22, COPY_ADAPT): adapted from
//! cua@a802eaf26ca97616a6bf0de6a29729a9346fbb1f
//! `libs/cua-driver/rust/crates/cua-driver-core/src/perception_client/containment/unix.rs`
//! (blob fbabc6a76b02aae8b905fa08ec6a0f5308143495), MIT; notice in
//! `docs/orcel/notices/cua-MIT.txt`. Orcel's changes: stderr is piped (and
//! relayed, bounded) instead of discarded; the exit is reported as a code or a
//! signal number instead of a display string; the guard gains `kill_tree` for
//! the one-shot deadline and output-limit paths.

use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::process::Command;

use crate::containment::RawExit;

/// `getrlimit`/`setrlimit` take `__rlimit_resource_t` on glibc and `c_int`
/// everywhere else this crate builds.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
type RlimitResource = libc::__rlimit_resource_t;
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
type RlimitResource = libc::c_int;

/// The child keeps this much CPU time past its soft ceiling before the kernel
/// escalates from `SIGXCPU` to `SIGKILL`. The gap is what lets the supervisor
/// report a CPU exhaustion as a resource limit instead of a crash.
const CPU_LIMIT_GRACE_SECONDS: u64 = 5;

/// Stdio and environment shape shared by every Unix platform: no inherited
/// environment, piped stdin so the child observes parent EOF, piped stdout and
/// stderr for the bounded relay, and a kill on handle drop.
///
/// `TMPDIR` points at the private working directory because writes are confined
/// to it; a runtime that spills into the system temporary directory would
/// otherwise fail.
pub(crate) fn base_command(program: &Path, working_directory: &Path) -> Command {
    let mut command = Command::new(program);
    command
        .env_clear()
        .env("TMPDIR", working_directory)
        .env("TMP", working_directory)
        .env("TEMP", working_directory)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    command
}

/// Apply the CPU-time and file-descriptor ceilings, plus an address-space
/// ceiling on the targets whose kernel enforces one.
///
/// Called between `fork` and `exec`, so it uses only raw syscalls and performs
/// no allocation. `RLIMIT_NPROC` is deliberately absent: Linux and Darwin both
/// count it per real UID rather than per process tree, so it bounded nothing
/// useful while breaking the child on any desktop whose user already owns more
/// tasks than the ceiling. Process creation is denied outright instead — by the
/// seccomp filter on Linux and by the deny-by-default Seatbelt profile on
/// macOS.
pub(crate) fn apply_resource_limits(
    max_address_space_bytes: Option<u64>,
    max_cpu_seconds: u64,
    max_open_files: u32,
) -> std::io::Result<()> {
    if let Some(bytes) = max_address_space_bytes {
        #[cfg(target_os = "linux")]
        set_limit(libc::RLIMIT_AS, bytes, bytes)?;
        #[cfg(not(target_os = "linux"))]
        let _ = bytes;
    }
    set_limit(
        libc::RLIMIT_CPU,
        max_cpu_seconds,
        max_cpu_seconds.saturating_add(CPU_LIMIT_GRACE_SECONDS),
    )?;
    set_limit(
        libc::RLIMIT_NOFILE,
        u64::from(max_open_files),
        u64::from(max_open_files),
    )
}

fn set_limit(resource: RlimitResource, soft: u64, hard: u64) -> std::io::Result<()> {
    let mut current = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `current` is a valid, writable rlimit.
    if unsafe { libc::getrlimit(resource, &mut current) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // An unprivileged process cannot raise its inherited hard limit, and the
    // stricter of the two is the safe choice, so clamp instead of failing.
    let clamp = |value: u64| -> libc::rlim_t {
        let requested = value as libc::rlim_t;
        if current.rlim_max == libc::RLIM_INFINITY {
            requested
        } else {
            current.rlim_max.min(requested)
        }
    };
    let limit = libc::rlimit {
        rlim_cur: clamp(soft),
        rlim_max: clamp(hard),
    };
    // SAFETY: `limit` is a valid rlimit for the duration of the call.
    if unsafe { libc::setrlimit(resource, &limit) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Mark every descriptor above the stdio pipes close-on-exec, so no file,
/// socket or device the helper had open survives into the child.
///
/// `retain` stays open: macOS uses it for the parent-death sentinel pipe. Runs
/// between `fork` and `exec`, so it allocates nothing.
///
/// Linux uses `close_range(2)` instead, which is a single syscall and needs no
/// descriptor-table sweep.
#[cfg(target_os = "macos")]
pub(crate) fn close_inherited_descriptors(retain: Option<libc::c_int>) -> std::io::Result<()> {
    // Read the ceiling before the descriptor limit is lowered, and cap the
    // sweep so an inherited `RLIM_INFINITY` cannot turn this into an unbounded
    // loop.
    const MAXIMUM_SWEEP: libc::c_int = 65_536;
    // SAFETY: getdtablesize has no preconditions.
    let ceiling = unsafe { libc::getdtablesize() }.clamp(3, MAXIMUM_SWEEP);
    for descriptor in 3..ceiling {
        if Some(descriptor) == retain {
            continue;
        }
        // SAFETY: closing an unowned or invalid descriptor in the forked child
        // is harmless; nothing in the child uses it before exec.
        unsafe {
            libc::close(descriptor);
        }
    }
    if let Some(retain) = retain {
        // The sentinel descriptor must survive `exec`, so its inherited
        // close-on-exec flag is cleared explicitly.
        // SAFETY: `retain` is an open descriptor in the child.
        if unsafe { libc::fcntl(retain, libc::F_SETFD, 0) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Kills the child's process group so descendants cannot outlive a deadline,
/// an output overflow, parent death or helper exit.
pub(crate) struct ProcessGroupGuard {
    pid: Option<u32>,
    reaped: bool,
    /// Whether the group must still be signalled after the leader was reaped.
    ///
    /// Once the leader is reaped its process-group id can be recycled, so
    /// signalling it blindly could reach an unrelated group. Linux sets this to
    /// `false` because seccomp denies `fork`, `setsid` and `setpgid`, which
    /// proves the group is empty. macOS sets it to `true` because its
    /// parent-death sentinel is still a live member, which keeps the group id
    /// reserved and the signal correctly addressed.
    kill_group_after_reap: bool,
    memory_ceiling_exceeded: Arc<AtomicBool>,
}

impl ProcessGroupGuard {
    pub(crate) fn new(pid: Option<u32>, kill_group_after_reap: bool) -> Self {
        Self {
            pid,
            reaped: false,
            kill_group_after_reap,
            memory_ceiling_exceeded: Arc::new(AtomicBool::new(false)),
        }
    }

    /// A flag a supervisor task sets when it kills the child for exceeding its
    /// memory ceiling, so the exit is reported as a resource limit. Only the
    /// macOS supervisor (`watch_memory`) sets it.
    #[cfg(target_os = "macos")]
    pub(crate) fn memory_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.memory_ceiling_exceeded)
    }

    pub(crate) fn note_reaped(&mut self) {
        self.reaped = true;
    }

    pub(crate) fn memory_ceiling_exceeded(&self) -> bool {
        self.memory_ceiling_exceeded.load(Ordering::Acquire)
    }

    /// Kill the whole group now, unless the group is provably empty.
    pub(crate) fn kill_tree(&mut self) {
        if self.reaped && !self.kill_group_after_reap {
            return;
        }
        if let Some(pid) = self.pid {
            if let Ok(pid) = i32::try_from(pid) {
                // The child is its own process-group leader, so the negative
                // pid reaches every descendant that did not change group.
                // SAFETY: kill has no memory preconditions.
                unsafe {
                    libc::kill(-pid, libc::SIGKILL);
                }
            }
        }
    }
}

impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        self.kill_tree();
    }
}

/// The Unix child process. The child owns the stdio pipes directly, so the
/// supervisor only has to reap it and classify how it ended.
pub(crate) struct Process {
    child: tokio::process::Child,
}

impl Process {
    pub(crate) fn new(child: tokio::process::Child) -> Self {
        Self { child }
    }

    pub(crate) async fn wait(&mut self) -> std::io::Result<RawExit> {
        use std::os::unix::process::ExitStatusExt as _;

        let status = self.child.wait().await?;
        let signal = status.signal();
        Ok(RawExit {
            success: status.success(),
            // `SIGXCPU` is only ever raised by the soft CPU ceiling installed
            // above; the hard ceiling that follows it is a plain `SIGKILL`.
            resource_limited: signal == Some(libc::SIGXCPU),
            code: i64::from(signal.or(status.code()).unwrap_or(-1)),
            signaled: signal.is_some(),
        })
    }
}
