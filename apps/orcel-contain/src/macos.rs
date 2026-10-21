// SPDX-License-Identifier: MIT
// Portions copyright (c) 2025 Cua AI, Inc.; modifications copyright Orcel.

//! macOS containment: a deny-by-default Seatbelt profile, a trusted
//! parent-death sentinel, inherited descriptor closure, resource limits and a
//! supervisor-sampled memory ceiling.
//!
//! The profile is applied by launching the child through
//! `/usr/bin/sandbox-exec`, which is the only supported way for a parent to
//! impose a Seatbelt profile on a child it does not control. `sandbox_init`
//! cannot be used from a `pre_exec` hook: it allocates and talks to `sandboxd`,
//! neither of which is async-signal-safe after `fork`. A profile that fails to
//! compile makes `sandbox-exec` exit before it execs anything, so a malformed
//! profile can never yield an unsandboxed child, and a missing `sandbox-exec`
//! fails the launch outright. Apple has deprecated `sandbox-exec` (risk S-25);
//! the capability report stays truthful and the launch refuses if the tool is
//! gone.
//!
//! Darwin has no `PR_SET_PDEATHSIG`, and a `kqueue` watch cannot be installed
//! across `exec`. The child is therefore launched underneath a fixed
//! `/bin/sh` script that holds one extra descriptor: the read end of a pipe
//! whose write end never leaves the helper. The script backgrounds a read on
//! that descriptor, closes its own copy, and then `exec`s `sandbox-exec`, so
//! the shell's pid — which is also the process-group id — becomes the child.
//! When the helper dies for any reason, including `SIGKILL`, the pipe reaches
//! end of file and the sentinel kills the whole process group.
//!
//! Darwin also has no usable hard address-space limit: `RLIMIT_AS` is an alias
//! for `RLIMIT_RSS`, which XNU does not enforce. Rather than advertise an
//! unenforced ceiling, the supervisor samples the child's resident footprint
//! and kills the tree when it exceeds the bound.
//! [`crate::containment::capabilities`] reports that as
//! [`crate::containment::MemoryLimitEnforcement::SupervisorSampling`].
//!
//! Provenance (T-CUA-22, COPY_ADAPT): adapted from
//! cua@a802eaf26ca97616a6bf0de6a29729a9346fbb1f
//! `libs/cua-driver/rust/crates/cua-driver-core/src/perception_client/containment/macos.rs`
//! (blob 28f9d8120057001db53dd40f80b591e290234469), MIT; notice in
//! `docs/orcel/notices/cua-MIT.txt`. Orcel's changes: stderr is a third piped
//! stream; the executable is readable as one exact file (the donor granted its
//! whole directory); the profile is passed to `sandbox-exec -p` as text
//! instead of a file in the child's writable working directory;
//! `sysctl-read` is narrowed to the names the loader and runtimes read; the shell and `sandbox-exec` paths are
//! parameters of `spawn_with_tools` so the refusal branch is testable; the
//! unit tests moved to `macos_tests.rs`.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::containment::{
    containment_error, os_detail, spawn_error, unsupported_error, ContainError, ContainedChild,
    ContainmentLimits, FilesystemBoundary,
};
use crate::pinned::PinnedExecutable;
use crate::unix::{
    apply_resource_limits, base_command, close_inherited_descriptors, ProcessGroupGuard,
};

pub(crate) type Process = crate::unix::Process;
pub(crate) type ChildStdin = tokio::process::ChildStdin;
pub(crate) type ChildStdout = tokio::process::ChildStdout;
pub(crate) type ChildStderr = tokio::process::ChildStderr;

const SHELL: &str = "/bin/sh";
const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// The descriptor the sentinel reads. Chosen because `pre_exec` runs after the
/// standard library has already placed the protocol pipes on 0, 1 and 2.
const SENTINEL_DESCRIPTOR: RawFd = 3;

/// Backgrounds a blocking read on the sentinel descriptor, drops its own copy
/// of that descriptor so the child never sees it, and replaces itself with
/// `sandbox-exec`. `$$` stays the pid of the original shell across both the
/// subshell and the `exec`, and that pid is the process-group id, so the kill
/// reaches the child and anything it left behind.
const PARENT_DEATH_SENTINEL: &str = concat!(
    "{ read -r orcel_parent_gone <&3; kill -9 -$$; } 0</dev/null 1>/dev/null 2>&1 &\n",
    "exec 3<&-\n",
    "exec \"$@\"\n",
);

/// How often the supervisor samples the child's footprint.
const MEMORY_SAMPLE_INTERVAL: Duration = Duration::from_millis(250);

/// Immutable system directories the dynamic loader and Objective-C runtime
/// read. None of them expose user data.
const SYSTEM_READ_TREES: &[&str] = &[
    "/usr/lib",
    "/System/Library",
    "/System/Volumes/Preboot/Cryptexes/OS",
    "/private/var/db/dyld",
];

/// The only devices the child may open. `/dev` as a whole is never granted.
const DEVICE_NODES: &[&str] = &[
    "/dev/null",
    "/dev/zero",
    "/dev/random",
    "/dev/urandom",
    "/dev/dtracehelper",
];

/// The Mach services a non-GUI process needs to start and log. Everything else
/// — `com.apple.windowserver.active`, `com.apple.tccd`, `com.apple.pasteboard.1`
/// and `com.apple.SecurityServer` among them — stays denied by the profile's
/// default, which is what keeps the child away from the helper's own screen
/// recording, accessibility and Keychain grants.
const MACH_SERVICES: &[&str] = &[
    "com.apple.system.opendirectoryd.libinfo",
    "com.apple.system.DirectoryService.libinfo_v1",
    "com.apple.system.notification_center",
    "com.apple.system.logger",
    "com.apple.logd",
    "com.apple.diagnosticd",
];

/// The sysctls a child may read: the CPU, memory and OS-version facts dyld,
/// libSystem and language runtimes ask for at startup. Everything else,
/// including `kern.proc.*` (other processes), `kern.hostname` and network
/// state, stays denied by the default rule.
const SYSCTL_NAMES: &[&str] = &[
    "hw.activecpu",
    "hw.byteorder",
    "hw.cachelinesize",
    "hw.cpufamily",
    "hw.cpusubtype",
    "hw.cputype",
    "hw.l1dcachesize",
    "hw.l1icachesize",
    "hw.l2cachesize",
    "hw.l3cachesize",
    "hw.logicalcpu",
    "hw.logicalcpu_max",
    "hw.machine",
    "hw.memsize",
    "hw.model",
    "hw.ncpu",
    "hw.nperflevels",
    "hw.pagesize",
    "hw.pagesize_compat",
    "hw.physicalcpu",
    "hw.physicalcpu_max",
    "kern.argmax",
    "kern.maxfilesperproc",
    "kern.ngroups",
    "kern.osproductversion",
    "kern.osrelease",
    "kern.ostype",
    "kern.osvariant_status",
    "kern.osversion",
    "kern.secure_kernel",
    "kern.usrstack64",
    "kern.version",
    "sysctl.proc_cputype",
    "sysctl.proc_native",
    "sysctl.proc_translated",
];

const SYSCTL_PREFIXES: &[&str] = &["hw.optional.", "hw.perflevel"];

/// Owns the child's process group, the sentinel pipe and the memory sampler.
///
/// Field order is load-bearing. [`Drop::drop`] runs first and stops the
/// sampler; then `group` drops and kills the tree, which reaches the sentinel
/// before it can observe end of file; only then does `sentinel` close. A
/// sentinel that fired after the group was reaped could otherwise signal a
/// recycled process-group id.
pub(crate) struct Guard {
    group: ProcessGroupGuard,
    /// Held only for its `Drop`: closing this end is what makes the sentinel
    /// observe end of file when the helper goes away.
    _sentinel: OwnedFd,
    memory_watch: tokio::task::JoinHandle<()>,
}

impl Guard {
    pub(crate) fn note_reaped(&mut self) {
        self.group.note_reaped();
    }

    pub(crate) fn kill_tree(&mut self) {
        self.group.kill_tree();
    }

    pub(crate) fn memory_ceiling_exceeded(&self) -> bool {
        self.group.memory_ceiling_exceeded()
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        self.memory_watch.abort();
    }
}

pub(crate) async fn spawn(
    executable: &PinnedExecutable,
    args: &[String],
    working_directory: &Path,
    boundary: &FilesystemBoundary,
    limits: &ContainmentLimits,
) -> Result<ContainedChild, ContainError> {
    spawn_with_tools(
        Path::new(SHELL),
        Path::new(SANDBOX_EXEC),
        executable,
        args,
        working_directory,
        boundary,
        limits,
    )
    .await
}

/// [`spawn`] with the trusted shell and `sandbox-exec` paths as parameters.
/// Shipped code passes only the two constants above.
pub(crate) async fn spawn_with_tools(
    shell: &Path,
    sandbox_exec: &Path,
    executable: &PinnedExecutable,
    args: &[String],
    working_directory: &Path,
    boundary: &FilesystemBoundary,
    limits: &ContainmentLimits,
) -> Result<ContainedChild, ContainError> {
    for required in [shell, sandbox_exec] {
        if !required.is_file() {
            return Err(unsupported_error(
                "this macOS build cannot contain the contained process: sandbox-exec or /bin/sh is unavailable",
            ));
        }
    }
    // `/bin/sh` is what is actually spawned, so a missing child would
    // otherwise surface as a crashed child instead of a failed launch.
    if !executable.path().is_file() {
        return Err(spawn_error(std::io::Error::from_raw_os_error(libc::ENOENT)));
    }
    // The profile travels as an argument, not a file: nothing the child can
    // write ever held it. It is visible in the process list only until
    // `/bin/sh` and then `sandbox-exec` exec, which replaces their argv; it
    // names the spec's paths, which are the user's own.
    let profile = build_profile(boundary)?;
    let (sentinel_read, sentinel_write) = sentinel_pipe()?;

    let mut command = base_command(shell, working_directory);
    command
        .arg("-c")
        .arg(PARENT_DEATH_SENTINEL)
        .arg("orcel-contain-supervisor")
        .arg(sandbox_exec)
        .arg("-p")
        .arg(&profile)
        .arg(executable.path())
        .args(args);
    command.current_dir(working_directory);
    command.process_group(0);

    let sentinel_source = sentinel_read.as_raw_fd();
    if sentinel_source < SENTINEL_DESCRIPTOR {
        return Err(containment_error(
            "the contained process sentinel pipe landed on a reserved descriptor",
            None,
        ));
    }
    let max_cpu_seconds = limits.max_cpu_seconds();
    let max_open_files = limits.max_open_files;
    // Runs between fork and exec using only raw syscalls. The limits and the
    // descriptor table survive the exec into `/bin/sh`, its exec of
    // `sandbox-exec`, and that program's exec of the child itself.
    // SAFETY: `pre_exec` runs in the forked child before exec. The closure makes only
    // async-signal-safe raw calls (dup2, close, fcntl, getrlimit/setrlimit) on integers it
    // captured by value, and allocates nothing.
    unsafe {
        command.as_std_mut().pre_exec(move || {
            if sentinel_source != SENTINEL_DESCRIPTOR
                && libc::dup2(sentinel_source, SENTINEL_DESCRIPTOR) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            close_inherited_descriptors(Some(SENTINEL_DESCRIPTOR))?;
            apply_resource_limits(None, max_cpu_seconds, max_open_files)
        });
    }

    // #384 item 2: `sandbox-exec` execs a path, so it must still name the
    // verified open file (the residual is the window after this check).
    executable.check_still_named()?;
    let mut child = command.spawn().map_err(spawn_error)?;
    drop(sentinel_read);
    let stdin = child.stdin.take();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let pid = child.id();
    // The sentinel subshell stays a live member of the group, so the group id
    // cannot be recycled and remains safe to signal even after the leader has
    // been reaped.
    let group = ProcessGroupGuard::new(pid, true);
    let Some(sample_pid) = pid.and_then(|pid| i32::try_from(pid).ok()) else {
        return Err(containment_error(
            "failed to identify the contained process for memory enforcement",
            None,
        ));
    };
    if resident_bytes(sample_pid).is_none() {
        // SAFETY: kill has no memory preconditions. `sample_pid` is the just-spawned shell, the
        // leader of its own new process group, so -pid addresses only the contained tree.
        unsafe {
            libc::kill(-sample_pid, libc::SIGKILL);
        }
        return Err(containment_error(
            "failed to install the contained process memory sampler",
            None,
        ));
    }
    let memory_watch = watch_memory(sample_pid, limits.max_memory_bytes, group.memory_flag());
    Ok(ContainedChild {
        guard: Guard {
            group,
            _sentinel: sentinel_write,
            memory_watch,
        },
        process: Process::new(child),
        stdin,
        stdout,
        stderr,
    })
}

/// Create the sentinel pipe with both ends close-on-exec, so no other helper
/// child can hold the write end open and keep a dead helper's child alive.
fn sentinel_pipe() -> Result<(OwnedFd, OwnedFd), ContainError> {
    let mut ends = [0 as libc::c_int; 2];
    // SAFETY: `ends` is a live two-element c_int array, exactly what pipe(2) writes.
    if unsafe { libc::pipe(ends.as_mut_ptr()) } != 0 {
        return Err(containment_error(
            "failed to create the contained process parent-death sentinel pipe",
            os_detail(&std::io::Error::last_os_error()),
        ));
    }
    // SAFETY: pipe(2) succeeded, so ends[0] is a fresh descriptor that nothing else owns.
    let read = unsafe { OwnedFd::from_raw_fd(ends[0]) };
    // SAFETY: pipe(2) succeeded, so ends[1] is a fresh descriptor that nothing else owns.
    let write = unsafe { OwnedFd::from_raw_fd(ends[1]) };
    for end in [&read, &write] {
        // SAFETY: `end` is an open descriptor owned by the OwnedFd it was borrowed from;
        // F_SETFD only changes its flags.
        if unsafe { libc::fcntl(end.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(containment_error(
                "failed to isolate the contained process parent-death sentinel pipe",
                os_detail(&std::io::Error::last_os_error()),
            ));
        }
    }
    Ok((read, write))
}

/// Sample the child's resident footprint and kill the tree once it exceeds the
/// ceiling. Darwin offers no kernel primitive a parent can install on a child
/// for this, so the boundary is reported as sampled rather than enforced.
fn watch_memory(
    pid: libc::c_int,
    ceiling: u64,
    exceeded: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(MEMORY_SAMPLE_INTERVAL).await;
            let Some(resident) = resident_bytes(pid) else {
                // ESRCH proves the child is gone. Any other sampling failure
                // leaves the ceiling unobservable, so kill the group rather
                // than silently continuing without enforcement.
                // SAFETY: kill with signal 0 only checks that `pid` exists; it has no memory
                // preconditions.
                if unsafe { libc::kill(pid, 0) } == 0
                    || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
                {
                    // SAFETY: kill has no memory preconditions. The sampler only runs while the
                    // guard holds the group, and the parent-death sentinel keeps the group id
                    // reserved, so -pid cannot address an unrelated group.
                    unsafe {
                        libc::kill(-pid, libc::SIGKILL);
                    }
                }
                return;
            };
            if resident > ceiling {
                exceeded.store(true, Ordering::Release);
                // SAFETY: kill has no memory preconditions. The sampler only runs while the
                // guard holds the group, and the parent-death sentinel keeps the group id
                // reserved, so -pid cannot address an unrelated group.
                unsafe {
                    libc::kill(-pid, libc::SIGKILL);
                }
                return;
            }
        }
    })
}

/// `struct proc_taskinfo` from `<libproc.h>`. The layout is stable ABI.
#[repr(C)]
#[derive(Clone, Copy)]
struct ProcTaskInfo {
    virtual_size: u64,
    resident_size: u64,
    total_user: u64,
    total_system: u64,
    threads_user: u64,
    threads_system: u64,
    policy: i32,
    faults: i32,
    pageins: i32,
    cow_faults: i32,
    messages_sent: i32,
    messages_received: i32,
    syscalls_mach: i32,
    syscalls_unix: i32,
    context_switches: i32,
    thread_count: i32,
    running_threads: i32,
    priority: i32,
}

/// `PROC_PIDTASKINFO` from `<sys/proc_info.h>`.
const PROC_PIDTASKINFO: libc::c_int = 4;

extern "C" {
    fn proc_pidinfo(
        pid: libc::c_int,
        flavor: libc::c_int,
        arg: u64,
        buffer: *mut libc::c_void,
        buffersize: libc::c_int,
    ) -> libc::c_int;
}

fn resident_bytes(pid: libc::c_int) -> Option<u64> {
    let mut info = ProcTaskInfo {
        virtual_size: 0,
        resident_size: 0,
        total_user: 0,
        total_system: 0,
        threads_user: 0,
        threads_system: 0,
        policy: 0,
        faults: 0,
        pageins: 0,
        cow_faults: 0,
        messages_sent: 0,
        messages_received: 0,
        syscalls_mach: 0,
        syscalls_unix: 0,
        context_switches: 0,
        thread_count: 0,
        running_threads: 0,
        priority: 0,
    };
    let size = std::mem::size_of::<ProcTaskInfo>() as libc::c_int;
    // SAFETY: `info` is a live, zero-initialised `proc_taskinfo` and `size` is its exact size,
    // so proc_pidinfo writes at most that many bytes into it.
    let written = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDTASKINFO,
            0,
            std::ptr::addr_of_mut!(info).cast(),
            size,
        )
    };
    (written == size).then_some(info.resident_size)
}

/// Deny-by-default Seatbelt profile.
///
/// Reads, executes and writes are confined to the exact executable, the
/// working directory and the spec's roots, plus the immutable system runtime
/// directories the loader needs. Network, fork, cross-process inspection,
/// IOKit, and every Mach service outside a short logging allowlist are denied
/// by the default rule.
fn build_profile(boundary: &FilesystemBoundary) -> Result<String, ContainError> {
    let mut profile = String::from(
        "(version 1)\n\
         (deny default)\n\
         ; Explicit for auditability; the default rule already denies these.\n\
         (deny network*)\n\
         (deny process-fork)\n\
         (deny mach-register)\n\
         (allow process-info* (target self))\n\
         (allow signal (target self))\n",
    );

    profile.push_str("(allow sysctl-read\n");
    for name in SYSCTL_NAMES {
        profile.push_str("  (sysctl-name \"");
        profile.push_str(name);
        profile.push_str("\")\n");
    }
    for prefix in SYSCTL_PREFIXES {
        profile.push_str("  (sysctl-name-prefix \"");
        profile.push_str(prefix);
        profile.push_str("\")\n");
    }
    profile.push_str(")\n");

    profile.push_str("(allow mach-lookup\n");
    for service in MACH_SERVICES {
        profile.push_str("  (global-name \"");
        profile.push_str(&escape(service));
        profile.push_str("\")\n");
    }
    profile.push_str(")\n");
    profile.push_str(
        "(allow ipc-posix-shm-read-data (ipc-posix-name \"apple.shm.notification_center\"))\n",
    );

    let mut metadata_paths = vec![PathBuf::from("/"), PathBuf::from("/var")];
    let mut add_ancestors = |path: &Path| {
        let mut parent = path.parent();
        while let Some(ancestor) = parent {
            metadata_paths.push(ancestor.to_path_buf());
            parent = ancestor.parent();
        }
    };
    for path in boundary
        .readable
        .iter()
        .chain(&boundary.writable)
        .chain(&boundary.executables)
    {
        add_ancestors(path);
    }
    for path in SYSTEM_READ_TREES.iter().chain(DEVICE_NODES) {
        add_ancestors(Path::new(path));
    }
    metadata_paths.sort();
    metadata_paths.dedup();
    let metadata = metadata_paths
        .iter()
        .map(|path| literal_rule(path))
        .collect::<Result<Vec<_>, _>>()?;
    push_rule(&mut profile, "file-read-metadata", metadata.iter());

    // A literal directory rule permits traversal and directory inspection but
    // cannot expose any file below it. Some runtimes inspect `/` at startup.
    let mut readable = vec!["  (literal \"/\")\n".to_owned()];
    for path in &boundary.readable {
        readable.push(subpath_rule(path)?);
    }
    // The executable is readable as one exact file, not through its directory.
    for path in &boundary.executables {
        readable.push(literal_rule(path)?);
    }
    for path in SYSTEM_READ_TREES {
        if Path::new(path).exists() {
            readable.push(subpath_rule(Path::new(path))?);
        }
    }
    let devices: Vec<String> = DEVICE_NODES
        .iter()
        .filter(|node| Path::new(node).exists())
        .map(|node| format!("  (literal \"{}\")\n", escape(node)))
        .collect();

    push_rule(&mut profile, "file-read*", readable.iter().chain(&devices));
    let executable: Vec<String> = boundary
        .executables
        .iter()
        .map(|path| literal_rule(path))
        .collect::<Result<_, _>>()?;
    let mut mappable = executable.clone();
    for path in SYSTEM_READ_TREES {
        if Path::new(path).exists() {
            mappable.push(subpath_rule(Path::new(path))?);
        }
    }
    push_rule(&mut profile, "file-map-executable", mappable.iter());
    push_rule(&mut profile, "process-exec*", executable.iter());
    push_rule(&mut profile, "file-ioctl", devices.iter());
    push_rule(&mut profile, "file-write-data", devices.iter());

    let mut writable = Vec::new();
    for path in &boundary.writable {
        writable.push(subpath_rule(path)?);
    }
    push_rule(&mut profile, "file-write*", writable.iter());
    Ok(profile)
}

fn push_rule<'a>(profile: &mut String, operation: &str, entries: impl Iterator<Item = &'a String>) {
    let mut opened = false;
    for entry in entries {
        if !opened {
            profile.push_str("(allow ");
            profile.push_str(operation);
            profile.push('\n');
            opened = true;
        }
        profile.push_str(entry);
    }
    if opened {
        profile.push_str(")\n");
    }
}

fn subpath_rule(path: &Path) -> Result<String, ContainError> {
    let text = path.to_str().ok_or_else(|| {
        containment_error(
            "a path for the macOS child sandbox is not valid UTF-8",
            None,
        )
    })?;
    Ok(format!("  (subpath \"{}\")\n", escape(text)))
}

fn literal_rule(path: &Path) -> Result<String, ContainError> {
    let text = path.to_str().ok_or_else(|| {
        containment_error(
            "a path for the macOS child sandbox is not valid UTF-8",
            None,
        )
    })?;
    Ok(format!("  (literal \"{}\")\n", escape(text)))
}

/// Escape a path for a Seatbelt double-quoted string literal so a crafted path
/// cannot terminate the literal and inject profile syntax.
fn escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if matches!(character, '\\' | '"') {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

#[cfg(test)]
#[path = "macos_tests.rs"]
mod tests;
