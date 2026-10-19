// SPDX-License-Identifier: MIT
// Portions copyright (c) 2025 Cua AI, Inc.; modifications copyright Orcel.

//! Bounded external-process containment for Orcel's contained tier.
//!
//! Containment is reported as platform capabilities rather than one misleading
//! cross-platform boolean. Each implementation must install every boundary it
//! advertises, or fail before child code executes. [`spawn`] refuses to launch
//! a child on any target whose reported capabilities do not meet
//! [`ContainmentCapabilities::meets_contract`], so a partially contained
//! platform is an explicit `unsupported_platform` refusal rather than a weaker
//! silent mode.
//!
//! Platform coverage:
//!
//! - Linux: process group, `PR_SET_PDEATHSIG`, `PR_SET_NO_NEW_PRIVS`,
//!   `close_range`, `RLIMIT_AS`/`RLIMIT_CPU`/`RLIMIT_NOFILE`, a Landlock
//!   ruleset that confines reads, executes and writes to an exact allowlist,
//!   and a seccomp filter that denies every socket, `io_uring`, process
//!   creation, `ptrace` and cross-process memory access.
//! - macOS: process group, a trusted `/bin/sh` parent-death sentinel, inherited
//!   descriptor closure, `RLIMIT_CPU`/`RLIMIT_NOFILE`, a supervisor-sampled
//!   memory ceiling, and a deny-by-default Seatbelt profile applied through
//!   `sandbox-exec` that confines reads, writes, execution, Mach lookups and
//!   IPC and denies network, fork and cross-process authority.
//! - Windows: an AppContainer (LowBox) identity with no capabilities, an
//!   explicit `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` carrying only the three
//!   stdio pipes, private security descriptors on the job, process, thread,
//!   pipes, desktop and working directory, a private desktop, and a Job Object
//!   with kill-on-close, memory, CPU-time, active-process and UI restrictions.
//!   The child is created suspended and resumed only after every boundary is
//!   in place. Filesystem ACLs are read and updated through verified no-follow
//!   handles so reparse-point swaps cannot redirect a grant.
//!
//! Network denial, read confinement and write confinement are deliberately not
//! configurable. The only tunable surface is [`ContainmentLimits`], including
//! the exact readable and writable roots the spec names.
//!
//! Provenance (T-CUA-21, COPY_ADAPT): adapted from
//! cua@a802eaf26ca97616a6bf0de6a29729a9346fbb1f
//! `libs/cua-driver/rust/crates/cua-driver-core/src/perception_client/containment.rs`
//! (blob 6179d5eac250382b76ad951a9abfc1c950193be8), MIT; notice in
//! `docs/orcel/notices/cua-MIT.txt`. Orcel's changes:
//! - the perception-worker error type is replaced by [`ContainError`] with the
//!   same code/message/retryable/detail shape;
//! - the boundary is exact. The donor derived extra read roots from the
//!   executable's directory and from every absolute path argument that
//!   existed; here nothing is derived. The executable is granted as one exact
//!   file and the only directories are the spec's working directory and its
//!   explicit `read`/`write` roots;
//! - the donor's test-only `additional_executable_paths` widening and its
//!   Windows ACL lease and journal paths are removed (the helper is one-shot
//!   and owns its cleanup synchronously);
//! - the broad-root refusal no longer reads `HOME`/`USERPROFILE`: this helper
//!   reads no environment variable at all. Home directories are still refused
//!   by shape (`/home/<name>`, `/Users/<name>`, `C:\Users\<name>`);
//! - `run_contained_hook` becomes [`run`], which relays bounded stdout and
//!   stderr and a wall-clock deadline instead of discarding output;
//! - the per-run process ceiling is fixed at one: the contained tier never
//!   forks, so it is not a limit callers can raise.

use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use tokio::io::AsyncReadExt as _;

#[cfg(target_os = "linux")]
use crate::linux as platform;
#[cfg(target_os = "macos")]
use crate::macos as platform;
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
use crate::unsupported as platform;
#[cfg(windows)]
use crate::windows as platform;

/// The parent end of the child's stdin pipe.
pub(crate) type ChildStdin = platform::ChildStdin;
/// The parent end of the child's stdout pipe.
pub(crate) type ChildStdout = platform::ChildStdout;
/// The parent end of the child's stderr pipe.
pub(crate) type ChildStderr = platform::ChildStderr;

/// The contained tier never creates a process. Unix denies process creation
/// outright through seccomp and Seatbelt; Windows caps the Job Object's
/// active-process count at this value instead, because a Job Object has no
/// equivalent creation hook.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) const MAX_PROCESSES: u32 = 1;

/// Why a containment step failed. The codes mirror the donor's
/// `VisualParseErrorCode` values this module used.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorCode {
    /// The target or host cannot install every advertised boundary.
    UnsupportedPlatform,
    /// An available facility could not be configured, or the contained
    /// process could not be launched.
    LaunchFailed,
    /// A limit in the spec is zero or out of range.
    ResourceLimitExceeded,
    /// The supervisor lost track of the contained process.
    Crashed,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::LaunchFailed => "launch_failed",
            Self::ResourceLimitExceeded => "resource_limit_exceeded",
            Self::Crashed => "crashed",
        }
    }
}

/// A containment failure. Neither variant executes child code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContainError {
    pub code: ErrorCode,
    pub message: String,
    pub retryable: bool,
    /// An operating-system status only. Paths, arguments and environment
    /// values never reach the caller through a containment failure.
    pub detail: Option<String>,
}

pub(crate) fn error(
    code: ErrorCode,
    message: &str,
    retryable: bool,
    detail: Option<String>,
) -> ContainError {
    ContainError {
        code,
        message: message.to_owned(),
        retryable,
        detail,
    }
}

/// How a memory ceiling is actually enforced on the current target. Each
/// target constructs only its own variant.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryLimitEnforcement {
    /// The kernel refuses allocations past the ceiling.
    Kernel,
    /// The supervisor samples the child's footprint and kills the process
    /// tree once the ceiling is exceeded. An allocation burst that both starts
    /// and completes between two samples is not prevented.
    SupervisorSampling,
    /// No ceiling is installed. The child is not memory bounded.
    None,
}

/// Truthful boundaries installed by the current target implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContainmentCapabilities {
    pub process_tree_cleanup: bool,
    pub parent_death: bool,
    pub parent_eof: bool,
    pub inherited_handle_closure: bool,
    pub memory_limit: MemoryLimitEnforcement,
    pub cpu_limit: bool,
    /// The child cannot create another process at all.
    pub process_creation_denial: bool,
    pub file_descriptor_limit: bool,
    pub filesystem_read_isolation: bool,
    pub filesystem_write_isolation: bool,
    pub network_isolation: bool,
    /// The child cannot read or write another process's memory, attach a
    /// debugger, or steal another process's descriptors.
    pub process_memory_isolation: bool,
    /// The child cannot capture the desktop, synthesize input, install input
    /// hooks, or read the clipboard.
    pub desktop_input_isolation: bool,
}

impl ContainmentCapabilities {
    /// Every boundary the contained tier requires before untrusted child code
    /// may run.
    ///
    /// `file_descriptor_limit` is deliberately absent: Windows Job Objects
    /// expose no per-job handle ceiling, and descriptor exhaustion is bounded
    /// there by the job's memory limit instead.
    pub const fn meets_contract(&self) -> bool {
        self.process_tree_cleanup
            && self.parent_death
            && self.parent_eof
            && self.inherited_handle_closure
            && self.cpu_limit
            && self.process_creation_denial
            && self.filesystem_read_isolation
            && self.filesystem_write_isolation
            && self.network_isolation
            && self.process_memory_isolation
            && self.desktop_input_isolation
            && !matches!(self.memory_limit, MemoryLimitEnforcement::None)
    }
}

/// Capabilities are compile-target facts. Host facilities are still checked at
/// launch and cause a stable fail-closed error when unavailable.
pub const fn capabilities() -> ContainmentCapabilities {
    #[cfg(target_os = "linux")]
    {
        ContainmentCapabilities {
            process_tree_cleanup: true,
            parent_death: true,
            parent_eof: true,
            inherited_handle_closure: true,
            memory_limit: MemoryLimitEnforcement::Kernel,
            cpu_limit: true,
            process_creation_denial: true,
            file_descriptor_limit: true,
            filesystem_read_isolation: true,
            filesystem_write_isolation: true,
            network_isolation: true,
            process_memory_isolation: true,
            desktop_input_isolation: true,
        }
    }
    #[cfg(target_os = "macos")]
    {
        ContainmentCapabilities {
            process_tree_cleanup: true,
            parent_death: true,
            parent_eof: true,
            inherited_handle_closure: true,
            memory_limit: MemoryLimitEnforcement::SupervisorSampling,
            cpu_limit: true,
            process_creation_denial: true,
            file_descriptor_limit: true,
            filesystem_read_isolation: true,
            filesystem_write_isolation: true,
            network_isolation: true,
            process_memory_isolation: true,
            desktop_input_isolation: true,
        }
    }
    #[cfg(windows)]
    {
        ContainmentCapabilities {
            process_tree_cleanup: true,
            parent_death: true,
            parent_eof: true,
            inherited_handle_closure: true,
            memory_limit: MemoryLimitEnforcement::Kernel,
            cpu_limit: true,
            process_creation_denial: true,
            file_descriptor_limit: false,
            filesystem_read_isolation: true,
            filesystem_write_isolation: true,
            network_isolation: true,
            process_memory_isolation: true,
            desktop_input_isolation: true,
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        ContainmentCapabilities {
            process_tree_cleanup: false,
            parent_death: false,
            parent_eof: false,
            inherited_handle_closure: false,
            memory_limit: MemoryLimitEnforcement::None,
            cpu_limit: false,
            process_creation_denial: false,
            file_descriptor_limit: false,
            filesystem_read_isolation: false,
            filesystem_write_isolation: false,
            network_isolation: false,
            process_memory_isolation: false,
            desktop_input_isolation: false,
        }
    }
}

/// Explicit, testable resource ceilings and the exact filesystem roots.
#[derive(Clone, Debug)]
pub struct ContainmentLimits {
    /// Memory ceiling in bytes. Linux applies it to each process's virtual
    /// address space, Windows to the Job Object's total committed memory, and
    /// macOS through supervisor sampling. [`capabilities`] reports which.
    pub max_memory_bytes: u64,
    /// Maximum CPU time the child may accumulate. The soft limit is this value
    /// and the hard limit a short grace period above it, so a child that
    /// exhausts its CPU budget dies with a distinguishable signal.
    pub max_cpu_time: Duration,
    /// Maximum number of open file descriptors on Unix. Windows reports that
    /// it cannot enforce an equivalent per-job handle count.
    pub max_open_files: u32,
    /// Directories the child may write to in addition to its working
    /// directory. Every entry widens the sandbox, so the spec names each one.
    pub additional_writable_paths: Vec<PathBuf>,
    /// Directories the child may read in addition to its working directory and
    /// the target's immutable system runtime directories.
    pub additional_readable_paths: Vec<PathBuf>,
}

impl ContainmentLimits {
    pub(crate) fn validate(&self) -> Result<(), ContainError> {
        if self.max_memory_bytes == 0
            || self.max_cpu_time.as_secs() == 0
            || self.max_open_files == 0
        {
            return Err(error(
                ErrorCode::ResourceLimitExceeded,
                "contained process limits must be non-zero",
                false,
                None,
            ));
        }
        Ok(())
    }

    pub(crate) fn max_cpu_seconds(&self) -> u64 {
        self.max_cpu_time.as_secs().max(1)
    }
}

/// The exact, canonical, symlink-free filesystem boundary handed to a platform
/// sandbox. Directory roots are canonical and executable entries are exact
/// canonical files.
pub(crate) struct FilesystemBoundary {
    /// Directories the child may read from.
    pub(crate) readable: Vec<PathBuf>,
    /// Directories the child may write to.
    pub(crate) writable: Vec<PathBuf>,
    /// Exact files the child may execute or map as executable code. The
    /// executable is also readable, as an exact file and not through its
    /// directory.
    pub(crate) executables: Vec<PathBuf>,
}

/// Derive the child's filesystem boundary from the spec.
///
/// Nothing is derived beyond what the spec names: the working directory, the
/// explicit read and write roots, and the exact executable file. The caller's
/// home directory, credential stores, browser profiles, desktop IPC sockets
/// and the temporary root all stay outside the sandbox unless a root names
/// them, and the broad ones are refused even then.
pub(crate) fn filesystem_boundary(
    executable: &Path,
    working_directory: &Path,
    limits: &ContainmentLimits,
) -> Result<FilesystemBoundary, ContainError> {
    let working_directory = canonical_directory(working_directory)?;
    reject_broad_read_root(&working_directory)?;
    let mut readable = vec![working_directory.clone()];
    let mut writable = vec![working_directory];
    let executables = vec![canonical_file(executable)?];

    for path in &limits.additional_readable_paths {
        let path = canonical_directory(path)?;
        reject_broad_read_root(&path)?;
        readable.push(path);
    }
    for path in &limits.additional_writable_paths {
        let path = canonical_directory(path)?;
        reject_broad_read_root(&path)?;
        readable.push(path.clone());
        writable.push(path);
    }

    Ok(FilesystemBoundary {
        readable: collapse_roots(readable),
        writable: collapse_roots(writable),
        executables,
    })
}

/// The executable as an exact, canonical file. A path that only reaches the
/// file through a symbolic link (or a `..`, or a junction) is refused rather
/// than followed, like the kernel's helper pin.
pub(crate) fn canonical_file(path: &Path) -> Result<PathBuf, ContainError> {
    let given = path;
    let path = std::fs::canonicalize(path).map_err(|cause| {
        containment_error(
            "failed to resolve the contained executable",
            os_detail(&cause),
        )
    })?;
    if !same_path(&path, given) {
        return Err(containment_error(
            "the contained executable is not named by its canonical path (a link or relative part)",
            None,
        ));
    }
    if !path.is_file() {
        return Err(containment_error(
            "the contained executable is not a file",
            None,
        ));
    }
    Ok(path)
}

/// A root must be specific to the task. A shared system directory, a home
/// directory or a filesystem root would hand the child unrelated user data, so
/// those are refused rather than silently widening the sandbox.
pub(crate) fn reject_broad_read_root(path: &Path) -> Result<(), ContainError> {
    let named = path
        .components()
        .filter(|component| matches!(component, Component::Normal(_)))
        .count();
    let parent_is_home_root = path.parent().is_some_and(|parent| {
        matches!(
            parent.to_str(),
            Some(
                "/Users"
                    | "/home"
                    | "/private/Users"
                    | "/var/folders"
                    | "/private/var/folders"
                    | "/root"
            )
        ) || parent
            .file_name()
            .is_some_and(|name| name.eq_ignore_ascii_case("Users"))
    });
    let denied = BROAD_READ_ROOTS
        .iter()
        .any(|entry| path.as_os_str().eq_ignore_ascii_case(*entry));
    if named < 2 || parent_is_home_root || denied {
        return Err(containment_error(
            "a contained path resolves to a directory too broad to grant",
            None,
        ));
    }
    Ok(())
}

/// Shared directories that must never become a root even though they are deep
/// enough to pass the component check.
const BROAD_READ_ROOTS: &[&str] = &[
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/lib64",
    "/usr/libexec",
    "/usr/local",
    "/usr/share",
    "/var/tmp",
    "/var/folders",
    "/private/tmp",
    "/private/var",
    "/System/Library",
    "/Library/Keychains",
    "/Library/Application Support",
    "/etc/ssl",
];

/// A root as an exact, canonical directory. A root that is (or passes
/// through) a symbolic link is refused, not followed: a writable root may
/// create links, so following one would let an earlier run plant
/// `work/out -> ~/.ssh` and have a later spec that names `work/out` grant the
/// target. The platform layer then opens the root without following links
/// and checks it again (Linux `O_PATH | O_NOFOLLOW` plus the fd's own path;
/// Windows no-follow handles plus the final path), closing the window between
/// this check and the grant.
pub(crate) fn canonical_directory(path: &Path) -> Result<PathBuf, ContainError> {
    let resolved = std::fs::canonicalize(path).map_err(|cause| {
        containment_error(
            "failed to resolve a contained sandbox directory",
            os_detail(&cause),
        )
    })?;
    if !same_path(&resolved, path) {
        return Err(containment_error(
            "a contained sandbox root is not named by its canonical path (a link or relative part)",
            None,
        ));
    }
    if !resolved.is_dir() {
        return Err(containment_error(
            "a contained sandbox path is not a directory",
            None,
        ));
    }
    Ok(resolved)
}

/// Whether `canonical` (from `canonicalize`) names exactly `given`. Windows
/// compares without the `\\?\` prefix and without case, as the filesystem
/// does; Unix compares bytes.
pub(crate) fn same_path(canonical: &Path, given: &Path) -> bool {
    #[cfg(windows)]
    {
        let strip = |path: &Path| {
            let text = path.to_string_lossy().replace('/', "\\");
            text.strip_prefix(r"\\?\")
                .map_or(text.clone(), str::to_owned)
                .trim_end_matches('\\')
                .to_ascii_lowercase()
        };
        strip(canonical) == strip(given)
    }
    #[cfg(not(windows))]
    {
        canonical == given
    }
}

/// Drop duplicates and any root already covered by an ancestor, so a platform
/// installs the smallest equivalent rule set.
pub(crate) fn collapse_roots(mut roots: Vec<PathBuf>) -> Vec<PathBuf> {
    roots.sort();
    roots.dedup();
    let mut collapsed: Vec<PathBuf> = Vec::with_capacity(roots.len());
    for root in roots {
        if collapsed.iter().any(|kept| root.starts_with(kept)) {
            continue;
        }
        collapsed.push(root);
    }
    collapsed
}

/// The raw operating-system result of a child exit, before the guard folds in
/// supervisor state such as a sampled memory kill.
pub(crate) struct RawExit {
    pub(crate) success: bool,
    /// The operating system itself ended the process for exhausting a
    /// containment ceiling.
    pub(crate) resource_limited: bool,
    /// The exit code, or the terminating signal on Unix (see `signaled`).
    pub(crate) code: i64,
    pub(crate) signaled: bool,
}

/// How the child process finished.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChildExit {
    Exited(i64),
    Signaled(i64),
    /// A containment ceiling (CPU time or memory) ended the child.
    ResourceLimit,
}

/// A launched child process plus the platform handles that bound it.
///
/// Field order is load-bearing: `guard` is declared first so it drops first,
/// tearing down the whole process tree before the process handle is reaped
/// and before the stdio pipes close.
pub(crate) struct ContainedChild {
    pub(crate) guard: platform::Guard,
    pub(crate) process: platform::Process,
    pub(crate) stdin: Option<ChildStdin>,
    pub(crate) stdout: Option<ChildStdout>,
    pub(crate) stderr: Option<ChildStderr>,
}

impl ContainedChild {
    /// Wait for the child to exit and classify how it ended.
    pub(crate) async fn wait(&mut self) -> std::io::Result<ChildExit> {
        let raw = self.process.wait().await?;
        // The process table entry is gone, so a later process-group signal
        // could reach a recycled group id. Platforms that cannot prove the
        // group is still occupied stop signalling it here.
        #[cfg(windows)]
        self.guard.note_reaped()?;
        #[cfg(not(windows))]
        self.guard.note_reaped();
        Ok(
            if raw.resource_limited || self.guard.memory_ceiling_exceeded() {
                ChildExit::ResourceLimit
            } else if raw.signaled {
                ChildExit::Signaled(raw.code)
            } else {
                debug_assert_eq!(raw.success, raw.code == 0);
                ChildExit::Exited(raw.code)
            },
        )
    }
}

/// Launch the child under full platform containment.
///
/// Returns [`ErrorCode::UnsupportedPlatform`] when the target or host lacks a
/// required containment facility and [`ErrorCode::LaunchFailed`] when an
/// available facility cannot be configured or the contained process cannot be
/// launched. Neither case executes child code.
pub(crate) async fn spawn(
    executable: &Path,
    args: &[String],
    working_directory: &Path,
    limits: &ContainmentLimits,
) -> Result<ContainedChild, ContainError> {
    spawn_checked(capabilities(), executable, args, working_directory, limits).await
}

/// [`spawn`] with the capability report as a parameter, so the fail-closed
/// branch is testable on every target.
pub(crate) async fn spawn_checked(
    reported: ContainmentCapabilities,
    executable: &Path,
    args: &[String],
    working_directory: &Path,
    limits: &ContainmentLimits,
) -> Result<ContainedChild, ContainError> {
    limits.validate()?;
    if !reported.meets_contract() {
        return Err(unsupported_error(
            "this platform cannot install every contained-tier boundary, so nothing is launched",
        ));
    }
    let boundary = filesystem_boundary(executable, working_directory, limits)?;
    // Launch through the same canonical names the platform policy contains.
    // This is load-bearing on macOS, where `/var` is a symlink to
    // `/private/var` and Seatbelt evaluates the path used by `exec`.
    let executable = canonical_file(executable)?;
    let working_directory = canonical_directory(working_directory)?;
    platform::spawn(&executable, args, &working_directory, &boundary, limits).await
}

/// How a one-shot contained run finished.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunOutcome {
    Exited(i64),
    Signaled(i64),
    /// A containment ceiling (CPU time or memory) ended the child.
    ResourceLimit,
    /// The child outlived its deadline, so its process tree was killed and
    /// reaped before this returned.
    TimedOut,
    /// The child wrote more than its stdout or stderr bound, so its tree was
    /// killed; the first `bound` bytes are kept.
    OutputLimit(Stream),
    /// The supervising parent (orceld) went away, so the tree was killed.
    ParentGone,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stream {
    Stdout,
    Stderr,
}

/// A finished run: the outcome and the bounded output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunResult {
    pub outcome: RunOutcome,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Bounds for one run that are not boundaries: deadline and output sizes.
#[derive(Clone, Copy, Debug)]
pub struct RunBounds {
    pub timeout: Duration,
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
}

/// How long the killed process tree is given to be reaped after a deadline,
/// so the helper leaves no zombie behind.
const TERMINATION_GRACE: Duration = Duration::from_secs(5);

/// Run one contained process to completion.
///
/// The child's stdin is closed immediately, so it observes end of file just as
/// a null stdin would. Its stdout and stderr are read concurrently, each up to
/// its bound; one byte past a bound kills the tree. `parent_gone` resolves when
/// the supervising parent closes the helper's stdin, which also kills the
/// tree.
///
/// Containment that cannot be installed is an error rather than a weaker
/// launch, so no child instruction runs before every boundary is in place.
pub async fn run(
    executable: &Path,
    args: &[String],
    working_directory: &Path,
    limits: &ContainmentLimits,
    bounds: RunBounds,
    parent_gone: impl std::future::Future<Output = ()>,
) -> Result<RunResult, ContainError> {
    if bounds.timeout.is_zero() {
        return Err(error(
            ErrorCode::ResourceLimitExceeded,
            "a contained run deadline must be non-zero",
            false,
            None,
        ));
    }
    let mut contained = spawn(executable, args, working_directory, limits).await?;
    supervise(&mut contained, bounds, parent_gone).await
}

async fn supervise(
    contained: &mut ContainedChild,
    bounds: RunBounds,
    parent_gone: impl std::future::Future<Output = ()>,
) -> Result<RunResult, ContainError> {
    // Closing the request pipe is what makes the child observe end of file.
    drop(contained.stdin.take());
    let mut stdout = contained.stdout.take();
    let mut stderr = contained.stderr.take();
    let mut out = Vec::new();
    let mut err = Vec::new();

    enum Ended {
        Exit(std::io::Result<ChildExit>),
        Output(Stream),
        Deadline,
        Parent,
    }

    let ended = {
        let collect = async {
            // Both pipes are read concurrently, and the first byte past either
            // bound ends collection at once: waiting for the other pipe's end
            // of file would let a child hold it open until the deadline.
            let mut out_open = stdout.is_some();
            let mut err_open = stderr.is_some();
            let mut out_chunk = [0_u8; 8 * 1024];
            let mut err_chunk = [0_u8; 8 * 1024];
            while out_open || err_open {
                tokio::select! {
                    read = read_chunk(&mut stdout, &mut out_chunk), if out_open => match read {
                        Ok(0) | Err(_) => out_open = false,
                        Ok(count) => {
                            out.extend_from_slice(&out_chunk[..count]);
                            if out.len() > bounds.stdout_bytes {
                                return Err(Stream::Stdout);
                            }
                        }
                    },
                    read = read_chunk(&mut stderr, &mut err_chunk), if err_open => match read {
                        Ok(0) | Err(_) => err_open = false,
                        Ok(count) => {
                            err.extend_from_slice(&err_chunk[..count]);
                            if err.len() > bounds.stderr_bytes {
                                return Err(Stream::Stderr);
                            }
                        }
                    },
                }
            }
            Ok(())
        };
        let finish = async {
            // Both pipes reach end of file (or one overflows) before the exit
            // is collected, so no output written just before exit is lost.
            collect.await?;
            Ok(contained.wait().await)
        };
        tokio::select! {
            biased;
            () = parent_gone => Ended::Parent,
            result = tokio::time::timeout(bounds.timeout, finish) => match result {
                Ok(Ok(exit)) => Ended::Exit(exit),
                Ok(Err(stream)) => Ended::Output(stream),
                Err(_) => Ended::Deadline,
            },
        }
    };

    let outcome = match ended {
        Ended::Exit(Ok(ChildExit::Exited(code))) => RunOutcome::Exited(code),
        Ended::Exit(Ok(ChildExit::Signaled(signal))) => RunOutcome::Signaled(signal),
        Ended::Exit(Ok(ChildExit::ResourceLimit)) => RunOutcome::ResourceLimit,
        Ended::Exit(Err(cause)) => {
            return Err(error(
                ErrorCode::Crashed,
                "failed to supervise the contained process",
                false,
                os_detail(&cause),
            ))
        }
        Ended::Output(stream) => RunOutcome::OutputLimit(stream),
        Ended::Deadline => RunOutcome::TimedOut,
        Ended::Parent => RunOutcome::ParentGone,
    };
    if !matches!(
        outcome,
        RunOutcome::Exited(_) | RunOutcome::Signaled(_) | RunOutcome::ResourceLimit
    ) {
        terminate(contained).await;
    }
    out.truncate(bounds.stdout_bytes);
    err.truncate(bounds.stderr_bytes);
    Ok(RunResult {
        outcome,
        stdout: out,
        stderr: err,
    })
}

/// Read one chunk from `pipe`; an absent pipe reads as end of file. `read` is
/// cancel-safe, so losing a `select!` race drops no bytes.
async fn read_chunk<R: tokio::io::AsyncRead + Unpin>(
    pipe: &mut Option<R>,
    chunk: &mut [u8],
) -> std::io::Result<usize> {
    match pipe {
        Some(pipe) => pipe.read(chunk).await,
        None => Ok(0),
    }
}

/// Tear a contained process tree down through its platform guard and reap it.
///
/// The guard kills the tree; the process handle is then awaited within a
/// bounded grace period. The guard itself is dropped with the child.
async fn terminate(contained: &mut ContainedChild) {
    contained.guard.kill_tree();
    let _ = tokio::time::timeout(TERMINATION_GRACE, contained.process.wait()).await;
}

/// A launch failure that is deterministic for this host: retrying cannot make
/// the containment facility appear.
pub(crate) fn containment_error(message: &str, detail: Option<String>) -> ContainError {
    error(ErrorCode::LaunchFailed, message, false, detail)
}

/// A platform or host that cannot install the full containment contract.
pub(crate) fn unsupported_error(message: &str) -> ContainError {
    error(ErrorCode::UnsupportedPlatform, message, false, None)
}

/// Error detail is limited to an operating-system status. Paths, arguments and
/// environment values never reach the caller through a containment failure.
#[allow(dead_code)]
pub(crate) fn os_detail(cause: &std::io::Error) -> Option<String> {
    Some(match cause.raw_os_error() {
        Some(code) => format!("os error {code}"),
        None => "os error unavailable".to_owned(),
    })
}

#[allow(dead_code)]
pub(crate) fn spawn_error(cause: std::io::Error) -> ContainError {
    error(
        ErrorCode::LaunchFailed,
        "failed to launch the contained process",
        false,
        os_detail(&cause),
    )
}

#[cfg(test)]
#[path = "containment_tests.rs"]
mod tests;
