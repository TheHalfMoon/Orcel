// SPDX-License-Identifier: MIT
// Portions copyright (c) 2025 Cua AI, Inc.; modifications copyright Orcel.

//! Linux containment: process group, parent-death signal, resource limits,
//! `PR_SET_NO_NEW_PRIVS`, a Landlock ruleset that confines reads, executes
//! and writes to an exact allowlist, and a seccomp filter that denies every
//! socket, `io_uring`, process creation, debugger attachment and
//! cross-process memory access.
//!
//! Landlock and seccomp are the two unprivileged kernel facilities a parent can
//! install on a child without root or a namespace. Neither is sufficient alone:
//!
//! - Landlock has no hook for `unix_stream_connect` through ABI 5, so it cannot
//!   stop the child from reaching the X11, Wayland, D-Bus or `ssh-agent`
//!   sockets. The seccomp filter denies socket creation outright instead, which
//!   removes every route — local and external — because the child also
//!   inherits no descriptors.
//! - seccomp cannot express a path policy, and it does not see `io_uring`'s
//!   asynchronous operations at all, which is why `io_uring_setup` is denied
//!   rather than filtered.
//!
//! Both are prepared in the parent so that a kernel without them fails the
//! launch with a stable error instead of degrading silently. No namespace of
//! any type is created, so a systemd unit with `RestrictNamespaces=yes` does
//! not affect this helper (issue #369, item 1).
//!
//! What "exact executable" means here: Landlock grants `EXECUTE` to the one
//! spec executable and to the immutable system trees (which hold the ELF
//! interpreter), and nowhere else; writable roots are never executable. It
//! limits which file `execve` may start, not which bytes may run: Landlock
//! does not mediate `mmap(PROT_EXEC)`, so code read from a readable root can
//! be mapped by hand or through the system loader (`ld.so <file>`), and
//! `memfd_create` + `execveat` is not denied. None of that escapes the
//! sandbox: `execve` keeps the same Landlock domain, seccomp filter, rlimits
//! and process group, and process creation stays denied. The guarantee is
//! the boundary, not code integrity. `/usr/libexec` is executable only
//! because it is one of the fixed system trees.
//!
//! Provenance (T-CUA-22, COPY_ADAPT): adapted from
//! cua@a802eaf26ca97616a6bf0de6a29729a9346fbb1f
//! `libs/cua-driver/rust/crates/cua-driver-core/src/perception_client/containment/linux.rs`
//! (blob 9c1e66bb95351fe87272b53168389b600430ae97), MIT; notice in
//! `docs/orcel/notices/cua-MIT.txt`. Orcel's changes: stderr is a third piped
//! stream; the ruleset builder takes the probed Landlock ABI as a parameter so
//! the refusal branches are testable; messages name the contained process
//! instead of the perception worker; the unit tests moved to `linux_tests.rs`.

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::Path;

use crate::containment::{
    containment_error, os_detail, spawn_error, unsupported_error, ContainError, ContainedChild,
    ContainmentLimits, FilesystemBoundary,
};
use crate::unix::{apply_resource_limits, base_command, ProcessGroupGuard};

pub(crate) type Guard = ProcessGroupGuard;
pub(crate) type Process = crate::unix::Process;
pub(crate) type ChildStdin = tokio::process::ChildStdin;
pub(crate) type ChildStdout = tokio::process::ChildStdout;
pub(crate) type ChildStderr = tokio::process::ChildStderr;

const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;
const SYS_CLOSE_RANGE: libc::c_long = 436;
const CLOSE_RANGE_CLOEXEC: u32 = 1 << 2;

const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;
const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
/// Landlock ABI 2.
const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
/// Landlock ABI 3.
const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;

/// Every filesystem right Landlock ABI 1-3 can restrict. Handling all of them
/// means the ruleset denies reads, executes and writes by default; a path is
/// reachable only through an explicit rule below.
const LANDLOCK_HANDLED_ACCESS: u64 = LANDLOCK_ACCESS_FS_EXECUTE
    | LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_READ_FILE
    | LANDLOCK_ACCESS_FS_READ_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_FILE
    | LANDLOCK_ACCESS_FS_MAKE_CHAR
    | LANDLOCK_ACCESS_FS_MAKE_DIR
    | LANDLOCK_ACCESS_FS_MAKE_REG
    | LANDLOCK_ACCESS_FS_MAKE_SOCK
    | LANDLOCK_ACCESS_FS_MAKE_FIFO
    | LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | LANDLOCK_ACCESS_FS_MAKE_SYM
    | LANDLOCK_ACCESS_FS_REFER
    | LANDLOCK_ACCESS_FS_TRUNCATE;

/// Read a directory tree without making every file beneath it executable.
const LANDLOCK_READ_TREE: u64 = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
/// Immutable system trees contain the ELF interpreter used during `execve`.
/// They remain executable, while caller-controlled readable/writable roots do
/// not acquire this right.
const LANDLOCK_SYSTEM_READ_TREE: u64 = LANDLOCK_READ_TREE | LANDLOCK_ACCESS_FS_EXECUTE;
/// Read a single file. Directory-only rights would make `landlock_add_rule`
/// reject a rule whose target is not a directory.
const LANDLOCK_READ_FILE_ONLY: u64 = LANDLOCK_ACCESS_FS_READ_FILE;
/// Execute one exact, prevalidated child entry point.
const LANDLOCK_EXECUTABLE_FILE: u64 = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_EXECUTE;
/// Writable workspace trees remain readable and may create/remove entries, but
/// code written there must never become executable inside the child.
const LANDLOCK_WRITABLE_TREE: u64 = LANDLOCK_HANDLED_ACCESS & !LANDLOCK_ACCESS_FS_EXECUTE;
/// Read and write one character device, without being able to create, replace
/// or remove anything beside it.
const LANDLOCK_DEVICE_ACCESS: u64 =
    LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_TRUNCATE;

/// Immutable system directories the native loader and inference runtime read.
/// Each is optional: a distribution that does not have one simply contributes
/// no rule. None of them expose user data.
const SYSTEM_READ_TREES: &[&str] = &[
    "/lib",
    "/lib64",
    "/usr/lib",
    "/usr/lib64",
    "/usr/lib32",
    "/usr/libexec",
    "/etc/ld.so.conf.d",
    "/sys/devices/system/cpu",
];

/// Exact system files the loader and allocator read. Whole-directory rules for
/// `/etc`, `/proc` and `/sys` would expose credentials and other processes, so
/// only these files are granted.
const SYSTEM_READ_FILES: &[&str] = &[
    "/etc/ld.so.cache",
    "/etc/ld.so.conf",
    "/etc/ld.so.preload",
    "/proc/cpuinfo",
    "/proc/meminfo",
    "/proc/stat",
    "/proc/sys/vm/overcommit_memory",
    "/proc/sys/vm/max_map_count",
];

/// The only devices the child may open. A rule beneath `/dev` itself would let
/// a child running as root reach `/dev/mem` or a raw block device.
const DEVICE_NODES: &[&str] = &[
    "/dev/null",
    "/dev/zero",
    "/dev/full",
    "/dev/random",
    "/dev/urandom",
];

const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 1;
const SECCOMP_GET_ACTION_AVAIL: libc::c_ulong = 2;

const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_KILL_THREAD: u32 = 0x0000_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_ALU: u16 = 0x04;
const BPF_AND: u16 = 0x50;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
// Only x86_64 needs an ordered compare (the x32 syscall-number range check).
#[cfg(target_arch = "x86_64")]
const BPF_JGE: u16 = 0x30;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

/// Offsets into `struct seccomp_data`.
const SECCOMP_DATA_NR: u32 = 0;
const SECCOMP_DATA_ARCH: u32 = 4;
/// Low half of `args[0]` on a little-endian target.
const SECCOMP_DATA_ARG0_LOW: u32 = 16;

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xC000_00B7;
/// x32 shares `AUDIT_ARCH_X86_64` but renumbers its syscalls, so a filter
/// written against the 64-bit table does not describe it.
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}

// The kernel declares `landlock_path_beneath_attr` as packed; an unpacked
// layout would add four bytes of tail padding and be rejected.
#[repr(C, packed)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

pub(crate) async fn spawn(
    executable: &Path,
    args: &[String],
    working_directory: &Path,
    boundary: &FilesystemBoundary,
    limits: &ContainmentLimits,
) -> Result<ContainedChild, ContainError> {
    // Both rulesets are built in the parent so an unsupported kernel or
    // architecture is reported explicitly rather than as an opaque
    // `pre_exec` failure after the point of no return.
    let ruleset = build_landlock_ruleset(landlock_abi(), boundary)?;
    let mut filter = build_seccomp_filter()?;

    let mut command = base_command(executable, working_directory);
    command.args(args).current_dir(working_directory);
    command.process_group(0);

    let max_memory_bytes = limits.max_memory_bytes;
    let max_cpu_seconds = limits.max_cpu_seconds();
    let max_open_files = limits.max_open_files;
    // Runs between fork and exec. Every call below is a raw syscall, nothing
    // allocates, and both the ruleset descriptor and the filter program were
    // materialized before the fork.
    // SAFETY: `pre_exec` runs in the forked child before exec, where only async-signal-safe
    // work is allowed. The closure makes only raw syscalls (getppid, prctl, raise, getrlimit/setrlimit,
    // landlock_restrict_self, close_range, seccomp) and one in-place store into the prebuilt
    // filter Vec; it allocates nothing and takes no lock. The ruleset fd and the filter were
    // created before the fork and are owned by the closure, so both are valid in the child.
    unsafe {
        command.as_std_mut().pre_exec(move || {
            let parent = libc::getppid();
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // The parent may have exited between the fork and the prctl, in
            // which case the death signal was already missed.
            if libc::getppid() != parent {
                libc::raise(libc::SIGKILL);
            }
            apply_resource_limits(Some(max_memory_bytes), max_cpu_seconds, max_open_files)?;
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::syscall(
                SYS_LANDLOCK_RESTRICT_SELF,
                ruleset.as_raw_fd(),
                0 as libc::c_ulong,
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            // Mark every non-stdio descriptor close-on-exec. This includes
            // descriptors inherited from the host and closes the otherwise
            // serious bypass where an already-open file or socket survives
            // into the child past Landlock/seccomp installation.
            if libc::syscall(SYS_CLOSE_RANGE, 3_u32, u32::MAX, CLOSE_RANGE_CLOEXEC) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Classic seccomp cannot compare an argument with the caller's
            // dynamic TGID. Patch the prebuilt comparison after fork, before
            // installing it, so `tgkill` remains available to the child's
            // own threads without becoming a same-UID signalling primitive.
            filter.instructions[filter.child_tgid_instruction].k = libc::getpid() as u32;
            let program = SockFprog {
                len: filter.instructions.len() as u16,
                filter: filter.instructions.as_ptr(),
            };
            if libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_SET_MODE_FILTER,
                0 as libc::c_ulong,
                &program as *const SockFprog,
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = command.spawn().map_err(spawn_error)?;
    let stdin = child.stdin.take();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    // seccomp denies `fork`, `clone` without `CLONE_THREAD`, `setsid` and
    // `setpgid`, so the child is provably the only member of its process
    // group and the group is empty once it is reaped.
    let guard = ProcessGroupGuard::new(child.id(), false);
    Ok(ContainedChild {
        guard,
        process: Process::new(child),
        stdin,
        stdout,
        stderr,
    })
}

pub(crate) fn landlock_abi() -> Option<u32> {
    // SAFETY: the version query takes no attribute and writes nothing.
    let abi = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<LandlockRulesetAttr>(),
            0 as libc::size_t,
            LANDLOCK_CREATE_RULESET_VERSION as libc::c_ulong,
        )
    };
    u32::try_from(abi).ok().filter(|abi| *abi >= 1)
}

/// Build the ruleset for the probed Landlock ABI (`None` when the kernel has
/// no Landlock at all). A missing or too-old ABI is a refusal, never a
/// weaker ruleset.
pub(crate) fn build_landlock_ruleset(
    abi: Option<u32>,
    boundary: &FilesystemBoundary,
) -> Result<OwnedFd, ContainError> {
    let Some(abi) = abi else {
        return Err(unsupported_error(
            "this Linux kernel does not provide the Landlock filesystem containment the contained process requires",
        ));
    };
    if abi < 3 {
        return Err(unsupported_error(
            "this Linux kernel cannot restrict file truncation for the contained process",
        ));
    }

    let attribute = LandlockRulesetAttr {
        handled_access_fs: LANDLOCK_HANDLED_ACCESS,
    };
    // SAFETY: `attribute` is a live, correctly sized `landlock_ruleset_attr` and the size
    // argument is its exact size; the kernel only reads it and returns a new fd or -1.
    let ruleset = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            &attribute as *const LandlockRulesetAttr,
            std::mem::size_of::<LandlockRulesetAttr>() as libc::size_t,
            0 as libc::c_ulong,
        )
    };
    let ruleset = RawFd::try_from(ruleset)
        .ok()
        .filter(|fd| *fd >= 0)
        .ok_or_else(|| {
            containment_error(
                "failed to create the Landlock ruleset for the contained process",
                os_detail(&std::io::Error::last_os_error()),
            )
        })?;
    // SAFETY: `ruleset` was checked to be a non-negative descriptor just returned by
    // landlock_create_ruleset, and nothing else owns it, so `OwnedFd` takes sole ownership.
    let ruleset = unsafe { OwnedFd::from_raw_fd(ruleset) };

    // Writable roots are readable but intentionally non-executable. Model
    // artifacts can be memory-mapped without granting execution of bytes the
    // child created or modified.
    for path in &boundary.writable {
        add_rule(&ruleset, path, LANDLOCK_WRITABLE_TREE, true)?;
    }
    for path in &boundary.readable {
        add_rule(&ruleset, path, LANDLOCK_READ_TREE, true)?;
    }
    for path in &boundary.executables {
        add_rule(&ruleset, path, LANDLOCK_EXECUTABLE_FILE, true)?;
    }
    for path in SYSTEM_READ_TREES {
        add_rule(&ruleset, Path::new(path), LANDLOCK_SYSTEM_READ_TREE, false)?;
    }
    for path in SYSTEM_READ_FILES {
        add_rule(&ruleset, Path::new(path), LANDLOCK_READ_FILE_ONLY, false)?;
    }
    for path in DEVICE_NODES {
        add_rule(&ruleset, Path::new(path), LANDLOCK_DEVICE_ACCESS, false)?;
    }
    Ok(ruleset)
}

fn add_rule(
    ruleset: &OwnedFd,
    path: &Path,
    allowed_access: u64,
    required: bool,
) -> Result<(), ContainError> {
    let Some(parent) = open_path(path, required)? else {
        return Ok(());
    };
    let attribute = LandlockPathBeneathAttr {
        allowed_access,
        parent_fd: parent.as_raw_fd(),
    };
    // SAFETY: `ruleset` and `parent` are open descriptors owned by this function, and
    // `attribute` is a live packed `landlock_path_beneath_attr`, the exact layout the kernel
    // reads for LANDLOCK_RULE_PATH_BENEATH; flags is 0.
    let added = unsafe {
        libc::syscall(
            SYS_LANDLOCK_ADD_RULE,
            ruleset.as_raw_fd(),
            LANDLOCK_RULE_PATH_BENEATH as libc::c_ulong,
            &attribute as *const LandlockPathBeneathAttr,
            0 as libc::c_ulong,
        )
    };
    if added != 0 {
        return Err(containment_error(
            "failed to grant a path in the Landlock ruleset for the contained process",
            os_detail(&std::io::Error::last_os_error()),
        ));
    }
    Ok(())
}

fn open_path(path: &Path, required: bool) -> Result<Option<OwnedFd>, ContainError> {
    let raw = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        containment_error(
            "a path for the Linux child sandbox contains an interior NUL",
            None,
        )
    })?;
    // `O_PATH` resolves the object without opening it for I/O. The system
    // trees (`required == false`) are followed deliberately: on most
    // distributions they are links to their merged-`/usr` targets, and they
    // are fixed, root-owned paths. Spec roots and the executable
    // (`required == true`) are never followed: `O_NOFOLLOW` refuses a link in
    // the last component, and the fd's own path must equal the canonical path
    // checked in `containment.rs`, which catches a link swapped into any
    // earlier component after that check. The rule is then added through this
    // fd, so what was checked is exactly what is granted.
    let flags = if required {
        libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC
    } else {
        libc::O_PATH | libc::O_CLOEXEC
    };
    // SAFETY: `raw` is a NUL-terminated CString that outlives the call; open with O_PATH does
    // no I/O and returns a new descriptor or -1.
    let fd = unsafe { libc::open(raw.as_ptr(), flags) };
    if fd < 0 {
        if !required {
            return Ok(None);
        }
        return Err(containment_error(
            "failed to open a path for the Linux child sandbox",
            os_detail(&std::io::Error::last_os_error()),
        ));
    }
    // SAFETY: `fd` is a non-negative descriptor this function just opened and has not shared,
    // so `OwnedFd` takes sole ownership.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    if required {
        verify_unfollowed(&fd, path)?;
    }
    Ok(Some(fd))
}

/// The opened object is not a link and the kernel names it by exactly `path`.
fn verify_unfollowed(fd: &OwnedFd, path: &Path) -> Result<(), ContainError> {
    let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `fd` is an open O_PATH descriptor (fstat accepts those since Linux 3.6) and
    // `status` is a writable stat buffer.
    if unsafe { libc::fstat(fd.as_raw_fd(), status.as_mut_ptr()) } != 0 {
        return Err(containment_error(
            "failed to inspect a path for the Linux child sandbox",
            os_detail(&std::io::Error::last_os_error()),
        ));
    }
    // SAFETY: fstat returned 0, so it filled the whole struct.
    let status = unsafe { status.assume_init() };
    if status.st_mode & libc::S_IFMT == libc::S_IFLNK {
        return Err(containment_error(
            "a Linux child sandbox root is a symbolic link",
            None,
        ));
    }
    // `/proc` is required: without it the fd's path cannot be checked, and
    // the launch fails closed.
    let named =
        std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).map_err(|cause| {
            containment_error(
                "failed to read back a path for the Linux child sandbox",
                os_detail(&cause),
            )
        })?;
    if named != path {
        return Err(containment_error(
            "a Linux child sandbox root changed after it was checked",
            None,
        ));
    }
    Ok(())
}

/// Syscalls the child may never make, on every architecture this filter
/// supports.
///
/// The network group is complete rather than domain-filtered: an `AF_UNIX`
/// endpoint reaches the X11, Wayland, D-Bus and `ssh-agent` sockets, which is
/// desktop capture, input injection and credential authority, so the child
/// gets no socket at all. The `io_uring` group is denied because seccomp does
/// not see the operations submitted through a ring, which would otherwise
/// reopen every route above.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn denied_syscalls() -> Vec<libc::c_long> {
    let denied = vec![
        // Sockets: creation, connection and every operation on one.
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_sendto,
        libc::SYS_recvfrom,
        libc::SYS_sendmsg,
        libc::SYS_recvmsg,
        libc::SYS_sendmmsg,
        libc::SYS_recvmmsg,
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        libc::SYS_setsockopt,
        libc::SYS_getsockopt,
        libc::SYS_shutdown,
        // io_uring: an unfiltered asynchronous path to all of the above.
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        // Debugger attachment and cross-process memory or descriptor access.
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_kcmp,
        libc::SYS_pidfd_open,
        libc::SYS_pidfd_getfd,
        libc::SYS_pidfd_send_signal,
        // Signalling an unrelated process or the whole session. `tgkill` is
        // handled separately so only this child's TGID is admitted; `tkill`
        // has no TGID argument and therefore cannot be constrained safely.
        libc::SYS_kill,
        libc::SYS_tkill,
        libc::SYS_rt_sigqueueinfo,
        libc::SYS_rt_tgsigqueueinfo,
        // Filesystem policy escapes: a file handle bypasses path resolution,
        // and a mount changes what a Landlock path even refers to.
        libc::SYS_name_to_handle_at,
        libc::SYS_open_by_handle_at,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        // Namespaces, kernel objects and keyrings.
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_userfaultfd,
        libc::SYS_add_key,
        libc::SYS_keyctl,
        libc::SYS_request_key,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_kexec_load,
        libc::SYS_kexec_file_load,
        libc::SYS_reboot,
        libc::SYS_syslog,
        libc::SYS_acct,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_quotactl,
        // Execution-environment changes, including disabling ASLR.
        libc::SYS_personality,
        // The child must remain its own process-group leader so the guard can
        // always reap it.
        libc::SYS_setsid,
        libc::SYS_setpgid,
    ];
    // Process creation. Runtime threads stay available through the
    // `CLONE_THREAD` rule in the assembled filter.
    #[cfg(target_arch = "x86_64")]
    let denied: Vec<_> = denied
        .into_iter()
        .chain([libc::SYS_fork, libc::SYS_vfork])
        .collect();
    denied
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn build_seccomp_filter() -> Result<SeccompFilter, ContainError> {
    Err(unsupported_error(
        "the contained process has no seccomp containment for this Linux architecture",
    ))
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn build_seccomp_filter() -> Result<SeccompFilter, ContainError> {
    if !seccomp_action_available(SECCOMP_RET_ERRNO) {
        return Err(unsupported_error(
            "this Linux kernel does not provide the seccomp containment the contained process requires",
        ));
    }
    // A foreign audit architecture means the syscall numbers below do not
    // describe the calling ABI, so the safe response is to stop the process
    // rather than let an unfiltered syscall through.
    let mismatch = if seccomp_action_available(SECCOMP_RET_KILL_PROCESS) {
        SECCOMP_RET_KILL_PROCESS
    } else {
        SECCOMP_RET_KILL_THREAD
    };
    Ok(assemble_seccomp_filter(mismatch))
}

/// Assemble the BPF program. Kept free of host probes so its shape can be
/// asserted on any machine.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn assemble_seccomp_filter(mismatch: u32) -> SeccompFilter {
    let denied = SECCOMP_RET_ERRNO | (libc::EPERM as u32 & 0xffff);
    let unavailable = SECCOMP_RET_ERRNO | (libc::ENOSYS as u32 & 0xffff);

    let mut filter = vec![
        load(SECCOMP_DATA_ARCH),
        jump_equal(AUDIT_ARCH, 1, 0),
        ret(mismatch),
        load(SECCOMP_DATA_NR),
    ];
    #[cfg(target_arch = "x86_64")]
    filter.extend([jump_at_least(X32_SYSCALL_BIT, 0, 1), ret(mismatch)]);
    for number in denied_syscalls() {
        filter.extend([jump_equal(number as u32, 0, 1), ret(denied)]);
    }
    filter.extend([
        jump_equal(libc::SYS_tgkill as u32, 0, 4),
        load(SECCOMP_DATA_ARG0_LOW),
        // Filled with the child TGID between fork and filter installation.
        jump_equal(0, 1, 0),
        ret(denied),
        load(SECCOMP_DATA_NR),
    ]);
    let child_tgid_instruction = filter.len() - 3;
    filter.extend([
        // Do not let the child clear the parent-death signal installed just
        // before this filter. Other prctl operations (for example thread names)
        // remain available.
        jump_equal(libc::SYS_prctl as u32, 0, 4),
        load(SECCOMP_DATA_ARG0_LOW),
        jump_equal(libc::PR_SET_PDEATHSIG as u32, 0, 1),
        ret(denied),
        load(SECCOMP_DATA_NR),
        // Returning ENOSYS for clone3 makes pthread implementations fall back
        // to clone, whose flags seccomp can inspect directly.
        jump_equal(libc::SYS_clone3 as u32, 0, 1),
        ret(unavailable),
        jump_equal(libc::SYS_clone as u32, 0, 4),
        load(SECCOMP_DATA_ARG0_LOW),
        and(libc::CLONE_THREAD as u32),
        jump_equal(libc::CLONE_THREAD as u32, 1, 0),
        ret(denied),
        load(SECCOMP_DATA_NR),
        ret(SECCOMP_RET_ALLOW),
    ]);
    SeccompFilter {
        instructions: filter,
        child_tgid_instruction,
    }
}

struct SeccompFilter {
    instructions: Vec<SockFilter>,
    child_tgid_instruction: usize,
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn seccomp_action_available(action: u32) -> bool {
    // SAFETY: SECCOMP_GET_ACTION_AVAIL only reads the u32 behind the pointer, which points at
    // the live `action` local for the duration of the call.
    unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_GET_ACTION_AVAIL,
            0 as libc::c_ulong,
            &action as *const u32,
        ) == 0
    }
}

fn load(offset: u32) -> SockFilter {
    SockFilter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: offset,
    }
}

fn jump_equal(value: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt,
        jf,
        k: value,
    }
}

#[cfg(target_arch = "x86_64")]
fn jump_at_least(value: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter {
        code: BPF_JMP | BPF_JGE | BPF_K,
        jt,
        jf,
        k: value,
    }
}

fn and(value: u32) -> SockFilter {
    SockFilter {
        code: BPF_ALU | BPF_AND | BPF_K,
        jt: 0,
        jf: 0,
        k: value,
    }
}

fn ret(action: u32) -> SockFilter {
    SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: action,
    }
}

#[cfg(test)]
#[path = "linux_tests.rs"]
mod tests;
