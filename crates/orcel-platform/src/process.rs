//! XP-03 process identity: a pid bound to its start generation.
//!
//! A pid alone names whichever process holds it now; once a process exits
//! its pid can be handed to an unrelated one. [`start_generation`] reads a
//! kernel fact that differs between the two, so a caller that records a
//! [`ProcessGeneration`] can later tell the original process from a
//! recycled pid with [`is_same_instance`].
//!
//! - Windows: the process creation time (`GetProcessTimes`), the value the
//!   UIA registry has bound since SG-000063. The code moved here from
//!   `orcel-provider-uia/src/native_desktop.rs`, which now calls it.
//! - Linux: `starttime` (field 22 of `/proc/<pid>/stat`, clock ticks since
//!   boot) together with `/proc/sys/kernel/random/boot_id`, because the
//!   tick count restarts at every boot.
//! - macOS: `proc_pidinfo(PROC_PIDTBSDINFO)` `pbi_start_tvsec` and
//!   `pbi_start_tvusec`, in microseconds since the Unix epoch.
//!
//! A pid that does not exist, has exited, or is a zombie waiting for its
//! parent is reported as [`PlatformError::ProcessGone`]; any other failure
//! to read the facts is [`PlatformError::IdentityUnavailable`], never a
//! made-up generation.
//!
//! Provenance: the Linux `/proc/<pid>/stat` parse (fields after the final
//! `)`, starttime as field 22) and the zombie rule are adapted from
//! `process_start_time_from_stat`, `process_stat_from_stat` and
//! `is_process_live` in cua@a802eaf26ca97616a6bf0de6a29729a9346fbb1f
//! `libs/cua-driver/rust/crates/platform-linux/src/proc_fs.rs` (blob
//! 7cf1622cdfa3969d79a11e14b9776925c68bb4e4, transplant row T-CUA-23; MIT,
//! Copyright (c) 2025 Cua AI, Inc.; full notice in
//! `docs/orcel/notices/cua-MIT.txt`). Modifications: typed errors instead
//! of `Option`, the boot id binding, and the zombie check read from the same
//! `stat` line rather than `/proc/<pid>/status`. The macOS path is new code.

use crate::PlatformError;

/// One process instance: its pid and a kernel fact that changes when the
/// pid is reused. Compare whole values; `generation` alone is meaningful
/// only for the same pid, OS and (on Linux) boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessGeneration {
    pub pid: u32,
    /// Windows: creation time as a FILETIME (100 ns since 1601). Linux:
    /// start time in clock ticks since boot. macOS: start time in
    /// microseconds since the Unix epoch.
    pub generation: u64,
    /// Linux boot id (`/proc/sys/kernel/random/boot_id` as a 128-bit
    /// integer); `None` where the generation is a wall-clock time.
    pub boot_id: Option<u128>,
    /// How the generation was read, for example `"win32-creation-time"`.
    pub source: &'static str,
}

/// The start generation of the process that holds `pid` now.
pub fn start_generation(pid: u32) -> Result<ProcessGeneration, PlatformError> {
    imp::start_generation(pid)
}

/// The start generation of this process.
pub fn current_instance() -> Result<ProcessGeneration, PlatformError> {
    start_generation(std::process::id())
}

/// Whether the process recorded as `recorded` still runs: `Ok(false)` when
/// its pid is gone or now belongs to another process instance.
pub fn is_same_instance(recorded: &ProcessGeneration) -> Result<bool, PlatformError> {
    same_instance(recorded, start_generation(recorded.pid))
}

/// The comparison behind [`is_same_instance`], given a fresh reading.
fn same_instance(
    recorded: &ProcessGeneration,
    now: Result<ProcessGeneration, PlatformError>,
) -> Result<bool, PlatformError> {
    match now {
        Ok(now) => Ok(now == *recorded),
        Err(PlatformError::ProcessGone(_)) => Ok(false),
        Err(error) => Err(error),
    }
}

/// The effective uid of the process holding `pid` now.
#[cfg(target_os = "linux")]
pub(crate) fn effective_uid_of(pid: u32) -> Result<u32, PlatformError> {
    imp::effective_uid_of(pid)
}

/// The Win32 image path of `pid` and its start generation, both read
/// through one process handle so they describe the same instance.
#[cfg(windows)]
pub fn image_path_and_generation(pid: u32) -> Result<(String, ProcessGeneration), PlatformError> {
    imp::image_path_and_generation(pid)
}

#[cfg(target_os = "linux")]
mod imp {
    use super::ProcessGeneration;
    use crate::PlatformError;
    use std::ffi::CStr;
    use std::fs::File;
    use std::io::{ErrorKind, Read};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::sync::OnceLock;

    pub(super) const SOURCE: &str = "linux-proc-starttime";
    const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";

    pub(super) fn start_generation(pid: u32) -> Result<ProcessGeneration, PlatformError> {
        // One directory handle serves both reads. If the process exits and
        // its pid is reused in between, reads through the old handle fail
        // instead of describing the new process, so the Tgid check and the
        // start time describe one instance.
        let dir = ProcDir::open(pid)?;
        // /proc/<tid> also exists for every thread id, unlisted; only a
        // thread group leader is a process.
        let (tgid, _) = parse_status(pid, &dir.read(c"status")?)?;
        if tgid != pid {
            return Err(PlatformError::IdentityUnavailable(format!(
                "{pid} is a thread of process {tgid}, not a process"
            )));
        }
        generation_from_stat(pid, &dir.read(c"stat")?, boot_id()?)
    }

    /// The effective uid of `pid` now, from `/proc/<pid>/status`.
    pub(super) fn effective_uid_of(pid: u32) -> Result<u32, PlatformError> {
        let dir = ProcDir::open(pid)?;
        parse_status(pid, &dir.read(c"status")?).map(|(_, euid)| euid)
    }

    /// An open `/proc/<pid>` directory, pinned to the process it named when
    /// it was opened.
    struct ProcDir {
        pid: u32,
        dir: File,
    }

    impl ProcDir {
        /// A missing entry means "gone" only when `kill(pid, 0)` agrees:
        /// with `hidepid=1/2`, another user's entries are hidden, and that
        /// must not read as an exit.
        fn open(pid: u32) -> Result<Self, PlatformError> {
            let path = format!("/proc/{pid}");
            match File::open(&path) {
                Ok(dir) => Ok(Self { pid, dir }),
                Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {
                    Err(PlatformError::ProcessGone(pid))
                }
                Err(error) if error.kind() == ErrorKind::NotFound && !pid_exists(pid) => {
                    Err(PlatformError::ProcessGone(pid))
                }
                Err(error) if error.kind() == ErrorKind::NotFound => {
                    Err(PlatformError::IdentityUnavailable(format!(
                        "{path} is hidden (hidepid) although pid {pid} exists"
                    )))
                }
                Err(error) => Err(PlatformError::IdentityUnavailable(format!(
                    "{path}: {error}"
                ))),
            }
        }

        /// Read one file of this directory. ESRCH or ENOENT through the
        /// held directory means its process has exited.
        fn read(&self, name: &CStr) -> Result<String, PlatformError> {
            let pid = self.pid;
            let fail = |error: std::io::Error| match error.raw_os_error() {
                Some(libc::ESRCH) | Some(libc::ENOENT) => PlatformError::ProcessGone(pid),
                _ => PlatformError::IdentityUnavailable(format!(
                    "/proc/{pid}/{}: {error}",
                    name.to_string_lossy()
                )),
            };
            // SAFETY: the directory fd is open for the lifetime of `self`
            // and `name` is a NUL-terminated C string; openat returns a new
            // descriptor or -1 and writes no memory of this process.
            let fd = unsafe {
                libc::openat(
                    self.dir.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(fail(std::io::Error::last_os_error()));
            }
            // SAFETY: openat returned a new descriptor that nothing else
            // owns; File takes ownership and closes it exactly once.
            let mut file = unsafe { File::from_raw_fd(fd) };
            let mut text = String::new();
            file.read_to_string(&mut text).map_err(fail)?;
            Ok(text)
        }
    }

    /// Whether any process (or thread) holds `pid`, by `kill(pid, 0)`.
    fn pid_exists(pid: u32) -> bool {
        let Ok(raw) = libc::pid_t::try_from(pid) else {
            return false;
        };
        // pid 0 and negative values address process groups, not a process.
        if raw <= 0 {
            return false;
        }
        // SAFETY: signal 0 sends nothing; kill only checks that the positive
        // pid exists and whether we may signal it, and touches no memory.
        if unsafe { libc::kill(raw, 0) } == 0 {
            return true;
        }
        std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
    }

    /// `Tgid` and the effective uid (second `Uid` field) of a
    /// `/proc/<pid>/status` text.
    pub(super) fn parse_status(pid: u32, status: &str) -> Result<(u32, u32), PlatformError> {
        let field = |name: &str, index: usize| {
            status
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .and_then(|rest| rest.split_whitespace().nth(index))
                .and_then(|value| value.parse::<u32>().ok())
        };
        match (field("Tgid:", 0), field("Uid:", 1)) {
            (Some(tgid), Some(euid)) => Ok((tgid, euid)),
            _ => Err(PlatformError::IdentityUnavailable(format!(
                "/proc/{pid}/status is malformed"
            ))),
        }
    }

    /// Parse one `/proc/<pid>/stat` line. `comm` is parenthesized and may
    /// itself contain spaces and `)`, so the fields are read after the final
    /// `)`: state is field 3 and starttime field 22.
    pub(super) fn generation_from_stat(
        pid: u32,
        stat: &str,
        boot_id: u128,
    ) -> Result<ProcessGeneration, PlatformError> {
        let malformed =
            || PlatformError::IdentityUnavailable(format!("/proc/{pid}/stat is malformed"));
        let fields = stat.rsplit_once(')').ok_or_else(malformed)?.1;
        let mut fields = fields.split_whitespace();
        let state = fields
            .next()
            .and_then(|state| state.chars().next())
            .ok_or_else(malformed)?;
        // A zombie has exited and only waits for its parent to reap it.
        if matches!(state, 'Z' | 'X' | 'x') {
            return Err(PlatformError::ProcessGone(pid));
        }
        let generation = fields
            .nth(18)
            .and_then(|start| start.parse::<u64>().ok())
            .ok_or_else(malformed)?;
        Ok(ProcessGeneration {
            pid,
            generation,
            boot_id: Some(boot_id),
            source: SOURCE,
        })
    }

    /// The boot id never changes while the system runs; only a successful
    /// read is cached.
    fn boot_id() -> Result<u128, PlatformError> {
        static BOOT_ID: OnceLock<u128> = OnceLock::new();
        if let Some(id) = BOOT_ID.get() {
            return Ok(*id);
        }
        let text = std::fs::read_to_string(BOOT_ID_PATH).map_err(|error| {
            PlatformError::IdentityUnavailable(format!("{BOOT_ID_PATH}: {error}"))
        })?;
        let id = parse_boot_id(&text).ok_or_else(|| {
            PlatformError::IdentityUnavailable(format!("{BOOT_ID_PATH} is malformed"))
        })?;
        Ok(*BOOT_ID.get_or_init(|| id))
    }

    /// Parse a UUID such as `0f6c3e1a-...` into its 128-bit value.
    pub(super) fn parse_boot_id(text: &str) -> Option<u128> {
        let hex: String = text.trim().chars().filter(|c| *c != '-').collect();
        if hex.len() != 32 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        u128::from_str_radix(&hex, 16).ok().filter(|id| *id != 0)
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::ProcessGeneration;
    use crate::PlatformError;

    pub(super) const SOURCE: &str = "macos-bsd-start-time";

    pub(super) fn start_generation(pid: u32) -> Result<ProcessGeneration, PlatformError> {
        let Ok(raw_pid) = libc::pid_t::try_from(pid) else {
            return Err(PlatformError::ProcessGone(pid));
        };
        // SAFETY: proc_bsdinfo is a plain C struct of integers and byte
        // arrays, for which the all-zero bit pattern is a valid value.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        // SAFETY: the buffer is a live, writable proc_bsdinfo and `size` is
        // its exact size, which is what PROC_PIDTBSDINFO writes; the call
        // reads no other memory of this process.
        let written = unsafe {
            libc::proc_pidinfo(
                raw_pid,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut info as *mut libc::proc_bsdinfo).cast(),
                size,
            )
        };
        if written <= 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                return Err(PlatformError::ProcessGone(pid));
            }
            return Err(PlatformError::IdentityUnavailable(format!(
                "proc_pidinfo({pid}, PROC_PIDTBSDINFO): {error}"
            )));
        }
        if written != size {
            return Err(PlatformError::IdentityUnavailable(format!(
                "proc_pidinfo({pid}, PROC_PIDTBSDINFO) returned {written} of {size} bytes"
            )));
        }
        generation_from_bsdinfo(
            pid,
            info.pbi_pid,
            info.pbi_status,
            info.pbi_start_tvsec,
            info.pbi_start_tvusec,
        )
    }

    pub(super) fn generation_from_bsdinfo(
        pid: u32,
        reported_pid: u32,
        status: u32,
        start_sec: u64,
        start_usec: u64,
    ) -> Result<ProcessGeneration, PlatformError> {
        if status == libc::SZOMB {
            return Err(PlatformError::ProcessGone(pid));
        }
        if reported_pid != pid {
            return Err(PlatformError::IdentityUnavailable(format!(
                "proc_pidinfo({pid}) described pid {reported_pid}"
            )));
        }
        let generation = start_sec
            .checked_mul(1_000_000)
            .and_then(|usec| usec.checked_add(start_usec))
            .filter(|generation| *generation != 0)
            .ok_or_else(|| {
                PlatformError::IdentityUnavailable(format!("pid {pid} has no usable start time"))
            })?;
        Ok(ProcessGeneration {
            pid,
            generation,
            boot_id: None,
            source: SOURCE,
        })
    }
}

#[cfg(windows)]
mod imp {
    use super::ProcessGeneration;
    use crate::PlatformError;
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{
        CloseHandle, ERROR_INVALID_PARAMETER, FILETIME, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, QueryFullProcessImageNameW, WaitForSingleObject,
        PROCESS_ACCESS_RIGHTS, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_SYNCHRONIZE,
    };

    /// The value orcel-provider-uia has always reported; the registry
    /// compares it.
    pub(super) const SOURCE: &str = "win32-creation-time";
    const IMAGE_PATH_CHARS: usize = 1_024;

    struct ProcessHandle(HANDLE);

    impl Drop for ProcessHandle {
        fn drop(&mut self) {
            // SAFETY: the handle came from a successful OpenProcess, is owned
            // only by this value, and is closed exactly once here.
            let _ = unsafe { CloseHandle(self.0) };
        }
    }

    fn open(pid: u32, access: PROCESS_ACCESS_RIGHTS) -> Result<ProcessHandle, PlatformError> {
        // SAFETY: OpenProcess takes plain values and returns a new handle
        // that ProcessHandle owns; it touches no memory of this process.
        match unsafe { OpenProcess(access, false, pid) } {
            Ok(handle) => Ok(ProcessHandle(handle)),
            // No process has this id.
            Err(error) if error.code() == ERROR_INVALID_PARAMETER.to_hresult() => {
                Err(PlatformError::ProcessGone(pid))
            }
            Err(error) => Err(PlatformError::IdentityUnavailable(format!(
                "OpenProcess({pid}): {error}"
            ))),
        }
    }

    /// A process object outlives its exit while anyone (for example the
    /// parent's `Child`) holds a handle. The object is signaled exactly when
    /// the process has exited, which, unlike `GetExitCodeProcess`, cannot be
    /// confused with a process that exits with code 259.
    fn ensure_running(handle: &ProcessHandle, pid: u32) -> Result<(), PlatformError> {
        // SAFETY: the handle is open with SYNCHRONIZE access; a zero timeout
        // only polls the object's state.
        let wait = unsafe { WaitForSingleObject(handle.0, 0) };
        if wait == WAIT_OBJECT_0 {
            Err(PlatformError::ProcessGone(pid))
        } else if wait == WAIT_TIMEOUT {
            Ok(())
        } else {
            Err(PlatformError::IdentityUnavailable(format!(
                "WaitForSingleObject({pid}) returned {:#x}",
                wait.0
            )))
        }
    }

    fn generation_of(handle: &ProcessHandle, pid: u32) -> Result<ProcessGeneration, PlatformError> {
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        // SAFETY: the handle is open with PROCESS_QUERY_LIMITED_INFORMATION
        // and all four pointers are live FILETIME values the call writes.
        unsafe { GetProcessTimes(handle.0, &mut creation, &mut exit, &mut kernel, &mut user) }
            .map_err(|error| {
                PlatformError::IdentityUnavailable(format!("GetProcessTimes({pid}): {error}"))
            })?;
        Ok(ProcessGeneration {
            pid,
            generation: ((creation.dwHighDateTime as u64) << 32) | (creation.dwLowDateTime as u64),
            boot_id: None,
            source: SOURCE,
        })
    }

    pub(super) fn start_generation(pid: u32) -> Result<ProcessGeneration, PlatformError> {
        let handle = open(pid, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE)?;
        ensure_running(&handle, pid)?;
        generation_of(&handle, pid)
    }

    pub(super) fn image_path_and_generation(
        pid: u32,
    ) -> Result<(String, ProcessGeneration), PlatformError> {
        // Exactly the access and the facts orcel-provider-uia read before
        // XP-03 (no liveness check), so desktop observation is unchanged.
        let handle = open(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
        let mut path = vec![0u16; IMAGE_PATH_CHARS];
        let mut len = path.len() as u32;
        // SAFETY: `path` is a live buffer of `len` UTF-16 units and the call
        // writes at most that many, then stores the written count in `len`.
        unsafe {
            QueryFullProcessImageNameW(
                handle.0,
                PROCESS_NAME_WIN32,
                PWSTR(path.as_mut_ptr()),
                &mut len,
            )
        }
        .map_err(|error| {
            PlatformError::IdentityUnavailable(format!(
                "QueryFullProcessImageNameW({pid}): {error}"
            ))
        })?;
        let image = String::from_utf16_lossy(&path[..(len as usize).min(path.len())]);
        Ok((image, generation_of(&handle, pid)?))
    }
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
mod imp {
    use super::ProcessGeneration;
    use crate::PlatformError;

    pub(super) fn start_generation(_pid: u32) -> Result<ProcessGeneration, PlatformError> {
        Err(PlatformError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Child, Command, Stdio};

    /// A child that stays alive until killed, on every OS.
    fn long_running_child() -> Child {
        let mut command = if cfg!(windows) {
            let mut command = Command::new("powershell");
            command.args(["-NoProfile", "-Command", "Start-Sleep -Seconds 60"]);
            command
        } else {
            let mut command = Command::new("sleep");
            command.arg("60");
            command
        };
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn child")
    }

    #[test]
    fn own_pid_generation_is_stable_across_calls() {
        let pid = std::process::id();
        let first = start_generation(pid).expect("own generation");
        let second = start_generation(pid).expect("own generation again");
        assert_eq!(first, second);
        assert_eq!(first.pid, pid);
        assert_ne!(first.generation, 0);
        assert_eq!(first.source, imp::SOURCE);
        assert_eq!(first.boot_id.is_some(), cfg!(target_os = "linux"));
        assert_eq!(current_instance().unwrap(), first);
        assert!(is_same_instance(&first).expect("compare own generation"));
    }

    #[test]
    fn a_live_child_has_its_own_generation_and_a_reaped_child_is_gone() {
        let mut child = long_running_child();
        let pid = child.id();
        let recorded = start_generation(pid).expect("child generation");
        assert_eq!(recorded.pid, pid);
        assert_ne!(recorded, start_generation(std::process::id()).unwrap());
        assert!(is_same_instance(&recorded).unwrap());

        child.kill().expect("kill child");
        child.wait().expect("reap child");
        // The pid is free now. It is either unused (gone) or, if the OS
        // already reused it, held by a different instance.
        let after = start_generation(pid);
        let gone_or_other = match &after {
            Err(PlatformError::ProcessGone(gone)) => *gone == pid,
            Ok(other) => *other != recorded,
            Err(_) => false,
        };
        assert!(gone_or_other, "reaped pid {pid} read as {after:?}");
        assert!(!is_same_instance(&recorded).unwrap());
    }

    #[test]
    fn nonexistent_pid_is_reported_gone() {
        // Above every OS's pid range: Linux pid_max is at most 2^22, macOS
        // pids stay below 100000, and Windows pids are multiples of four.
        let pid = i32::MAX as u32;
        assert_eq!(start_generation(pid), Err(PlatformError::ProcessGone(pid)));
        let recorded = ProcessGeneration {
            pid,
            generation: 1,
            boot_id: None,
            source: "recorded",
        };
        assert!(!is_same_instance(&recorded).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn an_unreaped_zombie_is_reported_gone() {
        use std::time::{Duration, Instant};
        let mut child = long_running_child();
        let pid = child.id();
        start_generation(pid).expect("live child generation");
        // SAFETY: kill(2) with a positive pid of our own unreaped child,
        // which cannot have been reused because we have not waited on it.
        let rc = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
        assert_eq!(rc, 0);
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut outcome = start_generation(pid);
        while outcome.is_ok() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
            outcome = start_generation(pid);
        }
        assert_eq!(outcome, Err(PlatformError::ProcessGone(pid)));
        child.wait().expect("reap child");
    }

    #[test]
    fn a_recycled_pid_with_a_new_generation_is_a_different_instance() {
        let recorded = start_generation(std::process::id()).unwrap();
        let recycled = ProcessGeneration {
            generation: recorded.generation + 1,
            ..recorded
        };
        assert_ne!(recycled, recorded);
        assert!(!same_instance(&recorded, Ok(recycled)).unwrap());
        assert!(same_instance(&recorded, Ok(recorded)).unwrap());
        assert!(!same_instance(&recorded, Err(PlatformError::ProcessGone(recorded.pid))).unwrap());
        let unreadable = PlatformError::IdentityUnavailable("denied".into());
        assert_eq!(
            same_instance(&recorded, Err(unreadable.clone())),
            Err(unreadable)
        );
        // Same tick count after a reboot is a different instance too.
        if let Some(boot) = recorded.boot_id {
            let rebooted = ProcessGeneration {
                boot_id: Some(boot ^ 1),
                ..recorded
            };
            assert!(!same_instance(&recorded, Ok(rebooted)).unwrap());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_stat_parse_uses_the_final_paren_and_detects_reuse_and_zombies() {
        const BOOT: u128 = 0x0f6c_3e1a_9b2d_4c11_8e7f_0123_4567_89ab;
        let line = |comm: &str, state: char, start: u64| {
            format!(
                "4242 ({comm}) {state} 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 {start} 1000 10 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0"
            )
        };
        let first = imp::generation_from_stat(4242, &line("a) b (c", 'S', 777), BOOT).unwrap();
        assert_eq!(first.generation, 777);
        assert_eq!(first.boot_id, Some(BOOT));
        let reused = imp::generation_from_stat(4242, &line("other", 'R', 9001), BOOT).unwrap();
        assert_ne!(first, reused);
        assert!(!same_instance(&first, Ok(reused)).unwrap());
        for state in ['Z', 'X'] {
            assert_eq!(
                imp::generation_from_stat(4242, &line("dead", state, 777), BOOT),
                Err(PlatformError::ProcessGone(4242))
            );
        }
        assert!(matches!(
            imp::generation_from_stat(4242, "4242 (truncated", BOOT),
            Err(PlatformError::IdentityUnavailable(_))
        ));
        assert!(matches!(
            imp::generation_from_stat(4242, "4242 (short) S 1 2", BOOT),
            Err(PlatformError::IdentityUnavailable(_))
        ));
        assert_eq!(
            imp::parse_boot_id("0f6c3e1a-9b2d-4c11-8e7f-0123456789ab\n"),
            Some(BOOT)
        );
        assert_eq!(imp::parse_boot_id("not-a-uuid"), None);
        assert_eq!(
            imp::parse_boot_id("00000000-0000-0000-0000-000000000000"),
            None
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_thread_ids_are_not_processes() {
        let (tid_tx, tid_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let thread = std::thread::spawn(move || {
            // SAFETY: gettid takes no arguments, always succeeds and touches
            // no memory.
            let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u32;
            tid_tx.send(tid).unwrap();
            let _ = done_rx.recv();
        });
        let tid = tid_rx.recv().unwrap();
        assert_ne!(tid, std::process::id());
        assert!(matches!(
            start_generation(tid),
            Err(PlatformError::IdentityUnavailable(reason)) if reason.contains("thread")
        ));
        done_tx.send(()).unwrap();
        thread.join().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_status_yields_tgid_and_effective_uid() {
        let status = "Name:	x
Tgid:	4242
Pid:	4243
Uid:	1000	1001	1000	1000
";
        assert_eq!(imp::parse_status(4243, status), Ok((4242, 1001)));
        assert!(matches!(
            imp::parse_status(
                4243, "Name:	x
"
            ),
            Err(PlatformError::IdentityUnavailable(_))
        ));
        assert_eq!(
            effective_uid_of(std::process::id()),
            Ok(crate::session::effective_uid().unwrap())
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_bsdinfo_times_detect_reuse_and_zombies() {
        let first = imp::generation_from_bsdinfo(4242, 4242, 2, 1_700_000_000, 5).unwrap();
        assert_eq!(first.generation, 1_700_000_000_000_005);
        let reused = imp::generation_from_bsdinfo(4242, 4242, 2, 1_700_000_100, 5).unwrap();
        assert!(!same_instance(&first, Ok(reused)).unwrap());
        assert_eq!(
            imp::generation_from_bsdinfo(4242, 4242, libc::SZOMB, 1_700_000_000, 5),
            Err(PlatformError::ProcessGone(4242))
        );
        assert!(matches!(
            imp::generation_from_bsdinfo(4242, 4243, 2, 1_700_000_000, 5),
            Err(PlatformError::IdentityUnavailable(_))
        ));
        assert!(matches!(
            imp::generation_from_bsdinfo(4242, 4242, 2, 0, 0),
            Err(PlatformError::IdentityUnavailable(_))
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_image_path_and_generation_share_one_instance() {
        let pid = std::process::id();
        let (image, generation) = image_path_and_generation(pid).unwrap();
        let exe = std::env::current_exe().unwrap();
        let exe_name = exe.file_name().unwrap().to_string_lossy().to_lowercase();
        assert!(image.to_lowercase().ends_with(&exe_name), "{image}");
        assert_eq!(generation, start_generation(pid).unwrap());
    }
}
