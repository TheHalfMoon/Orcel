//! SG-000074 supervised launch and deterministic cleanup.
//!
//! Two supervised shapes exist. Engine processes start suspended on
//! Windows, are assigned to a kill-on-close Job Object with a bounded
//! active-process count, and are resumed only afterwards, so no
//! unsupervised execution window exists. Host binaries start with standard
//! piped channels and are assigned to the same kind of job immediately
//! after spawn; pipe end-of-input independently stops a host whose parent
//! died, so cleanup never depends on the assignment race. Dropping
//! supervision terminates the job and confirms the processes are gone. Off
//! Windows the same shape holds with process-handle supervision and
//! drop-kill; the hard parent-death guarantee is Windows-only and recorded
//! as a platform boundary in the SG-000074 note.

use crate::error::{HostError, UnavailableReason};
use std::path::Path;
use std::time::Duration;
#[cfg(windows)]
use std::time::Instant;

use platform::PlatformChild;

/// Hard ceiling on processes inside one browser job (engine plus helpers).
pub const JOB_ACTIVE_PROCESS_LIMIT: u32 = 32;

/// Bounded waits owned by the supervisor.
pub const LAUNCH_GRACE: Duration = Duration::from_secs(2);
pub const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

/// Scrubbed environment entries for supervised processes.
pub type CleanEnv = Vec<(std::ffi::OsString, std::ffi::OsString)>;

/// A supervised child process that is dead by the time supervision drops.
pub struct SupervisedChild {
    inner: PlatformChild,
}

impl SupervisedChild {
    pub fn pid(&self) -> u32 {
        self.inner.pid()
    }

    pub fn is_alive(&mut self) -> bool {
        self.inner.is_alive()
    }

    /// SG-000135 OB-06: an owned handle of the family's job, for membership
    /// queries only.
    #[cfg(windows)]
    pub fn job_handle(&self) -> Option<std::os::windows::io::OwnedHandle> {
        self.inner.job_handle()
    }

    /// Terminate the whole supervised family and confirm it is gone.
    /// Returns true only when no process remains.
    pub fn shutdown(self) -> Result<bool, HostError> {
        self.inner.shutdown()
    }
}

/// Piped channel ends for a supervised host binary.
pub struct HostPipes {
    pub stdin: std::process::ChildStdin,
    pub stdout: std::io::BufReader<std::process::ChildStdout>,
}

/// Launch an engine with null standard handles under full supervision.
/// Used by the host binary for the engine process.
pub fn spawn_engine_null(
    binary: &Path,
    args: &[String],
    env: &CleanEnv,
) -> Result<SupervisedChild, HostError> {
    platform::spawn_null(binary, args, env)
}

/// Launch a host binary with piped stdio under supervision. The pipes are
/// the only channel; no listener is ever created.
/// Used by Orcel supervision for the host process.
pub fn spawn_host_piped(
    binary: &Path,
    args: &[String],
    env: &CleanEnv,
) -> Result<(SupervisedChild, HostPipes), HostError> {
    platform::spawn_piped(binary, args, env)
}

#[cfg(windows)]
pub(crate) mod platform {
    use super::*;
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, STILL_ACTIVE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, GetExitCodeProcess, ResumeThread, CREATE_SUSPENDED,
        CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT, PROCESS_INFORMATION,
        STARTUPINFOEXW,
    };

    pub struct OwnedHandle(HANDLE);

    impl OwnedHandle {
        pub(crate) fn new(handle: HANDLE) -> Option<Self> {
            (handle != 0 && handle != -1).then_some(Self(handle))
        }
    }

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            // SAFETY: owned exactly once from a successful create call.
            unsafe { CloseHandle(self.0) };
        }
    }

    fn wide(value: &std::ffi::OsStr) -> Vec<u16> {
        value.encode_wide().chain(Some(0)).collect()
    }

    /// A kill-on-close job with a bounded active-process count.
    pub struct Job(OwnedHandle);

    impl Job {
        pub fn create() -> Result<Self, HostError> {
            // SAFETY: null attributes and name are permitted.
            let handle = OwnedHandle::new(unsafe { CreateJobObjectW(ptr::null(), ptr::null()) })
                .ok_or_else(|| platform_error("CreateJobObjectW"))?;
            // SAFETY: zeroed limits are valid before the fields are set.
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
            limits.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
            limits.BasicLimitInformation.ActiveProcessLimit = JOB_ACTIVE_PROCESS_LIMIT;
            // SAFETY: pointer and size describe `limits`.
            if unsafe {
                SetInformationJobObject(
                    handle.0,
                    JobObjectExtendedLimitInformation,
                    &limits as *const _ as *const c_void,
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            } == 0
            {
                return Err(platform_error("SetInformationJobObject"));
            }
            Ok(Self(handle))
        }

        pub(crate) fn handle(&self) -> HANDLE {
            self.0.raw()
        }

        pub fn assign(&self, process: HANDLE) -> Result<(), HostError> {
            // SAFETY: both handles are valid for the duration of the call.
            if unsafe { AssignProcessToJobObject(self.0.raw(), process) } == 0 {
                return Err(platform_error("AssignProcessToJobObject"));
            }
            Ok(())
        }

        pub(crate) fn terminate(&self) {
            // SAFETY: valid job handle.
            unsafe { TerminateJobObject(self.0.raw(), 1) };
        }
    }

    impl OwnedHandle {
        pub(crate) fn raw(&self) -> HANDLE {
            self.0
        }

        /// Release ownership without closing (the caller takes it over).
        pub(crate) fn into_raw(self) -> HANDLE {
            let handle = self.0;
            std::mem::forget(self);
            handle
        }
    }

    pub struct PlatformChild {
        job: Job,
        waiter: Waiter,
        pid: u32,
    }

    enum Waiter {
        Handle(OwnedHandle),
        Child(std::process::Child),
    }

    impl PlatformChild {
        pub fn pid(&self) -> u32 {
            self.pid
        }

        pub fn is_alive(&mut self) -> bool {
            match &mut self.waiter {
                Waiter::Handle(process) => {
                    let mut code: u32 = 0;
                    // SAFETY: valid process handle and out-pointer.
                    if unsafe { GetExitCodeProcess(process.0, &mut code) } == 0 {
                        return false;
                    }
                    code == STILL_ACTIVE as u32
                }
                Waiter::Child(child) => matches!(child.try_wait(), Ok(None)),
            }
        }

        /// SG-000135 OB-06: a handle of this child's job of its own (the
        /// same access), so a caller can ask whether a process belongs to
        /// the supervised family (every descendant stays in the job: it
        /// allows no breakaway). `None` if it could not be duplicated.
        pub fn job_handle(&self) -> Option<std::os::windows::io::OwnedHandle> {
            use std::os::windows::io::{BorrowedHandle, RawHandle};
            // SAFETY: the job handle is open for as long as `self` lives,
            // which outlives this borrow; the clone is a new handle.
            let borrowed = unsafe { BorrowedHandle::borrow_raw(self.job.handle() as RawHandle) };
            borrowed.try_clone_to_owned().ok()
        }

        pub fn shutdown(mut self) -> Result<bool, HostError> {
            self.job.terminate();
            let deadline = Instant::now() + SHUTDOWN_TIMEOUT;
            loop {
                if !self.is_alive() {
                    return Ok(true);
                }
                if Instant::now() >= deadline {
                    return Ok(false);
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }

    impl Drop for PlatformChild {
        fn drop(&mut self) {
            self.job.terminate();
        }
    }

    /// Suspended spawn into a fresh job with a scrubbed environment and no
    /// inherited handles. Used for the engine, which needs no pipes.
    pub(super) fn spawn_null(
        binary: &Path,
        args: &[String],
        env: &CleanEnv,
    ) -> Result<SupervisedChild, HostError> {
        let job = Job::create()?;
        let mut command: Vec<u16> = wide(binary.as_os_str());
        for arg in args {
            command.push(' ' as u16);
            command.extend(format!("\"{arg}\"").encode_utf16());
        }
        command.push(0);
        let mut environment: Vec<u16> = Vec::new();
        for (key, value) in env {
            environment.extend(key.encode_wide());
            environment.push('=' as u16);
            environment.extend(value.encode_wide());
            environment.push(0);
        }
        environment.push(0);
        // SAFETY: zeroed STARTUPINFOEXW is valid before the fields are set.
        let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        let created = unsafe {
            CreateProcessW(
                ptr::null(),
                command.as_ptr() as *mut u16,
                ptr::null(),
                ptr::null(),
                0,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
                environment.as_ptr() as *mut c_void,
                ptr::null(),
                &startup.StartupInfo,
                &mut info,
            )
        };
        if created == 0 {
            return Err(platform_error("CreateProcessW"));
        }
        // SAFETY: owned exactly once from the successful create call.
        let process = OwnedHandle::new(info.hProcess)
            .ok_or_else(|| platform_error("CreateProcessW handle"))?;
        let thread = OwnedHandle::new(info.hThread)
            .ok_or_else(|| platform_error("CreateProcessW thread"))?;
        let pid = info.dwProcessId;
        job.assign(process.0)?;
        // SAFETY: valid primary thread handle of a suspended process.
        if unsafe { ResumeThread(thread.0) } == u32::MAX {
            return Err(platform_error("ResumeThread"));
        }
        // The raw handles close here; supervision continues through the
        // job object, which outlives them.
        Ok(SupervisedChild {
            inner: PlatformChild {
                job,
                waiter: Waiter::Handle(process),
                pid,
            },
        })
    }

    /// Piped spawn for the host binary: standard channels plus immediate
    /// job assignment. Pipe end-of-input stops a host whose parent died,
    /// independent of the assignment timing.
    pub(super) fn spawn_piped(
        binary: &Path,
        args: &[String],
        env: &CleanEnv,
    ) -> Result<(SupervisedChild, HostPipes), HostError> {
        let job = Job::create()?;
        let mut child = std::process::Command::new(binary)
            .args(args)
            .env_clear()
            .envs(env.iter().cloned())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|_| HostError::Unavailable(UnavailableReason::LaunchFailed))?;
        let pid = child.id();
        job.assign(child.as_raw_handle() as HANDLE)?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| HostError::Platform("host stdin unavailable".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| HostError::Platform("host stdout unavailable".into()))?;
        Ok((
            SupervisedChild {
                inner: PlatformChild {
                    job,
                    waiter: Waiter::Child(child),
                    pid,
                },
            },
            HostPipes {
                stdin,
                stdout: std::io::BufReader::new(stdout),
            },
        ))
    }

    fn platform_error(context: &str) -> HostError {
        HostError::Platform(format!("{context}: {}", std::io::Error::last_os_error()))
    }
}

#[cfg(not(windows))]
pub(crate) mod platform {
    use super::*;

    pub struct PlatformChild {
        child: std::process::Child,
    }

    impl PlatformChild {
        pub fn pid(&self) -> u32 {
            self.child.id()
        }

        pub fn is_alive(&mut self) -> bool {
            matches!(self.child.try_wait(), Ok(None))
        }

        pub fn shutdown(mut self) -> Result<bool, HostError> {
            let _ = self.child.kill();
            let _ = self.child.wait();
            Ok(true)
        }
    }

    impl Drop for PlatformChild {
        fn drop(&mut self) {
            // Best-effort kill on the drop path; the hard parent-death
            // guarantee is Windows-only in this grain.
            let _ = self.child.kill();
        }
    }

    pub(super) fn spawn_null(
        binary: &Path,
        args: &[String],
        env: &CleanEnv,
    ) -> Result<SupervisedChild, HostError> {
        let child = std::process::Command::new(binary)
            .args(args)
            .env_clear()
            .envs(env.iter().cloned())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|_| HostError::Unavailable(UnavailableReason::LaunchFailed))?;
        Ok(SupervisedChild {
            inner: PlatformChild { child },
        })
    }

    pub(super) fn spawn_piped(
        binary: &Path,
        args: &[String],
        env: &CleanEnv,
    ) -> Result<(SupervisedChild, HostPipes), HostError> {
        // Off Windows the same private piped shape holds with
        // process-handle supervision and drop-kill. The hard
        // kill-on-close parent-death guarantee is Windows-only and is
        // recorded as a platform boundary in the SG-000074 note.
        let mut child = std::process::Command::new(binary)
            .args(args)
            .env_clear()
            .envs(env.iter().cloned())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|_| HostError::Unavailable(UnavailableReason::LaunchFailed))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| HostError::Platform("host stdin unavailable".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| HostError::Platform("host stdout unavailable".into()))?;
        Ok((
            SupervisedChild {
                inner: PlatformChild { child },
            },
            HostPipes {
                stdin,
                stdout: std::io::BufReader::new(stdout),
            },
        ))
    }
}
