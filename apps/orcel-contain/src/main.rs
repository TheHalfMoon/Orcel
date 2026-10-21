//! orcel-contain: Orcel's one-shot launcher for the contained execution tier
//! (XP-13).
//!
//! orceld starts this helper from a pinned, digest-verified path with an empty
//! environment, writes one closed, bounded spec on stdin (`spec.rs`), and keeps
//! stdin open. The helper installs every boundary the platform advertises
//! (`containment.rs`), runs the child, relays its bounded stdout and stderr and
//! its exit, writes one result on stdout, and exits. It has no listener, reads
//! no environment variable and takes no argument.
//!
//! Parent death is covered twice: end of file on stdin (orceld closed it or
//! died) kills the child's tree, and on Linux the helper also arms
//! `PR_SET_PDEATHSIG` before it reads the spec. If the helper itself is killed,
//! the child dies through its own boundary: `PR_SET_PDEATHSIG` (Linux), the
//! sentinel pipe (macOS) or the kill-on-close Job Object (Windows).

mod containment;
mod digest;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
mod pinned;
mod spec;
#[cfg(unix)]
mod unix;
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
mod unsupported;
#[cfg(windows)]
mod windows;

use std::io::{Read as _, Write as _};
use std::process::ExitCode;
use std::time::Duration;

use containment::{ContainmentLimits, RunBounds, RunOutcome, Stream};

/// The helper ran the child and wrote its result.
const EXIT_RAN: u8 = 0;
/// The helper refused before launching anything and wrote the refusal.
const EXIT_REFUSED: u8 = 3;

fn main() -> ExitCode {
    let launcher = arm_parent_death();
    let mut stdin = std::io::stdin();
    let spec = match spec::read_spec(&mut stdin) {
        Ok(spec) => spec,
        Err(error) => return refuse(error.kind(), error.message(), None),
    };
    if let Some(launcher) = launcher {
        // The death signal is armed against whoever started the helper. That
        // must be the supervisor the spec names, or the guarantee is about the
        // wrong process (or the supervisor already died).
        if launcher != spec.parent {
            return refuse(
                "invalid_spec",
                "the helper was not started by the supervisor the spec names",
                None,
            );
        }
    }

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => return refuse("launch_failed", "failed to start the helper runtime", None),
    };
    let (gone, parent_gone) = tokio::sync::oneshot::channel::<()>();
    // The supervisor writes nothing after `end`; end of file or any byte at
    // all means it is gone or misbehaving, and either way the run stops.
    let watcher = std::thread::Builder::new()
        .name("orcel-contain-parent".to_owned())
        .spawn(move || {
            let mut byte = [0_u8; 1];
            let _ = stdin.read(&mut byte);
            let _ = gone.send(());
        });
    if watcher.is_err() {
        return refuse("launch_failed", "failed to watch the supervisor", None);
    }

    let limits = ContainmentLimits {
        max_memory_bytes: spec.memory_bytes,
        max_cpu_time: Duration::from_secs(spec.cpu_seconds),
        max_open_files: u32::try_from(spec.open_files).unwrap_or(u32::MAX),
        additional_writable_paths: spec.write.clone(),
        additional_readable_paths: spec.read.clone(),
    };
    let bounds = RunBounds {
        timeout: Duration::from_millis(spec.timeout_ms),
        stdout_bytes: usize::try_from(spec.stdout_bytes).unwrap_or(usize::MAX),
        stderr_bytes: usize::try_from(spec.stderr_bytes).unwrap_or(usize::MAX),
    };
    let result = runtime.block_on(containment::run(
        &spec.executable,
        &spec.executable_sha256,
        &spec.args,
        &spec.workdir,
        &limits,
        bounds,
        async {
            let _ = parent_gone.await;
        },
    ));
    let result = match result {
        Ok(result) => result,
        Err(error) => {
            let detail = error.detail.as_deref();
            return refuse(error.code.as_str(), &error.message, detail);
        }
    };
    let (outcome, code) = match result.outcome {
        RunOutcome::Exited(code) => ("exited", code),
        RunOutcome::Signaled(signal) => ("signaled", signal),
        RunOutcome::ResourceLimit => ("resource_limit", 0),
        RunOutcome::TimedOut => ("timed_out", 0),
        RunOutcome::OutputLimit(Stream::Stdout) => ("stdout_limit", 0),
        RunOutcome::OutputLimit(Stream::Stderr) => ("stderr_limit", 0),
        RunOutcome::ParentGone => ("parent_gone", 0),
    };
    let header = spec::result_header(
        outcome,
        code,
        result.stdout.len(),
        result.stderr.len(),
        None,
    );
    write_result(&header, &result.stdout, &result.stderr, EXIT_RAN)
}

fn refuse(kind: &str, message: &str, detail: Option<&str>) -> ExitCode {
    let text = match detail {
        Some(detail) => format!("{kind}: {message} ({detail})"),
        None => format!("{kind}: {message}"),
    };
    let header = spec::result_header("refused", 0, 0, 0, Some(&text));
    write_result(&header, &[], &[], EXIT_REFUSED)
}

fn write_result(header: &str, stdout: &[u8], stderr: &[u8], status: u8) -> ExitCode {
    let mut out = std::io::stdout().lock();
    let written = out
        .write_all(header.as_bytes())
        .and_then(|()| out.write_all(stdout))
        .and_then(|()| out.write_all(stderr))
        .and_then(|()| out.flush());
    match written {
        Ok(()) => ExitCode::from(status),
        // The supervisor is gone; there is no one to report to.
        Err(_) => ExitCode::from(EXIT_REFUSED),
    }
}

/// Arm `PR_SET_PDEATHSIG` for the helper itself and return the pid it is armed
/// against. The parent may already have exited between our start and the
/// prctl; the caller compares the pid with the spec, which catches that.
#[cfg(target_os = "linux")]
fn arm_parent_death() -> Option<u32> {
    // SAFETY: prctl and getppid have no memory preconditions.
    unsafe {
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
            libc::_exit(i32::from(EXIT_REFUSED));
        }
        u32::try_from(libc::getppid()).ok()
    }
}

/// macOS has no death signal; the supervisor's stdin and the child's sentinel
/// cover parent death. The launcher pid is still checked against the spec.
#[cfg(target_os = "macos")]
fn arm_parent_death() -> Option<u32> {
    // SAFETY: getppid has no preconditions.
    u32::try_from(unsafe { libc::getppid() }).ok()
}

/// Windows has no death signal; the supervisor's stdin and the kill-on-close
/// job cover parent death. The launcher is still checked against the spec:
/// its pid comes from a process snapshot, and it must still be running and
/// have started no later than the helper, so a recycled pid is not taken for
/// the supervisor. Any failure yields pid 0, which no spec names, so the
/// helper refuses.
#[cfg(windows)]
fn arm_parent_death() -> Option<u32> {
    Some(windows_launcher::launcher_pid().unwrap_or(0))
}

#[cfg(windows)]
mod windows_launcher {
    use std::ffi::c_void;

    type Handle = *mut c_void;
    const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x0000_1000;
    const STILL_ACTIVE: u32 = 259;
    const INVALID_HANDLE_VALUE: isize = -1;

    #[repr(C)]
    struct ProcessEntry32W {
        size: u32,
        usage: u32,
        process_id: u32,
        default_heap_id: usize,
        module_id: u32,
        threads: u32,
        parent_process_id: u32,
        priority_class_base: i32,
        flags: u32,
        exe_file: [u16; 260],
    }

    #[repr(C)]
    #[derive(Default)]
    struct FileTime {
        low: u32,
        high: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateToolhelp32Snapshot(flags: u32, process_id: u32) -> Handle;
        fn Process32FirstW(snapshot: Handle, entry: *mut ProcessEntry32W) -> i32;
        fn Process32NextW(snapshot: Handle, entry: *mut ProcessEntry32W) -> i32;
        fn GetCurrentProcessId() -> u32;
        fn GetCurrentProcess() -> Handle;
        fn OpenProcess(access: u32, inherit: i32, process_id: u32) -> Handle;
        fn GetExitCodeProcess(process: Handle, code: *mut u32) -> i32;
        fn GetProcessTimes(
            process: Handle,
            creation: *mut FileTime,
            exit: *mut FileTime,
            kernel: *mut FileTime,
            user: *mut FileTime,
        ) -> i32;
        fn CloseHandle(object: Handle) -> i32;
    }

    pub(super) fn launcher_pid() -> Option<u32> {
        // SAFETY: GetCurrentProcessId takes no arguments.
        let own = unsafe { GetCurrentProcessId() };
        let parent = parent_of(own)?;
        // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no closing.
        let own_start = start_time(unsafe { GetCurrentProcess() })?;
        // SAFETY: plain OpenProcess; a null result is handled, and the handle is
        // closed below exactly once.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, parent) };
        if handle.is_null() {
            return None;
        }
        let mut code = 0_u32;
        // SAFETY: `handle` is open with query access and `code` is a live out-pointer.
        let alive = unsafe { GetExitCodeProcess(handle, &mut code) } != 0 && code == STILL_ACTIVE;
        let parent_start = start_time(handle);
        // SAFETY: `handle` was opened above and is closed once.
        unsafe { CloseHandle(handle) };
        (alive && parent_start? <= own_start).then_some(parent)
    }

    fn parent_of(own: u32) -> Option<u32> {
        // SAFETY: a process snapshot takes no pointers; the handle is checked and
        // closed below exactly once.
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snapshot.is_null() || snapshot as isize == INVALID_HANDLE_VALUE {
            return None;
        }
        // SAFETY: PROCESSENTRY32W is integers and an inline array; all-zero is valid,
        // and `size` is set before the first call as the API requires.
        let mut entry: ProcessEntry32W = unsafe { std::mem::zeroed() };
        entry.size = std::mem::size_of::<ProcessEntry32W>() as u32;
        let mut parent = None;
        // SAFETY: `snapshot` is open and `entry` is a live, sized PROCESSENTRY32W.
        let mut more = unsafe { Process32FirstW(snapshot, &mut entry) } != 0;
        while more {
            if entry.process_id == own {
                parent = Some(entry.parent_process_id);
                break;
            }
            // SAFETY: as for Process32FirstW above.
            more = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
        }
        // SAFETY: `snapshot` was opened above and is closed once.
        unsafe { CloseHandle(snapshot) };
        parent.filter(|pid| *pid != 0)
    }

    fn start_time(process: Handle) -> Option<u64> {
        let mut creation = FileTime::default();
        let mut exit = FileTime::default();
        let mut kernel = FileTime::default();
        let mut user = FileTime::default();
        // SAFETY: `process` has query access and the four out-pointers are live locals.
        let ok =
            unsafe { GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user) };
        (ok != 0).then(|| u64::from(creation.high) << 32 | u64::from(creation.low))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn arm_parent_death() -> Option<u32> {
    None
}
