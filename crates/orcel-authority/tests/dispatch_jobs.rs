//! WP1-10 (SG-000132): the dispatch Job Objects the service makes, created
//! for real in this unelevated test process. The test process plays both
//! sides: the service (creating the unnamed job and holding the full
//! handle) and orceld (receiving the duplicated assign-only handle).
//!
//! What these tests show: the duplicated handle carries assign-process only
//! (terminate and query are refused through it, assign works) and is not
//! inheritable; a job is made only for the process the service observed
//! (same PID and creation time); the kill-on-close and no-breakaway limits;
//! that `CREATE_BREAKAWAY_FROM_JOB` fails inside the job; and that
//! terminating or closing the job ends its processes within one second.
//! Jobs have no name, so there is nothing to pre-create or squat. What only
//! the installed service can show (a handle duplicated from
//! `NT SERVICE\OrcelAuthority` into orceld after impersonating it) is
//! UNVERIFIED (founder run) in SG132_SLICE3.md.
#![cfg(windows)]

use orcel_authority::caller::CallerFacts;
use orcel_authority::core::dispatch_jobs::{DispatchJob, JobHost, JobProfile};
use orcel_authority::win::jobs::{
    active_processes, create_job, create_job_for, limit_flags, ui_limits, ClientProcess,
    ClientSlot, ServiceJobs, DESKTOP_HOST_UI_LIMITS, JOB_UI_LIMITS,
};
use std::io::Write;
use std::os::windows::io::AsRawHandle;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetHandleInformation, GetLastError, ERROR_ACCESS_DENIED, HANDLE,
    HANDLE_FLAG_INHERIT,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, TerminateJobObject, JOB_OBJECT_LIMIT_BREAKAWAY_OK,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
};

/// The helper's environment variable (see `job_helper_child`).
const HELPER: &str = "ORCEL_DISPATCH_JOB_HELPER";

/// Not a test of its own: the child process the tests below start. Without
/// the environment variable it does nothing.
#[test]
fn job_helper_child() {
    let Ok(mode) = std::env::var(HELPER) else {
        return;
    };
    match mode.as_str() {
        "sleep" => {
            std::thread::sleep(Duration::from_secs(60));
            std::process::exit(0);
        }
        "breakaway" => {
            // Wait until the parent assigned this process to the job.
            let mut line = String::new();
            let _ = std::io::stdin().read_line(&mut line);
            use std::os::windows::process::CommandExt;
            const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
            let spawned = Command::new(std::env::current_exe().expect("exe"))
                .arg("--list")
                .creation_flags(CREATE_BREAKAWAY_FROM_JOB)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn();
            std::process::exit(match spawned {
                Err(error) if error.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => 0,
                Ok(mut child) => {
                    let _ = child.kill();
                    1
                }
                Err(_) => 2,
            });
        }
        "windows" => {
            // Wait until the parent assigned this process to the job, then
            // report (as the exit code) how many titled windows of other
            // processes it can see and read. Read-only: no input.
            let mut line = String::new();
            let _ = std::io::stdin().read_line(&mut line);
            std::process::exit(foreign_titled_windows().min(250) as i32);
        }
        _ => std::process::exit(3),
    }
}

/// Visible top-level windows of other processes whose title this process
/// can read (`GetWindowTextLengthW` sends `WM_GETTEXT`-class messages,
/// which a job's `HANDLES` restriction refuses for windows outside it).
fn foreign_titled_windows() -> u32 {
    use windows_sys::Win32::Foundation::{BOOL, HWND, LPARAM};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        EnumWindows, GetWindowTextLengthW, GetWindowThreadProcessId, IsWindowVisible,
    };
    unsafe extern "system" fn visit(hwnd: HWND, counter: LPARAM) -> BOOL {
        let mut pid = 0u32;
        // SAFETY: a window handle EnumWindows passed and a live out-pointer.
        unsafe { GetWindowThreadProcessId(hwnd, &mut pid) };
        // SAFETY: read-only queries of a window handle EnumWindows passed.
        let readable = unsafe { IsWindowVisible(hwnd) } != 0
            && pid != std::process::id()
            && unsafe { GetWindowTextLengthW(hwnd) } > 0;
        if readable {
            // SAFETY: `counter` points at the caller's live u32.
            unsafe { *(counter as *mut u32) += 1 };
        }
        1
    }
    let mut count = 0u32;
    // SAFETY: the callback only reads windows and the counter outlives the
    // call.
    unsafe { EnumWindows(Some(visit), &mut count as *mut u32 as LPARAM) };
    count
}

fn helper(mode: &str) -> Child {
    Command::new(std::env::current_exe().expect("this test's path"))
        .args([
            "--exact",
            "job_helper_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(HELPER, mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start the helper")
}

/// This process as the service observed it.
fn me() -> (CallerFacts, ClientSlot) {
    let opened = ClientProcess::open(std::process::id()).expect("open this process");
    let facts = CallerFacts {
        pid: opened.pid,
        process_generation: opened.generation,
        image: String::new(),
        user_sid: orcel_authority::win::current_process_sid().expect("sid"),
        logon_session_id: 1,
        ts_session_id: 1,
        interactive: true,
        console_session: true,
        elevated: false,
    };
    (facts, Arc::new(Mutex::new(Some(opened))))
}

fn service_job(jobs: &mut ServiceJobs, slot: &ClientSlot, facts: &CallerFacts) -> DispatchJob {
    if slot.lock().expect("slot").is_none() {
        *slot.lock().expect("slot") =
            Some(ClientProcess::open(std::process::id()).expect("open this process"));
    }
    let id = format!(
        "fcj-{:08x}{:024x}",
        std::process::id(),
        orcel_authority::now_ms()
    );
    jobs.create(&id, facts, JobProfile::Dispatch)
        .expect("create the job")
}

fn assign(handle: HANDLE, child: &Child) {
    // SAFETY: both handles are valid for the call.
    let assigned = unsafe { AssignProcessToJobObject(handle, child.as_raw_handle() as _) };
    assert_ne!(assigned, 0, "assign: {}", std::io::Error::last_os_error());
}

fn exits_within(child: &mut Child, limit: Duration) -> Option<i32> {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if let Ok(Some(status)) = child.try_wait() {
            return Some(status.code().unwrap_or(-1));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

#[test]
fn wp110_the_duplicated_handle_carries_assign_process_only() {
    let (facts, slot) = me();
    let mut jobs = ServiceJobs::new(slot.clone());
    let job = service_job(&mut jobs, &slot, &facts);
    let handle = job.handle as HANDLE;
    assert_ne!(handle, 0);
    // SAFETY: a handle this process holds; the call only reads its flags.
    let mut flags = 0u32;
    assert_ne!(unsafe { GetHandleInformation(handle, &mut flags) }, 0);
    assert_eq!(flags & HANDLE_FLAG_INHERIT, 0, "never inheritable");
    // SAFETY: the call is refused for lack of JOB_OBJECT_TERMINATE.
    assert_eq!(unsafe { TerminateJobObject(handle, 1) }, 0);
    // SAFETY: plain call right after the failure.
    assert_eq!(unsafe { GetLastError() }, ERROR_ACCESS_DENIED);
    assert!(limit_flags(handle).is_err(), "no JOB_OBJECT_QUERY");
    assert!(active_processes(handle).is_err(), "no JOB_OBJECT_QUERY");
    let mut sleeper = helper("sleep");
    assign(handle, &sleeper);
    assert_eq!(jobs.active_processes(&job.id), Some(1));
    // SAFETY: orceld closes its handle right after assigning.
    unsafe { CloseHandle(handle) };
    jobs.terminate(&job.id);
    assert!(exits_within(&mut sleeper, Duration::from_secs(1)).is_some());
}

#[test]
fn wp110_a_job_is_made_only_for_the_observed_caller_instance() {
    let (facts, slot) = me();
    let mut jobs = ServiceJobs::new(slot.clone());
    // Another PID than the opened process: refused.
    let other = CallerFacts {
        pid: facts.pid.wrapping_add(4),
        ..facts.clone()
    };
    assert!(jobs
        .create(
            &format!("fcj-{}", "1".repeat(32)),
            &other,
            JobProfile::Dispatch
        )
        .is_err());
    // Same PID, another creation time (a recycled PID): refused.
    *slot.lock().expect("slot") = Some(ClientProcess::open(std::process::id()).expect("open"));
    let recycled = CallerFacts {
        process_generation: facts.process_generation.wrapping_add(1),
        ..facts.clone()
    };
    assert!(jobs
        .create(
            &format!("fcj-{}", "2".repeat(32)),
            &recycled,
            JobProfile::Dispatch
        )
        .is_err());
    // Nothing opened for this request: refused.
    assert!(slot.lock().expect("slot").is_none());
    assert!(jobs
        .create(
            &format!("fcj-{}", "3".repeat(32)),
            &facts,
            JobProfile::Dispatch
        )
        .is_err());
}

#[test]
fn wp110_the_job_kills_on_close_and_allows_no_breakaway() {
    let job = create_job().expect("create the job");
    let flags = limit_flags(job.0).expect("limits");
    assert_ne!(flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, 0);
    assert_eq!(flags & JOB_OBJECT_LIMIT_BREAKAWAY_OK, 0);
    assert_eq!(flags & JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK, 0);
    // WP1-15: the UI restrictions (USER handles, atoms, desktop, clipboard,
    // exit, system parameters, display settings) are set on every job.
    assert_eq!(ui_limits(job.0).expect("UI restrictions"), JOB_UI_LIMITS);
    assert_eq!(JOB_UI_LIMITS, 0xff);

    let mut child = helper("breakaway");
    assign(job.0, &child);
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(b"go\n")
        .expect("release the helper");
    assert_eq!(
        exits_within(&mut child, Duration::from_secs(30)),
        Some(0),
        "CREATE_BREAKAWAY_FROM_JOB must fail with access denied inside the job"
    );

    let mut sleeper = helper("sleep");
    assign(job.0, &sleeper);
    drop(job);
    assert!(
        exits_within(&mut sleeper, Duration::from_secs(1)).is_some(),
        "closing the last handle ends the job's processes"
    );
}

#[test]
fn wp110_the_service_terminates_a_dispatch_job_within_a_second() {
    let (facts, slot) = me();
    let mut jobs = ServiceJobs::new(slot.clone());
    let job = service_job(&mut jobs, &slot, &facts);
    assert_eq!(jobs.active_processes(&job.id), Some(0));
    let mut sleeper = helper("sleep");
    assign(job.handle as HANDLE, &sleeper);
    assert_eq!(jobs.active_processes(&job.id), Some(1));
    let started = Instant::now();
    jobs.terminate(&job.id);
    assert!(
        exits_within(&mut sleeper, Duration::from_secs(1)).is_some(),
        "terminated within a second"
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(jobs.active_processes(&job.id), None);
    // SAFETY: the duplicated handle is this process's to close.
    unsafe { CloseHandle(job.handle as HANDLE) };
}

/// Runs the "windows" helper inside `job` and returns its count.
fn windows_seen_in(job: HANDLE) -> i32 {
    let mut child = helper("windows");
    assign(job, &child);
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(b"go\n")
        .expect("release the helper");
    exits_within(&mut child, Duration::from_secs(30)).expect("the helper exits")
}

/// SG132_SLICE5.md: the desktop input host's job keeps kill-on-close and
/// no breakaway, and its UI restrictions leave out exactly `HANDLES` and
/// `GLOBALATOMS`, so a process in it can still use the windows of processes
/// outside it (desktop input on the user's desktop), which a dispatch job
/// refuses. Read-only: the helper reads window titles, nothing is typed or
/// clicked.
#[test]
fn wp110_the_desktop_host_job_keeps_desktop_input_working_and_allows_no_breakaway() {
    use windows_sys::Win32::System::JobObjects::{
        JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_HANDLES,
    };
    let host = create_job_for(JobProfile::DesktopHost).expect("create the desktop host job");
    let flags = limit_flags(host.0).expect("limits");
    assert_ne!(flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, 0);
    assert_eq!(flags & JOB_OBJECT_LIMIT_BREAKAWAY_OK, 0);
    assert_eq!(flags & JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK, 0);
    let ui = ui_limits(host.0).expect("UI restrictions");
    assert_eq!(ui, DESKTOP_HOST_UI_LIMITS);
    assert_eq!(
        DESKTOP_HOST_UI_LIMITS,
        JOB_UI_LIMITS & !(JOB_OBJECT_UILIMIT_HANDLES | JOB_OBJECT_UILIMIT_GLOBALATOMS)
    );

    // Breakaway is refused inside the desktop host job too.
    let mut child = helper("breakaway");
    assign(host.0, &child);
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(b"go\n")
        .expect("release the helper");
    assert_eq!(
        exits_within(&mut child, Duration::from_secs(30)),
        Some(0),
        "CREATE_BREAKAWAY_FROM_JOB must fail with access denied inside the job"
    );

    // Windows of other processes: visible from the desktop host job, not
    // from a dispatch job.
    let outside = foreign_titled_windows();
    let in_host = windows_seen_in(host.0);
    let dispatch = create_job().expect("create a dispatch job");
    let in_dispatch = windows_seen_in(dispatch.0);
    assert_eq!(in_dispatch, 0, "HANDLES hides out-of-job windows");
    if outside > 0 {
        assert!(
            in_host > 0,
            "the desktop host job sees other processes' windows ({outside} outside, {in_host} inside)"
        );
    } else {
        println!("no titled windows of other processes on this desktop; the in-job comparison is vacuous");
    }

    // Terminating ends it within a second; closing the service's handle
    // (kill-on-close) does too.
    let mut sleeper = helper("sleep");
    assign(host.0, &sleeper);
    // SAFETY: the creating handle has JOB_OBJECT_TERMINATE.
    assert_ne!(unsafe { TerminateJobObject(host.0, 1) }, 0);
    assert!(exits_within(&mut sleeper, Duration::from_secs(1)).is_some());
    let mut sleeper = helper("sleep");
    let second = create_job_for(JobProfile::DesktopHost).expect("another desktop host job");
    assign(second.0, &sleeper);
    drop(second);
    assert!(exits_within(&mut sleeper, Duration::from_secs(1)).is_some());
}

/// SG132_SLICE5.md: the service makes a desktop host job for the observed
/// caller only and duplicates an assign-only handle, as for a dispatch.
#[test]
fn wp110_a_desktop_host_job_handle_carries_assign_process_only() {
    let (facts, slot) = me();
    let mut jobs = ServiceJobs::new(slot.clone());
    let job = jobs
        .create(
            &format!("fcj-{}", "d".repeat(32)),
            &facts,
            JobProfile::DesktopHost,
        )
        .expect("create");
    let handle = job.handle as HANDLE;
    // SAFETY: the call is refused for lack of JOB_OBJECT_TERMINATE.
    assert_eq!(unsafe { TerminateJobObject(handle, 1) }, 0);
    assert!(ui_limits(handle).is_err(), "no JOB_OBJECT_QUERY");
    let mut sleeper = helper("sleep");
    assign(handle, &sleeper);
    // SAFETY: orceld closes its handle right after assigning.
    unsafe { CloseHandle(handle) };
    jobs.terminate(&job.id);
    assert!(exits_within(&mut sleeper, Duration::from_secs(1)).is_some());
    // A recycled PID gets nothing.
    *slot.lock().expect("slot") = Some(ClientProcess::open(std::process::id()).expect("open"));
    let recycled = CallerFacts {
        process_generation: facts.process_generation.wrapping_add(1),
        ..facts
    };
    assert!(jobs
        .create(
            &format!("fcj-{}", "e".repeat(32)),
            &recycled,
            JobProfile::DesktopHost
        )
        .is_err());
}
