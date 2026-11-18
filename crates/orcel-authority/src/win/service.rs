//! The SCM entry of `orcel-authority.exe` (service `OrcelAuthority`,
//! account `NT SERVICE\OrcelAuthority`).
//!
//! The service accepts STOP, SHUTDOWN and SESSIONCHANGE. Session changes
//! (`WTS_SESSION_UNLOCK`, `_LOCK`, `_LOGOFF`, `WTS_CONSOLE_DISCONNECT`,
//! `WTS_REMOTE_DISCONNECT`) reach the runtime through a channel; the control
//! handler itself only forwards and returns.
//!
//! Start refuses (and the SCM reports a service-specific error) unless the
//! process runs as the virtual service account, the state directory exists
//! with the protected DACL the install script set, and the pipe name is
//! free.

use super::runtime::{run_loop, start, Control, RunConfig};
use super::{account_sid, current_process_sid, wide};
use crate::caller::ClientPolicy;
use crate::core::EventSink;
use crate::error::AuthorityError;
use crate::RunMode;
use std::path::PathBuf;
use std::sync::atomic::{AtomicIsize, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Mutex, OnceLock};
use windows_sys::Win32::Foundation::{
    ERROR_CALL_NOT_IMPLEMENTED, ERROR_SERVICE_SPECIFIC_ERROR, NO_ERROR,
};
use windows_sys::Win32::System::RemoteDesktop::WTSSESSION_NOTIFICATION;
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW,
    SERVICE_ACCEPT_SESSIONCHANGE, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
    SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SESSIONCHANGE, SERVICE_CONTROL_SHUTDOWN,
    SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STOPPED,
    SERVICE_STOP_PENDING, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
};

/// The configuration file the install script writes in the state directory.
pub const CONFIG_FILE: &str = "config.json";

static CONTROL: OnceLock<Mutex<Option<Sender<Control>>>> = OnceLock::new();
static STATUS_HANDLE: AtomicIsize = AtomicIsize::new(0);

fn send(control: Control) {
    if let Some(slot) = CONTROL.get() {
        if let Ok(guard) = slot.lock() {
            if let Some(sender) = guard.as_ref() {
                let _ = sender.send(control);
            }
        }
    }
}

fn set_status(state: u32, accepted: u32, exit: u32, specific: u32) {
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: accepted,
        dwWin32ExitCode: exit,
        dwServiceSpecificExitCode: specific,
        dwCheckPoint: 0,
        dwWaitHint: if state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING {
            10_000
        } else {
            0
        },
    };
    let handle = STATUS_HANDLE.load(Ordering::Acquire);
    if handle != 0 {
        // SAFETY: a handle from RegisterServiceCtrlHandlerExW; `status` lives
        // through the call.
        unsafe { SetServiceStatus(handle, &status) };
    }
}

unsafe extern "system" fn handler(
    control: u32,
    event_type: u32,
    event_data: *mut std::ffi::c_void,
    _context: *mut std::ffi::c_void,
) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            set_status(SERVICE_STOP_PENDING, 0, NO_ERROR, 0);
            send(Control::Stop);
            NO_ERROR
        }
        SERVICE_CONTROL_SESSIONCHANGE => {
            if !event_data.is_null() {
                // SAFETY: for SESSIONCHANGE the SCM passes a
                // WTSSESSION_NOTIFICATION.
                let session = (*(event_data as *const WTSSESSION_NOTIFICATION)).dwSessionId;
                send(Control::SessionChange {
                    event: event_type,
                    session,
                });
            }
            NO_ERROR
        }
        SERVICE_CONTROL_INTERROGATE => NO_ERROR,
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}

/// `%ProgramFiles%`.
fn program_files() -> PathBuf {
    std::env::var_os("ProgramFiles")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"))
}

/// Every trusted orceld image must sit under `%ProgramFiles%\Orcel\` and be
/// replaceable by no one but SYSTEM, Administrators, TrustedInstaller and
/// the service (the file and every directory above it are checked). A
/// configured path anywhere a user could write refuses the start.
pub fn check_trusted_images(
    policy: &ClientPolicy,
    program_files: &std::path::Path,
    service_sid: &str,
) -> Result<(), AuthorityError> {
    let required = program_files.join("Orcel");
    let prefix = format!("{}\\", required.to_string_lossy().to_lowercase());
    for image in &policy.trusted_orceld_images {
        let text = image.to_string_lossy().to_lowercase();
        if !text.starts_with(&prefix) || text.contains("\\..\\") {
            return Err(AuthorityError::unavailable(format!(
                "the trusted orceld image {} is not under {}; reinstall with the hash-pinned orceld",
                image.display(),
                required.display()
            )));
        }
        super::acl::check_trusted_image(image, service_sid)?;
    }
    Ok(())
}

/// The service's own binary must sit under `%ProgramFiles%\Orcel\` with the
/// same protection as the trusted orceld image.
fn check_own_image(
    program_files: &std::path::Path,
    service_sid: &str,
) -> Result<(), AuthorityError> {
    let own = std::env::current_exe()
        .map_err(|error| AuthorityError::unavailable(format!("the service's own path: {error}")))?;
    check_trusted_images(
        &ClientPolicy {
            trusted_orceld_images: vec![own],
        },
        program_files,
        service_sid,
    )
}

/// The installed configuration: fixed paths under `%ProgramData%`, the
/// pipe owned by the virtual service SID, the protected state directory.
pub fn service_config() -> Result<RunConfig, AuthorityError> {
    let service_sid = account_sid(crate::SERVICE_ACCOUNT)?;
    let running_as = current_process_sid()?;
    if !running_as.eq_ignore_ascii_case(&service_sid) {
        return Err(AuthorityError::denied(format!(
            "the service must run as {} ({service_sid}), not {running_as}",
            crate::SERVICE_ACCOUNT
        )));
    }
    let program_data = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    let state_dir = program_data.join("Orcel").join("authority");
    if !state_dir.is_dir() {
        return Err(AuthorityError::unavailable(format!(
            "the state directory {} does not exist; run scripts/install-orcel-authority.ps1",
            state_dir.display()
        )));
    }
    super::acl::check_protected_dir(&state_dir, &service_sid)?;
    let policy = match std::fs::read_to_string(state_dir.join(CONFIG_FILE)) {
        Ok(text) => serde_json::from_str::<ClientPolicy>(&text)
            .map_err(|error| AuthorityError::internal(format!("parse {CONFIG_FILE}: {error}")))?,
        Err(_) => ClientPolicy::default(),
    };
    check_trusted_images(&policy, &program_files(), &service_sid)?;
    check_own_image(&program_files(), &service_sid)?;
    Ok(RunConfig {
        mode: RunMode::Service,
        state_dir,
        public_dir: program_data.join("Orcel").join("authority-public"),
        pipe_name: crate::SERVICE_PIPE_NAME.to_owned(),
        owner_sid: service_sid,
        policy,
        scripted_consent_log: None,
    })
}

fn report_start_failure(error: &AuthorityError) {
    if let Ok(sink) = super::eventlog::EventLogSink::open() {
        let _ = sink.record(
            crate::EVENT_SERVICE_ERROR,
            true,
            &format!("orcel-authority/1|refused-start|{}", error.message),
        );
    }
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut windows_sys::core::PWSTR) {
    let name = wide(crate::SERVICE_NAME);
    // SAFETY: `name` is NUL-terminated; `handler` is a valid callback.
    let handle = RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(handler), std::ptr::null());
    if handle == 0 {
        return;
    }
    STATUS_HANDLE.store(handle, Ordering::Release);
    set_status(SERVICE_START_PENDING, 0, NO_ERROR, 0);
    let (sender, receiver) = channel();
    let slot = CONTROL.get_or_init(|| Mutex::new(None));
    if let Ok(mut guard) = slot.lock() {
        *guard = Some(sender);
    }
    let runtime = match service_config().and_then(start) {
        Ok(runtime) => runtime,
        Err(error) => {
            report_start_failure(&error);
            set_status(SERVICE_STOPPED, 0, ERROR_SERVICE_SPECIFIC_ERROR, 1);
            return;
        }
    };
    set_status(
        SERVICE_RUNNING,
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_SESSIONCHANGE,
        NO_ERROR,
        0,
    );
    let result = run_loop(&runtime, &receiver);
    match result {
        Ok(()) => set_status(SERVICE_STOPPED, 0, NO_ERROR, 0),
        Err(error) => {
            report_start_failure(&error);
            set_status(SERVICE_STOPPED, 0, ERROR_SERVICE_SPECIFIC_ERROR, 2);
        }
    }
}

/// Hands the process to the SCM. Fails when not started by the SCM.
pub fn dispatch() -> Result<(), AuthorityError> {
    let mut name = wide(crate::SERVICE_NAME);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: std::ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    // SAFETY: a NULL-terminated table whose strings outlive the call.
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        return Err(AuthorityError::unavailable(format!(
            "not started by the service control manager ({}); use --console for the development harness",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_images_outside_program_files_orcel_are_refused() {
        let program_files = PathBuf::from(r"C:\Program Files");
        for image in [
            r"C:\Users\me\Orcel\target\release\orceld.exe",
            r"D:\Orcel\orceld.exe",
            r"C:\Program Files\Orcel\..\..\Users\me\orceld.exe",
            r"C:\Program Files\OrcelX\orceld.exe",
        ] {
            let policy = ClientPolicy {
                trusted_orceld_images: vec![PathBuf::from(image)],
            };
            assert!(
                check_trusted_images(&policy, &program_files, "S-1-5-80-1-2-3-4-5").is_err(),
                "{image}"
            );
        }
        // Under the right prefix the ACL check decides; a missing file fails.
        let policy = ClientPolicy {
            trusted_orceld_images: vec![PathBuf::from(
                r"C:\Program Files\Orcel\missing-orceld.exe",
            )],
        };
        assert!(check_trusted_images(&policy, &program_files, "S-1-5-80-1-2-3-4-5").is_err());
        assert_eq!(
            check_trusted_images(
                &ClientPolicy::default(),
                &program_files,
                "S-1-5-80-1-2-3-4-5"
            ),
            Ok(())
        );
    }
}
