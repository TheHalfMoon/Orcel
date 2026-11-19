//! SG-000132 WP1-10 (SG132_SLICE5.md): the desktop input host in a
//! service-made Job Object.
//!
//! The computer host (`apps/orcel-computer-host`, selected by
//! `ORCEL_COMPUTER_HOST_BIN`) is long-lived: one process serves many
//! requests and keeps window bindings between them. So its job is per lease,
//! not per dispatch: when the authority service admits a desktop input
//! action under a lease (`full_control_dispatch::desktop_gate`), the action
//! runs only in a host inside that lease's job
//! (`full_control_dispatch::ensure_lease_host`). The first action of a lease
//! starts a fresh host: `DesktopHostJob`, `JobAck`, the host started
//! suspended with a scrubbed environment (`computer_host_environment`),
//! assigned with the duplicated assign-only handle, `DispatchActive`, then
//! resumed; the host it replaces is ended. The service terminates the job
//! when the lease ends (revoke, Stop, session lock, sign-out, disconnect,
//! expiry, an epoch move), which ends the host and every per-request worker
//! it started, in the middle of an action if need be. A new lease gets a
//! fresh host.
//!
//! A request admitted under a lease never falls back to a host outside the
//! job: [`required`] names the lease for the rest of the request, and
//! `uia::computer_host` refuses (`LEASE_INVALID`) when the running host is
//! not that lease's or has ended. Observation (Safe mode, no lease) keeps
//! using whatever host runs; when the leased host was ended with its lease,
//! the next observation starts a plain host again, outside any job, as
//! before this slice. Where no service is installed, the deprecated store's
//! desktop input also keeps the plain host (slice 2 behaviour).
//!
//! Approvals and grants stay with the service's own Windows dialogs and the
//! per-action approval; nothing here approves anything.

use crate::full_control_dispatch::{ensure_lease_host, HostLauncher, LeaseHost};
use orcel_contracts::FailureCode;
use orcel_provider_fs::ProviderError;
use std::cell::RefCell;
use std::sync::Mutex;

/// The lease whose job the running computer host is in (`None`: the host,
/// if any, runs outside a job).
static CURRENT: Mutex<Option<LeaseHost>> = Mutex::new(None);

thread_local! {
    /// The lease whose host the request this thread is dispatching must
    /// use (set once the service admitted a desktop action under it).
    static REQUIRED: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// After the service admitted a desktop action under `lease_id`: the
/// computer host runs in that lease's job (started fresh if it does not),
/// and the rest of this request uses only that host.
///
/// SG132_SLICE6.md (slice 5 residual 4): from here every message this
/// request sends to the computer host is checked, under the adapter's
/// session lock, to reach that host while it runs
/// (`orcel_provider_uia::require_host_generation`), so a host replaced in
/// the middle of the action receives nothing more of it.
pub(crate) fn require_for(lease_id: &str) -> Result<(), ProviderError> {
    let port = crate::authority_link::ServicePort::installed_service();
    let host = ensure_lease_host(&port, &ComputerHostLauncher, &CURRENT, lease_id)?;
    orcel_provider_uia::require_host_generation(Some(host.generation));
    REQUIRED.with(|required| *required.borrow_mut() = Some(lease_id.to_owned()));
    Ok(())
}

/// The lease this thread's request must use the host of, if any.
pub(crate) fn required() -> Option<String> {
    REQUIRED.with(|required| required.borrow().clone())
}

/// Forgets what this thread's request required (at its start and end).
pub(crate) fn clear_required() {
    REQUIRED.with(|required| *required.borrow_mut() = None);
    orcel_provider_uia::require_host_generation(None);
}

/// The generation of the computer host started into `lease_id`'s job, if
/// that lease has one; the caller checks that this host is still the one
/// in use (`ComputerHostAdapter::host_running_at`), so a plain host started
/// after it (an observation's restart) is never taken for the lease's.
pub(crate) fn serving(lease_id: &str) -> Option<u64> {
    CURRENT.lock().ok().and_then(|current| {
        current
            .as_ref()
            .filter(|host| host.lease_id == lease_id)
            .map(|host| host.generation)
    })
}

/// The host was restarted outside any job (observation after the leased
/// host ended).
#[cfg(windows)]
pub(crate) fn forget() {
    if let Ok(mut current) = CURRENT.lock() {
        *current = None;
    }
}

/// The production launcher: the configured computer host, started into the
/// job and adopted by orceld's computer host adapter.
struct ComputerHostLauncher;

impl HostLauncher for ComputerHostLauncher {
    fn running(&self, generation: u64) -> bool {
        crate::uia::computer_host_running_at(generation)
    }

    #[cfg(windows)]
    fn start_in_job(
        &self,
        job_handle: u64,
        confirm: &dyn Fn() -> Result<(), ProviderError>,
    ) -> Result<u64, ProviderError> {
        // Owned from here: closed on every path, right after the assign.
        let job = orcel_authority::win::Owned(job_handle as _);
        let program = std::env::var_os("ORCEL_COMPUTER_HOST_BIN").ok_or_else(|| {
            ProviderError::new(
                FailureCode::ProviderUnavailable,
                "ORCEL_COMPUTER_HOST_BIN is not configured",
            )
        })?;
        let program = std::path::PathBuf::from(program);
        let environment = orcel_provider_uia::computer_host_environment();
        let (process, stdin, stdout) = crate::fc_worker::start_suspended_in_job(
            &crate::fc_worker::Launch {
                program: &program,
                arguments: "",
                environment: Some(&environment),
                no_window: false,
            },
            job,
            confirm,
        )?;
        crate::uia::adopt_computer_host(
            program,
            Box::new(JobbedHost(process)),
            Box::new(stdin),
            Box::new(stdout),
        )
    }

    #[cfg(not(windows))]
    fn start_in_job(
        &self,
        _job_handle: u64,
        _confirm: &dyn Fn() -> Result<(), ProviderError>,
    ) -> Result<u64, ProviderError> {
        Err(ProviderError::new(
            FailureCode::AuthorityUnavailable,
            "service-made Job Objects exist only on Windows",
        ))
    }
}

/// A computer host process orceld started into a Job Object.
#[cfg(windows)]
pub(crate) struct JobbedHost(pub(crate) orcel_authority::win::Owned);

#[cfg(windows)]
impl orcel_provider_uia::SpawnedHost for JobbedHost {
    fn running(&mut self) -> bool {
        use windows_sys::Win32::Foundation::WAIT_TIMEOUT;
        use windows_sys::Win32::System::Threading::WaitForSingleObject;
        // SAFETY: the process handle orceld holds; a zero-timeout wait.
        unsafe { WaitForSingleObject(self.0 .0, 0) == WAIT_TIMEOUT }
    }

    fn end(&mut self) {
        use windows_sys::Win32::System::Threading::{TerminateProcess, WaitForSingleObject};
        // SAFETY: the process handle orceld holds (it created the process).
        unsafe {
            TerminateProcess(self.0 .0, 1);
            WaitForSingleObject(self.0 .0, 5_000);
        }
    }
}
