//! The authority client every Orcel component uses (orceld first; the
//! indicator, `orcel authority enroll` and the CLI in later slices).
//!
//! Before anything is sent the client checks that the pipe's server process
//! is the service's process (`QueryServiceStatusEx`) and that the pipe's
//! owner is the virtual service SID of `NT SERVICE\OrcelAuthority`
//! (`LookupAccountNameW`). Any mismatch, an absent service or a failed
//! call is [`FailureCode::AuthorityUnavailable`]: the client fails closed
//! and never falls back to a user-readable store.
//!
//! Lease verification ([`AuthorityClient::verify_lease`]) asks the service
//! for the lease and its state now, then checks the ECDSA signature with the
//! public key the verified service reported, so a lease body the service
//! did not sign is refused even if the transport were wrong.
//!
//! [`FailureCode::AuthorityUnavailable`]: orcel_contracts::FailureCode::AuthorityUnavailable

use crate::error::AuthorityError;
use crate::lease::SignedLease;
use crate::protocol::{AuthorizeClaims, Request};
use orcel_contracts::ExecutorClass;
use serde_json::Value;
use std::time::Duration;

/// Per-frame timeout of a client call.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(15);

/// Who the client expects to serve the pipe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expectation {
    pub pipe_name: String,
    pub pid: u32,
    pub owner_sid: String,
}

impl Expectation {
    /// The installed service: its pipe, its current PID from the SCM, and
    /// the virtual service SID.
    pub fn installed_service() -> Result<Self, AuthorityError> {
        #[cfg(windows)]
        {
            let pid = scm::service_pid()?;
            let owner_sid = crate::win::account_sid(crate::SERVICE_ACCOUNT)?;
            Ok(Self {
                pipe_name: crate::SERVICE_PIPE_NAME.to_owned(),
                pid,
                owner_sid,
            })
        }
        #[cfg(not(windows))]
        {
            Err(AuthorityError::unsupported())
        }
    }
}

/// Slice 2 (desktop lease migration): whether the authority service is
/// installed (registered with the SCM), running or not. When it is, new
/// Full Control leases come from it only: the user-readable store issues
/// nothing, and an unreachable service fails closed instead of falling back.
pub fn service_installed() -> bool {
    #[cfg(windows)]
    {
        scm::installed()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// A lease the service confirmed active, with a verified signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedLease {
    pub lease: SignedLease,
    pub epoch: u64,
    pub revocations: u64,
    pub checked_at_ms: u64,
}

pub struct AuthorityClient {
    expectation: Expectation,
}

impl AuthorityClient {
    /// The installed service, or `AuthorityUnavailable`.
    pub fn installed() -> Result<Self, AuthorityError> {
        Ok(Self {
            expectation: Expectation::installed_service()?,
        })
    }

    /// A client for an explicit expectation (the console harness, tests).
    pub fn with_expectation(expectation: Expectation) -> Self {
        Self { expectation }
    }

    pub fn expectation(&self) -> &Expectation {
        &self.expectation
    }

    /// One request on a fresh, verified connection.
    pub fn call(&self, request: &Request) -> Result<Value, AuthorityError> {
        #[cfg(windows)]
        {
            use crate::protocol::{read_frame, write_frame, Response};
            let server = crate::win::pipe::ServerExpectation {
                pipe_name: self.expectation.pipe_name.clone(),
                pid: self.expectation.pid,
                owner_sid: self.expectation.owner_sid.clone(),
            };
            let mut pipe = crate::win::pipe::connect_verified(&server, CALL_TIMEOUT)?;
            let body = serde_json::to_vec(request).map_err(|error| {
                AuthorityError::internal(format!("encode the request: {error}"))
            })?;
            write_frame(&mut pipe, &body)?;
            let frame = read_frame(&mut pipe)?.ok_or_else(|| {
                AuthorityError::unavailable("the authority closed the pipe without an answer")
            })?;
            let response: Response = serde_json::from_slice(&frame).map_err(|error| {
                AuthorityError::unavailable(format!("a malformed authority answer: {error}"))
            })?;
            response.into_result()
        }
        #[cfg(not(windows))]
        {
            let _ = request;
            Err(AuthorityError::unsupported())
        }
    }

    pub fn status(&self) -> Result<Value, AuthorityError> {
        self.call(&Request::Status)
    }

    /// The lease, confirmed active by the service now, with its signature
    /// checked against the public key the verified service reported.
    pub fn verify_lease(&self, lease_id: &str) -> Result<VerifiedLease, AuthorityError> {
        #[cfg(windows)]
        {
            use crate::lease::SignatureVerifier;
            let status = self.status()?;
            let public = status["public_key_hex"]
                .as_str()
                .and_then(crate::unhex)
                .ok_or_else(|| {
                    AuthorityError::unavailable("the authority reported no public key")
                })?;
            let verifier = crate::win::crypto::EcdsaP256Verifier::from_public_blob(&public)?;
            if status["key_id"].as_str() != Some(verifier.key_id().as_str()) {
                return Err(AuthorityError::unavailable(
                    "the authority's key id does not match its key",
                ));
            }
            let answer = self.call(&Request::Verify {
                lease_id: lease_id.to_owned(),
            })?;
            let lease: SignedLease =
                serde_json::from_value(answer["lease"].clone()).map_err(|error| {
                    AuthorityError::unavailable(format!("a malformed lease: {error}"))
                })?;
            if lease.body.lease_id != lease_id || answer["state"].as_str() != Some("active") {
                return Err(AuthorityError::lease_invalid(
                    "the authority did not confirm this lease active",
                ));
            }
            lease.verify_signature(&verifier)?;
            Ok(VerifiedLease {
                lease,
                epoch: answer["epoch"].as_u64().unwrap_or(0),
                revocations: answer["revocations"].as_u64().unwrap_or(0),
                checked_at_ms: answer["checked_at_ms"].as_u64().unwrap_or(0),
            })
        }
        #[cfg(not(windows))]
        {
            let _ = lease_id;
            Err(AuthorityError::unsupported())
        }
    }

    pub fn authorize(
        &self,
        lease_id: &str,
        executor: ExecutorClass,
        claims: AuthorizeClaims,
    ) -> Result<Value, AuthorityError> {
        self.call(&Request::Authorize {
            lease_id: lease_id.to_owned(),
            executor,
            claims,
        })
    }

    pub fn revoke(&self, lease_id: &str) -> Result<Value, AuthorityError> {
        self.call(&Request::Revoke {
            lease_id: lease_id.to_owned(),
        })
    }

    pub fn stop(&self) -> Result<Value, AuthorityError> {
        self.call(&Request::Stop)
    }

    pub fn list(&self) -> Result<Value, AuthorityError> {
        self.call(&Request::List)
    }

    /// WP1-03: the latest anchor the service holds of this account's `log`
    /// (`Value::Null` when it holds none).
    pub fn anchor_status(&self, log: &str) -> Result<Value, AuthorityError> {
        self.call(&Request::AnchorStatus {
            log: log.to_owned(),
        })
    }

    /// WP1-03: asks the service to hold an anchor of orceld's audit chain;
    /// `reset` is the owner reset record digest a post-reset file names.
    pub fn anchor(
        &self,
        anchor: &orcel_contracts::event::AnchorRef,
        link: Option<crate::protocol::ChainLink>,
        reset: Option<String>,
    ) -> Result<Value, AuthorityError> {
        self.call(&Request::Anchor {
            anchor: anchor.clone(),
            link,
            reset,
        })
    }
}

#[cfg(windows)]
mod scm {
    use crate::error::AuthorityError;
    use crate::win::wide;
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_MANAGER_CONNECT,
        SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_STATUS_PROCESS,
    };

    struct Sc(isize);

    impl Drop for Sc {
        fn drop(&mut self) {
            if self.0 != 0 {
                // SAFETY: opened below, closed once.
                unsafe { CloseServiceHandle(self.0) };
            }
        }
    }

    /// Whether the service is registered with the SCM.
    pub(super) fn installed() -> bool {
        // SAFETY: plain calls; handles are closed by Sc.
        let manager =
            Sc(unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) });
        if manager.0 == 0 {
            // The SCM could not be asked: treat the service as present, so
            // nothing falls back to the user-readable store (fail closed).
            return true;
        }
        let name = wide(crate::SERVICE_NAME);
        let service = Sc(unsafe { OpenServiceW(manager.0, name.as_ptr(), SERVICE_QUERY_STATUS) });
        if service.0 != 0 {
            return true;
        }
        // Only "does not exist" means not installed; any other failure
        // (access denied, for example) fails closed as installed.
        // SAFETY: plain call.
        let error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        error != windows_sys::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST
    }

    /// The running service's process id.
    pub(super) fn service_pid() -> Result<u32, AuthorityError> {
        // SAFETY: plain calls; handles are closed by Sc.
        let manager =
            Sc(unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) });
        if manager.0 == 0 {
            return Err(AuthorityError::unavailable(
                "the service control manager could not be opened",
            ));
        }
        let name = wide(crate::SERVICE_NAME);
        let service = Sc(unsafe { OpenServiceW(manager.0, name.as_ptr(), SERVICE_QUERY_STATUS) });
        if service.0 == 0 {
            return Err(AuthorityError::unavailable(
                "the Orcel authority service is not installed; Full Control is unavailable",
            ));
        }
        let mut status: SERVICE_STATUS_PROCESS = unsafe { std::mem::zeroed() };
        let mut needed = 0u32;
        // SAFETY: `status` is a SERVICE_STATUS_PROCESS of the size passed.
        let ok = unsafe {
            QueryServiceStatusEx(
                service.0,
                SC_STATUS_PROCESS_INFO,
                (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
                std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut needed,
            )
        };
        if ok == 0 || status.dwCurrentState != SERVICE_RUNNING || status.dwProcessId == 0 {
            return Err(AuthorityError::unavailable(
                "the Orcel authority service is not running; Full Control is unavailable",
            ));
        }
        Ok(status.dwProcessId)
    }
}
