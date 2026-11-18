//! SG-000132 slice 1: orceld's link to the Orcel authority service.
//!
//! orceld never holds a lease-signing key and never issues a lease here.
//! It reaches the service through `orcel_authority::client`, which verifies
//! the server (PID from the SCM, pipe owner = the virtual service SID)
//! before it sends anything, and checks every lease's ECDSA signature with
//! the public key the verified service reported. When the service is
//! absent or fails a check, every call here answers `AUTHORITY_UNAVAILABLE`:
//! there is no fallback to the user-readable full-control store.
//!
//! How OB-08 plugs in (branch `browser/ob08-full-access`, not yet on main):
//! - `browser_lease::OwnerChannel::requester` is implemented by
//!   [`ServiceOwnerChannel::requester`]: the requester is the process the
//!   service observed recording the grant intent, carried in the signed
//!   lease, not orceld's parent.
//! - OB-08's `ManagementEnv::default(true)` (issuance on the interim store)
//!   is replaced by the service's grant flow; orceld only verifies
//!   ([`ServiceOwnerChannel::verify`]) and, per dispatch, asks `Authorize`.
//!   New browser leases are never written to the user-readable store once
//!   this link is wired; interim-store leases end at migration
//!   (SG-000135 amendment change 3).
//! - The SG-000095 desktop lease keeps its current path in this slice;
//!   SG132_SLICE1.md records the migration plan (desktop dispatch moves
//!   behind `Authorize` with WP1-12, then the per-user store is retired).
//!
//! The `orceld authority-status` and `orceld authority-verify <lease id>`
//! commands exercise the link against the installed service.

#[cfg(test)]
use orcel_authority::client::Expectation;
use orcel_authority::client::{AuthorityClient, VerifiedLease};
use orcel_authority::AuthorityError;

/// The channel name OB-08's prompt and lease record use.
pub(crate) const SERVICE_CHANNEL: &str =
    "Orcel authority service (service-rendered confirmation and Windows Hello)";

/// Who asked for a service-issued lease, as the service observed it
/// (OB-08's `Requester` shape).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServiceRequester {
    pub pid: u32,
    pub image: String,
    pub channel: &'static str,
}

/// The owner channel backed by the authority service.
pub(crate) struct ServiceOwnerChannel {
    client: Result<AuthorityClient, AuthorityError>,
}

impl ServiceOwnerChannel {
    /// The installed service, or a channel that refuses every call.
    pub(crate) fn installed() -> Self {
        Self {
            client: AuthorityClient::installed(),
        }
    }

    /// A channel for an explicit server (tests and the console harness).
    #[cfg(test)]
    pub(crate) fn with_expectation(expectation: Expectation) -> Self {
        Self {
            client: Ok(AuthorityClient::with_expectation(expectation)),
        }
    }

    fn client(&self) -> Result<&AuthorityClient, AuthorityError> {
        self.client.as_ref().map_err(Clone::clone)
    }

    /// The lease, confirmed active by the service and signature-checked.
    pub(crate) fn verify(&self, lease_id: &str) -> Result<VerifiedLease, AuthorityError> {
        self.client()?.verify_lease(lease_id)
    }

    /// The requester the service recorded for `lease_id`.
    pub(crate) fn requester(&self, lease_id: &str) -> Result<ServiceRequester, AuthorityError> {
        let verified = self.verify(lease_id)?;
        Ok(ServiceRequester {
            pid: verified.lease.body.requester.pid,
            image: verified.lease.body.requester.image,
            channel: SERVICE_CHANNEL,
        })
    }

    /// The service's status as it reported it.
    pub(crate) fn status(&self) -> Result<serde_json::Value, AuthorityError> {
        self.client()?.status()
    }
}

fn print_error(error: &AuthorityError) -> i32 {
    eprintln!("orceld authority: {error}");
    3
}

/// `orceld authority-status` and `orceld authority-verify <lease id>`.
/// `None` when `args` is not one of them.
pub(crate) fn run_cli(args: &[String]) -> Option<i32> {
    let command = args.first()?.as_str();
    match command {
        "authority-status" => {
            let channel = ServiceOwnerChannel::installed();
            Some(match channel.status() {
                Ok(status) => {
                    println!("{status}");
                    0
                }
                Err(error) => print_error(&error),
            })
        }
        "authority-verify" => {
            let Some(lease_id) = args.get(1) else {
                eprintln!("usage: orceld authority-verify <lease id>");
                return Some(2);
            };
            let channel = ServiceOwnerChannel::installed();
            Some(
                match (channel.verify(lease_id), channel.requester(lease_id)) {
                    (Ok(verified), Ok(requester)) => {
                        let summary = serde_json::json!({
                            "lease_id": verified.lease.body.lease_id,
                            "scope": verified.lease.body.scope.describe(),
                            "expires_at_ms": verified.lease.body.expires_at_ms,
                            "epoch": verified.epoch,
                            "revocations": verified.revocations,
                            "requester": format!("pid {} {} (via {})", requester.pid, requester.image, requester.channel),
                            "signature": "verified",
                        });
                        println!("{summary}");
                        0
                    }
                    (Err(error), _) | (_, Err(error)) => print_error(&error),
                },
            )
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use orcel_contracts::FailureCode;

    fn absent() -> ServiceOwnerChannel {
        ServiceOwnerChannel::with_expectation(Expectation {
            pipe_name: format!(
                "{}orceld-absent-{}",
                orcel_authority::CONSOLE_PIPE_PREFIX,
                std::process::id()
            ),
            pid: 4,
            owner_sid: "S-1-5-18".to_owned(),
        })
    }

    #[test]
    fn sg132_the_link_fails_closed_when_the_service_is_absent() {
        let channel = absent();
        let expected = if cfg!(windows) {
            FailureCode::AuthorityUnavailable
        } else {
            FailureCode::Unsupported
        };
        assert_eq!(
            channel.verify("al-0").err().map(|e| e.code),
            Some(expected.clone())
        );
        assert_eq!(
            channel.requester("al-0").err().map(|e| e.code),
            Some(expected.clone())
        );
        assert_eq!(channel.status().err().map(|e| e.code), Some(expected));
    }

    #[test]
    fn sg132_other_arguments_are_not_authority_commands() {
        assert_eq!(run_cli(&[]), None);
        assert_eq!(run_cli(&["--help".to_owned()]), None);
        assert_eq!(run_cli(&["authority-verify".to_owned()]), Some(2));
    }
}
