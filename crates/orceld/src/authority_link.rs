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
//! Slice 2 wires OB-08 and the desktop path to it:
//! - [`ServiceLeaseSource`] is OB-08's lease source: it reads the browser
//!   leases of this Windows user and logon session from the service, checks
//!   each one's ECDSA signature with the public key the verified service
//!   reported (no key orceld or the user can read), and asks the service's
//!   audit-first `Authorize` (executor Browser) before each covered action.
//!   Only the trusted orceld image (`%ProgramFiles%\Orcel\orceld.exe`) uses
//!   a lease; any other orceld asks for every action as before. The
//!   requester shown is the process the service observed recording the
//!   grant intent, carried in the signed lease.
//! - [`ServiceLeaseManager`] is the owner's list and revoke; orceld issues
//!   nothing (`orcel browser grant` runs the service's grant flow).
//! - [`desktop_input_gate`]: when the service is installed, a desktop
//!   action needs an active service-issued desktop lease and the service's
//!   `Authorize` (DesktopInput); the deprecated user-readable store is
//!   consulted only where the service is not installed (existing
//!   behaviour), never as a fallback for an unreachable service.
//!
//! The `orceld authority-status` and `orceld authority-verify <lease id>`
//! commands exercise the link against the installed service.

use crate::browser_lease::{AuthorityView, CoveredAction, LeaseManager, LeaseSource};
#[cfg(any(test, feature = "browser-full-scripted-consent"))]
use orcel_authority::client::Expectation;
use orcel_authority::client::{AuthorityClient, VerifiedLease};
use orcel_authority::lease::{LeaseScope, SignatureVerifier, SignedLease};
use orcel_authority::protocol::AuthorizeClaims;
use orcel_authority::AuthorityError;
use orcel_contracts::{ExecutorClass, FailureCode, RequestEnvelope};
use orcel_policy::browser_lease::{BrowserFamily, BrowserLease};
use orcel_provider_fs::ProviderError;
use serde_json::Value;
use sha2::{Digest, Sha256};

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

// ---------------------------------------------------------------------
// Slice 2: service-issued browser leases (OB-08) and the desktop gate.
// ---------------------------------------------------------------------

fn provider(error: AuthorityError) -> ProviderError {
    ProviderError::new(error.code, error.message)
}

fn unavailable(message: impl Into<String>) -> ProviderError {
    ProviderError::new(FailureCode::AuthorityUnavailable, message)
}

/// A service lease with a browser scope, admitted after its signature
/// verified with the service's public key. Desktop leases are `None`.
pub(crate) fn admit_browser_lease(
    lease: &SignedLease,
    verifier: &dyn SignatureVerifier,
) -> Result<Option<BrowserLease>, ProviderError> {
    lease
        .verify_signature(verifier)
        .map_err(|error| unavailable(format!("a lease from the authority service: {error}")))?;
    let body = &lease.body;
    let LeaseScope::BrowserFullAccess {
        client_ref,
        session_id,
        origins,
        families,
        task,
    } = &body.scope
    else {
        return Ok(None);
    };
    let mut families = families
        .iter()
        .map(|family| {
            let name = serde_json::to_value(family)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .unwrap_or_default();
            BrowserFamily::parse(&name)
                .ok_or_else(|| unavailable("a service lease names an unknown family"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    families.sort();
    let admitted = BrowserLease {
        lease_id: body.lease_id.clone(),
        client_ref: client_ref.clone(),
        session_id: session_id.clone(),
        windows_user_sid: body.windows_user_sid.clone(),
        logon_session_id: body.logon_session_id,
        authority_epoch: body.authority_epoch,
        revocations_at_issue: body.revocations_at_issue,
        origins: origins.clone(),
        families,
        issued_at_ms: body.issued_at_ms,
        expires_at_ms: body.expires_at_ms,
        task: task.clone(),
        principal_id: body.principal_id.clone(),
        requester: format!(
            "pid {} {} (via the Orcel authority service)",
            body.requester.pid, body.requester.image
        ),
    };
    admitted.check_shape().map_err(|error| {
        unavailable(format!(
            "a browser lease from the authority service is out of shape: {}",
            error.message
        ))
    })?;
    Ok(Some(admitted))
}

/// The active browser leases of a `List` answer, each admitted.
pub(crate) fn admit_listed(
    listed: &Value,
    verifier: &dyn SignatureVerifier,
) -> Result<Vec<BrowserLease>, ProviderError> {
    let mut out = Vec::new();
    for entry in listed["leases"].as_array().into_iter().flatten() {
        if entry["state"].as_str() != Some("active") {
            continue;
        }
        let lease: SignedLease = serde_json::from_value(entry["lease"].clone())
            .map_err(|error| unavailable(format!("a malformed lease from the service: {error}")))?;
        if let Some(admitted) = admit_browser_lease(&lease, verifier)? {
            out.push(admitted);
        }
    }
    Ok(out)
}

/// Only the trusted orceld image (the service's `orceld` role, observed from
/// the pipe) uses service leases; any other orceld sees none and asks.
pub(crate) fn status_admits_leases(status: &Value) -> bool {
    status["caller_role"].as_str() == Some("orceld")
}

/// The SHA-256 the service's audit records for one covered browser action.
pub(crate) fn action_digest(action: &CoveredAction) -> String {
    let material = format!(
        "orcel-browser-lease-action/1|{}|{}|{}|{}|{}",
        action.lease_id,
        action.record_id,
        action.family.as_str(),
        action.origin,
        action.page_id
    );
    Sha256::digest(material.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Which service this build talks to for leases.
enum Target {
    /// No service is installed: no service lease can apply.
    NotInstalled,
    Client(AuthorityClient),
    Broken(AuthorityError),
}

fn target_for_this_build() -> Target {
    // TEST BUILDS ONLY: the scripted E2E harness runs a console authority
    // and names it here.
    #[cfg(feature = "browser-full-scripted-consent")]
    if let Ok(text) = std::env::var("ORCEL_E2E_AUTHORITY") {
        let parsed: Result<Value, _> = serde_json::from_str(&text);
        return match parsed {
            Ok(value) => match (
                value["pipe"].as_str(),
                value["pid"]
                    .as_u64()
                    .and_then(|pid| u32::try_from(pid).ok()),
                value["owner_sid"].as_str(),
            ) {
                (Some(pipe), Some(pid), Some(owner)) => {
                    Target::Client(AuthorityClient::with_expectation(Expectation {
                        pipe_name: pipe.to_owned(),
                        pid,
                        owner_sid: owner.to_owned(),
                    }))
                }
                _ => Target::Broken(AuthorityError::unavailable(
                    "ORCEL_E2E_AUTHORITY names no pipe, pid and owner",
                )),
            },
            Err(error) => Target::Broken(AuthorityError::unavailable(format!(
                "ORCEL_E2E_AUTHORITY is not JSON: {error}"
            ))),
        };
    }
    if !orcel_authority::client::service_installed() {
        return Target::NotInstalled;
    }
    match AuthorityClient::installed() {
        Ok(client) => Target::Client(client),
        Err(error) => Target::Broken(error),
    }
}

/// OB-08's lease source: the authority service.
pub(crate) struct ServiceLeaseSource {
    target: Target,
}

impl ServiceLeaseSource {
    pub(crate) fn for_this_build() -> Self {
        Self {
            target: target_for_this_build(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_expectation(expectation: Expectation) -> Self {
        Self {
            target: Target::Client(AuthorityClient::with_expectation(expectation)),
        }
    }

    fn client(&self) -> Result<Option<&AuthorityClient>, ProviderError> {
        match &self.target {
            Target::NotInstalled => Ok(None),
            Target::Client(client) => Ok(Some(client)),
            Target::Broken(error) => Err(provider(error.clone())),
        }
    }

    /// The verified service's status and a verifier for its public key.
    fn verified(
        client: &AuthorityClient,
    ) -> Result<(Value, Box<dyn SignatureVerifier>), ProviderError> {
        let status = client.status().map_err(provider)?;
        let public = status["public_key_hex"]
            .as_str()
            .and_then(orcel_authority::unhex)
            .ok_or_else(|| unavailable("the authority reported no public key"))?;
        let verifier = public_verifier(&public)?;
        if status["key_id"].as_str() != Some(verifier.key_id().as_str()) {
            return Err(unavailable("the authority's key id does not match its key"));
        }
        Ok((status, verifier))
    }
}

#[cfg(windows)]
fn public_verifier(public: &[u8]) -> Result<Box<dyn SignatureVerifier>, ProviderError> {
    orcel_authority::win::crypto::EcdsaP256Verifier::from_public_blob(public)
        .map(|verifier| Box::new(verifier) as Box<dyn SignatureVerifier>)
        .map_err(provider)
}

#[cfg(not(windows))]
fn public_verifier(_public: &[u8]) -> Result<Box<dyn SignatureVerifier>, ProviderError> {
    Err(provider(AuthorityError::unsupported()))
}

impl LeaseSource for ServiceLeaseSource {
    fn read(&self) -> Result<Option<AuthorityView>, ProviderError> {
        let Some(client) = self.client()? else {
            return Ok(None);
        };
        let (status, verifier) = Self::verified(client)?;
        // Only the trusted orceld image may Authorize: any other orceld
        // asks for every action, as before.
        if !status_admits_leases(&status) {
            return Ok(None);
        }
        let listed = client.list().map_err(provider)?;
        let epoch = listed["epoch"]
            .as_u64()
            .ok_or_else(|| unavailable("the authority's list has no epoch"))?;
        let revocations = listed["revocations"]
            .as_u64()
            .ok_or_else(|| unavailable("the authority's list has no revocation counter"))?;
        Ok(Some(AuthorityView {
            epoch,
            revocations,
            leases: admit_listed(&listed, verifier.as_ref())?,
        }))
    }

    fn authorize(&self, action: &CoveredAction) -> Result<(), ProviderError> {
        let client = self
            .client()?
            .ok_or_else(|| unavailable("the Orcel authority service is not installed"))?;
        client
            .authorize(
                &action.lease_id,
                ExecutorClass::Browser,
                AuthorizeClaims {
                    request_id: action.record_id.clone(),
                    capability: "browser.full_access".to_owned(),
                    operation: action.family.as_str().to_owned(),
                    principal_id: action.principal_id.clone(),
                    task: action.task.clone(),
                    action_digest: action_digest(action),
                    // Review F4: the service checks the family and origin.
                    origin: Some(action.origin.clone()),
                },
            )
            .map(|_| ())
            .map_err(provider)
    }

    fn end_session(&self, session_id: &str) {
        let Ok(Some(client)) = self.client() else {
            return;
        };
        let Ok((_, verifier)) = Self::verified(client) else {
            return;
        };
        let Ok(listed) = client.list() else {
            return;
        };
        for lease in admit_listed(&listed, verifier.as_ref()).unwrap_or_default() {
            if lease.session_id == session_id {
                let _ = client.revoke(&lease.lease_id);
            }
        }
    }
}

/// The owner's list and revoke, through the service.
pub(crate) struct ServiceLeaseManager {
    source: ServiceLeaseSource,
}

impl ServiceLeaseManager {
    pub(crate) fn for_this_build() -> Self {
        Self {
            source: ServiceLeaseSource::for_this_build(),
        }
    }

    fn leases(&self) -> Result<Vec<BrowserLease>, ProviderError> {
        let Some(client) = self.source.client()? else {
            return Ok(Vec::new());
        };
        let (_, verifier) = ServiceLeaseSource::verified(client)?;
        admit_listed(&client.list().map_err(provider)?, verifier.as_ref())
    }
}

impl LeaseManager for ServiceLeaseManager {
    fn list(&self) -> Result<Vec<BrowserLease>, ProviderError> {
        self.leases()
    }

    fn revoke(&self, lease_id: Option<&str>) -> Result<usize, ProviderError> {
        let Some(client) = self.source.client()? else {
            return Ok(0);
        };
        let mut revoked = 0;
        for lease in self.leases()? {
            if lease_id.is_none_or(|id| id == lease.lease_id) {
                client.revoke(&lease.lease_id).map_err(provider)?;
                revoked += 1;
            }
        }
        Ok(revoked)
    }
}

/// SG-000132 slice 2, desktop lease migration step: the DesktopInput gate.
/// With the service installed only a service-issued desktop lease of this
/// user and logon session counts, admitted by the service's audit-first
/// `Authorize`; the deprecated user-readable store is consulted only where
/// no service is installed (its existing behaviour), never as a fallback.
pub(crate) fn desktop_input_gate(request: &RequestEnvelope) -> Result<(), ProviderError> {
    if !orcel_authority::client::service_installed() {
        // DEPRECATED path (no new issuance happens through it once the
        // service is installed; `orcel full-control grant` uses the service).
        return orcel_policy::full_control_store::check_current_desktop_input()
            .map(|_| ())
            .map_err(|error| ProviderError::new(error.code, error.message));
    }
    let client = AuthorityClient::installed().map_err(provider)?;
    let (_, verifier) = ServiceLeaseSource::verified(&client)?;
    let listed = client.list().map_err(provider)?;
    for entry in listed["leases"].as_array().into_iter().flatten() {
        if entry["state"].as_str() != Some("active") {
            continue;
        }
        let Ok(lease) = serde_json::from_value::<SignedLease>(entry["lease"].clone()) else {
            continue;
        };
        if !lease.body.scope.admits(ExecutorClass::DesktopInput)
            || lease.verify_signature(verifier.as_ref()).is_err()
        {
            continue;
        }
        let now = orcel_approval::now_ms();
        return client
            .authorize(
                &lease.body.lease_id,
                ExecutorClass::DesktopInput,
                AuthorizeClaims {
                    request_id: format!("desktop-{now}"),
                    capability: request.capability.clone(),
                    operation: request.operation.clone(),
                    principal_id: lease.body.principal_id.clone(),
                    task: lease.body.task.clone(),
                    action_digest: desktop_action_digest(request, now),
                    origin: None,
                },
            )
            .map(|_| ())
            .map_err(provider);
    }
    Err(ProviderError::new(
        FailureCode::LeaseRequired,
        "no active Full User desktop lease from the Orcel authority service; run `orcel full-control grant`",
    ))
}

/// Review F5: the SHA-256 the service's audit records for one desktop
/// action: its workspace, capability, operation, target, arguments and time,
/// so the record names what was done, not only its kind.
pub(crate) fn desktop_action_digest(request: &RequestEnvelope, now_ms: u64) -> String {
    let mut hasher = Sha256::new();
    for part in [
        "orcel-desktop-lease-action/2".to_owned(),
        request.workspace_id.clone(),
        request.capability.clone(),
        request.operation.clone(),
        request.target.clone().unwrap_or_default(),
        request.arguments.to_string(),
        now_ms.to_string(),
    ] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
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

    /// Slice 2: an unreachable service covers nothing and authorizes
    /// nothing; the lease cache then asks as before.
    #[test]
    fn sg132_an_unreachable_service_covers_nothing() {
        use crate::browser_lease::{
            CoveredAction, FullAccess, LeaseDecision, LeaseMoment, LeaseQuery, LeaseSource,
            SecretMatcher,
        };
        struct NoSecrets;
        impl SecretMatcher for NoSecrets {
            fn matches(&self, _value: &str) -> Result<bool, ()> {
                Ok(false)
            }
        }
        let expectation = Expectation {
            pipe_name: format!(
                "{}orceld-lease-absent-{}",
                orcel_authority::CONSOLE_PIPE_PREFIX,
                std::process::id()
            ),
            pid: 4,
            owner_sid: "S-1-5-18".to_owned(),
        };
        let source = ServiceLeaseSource::with_expectation(expectation.clone());
        assert!(source.read().is_err());
        let action = CoveredAction {
            lease_id: format!("al-{}", "1".repeat(32)),
            principal_id: format!("cl-{}", "2".repeat(32)),
            task: "t".to_owned(),
            record_id: "lease-1-x".to_owned(),
            family: BrowserFamily::Click,
            origin: "https://fixture.test".to_owned(),
            page_id: "pg-1".to_owned(),
        };
        assert!(source.authorize(&action).is_err());
        assert_eq!(action_digest(&action).len(), 64);
        let mut access = FullAccess::new(
            "bs-0123456789abcdef-1-0001020304050607",
            &format!("cl-{}", "2".repeat(32)),
            None,
            Box::new(ServiceLeaseSource::with_expectation(expectation)),
            Box::new(NoSecrets),
            Some(("S-1-5-21-1".to_owned(), 7)),
        );
        let decision = access.decide(
            &LeaseQuery {
                family: BrowserFamily::Click,
                also: None,
                effect_origin: "https://fixture.test",
                committed_origin: Some("https://fixture.test"),
                impact: orcel_contracts::browser_impact::Impact::Routine,
                page_id: "pg-1",
            },
            &LeaseMoment {
                approval_epoch: Some(1),
                now_ms: 1,
                interventions: Some(std::collections::BTreeMap::from([("pg-1".to_owned(), 0)])),
            },
        );
        assert!(matches!(decision, LeaseDecision::Ask), "{decision:?}");
    }

    /// Slice 2: admission with the real ECDSA P-256 verifier: a lease the
    /// service key signed is admitted, any other key's is refused.
    #[cfg(windows)]
    #[test]
    fn sg132_browser_leases_are_admitted_only_with_the_service_ecdsa_key() -> Result<(), String> {
        use orcel_authority::core::LeaseSigner;
        use orcel_authority::lease::{
            signing_input, BrowserFamily as Family, GrantEvidence, LeaseBody, ObservedRequester,
            LEASE_CONTRACT,
        };
        use orcel_authority::win::crypto::{EcdsaP256Signer, EcdsaP256Verifier};
        let dir = std::env::temp_dir().join(format!(
            "orceld-sg132-ecdsa-{}-{}",
            std::process::id(),
            orcel_authority::now_ms()
        ));
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let service =
            EcdsaP256Signer::load_or_create(&dir.join("service.key")).map_err(|e| e.to_string())?;
        let stranger = EcdsaP256Signer::load_or_create(&dir.join("stranger.key"))
            .map_err(|e| e.to_string())?;
        let verifier = EcdsaP256Verifier::from_public_blob(&service.public_key())
            .map_err(|e| e.to_string())?;
        let client = format!("cl-{}", "ab".repeat(16));
        let body = LeaseBody {
            contract: LEASE_CONTRACT.to_owned(),
            lease_id: format!("al-{}", "3".repeat(32)),
            scope: LeaseScope::BrowserFullAccess {
                client_ref: client.clone(),
                session_id: "bs-0123456789abcdef-1-0001020304050607".to_owned(),
                origins: vec!["https://fixture.test".to_owned()],
                families: vec![Family::Navigate, Family::Click],
                task: None,
            },
            windows_user_sid: "S-1-5-21-1".to_owned(),
            logon_session_id: 7,
            ts_session_id: 1,
            principal_id: client,
            task: "browse".to_owned(),
            requester: ObservedRequester {
                pid: 9,
                image: "C:\\Program Files\\Orcel\\orcel.exe".to_owned(),
            },
            authority_epoch: 1,
            revocations_at_issue: 0,
            issued_at_ms: 1_000,
            expires_at_ms: 1_000 + 30 * 60_000,
            key_id: verifier.key_id(),
            grant: GrantEvidence {
                intent_digest: "0".repeat(64),
                confirmation_text_digest: "1".repeat(64),
                confirmation: "service_rendered".to_owned(),
                confirmation_input_protected: false,
                presence: "windows_hello_key_credential".to_owned(),
                presence_key_digest: "2".repeat(64),
            },
        };
        let input = signing_input(&body).map_err(|e| e.to_string())?;
        let good = SignedLease {
            body: body.clone(),
            signature: orcel_authority::hex(&service.sign(&input).map_err(|e| e.to_string())?),
        };
        let admitted = admit_browser_lease(&good, &verifier).map_err(|e| e.message)?;
        assert!(
            admitted.is_some_and(
                |lease| lease.families == [BrowserFamily::Navigate, BrowserFamily::Click]
            )
        );
        let forged = SignedLease {
            body,
            signature: orcel_authority::hex(&stranger.sign(&input).map_err(|e| e.to_string())?),
        };
        assert!(admit_browser_lease(&forged, &verifier).is_err());
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    /// A dev orceld (role interactive or other at the service) never uses a
    /// service lease; only the trusted image does.
    #[test]
    fn sg132_only_the_trusted_orceld_role_uses_service_leases() {
        assert!(status_admits_leases(
            &serde_json::json!({"caller_role": "orceld"})
        ));
        for role in ["interactive", "other", "Orceld", ""] {
            assert!(
                !status_admits_leases(&serde_json::json!({"caller_role": role})),
                "{role}"
            );
        }
        assert!(!status_admits_leases(&serde_json::json!({})));
    }

    /// Review F5: the desktop action digest names the action's target and
    /// arguments, not only its kind.
    #[test]
    fn sg132_the_desktop_action_digest_binds_target_and_arguments() {
        let request = |target: Option<&str>, arguments: serde_json::Value| RequestEnvelope {
            version: orcel_contracts::INTERNAL_PROTOCOL_VERSION,
            request_id: "r".into(),
            client_session_id: "c".into(),
            workspace_id: "default".into(),
            capability: "desktop.input".into(),
            operation: "click".into(),
            target: target.map(str::to_owned),
            arguments,
        };
        let base = desktop_action_digest(&request(Some("w1"), serde_json::json!({"x": 1})), 5);
        assert_eq!(base.len(), 64);
        assert_eq!(
            base,
            desktop_action_digest(&request(Some("w1"), serde_json::json!({"x": 1})), 5)
        );
        for other in [
            desktop_action_digest(&request(Some("w1"), serde_json::json!({"x": 2})), 5),
            desktop_action_digest(&request(Some("w2"), serde_json::json!({"x": 1})), 5),
            desktop_action_digest(&request(None, serde_json::json!({"x": 1})), 5),
            desktop_action_digest(&request(Some("w1"), serde_json::json!({"x": 1})), 6),
        ] {
            assert_ne!(base, other);
        }
    }

    #[test]
    fn sg132_other_arguments_are_not_authority_commands() {
        assert_eq!(run_cli(&[]), None);
        assert_eq!(run_cli(&["--help".to_owned()]), None);
        assert_eq!(run_cli(&["authority-verify".to_owned()]), Some(2));
    }
}
