//! Rules of the authority core, on every OS, with test doubles for the
//! platform pieces: a keyed-hash signer, a presence verifier that accepts
//! `sha256(spki || challenge)`, a recording event sink, counter entropy and
//! a per-thread clock.

use crate::caller::{CallerFacts, ClientPolicy};
use crate::core::{
    AuthorityCore, ConfirmAnswer, Entropy, EventSink, LeaseSigner, PresenceVerifier, Services,
    GRANT_WINDOW_MS, INTENT_TTL_MS,
};
use crate::error::AuthorityError;
use crate::lease::{LeaseScope, SignedLease};
use crate::protocol::{AuthorizeClaims, ClaimedOrigin, Request};
use crate::{hex, sha256_hex, unhex, RunMode};
use orcel_contracts::{ExecutorClass, FailureCode};
use serde_json::Value;
use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

thread_local! {
    static NOW: Cell<u64> = const { Cell::new(1_000_000) };
}

fn clock() -> u64 {
    NOW.with(Cell::get)
}

fn advance(ms: u64) {
    NOW.with(|now| now.set(now.get() + ms));
}

struct KeyedHashSigner;

impl LeaseSigner for KeyedHashSigner {
    fn public_key(&self) -> Vec<u8> {
        b"test-public-key".to_vec()
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, AuthorityError> {
        let mut input = b"test-signing-key".to_vec();
        input.extend_from_slice(message);
        unhex(&sha256_hex(&input)).ok_or_else(|| AuthorityError::internal("hex"))
    }
}

struct HashPresence;

fn presence_signature(spki: &[u8], challenge: &[u8]) -> String {
    let mut input = spki.to_vec();
    input.extend_from_slice(challenge);
    sha256_hex(&input)
}

impl PresenceVerifier for HashPresence {
    fn check_public_key(&self, spki_der: &[u8]) -> Result<(), AuthorityError> {
        if spki_der.starts_with(b"spki:") {
            Ok(())
        } else {
            Err(AuthorityError::invalid("not a test key"))
        }
    }
    fn verify(
        &self,
        spki_der: &[u8],
        challenge: &[u8],
        signature: &[u8],
    ) -> Result<(), AuthorityError> {
        if hex(signature) == presence_signature(spki_der, challenge) {
            Ok(())
        } else {
            Err(AuthorityError::denied("bad presence signature"))
        }
    }
}

#[derive(Clone, Default)]
struct Events(Arc<Mutex<Vec<(u32, String)>>>);

impl EventSink for Events {
    fn record(&self, event_id: u32, _error: bool, text: &str) -> Result<(), AuthorityError> {
        self.0
            .lock()
            .map_err(|_| AuthorityError::internal("poisoned"))?
            .push((event_id, text.to_owned()));
        Ok(())
    }
}

impl Events {
    fn with_id(&self, id: u32) -> Vec<String> {
        self.0
            .lock()
            .map(|events| {
                events
                    .iter()
                    .filter(|(i, _)| *i == id)
                    .map(|(_, t)| t.clone())
                    .collect()
            })
            .unwrap_or_default()
    }
}

struct Counter(AtomicU64);

impl Entropy for Counter {
    fn fill(&self, out: &mut [u8]) -> Result<(), AuthorityError> {
        let value = self.0.fetch_add(1, Ordering::Relaxed) + 1;
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = (value as u8).wrapping_add(index as u8) | 1;
        }
        Ok(())
    }
}

const ORCELD: &str = r"C:\Orcel\bin\orceld.exe";
const SPKI: &[u8] = b"spki:owner-hello-key";

fn temp_dir(name: &str) -> Result<PathBuf, String> {
    let dir = std::env::temp_dir().join(format!(
        "orcel-authority-core-{name}-{}-{}",
        std::process::id(),
        crate::now_ms()
    ));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir)
}

fn open(dir: &Path, events: &Events) -> Result<AuthorityCore, String> {
    AuthorityCore::open(
        RunMode::Service,
        dir,
        ClientPolicy {
            trusted_orceld_images: vec![PathBuf::from(ORCELD)],
        },
        Services {
            signer: Box::new(KeyedHashSigner),
            presence: Box::new(HashPresence),
            events: Box::new(events.clone()),
            entropy: Box::new(Counter(AtomicU64::new(0))),
            clock,
        },
    )
    .map_err(|e| e.to_string())
}

fn owner() -> CallerFacts {
    CallerFacts {
        pid: 4100,
        image: r"C:\Orcel\bin\orcel.exe".to_owned(),
        user_sid: "S-1-5-21-1-2-3-1001".to_owned(),
        logon_session_id: 0x5555,
        ts_session_id: 1,
        interactive: true,
        console_session: true,
    }
}

fn orceld() -> CallerFacts {
    CallerFacts {
        pid: 4200,
        image: ORCELD.to_owned(),
        ..owner()
    }
}

fn ok(result: Result<Value, AuthorityError>) -> Result<Value, String> {
    result.map_err(|e| e.to_string())
}

fn code(result: Result<Value, AuthorityError>) -> Option<FailureCode> {
    result.err().map(|e| e.code)
}

fn str_of(value: &Value, key: &str) -> Result<String, String> {
    value[key]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("missing {key} in {value}"))
}

/// Unlock, confirm Yes, read the challenge, sign it with `spki`.
fn complete(
    core: &mut AuthorityCore,
    caller: &CallerFacts,
    intent_id: &str,
    spki: &[u8],
) -> Result<Value, String> {
    let task = core
        .observe_unlock(caller.ts_session_id)
        .ok_or("the unlock opened no window")?;
    assert_eq!(task.intent_id, intent_id);
    assert_eq!(task.title, "Orcel Authority");
    assert!(task
        .text
        .contains("Full Control acts with your Windows rights"));
    assert!(task.text.contains("Biometric Windows Hello is recommended"));
    core.confirmation_answer(intent_id, ConfirmAnswer::Yes)
        .map_err(|e| e.to_string())?;
    let status = ok(core.handle(
        caller,
        Request::IntentStatus {
            intent_id: intent_id.to_owned(),
        },
    ))?;
    let challenge = unhex(&str_of(&status, "challenge_hex")?).ok_or("challenge hex")?;
    assert_eq!(challenge.len(), 32);
    ok(core.handle(
        caller,
        Request::PresenceComplete {
            intent_id: intent_id.to_owned(),
            signature_hex: presence_signature(spki, &challenge),
        },
    ))
}

fn enroll(core: &mut AuthorityCore, caller: &CallerFacts) -> Result<(), String> {
    let begun = ok(core.handle(
        caller,
        Request::EnrollBegin {
            origin: ClaimedOrigin::OwnerCli,
            public_key_spki_hex: hex(SPKI),
        },
    ))?;
    let done = complete(core, caller, &str_of(&begun, "intent_id")?, SPKI)?;
    assert_eq!(done["enrolled"], Value::Bool(true));
    Ok(())
}

fn grant_begin(scope: Option<LeaseScope>) -> Request {
    Request::GrantBegin {
        origin: ClaimedOrigin::OwnerCli,
        scope,
        minutes: None,
        principal_id: "mcp-client-1".to_owned(),
        task: "tidy the downloads folder".to_owned(),
    }
}

fn grant(
    core: &mut AuthorityCore,
    caller: &CallerFacts,
    scope: Option<LeaseScope>,
) -> Result<SignedLease, String> {
    let begun = ok(core.handle(caller, grant_begin(scope)))?;
    let done = complete(core, caller, &str_of(&begun, "intent_id")?, SPKI)?;
    serde_json::from_value(done["lease"].clone()).map_err(|e| e.to_string())
}

fn claims() -> AuthorizeClaims {
    AuthorizeClaims {
        request_id: "req-1".to_owned(),
        capability: "desktop.input".to_owned(),
        operation: "click".to_owned(),
        principal_id: "mcp-client-1".to_owned(),
        task: "tidy the downloads folder".to_owned(),
        action_digest: sha256_hex(b"click 10 20"),
    }
}

fn authorize(
    core: &mut AuthorityCore,
    caller: &CallerFacts,
    lease_id: &str,
    executor: ExecutorClass,
) -> Result<Value, AuthorityError> {
    core.handle(
        caller,
        Request::Authorize {
            lease_id: lease_id.to_owned(),
            executor,
            claims: claims(),
        },
    )
}

#[test]
fn issuance_is_refused_for_every_non_owner_caller() -> Result<(), String> {
    let dir = temp_dir("non-owner")?;
    let events = Events::default();
    let mut core = open(&dir, &events)?;
    enroll(&mut core, &owner())?;
    let mut not_interactive = owner();
    not_interactive.interactive = false;
    let mut remote_session = owner();
    remote_session.console_session = false;
    remote_session.ts_session_id = 3;
    for caller in [orceld(), not_interactive, remote_session] {
        assert_eq!(
            code(core.handle(&caller, grant_begin(None))),
            Some(FailureCode::CapabilityDenied)
        );
    }
    for origin in [
        ClaimedOrigin::Mcp,
        ClaimedOrigin::Agent,
        ClaimedOrigin::Remote,
        ClaimedOrigin::Orceld,
    ] {
        let request = Request::GrantBegin {
            origin,
            scope: None,
            minutes: None,
            principal_id: "p".to_owned(),
            task: "t".to_owned(),
        };
        assert_eq!(
            code(core.handle(&owner(), request)),
            Some(FailureCode::CapabilityDenied)
        );
        let enroll = Request::EnrollBegin {
            origin,
            public_key_spki_hex: hex(b"spki:other"),
        };
        assert_eq!(
            code(core.handle(&owner(), enroll)),
            Some(FailureCode::CapabilityDenied)
        );
    }
    // Nothing was recorded, so an unlock opens nothing.
    assert!(core.observe_unlock(1).is_none());
    // orceld cannot complete presence either.
    assert_eq!(
        code(core.handle(
            &orceld(),
            Request::PresenceComplete {
                intent_id: "in-x".into(),
                signature_hex: "00".into()
            }
        )),
        Some(FailureCode::CapabilityDenied)
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn a_grant_needs_enrollment_intent_unlock_confirmation_and_presence() -> Result<(), String> {
    let dir = temp_dir("flow")?;
    let events = Events::default();
    let mut core = open(&dir, &events)?;
    // Without an enrolled key there is no grant.
    assert_eq!(
        code(core.handle(&owner(), grant_begin(None))),
        Some(FailureCode::CapabilityDenied)
    );
    enroll(&mut core, &owner())?;
    // A routine unlock without an intent opens nothing.
    assert!(core.observe_unlock(1).is_none());
    // Presence before the unlock is refused.
    let begun = ok(core.handle(&owner(), grant_begin(None)))?;
    let intent_id = str_of(&begun, "intent_id")?;
    assert_eq!(
        code(core.handle(
            &owner(),
            Request::PresenceComplete {
                intent_id: intent_id.clone(),
                signature_hex: "00".into()
            }
        )),
        Some(FailureCode::CapabilityDenied)
    );
    // That refusal consumed nothing: the intent still awaits the unlock.
    let lease_value = complete(&mut core, &owner(), &intent_id, SPKI);
    let lease: SignedLease =
        serde_json::from_value(lease_value?["lease"].clone()).map_err(|e| e.to_string())?;
    assert_eq!(
        lease.body.scope,
        LeaseScope::narrow_default(),
        "the default is the narrow scope"
    );
    assert_eq!(
        lease.body.expires_at_ms - lease.body.issued_at_ms,
        30 * 60_000
    );
    assert_eq!(lease.body.requester.pid, 4100);
    assert!(!lease.body.grant.confirmation_input_protected);
    let granted = events.with_id(crate::EVENT_GRANTED_SCOPE);
    assert_eq!(granted.len(), 1);
    assert!(
        granted[0].contains(&lease.body.lease_id)
            && granted[0].contains("executors [desktop_input]")
    );
    assert!(granted[0].contains("roots [none]") && granted[0].contains("shells no"));
    assert!(!events.with_id(crate::EVENT_INTENT).is_empty());
    assert!(!events.with_id(crate::EVENT_ANCHOR).is_empty());

    // Authorize: orceld only, in scope only, never Admin, same principal.
    let allowed = ok(authorize(
        &mut core,
        &orceld(),
        &lease.body.lease_id,
        ExecutorClass::DesktopInput,
    ))?;
    assert!(str_of(&allowed, "authorization_id")?.starts_with("az-"));
    assert_eq!(allowed["job_name"], Value::Null);
    assert_eq!(
        code(authorize(
            &mut core,
            &owner(),
            &lease.body.lease_id,
            ExecutorClass::DesktopInput
        )),
        Some(FailureCode::CapabilityDenied)
    );
    assert_eq!(
        code(authorize(
            &mut core,
            &orceld(),
            &lease.body.lease_id,
            ExecutorClass::ShellProcess
        )),
        Some(FailureCode::CapabilityDenied)
    );
    assert_eq!(
        code(authorize(
            &mut core,
            &orceld(),
            &lease.body.lease_id,
            ExecutorClass::Admin
        )),
        Some(FailureCode::CapabilityDenied)
    );
    let mut other_client = claims();
    other_client.principal_id = "mcp-client-2".to_owned();
    assert_eq!(
        code(core.handle(
            &orceld(),
            Request::Authorize {
                lease_id: lease.body.lease_id.clone(),
                executor: ExecutorClass::DesktopInput,
                claims: other_client
            }
        )),
        Some(FailureCode::CapabilityDenied)
    );

    // The audit record of the allowed dispatch keeps claims and observations apart.
    let audit =
        std::fs::read_to_string(dir.join(crate::core::AUDIT_FILE)).map_err(|e| e.to_string())?;
    let record: Value = audit
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|record| record["kind"] == "authorize")
        .ok_or("no authorize record")?;
    assert_eq!(record["asserted_by_session"]["capability"], "desktop.input");
    assert_eq!(record["observed"]["caller_pid"], 4200);
    assert_eq!(record["observed"]["caller_image"], ORCELD);
    assert_eq!(record["observed"]["role"], "orceld");
    assert_eq!(record["detail"]["decision"], "allow");

    // A grant (or renewal) while a lease is active is refused.
    assert_eq!(
        code(core.handle(&owner(), grant_begin(None))),
        Some(FailureCode::CapabilityDenied)
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn the_window_closes_and_a_no_or_a_bad_signature_ends_the_intent() -> Result<(), String> {
    let dir = temp_dir("window")?;
    let events = Events::default();
    let mut core = open(&dir, &events)?;
    enroll(&mut core, &owner())?;

    // No at the confirmation clears the intent.
    let begun = ok(core.handle(&owner(), grant_begin(None)))?;
    let id = str_of(&begun, "intent_id")?;
    assert!(core.observe_unlock(1).is_some());
    core.confirmation_answer(&id, ConfirmAnswer::No)
        .map_err(|e| e.to_string())?;
    assert!(core
        .handle(&owner(), Request::IntentStatus { intent_id: id })
        .is_err());

    // A timeout clears it too.
    let begun = ok(core.handle(&owner(), grant_begin(None)))?;
    let id = str_of(&begun, "intent_id")?;
    assert!(core.observe_unlock(1).is_some());
    core.confirmation_answer(&id, ConfirmAnswer::Timeout)
        .map_err(|e| e.to_string())?;
    assert!(core
        .handle(&owner(), Request::IntentStatus { intent_id: id })
        .is_err());

    // Only one intent per session.
    let begun = ok(core.handle(&owner(), grant_begin(None)))?;
    let id = str_of(&begun, "intent_id")?;
    assert_eq!(
        code(core.handle(&owner(), grant_begin(None))),
        Some(FailureCode::CapabilityDenied)
    );
    // A lock keeps the intent that awaits its unlock (the flow locks).
    core.session_ended(1, "session_lock", true)
        .map_err(|e| e.to_string())?;
    // The intent expires after five minutes without an unlock.
    advance(INTENT_TTL_MS + 1);
    assert!(core.observe_unlock(1).is_none());
    assert!(core
        .handle(&owner(), Request::IntentStatus { intent_id: id })
        .is_err());

    // The window closes 120 s after the unlock.
    let begun = ok(core.handle(&owner(), grant_begin(None)))?;
    let id = str_of(&begun, "intent_id")?;
    assert!(core.observe_unlock(1).is_some());
    core.confirmation_answer(&id, ConfirmAnswer::Yes)
        .map_err(|e| e.to_string())?;
    advance(GRANT_WINDOW_MS + 1);
    assert!(core
        .handle(
            &owner(),
            Request::PresenceComplete {
                intent_id: id,
                signature_hex: "00".into()
            }
        )
        .is_err());

    // A wrong signature is refused and consumes the intent.
    let begun = ok(core.handle(&owner(), grant_begin(None)))?;
    let id = str_of(&begun, "intent_id")?;
    assert!(core.observe_unlock(1).is_some());
    core.confirmation_answer(&id, ConfirmAnswer::Yes)
        .map_err(|e| e.to_string())?;
    let status = ok(core.handle(
        &owner(),
        Request::IntentStatus {
            intent_id: id.clone(),
        },
    ))?;
    let challenge = unhex(&str_of(&status, "challenge_hex")?).ok_or("hex")?;
    let forged = presence_signature(b"spki:someone-else", &challenge);
    assert_eq!(
        code(core.handle(
            &owner(),
            Request::PresenceComplete {
                intent_id: id.clone(),
                signature_hex: forged
            }
        )),
        Some(FailureCode::CapabilityDenied)
    );
    assert!(core
        .handle(&owner(), Request::IntentStatus { intent_id: id })
        .is_err());
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn revoke_stop_lock_and_expiry_move_the_counters_and_end_leases() -> Result<(), String> {
    let dir = temp_dir("counters")?;
    let events = Events::default();
    let mut core = open(&dir, &events)?;
    enroll(&mut core, &owner())?;
    let start_epoch = core.epoch();
    let start_revocations = core.revocations();

    // Revoke: the counter moves, the epoch does not.
    let lease = grant(&mut core, &owner(), None)?;
    ok(core.handle(
        &owner(),
        Request::Revoke {
            lease_id: lease.body.lease_id.clone(),
        },
    ))?;
    assert_eq!(core.revocations(), start_revocations + 1);
    assert_eq!(core.epoch(), start_epoch);
    assert_eq!(
        code(authorize(
            &mut core,
            &orceld(),
            &lease.body.lease_id,
            ExecutorClass::DesktopInput
        )),
        Some(FailureCode::LeaseInvalid)
    );

    // Stop: both move; the lease ends; the next call fails LEASE_INVALID.
    let lease = grant(&mut core, &owner(), None)?;
    let stopped = ok(core.handle(&orceld(), Request::Stop))?;
    assert_eq!(
        stopped["ended"][0],
        Value::String(lease.body.lease_id.clone())
    );
    assert_eq!(core.epoch(), start_epoch + 1);
    assert_eq!(
        code(authorize(
            &mut core,
            &orceld(),
            &lease.body.lease_id,
            ExecutorClass::DesktopInput
        )),
        Some(FailureCode::LeaseInvalid)
    );

    // Session lock (the service observes it): ends the session's lease.
    let lease = grant(&mut core, &owner(), None)?;
    core.session_ended(1, "session_lock", true)
        .map_err(|e| e.to_string())?;
    assert_eq!(core.epoch(), start_epoch + 2);
    assert_eq!(
        code(authorize(
            &mut core,
            &orceld(),
            &lease.body.lease_id,
            ExecutorClass::DesktopInput
        )),
        Some(FailureCode::LeaseInvalid)
    );

    // Expiry: the tick ends it and advances the epoch.
    let lease = grant(&mut core, &owner(), None)?;
    advance(30 * 60_000);
    core.tick().map_err(|e| e.to_string())?;
    assert_eq!(core.epoch(), start_epoch + 3);
    assert_eq!(
        code(authorize(
            &mut core,
            &orceld(),
            &lease.body.lease_id,
            ExecutorClass::DesktopInput
        )),
        Some(FailureCode::LeaseInvalid)
    );

    // Counters survive a restart and never go back.
    let (epoch, revocations) = (core.epoch(), core.revocations());
    drop(core);
    let core = open(&dir, &events)?;
    assert_eq!((core.epoch(), core.revocations()), (epoch, revocations));
    drop(core);
    // A deleted state file with audit records left refuses to start.
    std::fs::remove_file(dir.join(crate::core::STATE_FILE)).map_err(|e| e.to_string())?;
    assert!(open(&dir, &events).is_err());
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn leases_are_bound_to_their_user_and_logon_session() -> Result<(), String> {
    let dir = temp_dir("binding")?;
    let events = Events::default();
    let mut core = open(&dir, &events)?;
    enroll(&mut core, &owner())?;
    let lease = grant(&mut core, &owner(), None)?;
    let mut stranger = orceld();
    stranger.user_sid = "S-1-5-21-9-9-9-1002".to_owned();
    let mut other_logon = orceld();
    other_logon.logon_session_id = 0x6666;
    for caller in [stranger, other_logon] {
        assert_eq!(
            code(authorize(
                &mut core,
                &caller,
                &lease.body.lease_id,
                ExecutorClass::DesktopInput
            )),
            Some(FailureCode::LeaseInvalid)
        );
        assert_eq!(
            code(core.handle(
                &caller,
                Request::Verify {
                    lease_id: lease.body.lease_id.clone()
                }
            )),
            Some(FailureCode::LeaseInvalid)
        );
        assert_eq!(
            code(core.handle(
                &caller,
                Request::Revoke {
                    lease_id: lease.body.lease_id.clone()
                }
            )),
            Some(FailureCode::LeaseInvalid)
        );
        // Another session's Stop ends nothing of this one.
        ok(core.handle(&caller, Request::Stop))?;
    }
    // The epoch moved with those stops, so the lease is no longer usable;
    // the binding refusals above happened first.
    assert_eq!(
        code(authorize(
            &mut core,
            &orceld(),
            &lease.body.lease_id,
            ExecutorClass::DesktopInput
        )),
        Some(FailureCode::LeaseInvalid)
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn a_browser_lease_covers_the_browser_executor_only() -> Result<(), String> {
    let dir = temp_dir("browser")?;
    let events = Events::default();
    let mut core = open(&dir, &events)?;
    enroll(&mut core, &owner())?;
    let scope = LeaseScope::BrowserFullAccess {
        client_ref: "cl-abc123".to_owned(),
        session_id: "bs-1".to_owned(),
        origins: vec!["https://example.com".to_owned()],
        families: vec![
            crate::lease::BrowserFamily::Click,
            crate::lease::BrowserFamily::Type,
        ],
        task: Some("fill the form".to_owned()),
    };
    let lease = grant(&mut core, &owner(), Some(scope))?;
    ok(authorize(
        &mut core,
        &orceld(),
        &lease.body.lease_id,
        ExecutorClass::Browser,
    ))?;
    assert_eq!(
        code(authorize(
            &mut core,
            &orceld(),
            &lease.body.lease_id,
            ExecutorClass::DesktopInput
        )),
        Some(FailureCode::CapabilityDenied)
    );
    let granted = events.with_id(crate::EVENT_GRANTED_SCOPE);
    assert!(granted
        .iter()
        .any(|line| line.contains("browser Full Access") && line.contains("https://example.com")));
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
