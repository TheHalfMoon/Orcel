//! Rules of the authority core, on every OS, with test doubles for the
//! platform pieces: a keyed-hash signer, a presence verifier that accepts
//! `sha256(spki || challenge)`, a recording event sink, counter entropy and
//! a per-thread clock, and a scripted attestation verifier. Most grant flow
//! tests seed an enrolled key through `enroll_for_test`; the slice 2
//! enrollment tests run the whole elevated, attested, confirmed flow.

use crate::attestation::AttestationReport;
use crate::caller::{CallerFacts, ClientPolicy};
use crate::core::{
    check_signing_key_history, display_image, is_builtin_administrator, key_fingerprint,
    AttestationVerifier, AuthorityCore, ConfirmAnswer, Entropy, EventSink, LeaseSigner,
    PresenceVerifier, Services, UacPolicy, UacSettings, EVENT_SIGNING_DOMAIN, GRANT_WINDOW_MS,
    INTENT_TTL_MS,
};
use crate::error::{AuthorityError, ENROLLMENT_UNAVAILABLE};
use crate::lease::{LeaseScope, SignedLease};
use crate::protocol::{AuthorizeClaims, ChainLink, ClaimedOrigin, Request};
use crate::{hex, sha256_hex, unhex, RunMode};
use orcel_contracts::event::AnchorRef;
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

fn keyed_hash(message: &[u8]) -> String {
    let mut input = b"test-signing-key".to_vec();
    input.extend_from_slice(message);
    sha256_hex(&input)
}

impl LeaseSigner for KeyedHashSigner {
    fn public_key(&self) -> Vec<u8> {
        b"test-public-key".to_vec()
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, AuthorityError> {
        unhex(&keyed_hash(message)).ok_or_else(|| AuthorityError::internal("hex"))
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
    fn all(&self) -> Vec<(u32, String)> {
        self.0
            .lock()
            .map(|events| events.clone())
            .unwrap_or_default()
    }

    fn with_id(&self, id: u32) -> Vec<String> {
        self.all()
            .into_iter()
            .filter(|(i, _)| *i == id)
            .map(|(_, t)| t)
            .collect()
    }
}

/// What the scripted attestation verifier answers.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Attest {
    Verified,
    NoRoot,
}

thread_local! {
    static ATTEST: Cell<Attest> = const { Cell::new(Attest::Verified) };
}

thread_local! {
    static UAC_ALWAYS_NOTIFY: Cell<bool> = const { Cell::new(true) };
    static FILTER_ADMINISTRATOR_TOKEN: Cell<Option<u32>> = const { Cell::new(None) };
}

/// The scripted UAC policy: Always notify on the secure desktop, or the
/// Windows default (notify only for apps, ConsentPromptBehaviorAdmin 5).
struct ScriptedUac;

impl UacPolicy for ScriptedUac {
    fn read(&self) -> UacSettings {
        UacSettings {
            enable_lua: Some(1),
            consent_prompt_behavior_admin: Some(if UAC_ALWAYS_NOTIFY.with(Cell::get) {
                2
            } else {
                5
            }),
            prompt_on_secure_desktop: Some(1),
            filter_administrator_token: FILTER_ADMINISTRATOR_TOKEN.with(Cell::get),
        }
    }
}

struct ScriptedAttestation;

impl AttestationVerifier for ScriptedAttestation {
    fn available(&self) -> bool {
        ATTEST.with(Cell::get) != Attest::NoRoot
    }

    fn verify(
        &self,
        spki_der: &[u8],
        attestation: &[u8],
        _chain: &[u8],
        _now_ms: u64,
    ) -> Result<AttestationReport, AuthorityError> {
        if ATTEST.with(Cell::get) != Attest::Verified || attestation != b"attested:".as_slice() {
            return Err(AuthorityError::denied("key attestation refused: scripted"));
        }
        Ok(AttestationReport {
            format: "scripted".to_owned(),
            root_sha256: crate::attestation::MICROSOFT_TPM_ROOT_2014_SHA256.to_owned(),
            aik_certificate_sha256: sha256_hex(spki_der),
            chain_length: 2,
            name_alg: "sha256".to_owned(),
            object_attributes: 0x0004_0072,
            verified: vec!["scripted".to_owned()],
            not_verified: Vec::new(),
        })
    }
}

struct Counter(AtomicU64);

impl Entropy for Counter {
    fn fill(&self, out: &mut [u8]) -> Result<(), AuthorityError> {
        let value = self.0.fetch_add(1, Ordering::Relaxed) + 1;
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = (value as u8).wrapping_add(index as u8 * 7) | 1;
        }
        Ok(())
    }
}

const ORCELD: &str = r"C:\Program Files\Orcel\orceld.exe";
const OWNER_CLI: &str = r"C:\Program Files\Orcel\orcel.exe";
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
    open_in(RunMode::Service, dir, events)
}

fn open_in(mode: RunMode, dir: &Path, events: &Events) -> Result<AuthorityCore, String> {
    AuthorityCore::open(
        mode,
        dir,
        ClientPolicy {
            trusted_orceld_images: vec![PathBuf::from(ORCELD)],
            trusted_owner_cli_images: vec![PathBuf::from(OWNER_CLI)],
        },
        Services {
            signer: Box::new(KeyedHashSigner),
            presence: Box::new(HashPresence),
            attestation: Box::new(ScriptedAttestation),
            uac: Box::new(ScriptedUac),
            events: Box::new(events.clone()),
            entropy: Box::new(Counter(AtomicU64::new(0))),
            clock,
        },
    )
    .map_err(|e| e.to_string())
}

fn open_enrolled(dir: &Path, events: &Events) -> Result<AuthorityCore, String> {
    let mut core = open(dir, events)?;
    core.enroll_for_test(&owner().user_sid, SPKI)
        .map_err(|e| e.to_string())?;
    Ok(core)
}

fn owner() -> CallerFacts {
    CallerFacts {
        pid: 4100,
        process_generation: 0x01dc_5a00_0000_0001,
        image: r"C:\Program Files\Orcel\orcel.exe".to_owned(),
        user_sid: "S-1-5-21-1-2-3-1001".to_owned(),
        logon_session_id: 0x5555,
        ts_session_id: 1,
        interactive: true,
        console_session: true,
        elevated: false,
    }
}

/// The owner's elevated `orcel authority enroll` process.
fn elevated_owner() -> CallerFacts {
    CallerFacts {
        pid: 4300,
        logon_session_id: 0x6666,
        elevated: true,
        ..owner()
    }
}

fn other_process() -> CallerFacts {
    CallerFacts {
        pid: 4999,
        image: r"C:\Users\me\agent.exe".to_owned(),
        ..owner()
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

fn grant_begin_with(scope: Option<LeaseScope>, principal: &str, task: &str) -> Request {
    Request::GrantBegin {
        origin: ClaimedOrigin::OwnerCli,
        scope,
        minutes: None,
        principal_id: principal.to_owned(),
        task: task.to_owned(),
    }
}

fn grant_begin(scope: Option<LeaseScope>) -> Request {
    grant_begin_with(scope, "mcp-client-1", "tidy the downloads folder")
}

/// Unlock and confirm Yes; returns the challenge and the confirmation text.
fn confirm_yes(
    core: &mut AuthorityCore,
    caller: &CallerFacts,
    intent_id: &str,
) -> Result<(Vec<u8>, String), String> {
    let task = core
        .observe_unlock(caller.ts_session_id)
        .ok_or("the unlock opened no window")?;
    assert_eq!(task.intent_id, intent_id);
    core.confirmation_answer(intent_id, ConfirmAnswer::Yes)
        .map_err(|e| e.to_string())?;
    let status = ok(core.handle(
        caller,
        Request::IntentStatus {
            intent_id: intent_id.to_owned(),
        },
    ))?;
    let challenge = unhex(&str_of(&status, "challenge_hex")?).ok_or("challenge hex")?;
    assert_eq!(str_of(&status, "confirmation_text")?, task.text);
    assert_eq!(
        str_of(&status, "confirmation_text_digest")?,
        sha256_hex(task.text.as_bytes())
    );
    Ok((challenge, task.text))
}

fn presence(intent_id: &str, code: &str, challenge: &[u8]) -> Request {
    Request::PresenceComplete {
        intent_id: intent_id.to_owned(),
        code: code.to_owned(),
        signature_hex: presence_signature(SPKI, challenge),
    }
}

fn grant(
    core: &mut AuthorityCore,
    scope: Option<LeaseScope>,
) -> Result<(SignedLease, String), String> {
    let begun = ok(core.handle(&owner(), grant_begin(scope)))?;
    let id = str_of(&begun, "intent_id")?;
    let one_time = str_of(&begun, "code")?;
    let (challenge, text) = confirm_yes(core, &owner(), &id)?;
    let done = ok(core.handle(&owner(), presence(&id, &one_time, &challenge)))?;
    let lease = serde_json::from_value(done["lease"].clone()).map_err(|e| e.to_string())?;
    Ok((lease, text))
}

fn claims() -> AuthorizeClaims {
    AuthorizeClaims {
        request_id: "req-1".to_owned(),
        capability: "desktop.input".to_owned(),
        operation: "click".to_owned(),
        principal_id: "mcp-client-1".to_owned(),
        task: "tidy the downloads folder".to_owned(),
        action_digest: sha256_hex(b"click 10 20"),
        origin: None,
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

const NEW_SPKI: &[u8] = b"spki:replacement-hello-key";

fn enroll_request(spki: &[u8], replace: bool) -> Request {
    Request::EnrollBegin {
        origin: ClaimedOrigin::OwnerCli,
        public_key_spki_hex: hex(spki),
        attestation_hex: hex(b"attested:"),
        certificate_chain_hex: hex(b"chain"),
        replace,
    }
}

/// Runs an enrollment to its end: begin, the rendered confirmation, Yes,
/// and the new key's signature. Returns the confirmation text.
fn enroll(core: &mut AuthorityCore, spki: &[u8], replace: bool) -> Result<String, String> {
    let caller = elevated_owner();
    let begun = ok(core.handle(&caller, enroll_request(spki, replace)))?;
    let id = str_of(&begun, "intent_id")?;
    let one_time = str_of(&begun, "code")?;
    let fingerprint = str_of(&begun, "key_fingerprint")?;
    assert_eq!(fingerprint, key_fingerprint(&sha256_hex(spki)));
    let tasks = core.take_pending_confirmations();
    assert_eq!(tasks.len(), 1);
    let text = tasks[0].text.clone();
    assert!(
        text.contains(&one_time) && text.contains(&fingerprint),
        "{text}"
    );
    core.confirmation_answer(&id, ConfirmAnswer::Yes)
        .map_err(|e| e.to_string())?;
    let status = ok(core.handle(
        &caller,
        Request::IntentStatus {
            intent_id: id.clone(),
        },
    ))?;
    assert_eq!(str_of(&status, "purpose")?, "enroll");
    let challenge = unhex(&str_of(&status, "challenge_hex")?).ok_or("challenge")?;
    ok(core.handle(
        &caller,
        Request::PresenceComplete {
            intent_id: id,
            code: one_time,
            signature_hex: presence_signature(spki, &challenge),
        },
    ))?;
    Ok(text)
}

#[test]
fn enrollment_needs_an_elevated_owner_and_a_verified_attestation() -> Result<(), String> {
    let dir = temp_dir("enroll-refused")?;
    let events = Events::default();
    let mut core = open(&dir, &events)?;
    // Not elevated, orceld, another session's process: refused, whatever
    // they claim.
    for caller in [owner(), orceld(), other_process()] {
        assert_eq!(
            code(core.handle(&caller, enroll_request(SPKI, false))),
            Some(FailureCode::CapabilityDenied)
        );
    }
    let mut elevated_orceld = orceld();
    elevated_orceld.elevated = true;
    assert_eq!(
        code(core.handle(&elevated_orceld, enroll_request(SPKI, false))),
        Some(FailureCode::CapabilityDenied)
    );
    let agent_claim = Request::EnrollBegin {
        origin: ClaimedOrigin::Agent,
        public_key_spki_hex: hex(SPKI),
        attestation_hex: hex(b"attested:"),
        certificate_chain_hex: hex(b"chain"),
        replace: false,
    };
    assert_eq!(
        code(core.handle(&elevated_owner(), agent_claim)),
        Some(FailureCode::CapabilityDenied)
    );
    // An attestation that does not verify refuses enrollment (fail closed).
    let unattested = Request::EnrollBegin {
        origin: ClaimedOrigin::OwnerCli,
        public_key_spki_hex: hex(SPKI),
        attestation_hex: hex(b"software key"),
        certificate_chain_hex: hex(b"chain"),
        replace: false,
    };
    assert_eq!(
        code(core.handle(&elevated_owner(), unattested)),
        Some(FailureCode::CapabilityDenied)
    );
    // No pinned root on this PC: enrollment is unavailable.
    ATTEST.with(|a| a.set(Attest::NoRoot));
    let error = core
        .handle(&elevated_owner(), enroll_request(SPKI, false))
        .err()
        .ok_or("enrollment without a root was not refused")?;
    ATTEST.with(|a| a.set(Attest::Verified));
    assert_eq!(error.code, FailureCode::Unsupported);
    assert!(
        error.message.starts_with(ENROLLMENT_UNAVAILABLE),
        "{}",
        error.message
    );
    // Not an RSA key the presence verifier accepts.
    assert_eq!(
        code(core.handle(&elevated_owner(), enroll_request(b"not a key", false))),
        Some(FailureCode::InvalidRequest)
    );
    assert!(core.take_pending_confirmations().is_empty());
    let status = ok(core.handle(&owner(), Request::Status))?;
    assert_eq!(status["caller_enrolled"], Value::Bool(false));
    assert_eq!(status["can_issue"], Value::Bool(false));
    assert_eq!(status["enrollment_available"], Value::Bool(true));
    // Without an enrolled key, a grant cannot even begin.
    assert_eq!(
        code(core.handle(&owner(), grant_begin(None))),
        Some(FailureCode::CapabilityDenied)
    );
    // Console mode never enrolls, elevated or not.
    let console_dir = temp_dir("enroll-console")?;
    let mut console = open_in(RunMode::Console, &console_dir, &Events::default())?;
    assert_eq!(
        code(console.handle(&elevated_owner(), enroll_request(SPKI, false))),
        Some(FailureCode::CapabilityDenied)
    );
    let _ = std::fs::remove_dir_all(&console_dir);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn enrollment_shows_the_fingerprint_and_enrolls_only_after_the_new_key_signs() -> Result<(), String>
{
    let dir = temp_dir("enroll-flow")?;
    let events = Events::default();
    let mut core = open(&dir, &events)?;
    let caller = elevated_owner();
    let begun = ok(core.handle(&caller, enroll_request(SPKI, false)))?;
    let id = str_of(&begun, "intent_id")?;
    let one_time = str_of(&begun, "code")?;
    assert_eq!(str_of(&begun, "state")?, "awaiting_confirmation");
    let tasks = core.take_pending_confirmations();
    assert_eq!(tasks.len(), 1);
    assert_eq!(
        sha256_hex(tasks[0].text.as_bytes()),
        str_of(&begun, "confirmation_text_digest")?
    );
    assert!(tasks[0].text.is_ascii());
    // Another process cannot see or complete it.
    assert_eq!(
        code(core.handle(
            &other_process(),
            Request::IntentStatus {
                intent_id: id.clone()
            }
        )),
        Some(FailureCode::InvalidRequest)
    );
    core.confirmation_answer(&id, ConfirmAnswer::Yes)
        .map_err(|e| e.to_string())?;
    let status = ok(core.handle(
        &caller,
        Request::IntentStatus {
            intent_id: id.clone(),
        },
    ))?;
    let challenge = unhex(&str_of(&status, "challenge_hex")?).ok_or("challenge")?;
    // Signed by another key (the enrolled one does not exist yet; a
    // stranger's key): refused, the intent is consumed, nothing enrolled.
    assert_eq!(
        code(core.handle(
            &caller,
            Request::PresenceComplete {
                intent_id: id.clone(),
                code: one_time.clone(),
                signature_hex: presence_signature(NEW_SPKI, &challenge),
            }
        )),
        Some(FailureCode::CapabilityDenied)
    );
    assert_eq!(
        ok(core.handle(&owner(), Request::Status))?["caller_enrolled"],
        Value::Bool(false)
    );
    // The whole flow.
    let text = enroll(&mut core, SPKI, false)?;
    assert!(text.contains("TPM attestation: verified"), "{text}");
    let status = ok(core.handle(&owner(), Request::Status))?;
    assert_eq!(status["caller_enrolled"], Value::Bool(true));
    assert_eq!(
        status["caller_key_fingerprint"],
        Value::String(key_fingerprint(&sha256_hex(SPKI)))
    );
    assert!(events
        .with_id(crate::EVENT_ENROLLED)
        .iter()
        .any(|e| e.contains("|enrolled|")));
    // The enrolled key now completes a grant.
    let (lease, _) = grant(&mut core, None)?;
    assert_eq!(lease.body.grant.presence_key_digest, sha256_hex(SPKI));
    // A No leaves nothing enrolled or replaced.
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn re_enrollment_needs_replace_and_ends_every_lease_of_the_user() -> Result<(), String> {
    let dir = temp_dir("enroll-replace")?;
    let events = Events::default();
    let mut core = open(&dir, &events)?;
    enroll(&mut core, SPKI, false)?;
    let (lease, _) = grant(&mut core, None)?;
    let epoch = core.epoch();
    // Already enrolled: replacing needs --replace; the same key is refused.
    assert_eq!(
        code(core.handle(&elevated_owner(), enroll_request(NEW_SPKI, false))),
        Some(FailureCode::CapabilityDenied)
    );
    assert_eq!(
        code(core.handle(&elevated_owner(), enroll_request(SPKI, true))),
        Some(FailureCode::InvalidRequest)
    );
    let text = enroll(&mut core, NEW_SPKI, true)?;
    assert!(
        text.contains(&format!(
            "REPLACES the enrolled key {}",
            key_fingerprint(&sha256_hex(SPKI))
        )),
        "{text}"
    );
    assert!(core.epoch() > epoch);
    assert_eq!(
        code(core.handle(
            &owner(),
            Request::Verify {
                lease_id: lease.body.lease_id.clone()
            }
        )),
        Some(FailureCode::LeaseInvalid)
    );
    // A grant signed with the old key fails now.
    let begun = ok(core.handle(&owner(), grant_begin(None)))?;
    let id = str_of(&begun, "intent_id")?;
    let (challenge, _) = confirm_yes(&mut core, &owner(), &id)?;
    assert_eq!(
        code(core.handle(
            &owner(),
            presence(&id, &str_of(&begun, "code")?, &challenge)
        )),
        Some(FailureCode::CapabilityDenied)
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn a_reset_needs_elevation_and_a_confirmed_yes() -> Result<(), String> {
    let dir = temp_dir("enroll-reset")?;
    let events = Events::default();
    let mut core = open(&dir, &events)?;
    enroll(&mut core, SPKI, false)?;
    let reset = || Request::ResetEnrollment {
        origin: ClaimedOrigin::OwnerCli,
    };
    assert_eq!(
        code(core.handle(&owner(), reset())),
        Some(FailureCode::CapabilityDenied)
    );
    // No: nothing changes.
    let begun = ok(core.handle(&elevated_owner(), reset()))?;
    let id = str_of(&begun, "intent_id")?;
    let tasks = core.take_pending_confirmations();
    assert!(tasks[0].text.contains("REMOVE"), "{}", tasks[0].text);
    core.confirmation_answer(&id, ConfirmAnswer::No)
        .map_err(|e| e.to_string())?;
    assert_eq!(
        ok(core.handle(&owner(), Request::Status))?["caller_enrolled"],
        Value::Bool(true)
    );
    // Yes: the key goes, the epoch moves, the status reports it once.
    let epoch = core.epoch();
    let begun = ok(core.handle(&elevated_owner(), reset()))?;
    let id = str_of(&begun, "intent_id")?;
    core.take_pending_confirmations();
    core.confirmation_answer(&id, ConfirmAnswer::Yes)
        .map_err(|e| e.to_string())?;
    let status = ok(core.handle(
        &elevated_owner(),
        Request::IntentStatus {
            intent_id: id.clone(),
        },
    ))?;
    assert_eq!(str_of(&status, "state")?, "completed");
    assert_eq!(
        code(core.handle(&elevated_owner(), Request::IntentStatus { intent_id: id })),
        Some(FailureCode::InvalidRequest)
    );
    assert!(core.epoch() > epoch);
    assert_eq!(
        ok(core.handle(&owner(), Request::Status))?["caller_enrolled"],
        Value::Bool(false)
    );
    assert!(events
        .with_id(crate::EVENT_ENROLLED)
        .iter()
        .any(|e| e.contains("|reset|")));
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn browser_grants_name_their_client_and_only_the_routine_families() -> Result<(), String> {
    use crate::lease::BrowserFamily;
    let dir = temp_dir("browser-scope")?;
    let events = Events::default();
    let mut core = open_enrolled(&dir, &events)?;
    let client = format!("cl-{}", "a".repeat(32));
    let scope =
        |families: Vec<BrowserFamily>, origins: Vec<String>| LeaseScope::BrowserFullAccess {
            client_ref: client.clone(),
            session_id: "bs-0123456789abcdef-1-0001020304050607".to_owned(),
            origins,
            families,
            task: Some("Book a table".to_owned()),
        };
    let one = vec!["https://fixture.test".to_owned()];
    for family in [
        BrowserFamily::Scroll,
        BrowserFamily::Read,
        BrowserFamily::Download,
    ] {
        assert_eq!(
            code(core.handle(
                &owner(),
                grant_begin_with(
                    Some(scope(vec![BrowserFamily::Navigate, family], one.clone())),
                    &client,
                    "browse"
                )
            )),
            Some(FailureCode::InvalidRequest),
            "{family:?}"
        );
    }
    let seventeen: Vec<String> = (0..17).map(|n| format!("https://h{n}.test")).collect();
    assert_eq!(
        code(core.handle(
            &owner(),
            grant_begin_with(
                Some(scope(vec![BrowserFamily::Click], seventeen)),
                &client,
                "browse"
            )
        )),
        Some(FailureCode::InvalidRequest)
    );
    assert_eq!(
        code(core.handle(
            &owner(),
            grant_begin_with(
                Some(scope(vec![BrowserFamily::Click], one.clone())),
                "mcp-client-1",
                "browse"
            )
        )),
        Some(FailureCode::InvalidRequest),
        "the principal is the client_ref"
    );
    let routine = vec![
        BrowserFamily::Navigate,
        BrowserFamily::Click,
        BrowserFamily::Type,
        BrowserFamily::Select,
        BrowserFamily::Tabs,
    ];
    let begun = ok(core.handle(
        &owner(),
        grant_begin_with(Some(scope(routine, one)), &client, "browse"),
    ))?;
    let id = str_of(&begun, "intent_id")?;
    let (challenge, text) = confirm_yes(&mut core, &owner(), &id)?;
    assert!(text.contains("browser Full Access"), "{text}");
    let done = ok(core.handle(
        &owner(),
        presence(&id, &str_of(&begun, "code")?, &challenge),
    ))?;
    let lease: SignedLease =
        serde_json::from_value(done["lease"].clone()).map_err(|e| e.to_string())?;
    assert!(lease.body.scope.admits(ExecutorClass::Browser));
    assert!(!lease.body.scope.admits(ExecutorClass::DesktopInput));
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
#[test]
fn issuance_is_refused_for_every_non_owner_caller() -> Result<(), String> {
    let dir = temp_dir("non-owner")?;
    let events = Events::default();
    let mut core = open_enrolled(&dir, &events)?;
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
    }
    assert!(core.observe_unlock(1).is_none(), "nothing was recorded");
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn a_grant_binds_the_code_the_requesting_process_and_the_confirmation_text() -> Result<(), String> {
    let dir = temp_dir("flow")?;
    let events = Events::default();
    let mut core = open_enrolled(&dir, &events)?;
    // A routine unlock without an intent opens nothing.
    assert!(core.observe_unlock(1).is_none());
    let begun = ok(core.handle(&owner(), grant_begin(None)))?;
    let id = str_of(&begun, "intent_id")?;
    let one_time = str_of(&begun, "code")?;
    assert_eq!(one_time.len(), 9);
    // Another process of the same user cannot take over the slot, read the
    // intent, cancel it, or record a second one.
    for request in [
        Request::IntentStatus {
            intent_id: id.clone(),
        },
        Request::CancelIntent {
            intent_id: id.clone(),
        },
    ] {
        assert!(core.handle(&other_process(), request).is_err());
    }
    assert_eq!(
        code(core.handle(&other_process(), grant_begin(None))),
        Some(FailureCode::CapabilityDenied)
    );
    // Presence before the unlock is refused and consumes nothing.
    assert_eq!(
        code(core.handle(&owner(), presence(&id, &one_time, &[0u8; 32]))),
        Some(FailureCode::CapabilityDenied)
    );
    let (challenge, text) = confirm_yes(&mut core, &owner(), &id)?;
    assert!(text.contains(&format!("Code: {one_time}")), "{text}");
    assert!(text.contains("Requested by: process 4100 "), "{text}");
    assert!(text.contains("Full Control acts with your Windows rights"));
    assert!(text.is_ascii());
    // Another process holding a valid signature still cannot complete.
    assert!(core
        .handle(&other_process(), presence(&id, &one_time, &challenge))
        .is_err());
    let done = ok(core.handle(&owner(), presence(&id, &one_time, &challenge)))?;
    let lease: SignedLease =
        serde_json::from_value(done["lease"].clone()).map_err(|e| e.to_string())?;
    assert_eq!(lease.body.scope, LeaseScope::narrow_default());
    assert_eq!(
        lease.body.expires_at_ms - lease.body.issued_at_ms,
        30 * 60_000
    );
    assert_eq!(lease.body.requester.pid, 4100);
    assert!(!lease.body.grant.confirmation_input_protected);
    assert_eq!(
        lease.body.grant.confirmation_text_digest,
        sha256_hex(text.as_bytes())
    );
    let granted = events.with_id(crate::EVENT_GRANTED_SCOPE);
    assert_eq!(granted.len(), 1);
    assert!(
        granted[0].contains(&lease.body.lease_id)
            && granted[0].contains("executors [desktop_input]")
    );

    // Authorize: orceld only, in scope only, never Admin, same principal.
    let allowed = ok(authorize(
        &mut core,
        &orceld(),
        &lease.body.lease_id,
        ExecutorClass::DesktopInput,
    ))?;
    assert!(str_of(&allowed, "authorization_id")?.starts_with("az-"));
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
    let audit =
        std::fs::read_to_string(dir.join(crate::core::AUDIT_FILE)).map_err(|e| e.to_string())?;
    let record: Value = audit
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|record| record["kind"] == "authorize")
        .ok_or("no authorize record")?;
    assert_eq!(record["asserted_by_session"]["capability"], "desktop.input");
    assert_eq!(record["observed"]["caller_pid"], 4200);
    assert_eq!(record["observed"]["role"], "orceld");
    // A grant (or renewal) while a lease is active is refused.
    assert_eq!(
        code(core.handle(&owner(), grant_begin(None))),
        Some(FailureCode::CapabilityDenied)
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn a_wrong_code_or_signature_is_refused_and_consumes_the_intent() -> Result<(), String> {
    let dir = temp_dir("code")?;
    let events = Events::default();
    let mut core = open_enrolled(&dir, &events)?;
    let begun = ok(core.handle(&owner(), grant_begin(None)))?;
    let id = str_of(&begun, "intent_id")?;
    let (challenge, _) = confirm_yes(&mut core, &owner(), &id)?;
    assert_eq!(
        code(core.handle(&owner(), presence(&id, "AAAA-AAAA", &challenge))),
        Some(FailureCode::CapabilityDenied)
    );
    assert!(core
        .handle(&owner(), Request::IntentStatus { intent_id: id })
        .is_err());

    let begun = ok(core.handle(&owner(), grant_begin(None)))?;
    let id = str_of(&begun, "intent_id")?;
    let one_time = str_of(&begun, "code")?;
    let (challenge, _) = confirm_yes(&mut core, &owner(), &id)?;
    let forged = Request::PresenceComplete {
        intent_id: id.clone(),
        code: one_time,
        signature_hex: presence_signature(b"spki:someone-else", &challenge),
    };
    assert_eq!(
        code(core.handle(&owner(), forged)),
        Some(FailureCode::CapabilityDenied)
    );
    assert!(core
        .handle(&owner(), Request::IntentStatus { intent_id: id })
        .is_err());
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn confirmation_fields_are_printable_ascii_without_padding() -> Result<(), String> {
    let dir = temp_dir("text")?;
    let events = Events::default();
    let mut core = open_enrolled(&dir, &events)?;
    let bad = [
        "line\u{2028}break",
        "para\u{2029}graph",
        "evil\u{202E}txt.exe",
        "zero\u{200B}width",
        "bom\u{FEFF}here",
        "caf\u{e9}",
        " leading",
        "trailing ",
        "two  spaces",
        "tab\there",
        "new\nline",
        "",
    ];
    for text in bad {
        assert_eq!(
            code(core.handle(&owner(), grant_begin_with(None, text, "task"))),
            Some(FailureCode::InvalidRequest),
            "principal {text:?}"
        );
        assert_eq!(
            code(core.handle(&owner(), grant_begin_with(None, "client", text))),
            Some(FailureCode::InvalidRequest),
            "task {text:?}"
        );
    }
    let long = "x".repeat(65);
    assert_eq!(
        code(core.handle(&owner(), grant_begin_with(None, &long, "task"))),
        Some(FailureCode::InvalidRequest)
    );
    let unicode_root = LeaseScope::DesktopFullUser {
        executors: vec![ExecutorClass::Filesystem],
        roots: vec!["D:\\w\u{202E}ork".to_owned()],
        shells: false,
    };
    assert_eq!(
        code(core.handle(&owner(), grant_begin(Some(unicode_root)))),
        Some(FailureCode::InvalidRequest)
    );
    // The observed image is cleaned, not refused: it comes from the OS.
    let shown = display_image("C:\\Users\\x\\\u{202E}exe.txt\u{200B}\u{2028}.exe");
    assert!(shown.is_ascii() && !shown.contains('\u{202E}'), "{shown}");
    let long_image = format!("C:\\{}\\orceld.exe", "d".repeat(400));
    let shown = display_image(&long_image);
    assert!(
        shown.len() <= 163 && shown.ends_with("orceld.exe"),
        "{shown}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn the_window_closes_and_a_no_or_a_timeout_ends_the_intent() -> Result<(), String> {
    let dir = temp_dir("window")?;
    let events = Events::default();
    let mut core = open_enrolled(&dir, &events)?;
    for answer in [ConfirmAnswer::No, ConfirmAnswer::Timeout] {
        let begun = ok(core.handle(&owner(), grant_begin(None)))?;
        let id = str_of(&begun, "intent_id")?;
        assert!(core.observe_unlock(1).is_some());
        core.confirmation_answer(&id, answer)
            .map_err(|e| e.to_string())?;
        assert!(core
            .handle(&owner(), Request::IntentStatus { intent_id: id })
            .is_err());
    }
    // A lock keeps the intent that awaits its unlock; it expires after 5 min.
    let begun = ok(core.handle(&owner(), grant_begin(None)))?;
    let id = str_of(&begun, "intent_id")?;
    core.session_ended(1, "session_lock", true)
        .map_err(|e| e.to_string())?;
    assert!(core
        .handle(
            &owner(),
            Request::IntentStatus {
                intent_id: id.clone()
            }
        )
        .is_ok());
    advance(INTENT_TTL_MS + 1);
    assert!(core.observe_unlock(1).is_none());
    assert!(core
        .handle(&owner(), Request::IntentStatus { intent_id: id })
        .is_err());
    // The window closes 120 s after the unlock.
    let begun = ok(core.handle(&owner(), grant_begin(None)))?;
    let id = str_of(&begun, "intent_id")?;
    let one_time = str_of(&begun, "code")?;
    let (challenge, _) = confirm_yes(&mut core, &owner(), &id)?;
    advance(GRANT_WINDOW_MS + 1);
    assert!(core
        .handle(&owner(), presence(&id, &one_time, &challenge))
        .is_err());
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn revoke_stop_lock_and_expiry_move_the_counters_and_end_leases() -> Result<(), String> {
    let dir = temp_dir("counters")?;
    let events = Events::default();
    let mut core = open_enrolled(&dir, &events)?;
    let start_epoch = core.epoch();
    let start_revocations = core.revocations();

    let (lease, _) = grant(&mut core, None)?;
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

    let (lease, _) = grant(&mut core, None)?;
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

    let (lease, _) = grant(&mut core, None)?;
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

    let (lease, _) = grant(&mut core, None)?;
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

    let (epoch, revocations) = (core.epoch(), core.revocations());
    drop(core);
    let core = open(&dir, &events)?;
    assert_eq!((core.epoch(), core.revocations()), (epoch, revocations));
    drop(core);
    std::fs::remove_file(dir.join(crate::core::STATE_FILE)).map_err(|e| e.to_string())?;
    assert!(
        open(&dir, &events).is_err(),
        "a missing state with audit history refuses"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn a_missing_signing_key_with_audit_history_refuses_a_new_key() -> Result<(), String> {
    let dir = temp_dir("keyhistory")?;
    assert_eq!(
        check_signing_key_history(&dir, "lease-signing.key"),
        Ok(()),
        "a fresh directory may create a key"
    );
    let events = Events::default();
    drop(open(&dir, &events)?);
    assert!(check_signing_key_history(&dir, "lease-signing.key").is_err());
    std::fs::write(dir.join("lease-signing.key"), b"wrapped").map_err(|e| e.to_string())?;
    assert_eq!(check_signing_key_history(&dir, "lease-signing.key"), Ok(()));
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn every_event_carries_a_signature_by_the_lease_key() -> Result<(), String> {
    let dir = temp_dir("events")?;
    let events = Events::default();
    let mut core = open_enrolled(&dir, &events)?;
    grant(&mut core, None)?;
    let all = events.all();
    assert!(all.len() >= 4, "{all:?}");
    for (id, line) in all {
        let (text, signature) = line.rsplit_once("|sig=").ok_or("an unsigned event")?;
        assert!(
            text.starts_with(&format!("orcel-event/1|id={id}|audit_seq=")),
            "{text}"
        );
        let mut input = EVENT_SIGNING_DOMAIN.to_vec();
        input.extend_from_slice(text.as_bytes());
        assert_eq!(signature, keyed_hash(&input), "{text}");
    }
    // A forged id (or position) does not verify.
    let (id, line) = events.all().into_iter().next().ok_or("no event")?;
    let (text, signature) = line.rsplit_once("|sig=").ok_or("unsigned")?;
    let forged = text.replacen(&format!("id={id}"), "id=4101", 1);
    let mut input = EVENT_SIGNING_DOMAIN.to_vec();
    input.extend_from_slice(forged.as_bytes());
    assert_ne!(signature, keyed_hash(&input));
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn an_intent_is_bound_to_the_process_instance_and_needs_its_image() -> Result<(), String> {
    let dir = temp_dir("generation")?;
    let events = Events::default();
    let mut core = open_enrolled(&dir, &events)?;
    let mut no_image = owner();
    no_image.image.clear();
    assert_eq!(
        code(core.handle(&no_image, grant_begin(None))),
        Some(FailureCode::CapabilityDenied)
    );
    let mut no_generation = owner();
    no_generation.process_generation = 0;
    assert_eq!(
        code(core.handle(&no_generation, grant_begin(None))),
        Some(FailureCode::CapabilityDenied)
    );
    let begun = ok(core.handle(&owner(), grant_begin(None)))?;
    let id = str_of(&begun, "intent_id")?;
    // The same PID and image in a later process (a reused PID) is another caller.
    let mut reused = owner();
    reused.process_generation += 1;
    assert!(core
        .handle(
            &reused,
            Request::IntentStatus {
                intent_id: id.clone()
            }
        )
        .is_err());
    assert!(core
        .handle(
            &reused,
            Request::CancelIntent {
                intent_id: id.clone()
            }
        )
        .is_err());
    assert!(core
        .handle(&owner(), Request::IntentStatus { intent_id: id })
        .is_ok());
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn leases_are_bound_to_their_user_and_logon_session() -> Result<(), String> {
    let dir = temp_dir("binding")?;
    let events = Events::default();
    let mut core = open_enrolled(&dir, &events)?;
    let (lease, _) = grant(&mut core, None)?;
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
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn a_browser_lease_covers_the_browser_executor_only() -> Result<(), String> {
    let dir = temp_dir("browser")?;
    let events = Events::default();
    let mut core = open_enrolled(&dir, &events)?;
    let client = format!("cl-{}", "0123456789abcdef".repeat(2));
    let scope = LeaseScope::BrowserFullAccess {
        client_ref: client.clone(),
        session_id: "bs-0123456789abcdef-1-0001020304050607".to_owned(),
        origins: vec!["https://example.com".to_owned()],
        families: vec![
            crate::lease::BrowserFamily::Click,
            crate::lease::BrowserFamily::Type,
        ],
        task: Some("fill the form".to_owned()),
    };
    let begun = ok(core.handle(
        &owner(),
        grant_begin_with(Some(scope), &client, "fill the form"),
    ))?;
    let id = str_of(&begun, "intent_id")?;
    let (challenge, _) = confirm_yes(&mut core, &owner(), &id)?;
    let done = ok(core.handle(
        &owner(),
        presence(&id, &str_of(&begun, "code")?, &challenge),
    ))?;
    let lease: SignedLease =
        serde_json::from_value(done["lease"].clone()).map_err(|e| e.to_string())?;
    let browser_claims = AuthorizeClaims {
        principal_id: client.clone(),
        origin: Some("https://example.com".to_owned()),
        ..claims()
    };
    let as_browser = |executor| Request::Authorize {
        lease_id: lease.body.lease_id.clone(),
        executor,
        claims: browser_claims.clone(),
    };
    ok(core.handle(&orceld(), as_browser(ExecutorClass::Browser)))?;
    assert_eq!(
        code(core.handle(&orceld(), as_browser(ExecutorClass::DesktopInput))),
        Some(FailureCode::CapabilityDenied)
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

fn anchor_request(file: char, seq: u64, digest: char, link: Option<ChainLink>) -> Request {
    Request::Anchor {
        anchor: AnchorRef {
            log: "orceld".to_owned(),
            file_id: file.to_string().repeat(64),
            seq,
            digest: digest.to_string().repeat(64),
        },
        link,
    }
}

fn link_to(file: char, seq: u64, digest: char) -> Option<ChainLink> {
    Some(ChainLink {
        previous_file_id: file.to_string().repeat(64),
        previous_head_seq: seq,
        previous_head_digest: digest.to_string().repeat(64),
    })
}

/// WP1-03: orceld, and only orceld, can have the service hold an anchor of
/// its own audit chain; the anchor is recorded as orceld's claim and
/// written to the Event Log as a signed 4100 event.
#[test]
fn wp103_the_service_holds_orcelds_chain_anchor() -> Result<(), String> {
    let dir = temp_dir("anchor")?;
    let events = Events::default();
    let mut core = open(&dir, &events)?;
    for caller in [owner(), other_process()] {
        assert_eq!(
            code(core.handle(&caller, anchor_request('a', 31, 'b', None))),
            Some(FailureCode::CapabilityDenied)
        );
    }
    let bad_log = Request::Anchor {
        anchor: AnchorRef {
            log: "authority".to_owned(),
            file_id: "a".repeat(64),
            seq: 31,
            digest: "b".repeat(64),
        },
        link: None,
    };
    for bad in [
        bad_log,
        anchor_request('a', 31, 'B', None),
        anchor_request('a', 31, 'b', link_to('Z', 1, 'c')),
    ] {
        assert_eq!(
            code(core.handle(&orceld(), bad)),
            Some(FailureCode::InvalidRequest)
        );
    }
    let answer = ok(core.handle(&orceld(), anchor_request('a', 31, 'b', None)))?;
    assert_eq!(answer["anchored"], Value::Bool(true));
    assert_eq!(answer["event_id"], 4100);
    let insertion = format!(
        "orcel-anchor/1|orceld|{}|31|{}",
        "a".repeat(64),
        "b".repeat(64)
    );
    let written = events.with_id(4100);
    assert!(
        written
            .iter()
            .any(|text| text.contains(&insertion) && text.contains("|sig=")),
        "{written:?}"
    );
    let audit =
        std::fs::read_to_string(dir.join(crate::core::AUDIT_FILE)).map_err(|e| e.to_string())?;
    let record = audit
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|record| record["kind"] == "anchor" && record["observed"]["role"] == "orceld")
        .ok_or("an anchor record")?;
    assert_eq!(record["asserted_by_session"]["digest"], "b".repeat(64));
    assert_eq!(record["seq"], answer["authority_seq"]);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// WP1-03 review: per account and log the service refuses a seq
/// regression or rewrite, answers a repeat without a second record, refuses
/// a replacement file that does not link to the held one (and a file the
/// log left), accepts a linked continuation, and caps the rate.
#[test]
fn wp103_the_service_refuses_rewrites_regressions_and_unlinked_files() -> Result<(), String> {
    let dir = temp_dir("anchor-rules")?;
    let events = Events::default();
    let mut core = open(&dir, &events)?;
    ok(core.handle(&orceld(), anchor_request('a', 31, 'b', None)))?;
    let count = || events.with_id(4100).len();
    let before = count();
    let repeat = ok(core.handle(&orceld(), anchor_request('a', 31, 'b', None)))?;
    assert_eq!(repeat["duplicate"], Value::Bool(true));
    assert_eq!(count(), before, "a repeat writes nothing");
    for refused in [
        anchor_request('a', 31, 'c', None),
        anchor_request('a', 7, 'c', None),
        // A new file with no link, a wrong link, or a head before the
        // anchored record.
        anchor_request('d', 31, 'e', None),
        anchor_request('d', 31, 'e', link_to('f', 40, 'b')),
        anchor_request('d', 31, 'e', link_to('a', 30, 'b')),
        anchor_request('d', 31, 'e', link_to('a', 31, 'c')),
    ] {
        assert_eq!(
            code(core.handle(&orceld(), refused)),
            Some(FailureCode::CapabilityDenied)
        );
    }
    ok(core.handle(&orceld(), anchor_request('a', 63, 'c', None)))?;
    let moved = ok(core.handle(
        &orceld(),
        anchor_request('d', 31, 'e', link_to('a', 70, 'f')),
    ))?;
    assert_eq!(moved["new_file"], Value::Bool(true));
    // The file the log left is refused from now on.
    assert_eq!(
        code(core.handle(&orceld(), anchor_request('a', 95, 'c', None))),
        Some(FailureCode::CapabilityDenied)
    );
    // Another account's chain is its own.
    let other_account = CallerFacts {
        user_sid: "S-1-5-21-1-2-3-1002".to_owned(),
        ..orceld()
    };
    ok(core.handle(&other_account, anchor_request('a', 31, 'b', None)))?;
    // The rate cap.
    let mut refused = None;
    for n in 0..=crate::core::chain_anchor::ANCHORS_PER_MINUTE as u64 {
        if let Err(error) = core.handle(&orceld(), anchor_request('d', 100 + n, 'e', None)) {
            refused = Some(error);
            break;
        }
    }
    let refused = refused.ok_or("the rate cap never refused")?;
    assert!(
        refused.message.contains("in a minute"),
        "{}",
        refused.message
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// WP1-03 re-review: orceld reads back what the service holds of its chain
/// (the verifier and a starting writer check against it), and every rule
/// refusal carries the prefix orceld records as `link_refused`.
#[test]
fn wp103_the_service_reports_its_held_anchor_and_marks_rule_refusals() -> Result<(), String> {
    let dir = temp_dir("anchor-status")?;
    let events = Events::default();
    let mut core = open(&dir, &events)?;
    let status = |core: &mut AuthorityCore, caller: &CallerFacts| {
        core.handle(
            caller,
            Request::AnchorStatus {
                log: "orceld".to_owned(),
            },
        )
    };
    assert_eq!(ok(status(&mut core, &orceld()))?["held"], Value::Null);
    assert_eq!(
        code(status(&mut core, &other_process())),
        Some(FailureCode::CapabilityDenied)
    );
    ok(core.handle(&orceld(), anchor_request('a', 31, 'b', None)))?;
    let held = ok(status(&mut core, &orceld()))?;
    assert_eq!(held["held"]["file_id"], "a".repeat(64));
    assert_eq!(held["held"]["seq"], 31);
    assert_eq!(held["held"]["digest"], "b".repeat(64));
    let refused = core
        .handle(&orceld(), anchor_request('d', 31, 'e', None))
        .err()
        .ok_or("an unlinked file is refused")?;
    assert!(
        refused
            .message
            .starts_with(crate::core::chain_anchor::REFUSED_PREFIX),
        "{}",
        refused.message
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn review_f1_enroll_and_reset_need_always_notify_and_every_intent_the_owner_cli(
) -> Result<(), String> {
    let dir = temp_dir("review-f1")?;
    let events = Events::default();
    let mut core = open(&dir, &events)?;
    UAC_ALWAYS_NOTIFY.with(|v| v.set(false));
    let refused = core.handle(&elevated_owner(), enroll_request(SPKI, false));
    let reset = core.handle(
        &elevated_owner(),
        Request::ResetEnrollment {
            origin: ClaimedOrigin::OwnerCli,
        },
    );
    let status = ok(core.handle(&owner(), Request::Status))?;
    UAC_ALWAYS_NOTIFY.with(|v| v.set(true));
    let error = refused
        .err()
        .ok_or("enrollment under the default UAC was not refused")?;
    assert_eq!(error.code, FailureCode::CapabilityDenied);
    assert!(error.message.contains("Always notify"), "{}", error.message);
    assert_eq!(code(reset), Some(FailureCode::CapabilityDenied));
    assert_eq!(
        status["uac_always_notify_on_secure_desktop"],
        Value::Bool(false)
    );
    assert_eq!(
        status["uac"]["consent_prompt_behavior_admin"],
        Value::from(5)
    );
    // Any image but the installed CLI: no grant, enrollment or reset intent.
    let elsewhere = CallerFacts {
        image: r"C:\Users\me\Downloads\orcel.exe".to_owned(),
        ..elevated_owner()
    };
    assert_eq!(
        code(core.handle(&elsewhere, enroll_request(SPKI, false))),
        Some(FailureCode::CapabilityDenied)
    );
    enroll(&mut core, SPKI, false)?;
    let cli_elsewhere = CallerFacts {
        image: r"C:\Users\me\Downloads\orcel.exe".to_owned(),
        ..owner()
    };
    let refused = core
        .handle(&cli_elsewhere, grant_begin(None))
        .err()
        .ok_or("a grant from another image was not refused")?;
    assert!(
        refused.message.contains("installed Orcel CLI"),
        "{}",
        refused.message
    );
    assert_eq!(
        ok(core.handle(&owner(), Request::Status))?["caller_is_owner_cli"],
        Value::Bool(true)
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn review_f4_f7_browser_authorize_checks_family_and_origin_and_the_box_says_browser(
) -> Result<(), String> {
    use crate::lease::BrowserFamily;
    let dir = temp_dir("review-f4")?;
    let events = Events::default();
    let mut core = open_enrolled(&dir, &events)?;
    let client = format!("cl-{}", "cd".repeat(16));
    let scope = LeaseScope::BrowserFullAccess {
        client_ref: client.clone(),
        session_id: "bs-0123456789abcdef-1-0001020304050607".to_owned(),
        origins: vec!["https://fixture.test".to_owned()],
        families: vec![BrowserFamily::Navigate, BrowserFamily::Click],
        task: None,
    };
    let begun = ok(core.handle(&owner(), grant_begin_with(Some(scope), &client, "browse")))?;
    let id = str_of(&begun, "intent_id")?;
    let (challenge, text) = confirm_yes(&mut core, &owner(), &id)?;
    assert!(
        text.starts_with("A program asked for Orcel Browser Full Access"),
        "{text}"
    );
    assert!(text.contains("Approve this browser grant?"), "{text}");
    assert!(text.contains("PIN or fingerprint"), "{text}");
    let done = ok(core.handle(
        &owner(),
        presence(&id, &str_of(&begun, "code")?, &challenge),
    ))?;
    let lease: SignedLease =
        serde_json::from_value(done["lease"].clone()).map_err(|e| e.to_string())?;
    let ask = |operation: &str, origin: Option<&str>| Request::Authorize {
        lease_id: lease.body.lease_id.clone(),
        executor: ExecutorClass::Browser,
        claims: AuthorizeClaims {
            principal_id: client.clone(),
            operation: operation.to_owned(),
            origin: origin.map(str::to_owned),
            ..claims()
        },
    };
    ok(core.handle(&orceld(), ask("click", Some("https://fixture.test"))))?;
    ok(core.handle(&orceld(), ask("navigate", Some("https://fixture.test"))))?;
    assert_eq!(
        code(core.handle(&orceld(), ask("type", Some("https://fixture.test")))),
        Some(FailureCode::CapabilityDenied),
        "a family the lease does not name"
    );
    assert_eq!(
        code(core.handle(&orceld(), ask("click", Some("https://other.test")))),
        Some(FailureCode::CapabilityDenied),
        "an origin the lease does not name"
    );
    assert_eq!(
        code(core.handle(&orceld(), ask("click", None))),
        Some(FailureCode::InvalidRequest),
        "no origin"
    );
    // A desktop grant keeps the Full Control wording.
    let (_, desktop_text) = {
        ok(core.handle(&orceld(), Request::Stop))?;
        grant(&mut core, None)?
    };
    assert!(
        desktop_text.starts_with("A program asked for Orcel Full Control"),
        "{desktop_text}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn review_reverify_the_builtin_administrator_needs_admin_approval_mode() -> Result<(), String> {
    assert!(is_builtin_administrator("S-1-5-21-1-2-3-500"));
    assert!(!is_builtin_administrator("S-1-5-21-1-2-3-1001"));
    assert!(!is_builtin_administrator("S-1-5-21-1-2-3-1500"));
    assert!(!is_builtin_administrator("S-1-5-32-500"));
    let dir = temp_dir("review-rid500")?;
    let events = Events::default();
    let mut core = open(&dir, &events)?;
    let administrator = CallerFacts {
        user_sid: "S-1-5-21-1-2-3-500".to_owned(),
        ..elevated_owner()
    };
    let refused = core
        .handle(&administrator, enroll_request(SPKI, false))
        .err()
        .ok_or("the built-in Administrator enrolled without Admin Approval Mode")?;
    assert!(
        refused.message.contains("FilterAdministratorToken"),
        "{}",
        refused.message
    );
    assert_eq!(
        code(core.handle(
            &administrator,
            Request::ResetEnrollment {
                origin: ClaimedOrigin::OwnerCli
            }
        )),
        Some(FailureCode::CapabilityDenied)
    );
    let status = ok(core.handle(&administrator, Request::Status))?;
    assert_eq!(status["caller_is_builtin_administrator"], Value::Bool(true));
    FILTER_ADMINISTRATOR_TOKEN.with(|v| v.set(Some(1)));
    let begun = core.handle(&administrator, enroll_request(SPKI, false));
    let status = ok(core.handle(&administrator, Request::Status))?;
    FILTER_ADMINISTRATOR_TOKEN.with(|v| v.set(None));
    ok(begun)?;
    assert_eq!(status["uac"]["filter_administrator_token"], Value::from(1));
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
