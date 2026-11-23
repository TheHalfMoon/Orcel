//! SG-000132 slice 2: the user-session side of the Orcel authority
//! service's grant and enrollment flows.
//!
//! - `orcel authority enroll [--replace]` (from an ELEVATED terminal): creates
//!   the Windows Hello key credential, reads its public key and TPM
//!   attestation, sends them, prints the one-time code and the key
//!   fingerprint, waits for the service-rendered confirmation, then signs the
//!   challenge with the new key (one Hello gesture).
//! - `orcel authority reset` (elevated): asks the service to remove the
//!   enrolled key; the service confirms in its own box.
//! - `orcel full-control grant` and `orcel browser grant`: record the intent,
//!   print the one-time code, wait for the service-observed unlock and the
//!   confirmation, then sign the challenge, which is bound to the digest of
//!   the confirmation text, with the enrolled key.
//! - WP1-14: `orcel full-control standing grant`: the same gate for a lease
//!   and the standing approval (spec 4.15) issued with it.
//!
//! The service decides everything; this side only carries the human's
//! answers. Every wait is bounded by the service's own intent and window
//! timeouts.

use crate::LifecycleError;
use orcel_authority::client::AuthorityClient;
use orcel_authority::core::standing::{
    PinnedProgram, StandingApproval, StandingScope, STANDING_OPERATIONS,
};
use orcel_authority::lease::{BrowserFamily, LeaseScope, SignedLease, MAX_ORIGINS};
use orcel_authority::protocol::{ClaimedOrigin, Request};
use orcel_authority::{hex, sha256_hex, unhex, AuthorityError};
use orcel_contracts::ExecutorClass;
use serde_json::Value;
use std::time::{Duration, Instant};

/// How often the intent is polled.
pub const POLL: Duration = Duration::from_millis(750);
/// The longest wait: the intent's 5 minutes plus the 120 s window.
pub const MAX_WAIT: Duration = Duration::from_secs(5 * 60 + 120 + 10);

/// Signs a challenge with the user's Windows Hello key credential.
pub trait HelloSigner {
    fn sign(&self, challenge: &[u8]) -> Result<Vec<u8>, String>;
}

/// What `orcel authority enroll` needs from the Hello key it created.
pub trait EnrollKey: HelloSigner {
    fn public_key_spki(&self) -> Result<Vec<u8>, String>;
    /// The attestation buffer and certificate chain buffer.
    fn attestation(&self) -> Result<(Vec<u8>, Vec<u8>), String>;
}

fn authority(error: AuthorityError) -> LifecycleError {
    LifecycleError::state(format!("the Orcel authority service refused: {error}"))
}

fn text(value: &Value, key: &str) -> Result<String, LifecycleError> {
    value[key]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| LifecycleError::state(format!("the authority's answer has no {key}")))
}

/// The key fingerprint as the service shows it (16 groups of 4 hex digits
/// of the SubjectPublicKeyInfo's SHA-256).
pub fn fingerprint(spki: &[u8]) -> String {
    orcel_authority::core::key_fingerprint(&sha256_hex(spki))
}

/// Parses `--executors` (comma separated, snake case) for a desktop grant.
pub fn parse_executors(list: &str) -> Result<Vec<ExecutorClass>, LifecycleError> {
    list.split(',')
        .map(|name| {
            serde_json::from_value::<ExecutorClass>(Value::String(name.trim().to_owned()))
                .map_err(|_| {
                    LifecycleError::usage(format!(
                        "unknown executor {name:?}; use desktop_input, desktop_observation, filesystem, shell_process or visual_agent"
                    ))
                })
        })
        .collect()
}

/// The desktop scope a grant asks for: the narrow default (desktop input
/// only, no roots, no shells) unless widened explicitly.
pub fn desktop_scope(
    executors: Option<Vec<ExecutorClass>>,
    roots: Vec<String>,
    shells: bool,
) -> Result<Option<LeaseScope>, LifecycleError> {
    if executors.is_none() && roots.is_empty() && !shells {
        return Ok(None);
    }
    let mut executors = executors.unwrap_or_else(|| vec![ExecutorClass::DesktopInput]);
    if shells && !executors.contains(&ExecutorClass::ShellProcess) {
        executors.push(ExecutorClass::ShellProcess);
    }
    if !roots.is_empty() && !executors.contains(&ExecutorClass::Filesystem) {
        executors.push(ExecutorClass::Filesystem);
    }
    let scope = LeaseScope::DesktopFullUser {
        executors,
        roots,
        shells,
    };
    scope
        .validate()
        .map_err(|error| LifecycleError::usage(error.message))?;
    Ok(Some(scope))
}

/// Parses `--families` (comma separated) for a browser grant.
pub fn parse_families(list: &str) -> Result<Vec<BrowserFamily>, LifecycleError> {
    list.split(',')
        .map(|name| {
            serde_json::from_value::<BrowserFamily>(Value::String(name.trim().to_owned())).map_err(
                |_| {
                    LifecycleError::usage(format!(
                        "unknown family {name:?}; use navigate, click, type, select or tabs"
                    ))
                },
            )
        })
        .collect()
}

/// The browser scope a grant asks for (SG-000135): one session, its
/// client, 1 to 16 exact origins, routine families only.
pub fn browser_scope(
    session_id: String,
    client_ref: String,
    origins: Vec<String>,
    families: Vec<BrowserFamily>,
    task: Option<String>,
) -> Result<LeaseScope, LifecycleError> {
    if origins.len() > MAX_ORIGINS {
        return Err(LifecycleError::usage(format!(
            "a browser grant names at most {MAX_ORIGINS} origins"
        )));
    }
    let scope = LeaseScope::BrowserFullAccess {
        client_ref,
        session_id,
        origins,
        families,
        task,
    };
    scope
        .validate()
        .map_err(|error| LifecycleError::usage(error.message))?;
    Ok(scope)
}

/// One grant request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRequest {
    pub scope: Option<LeaseScope>,
    pub minutes: u64,
    pub principal_id: String,
    pub task: String,
}

/// Waits until the caller's intent awaits presence, then returns its
/// challenge after checking the confirmation text's digest.
fn await_presence(
    client: &AuthorityClient,
    intent_id: &str,
    progress: &mut dyn FnMut(&str),
) -> Result<(Vec<u8>, String), LifecycleError> {
    let started = Instant::now();
    let mut last_state = String::new();
    loop {
        let status = client
            .call(&Request::IntentStatus {
                intent_id: intent_id.to_owned(),
            })
            .map_err(|error| {
                LifecycleError::state(format!(
                    "the request ended without approval (refused, cancelled, timed out, or the window closed): {error}"
                ))
            })?;
        let state = text(&status, "state")?;
        if state != last_state {
            match state.as_str() {
                "awaiting_unlock" => progress(
                    "Waiting for you to lock (Win+L) and unlock this PC; the Orcel Authority box appears after the unlock.",
                ),
                "awaiting_confirmation" => {
                    progress("Waiting for your answer in the Orcel Authority box.")
                }
                _ => {}
            }
            last_state = state.clone();
        }
        if state == "awaiting_presence" {
            let confirmation = text(&status, "confirmation_text")?;
            let digest = text(&status, "confirmation_text_digest")?;
            if sha256_hex(confirmation.as_bytes()) != digest {
                return Err(LifecycleError::state(
                    "the confirmation text does not match its digest; nothing was signed",
                ));
            }
            let challenge = unhex(&text(&status, "challenge_hex")?)
                .filter(|bytes| bytes.len() == 32)
                .ok_or_else(|| LifecycleError::state("the challenge is not 32 bytes of hex"))?;
            return Ok((challenge, digest));
        }
        if started.elapsed() > MAX_WAIT {
            let _ = client.call(&Request::CancelIntent {
                intent_id: intent_id.to_owned(),
            });
            return Err(LifecycleError::state(
                "the request timed out and was cancelled",
            ));
        }
        std::thread::sleep(POLL);
    }
}

/// The grant gate both grants share: record the intent (`begin`), print the
/// one-time code, wait for the observed unlock and the confirmation, sign
/// the challenge with Windows Hello, and complete it (`complete`, given the
/// intent id, the code and the signature). Returns the completion's answer.
fn run_intent(
    client: &AuthorityClient,
    begin: &Request,
    complete: &dyn Fn(String, String, String) -> Request,
    signer: &dyn HelloSigner,
    progress: &mut dyn FnMut(&str),
) -> Result<Value, LifecycleError> {
    let begun = client.call(begin).map_err(authority)?;
    let intent_id = text(&begun, "intent_id")?;
    let code = text(&begun, "code")?;
    progress(&format!(
        "Grant requested. One-time code: {code}\nThe Orcel Authority box must show this code and this process (pid {}). Lock your PC (Win+L) and unlock it within 5 minutes; choose Yes only if the code, process and scope match.",
        std::process::id()
    ));
    let (challenge, digest) = await_presence(client, &intent_id, progress)?;
    progress(&format!(
        "You approved the confirmation (text digest {}). Windows Hello asks for your gesture to sign it.",
        &digest[..16]
    ));
    let signature = signer.sign(&challenge).map_err(|error| {
        let _ = client.call(&Request::CancelIntent {
            intent_id: intent_id.clone(),
        });
        LifecycleError::state(format!("Windows Hello did not sign: {error}"))
    })?;
    client
        .call(&complete(intent_id, code, hex(&signature)))
        .map_err(authority)
}

fn lease_of(done: &Value) -> Result<SignedLease, LifecycleError> {
    serde_json::from_value(done["lease"].clone())
        .map_err(|error| LifecycleError::state(format!("the service returned no lease: {error}")))
}

/// `orcel full-control grant` and `orcel browser grant` through the service.
pub fn run_grant(
    client: &AuthorityClient,
    request: &GrantRequest,
    signer: &dyn HelloSigner,
    progress: &mut dyn FnMut(&str),
) -> Result<SignedLease, LifecycleError> {
    let begin = Request::GrantBegin {
        origin: ClaimedOrigin::OwnerCli,
        scope: request.scope.clone(),
        minutes: Some(request.minutes),
        principal_id: request.principal_id.clone(),
        task: request.task.clone(),
    };
    let complete = |intent_id, code, signature_hex| Request::PresenceComplete {
        intent_id,
        code,
        signature_hex,
    };
    let done = run_intent(client, &begin, &complete, signer, progress)?;
    lease_of(&done)
}

/// WP1-14: one standing approval request (spec 4.15): the lease it is
/// granted with and what it covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandingRequest {
    pub scope: LeaseScope,
    pub minutes: u64,
    /// The identified client (`cl-` client reference, as `fc_status` shows
    /// it).
    pub client_ref: String,
    pub task: String,
    pub standing: StandingScope,
}

/// Parses `--operations` (comma separated) for a standing approval.
pub fn parse_operations(list: &str) -> Result<Vec<String>, LifecycleError> {
    list.split(',')
        .map(|name| {
            let name = name.trim();
            if STANDING_OPERATIONS.contains(&name) {
                Ok(name.to_owned())
            } else {
                Err(LifecycleError::usage(format!(
                    "unknown operation {name:?}; a standing approval covers only run (every Git change asks)"
                )))
            }
        })
        .collect()
}

/// Review of #844: pins each `--program` as it is now (path, SHA-256 of its
/// contents, file identity).
pub fn pin_programs(paths: &[String]) -> Result<Vec<PinnedProgram>, LifecycleError> {
    paths
        .iter()
        .map(|path| {
            orcel_authority::core::standing::pin_program_for_grant(path).map_err(|error| {
                LifecycleError::usage(format!("--program {path}: {}", error.message))
            })
        })
        .collect()
}

/// WP1-14: the lease and standing approval a standing grant asks for. The
/// lease grants the filesystem and shell/process executors over `roots`;
/// the standing approval covers `operations` inside `folders`. Validated
/// here as the service validates it, which refuses `run` under such a lease
/// (review of #847).
pub fn standing_request(
    client_ref: String,
    task: String,
    roots: Vec<String>,
    minutes: u64,
    standing: StandingScope,
) -> Result<StandingRequest, LifecycleError> {
    let scope = desktop_scope(
        Some(vec![ExecutorClass::Filesystem, ExecutorClass::ShellProcess]),
        roots,
        true,
    )?
    .ok_or_else(|| LifecycleError::usage("a standing grant names its lease's roots"))?;
    standing
        .validate(&scope, &client_ref, minutes)
        .map_err(|error| LifecycleError::usage(error.message))?;
    Ok(StandingRequest {
        scope,
        minutes,
        client_ref,
        task,
        standing,
    })
}

/// WP1-14: `orcel full-control standing grant` through the service: the
/// lease and its standing approval, through the same intent, unlock,
/// service-rendered confirmation and Windows Hello as a grant.
pub fn run_standing_grant(
    client: &AuthorityClient,
    request: &StandingRequest,
    signer: &dyn HelloSigner,
    progress: &mut dyn FnMut(&str),
) -> Result<(SignedLease, StandingApproval), LifecycleError> {
    let begin = Request::StandingBegin {
        origin: ClaimedOrigin::OwnerCli,
        scope: request.scope.clone(),
        minutes: Some(request.minutes),
        principal_id: request.client_ref.clone(),
        task: request.task.clone(),
        standing: request.standing.clone(),
    };
    let complete = |intent_id, code, signature_hex| Request::StandingComplete {
        intent_id,
        code,
        signature_hex,
    };
    let done = run_intent(client, &begin, &complete, signer, progress)?;
    let standing = serde_json::from_value(done["standing"].clone()).map_err(|error| {
        LifecycleError::state(format!(
            "the service returned no standing approval: {error}"
        ))
    })?;
    Ok((lease_of(&done)?, standing))
}

/// WP1-14: the standing approvals of this user and logon session, as the
/// service lists them (each with its state and whether it is in effect).
pub fn standing_approvals(client: &AuthorityClient) -> Result<Vec<Value>, LifecycleError> {
    let listed = client.list().map_err(authority)?;
    Ok(listed["standing"].as_array().cloned().unwrap_or_default())
}

/// `orcel authority enroll` (the caller is elevated; the service checks).
pub fn run_enroll(
    client: &AuthorityClient,
    key: &dyn EnrollKey,
    replace: bool,
    progress: &mut dyn FnMut(&str),
) -> Result<Value, LifecycleError> {
    let spki = key
        .public_key_spki()
        .map_err(|error| LifecycleError::state(format!("read the key's public key: {error}")))?;
    let (attestation, chain) = key.attestation().map_err(|error| {
        LifecycleError::prerequisite(format!(
            "the key cannot be attested on this PC, so enrollment stays refused (fail closed): {error}"
        ))
    })?;
    let begun = client
        .call(&Request::EnrollBegin {
            origin: ClaimedOrigin::OwnerCli,
            public_key_spki_hex: hex(&spki),
            attestation_hex: hex(&attestation),
            certificate_chain_hex: hex(&chain),
            replace,
        })
        .map_err(authority)?;
    let intent_id = text(&begun, "intent_id")?;
    let code = text(&begun, "code")?;
    let shown = text(&begun, "key_fingerprint")?;
    let local = fingerprint(&spki);
    if shown != local {
        let _ = client.call(&Request::CancelIntent { intent_id });
        return Err(LifecycleError::state(
            "the service reports another fingerprint than this key's; the enrollment was cancelled",
        ));
    }
    progress(&format!(
        "Enrollment requested. One-time code: {code}\nKey fingerprint (SHA-256): {local}\nThe Orcel Authority box must show this code and this fingerprint. Choose Yes only if both match."
    ));
    let (challenge, _) = await_presence(client, &intent_id, progress)?;
    progress("You approved. Windows Hello asks for your gesture once to prove the new key.");
    let signature = key.sign(&challenge).map_err(|error| {
        let _ = client.call(&Request::CancelIntent {
            intent_id: intent_id.clone(),
        });
        LifecycleError::state(format!("Windows Hello did not sign: {error}"))
    })?;
    client
        .call(&Request::PresenceComplete {
            intent_id,
            code,
            signature_hex: hex(&signature),
        })
        .map_err(authority)
}

/// `orcel authority reset` (elevated): returns once the service removed
/// the key, or the error if it did not.
pub fn run_reset(
    client: &AuthorityClient,
    progress: &mut dyn FnMut(&str),
) -> Result<(), LifecycleError> {
    let begun = client
        .call(&Request::ResetEnrollment {
            origin: ClaimedOrigin::OwnerCli,
        })
        .map_err(authority)?;
    let intent_id = text(&begun, "intent_id")?;
    progress(&format!(
        "Reset requested. One-time code: {}\nKey fingerprint (SHA-256): {}\nChoose Yes in the Orcel Authority box only if both match.",
        text(&begun, "code")?,
        text(&begun, "key_fingerprint")?
    ));
    await_completion(client, intent_id, "reset")
}

/// Polls a confirmed intent until the service completed it; cancels it
/// after [`MAX_WAIT`].
fn await_completion(
    client: &AuthorityClient,
    intent_id: String,
    what: &str,
) -> Result<(), LifecycleError> {
    let started = Instant::now();
    loop {
        let status = client
            .call(&Request::IntentStatus {
                intent_id: intent_id.clone(),
            })
            .map_err(|error| {
                LifecycleError::state(format!(
                    "the {what} ended without approval (refused, timed out, or the window closed): {error}"
                ))
            })?;
        if status["state"].as_str() == Some("completed") {
            return Ok(());
        }
        if started.elapsed() > MAX_WAIT {
            let _ = client.call(&Request::CancelIntent { intent_id });
            return Err(LifecycleError::state(format!(
                "the {what} timed out and was cancelled"
            )));
        }
        std::thread::sleep(POLL);
    }
}

/// WP1-03 `orcel audit reset-anchor` (elevated): asks the service to reset
/// its held anchor of `log` and waits for the owner's Yes in the
/// service-rendered box. Returns the service's `AnchorStatus` answer after
/// the reset (it names the reset record).
pub fn run_anchor_reset(
    client: &AuthorityClient,
    log: &str,
    progress: &mut dyn FnMut(&str),
) -> Result<Value, LifecycleError> {
    let begun = client
        .call(&Request::AnchorReset {
            origin: ClaimedOrigin::OwnerCli,
            log: log.to_owned(),
        })
        .map_err(authority)?;
    let intent_id = text(&begun, "intent_id")?;
    progress(&format!(
        "Audit anchor reset requested for the log {log}. One-time code: {}\nThe service stops holding chain file {} at seq {} (digest {}).\nChoose Yes in the Orcel Authority box only if the code matches and you lost or replaced the audit chain yourself.",
        text(&begun, "code")?,
        begun["held"]["file_id"].as_str().unwrap_or("?"),
        begun["held"]["seq"],
        begun["held"]["digest"].as_str().unwrap_or("?"),
    ));
    await_completion(client, intent_id, "anchor reset")?;
    client.anchor_status(log).map_err(authority)
}

/// The opening record of the chain file at `chain`, as an anchor of
/// orceld's log (seq 0, its own digest): what the owner CLI asks the service
/// to hold right after a reset opened the file.
pub fn opening_anchor(
    chain: &std::path::Path,
) -> Result<orcel_contracts::event::AnchorRef, LifecycleError> {
    let report = orcel_audit::verify_file(chain)
        .map_err(|error| LifecycleError::state(format!("read the chain: {error}")))?;
    let file_id = report
        .file_id
        .ok_or_else(|| LifecycleError::state("the chain file has no opening record"))?;
    Ok(orcel_contracts::event::AnchorRef {
        log: orcel_audit::ORCELD_LOG.to_owned(),
        digest: file_id.clone(),
        file_id,
        seq: 0,
    })
}

/// After a confirmed anchor reset: opens the new first chain file at
/// `chain`, naming the reset record from `status` (the service's
/// `AnchorStatus` answer). Never keeps a file found on disk: whatever is at
/// the chain path (an earlier run's file included) is moved aside and a
/// fresh file opens, whose opening the CLI then anchors.
pub fn open_reset_chain(chain: &std::path::Path, status: &Value) -> Result<Value, LifecycleError> {
    let reset = &status["reset"];
    if reset["event_digest"].as_str().is_none() {
        return Err(LifecycleError::state(
            "the authority service reports no anchor reset for this log",
        ));
    }
    let opened = orcel_audit::open_after_reset(chain, orcel_audit::ORCELD_LOG, reset.clone())
        .map_err(|error| LifecycleError::state(error.to_string()))?;
    Ok(serde_json::json!({
        "chain": chain.display().to_string(),
        "new_file_id": opened.file_id,
        "abandoned_file_kept_as": opened.moved_to,
        "reset": reset,
    }))
}

/// The active leases of this user and logon session, as the service lists
/// them.
pub fn active_leases(client: &AuthorityClient) -> Result<Vec<SignedLease>, LifecycleError> {
    let listed = client.list().map_err(authority)?;
    Ok(listed["leases"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|entry| entry["state"].as_str() == Some("active"))
        .filter_map(|entry| serde_json::from_value(entry["lease"].clone()).ok())
        .collect())
}

/// The Windows Hello key credential (Windows only).
#[cfg(windows)]
pub mod hello {
    use super::{EnrollKey, HelloSigner};
    use orcel_approval::key_credential::{self, HelloKey};

    pub struct Hello(pub HelloKey);

    impl HelloSigner for Hello {
        fn sign(&self, challenge: &[u8]) -> Result<Vec<u8>, String> {
            self.0.sign(challenge)
        }
    }

    impl EnrollKey for Hello {
        fn public_key_spki(&self) -> Result<Vec<u8>, String> {
            self.0.public_key_spki()
        }

        fn attestation(&self) -> Result<(Vec<u8>, Vec<u8>), String> {
            self.0.attestation()
        }
    }

    /// Every name a key of ours may have in the Hello container.
    fn names() -> impl Iterator<Item = &'static str> {
        key_credential::KEY_SLOTS
            .into_iter()
            .chain([key_credential::LEGACY_KEY_NAME])
    }

    /// The slot holding the key whose fingerprint the service has enrolled
    /// (opening needs no prompt).
    pub fn open_enrolled(fingerprint: &str) -> Result<(Hello, &'static str), String> {
        for name in names() {
            if let Ok(key) = key_credential::open(name) {
                if key
                    .public_key_spki()
                    .is_ok_and(|spki| super::fingerprint(&spki) == fingerprint)
                {
                    return Ok((Hello(key), name));
                }
            }
        }
        Err("no Windows Hello key of this account matches the enrolled fingerprint".to_owned())
    }

    /// Review F6: a new key in the slot that does NOT hold the enrolled key
    /// (Hello prompt), so the enrolled key stays until the service enrolled
    /// the new one after the box's Yes.
    pub fn create_beside(
        enrolled: Option<&str>,
        replace: bool,
    ) -> Result<(Hello, &'static str), String> {
        let active =
            enrolled.and_then(|fingerprint| open_enrolled(fingerprint).ok().map(|(_, name)| name));
        let slot = plan_new_slot(enrolled.is_some(), active, replace)?;
        key_credential::create(slot, true).map(|key| (Hello(key), slot))
    }

    /// Review re-verify item 4: with a key enrolled at the service but no
    /// slot holding it, a new key is created only under `--replace` (the
    /// enrolled key is gone from Windows Hello, or another slot layout holds
    /// it); otherwise nothing is touched.
    pub fn plan_new_slot(
        enrolled: bool,
        active: Option<&str>,
        replace: bool,
    ) -> Result<&'static str, String> {
        if enrolled && active.is_none() && !replace {
            return Err(
                "a key is enrolled but no Orcel Authority key in Windows Hello matches it; nothing was created (use --replace to enroll a new one)"
                    .to_owned(),
            );
        }
        Ok(new_key_slot(active))
    }

    /// The slot a new key goes into: never the one holding the enrolled key.
    pub fn new_key_slot(active: Option<&str>) -> &'static str {
        key_credential::KEY_SLOTS
            .into_iter()
            .find(|name| Some(*name) != active)
            .unwrap_or(key_credential::KEY_SLOTS[0])
    }

    /// Removes every key of ours except `keep` (after a confirmed
    /// enrollment), or all of them (after a confirmed reset).
    pub fn delete_others(keep: Option<&str>) -> usize {
        names()
            .filter(|name| Some(*name) != keep)
            .filter(|name| key_credential::delete(name).is_ok())
            .count()
    }
    /// Whether this process runs elevated (observed from its own token; the
    /// service checks the same on the pipe).
    pub fn this_process_is_elevated() -> bool {
        // SAFETY: the pseudo handle of this process needs no closing.
        let process = unsafe { windows_sys::Win32::System::Threading::GetCurrentProcess() };
        orcel_authority::win::identity::open_process_token(process)
            .map(|token| orcel_authority::win::identity::token_elevated(&token))
            .unwrap_or(false)
    }

    #[cfg(test)]
    mod tests {
        use super::new_key_slot;
        use orcel_approval::key_credential::{KEY_SLOTS, LEGACY_KEY_NAME};

        /// Review F6: re-enrollment never writes the enrolled key's slot.
        #[test]
        fn sg132_a_new_key_never_takes_the_enrolled_slot() {
            assert_eq!(new_key_slot(None), KEY_SLOTS[0]);
            assert_eq!(new_key_slot(Some(KEY_SLOTS[0])), KEY_SLOTS[1]);
            assert_eq!(new_key_slot(Some(KEY_SLOTS[1])), KEY_SLOTS[0]);
            assert_eq!(new_key_slot(Some(LEGACY_KEY_NAME)), KEY_SLOTS[0]);
            assert_ne!(KEY_SLOTS[0], KEY_SLOTS[1]);
            // Enrolled but no slot matches: refused unless --replace.
            assert!(super::plan_new_slot(true, None, false).is_err());
            assert_eq!(super::plan_new_slot(true, None, true), Ok(KEY_SLOTS[0]));
            assert_eq!(
                super::plan_new_slot(true, Some(KEY_SLOTS[0]), true),
                Ok(KEY_SLOTS[1])
            );
            assert_eq!(super::plan_new_slot(false, None, false), Ok(KEY_SLOTS[0]));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// WP1-03: after a confirmed anchor reset the CLI keeps the abandoned
    /// chain and opens a first file naming the reset record, which the
    /// verifier reports as reset_by_owner; without a reported reset it
    /// opens nothing.
    #[test]
    fn wp103_a_confirmed_anchor_reset_opens_a_visible_first_chain_file() -> Result<(), String> {
        let dir = std::env::temp_dir().join(format!(
            "orcel-lifecycle-anchor-reset-{}-{}",
            std::process::id(),
            orcel_authority::now_ms()
        ));
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let chain = dir.join("audit-chain.jsonl");
        std::fs::write(&chain, "{\"broken\":true}\n").map_err(|e| e.to_string())?;
        let refused = open_reset_chain(&chain, &serde_json::json!({"held": null}));
        assert!(refused.is_err());
        let status = serde_json::json!({
            "held": null,
            "reset": {"event_digest": "e".repeat(64), "authority_seq": 12},
        });
        let opened = open_reset_chain(&chain, &status).map_err(|e| e.to_string())?;
        let kept = opened["abandoned_file_kept_as"]
            .as_str()
            .ok_or("the abandoned file is kept")?;
        assert_eq!(
            std::fs::read_to_string(dir.join(kept)).map_err(|e| e.to_string())?,
            "{\"broken\":true}\n"
        );
        let report = orcel_audit::verify_file(&chain).map_err(|e| e.to_string())?;
        assert_eq!(report.verdict, orcel_audit::Verdict::ResetByOwner);
        assert_eq!(
            opening_anchor(&chain).map_err(|e| e.to_string())?.digest,
            opened["new_file_id"].as_str().unwrap_or_default()
        );
        // Resumed (the service still reports the same reset): the file found
        // on disk is never kept, even the one this reset opened; it is moved
        // aside and a fresh file opens.
        let again = open_reset_chain(&chain, &status).map_err(|e| e.to_string())?;
        assert_ne!(again["new_file_id"], opened["new_file_id"]);
        let moved = again["abandoned_file_kept_as"]
            .as_str()
            .ok_or("the earlier file is kept aside")?;
        assert!(dir.join(moved).is_file());
        assert_eq!(
            orcel_audit::verify_file(&chain)
                .map_err(|e| e.to_string())?
                .verdict,
            orcel_audit::Verdict::ResetByOwner
        );
        assert_eq!(
            report
                .reset_by_owner
                .as_ref()
                .map(|reset| reset["event_digest"].clone()),
            Some(serde_json::Value::from("e".repeat(64)))
        );
        let _ = std::fs::remove_dir_all(dir);
        Ok(())
    }
    #[test]
    fn standing_grant_requests_are_checked_as_the_service_checks_them() {
        let client = format!("cl-{}", "ab".repeat(16));
        let standing = |operations: &str, folders: &[&str], programs: Option<Vec<&str>>| {
            Ok::<_, LifecycleError>(StandingScope {
                executors: vec![ExecutorClass::ShellProcess],
                operations: parse_operations(operations)?,
                roots: folders.iter().map(|f| (*f).to_owned()).collect(),
                origins: Vec::new(),
                commands: programs
                    .unwrap_or_default()
                    .into_iter()
                    .map(|path| PinnedProgram {
                        path: path.to_owned(),
                        sha256: "ab".repeat(32),
                        identity: "1-2".to_owned(),
                    })
                    .collect(),
                minutes: None,
            })
        };
        let roots = vec![r"D:\work".to_owned()];
        // Nothing a standing approval covers can be granted today (review of
        // #847): Git changes always ask, and `run` is refused under a lease
        // that writes its folders without a prompt.
        for git in ["git_add", "git_unstage", "git_commit", "git_branch_create"] {
            assert!(parse_operations(git).is_err(), "{git}");
        }
        assert!(parse_operations("run").is_ok());
        // Unknown operations, folders outside the roots, an unidentified
        // client and Admin are refused before anything is sent.
        assert!(parse_operations("run,delete").is_err());
        let tool = || Some(vec![r"D:\work\repo\tool.exe"]);
        let outside = standing("run", &[r"E:\elsewhere"], tool()).and_then(|scope| {
            standing_request(client.clone(), "b".into(), roots.clone(), 30, scope)
        });
        assert!(outside.is_err());
        let unidentified = standing("run", &[r"D:\work\repo"], tool()).and_then(|scope| {
            standing_request("orcel-owner".into(), "b".into(), roots.clone(), 30, scope)
        });
        assert!(unidentified.is_err());
        let admin = standing("run", &[r"D:\work\repo"], tool()).and_then(|mut scope| {
            scope.executors = vec![ExecutorClass::Admin];
            standing_request(client.clone(), "b".into(), roots.clone(), 30, scope)
        });
        assert!(admin.is_err());
        // Review of #844: a run needs pinned programs, and a program that
        // cannot be read cannot be pinned.
        let any_program = standing("run", &[r"D:\work\repo"], None).and_then(|scope| {
            standing_request(client.clone(), "b".into(), roots.clone(), 30, scope)
        });
        assert!(any_program.is_err());
        // Review of #847: nor a pinned one, under a lease that writes its
        // folder without a prompt.
        let pinned = standing(
            "run",
            &[r"D:\work\repo"],
            Some(vec![r"D:\work\repo\tool.exe"]),
        )
        .and_then(|scope| standing_request(client.clone(), "b".into(), roots.clone(), 30, scope));
        assert!(pinned.err().is_some_and(|error| error
            .to_string()
            .contains("each run keeps its own approval")));
        assert!(pin_programs(&[r"Z:\no\such\tool.exe".to_owned()]).is_err());
    }

    #[test]
    fn sg132_desktop_grants_default_to_the_narrow_scope_and_widen_explicitly() {
        assert_eq!(desktop_scope(None, Vec::new(), false).ok(), Some(None));
        let widened = desktop_scope(None, vec!["D:\\work".to_owned()], true);
        let Ok(Some(LeaseScope::DesktopFullUser {
            executors, shells, ..
        })) = widened
        else {
            assert!(widened.is_ok(), "{widened:?}");
            return;
        };
        assert!(shells);
        assert!(executors.contains(&ExecutorClass::Filesystem));
        assert!(executors.contains(&ExecutorClass::ShellProcess));
        assert!(executors.contains(&ExecutorClass::DesktopInput));
        let admin = parse_executors("admin");
        assert!(admin.is_err() || desktop_scope(admin.ok(), Vec::new(), false).is_err());
        assert!(desktop_scope(None, vec!["relative\\path".to_owned()], false).is_err());
        assert!(parse_executors("desktop_input,nope").is_err());
    }

    #[test]
    fn sg132_browser_grants_are_one_session_exact_origins_routine_families() {
        let session = "bs-0123456789abcdef-1-0001020304050607".to_owned();
        let client = format!("cl-{}", "ab".repeat(16));
        let one = vec!["https://fixture.test".to_owned()];
        let routine = parse_families("navigate,click,type,select,tabs");
        assert!(routine.is_ok());
        let routine = routine.unwrap_or_default();
        assert!(browser_scope(
            session.clone(),
            client.clone(),
            one.clone(),
            routine.clone(),
            None
        )
        .is_ok());
        for family in ["scroll", "read", "download"] {
            let families = parse_families(family).unwrap_or_default();
            assert!(
                browser_scope(session.clone(), client.clone(), one.clone(), families, None)
                    .is_err(),
                "{family}"
            );
        }
        let seventeen: Vec<String> = (0..17).map(|n| format!("https://h{n}.test")).collect();
        assert!(browser_scope(
            session.clone(),
            client.clone(),
            seventeen,
            routine.clone(),
            None
        )
        .is_err());
        for bad in [
            "http://fixture.test",
            "https://*.fixture.test",
            "https://fixture.test/x",
        ] {
            assert!(
                browser_scope(
                    session.clone(),
                    client.clone(),
                    vec![bad.to_owned()],
                    routine.clone(),
                    None
                )
                .is_err(),
                "{bad}"
            );
        }
        assert!(browser_scope(
            "bs-1".to_owned(),
            client.clone(),
            one.clone(),
            routine.clone(),
            None
        )
        .is_err());
        assert!(browser_scope(session, "client".to_owned(), one, routine, None).is_err());
        assert!(parse_families("submit").is_err());
    }

    #[test]
    fn sg132_the_fingerprint_matches_the_service_rendering() {
        let spki = b"spki bytes";
        let shown = fingerprint(spki);
        assert_eq!(shown.split(' ').count(), 16);
        assert_eq!(shown.replace(' ', ""), sha256_hex(spki));
    }
}
