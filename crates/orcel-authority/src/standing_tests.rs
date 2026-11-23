//! WP1-14 (spec 4.15; SG132_SLICE10.md): standing approvals in the
//! authority core, with the core tests' doubles. `cargo test -p
//! orcel-authority standing_` runs them. The indicator heartbeat (WP1-12)
//! is stood in for by `indicator_heartbeat_for_test`; without it every
//! standing request fails closed.

use super::*;
use crate::core::standing::{
    pin_program, PinnedProgram, StandingApproval, StandingScope, INDICATOR_HEARTBEAT_MS,
};
use crate::protocol::StandingClaim;

const TASK: &str = "build the repo";
const REPO: &str = r"C:\work\repo";
const TOOL: &str = r"C:\work\repo\tool.exe";

/// A program pinned at grant (a fixed SHA-256 and file identity).
fn pin(path: &str) -> PinnedProgram {
    PinnedProgram {
        path: path.to_owned(),
        sha256: "ab".repeat(32),
        identity: "0000000a-0000000000000001".to_owned(),
    }
}

fn client_ref() -> String {
    format!("cl-{}", "a".repeat(32))
}

fn lease_scope() -> LeaseScope {
    LeaseScope::DesktopFullUser {
        executors: vec![ExecutorClass::Filesystem, ExecutorClass::ShellProcess],
        roots: vec![r"C:\work".to_owned()],
        shells: true,
    }
}

fn standing_scope() -> StandingScope {
    StandingScope {
        executors: vec![ExecutorClass::ShellProcess],
        operations: vec!["run".to_owned(), "git_commit".to_owned()],
        roots: vec![REPO.to_owned()],
        origins: Vec::new(),
        commands: vec![pin(TOOL)],
        minutes: None,
    }
}

fn standing_begin_with(scope: LeaseScope, principal: &str, standing: StandingScope) -> Request {
    Request::StandingBegin {
        origin: ClaimedOrigin::OwnerCli,
        scope,
        minutes: None,
        principal_id: principal.to_owned(),
        task: TASK.to_owned(),
        standing,
    }
}

fn standing_begin(standing: StandingScope) -> Request {
    standing_begin_with(lease_scope(), &client_ref(), standing)
}

/// The whole gate: a live indicator, the intent, the observed unlock, Yes
/// in the service's box, then the Hello signature over its challenge.
/// Returns the lease, the standing approval and the confirmation text.
fn grant_standing(
    core: &mut AuthorityCore,
    standing: StandingScope,
) -> Result<(SignedLease, StandingApproval, String), String> {
    core.indicator_heartbeat_for_test(&owner());
    let begun = ok(core.handle(&owner(), standing_begin(standing)))?;
    let id = str_of(&begun, "intent_id")?;
    let one_time = str_of(&begun, "code")?;
    let (challenge, text) = confirm_yes(core, &owner(), &id)?;
    let done = ok(core.handle(
        &owner(),
        Request::StandingComplete {
            intent_id: id,
            code: one_time,
            signature_hex: presence_signature(SPKI, &challenge),
        },
    ))?;
    let lease = serde_json::from_value(done["lease"].clone()).map_err(|e| e.to_string())?;
    let standing = serde_json::from_value(done["standing"].clone()).map_err(|e| e.to_string())?;
    Ok((lease, standing, text))
}

fn run_claims(program: &str) -> AuthorizeClaims {
    AuthorizeClaims {
        request_id: "req-s".to_owned(),
        capability: "fc.process".to_owned(),
        operation: "run".to_owned(),
        principal_id: client_ref(),
        task: TASK.to_owned(),
        action_digest: sha256_hex(program.as_bytes()),
        origin: None,
        paths: Some(vec![REPO.to_owned(), program.to_owned()]),
    }
}

fn git_claims(operation: &str, repository: &str) -> AuthorizeClaims {
    AuthorizeClaims {
        capability: "fc.git".to_owned(),
        operation: operation.to_owned(),
        paths: Some(vec![repository.to_owned()]),
        ..run_claims(TOOL)
    }
}

fn covered(
    core: &mut AuthorityCore,
    lease: &SignedLease,
    executor: ExecutorClass,
    claims: AuthorizeClaims,
    standing_id: &str,
    program: Option<&str>,
) -> Result<Value, AuthorityError> {
    core.handle(
        &orceld(),
        Request::Authorize {
            lease_id: lease.body.lease_id.clone(),
            executor,
            claims,
            job_ack: crate::core::dispatch_jobs::executor_runs_in_job(executor),
            standing: Some(StandingClaim {
                standing_id: standing_id.to_owned(),
                program: program.map(pin),
            }),
        },
    )
}

/// The caller's standing approvals as `List` reports them.
fn listed(core: &mut AuthorityCore, caller: &CallerFacts) -> Result<Vec<Value>, String> {
    let list = ok(core.handle(caller, Request::List))?;
    Ok(list["standing"].as_array().cloned().unwrap_or_default())
}

fn audit_text(dir: &Path) -> Result<String, String> {
    std::fs::read_to_string(dir.join(crate::core::AUDIT_FILE)).map_err(|e| e.to_string())
}

#[test]
fn standing_without_a_live_indicator_fails_closed() -> Result<(), String> {
    let dir = temp_dir("standing-indicator")?;
    let events = Events::default();
    let mut core = open_enrolled(&dir, &events)?;
    // No heartbeat at all: nothing is recorded.
    assert_eq!(
        code(core.handle(&owner(), standing_begin(standing_scope()))),
        Some(FailureCode::IndicatorUnavailable)
    );
    let status = ok(core.handle(&owner(), Request::Status))?;
    assert_eq!(status["standing_approvals"]["indicator_alive"], false);
    // A stale heartbeat is no heartbeat.
    core.indicator_heartbeat_for_test(&owner());
    advance(INDICATOR_HEARTBEAT_MS);
    assert_eq!(
        code(core.handle(&owner(), standing_begin(standing_scope()))),
        Some(FailureCode::IndicatorUnavailable)
    );
    assert!(core.sessions_awaiting_unlock().is_empty());
    // Issued while the indicator lived; once it is gone the approval is
    // listed as not in effect and Authorize refuses it.
    let (lease, standing, _) = grant_standing(&mut core, standing_scope())?;
    assert_eq!(listed(&mut core, &orceld())?[0]["in_effect"], true);
    advance(INDICATOR_HEARTBEAT_MS);
    assert_eq!(listed(&mut core, &orceld())?[0]["in_effect"], false);
    assert_eq!(
        code(covered(
            &mut core,
            &lease,
            ExecutorClass::ShellProcess,
            run_claims(TOOL),
            &standing.id,
            Some(TOOL)
        )),
        Some(FailureCode::IndicatorUnavailable)
    );
    // The indicator gone between the box and Hello: nothing is issued.
    ok(core.handle(&owner(), Request::Stop))?;
    core.indicator_heartbeat_for_test(&owner());
    let begun = ok(core.handle(&owner(), standing_begin(standing_scope())))?;
    let id = str_of(&begun, "intent_id")?;
    let (challenge, _) = confirm_yes(&mut core, &owner(), &id)?;
    advance(INDICATOR_HEARTBEAT_MS);
    let refused = core.handle(
        &owner(),
        Request::StandingComplete {
            intent_id: id,
            code: str_of(&begun, "code")?,
            signature_hex: presence_signature(SPKI, &challenge),
        },
    );
    assert_eq!(code(refused), Some(FailureCode::IndicatorUnavailable));
    let list = ok(core.handle(&owner(), Request::List))?;
    assert!(!list["leases"]
        .as_array()
        .ok_or("leases")?
        .iter()
        .any(|entry| entry["state"] == "active"));
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn standing_is_issued_with_its_lease_through_the_owner_gate() -> Result<(), String> {
    let dir = temp_dir("standing-gate")?;
    let events = Events::default();
    let mut core = open_enrolled(&dir, &events)?;
    core.indicator_heartbeat_for_test(&owner());
    // Not the owner CLI, orceld, or a claimed agent origin: refused.
    for caller in [other_process(), orceld()] {
        core.indicator_heartbeat_for_test(&caller);
        assert_eq!(
            code(core.handle(&caller, standing_begin(standing_scope()))),
            Some(FailureCode::CapabilityDenied)
        );
    }
    let agent = Request::StandingBegin {
        origin: ClaimedOrigin::Agent,
        scope: lease_scope(),
        minutes: None,
        principal_id: client_ref(),
        task: TASK.to_owned(),
        standing: standing_scope(),
    };
    assert_eq!(
        code(core.handle(&owner(), agent)),
        Some(FailureCode::CapabilityDenied)
    );
    // The intent waits for the observed unlock like a grant's; the box
    // shows the lease and the standing approval's client, task, operations,
    // folders, programs and expiry.
    let begun = ok(core.handle(&owner(), standing_begin(standing_scope())))?;
    let id = str_of(&begun, "intent_id")?;
    let one_time = str_of(&begun, "code")?;
    let (challenge, text) = confirm_yes(&mut core, &owner(), &id)?;
    for shown in [
        "STANDING APPROVAL",
        &client_ref(),
        TASK,
        "operations [run, git_commit]",
        REPO,
        TOOL,
        "Standing approval expires: 30 minutes",
        &one_time,
    ] {
        assert!(text.contains(shown), "{shown} missing from {text}");
    }
    // A grant's completion does not complete it (and keeps it).
    assert_eq!(
        code(core.handle(&owner(), presence(&id, &one_time, &challenge))),
        Some(FailureCode::InvalidRequest)
    );
    let done = ok(core.handle(
        &owner(),
        Request::StandingComplete {
            intent_id: id,
            code: one_time,
            signature_hex: presence_signature(SPKI, &challenge),
        },
    ))?;
    let lease: SignedLease =
        serde_json::from_value(done["lease"].clone()).map_err(|e| e.to_string())?;
    let standing: StandingApproval =
        serde_json::from_value(done["standing"].clone()).map_err(|e| e.to_string())?;
    assert_eq!(standing.lease_id, lease.body.lease_id);
    assert_eq!(standing.principal_id, client_ref());
    assert_eq!(standing.task, TASK);
    assert!(standing.id.starts_with("sa-") && standing.id.len() == 35);
    assert!(standing.expires_at_ms <= lease.body.expires_at_ms);
    assert!(!standing.executors.contains(&ExecutorClass::Admin));
    let granted = events.with_id(crate::EVENT_GRANTED_SCOPE);
    assert!(granted
        .iter()
        .any(|entry| entry.contains("orcel-standing/1|") && entry.contains(&standing.id)));
    assert!(audit_text(&dir)?.contains("\"decision\":\"issued\""));
    // While the lease is active nothing more is granted, standing or not.
    core.indicator_heartbeat_for_test(&owner());
    assert_eq!(
        code(core.handle(&owner(), standing_begin(standing_scope()))),
        Some(FailureCode::CapabilityDenied)
    );
    // A standing completion does not complete a plain grant.
    ok(core.handle(&owner(), Request::Stop))?;
    let begun = ok(core.handle(&owner(), grant_begin(None)))?;
    let id = str_of(&begun, "intent_id")?;
    let (challenge, _) = confirm_yes(&mut core, &owner(), &id)?;
    let refused = core.handle(
        &owner(),
        Request::StandingComplete {
            intent_id: id,
            code: str_of(&begun, "code")?,
            signature_hex: presence_signature(SPKI, &challenge),
        },
    );
    assert_eq!(code(refused), Some(FailureCode::InvalidRequest));
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn standing_admin_remote_and_browser_are_refused() -> Result<(), String> {
    let dir = temp_dir("standing-admin")?;
    let events = Events::default();
    let mut core = open_enrolled(&dir, &events)?;
    core.indicator_heartbeat_for_test(&owner());
    let with = |change: &dyn Fn(&mut StandingScope)| {
        let mut scope = standing_scope();
        change(&mut scope);
        standing_begin(scope)
    };
    for (request, expected) in [
        (
            with(&|s| s.executors = vec![ExecutorClass::Admin]),
            FailureCode::CapabilityDenied,
        ),
        (
            with(&|s| s.executors.push(ExecutorClass::Admin)),
            FailureCode::CapabilityDenied,
        ),
        (
            with(&|s| s.executors = vec![ExecutorClass::Remote]),
            FailureCode::CapabilityDenied,
        ),
        (
            with(&|s| s.origins = vec!["https://example.com".to_owned()]),
            FailureCode::CapabilityDenied,
        ),
        (
            with(&|s| s.executors = vec![ExecutorClass::DesktopInput]),
            FailureCode::InvalidRequest,
        ),
    ] {
        assert_eq!(code(core.handle(&owner(), request)), Some(expected));
    }
    let browser = LeaseScope::BrowserFullAccess {
        client_ref: client_ref(),
        session_id: "bs-0123456789abcdef-1-0001020304050607".to_owned(),
        origins: vec!["https://example.com".to_owned()],
        families: vec![crate::lease::BrowserFamily::Click],
        task: None,
    };
    assert_eq!(
        code(core.handle(
            &owner(),
            standing_begin_with(browser, &client_ref(), standing_scope())
        )),
        Some(FailureCode::CapabilityDenied)
    );
    // At Authorize, Admin and Remote are refused whatever is named.
    let (lease, standing, _) = grant_standing(&mut core, standing_scope())?;
    for executor in [ExecutorClass::Admin, ExecutorClass::Remote] {
        assert_eq!(
            code(covered(
                &mut core,
                &lease,
                executor,
                run_claims(TOOL),
                &standing.id,
                Some(TOOL)
            )),
            Some(FailureCode::CapabilityDenied),
            "{executor:?}"
        );
    }
    assert!(core.sessions_awaiting_unlock().is_empty());
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn standing_scope_must_fit_its_lease_and_one_identified_client() -> Result<(), String> {
    let dir = temp_dir("standing-fit")?;
    let events = Events::default();
    let mut core = open_enrolled(&dir, &events)?;
    core.indicator_heartbeat_for_test(&owner());
    // A free label is not an identified client.
    assert_eq!(
        code(core.handle(
            &owner(),
            standing_begin_with(lease_scope(), "orcel-owner", standing_scope())
        )),
        Some(FailureCode::InvalidRequest)
    );
    let refused = |change: &dyn Fn(&mut StandingScope)| {
        let mut scope = standing_scope();
        change(&mut scope);
        scope.validate(&lease_scope(), &client_ref(), 30).err()
    };
    let codes = [
        refused(&|s| s.roots = vec![r"C:\elsewhere".to_owned()]),
        refused(&|s| s.commands = vec![pin(r"C:\work\other\tool.exe")]),
        refused(&|s| s.operations = vec!["git_commit".to_owned()]),
        refused(&|s| s.operations = vec!["write_text".to_owned()]),
        refused(&|s| s.operations.push("run".to_owned())),
        refused(&|s| s.minutes = Some(31)),
        refused(&|s| s.minutes = Some(0)),
        refused(&|s| s.roots = Vec::new()),
        refused(&|s| s.commands = vec![pin(r"C:\work\repo\script.ps1")]),
        refused(&|s| s.executors = Vec::new()),
        // Review of #844: a run never covers "any program in the folders",
        // and a pin must be a real SHA-256 and file identity.
        refused(&|s| s.commands = Vec::new()),
        refused(&|s| s.commands[0].sha256 = "x".repeat(64)),
        refused(&|s| s.commands[0].identity = String::new()),
    ];
    for (index, error) in codes.iter().enumerate() {
        assert!(error.is_some(), "case {index} was accepted");
    }
    assert_eq!(
        codes[0].as_ref().map(|e| e.code.clone()),
        Some(FailureCode::CapabilityDenied)
    );
    // A lease without shells cannot carry one.
    let no_shells = LeaseScope::DesktopFullUser {
        executors: vec![ExecutorClass::Filesystem],
        roots: vec![r"C:\work".to_owned()],
        shells: false,
    };
    assert!(standing_scope()
        .validate(&no_shells, &client_ref(), 30)
        .is_err());
    assert!(standing_scope()
        .validate(&lease_scope(), &client_ref(), 30)
        .is_ok());
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn standing_covers_only_its_scope_client_and_task() -> Result<(), String> {
    let dir = temp_dir("standing-cover")?;
    let events = Events::default();
    let mut core = open_enrolled(&dir, &events)?;
    let (lease, standing, _) = grant_standing(&mut core, standing_scope())?;
    // Covered: the named program in its folder, and a commit there.
    let run = ok(covered(
        &mut core,
        &lease,
        ExecutorClass::ShellProcess,
        run_claims(TOOL),
        &standing.id,
        Some(TOOL),
    ))?;
    assert_eq!(run["standing_id"], Value::String(standing.id.clone()));
    let commit = ok(covered(
        &mut core,
        &lease,
        ExecutorClass::ShellProcess,
        git_claims("git_commit", REPO),
        &standing.id,
        None,
    ))?;
    assert_eq!(commit["standing_id"], Value::String(standing.id.clone()));
    assert!(audit_text(&dir)?.contains(&format!("\"standing_id\":\"{}\"", standing.id)));
    // Not covered: another program, a folder outside, another operation, a
    // capability that does not match, another client, another task, a
    // browser origin, the filesystem executor.
    let other_program = r"C:\work\repo\other.exe";
    let outside = r"C:\work\elsewhere";
    let mut other_client = run_claims(TOOL);
    other_client.principal_id = format!("cl-{}", "b".repeat(32));
    let mut other_task = run_claims(TOOL);
    other_task.task = "another task".to_owned();
    let mut wrong_capability = run_claims(TOOL);
    wrong_capability.capability = "fc.git".to_owned();
    let mut with_origin = run_claims(TOOL);
    with_origin.origin = Some("https://example.com".to_owned());
    let cases: Vec<(ExecutorClass, AuthorizeClaims, Option<&str>)> = vec![
        (
            ExecutorClass::ShellProcess,
            run_claims(other_program),
            Some(other_program),
        ),
        (
            ExecutorClass::ShellProcess,
            git_claims("git_commit", outside),
            None,
        ),
        (
            ExecutorClass::ShellProcess,
            git_claims("git_add", REPO),
            None,
        ),
        (ExecutorClass::ShellProcess, wrong_capability, Some(TOOL)),
        (ExecutorClass::ShellProcess, other_client, Some(TOOL)),
        (ExecutorClass::ShellProcess, other_task, Some(TOOL)),
        (ExecutorClass::ShellProcess, with_origin, Some(TOOL)),
        (ExecutorClass::ShellProcess, run_claims(TOOL), None),
        (
            ExecutorClass::ShellProcess,
            git_claims("git_commit", REPO),
            Some(TOOL),
        ),
        (
            ExecutorClass::Filesystem,
            git_claims("git_commit", REPO),
            None,
        ),
    ];
    for (index, (executor, claims, program)) in cases.into_iter().enumerate() {
        let refused = covered(&mut core, &lease, executor, claims, &standing.id, program);
        assert!(refused.is_err(), "case {index} was covered");
    }
    // An id that is not the caller's covers nothing.
    assert_eq!(
        code(covered(
            &mut core,
            &lease,
            ExecutorClass::ShellProcess,
            run_claims(TOOL),
            &format!("sa-{}", "0".repeat(32)),
            Some(TOOL)
        )),
        Some(FailureCode::LeaseInvalid)
    );
    let mut stranger = orceld();
    stranger.logon_session_id = 0x7777;
    let foreign = core.handle(
        &stranger,
        Request::Authorize {
            lease_id: lease.body.lease_id.clone(),
            executor: ExecutorClass::ShellProcess,
            claims: run_claims(TOOL),
            job_ack: true,
            standing: Some(StandingClaim {
                standing_id: standing.id.clone(),
                program: Some(pin(TOOL)),
            }),
        },
    );
    assert_eq!(code(foreign), Some(FailureCode::LeaseInvalid));
    // Review of #844: the named program with other contents, or another
    // file at its path (replaced since the grant), is not covered.
    let mut rewritten = pin(TOOL);
    rewritten.sha256 = "cd".repeat(32);
    let mut replaced = pin(TOOL);
    replaced.identity = "0000000a-0000000000000002".to_owned();
    for changed in [rewritten, replaced] {
        let refused = core.handle(
            &orceld(),
            Request::Authorize {
                lease_id: lease.body.lease_id.clone(),
                executor: ExecutorClass::ShellProcess,
                claims: run_claims(TOOL),
                job_ack: true,
                standing: Some(StandingClaim {
                    standing_id: standing.id.clone(),
                    program: Some(changed),
                }),
            },
        );
        assert_eq!(code(refused), Some(FailureCode::CapabilityDenied));
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn standing_expiry_ends_it_and_the_lease_stays() -> Result<(), String> {
    let dir = temp_dir("standing-expiry")?;
    let events = Events::default();
    let mut core = open_enrolled(&dir, &events)?;
    let mut short = standing_scope();
    short.minutes = Some(5);
    let (lease, standing, text) = grant_standing(&mut core, short)?;
    assert!(text.contains("Standing approval expires: 5 minutes"));
    assert_eq!(standing.expires_at_ms, standing.issued_at_ms + 5 * 60_000);
    advance(5 * 60_000);
    core.tick().map_err(|e| e.to_string())?;
    core.indicator_heartbeat_for_test(&owner());
    assert_eq!(
        code(covered(
            &mut core,
            &lease,
            ExecutorClass::ShellProcess,
            run_claims(TOOL),
            &standing.id,
            Some(TOOL)
        )),
        Some(FailureCode::LeaseInvalid)
    );
    let entry = listed(&mut core, &orceld())?;
    assert_eq!(entry[0]["state"], "ended");
    assert_eq!(entry[0]["ended_by"], "expired");
    assert!(audit_text(&dir)?.contains("\"reason\":\"expired\""));
    // The lease itself still stands, and without a standing approval the
    // action keeps its own approval path (Authorize without one).
    let mut plain = run_claims(TOOL);
    plain.request_id = "req-plain".to_owned();
    ok(core.handle(
        &orceld(),
        Request::Authorize {
            lease_id: lease.body.lease_id.clone(),
            executor: ExecutorClass::ShellProcess,
            claims: plain,
            job_ack: true,
            standing: None,
        },
    ))?;
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn standing_stop_lock_revoke_and_epoch_end_it() -> Result<(), String> {
    let dir = temp_dir("standing-stop")?;
    let events = Events::default();
    let mut core = open_enrolled(&dir, &events)?;
    let ended_by = |core: &mut AuthorityCore| -> Result<Value, String> {
        let entries = listed(core, &owner())?;
        Ok(entries.last().ok_or("no standing")?["ended_by"].clone())
    };
    // Stop from any process of the session.
    let (lease, standing, _) = grant_standing(&mut core, standing_scope())?;
    ok(core.handle(&other_process(), Request::Stop))?;
    assert_eq!(ended_by(&mut core)?, "stopped");
    core.indicator_heartbeat_for_test(&owner());
    assert_eq!(
        code(covered(
            &mut core,
            &lease,
            ExecutorClass::ShellProcess,
            run_claims(TOOL),
            &standing.id,
            Some(TOOL)
        )),
        Some(FailureCode::LeaseInvalid)
    );
    // Session lock.
    grant_standing(&mut core, standing_scope())?;
    core.session_ended(1, "session_lock", true)
        .map_err(|e| e.to_string())?;
    assert_eq!(ended_by(&mut core)?, "stopped");
    // Revoking its lease.
    let (lease, _, _) = grant_standing(&mut core, standing_scope())?;
    ok(core.handle(
        &owner(),
        Request::Revoke {
            lease_id: lease.body.lease_id.clone(),
        },
    ))?;
    assert_eq!(ended_by(&mut core)?, "revoked");
    // Revoking the standing approval only: its lease stays.
    let (lease, standing, _) = grant_standing(&mut core, standing_scope())?;
    let mut stranger = owner();
    stranger.logon_session_id = 0x7777;
    assert_eq!(
        code(core.handle(
            &stranger,
            Request::StandingRevoke {
                standing_id: standing.id.clone(),
            }
        )),
        Some(FailureCode::LeaseInvalid)
    );
    let before = core.revocations();
    ok(core.handle(
        &other_process(),
        Request::StandingRevoke {
            standing_id: standing.id.clone(),
        },
    ))?;
    assert_eq!(core.revocations(), before + 1);
    assert_eq!(ended_by(&mut core)?, "revoked");
    assert_eq!(
        code(core.handle(
            &owner(),
            Request::StandingRevoke {
                standing_id: standing.id.clone(),
            }
        )),
        Some(FailureCode::LeaseInvalid)
    );
    ok(core.handle(
        &owner(),
        Request::Verify {
            lease_id: lease.body.lease_id.clone(),
        },
    ))?;
    // An epoch move (another session's Stop) ends it with its lease.
    ok(core.handle(
        &owner(),
        Request::Revoke {
            lease_id: lease.body.lease_id.clone(),
        },
    ))?;
    grant_standing(&mut core, standing_scope())?;
    ok(core.handle(&stranger, Request::Stop))?;
    assert_eq!(ended_by(&mut core)?, "epoch_moved");
    let audit = audit_text(&dir)?;
    for reason in ["stopped", "revoked", "epoch_moved"] {
        assert!(
            audit.contains(&format!("\"reason\":\"{reason}\"")),
            "{reason}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn standing_survives_a_restart_only_as_its_lease_does_and_needs_the_indicator_again(
) -> Result<(), String> {
    let dir = temp_dir("standing-restart")?;
    let events = Events::default();
    let (lease, standing) = {
        let mut core = open_enrolled(&dir, &events)?;
        let (lease, standing, _) = grant_standing(&mut core, standing_scope())?;
        core.shutdown().map_err(|e| e.to_string())?;
        (lease, standing)
    };
    let mut core = open(&dir, &events)?;
    let entries = listed(&mut core, &orceld())?;
    assert_eq!(entries[0]["state"], "active");
    assert_eq!(entries[0]["in_effect"], false);
    assert_eq!(
        code(covered(
            &mut core,
            &lease,
            ExecutorClass::ShellProcess,
            run_claims(TOOL),
            &standing.id,
            Some(TOOL)
        )),
        Some(FailureCode::IndicatorUnavailable)
    );
    // A state with no standing approval is written without the field, so an
    // older service still reads it.
    ok(core.handle(&owner(), Request::Stop))?;
    advance(31 * 60_000);
    core.tick().map_err(|e| e.to_string())?;
    let state =
        std::fs::read_to_string(dir.join(crate::core::STATE_FILE)).map_err(|e| e.to_string())?;
    assert!(state.contains("\"standing\""));
    let without: crate::core::PersistedState = serde_json::from_str(
        r#"{"contract":"orcel.authority-state/1","epoch":1,"revocations":0,"leases":[],"enrolled":[]}"#,
    )
    .map_err(|e| e.to_string())?;
    assert!(without.standing.is_empty());
    assert!(!serde_json::to_string(&without)
        .map_err(|e| e.to_string())?
        .contains("standing"));
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn standing_program_pins_bind_contents_and_file() -> Result<(), String> {
    let dir = temp_dir("standing-pin")?;
    let program = dir.join("tool.exe");
    std::fs::write(&program, b"first build").map_err(|e| e.to_string())?;
    let path = program.display().to_string();
    let first = pin_program(&path).map_err(|e| e.to_string())?;
    assert_eq!(first.sha256, sha256_hex(b"first build"));
    assert!(!first.identity.is_empty());
    assert_eq!(pin_program(&path).map_err(|e| e.to_string())?, first);
    // Rewritten in place: the same file, other contents.
    std::fs::write(&program, b"second build").map_err(|e| e.to_string())?;
    let rewritten = pin_program(&path).map_err(|e| e.to_string())?;
    assert_ne!(rewritten.sha256, first.sha256);
    assert!(!first.matches(&rewritten));
    // Replaced by another file with the first contents: another identity.
    let other = dir.join("other.exe");
    std::fs::write(&other, b"first build").map_err(|e| e.to_string())?;
    std::fs::remove_file(&program).map_err(|e| e.to_string())?;
    std::fs::rename(&other, &program).map_err(|e| e.to_string())?;
    let replaced = pin_program(&path).map_err(|e| e.to_string())?;
    assert_eq!(replaced.sha256, first.sha256);
    assert!(!first.matches(&replaced));
    assert!(pin_program(&dir.display().to_string()).is_err());
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
