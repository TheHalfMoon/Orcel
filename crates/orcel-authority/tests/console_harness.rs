//! SG-000132 slice 1: the pipe protocol end to end through
//! `orcel-authority --console`, under the current user with a temporary
//! state directory and a console pipe name. Nothing is installed and no
//! system setting changes.
//!
//! What these tests prove holds in both modes: the protocol, the server
//! verification every client does before sending, refusal of a pre-created
//! pipe name, the pipe's DACL shape (exact INTERACTIVE mask, protected),
//! issuance refusal for orceld and claimed MCP/agent/remote origins,
//! Authorize gated on the trusted orceld image, Stop moving the epoch, and
//! the audit chain. What holds only when installed as the service (state
//! unreadable by the user, a pipe owner no user process runs as, so no
//! second instance; observed session changes, so grants at all) is
//! documented in SG132_SLICE1.md and cannot be shown here.
#![cfg(windows)]

use orcel_authority::client::{AuthorityClient, Expectation};
use orcel_authority::protocol::{AuthorizeClaims, ClaimedOrigin, Request};
use orcel_contracts::{ExecutorClass, FailureCode};
use serde_json::Value;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

static NEXT: AtomicU32 = AtomicU32::new(0);

struct Harness {
    child: Child,
    stdin: Option<ChildStdin>,
    dir: PathBuf,
    expectation: Expectation,
}

impl Drop for Harness {
    fn drop(&mut self) {
        drop(self.stdin.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn unique(name: &str) -> String {
    format!(
        "t{}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed),
        name
    )
}

fn state_dir(suffix: &str) -> PathBuf {
    std::env::temp_dir().join(format!("orcel-authority-console-{suffix}"))
}

fn spawn(suffix: &str, dir: &Path, trust_this_test: bool) -> std::io::Result<Child> {
    spawn_with(suffix, dir, trust_this_test, &[])
}

fn spawn_with(
    suffix: &str,
    dir: &Path,
    trust_this_test: bool,
    extra: &[&std::ffi::OsStr],
) -> std::io::Result<Child> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_orcel-authority"));
    command
        .args(["--console", "--state-dir"])
        .arg(dir)
        .args(["--pipe-suffix", suffix])
        .args(extra);
    if trust_this_test {
        command
            .arg("--trusted-orceld")
            .arg(std::env::current_exe()?);
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
}

fn start(name: &str, trust_this_test: bool) -> Harness {
    start_with(name, trust_this_test, &[])
}

fn start_with(name: &str, trust_this_test: bool, extra: &[&std::ffi::OsStr]) -> Harness {
    let suffix = unique(name);
    let dir = state_dir(&suffix);
    let mut child =
        spawn_with(&suffix, &dir, trust_this_test, extra).expect("spawn the console harness");
    let stdout = child.stdout.take().expect("stdout");
    let mut line = String::new();
    BufReader::new(stdout)
        .read_line(&mut line)
        .expect("ready line");
    let ready: Value = match serde_json::from_str(line.trim()) {
        Ok(ready) => ready,
        Err(_) => {
            let _ = child.kill();
            let output = child.wait_with_output().ok();
            panic!(
                "the console harness did not start: {line:?} {:?}",
                output.map(|o| String::from_utf8_lossy(&o.stderr).into_owned())
            )
        }
    };
    assert_eq!(ready["ready"], Value::Bool(true));
    assert_eq!(ready["mode"], "console");
    let expectation = Expectation {
        pipe_name: ready["pipe"].as_str().expect("pipe").to_owned(),
        pid: ready["pid"].as_u64().expect("pid") as u32,
        owner_sid: ready["owner_sid"].as_str().expect("sid").to_owned(),
    };
    assert_eq!(expectation.pid, child.id());
    assert!(expectation
        .pipe_name
        .starts_with(orcel_authority::CONSOLE_PIPE_PREFIX));
    let stdin = child.stdin.take();
    Harness {
        child,
        stdin,
        dir,
        expectation,
    }
}

fn client(harness: &Harness) -> AuthorityClient {
    AuthorityClient::with_expectation(harness.expectation.clone())
}

fn code<T>(result: Result<T, orcel_authority::AuthorityError>) -> Option<FailureCode> {
    result.err().map(|error| error.code)
}

fn claims() -> AuthorizeClaims {
    AuthorizeClaims {
        request_id: "req-1".into(),
        capability: "desktop.input".into(),
        operation: "click".into(),
        principal_id: "mcp-client-1".into(),
        task: "a task".into(),
        action_digest: "0".repeat(64),
        origin: None,
        paths: None,
    }
}

#[test]
fn status_reports_console_mode_the_key_and_that_nothing_can_be_issued() {
    let harness = start("status", false);
    let status = client(&harness).status().expect("status");
    assert_eq!(status["protocol"], "orcel.authority-pipe/1");
    assert_eq!(status["mode"], "console");
    assert_eq!(status["can_issue"], Value::Bool(false));
    assert_eq!(status["signature_algorithm"], "ECDSA_P256_SHA256");
    let published =
        std::fs::read_to_string(harness.dir.join("public").join("lease-signing-key.json"))
            .expect("the public key is published");
    let published: Value = serde_json::from_str(&published).expect("json");
    assert_eq!(published["key_id"], status["key_id"]);
    assert_eq!(published["public_key_hex"], status["public_key_hex"]);
    // The private key file is DPAPI-wrapped, never the public blob or hex.
    let wrapped = std::fs::read(harness.dir.join("lease-signing.key")).expect("key file");
    let public_hex = status["public_key_hex"].as_str().expect("hex");
    assert!(!String::from_utf8_lossy(&wrapped).contains(public_hex));
}

#[test]
fn the_client_refuses_a_server_with_the_wrong_pid_or_owner_before_sending() {
    let harness = start("verify", false);
    let good = client(&harness);
    let epoch = good.status().expect("status")["epoch"]
        .as_u64()
        .expect("epoch");

    let mut wrong_pid = harness.expectation.clone();
    wrong_pid.pid = wrong_pid.pid.wrapping_add(4);
    let refused = AuthorityClient::with_expectation(wrong_pid).stop();
    assert_eq!(
        code(refused.clone()),
        Some(FailureCode::AuthorityUnavailable),
        "{refused:?}"
    );

    let mut wrong_owner = harness.expectation.clone();
    wrong_owner.owner_sid = "S-1-5-80-1-2-3-4-5".to_owned();
    let refused = AuthorityClient::with_expectation(wrong_owner).stop();
    assert_eq!(
        code(refused.clone()),
        Some(FailureCode::AuthorityUnavailable),
        "{refused:?}"
    );

    // Neither Stop reached the server: the epoch did not move.
    assert_eq!(
        good.status().expect("status")["epoch"].as_u64(),
        Some(epoch)
    );
    // A real Stop does move it.
    let stopped = good.stop().expect("stop");
    assert_eq!(stopped["epoch"].as_u64(), Some(epoch + 1));
}

#[test]
fn a_missing_service_fails_closed() {
    let expectation = Expectation {
        pipe_name: format!(
            "{}{}",
            orcel_authority::CONSOLE_PIPE_PREFIX,
            unique("absent")
        ),
        pid: 4,
        owner_sid: "S-1-5-18".to_owned(),
    };
    let client = AuthorityClient::with_expectation(expectation);
    assert_eq!(
        code(client.status()),
        Some(FailureCode::AuthorityUnavailable)
    );
    assert_eq!(
        code(client.verify_lease("al-0")),
        Some(FailureCode::AuthorityUnavailable)
    );
}

#[test]
fn a_pre_created_pipe_name_makes_the_authority_refuse_to_start() {
    let suffix = unique("squat");
    let name = format!("{}{suffix}", orcel_authority::CONSOLE_PIPE_PREFIX);
    let me = orcel_authority::win::current_process_sid().expect("sid");
    let squatter = orcel_authority::win::pipe::create_instance(&name, &me, true);
    assert!(
        squatter.is_ok(),
        "the test could not create the squatting pipe"
    );
    let dir = state_dir(&suffix);
    let output = spawn(&suffix, &dir, false)
        .expect("spawn")
        .wait_with_output()
        .expect("wait");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("already exists"), "{stderr}");
    drop(squatter);
}

#[test]
fn a_second_authority_on_the_same_name_refuses_to_start() {
    let harness = start("second", false);
    let suffix = harness
        .expectation
        .pipe_name
        .trim_start_matches(orcel_authority::CONSOLE_PIPE_PREFIX)
        .to_owned();
    let dir = state_dir(&format!("{suffix}-b"));
    let output = spawn(&suffix, &dir, false)
        .expect("spawn")
        .wait_with_output()
        .expect("wait");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("already exists"));
}

#[test]
fn the_live_pipe_grants_interactive_exactly_the_client_mask() {
    let harness = start("dacl", false);
    let server = orcel_authority::win::pipe::ServerExpectation {
        pipe_name: harness.expectation.pipe_name.clone(),
        pid: harness.expectation.pid,
        owner_sid: harness.expectation.owner_sid.clone(),
    };
    let pipe =
        orcel_authority::win::pipe::connect_verified(&server, std::time::Duration::from_secs(5))
            .expect("connect");
    let (owner, aces) = orcel_authority::win::pipe::pipe_security(pipe.raw()).expect("security");
    assert_eq!(owner, harness.expectation.owner_sid);
    let interactive: Vec<u32> = aces
        .iter()
        .filter(|(sid, _)| sid == "S-1-5-4")
        .map(|(_, mask)| *mask)
        .collect();
    assert_eq!(interactive, vec![orcel_authority::pipe_sddl::CLIENT_ACCESS]);
    assert!(
        aces.iter()
            .all(|(sid, mask)| sid == &owner
                || orcel_authority::pipe_sddl::client_mask_is_safe(*mask))
    );
    assert_eq!(aces.len(), 2, "only the owner and INTERACTIVE: {aces:?}");
}

#[test]
fn issuance_is_refused_to_orceld_and_to_claimed_agent_origins() {
    let harness = start("issue", true);
    let client = client(&harness);
    let status = client.status().expect("status");
    assert_eq!(status["caller_role"], "orceld");
    // This test process is the configured orceld image: never an issuer.
    let begin = client.call(&Request::GrantBegin {
        origin: ClaimedOrigin::OwnerCli,
        scope: None,
        minutes: None,
        principal_id: "p".into(),
        task: "t".into(),
    });
    assert_eq!(code(begin), Some(FailureCode::CapabilityDenied));

    let plain = start("issue-plain", false);
    let other = AuthorityClient::with_expectation(plain.expectation.clone());
    for origin in [
        ClaimedOrigin::Mcp,
        ClaimedOrigin::Agent,
        ClaimedOrigin::Remote,
        ClaimedOrigin::Orceld,
    ] {
        let begin = other.call(&Request::GrantBegin {
            origin,
            scope: None,
            minutes: None,
            principal_id: "p".into(),
            task: "t".into(),
        });
        assert_eq!(code(begin), Some(FailureCode::CapabilityDenied));
    }
    // Slice 2: enrollment needs an elevated caller of the installed
    // service; the console harness never enrolls, whoever asks and
    // whatever origin they claim, and a reset is refused the same way.
    for origin in [ClaimedOrigin::OwnerCli, ClaimedOrigin::Mcp] {
        let enroll = other.call(&Request::EnrollBegin {
            origin,
            public_key_spki_hex: "00".into(),
            attestation_hex: "00".into(),
            certificate_chain_hex: "00".into(),
            replace: false,
        });
        let error = enroll.expect_err("enrollment refused");
        assert_eq!(error.code, FailureCode::CapabilityDenied, "{error}");
        let reset = other.call(&Request::ResetEnrollment { origin });
        assert_eq!(
            reset.expect_err("reset refused").code,
            FailureCode::CapabilityDenied
        );
    }
    let status = other.status().expect("status");
    assert_eq!(status["enrollment_available"], Value::Bool(false));
    assert!(status["caller_elevated"].is_boolean());
    // Even the owner origin cannot complete a grant here: no key is
    // enrolled and console mode never observes an unlock.
    let begin = other.call(&Request::GrantBegin {
        origin: ClaimedOrigin::OwnerCli,
        scope: None,
        minutes: None,
        principal_id: "p".into(),
        task: "t".into(),
    });
    assert_eq!(code(begin), Some(FailureCode::CapabilityDenied));
}

#[test]
fn authorize_needs_the_trusted_orceld_image_and_a_live_lease() {
    let trusted = start("authz", true);
    let as_orceld = client(&trusted);
    let refused = as_orceld.authorize(
        "al-00000000000000000000000000000000",
        ExecutorClass::DesktopInput,
        claims(),
    );
    assert_eq!(code(refused), Some(FailureCode::LeaseInvalid));
    let admin = as_orceld.authorize(
        "al-00000000000000000000000000000000",
        ExecutorClass::Admin,
        claims(),
    );
    assert_eq!(code(admin), Some(FailureCode::CapabilityDenied));
    assert_eq!(
        code(as_orceld.verify_lease("al-00000000000000000000000000000000")),
        Some(FailureCode::LeaseInvalid)
    );

    let untrusted = start("authz-plain", false);
    let refused = client(&untrusted).authorize(
        "al-00000000000000000000000000000000",
        ExecutorClass::DesktopInput,
        claims(),
    );
    assert_eq!(code(refused), Some(FailureCode::CapabilityDenied));
}

/// WP1-10: the console runtime holds real, unnamed dispatch Job Objects; a
/// filesystem Authorize without a live lease makes none, and only orceld
/// asks about or reports an outcome, once, for an authorization it holds.
#[test]
fn wp110_dispatch_jobs_need_a_live_lease_and_outcomes_are_orcelds() {
    use orcel_authority::protocol::DispatchOutcome;
    let trusted = start("wp110", true);
    let as_orceld = client(&trusted);
    let status = as_orceld.status().expect("status");
    assert_eq!(status["job_objects"]["named"], Value::Bool(false));
    assert_eq!(status["job_objects"]["held"], 0);
    assert_eq!(status["job_objects"]["breakaway"], Value::Bool(false));
    let refused = as_orceld.authorize(
        "al-00000000000000000000000000000000",
        ExecutorClass::Filesystem,
        AuthorizeClaims {
            paths: Some(vec![r"C:\work\a.txt".into()]),
            ..claims()
        },
    );
    assert_eq!(code(refused), Some(FailureCode::LeaseInvalid));
    assert_eq!(
        as_orceld.status().expect("status")["job_objects"]["held"],
        0
    );
    let unknown = format!("az-{}", "0".repeat(32));
    assert_eq!(
        code(as_orceld.outcome(&unknown, DispatchOutcome::Succeeded, None)),
        Some(FailureCode::InvalidRequest)
    );
    assert_eq!(
        code(as_orceld.dispatch_active(&unknown)),
        Some(FailureCode::InvalidRequest)
    );
    let plain = start("wp110-plain", false);
    assert_eq!(
        code(client(&plain).outcome(&unknown, DispatchOutcome::Succeeded, None)),
        Some(FailureCode::CapabilityDenied)
    );
}

#[test]
fn malformed_frames_are_refused_and_the_audit_chain_verifies_after_shutdown() {
    use orcel_authority::protocol::{read_frame, write_frame, Response};
    let mut harness = start("audit", true);
    let server = orcel_authority::win::pipe::ServerExpectation {
        pipe_name: harness.expectation.pipe_name.clone(),
        pid: harness.expectation.pid,
        owner_sid: harness.expectation.owner_sid.clone(),
    };
    let mut pipe =
        orcel_authority::win::pipe::connect_verified(&server, std::time::Duration::from_secs(5))
            .expect("connect");
    write_frame(&mut pipe, br#"{"op":"heartbeat"}"#).expect("write");
    let answer: Response =
        serde_json::from_slice(&read_frame(&mut pipe).expect("read").expect("frame"))
            .expect("json");
    assert!(!answer.ok);
    assert_eq!(answer.code, Some(FailureCode::InvalidRequest));
    drop(pipe);
    client(&harness).stop().expect("stop");
    // Close stdin: the harness shuts down cleanly and anchors the chain.
    drop(harness.stdin.take());
    let status = harness.child.wait().expect("wait");
    assert!(status.success());
    let (next, _) = orcel_authority::audit::verify_file(&harness.dir.join("audit.jsonl"))
        .expect("chain verifies");
    assert!(next > 3);
    let audit = std::fs::read_to_string(harness.dir.join("audit.jsonl")).expect("audit");
    let stop: Value = audit
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|record| record["kind"] == "emergency_stop")
        .expect("a stop record");
    assert_eq!(stop["observed"]["caller_pid"], std::process::id());
    assert_eq!(stop["observed"]["role"], "orceld");
    let events = std::fs::read_to_string(harness.dir.join("events.jsonl")).expect("events");
    assert!(
        events.contains("\"event_id\":4100"),
        "anchors are written: {events}"
    );
}

/// SG-000132 slice 2, TEST BUILDS ONLY (`cargo test -p orcel-authority
/// --features authority-scripted-consent`): the whole grant flow over the
/// pipe, with the scripted consent standing in for the unlock, the
/// confirmation and Windows Hello. The lease verifies with the published
/// public key, Authorize stays orceld's alone, and a revoke ends it.
#[cfg(feature = "authority-scripted-consent")]
#[test]
fn a_scripted_grant_issues_a_signed_browser_lease_over_the_pipe() {
    use orcel_authority::lease::{BrowserFamily, LeaseScope, SignatureVerifier, SignedLease};
    use sha2::{Digest, Sha256};
    let log_dir = state_dir(&unique("scripted-log"));
    std::fs::create_dir_all(&log_dir).expect("log dir");
    let log = log_dir.join("authority-consent.jsonl");
    let me = std::env::current_exe().expect("this test's path");
    let harness = start_with(
        "scripted",
        false,
        &[
            std::ffi::OsStr::new("--e2e-scripted-consent"),
            log.as_os_str(),
            std::ffi::OsStr::new("--trusted-cli"),
            me.as_os_str(),
        ],
    );
    let client = client(&harness);
    let status = client.status().expect("status");
    if status["caller_role"] != "interactive" {
        // A runner without an interactive console logon cannot be the
        // owner's CLI; the grant flow is covered by the core tests there.
        record_scripted_outcome(&format!(
            "skipped: caller_role {} (no interactive console logon)",
            status["caller_role"]
        ));
        let _ = std::fs::remove_dir_all(&log_dir);
        return;
    }
    let client_ref = format!("cl-{}", "ab".repeat(16));
    let begun = client
        .call(&Request::GrantBegin {
            origin: ClaimedOrigin::OwnerCli,
            scope: Some(LeaseScope::BrowserFullAccess {
                client_ref: client_ref.clone(),
                session_id: "bs-0123456789abcdef-1-0001020304050607".into(),
                origins: vec!["https://fixture.test".into()],
                families: vec![BrowserFamily::Navigate, BrowserFamily::Click],
                task: Some("console grant".into()),
            }),
            minutes: Some(30),
            principal_id: client_ref.clone(),
            task: "console grant".into(),
        })
        .expect("grant begin");
    let intent_id = begun["intent_id"].as_str().expect("intent").to_owned();
    let status = client
        .call(&Request::IntentStatus {
            intent_id: intent_id.clone(),
        })
        .expect("intent status");
    assert_eq!(status["state"], "awaiting_presence");
    let challenge =
        orcel_authority::unhex(status["challenge_hex"].as_str().expect("challenge")).expect("hex");
    // A wrong presence is refused and consumes the intent.
    let mut wrong = Sha256::new();
    wrong.update(b"not the scripted domain");
    wrong.update(&challenge);
    let refused = client.call(&Request::PresenceComplete {
        intent_id: intent_id.clone(),
        code: begun["code"].as_str().expect("code").to_owned(),
        signature_hex: orcel_authority::hex(&wrong.finalize()),
    });
    assert_eq!(code(refused), Some(FailureCode::CapabilityDenied));
    // Again, properly.
    let begun = client
        .call(&Request::GrantBegin {
            origin: ClaimedOrigin::OwnerCli,
            scope: Some(LeaseScope::BrowserFullAccess {
                client_ref: client_ref.clone(),
                session_id: "bs-0123456789abcdef-1-0001020304050607".into(),
                origins: vec!["https://fixture.test".into()],
                families: vec![BrowserFamily::Navigate, BrowserFamily::Click],
                task: Some("console grant".into()),
            }),
            minutes: Some(30),
            principal_id: client_ref.clone(),
            task: "console grant".into(),
        })
        .expect("grant begin");
    let intent_id = begun["intent_id"].as_str().expect("intent").to_owned();
    let status = client
        .call(&Request::IntentStatus {
            intent_id: intent_id.clone(),
        })
        .expect("intent status");
    let challenge =
        orcel_authority::unhex(status["challenge_hex"].as_str().expect("challenge")).expect("hex");
    let mut presence = Sha256::new();
    presence.update(orcel_authority::win::runtime::SCRIPTED_PRESENCE_DOMAIN);
    presence.update(&challenge);
    let done = client
        .call(&Request::PresenceComplete {
            intent_id,
            code: begun["code"].as_str().expect("code").to_owned(),
            signature_hex: orcel_authority::hex(&presence.finalize()),
        })
        .expect("issued");
    let lease: SignedLease = serde_json::from_value(done["lease"].clone()).expect("lease");
    let published: Value = serde_json::from_str(
        &std::fs::read_to_string(harness.dir.join("public").join("lease-signing-key.json"))
            .expect("public key"),
    )
    .expect("json");
    let verifier = orcel_authority::win::crypto::EcdsaP256Verifier::from_public_blob(
        &orcel_authority::unhex(published["public_key_hex"].as_str().expect("hex")).expect("hex"),
    )
    .expect("verifier");
    assert_eq!(verifier.key_id(), lease.body.key_id);
    lease
        .verify_signature(&verifier)
        .expect("the published key verifies the lease");
    let confirmations = std::fs::read_to_string(&log).expect("consent log");
    assert_eq!(confirmations.lines().count(), 2, "{confirmations}");
    assert!(confirmations.contains("origins [https://fixture.test]"));
    // Authorize is orceld's alone; verify works for the owner; a revoke ends it.
    assert_eq!(
        client.status().expect("status")["caller_is_owner_cli"],
        Value::Bool(true)
    );
    let authorize = client.authorize(
        &lease.body.lease_id,
        ExecutorClass::Browser,
        AuthorizeClaims {
            principal_id: client_ref,
            origin: Some("https://fixture.test".into()),
            ..claims()
        },
    );
    assert_eq!(code(authorize), Some(FailureCode::CapabilityDenied));
    client.verify_lease(&lease.body.lease_id).expect("active");
    client.revoke(&lease.body.lease_id).expect("revoke");
    assert_eq!(
        code(client.verify_lease(&lease.body.lease_id)),
        Some(FailureCode::LeaseInvalid)
    );
    record_scripted_outcome(
        "ran: scripted grant issued a signed lease, Authorize refused, revoke ended it",
    );
    let _ = std::fs::remove_dir_all(&log_dir);
}

/// The CI install E2E (scripts/authority-install-e2e.ps1) records whether
/// the scripted grant ran or the runner had no interactive console logon,
/// so a skip is reported, never mistaken for a pass.
#[cfg(feature = "authority-scripted-consent")]
fn record_scripted_outcome(outcome: &str) {
    if let Some(path) = std::env::var_os("ORCEL_E2E_SCRIPTED_GRANT_MARKER") {
        std::fs::write(path, outcome).expect("write the scripted grant marker");
    }
}
