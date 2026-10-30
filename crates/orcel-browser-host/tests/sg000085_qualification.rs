//! SG-000085 P18 adversarial qualification: server-owned ceilings,
//! privacy (no secret or payload leakage into errors), failure
//! semantics, cross-surface replay and drift, and denied authority.
//!
//! Test-only. No production code and no authority change.

use orcel_browser_host::{
    adopt_profile, arbitrary_drag, assert_argv_clean, background_stream, build_argv,
    capture_binding_digest, cdp_command, check_freshness, check_lease, clipboard_typing,
    coordinate_fallback, decode_frame, delayed_execution, devtools_open, dispatch,
    download_trigger_allowed, encode_frame, evaluate_javascript, execute_automatically,
    execute_one, external_handler_allowed, extract_automatically, hotkey_press, input_stream,
    invalidate_on, invoke, invoke_backend_directly, is_denied_shape, is_live_exposed,
    is_protected_surface, is_protected_uia_surface, issue_local, issue_remote, keyboard_synthesis,
    mediate_frame, mediate_popup, mediate_service_worker, mediate_subresource, mediate_worker,
    mint_target_identity, mouse_synthesis, offline_queue, open_automatically, parse_navigation_url,
    parse_proposal, permission_allowed, profile_tools, read_credentials, redact_value,
    remote_browser_mapping_enabled, remote_execution_allowed, renew_silently, resurrect,
    retry_after_dispatch, role_supports_action, scroll, select_by_caller_selector, self_approve,
    set_value, setup_ephemeral_profile, sniff_denied_class, uia_coordinate_fallback,
    uia_target_digest, validate_capture_target, validate_identity_field, validate_proposal,
    validate_redirect, validate_route, validate_transfer_size, validate_upload_source,
    verify_pattern_support, verify_postcondition, verify_target, verify_uia_target, widen_lease,
    ApprovalToken, CaptureGeometry, CaptureLease, CaptureProcess, CaptureScope, CaptureTarget,
    CaptureWindow, CoordinateAction, CoordinateProposal, DnsResolver, HostError, InputLease,
    InvalidationEvent, LeaseScope, PresentedUpload, RecordedUpload, RedirectChain, RemoteLease,
    ScrollDirection, SubresourceKind, SupportedAction, SupportedPattern, UiaApproval, UiaElement,
    UiaLive, UiaProcess, UiaTarget, UiaWindow, DENIED_BROWSER_SHAPES, DOWNLOAD_SOURCE_TTL_MS,
    HANDSHAKE_TIMEOUT, INPUT_LEASE_TTL_MS, JOB_ACTIVE_PROCESS_LIMIT, LAUNCH_GRACE,
    MAX_CAPTURE_BYTES, MAX_CAPTURE_DPI, MAX_CAPTURE_FRAMES, MAX_CAPTURE_HEIGHT,
    MAX_CAPTURE_LEASE_MS, MAX_CAPTURE_RATE_PER_MINUTE, MAX_CAPTURE_WIDTH,
    MAX_CONCURRENT_OBSERVATIONS, MAX_DESTINATION_BYTES, MAX_FRAME_BYTES, MAX_IDENTITY_BYTES,
    MAX_INPUT_TEXT_CHARS, MAX_LEASE_CAPABILITIES, MAX_LEASE_FIELD_BYTES, MAX_LEASE_TARGETS,
    MAX_OBSERVATION_DEPTH, MAX_OBSERVATION_MS, MAX_OBSERVED_NODES, MAX_PROPOSAL_BYTES,
    MAX_REDIRECT_HOPS, MAX_REMOTE_LEASE_MS, MAX_SCROLL_AMOUNT, MAX_SCROLL_DELTA,
    MAX_SNAPSHOT_BYTES, MAX_TARGET_FIELD_BYTES, MAX_TRANSFER_BYTES, MAX_UIA_VALUE_CHARS,
    MAX_URL_BYTES, MAX_VALUE_BYTES, MIN_CAPTURE_DPI, MIN_SCROLL_AMOUNT, PROPOSAL_ACTION_VERBS,
    SHUTDOWN_TIMEOUT,
};
use std::net::IpAddr;

// ---------------------------------------------------------------------------
// Shared fixtures.
// ---------------------------------------------------------------------------

/// Marker that must never appear in an error string, digest-bound receipt
/// aside: it stands in for secret or payload material.
const SECRET_MARKER: &str = "s3cr3t-marker-7f2b9d";

fn assert_no_leak(result: &Result<(), HostError>, marker: &str) {
    let err = result.as_ref().expect_err("expected fail-closed denial");
    let text = format!("{err:?} {err}");
    assert!(
        !text.contains(marker),
        "secret material leaked into error: {text}"
    );
}

fn coordinate_proposal() -> CoordinateProposal {
    CoordinateProposal {
        capture_generation: 4,
        hwnd: 0x00A1B2,
        window_generation: 5,
        geometry_x: 0,
        geometry_y: 0,
        geometry_width: 800,
        geometry_height: 600,
        dpi: 96,
        action: CoordinateAction::Click,
        x: 100,
        y: 200,
    }
}

fn input_lease_for(proposal: &CoordinateProposal) -> InputLease {
    InputLease::issue(
        "lease-1",
        &orcel_browser_host::proposal_digest(proposal),
        1_000,
        0,
    )
    .unwrap()
}

fn capture_target() -> CaptureTarget {
    CaptureTarget {
        process: CaptureProcess {
            pid: 4242,
            executable_digest: "engine-digest".into(),
            process_generation: 11,
        },
        window: CaptureWindow {
            hwnd: 0x00A1B2,
            window_generation: 5,
            session: "session-1".into(),
        },
        geometry: CaptureGeometry {
            x: 0,
            y: 0,
            width: 800,
            height: 600,
            dpi: 96,
        },
        policy_revision: 9,
        capture_generation: 1,
    }
}

fn uia_target(pattern: SupportedPattern, control_type: &str) -> UiaTarget {
    UiaTarget {
        process: UiaProcess {
            pid: 4242,
            executable_digest: "app-digest".into(),
            process_generation: 11,
        },
        window: UiaWindow {
            hwnd: 0x00A1B2,
            window_generation: 5,
        },
        element: UiaElement {
            runtime_id: "element-1".into(),
            tree_generation: 3,
            control_type: control_type.into(),
        },
        pattern,
        enabled: true,
        workspace: "workspace-1".into(),
        policy_revision: 9,
    }
}

fn uia_live() -> UiaLive {
    UiaLive {
        process_generation: 11,
        window_generation: 5,
        tree_generation: 3,
        control_type: "button".into(),
        workspace: "workspace-1".into(),
        policy_revision: 9,
    }
}

fn uia_approval_for(target: &UiaTarget) -> UiaApproval {
    UiaApproval {
        approval_id: "approval-1".into(),
        target_digest: uia_target_digest(target),
        workspace: target.workspace.clone(),
        policy_revision: target.policy_revision,
        consumed: false,
    }
}

fn actuation_target() -> orcel_browser_host::ActuationTarget {
    orcel_browser_host::ActuationTarget {
        page_id: "page-7".into(),
        origin: "https://example.com/".into(),
        document_generation: 12,
        node_id: "node-3".into(),
        role: "button".into(),
        state: "enabled".into(),
        action: SupportedAction::Click,
        workspace: "workspace-1".into(),
        policy_revision: 9,
    }
}

fn approval_for(target: &orcel_browser_host::ActuationTarget) -> ApprovalToken {
    ApprovalToken {
        approval_id: "approval-1".into(),
        target_digest: orcel_browser_host::target_digest(target),
        workspace: target.workspace.clone(),
        policy_revision: target.policy_revision,
        consumed: false,
    }
}

fn remote_lease() -> RemoteLease {
    RemoteLease {
        lease_id: "remote-lease-1".into(),
        provider: "provider-a".into(),
        principal: "principal-1".into(),
        device_id: "device-1".into(),
        route: "route-1".into(),
        session_epoch: 3,
        route_epoch: 1,
        workspace: "workspace-1".into(),
        capabilities: vec!["observe".into(), "click".into()],
        targets: vec!["window-1".into()],
        issued_ms: 1_000,
        expiry_ms: 2_000,
        policy_revision: 9,
        revoked: false,
    }
}

fn lease_scope() -> LeaseScope<'static> {
    LeaseScope {
        provider: "provider-a",
        principal: "principal-1",
        device_id: "device-1",
        session_epoch: 3,
        route_epoch: 1,
        workspace: "workspace-1",
        policy_revision: 9,
        now_ms: 1_500,
    }
}

struct PublicOnlyResolver;

impl DnsResolver for PublicOnlyResolver {
    fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>, HostError> {
        Ok(vec!["93.184.216.34".parse().unwrap()])
    }
}

fn valid_envelope() -> String {
    let verb = PROPOSAL_ACTION_VERBS
        .first()
        .expect("verbs are never empty");
    format!(r#"{{"action":{verb:?},"target":{{}},"parameters":{{}}}}"#)
}

// ---------------------------------------------------------------------------
// A. Server-owned hard ceilings: values are locked and enforced.
// ---------------------------------------------------------------------------

#[test]
fn ceiling_values_are_locked_against_silent_raising() {
    assert_eq!(MAX_OBSERVED_NODES, 512);
    assert_eq!(MAX_OBSERVATION_DEPTH, 16);
    assert_eq!(MAX_SNAPSHOT_BYTES, 65_536);
    assert_eq!(MAX_VALUE_BYTES, 1_024);
    assert_eq!(MAX_IDENTITY_BYTES, 256);
    assert_eq!(MAX_CONCURRENT_OBSERVATIONS, 4);
    assert_eq!(MAX_OBSERVATION_MS, 2_000);
    assert_eq!(MAX_FRAME_BYTES, 64 * 1024);
    assert_eq!(MAX_PROPOSAL_BYTES, 65_536);
    assert_eq!(MAX_TARGET_FIELD_BYTES, 512);
    assert_eq!(MAX_TRANSFER_BYTES, 8 * 1024 * 1024);
    assert_eq!(MAX_DESTINATION_BYTES, 512);
    assert_eq!(DOWNLOAD_SOURCE_TTL_MS, 120_000);
    assert_eq!(MAX_CAPTURE_WIDTH, 3_840);
    assert_eq!(MAX_CAPTURE_HEIGHT, 2_160);
    assert_eq!(MAX_CAPTURE_BYTES, 33_177_600);
    assert_eq!(MAX_CAPTURE_DPI, 576);
    assert_eq!(MIN_CAPTURE_DPI, 48);
    assert_eq!(MAX_CAPTURE_FRAMES, 30);
    assert_eq!(MAX_CAPTURE_RATE_PER_MINUTE, 20);
    assert_eq!(MAX_CAPTURE_LEASE_MS, 60_000);
    assert_eq!(MAX_SCROLL_DELTA, 500);
    assert_eq!(MAX_INPUT_TEXT_CHARS, 256);
    assert_eq!(INPUT_LEASE_TTL_MS, 60_000);
    assert_eq!(MAX_UIA_VALUE_CHARS, 1_024);
    assert_eq!(MIN_SCROLL_AMOUNT, 1);
    assert_eq!(MAX_SCROLL_AMOUNT, 100);
    assert_eq!(MAX_REDIRECT_HOPS, 5);
    assert_eq!(MAX_URL_BYTES, 2048);
    assert_eq!(MAX_REMOTE_LEASE_MS, 900_000);
    assert_eq!(MAX_LEASE_CAPABILITIES, 8);
    assert_eq!(MAX_LEASE_TARGETS, 16);
    assert_eq!(MAX_LEASE_FIELD_BYTES, 256);
    assert_eq!(JOB_ACTIVE_PROCESS_LIMIT, 32);
    assert_eq!(HANDSHAKE_TIMEOUT, std::time::Duration::from_secs(5));
    assert_eq!(LAUNCH_GRACE, std::time::Duration::from_secs(2));
    assert_eq!(SHUTDOWN_TIMEOUT, std::time::Duration::from_secs(10));
}

#[test]
fn transfer_and_identity_bounds_hold_at_the_edge() {
    assert!(validate_transfer_size(MAX_TRANSFER_BYTES, MAX_TRANSFER_BYTES).is_ok());
    assert!(validate_transfer_size(MAX_TRANSFER_BYTES, MAX_TRANSFER_BYTES + 1).is_err());
    assert!(validate_transfer_size(MAX_TRANSFER_BYTES + 1, MAX_TRANSFER_BYTES + 1).is_err());
    assert!(validate_identity_field(&"i".repeat(MAX_IDENTITY_BYTES)).is_ok());
    assert!(validate_identity_field(&"i".repeat(MAX_IDENTITY_BYTES + 1)).is_err());
    assert!(validate_identity_field("has-\u{7}-control").is_err());
}

#[test]
fn navigation_url_and_redirect_bounds_hold() {
    let room = "https://example.com/".len();
    let big = format!(
        "https://example.com/{}",
        "p".repeat(MAX_URL_BYTES - room + 1)
    );
    assert!(big.len() > MAX_URL_BYTES);
    assert!(parse_navigation_url(&big).is_err());
    assert!(parse_navigation_url("https://example.com/").is_ok());
    let mut chain = RedirectChain::start("https://example.com/").unwrap();
    for hop in 0..MAX_REDIRECT_HOPS {
        chain
            .push(&format!("https://example.com/hop-{hop}"))
            .unwrap();
    }
    assert!(chain.push("https://example.com/one-too-many").is_err());
}

#[test]
fn frame_and_proposal_bounds_hold() {
    use std::io::Cursor;
    // JSON string encoding adds two quote bytes, so the body boundary
    // sits at MAX_FRAME_BYTES - 2 payload characters.
    assert!(encode_frame(&"small".to_string()).is_ok());
    let back: String = decode_frame(&mut Cursor::new(
        encode_frame(&"small".to_string()).unwrap(),
    ))
    .unwrap();
    assert_eq!(back, "small");
    assert!(encode_frame(&"x".repeat(MAX_FRAME_BYTES - 2)).is_ok());
    assert!(encode_frame(&"x".repeat(MAX_FRAME_BYTES - 1)).is_err());
    let mut big = (MAX_FRAME_BYTES as u32 + 1).to_le_bytes().to_vec();
    big.extend_from_slice(b"{}");
    assert!(decode_frame::<String, _>(&mut Cursor::new(big)).is_err());
    assert!(decode_frame::<String, _>(&mut Cursor::new(Vec::new())).is_err());
    assert!(parse_proposal(&format!(
        "{{\"action\":\"click\",\"target\":{{\"t\":\"{}\"}}}}",
        "v".repeat(MAX_PROPOSAL_BYTES)
    ))
    .is_err());
}

#[test]
fn capture_geometry_and_lease_bounds_hold() {
    let target = capture_target();
    assert!(validate_capture_target(
        &target,
        CaptureScope::ExactWindow,
        "app",
        "win",
        5,
        "session-1",
        9
    )
    .is_ok());
    let mut wide = target.clone();
    wide.geometry.width = MAX_CAPTURE_WIDTH + 1;
    assert!(validate_capture_target(
        &wide,
        CaptureScope::ExactWindow,
        "app",
        "win",
        5,
        "session-1",
        9
    )
    .is_err());
    // 3840x2160 RGBA is exactly the byte ceiling: admissible.
    let mut full = target.clone();
    full.geometry.width = MAX_CAPTURE_WIDTH;
    full.geometry.height = MAX_CAPTURE_HEIGHT;
    assert!(validate_capture_target(
        &full,
        CaptureScope::ExactWindow,
        "app",
        "win",
        5,
        "session-1",
        9
    )
    .is_ok());
    let mut over = full.clone();
    over.geometry.height = MAX_CAPTURE_HEIGHT + 1;
    assert!(validate_capture_target(
        &over,
        CaptureScope::ExactWindow,
        "app",
        "win",
        5,
        "session-1",
        9
    )
    .is_err());

    let digest = capture_binding_digest(&target);
    let mut lease = CaptureLease::issue("cap-1", &digest, 1_000).unwrap();
    assert!(lease.use_frame(2_000, 1024, &digest).is_ok());
    assert!(lease
        .use_frame(3_000, MAX_CAPTURE_BYTES + 1, &digest)
        .is_err());
    assert!(lease.use_frame(4_000, 0, &digest).is_err());
    assert!(lease.use_frame(5_000, 64, "wrong-digest").is_err());
    let mut flood = CaptureLease::issue("cap-2", &digest, 1_000).unwrap();
    for _ in 0..MAX_CAPTURE_RATE_PER_MINUTE {
        flood.use_frame(1_001, 64, &digest).unwrap();
    }
    assert_eq!(flood.frames_used, MAX_CAPTURE_RATE_PER_MINUTE);
    assert!(flood.use_frame(1_001, 64, &digest).is_err());
    // The absolute frame-count bound is shadowed by the rate bound and
    // the lease lifetime (at most 20 frames fit in 60 seconds), so it
    // stands as unreachable defense in depth rather than a live gate.
    // What matters is proven here: every frame path enforces a bound.
    let mut stale = CaptureLease::issue("cap-4", &digest, 1_000).unwrap();
    assert!(stale
        .use_frame(1_000 + MAX_CAPTURE_LEASE_MS + 1, 64, &digest)
        .is_err());
}

#[test]
fn coordinate_text_scroll_and_lease_ttl_bounds_hold() {
    let proposal = coordinate_proposal();
    let mut lease = input_lease_for(&proposal);
    assert!(execute_one(&proposal, &mut lease, 4, 5, 96, 2_000, 0).is_ok());

    let mut scroll = coordinate_proposal();
    scroll.action = CoordinateAction::Scroll {
        dx: MAX_SCROLL_DELTA + 1,
        dy: 0,
    };
    let mut lease = input_lease_for(&scroll);
    assert!(execute_one(&scroll, &mut lease, 4, 5, 96, 2_000, 0).is_err());
    assert!(validate_proposal(&coordinate_proposal(), 4, 5, 96).is_ok());
    assert!(validate_proposal(&coordinate_proposal(), 9, 5, 96).is_err());

    let mut text = coordinate_proposal();
    text.action = CoordinateAction::Text {
        text: "x".repeat(MAX_INPUT_TEXT_CHARS + 1),
    };
    let mut lease = input_lease_for(&text);
    assert!(execute_one(&text, &mut lease, 4, 5, 96, 2_000, 0).is_err());

    let proposal = coordinate_proposal();
    let mut lease = input_lease_for(&proposal);
    assert!(execute_one(
        &proposal,
        &mut lease,
        4,
        5,
        96,
        1_000 + INPUT_LEASE_TTL_MS + 1,
        0
    )
    .is_err());
}

#[test]
fn uia_value_and_scroll_bounds_hold() {
    let target = uia_target(SupportedPattern::Value, "edit");
    let live = UiaLive {
        control_type: "edit".into(),
        ..uia_live()
    };
    let mut approval = uia_approval_for(&target);
    assert!(set_value(
        &target,
        "field",
        &"v".repeat(MAX_UIA_VALUE_CHARS + 1),
        &mut approval,
        &live
    )
    .is_err());
    assert!(
        !approval.consumed,
        "rejected value must not consume approval"
    );

    let scroll_target = uia_target(SupportedPattern::Scroll, "pane");
    let scroll_live = UiaLive {
        control_type: "pane".into(),
        ..uia_live()
    };
    let mut approval = uia_approval_for(&scroll_target);
    assert!(scroll(
        &scroll_target,
        "pane",
        ScrollDirection::Down,
        MAX_SCROLL_AMOUNT + 1,
        &mut approval,
        &scroll_live
    )
    .is_err());
    let mut approval = uia_approval_for(&scroll_target);
    assert!(scroll(
        &scroll_target,
        "pane",
        ScrollDirection::Down,
        MAX_SCROLL_AMOUNT,
        &mut approval,
        &scroll_live
    )
    .is_ok());
}

#[test]
fn remote_lease_lifetime_ceiling_holds() {
    let mut lease = remote_lease();
    lease.expiry_ms = lease.issued_ms + MAX_REMOTE_LEASE_MS;
    assert!(issue_local(lease.clone()).is_ok());
    lease.expiry_ms = lease.issued_ms + MAX_REMOTE_LEASE_MS + 1;
    assert!(issue_local(lease).is_err());
}

// ---------------------------------------------------------------------------
// B. Privacy: secrets and payload material never enter errors or digests.
// ---------------------------------------------------------------------------

#[test]
fn secret_roles_are_redacted_and_truncated() {
    for role in [
        "password",
        "PASSWORD",
        "secret",
        "credential",
        "token",
        "pin",
        "user Password field",
    ] {
        let value = format!("prefix-{SECRET_MARKER}-suffix");
        let (out, redacted) = redact_value(role, &value);
        assert!(redacted, "{role}");
        assert_eq!(out, "[redacted]");
        assert!(!out.contains(SECRET_MARKER));
    }
    let long = format!(
        "plain-{}-{}",
        SECRET_MARKER,
        "v".repeat(MAX_VALUE_BYTES + 64)
    );
    let (out, redacted) = redact_value("textbox", &long);
    assert!(!redacted);
    assert!(out.chars().count() <= MAX_VALUE_BYTES);
}

#[test]
fn proposal_errors_never_echo_payload_secrets() {
    // Malformed document carrying the marker: static reason only.
    let malformed = format!("{{\"action\": \"click\", \"target\": {{oops {SECRET_MARKER}");
    assert_no_leak(&parse_proposal(&malformed).map(|_| ()), SECRET_MARKER);
    // Unknown action with the marker in a value: static denial only.
    let unknown = format!(
        "{{\"action\": \"launch-missiles\", \"target\": {{\"note\": \"{SECRET_MARKER}\"}}}}"
    );
    let err = parse_proposal(&unknown).map(|_| ());
    assert_no_leak(&err, SECRET_MARKER);
    // Oversized document carrying the marker: size denial only.
    let pad = format!("{SECRET_MARKER}-{}", "p".repeat(MAX_PROPOSAL_BYTES));
    let big = format!("{{\"action\":\"click\",\"target\":{{\"pad\":\"{pad}\"}}}}");
    assert!(big.len() > MAX_PROPOSAL_BYTES);
    assert_no_leak(&parse_proposal(&big).map(|_| ()), SECRET_MARKER);
    // Diagnostic echo stays within the validated input bound.
    let err = parse_proposal(&malformed).expect_err("must fail");
    assert!(err.to_string().len() <= malformed.len() + 64);
}

#[test]
fn identity_navigation_and_argv_errors_never_echo_secrets() {
    assert_no_leak(
        &validate_identity_field(&format!("field-{SECRET_MARKER}-\u{7}")).map(|_| ()),
        SECRET_MARKER,
    );
    let big_url = format!(
        "https://example.com/{SECRET_MARKER}-{}",
        "p".repeat(MAX_URL_BYTES)
    );
    assert_no_leak(&parse_navigation_url(&big_url).map(|_| ()), SECRET_MARKER);
    let widened = validate_redirect(
        "https://example.com/",
        "https://example.org/",
        &PublicOnlyResolver,
    );
    assert!(widened.is_err());
    let text = format!("{:?} {}", widened.expect_err("must fail"), "");
    assert!(text.len() <= 2 * MAX_URL_BYTES + 64);

    let profile = std::path::PathBuf::from(format!("/tmp/orcel-{SECRET_MARKER}"));
    let argv = build_argv(&profile).unwrap();
    assert!(argv.iter().any(|arg| arg.contains(SECRET_MARKER)));
    // The profile path is construction material, never diagnostic echo:
    // hostile-flag errors name the flag, never the profile directory.
    let hostile = vec![
        "--headless".to_string(),
        format!("--evil-{SECRET_MARKER}"),
        format!("--user-data-dir={}", profile.display()),
    ];
    let err = assert_argv_clean(&hostile).expect_err("must fail");
    let text = format!("{err:?} {err}");
    assert!(
        text.contains(SECRET_MARKER),
        "flag diagnostic names the flag"
    );
    let profile_only = vec![
        "--headless".to_string(),
        "--no-first-run".to_string(),
        "--no-default-browser-check".to_string(),
        "--disable-extensions".to_string(),
        "--disable-background-networking".to_string(),
        "--disable-sync".to_string(),
        "--no-service-autorun".to_string(),
        format!("--user-data-dir={}", profile.display()),
        "about:blank".to_string(),
    ];
    assert!(assert_argv_clean(&profile_only).is_ok());
}

#[test]
fn error_vocabulary_is_typed_and_secret_free() {
    for reason in [
        orcel_browser_host::UnavailableReason::NoEngine,
        orcel_browser_host::UnavailableReason::UnsupportedEngine,
        orcel_browser_host::UnavailableReason::LaunchFailed,
        orcel_browser_host::UnavailableReason::ProtocolViolation,
        orcel_browser_host::UnavailableReason::UnsupportedRuntime,
        orcel_browser_host::UnavailableReason::ManagedPolicy,
        orcel_browser_host::UnavailableReason::TimedOut,
        orcel_browser_host::UnavailableReason::ActionFailed,
        orcel_browser_host::UnavailableReason::WorkerExited,
        orcel_browser_host::UnavailableReason::Cancelled,
        orcel_browser_host::UnavailableReason::TargetStale,
        orcel_browser_host::UnavailableReason::OutcomeUnknown,
        orcel_browser_host::UnavailableReason::TargetOccluded,
    ] {
        let text = format!(
            "{:?} {}",
            HostError::Unavailable(reason),
            HostError::Unavailable(reason)
        );
        assert!(!text.contains(SECRET_MARKER));
        assert!(text.contains("browser unavailable: "));
    }
    assert_no_leak(
        &adopt_profile(std::path::Path::new("/nonexistent-personal-profile"), "fp").map(|_| ()),
        SECRET_MARKER,
    );
    let scratch = std::env::temp_dir().join(format!(
        "orcel-sg85-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_dir_all(&scratch);
    let profile = setup_ephemeral_profile(&scratch, "engine-fingerprint-1").unwrap();
    assert!(profile.dir().starts_with(&scratch));
    let _ = std::fs::remove_dir_all(&scratch);
}

// ---------------------------------------------------------------------------
// C. Failure semantics: hostile input fails closed, never panics, never
// widens; dispatch states are exactly classified by the supported
// vocabulary (pre-dispatch validation failure, dispatched receipt,
// postcondition verification), and mutation is never retried.
// ---------------------------------------------------------------------------

#[test]
fn hostile_corpus_never_panics_and_never_succeeds() {
    let proposal = parse_proposal(&valid_envelope()).expect("valid envelope must parse");
    let denied: Vec<(&str, Result<(), HostError>)> = vec![
        ("javascript", evaluate_javascript("alert(1)").map(|_| ())),
        ("cdp", cdp_command("Runtime.evaluate").map(|_| ())),
        ("devtools", devtools_open().map(|_| ())),
        ("credentials", read_credentials("login-data").map(|_| ())),
        ("selector", select_by_caller_selector("#app .x").map(|_| ())),
        ("backend", invoke_backend_directly(&proposal).map(|_| ())),
        ("mint-target", mint_target_identity().map(|_| ())),
        ("hotkey", hotkey_press().map(|_| ())),
        ("drag", arbitrary_drag().map(|_| ())),
        ("stream", input_stream().map(|_| ())),
        ("clipboard-typing", clipboard_typing().map(|_| ())),
        ("coordinate-fallback", coordinate_fallback().map(|_| ())),
        ("uia-keyboard", keyboard_synthesis().map(|_| ())),
        ("uia-mouse", mouse_synthesis().map(|_| ())),
        ("uia-fallback", uia_coordinate_fallback().map(|_| ())),
        ("issue-remote", issue_remote().map(|_| ())),
        ("widen", widen_lease(&remote_lease()).map(|_| ())),
        ("renew", renew_silently(&remote_lease()).map(|_| ())),
        ("self-approve", self_approve().map(|_| ())),
        ("resurrect", resurrect(&remote_lease()).map(|_| ())),
        ("background-stream", background_stream().map(|_| ())),
        ("offline-queue", offline_queue().map(|_| ())),
        ("delayed", delayed_execution().map(|_| ())),
        ("auto-open", open_automatically("report.pdf").map(|_| ())),
        ("auto-exec", execute_automatically("setup.exe").map(|_| ())),
        (
            "auto-extract",
            extract_automatically("data.zip").map(|_| ()),
        ),
        (
            "download-trigger",
            download_trigger_allowed("https://example.com/f").map(|_| ()),
        ),
        ("permission", permission_allowed("camera").map(|_| ())),
        (
            "external-handler",
            external_handler_allowed("mailto:a@b.c").map(|_| ()),
        ),
        ("retry", retry_after_dispatch("dispatch-abc").map(|_| ())),
        (
            "bad-url",
            parse_navigation_url("http://example.com/").map(|_| ()),
        ),
        (
            "bad-scheme",
            parse_navigation_url("file:///etc/passwd").map(|_| ()),
        ),
        (
            "popup-widen",
            mediate_popup("https://example.com/", "https://example.org/").map(|_| ()),
        ),
        (
            "frame-widen",
            mediate_frame("https://example.com/", "https://example.org/").map(|_| ()),
        ),
        (
            "worker-widen",
            mediate_worker("https://example.com/", "https://example.org/x.js").map(|_| ()),
        ),
        (
            "websocket",
            mediate_subresource(
                "https://example.com/",
                "wss://example.com/s",
                SubresourceKind::WebSocket,
            )
            .map(|_| ()),
        ),
        (
            "quic",
            mediate_subresource(
                "https://example.com/",
                "https://example.com/q",
                SubresourceKind::Quic,
            )
            .map(|_| ()),
        ),
        (
            "doh",
            mediate_subresource(
                "https://example.com/",
                "https://example.com/dns",
                SubresourceKind::Doh,
            )
            .map(|_| ()),
        ),
        (
            "webrtc",
            mediate_subresource(
                "https://example.com/",
                "https://example.com/rtc",
                SubresourceKind::WebRtc,
            )
            .map(|_| ()),
        ),
        (
            "role-password",
            role_supports_action("password", SupportedAction::Fill).map(|_| ()),
        ),
        (
            "pattern-value-on-button",
            verify_pattern_support("button", SupportedPattern::Value, true, "ok").map(|_| ()),
        ),
        (
            "service-worker-widen",
            mediate_service_worker("https://example.com/", "https://example.org/sw.js").map(|_| ()),
        ),
    ];
    assert!(!denied.is_empty());
    for (name, result) in &denied {
        let err = result.as_ref().expect_err("must fail closed");
        assert!(result.is_err(), "{name} must fail closed");
        let text = format!("{err:?} {err}");
        assert!(!text.contains(SECRET_MARKER), "{name} leaked");
    }
    assert!(!remote_execution_allowed());
    assert!(!remote_browser_mapping_enabled());
    assert!(profile_tools("no-such-profile").is_err());
    assert!(profile_tools("core").is_err());
    // SG-000108 slice 3c: browser_structured resolves to the live set only.
    assert_eq!(
        profile_tools("browser_structured").unwrap(),
        orcel_browser_host::LIVE_BROWSER_MCP_TOOLS
    );
}

#[test]
fn dispatch_outcomes_are_exactly_classified() {
    // Pre-dispatch validation failure: approval stays unconsumed, so the
    // failure is recorded as not started rather than as an unknown
    // outcome of a mutation.
    let target = actuation_target();
    let mut approval = approval_for(&target);
    assert!(dispatch(&target, &mut approval, 13, "enabled", 9, "workspace-1").is_err());
    assert!(!approval.consumed);
    assert!(verify_target(&target, 13, "enabled", 9, "workspace-1").is_err());

    // Dispatched: success carries only a receipt; completion still
    // requires separate postcondition verification.
    let mut approval = approval_for(&target);
    let outcome = dispatch(&target, &mut approval, 12, "enabled", 9, "workspace-1").unwrap();
    assert!(approval.consumed);
    let receipt = match outcome {
        orcel_browser_host::DispatchOutcome::Dispatched { receipt } => receipt,
    };
    assert!(!receipt.is_empty());
    assert!(dispatch(&target, &mut approval, 12, "enabled", 9, "workspace-1").is_err());

    // Postcondition: exactly one generation advance verifies; anything
    // else stays unverified and is never retried.
    assert!(verify_postcondition(12, 13).is_ok());
    assert!(verify_postcondition(12, 12).is_err());
    assert!(verify_postcondition(12, 14).is_err());
    assert!(retry_after_dispatch(&receipt).is_err());

    // Freshness and identity drift fail closed across generations.
    assert!(check_freshness(7, 7, 12, 12).is_ok());
    assert!(check_freshness(7, 8, 12, 12).is_err());
    assert!(check_freshness(7, 7, 12, 13).is_err());
}

#[test]
fn uia_gate_consumes_exactly_once_with_digest_binding() {
    let target = uia_target(SupportedPattern::Invoke, "button");
    let live = uia_live();
    let mut approval = uia_approval_for(&target);
    let next = invoke(&target, "ok-button", &mut approval, &live).unwrap();
    assert_eq!(next, live.tree_generation.wrapping_add(1));
    assert!(invoke(&target, "ok-button", &mut approval, &live).is_err());

    let other = uia_target(SupportedPattern::Invoke, "hyperlink");
    let other_live = UiaLive {
        control_type: "hyperlink".into(),
        ..uia_live()
    };
    let mut cross = uia_approval_for(&target);
    assert!(invoke(&other, "link", &mut cross, &other_live).is_err());

    let value_target = uia_target(SupportedPattern::Value, "edit");
    let value_live = UiaLive {
        control_type: "edit".into(),
        ..uia_live()
    };
    let mut approval = uia_approval_for(&value_target);
    assert!(set_value(
        &value_target,
        "field",
        "bounded text",
        &mut approval,
        &value_live
    )
    .is_ok());
    assert!(verify_pattern_support("button", SupportedPattern::Invoke, true, "ok").is_ok());
    assert!(verify_pattern_support("button", SupportedPattern::Value, true, "ok").is_err());
    assert!(verify_pattern_support("button", SupportedPattern::Invoke, false, "ok").is_err());
    assert!(
        verify_pattern_support("edit", SupportedPattern::Value, true, "password field").is_err()
    );
}

// ---------------------------------------------------------------------------
// D. Cross-surface replay and drift: recycled handles, epochs, and scopes.
// ---------------------------------------------------------------------------

#[test]
fn recycled_window_handle_fails_closed_across_restart() {
    let target = capture_target();
    assert!(validate_capture_target(
        &target,
        CaptureScope::ExactWindow,
        "app",
        "win",
        5,
        "session-1",
        9
    )
    .is_ok());
    // The OS recycled the handle for a new window (generation advanced).
    assert!(validate_capture_target(
        &target,
        CaptureScope::ExactWindow,
        "app",
        "win",
        8,
        "session-1",
        9
    )
    .is_err());
    // A session transition invalidates the old binding as well.
    assert!(validate_capture_target(
        &target,
        CaptureScope::ExactWindow,
        "app",
        "win",
        5,
        "session-2",
        9
    )
    .is_err());
    // Restart revokes every live lease; the old digest never authorizes.
    let digest = capture_binding_digest(&target);
    let mut lease = CaptureLease::issue("cap-restart", &digest, 1_000).unwrap();
    invalidate_on(&mut lease, InvalidationEvent::Restart);
    assert!(lease.use_frame(2_000, 64, &digest).is_err());
    for event in [
        InvalidationEvent::ProcessReplaced,
        InvalidationEvent::WindowReplaced,
        InvalidationEvent::LockLogoff,
        InvalidationEvent::SessionChange,
        InvalidationEvent::RdpTransition,
        InvalidationEvent::PolicyChange,
    ] {
        let mut lease = CaptureLease::issue("cap-event", &digest, 1_000).unwrap();
        invalidate_on(&mut lease, event);
        assert!(lease.use_frame(2_000, 64, &digest).is_err());
    }
    // Whole-screen scope never validates, even for a known target.
    assert!(validate_capture_target(
        &target,
        CaptureScope::WholeScreen,
        "app",
        "win",
        5,
        "session-1",
        9
    )
    .is_err());
    // Protected Orcel and credential surfaces never validate.
    assert!(is_protected_surface("CredentialUIBroker", "sign in"));
    assert!(is_protected_surface("consent", "User Account Control"));
    assert!(is_protected_surface(
        "Orcel Approval",
        "approve this action"
    ));
    assert!(!is_protected_surface("notepad", "notes.txt"));
    assert!(is_protected_uia_surface("edit", "account password"));
    assert!(!is_protected_uia_surface("button", "ok"));
}

#[test]
fn pid_reuse_and_element_drift_fail_closed() {
    let target = uia_target(SupportedPattern::Invoke, "button");
    let live = uia_live();
    let mut approval = uia_approval_for(&target);
    assert!(invoke(&target, "ok", &mut approval, &live).is_ok());

    // Process replaced: the pid now belongs to a new generation.
    let restarted = UiaLive {
        process_generation: 12,
        ..uia_live()
    };
    assert!(verify_uia_target(&target, "ok", &restarted).is_err());
    let mut approval = uia_approval_for(&target);
    assert!(invoke(&target, "ok", &mut approval, &restarted).is_err());

    // Window destroyed and handle reused by another generation.
    let rehung = UiaLive {
        window_generation: 6,
        ..uia_live()
    };
    let mut approval = uia_approval_for(&target);
    assert!(invoke(&target, "ok", &mut approval, &rehung).is_err());

    // Element replaced under the same runtime id.
    let replaced = UiaLive {
        tree_generation: 4,
        ..uia_live()
    };
    let mut approval = uia_approval_for(&target);
    assert!(invoke(&target, "ok", &mut approval, &replaced).is_err());

    // Role changed under the observer: no silent retargeting.
    let morphed = UiaLive {
        control_type: "hyperlink".into(),
        ..uia_live()
    };
    let mut approval = uia_approval_for(&target);
    assert!(invoke(&target, "ok", &mut approval, &morphed).is_err());
}

#[test]
fn remote_lease_never_crosses_scope_or_route() {
    let lease = issue_local(remote_lease()).unwrap();
    assert!(check_lease(&lease, &lease_scope()).is_ok());
    let mutations: Vec<(&str, LeaseScope<'_>)> = vec![
        (
            "provider",
            LeaseScope {
                provider: "provider-b",
                ..lease_scope()
            },
        ),
        (
            "principal",
            LeaseScope {
                principal: "principal-2",
                ..lease_scope()
            },
        ),
        (
            "device",
            LeaseScope {
                device_id: "device-2",
                ..lease_scope()
            },
        ),
        (
            "session",
            LeaseScope {
                session_epoch: 4,
                ..lease_scope()
            },
        ),
        (
            "route-epoch",
            LeaseScope {
                route_epoch: 2,
                ..lease_scope()
            },
        ),
        (
            "workspace",
            LeaseScope {
                workspace: "workspace-2",
                ..lease_scope()
            },
        ),
        (
            "policy",
            LeaseScope {
                policy_revision: 10,
                ..lease_scope()
            },
        ),
        (
            "expiry",
            LeaseScope {
                now_ms: 2_000,
                ..lease_scope()
            },
        ),
    ];
    for (name, scope) in &mutations {
        assert!(check_lease(&lease, scope).is_err(), "{name}");
    }
    let mut revoked = lease.clone();
    revoked.revoked = true;
    assert!(check_lease(&revoked, &lease_scope()).is_err());
    assert!(validate_route(&lease, "route-1", true).is_ok());
    assert!(validate_route(&lease, "route-evil", true).is_err());
    assert!(validate_route(&lease, "route-1", false).is_err());
}

#[test]
fn stale_capture_breaks_coordinate_binding() {
    // The capture advanced (new frame generation) after the proposal was
    // derived: executing against the new generation fails closed.
    let proposal = coordinate_proposal();
    let mut lease = input_lease_for(&proposal);
    assert!(execute_one(&proposal, &mut lease, 9, 5, 96, 2_000, 0).is_err());
    // A lease bound to one proposal digest never executes another.
    let mut other = coordinate_proposal();
    other.x = 150;
    let mut lease = input_lease_for(&proposal);
    assert!(execute_one(&other, &mut lease, 4, 5, 96, 2_000, 0).is_err());
    // Actuation targets bind the same way: digest mismatch denies.
    let target = actuation_target();
    let mut approval = approval_for(&target);
    let mut drifted = target.clone();
    drifted.node_id = "node-9".into();
    assert!(dispatch(&drifted, &mut approval, 12, "enabled", 9, "workspace-1").is_err());
    assert!(!approval.consumed);
}

#[test]
fn transfer_source_binding_and_type_denial_hold() {
    assert!(validate_transfer_size(100, 100).is_ok());
    assert!(validate_transfer_size(100, 101).is_err());
    assert_eq!(
        sniff_denied_class(b"MZ\x90\x00"),
        Some(orcel_browser_host::DeniedContentClass::Pe)
    );
    assert_eq!(
        sniff_denied_class(b"#!/bin/sh\n"),
        Some(orcel_browser_host::DeniedContentClass::ShellScript)
    );
    assert_eq!(
        sniff_denied_class(b"%PDF-1.7\n"),
        Some(orcel_browser_host::DeniedContentClass::Pdf)
    );
    assert_eq!(sniff_denied_class(b"plain text body"), None);
    let recorded = RecordedUpload {
        digest: "digest-1".into(),
        size: 512,
        media_type: "text/plain".into(),
        file_input: "input-1".into(),
        workspace: "workspace-1".into(),
    };
    let presented = PresentedUpload {
        digest: "digest-1".into(),
        size: 512,
        media_type: "text/plain".into(),
        file_input: "input-1".into(),
        workspace: "workspace-1".into(),
    };
    assert!(validate_upload_source(&recorded, &presented).is_ok());
    let swapped = PresentedUpload {
        digest: "digest-2".into(),
        ..presented.clone()
    };
    assert!(validate_upload_source(&recorded, &swapped).is_err());
    // Address policy is enforced through navigation, not around it:
    // a resolver returning only private addresses denies navigation,
    // while a public address allows it.
    struct PrivateOnlyResolver;
    impl DnsResolver for PrivateOnlyResolver {
        fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>, HostError> {
            Ok(vec!["10.0.0.8".parse().unwrap()])
        }
    }
    assert!(
        orcel_browser_host::validate_navigation("https://example.com/", &PrivateOnlyResolver)
            .is_err()
    );
    assert!(
        orcel_browser_host::validate_navigation("https://example.com/", &PublicOnlyResolver)
            .is_ok()
    );
}

// ---------------------------------------------------------------------------
// E. Denied authority: closed registries plus static tripwires over the
// implementation surface.
// ---------------------------------------------------------------------------

#[test]
fn denied_shapes_are_closed_in_every_registry() {
    let required = [
        "browser_evaluate",
        "browser.evaluate",
        "browser.script",
        "browser.cdp",
        "browser.devtools",
        "browser.profile.use_personal",
        "browser.profile.attach",
        "browser.process.launch",
        "browser.process.attach",
        "browser.fs.read",
        "browser.fs.list",
        "browser.remote.map",
    ];
    for shape in required {
        assert!(is_denied_shape(shape), "{shape}");
        assert!(!is_live_exposed(shape), "{shape}");
    }
    // The denial registry is locked: exactly these twelve shapes, no
    // silent additions or removals.
    assert_eq!(DENIED_BROWSER_SHAPES.len(), required.len());
    for shape in DENIED_BROWSER_SHAPES {
        assert!(required.contains(shape), "{shape}");
    }
    assert!(!is_denied_shape("browser.snapshot"));
    assert!(!is_live_exposed("browser.snapshot"));
}

fn crate_sources() -> Vec<(String, String)> {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).expect("src must be readable");
        for entry in entries {
            let path = entry.expect("entry must be readable").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().map(|ext| ext == "rs").unwrap_or(false) {
                let text = std::fs::read_to_string(&path).expect("source must be readable");
                out.push((
                    path.file_name().unwrap().to_string_lossy().into_owned(),
                    text,
                ));
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

#[test]
fn no_shell_script_or_remote_process_surface_exists() {
    let sources = crate_sources();
    assert!(!sources.is_empty());
    // These tokens must not appear anywhere: no shell, no script
    // evaluation, no remote-process primitives.
    for token in [
        "powershell",
        "cmd.exe",
        "/bin/sh",
        "execScript",
        "CreateRemoteThread",
        "ShellExecute",
        "WinExec",
        "system(\"",
        "eval(",
    ] {
        for (file, text) in &sources {
            assert!(!text.contains(token), "{token} must not appear in {file}");
        }
    }
    // SG-000108: the fixture certificate trust flag exists only in test
    // builds. Outside the cfg(test) native test module it may appear only
    // inside the test-gated helper in worker_launch.rs: cfg(test), or the
    // test-only `live-browser-test` feature of the product caller's worker
    // mode, which release qualification keeps out of every release build.
    for (file, text) in &sources {
        if !text.contains("ignore-certificate-errors") || file == "worker_launch_tests.rs" {
            continue;
        }
        assert_eq!(file, "worker_launch.rs", "certificate flag in {file}");
        let lines: Vec<&str> = text.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            if line.contains("ignore-certificate-errors") {
                let gated = lines[index.saturating_sub(4)..index].iter().any(|above| {
                    above.trim() == "#[cfg(test)]"
                        || above.trim() == "#[cfg(any(test, feature = \"live-browser-test\"))]"
                });
                assert!(
                    gated,
                    "certificate flag outside cfg(test) at worker_launch.rs:{}",
                    index + 1
                );
            }
        }
    }
    // Process spawning exists only where the supervised launch and the
    // read-only engine version probe live. The SG-000108 worker launch uses
    // CreateProcessW in worker_process.rs (no Command::new);
    // worker_launch_tests.rs and discovery_macos_tests.rs compile only under
    // cfg(test) and spawn test fixtures (XP-14: `cp -c` clones and
    // `codesign` for the tamper tests).
    // SG-000115 category A (recorded rule change, prep/SG-000115.md): the
    // inert Unix fixture spawners A2 (unix_supervise.rs) and A5
    // (unix_cleanup.rs), admitted only while lib.rs declares them under
    // #[cfg(all(test, unix))]. A6 (unix_rehearsal.rs) spawns only through
    // A2's `python_fixture`, pinned below under the same guard.
    let lib = sources
        .iter()
        .find(|(file, _)| file == "lib.rs")
        .map(|(_, text)| text.replace("\r\n", "\n"))
        .expect("lib.rs is a crate source");
    // Exactly one declaration, private, directly under the Unix test cfg:
    // a second declaration (another cfg, or `pub mod`) defeats the guard.
    let unix_test_only = |module: &str| {
        lib.matches(&format!("mod {module};")).count() == 1
            && !lib.contains(&format!("pub mod {module}"))
            && lib.contains(&format!("#[cfg(all(test, unix))]\nmod {module};\n"))
    };
    for (file, text) in &sources {
        if text.contains("Command::new") {
            assert!(
                file == "supervise.rs"
                    || file == "discovery.rs"
                    || file == "worker_launch_tests.rs"
                    || file == "discovery_macos_tests.rs"
                    || (file == "unix_supervise.rs" && unix_test_only("unix_supervise"))
                    || (file == "unix_cleanup.rs" && unix_test_only("unix_cleanup")),
                "unexpected process spawn in {file}"
            );
        }
        // A6 (unix_rehearsal.rs) spawns its fake engine through A2's fixture
        // constructor, which evaluates a fixed Python string: that
        // indirection is pinned to the same two test-only modules.
        if text.contains("python_fixture(") {
            assert!(
                (file == "unix_supervise.rs" && unix_test_only("unix_supervise"))
                    || (file == "unix_rehearsal.rs" && unix_test_only("unix_rehearsal")),
                "unexpected fixture-script spawn in {file}"
            );
        }
        if text.contains("use_personal") {
            assert_eq!(
                file, "exposure.rs",
                "personal-profile token outside denial registry"
            );
        }
        if text.contains("personal profile") || text.contains("personal browser") {
            assert!(
                file == "exposure.rs" || file == "main.rs",
                "personal-profile mention outside denial context in {file}"
            );
        }
        if text.contains("background_stream")
            || text.contains("offline_queue")
            || text.contains("delayed_execution")
        {
            assert!(
                file == "remote_leases.rs" || file == "lib.rs",
                "remote-capability token outside denial definition in {file}"
            );
        }
    }
    // The tripwire above must actually see the denial definitions, or it
    // would pass vacuously.
    let lib = sources
        .iter()
        .find(|(file, _)| file == "lib.rs")
        .expect("lib.rs")
        .1
        .clone();
    assert!(lib.contains("background_stream"));
    let exposure = sources
        .iter()
        .find(|(file, _)| file == "exposure.rs")
        .expect("exposure.rs")
        .1
        .clone();
    assert!(exposure.contains("use_personal"));
}

// __PART3__
