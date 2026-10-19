//! SG-000038 deterministic bounded clipboard-read tests.
//!
//! These tests use an injected fake adapter, so they prove read bounds,
//! format denial, secret denial, sequence binding, approval-digest shape,
//! and evidence secrecy deterministically on every platform without a
//! live desktop. Real Windows clipboard API gating is proven separately
//! through the native adapter test, and headless clipboard access is
//! reported as unavailable instead of fabricated.

use super::*;
use std::cell::Cell;

const WORKSPACE: &str = "clipboard-test-workspace";
const POLICY: &str = "sg-000038-v1";

struct FakeClipboardAdapter {
    sequence: Cell<u64>,
    content: std::cell::RefCell<Option<String>>,
    non_text: bool,
    locked: bool,
    writes: Cell<usize>,
    last_placed: std::cell::RefCell<Option<String>>,
}

impl FakeClipboardAdapter {
    fn with_text(sequence: u64, text: impl Into<String>) -> Self {
        Self {
            sequence: Cell::new(sequence),
            content: std::cell::RefCell::new(Some(text.into())),
            non_text: false,
            locked: false,
            writes: Cell::new(0),
            last_placed: std::cell::RefCell::new(None),
        }
    }

    fn empty(sequence: u64) -> Self {
        Self {
            sequence: Cell::new(sequence),
            content: std::cell::RefCell::new(None),
            non_text: false,
            locked: false,
            writes: Cell::new(0),
            last_placed: std::cell::RefCell::new(None),
        }
    }

    fn non_text(sequence: u64) -> Self {
        Self {
            sequence: Cell::new(sequence),
            content: std::cell::RefCell::new(None),
            non_text: true,
            locked: false,
            writes: Cell::new(0),
            last_placed: std::cell::RefCell::new(None),
        }
    }

    fn locked(sequence: u64) -> Self {
        Self {
            sequence: Cell::new(sequence),
            content: std::cell::RefCell::new(None),
            non_text: false,
            locked: true,
            writes: Cell::new(0),
            last_placed: std::cell::RefCell::new(None),
        }
    }

    fn bump_sequence(&self) {
        self.sequence.set(self.sequence.get().saturating_add(1));
    }
}

impl ClipboardAdapter for FakeClipboardAdapter {
    fn sequence_number(&self) -> Result<u64, ClipboardError> {
        if self.locked {
            return Err(ClipboardError::new(
                FailureCode::ProviderUnavailable,
                "clipboard is locked by another owner and cannot be sampled now",
            ));
        }
        Ok(self.sequence.get())
    }

    fn read_unicode_text(&self) -> Result<String, ClipboardError> {
        if self.locked {
            return Err(ClipboardError::new(
                FailureCode::ProviderUnavailable,
                "clipboard is locked by another owner and cannot be sampled now",
            ));
        }
        if self.non_text {
            return Err(ClipboardError::new(
                FailureCode::CapabilityDenied,
                "clipboard holds no Unicode text; bounded reads never transfer binary or object formats",
            ));
        }
        match &*self.content.borrow() {
            Some(text) => Ok(text.clone()),
            None => Err(ClipboardError::new(
                FailureCode::TargetStale,
                "clipboard is empty; there is no readable text",
            )),
        }
    }

    fn write_unicode_text(&self, text: &str) -> Result<u64, ClipboardError> {
        if self.locked {
            return Err(ClipboardError::new(
                FailureCode::ProviderUnavailable,
                "clipboard is locked by another owner and cannot be placed now",
            ));
        }
        self.writes.set(self.writes.get().saturating_add(1));
        self.last_placed.replace(Some(text.to_owned()));
        self.content.replace(Some(text.to_owned()));
        self.bump_sequence();
        Ok(self.sequence.get())
    }
}

fn read(
    adapter: &FakeClipboardAdapter,
    expected: Option<u64>,
) -> Result<ReadOutcome, ClipboardError> {
    read_bounded_text(adapter, expected, WORKSPACE, POLICY)
}

/// Process-global serialization for the two native clipboard tests.
/// The Win32 clipboard is process-global state: a test holding a locked
/// clipboard view while another test empties or replaces clipboard data
/// corrupts the heap, so native tests must never run concurrently.
pub(crate) fn native_clipboard_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .expect("native clipboard test lock")
}

#[test]
fn read_shape_predicates_behave() {
    assert!(is_clipboard_read_shape("clipboard", "read"));
    assert!(!is_clipboard_read_shape("clipboard", "write"));
    assert!(!is_clipboard_read_shape("clipboard", "subscribe"));
    assert!(!is_clipboard_read_shape("clipboard", "poll"));
    assert!(!is_clipboard_read_shape("clipboard", "monitor"));
    assert!(!is_clipboard_read_shape("clipboard", "history"));
    assert!(!is_clipboard_read_shape("clipboard", "watch"));
    assert!(!is_clipboard_read_shape("uia.input", "execute"));
    assert!(is_clipboard_write_shape("clipboard", "write"));
    assert!(!is_clipboard_write_shape("clipboard", "read"));
    assert!(!is_clipboard_write_shape("clipboard", "subscribe"));
    assert!(!is_clipboard_write_shape("clipboard", "paste"));
    for operation in ["subscribe", "poll", "monitor", "history", "watch"] {
        assert!(
            is_denied_clipboard_shape("clipboard", operation),
            "operation must stay denied: {operation}"
        );
    }
    assert!(!is_denied_clipboard_shape("clipboard", "read"));
    assert!(!is_denied_clipboard_shape("clipboard", "write"));
    assert_eq!(MAX_CLIPBOARD_BYTES, 65536);
    assert_eq!(UNICODE_TEXT_FORMAT, "unicode-text");
    assert_eq!(CLIPBOARD_SCHEMA, "orcel-clipboard-read-v1");
    assert_eq!(WRITE_SCHEMA, "orcel-clipboard-write-v1");
}

#[test]
fn happy_path_text_read_returns_bounded_text_with_secret_free_evidence() {
    let adapter = FakeClipboardAdapter::with_text(7, "deploy the staging build at noon");
    let outcome = read(&adapter, None).unwrap();
    assert_eq!(outcome.text, "deploy the staging build at noon");
    assert_eq!(outcome.evidence["schema"], CLIPBOARD_SCHEMA);
    assert_eq!(outcome.evidence["action"], "read");
    assert_eq!(outcome.evidence["format"], UNICODE_TEXT_FORMAT);
    assert_eq!(outcome.evidence["sequence"], 7);
    assert_eq!(outcome.evidence["byte_length"], 32);
    assert_eq!(outcome.evidence["workspace_id"], WORKSPACE);
    assert_eq!(outcome.evidence["policy_revision"], POLICY);
    let digest = outcome.evidence["content_digest"]
        .as_str()
        .expect("content digest");
    assert_eq!(digest.len(), 64);
    assert!(digest.chars().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(digest, clipboard_content_digest(&outcome.text));
    for key in [
        "text", "content", "password", "secret", "token", "approval", "pixels",
    ] {
        assert!(
            outcome.evidence.get(key).is_none(),
            "evidence must not carry {key}"
        );
    }
}

#[test]
fn empty_clipboard_fails_closed() {
    let adapter = FakeClipboardAdapter::empty(3);
    let error = read(&adapter, None).expect_err("empty clipboard must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
}

#[test]
fn non_text_clipboard_fails_closed_without_binary_transfer() {
    let adapter = FakeClipboardAdapter::non_text(3);
    let error = read(&adapter, None).expect_err("non-text content must fail");
    assert_eq!(error.code, FailureCode::CapabilityDenied);
}

#[test]
fn locked_clipboard_fails_closed_as_unavailable() {
    let adapter = FakeClipboardAdapter::locked(3);
    let error = read(&adapter, None).expect_err("locked clipboard must fail");
    assert_eq!(error.code, FailureCode::ProviderUnavailable);
}

#[test]
fn exact_size_boundary_accepts_limit_minus_one_and_limit() {
    let at_limit = FakeClipboardAdapter::with_text(1, "a".repeat(MAX_CLIPBOARD_BYTES));
    let outcome = read(&at_limit, None).unwrap();
    assert_eq!(outcome.evidence["byte_length"], MAX_CLIPBOARD_BYTES as u64);
    let below_limit = FakeClipboardAdapter::with_text(1, "a".repeat(MAX_CLIPBOARD_BYTES - 1));
    let outcome = read(&below_limit, None).unwrap();
    assert_eq!(
        outcome.evidence["byte_length"],
        (MAX_CLIPBOARD_BYTES - 1) as u64
    );
}

#[test]
fn limit_plus_one_and_pathological_encoding_fail_closed() {
    let over_limit = FakeClipboardAdapter::with_text(1, "a".repeat(MAX_CLIPBOARD_BYTES + 1));
    let error = read(&over_limit, None).expect_err("oversized content must fail");
    assert_eq!(error.code, FailureCode::OutputLimit);
    // 65535 ASCII bytes plus one two-byte character is 65537 bytes.
    let mut pathological = "a".repeat(MAX_CLIPBOARD_BYTES - 1);
    pathological.push('\u{e9}');
    assert_eq!(pathological.len(), MAX_CLIPBOARD_BYTES + 1);
    let adapter = FakeClipboardAdapter::with_text(1, pathological);
    let error = read(&adapter, None).expect_err("unexpected encoding size must fail");
    assert_eq!(error.code, FailureCode::OutputLimit);
}

#[test]
fn secret_families_are_denied_without_leaking_bytes() {
    // Every fixture below is synthetic and credential-shaped only: the
    // bodies are sequential or repeated characters with no live secret
    // material. Several are assembled with `concat!` so repository
    // secret-scanning push protection does not false-positive on the
    // non-secret fixtures; runtime strings keep the documented shapes.
    let secrets = [
        "deploy password=hunter2 tonight",
        "login passwd: s3cr3t-value",
        "config pwd=abc123",
        "my api_key is AK-999",
        "set apikey=ZZ-112233",
        "rotate the api-key now: K-1",
        "api_secret=shhh-do-not-share",
        "client_secret=shhh-do-not-share",
        "Authorization: Bearer abcdef123456",
        "token=tok_live_999",
        "auth_token=tok_live_999",
        "access_token=tok_live_999",
        concat!("aws_access_key_id=", "AKIAIOSFODNN7EXAMPLE"),
        concat!("aws_secret_access_key=", "wJalrXUtnFEMI"),
        concat!("ghp_", "1234567890abcdef1234567890abcdef1234"),
        concat!("xox", "b-123456789012-abcdefghijklmnopqrstuvwx"),
        concat!("sk-li", "ve-abcdefgh12345678"),
        "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAC3",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIE",
        "ssh private_key material below",
        "mnemonic rescue phrase list enclosed",
        "write down this seed phrase now",
        "account recovery phrase: apple banana",
        "use recovery-code 482913 on file",
        "paste the orcel-approval nonce here: 123",
        "export orcel-trust state tonight",
        "connectionstring=Server=db;Password=x;",
    ];
    for secret in secrets {
        let adapter = FakeClipboardAdapter::with_text(1, secret);
        let error = read(&adapter, None).expect_err("secret content must fail");
        assert_eq!(error.code, FailureCode::CapabilityDenied, "input: {secret}");
        assert!(
            !error.message.contains(secret),
            "denial must not quote secret bytes"
        );
    }
}

#[test]
fn innocent_text_without_credential_shapes_is_returned() {
    let adapter = FakeClipboardAdapter::with_text(
        1,
        "remind me to rotate the quarterly report password policy discussion",
    );
    let outcome = read(&adapter, None).unwrap();
    assert!(outcome.text.contains("password policy"));
}

#[test]
fn sequence_drift_after_approval_fails_closed() {
    let adapter = FakeClipboardAdapter::with_text(7, "stable clipboard text");
    let outcome = read(&adapter, Some(7)).unwrap();
    assert_eq!(outcome.evidence["sequence"], 7);
    adapter.bump_sequence();
    let error = read(&adapter, Some(7)).expect_err("drifted sequence must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    let wrong = read(&adapter, Some(6)).expect_err("wrong sequence must fail");
    assert_eq!(wrong.code, FailureCode::TargetStale);
}

#[test]
fn approval_digest_binds_sequence_workspace_and_policy() {
    let first = clipboard_read_digest(WORKSPACE, POLICY, 7);
    assert_eq!(first.len(), 64);
    assert!(first.chars().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(first, clipboard_read_digest(WORKSPACE, POLICY, 7));
    assert_ne!(first, clipboard_read_digest(WORKSPACE, POLICY, 8));
    assert_ne!(first, clipboard_read_digest("other-workspace", POLICY, 7));
    assert_ne!(first, clipboard_read_digest(WORKSPACE, "sg-000037-v1", 7));
}

#[test]
fn malformed_scope_fails_closed() {
    let adapter = FakeClipboardAdapter::with_text(1, "plain text");
    let error =
        read_bounded_text(&adapter, None, "", POLICY).expect_err("empty workspace must fail");
    assert_eq!(error.code, FailureCode::InvalidRequest);
    let error =
        read_bounded_text(&adapter, None, WORKSPACE, "").expect_err("empty policy must fail");
    assert_eq!(error.code, FailureCode::InvalidRequest);
    let error = read_bounded_text(&adapter, None, "other-workspace", POLICY).unwrap();
    assert_eq!(error.evidence["workspace_id"], "other-workspace");
}

#[test]
fn cross_policy_reads_bind_their_own_revision() {
    let adapter = FakeClipboardAdapter::with_text(1, "plain text");
    let outcome = read_bounded_text(&adapter, None, WORKSPACE, "sg-000037-v1").unwrap();
    assert_eq!(outcome.evidence["policy_revision"], "sg-000037-v1");
}

#[test]
fn native_adapter_reports_honest_typed_results() {
    // The Win32 clipboard is process-global: parallel tests must not
    // hold a locked clipboard view while another test empties or
    // replaces clipboard data, so native clipboard tests serialize on
    // this mutex. Product dispatch paths are single-call and unaffected.
    let _guard = native_clipboard_test_lock();
    let native = NativeAdapter::new();
    match native.sequence_number() {
        Ok(sequence) => {
            // Win32 sequence numbers are 32-bit; the macOS and Linux adapter
            // derives a 64-bit sequence from the clipboard text.
            if cfg!(windows) {
                assert!(sequence <= u32::MAX as u64);
            }
            match native.read_unicode_text() {
                Ok(text) => {
                    // The raw adapter returns content without policy
                    // filtering; secret denial lives in the approved
                    // read pipeline, not in the adapter.
                    assert!(!text.is_empty());
                    assert!(text.len() <= MAX_CLIPBOARD_BYTES);
                }
                Err(error) => {
                    assert!(matches!(
                        error.code,
                        FailureCode::ProviderUnavailable
                            | FailureCode::CapabilityDenied
                            | FailureCode::TargetStale
                            | FailureCode::OutputLimit
                    ));
                }
            }
        }
        Err(error) => {
            assert_eq!(error.code, FailureCode::ProviderUnavailable);
            #[cfg(windows)]
            panic!("native sequence state must be queryable on Windows");
        }
    }
}

fn write(adapter: &FakeClipboardAdapter, text: &str) -> Result<WriteOutcome, ClipboardError> {
    write_bounded_text(adapter, text, WORKSPACE, POLICY)
}

#[test]
fn happy_path_text_write_places_bounded_text_with_secret_free_evidence() {
    let adapter = FakeClipboardAdapter::with_text(7, "old clipboard text");
    let outcome = write(&adapter, "deploy the staging build at noon").unwrap();
    assert_eq!(outcome.resulting_sequence, 8);
    assert_eq!(outcome.evidence["schema"], WRITE_SCHEMA);
    assert_eq!(outcome.evidence["action"], "write");
    assert_eq!(outcome.evidence["format"], UNICODE_TEXT_FORMAT);
    assert_eq!(outcome.evidence["byte_length"], 32);
    assert_eq!(outcome.evidence["resulting_sequence"], 8);
    assert_eq!(outcome.evidence["workspace_id"], WORKSPACE);
    assert_eq!(outcome.evidence["policy_revision"], POLICY);
    let digest = outcome.evidence["content_digest"]
        .as_str()
        .expect("content digest");
    assert_eq!(digest.len(), 64);
    assert!(digest.chars().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(
        digest,
        clipboard_write_content_digest("deploy the staging build at noon")
    );
    assert_eq!(adapter.writes.get(), 1);
    assert_eq!(
        adapter.last_placed.borrow().as_deref(),
        Some("deploy the staging build at noon")
    );
    for key in [
        "text", "content", "password", "secret", "token", "approval", "pixels",
    ] {
        assert!(
            outcome.evidence.get(key).is_none(),
            "evidence must not carry {key}"
        );
    }
}

#[test]
fn empty_write_text_fails_closed_without_touching_the_adapter() {
    let adapter = FakeClipboardAdapter::with_text(7, "old clipboard text");
    let error = write(&adapter, "").expect_err("empty write must fail");
    assert_eq!(error.code, FailureCode::InvalidRequest);
    assert_eq!(adapter.writes.get(), 0);
    assert!(adapter.last_placed.borrow().is_none());
}

#[test]
fn write_size_boundaries_behave() {
    let adapter = FakeClipboardAdapter::with_text(1, "old");
    let outcome = write(&adapter, &"a".repeat(MAX_CLIPBOARD_BYTES)).unwrap();
    assert_eq!(outcome.evidence["byte_length"], MAX_CLIPBOARD_BYTES as u64);
    let error = write(&adapter, &"a".repeat(MAX_CLIPBOARD_BYTES + 1))
        .expect_err("oversized write must fail");
    assert_eq!(error.code, FailureCode::OutputLimit);
    assert_eq!(adapter.writes.get(), 1);
    // 65535 ASCII bytes plus one two-byte character is 65537 bytes.
    let mut pathological = "a".repeat(MAX_CLIPBOARD_BYTES - 1);
    pathological.push('\u{e9}');
    let error = write(&adapter, &pathological).expect_err("encoding size must fail");
    assert_eq!(error.code, FailureCode::OutputLimit);
}

#[test]
fn write_secret_families_are_denied_before_placement() {
    // Synthetic credential-shaped fixtures only; bodies are sequential
    // or repeated characters with no live secret material. Assembled
    // with `concat!` where noted so repository secret-scanning push
    // protection does not false-positive on the non-secret fixtures.
    let secrets = [
        "deploy password=hunter2 tonight",
        "api_secret=shhh-do-not-share",
        "Authorization: Bearer abcdef123456",
        "token=tok_live_999",
        concat!("ghp_", "1234567890abcdef1234567890abcdef1234"),
        concat!("xox", "b-123456789012-abcdefghijklmnopqrstuvwx"),
        "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAC3",
        "ssh private_key material below",
        "write down this seed phrase now",
        "use recovery-code 482913 on file",
        "paste the orcel-approval nonce here: 123",
    ];
    for secret in secrets {
        let adapter = FakeClipboardAdapter::with_text(1, "old");
        let error = write(&adapter, secret).expect_err("secret write must fail");
        assert_eq!(error.code, FailureCode::CapabilityDenied);
        assert!(
            !error.message.contains(secret),
            "denial must not quote secret bytes"
        );
        assert_eq!(adapter.writes.get(), 0);
        assert!(adapter.last_placed.borrow().is_none());
    }
}

#[test]
fn locked_adapter_fails_write_closed_as_unavailable() {
    let adapter = FakeClipboardAdapter::locked(3);
    let error = write(&adapter, "plain placement text").expect_err("locked write must fail");
    assert_eq!(error.code, FailureCode::ProviderUnavailable);
}

#[test]
fn write_approval_digest_binds_payload_workspace_and_policy() {
    let digest = clipboard_write_content_digest("placement text");
    let first = clipboard_write_digest(WORKSPACE, POLICY, &digest, 14);
    assert_eq!(first.len(), 64);
    assert!(first.chars().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(
        first,
        clipboard_write_digest(WORKSPACE, POLICY, &digest, 14)
    );
    assert_ne!(
        first,
        clipboard_write_digest(
            WORKSPACE,
            POLICY,
            &clipboard_write_content_digest("other"),
            14
        )
    );
    assert_ne!(
        first,
        clipboard_write_digest(WORKSPACE, POLICY, &digest, 15)
    );
    assert_ne!(
        first,
        clipboard_write_digest("other-workspace", POLICY, &digest, 14)
    );
    assert_ne!(
        first,
        clipboard_write_digest(WORKSPACE, "sg-000039-v1", &digest, 14)
    );
    assert_ne!(
        clipboard_write_content_digest("placement text"),
        clipboard_content_digest("placement text")
    );
}

#[test]
fn write_malformed_scope_fails_closed() {
    let adapter = FakeClipboardAdapter::with_text(1, "old");
    let error = write_bounded_text(&adapter, "plain text", "", POLICY)
        .expect_err("empty workspace must fail");
    assert_eq!(error.code, FailureCode::InvalidRequest);
    let error = write_bounded_text(&adapter, "plain text", WORKSPACE, "")
        .expect_err("empty policy must fail");
    assert_eq!(error.code, FailureCode::InvalidRequest);
    assert_eq!(adapter.writes.get(), 0);
}

#[test]
fn write_then_read_round_trip_with_fresh_sequence() {
    let adapter = FakeClipboardAdapter::with_text(20, "old clipboard text");
    let placed = write(&adapter, "standup notes").unwrap();
    assert_eq!(placed.resulting_sequence, 21);
    let sampled = read(&adapter, Some(21)).unwrap();
    assert_eq!(sampled.text, "standup notes");
    assert_eq!(sampled.evidence["sequence"], 21);
}

#[test]
fn native_write_path_reports_honest_typed_results() {
    let _guard = native_clipboard_test_lock();
    let native = NativeAdapter::new();
    // This test performs one real placement of benign marker text
    // through the Win32 clipboard APIs where an interactive session
    // exists, which genuinely proves the placement path including the
    // resulting sequence number. The marker is non-secret and the
    // mutation is disclosed here; ephemeral CI runners are unaffected
    // beyond their throwaway session clipboard. In headless contexts
    // the adapter must fail closed as unavailable instead of
    // fabricating success.
    match native.write_unicode_text("orcel-write-gating-probe") {
        Ok(sequence) => {
            // Win32 sequence numbers are 32-bit; the macOS and Linux adapter
            // derives a 64-bit sequence from the clipboard text.
            if cfg!(windows) {
                assert!(sequence <= u32::MAX as u64);
            }
        }
        Err(error) => {
            assert!(matches!(
                error.code,
                FailureCode::ProviderUnavailable
                    | FailureCode::CapabilityDenied
                    | FailureCode::OutputLimit
            ));
        }
    }
}

/// SG-000064 live qualification on real Windows: one approved-pipeline
/// placement of benign marker text, then one sequence-bound read of the
/// same text, a stale-sequence read that fails closed, and a secret
/// placement refused before the operating system is touched. Outside an
/// interactive session every step must fail closed as unavailable.
#[test]
fn sg000064_live_clipboard_round_trip_is_sequence_bound_and_secret_safe() {
    let _guard = native_clipboard_test_lock();
    let native = NativeAdapter::new();
    let marker = "orcel-sg000064-live-qualification-marker";
    let placed = match write_bounded_text(&native, marker, WORKSPACE, POLICY) {
        Ok(placed) => placed,
        Err(error) => {
            assert!(matches!(
                error.code,
                FailureCode::ProviderUnavailable | FailureCode::CapabilityDenied
            ));
            eprintln!(
                "SG-000064 live clipboard evidence: UNAVAILABLE ({})",
                error.message
            );
            return;
        }
    };
    // Windows may advance the sequence after placement (clipboard history
    // and synthesized formats), so a read binds the sequence it observes
    // immediately before reading, exactly as dispatch binds the sequence
    // observed before approval.
    let placed_sequence = placed.resulting_sequence;
    let mut sampled = None;
    for _ in 0..20 {
        let observed = native.sequence_number().unwrap();
        // The Win32 sequence only advances; the macOS and Linux sequence
        // is content-derived, so it has no order.
        if cfg!(windows) {
            assert!(observed >= placed_sequence);
        }
        match read_bounded_text(&native, Some(observed), WORKSPACE, POLICY) {
            Ok(outcome) => {
                sampled = Some((observed, outcome));
                break;
            }
            Err(error) => {
                assert_eq!(error.code, FailureCode::TargetStale);
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    }
    let (sequence, sampled) = sampled.expect("a sequence-bound read of the placed text");
    assert_eq!(sampled.text, marker);
    assert_eq!(sampled.evidence["sequence"], sequence);
    let stale = read_bounded_text(&native, Some(sequence.wrapping_sub(1)), WORKSPACE, POLICY)
        .expect_err("a stale sequence must fail closed");
    assert_eq!(stale.code, FailureCode::TargetStale);
    let refused = write_bounded_text(&native, "token=tok_live_sg64", WORKSPACE, POLICY)
        .expect_err("secret placement must be refused");
    assert_eq!(refused.code, FailureCode::CapabilityDenied);
    let still = read_bounded_text(&native, None, WORKSPACE, POLICY).unwrap();
    assert_eq!(
        still.text, marker,
        "a refused secret never reaches the clipboard"
    );
    eprintln!("SG-000064 live clipboard evidence: placed at sequence {placed_sequence}, read back at sequence {sequence}; stale read and secret placement refused");
}

/// XP-15: the oversize and secret refusals hold through the native
/// adapter on every OS, with or without a reachable clipboard, because
/// the approved pipeline refuses before the operating system is touched
/// and the adapter enforces the size bound itself.
#[test]
fn xp15_native_adapter_refuses_oversize_and_secret_text_on_every_os() {
    let _guard = native_clipboard_test_lock();
    let native = NativeAdapter::new();
    let oversize = "a".repeat(MAX_CLIPBOARD_BYTES + 1);
    let refused = write_bounded_text(&native, &oversize, WORKSPACE, POLICY)
        .expect_err("oversize placement must be refused");
    assert_eq!(refused.code, FailureCode::OutputLimit);
    let refused = native
        .write_unicode_text(&oversize)
        .expect_err("the adapter itself must refuse oversize text");
    assert_eq!(refused.code, FailureCode::OutputLimit);
    for secret in [
        "password=hunter2-xp15",
        "-----BEGIN OPENSSH KEY-----",
        "export AWS_SECRET_ACCESS_KEY=xp15",
    ] {
        let refused = write_bounded_text(&native, secret, WORKSPACE, POLICY)
            .expect_err("secret placement must be refused");
        assert_eq!(refused.code, FailureCode::CapabilityDenied);
        assert!(!refused.message.contains(secret));
    }
}

/// XP-15 live roundtrip through the native adapter where a clipboard is
/// reachable: a real Windows session, the macOS pasteboard, or an X11 or
/// data-control Wayland display on Linux. Without one the test reports
/// why and returns, unless `ORCEL_REQUIRE_LIVE_CLIPBOARD=1` is set, as CI
/// sets it on macOS and on Linux under Xvfb, in which case it fails.
#[test]
fn xp15_native_round_trip_where_a_clipboard_is_reachable() {
    let _guard = native_clipboard_test_lock();
    let native = NativeAdapter::new();
    let required = std::env::var("ORCEL_REQUIRE_LIVE_CLIPBOARD").as_deref() == Ok("1");
    let marker = "orcel-xp15-roundtrip-marker \u{2713} caf\u{e9}";
    let placed = match write_bounded_text(&native, marker, WORKSPACE, POLICY) {
        Ok(placed) => placed,
        Err(error) => {
            assert_eq!(error.code, FailureCode::ProviderUnavailable);
            assert!(
                !required,
                "a live clipboard was required but is unavailable: {}",
                error.message
            );
            eprintln!(
                "XP-15 live roundtrip skipped: no clipboard is reachable ({})",
                error.message
            );
            return;
        }
    };
    let mut sampled = None;
    for _ in 0..20 {
        let observed = native.sequence_number().unwrap();
        if let Ok(outcome) = read_bounded_text(&native, Some(observed), WORKSPACE, POLICY) {
            if outcome.text == marker {
                sampled = Some(outcome);
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let sampled = sampled.expect("the placed text reads back through the bounded pipeline");
    assert_eq!(
        sampled.evidence["content_digest"],
        clipboard_content_digest(marker)
    );
    if !cfg!(windows) {
        // The content-derived sequence of the placed text is the one the
        // read observes.
        assert_eq!(sampled.evidence["sequence"], placed.resulting_sequence);
    }
    // Read-side denial on the live clipboard: secret text placed by
    // another party (here the raw adapter, which applies no policy) is
    // refused by the bounded read without quoting it.
    let secret = "password=hunter2-xp15-read";
    native
        .write_unicode_text(secret)
        .expect("raw placement on a reachable clipboard");
    let mut refused = None;
    for _ in 0..20 {
        match read_bounded_text(&native, None, WORKSPACE, POLICY) {
            Err(error) if error.code == FailureCode::CapabilityDenied => {
                refused = Some(error);
                break;
            }
            _ => std::thread::sleep(std::time::Duration::from_millis(50)),
        }
    }
    let refused = refused.expect("a secret on the clipboard must be refused by the bounded read");
    assert!(!refused.message.contains(secret));
    // Leave benign text behind.
    write_bounded_text(&native, marker, WORKSPACE, POLICY).unwrap();
}
