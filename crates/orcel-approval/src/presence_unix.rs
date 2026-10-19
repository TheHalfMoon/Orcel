// SPDX-License-Identifier: FSL-1.1-MIT
// Portions copyright (c) 2026 Cua AI, Inc.; modifications copyright Orcel.

//! XP-09 STRONG user presence off Windows, and the interactive-session
//! probe the macOS SOFT dialog shares.
//!
//! macOS: LocalAuthentication (`LAContext`,
//! `evaluatePolicy:localizedReason:reply:`) with
//! `LAPolicyDeviceOwnerAuthentication`: Touch ID, an Apple Watch or the
//! login password. It runs in the broker's own process; there is no
//! helper, so no answer arrives over IPC and no helper signature has to be
//! checked (XP-09 step 2 applies only "if LocalAuthentication must run in
//! a GUI-capable signed helper"). The verifier reports only whether the
//! person passed; the broker binds that to the request's nonce and digest
//! and the ledger issues, expires and consumes the token as on Windows.
//!
//! Linux (XP-10) adds its polkit `auth_self` verifier and session probe
//! next to the macOS ones, under `cfg(target_os = "linux")`.
//!
//! Provenance (T-CUA-20, COPY_ADAPT): the macOS backend is adapted from
//! cua@a802eaf26ca97616a6bf0de6a29729a9346fbb1f
//! `libs/cua/crates/cua-teleport/src/biometric.rs`
//! (blob 3fa6cc4132ef2d57ce8b57740fbeb9fb8b6f37cf), FSL-1.1-MIT, used under
//! FD-04; notice in `docs/orcel/notices/cua-FSL-1.1-MIT.txt`. Orcel's
//! modifications:
//! - both donor bypass variables are deleted, with every code path that
//!   read them: the skip variable, which returned success without asking
//!   in any debug build (including `cargo test`), and the operator
//!   override that let a sensitive export proceed unverified. No
//!   environment variable can produce a STRONG approval;
//! - the session probe runs first: no GUI session (launchd background,
//!   SSH) or an automation runner is `unavailable` before LocalAuthentication
//!   is touched, never a SOFT downgrade;
//! - LAError codes map onto Orcel's `PresenceError` reasons, and unknown
//!   codes are a denial;
//! - a reply that does not arrive in `STRONG_VERIFY_TIMEOUT_MS` is a
//!   timeout (the donor called it cancelled) and the context is
//!   invalidated so the prompt is withdrawn;
//! - the prompt reason names the request (nonce and digest prefixes,
//!   bounded and escaped action and workspace);
//! - the Windows (Hello + CredUI password fallback) and Linux branches and
//!   the export-manifest helpers are not taken.

// Off macOS this module is compiled only into tests, which run its pure
// rules (session classification, LAError mapping, the STRONG flow) on
// every OS. XP-10 widens the cfg when it adds Linux.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use crate::soft_macos::display_field;
#[cfg(target_os = "macos")]
use crate::PresenceVerifier;
use crate::{InputLeaseGuard, PresenceAttestation, PresenceContext, PresenceError};

/// The method name the ledger records for a macOS STRONG approval.
pub const MAC_LOCAL_AUTH_METHOD: &str = "macos-local-authentication";

/// Whether a person can be asked in the current session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionState {
    /// A login session with access to the window server.
    Interactive,
    /// A CI runner: nobody is there to answer, so nothing is shown.
    Automation,
    /// No GUI: a launchd background job, an SSH login, or a probe failure.
    NoGraphicSession,
}

/// The current session. Every state but `Interactive` fails closed.
pub(crate) fn session_state() -> SessionState {
    classify_session(automation_environment(), session_info())
}

/// A CI runner has no person at the keyboard (the Windows Hello verifier
/// makes the same check). This can only make approvals unavailable.
fn automation_environment() -> bool {
    std::env::var_os("CI").is_some() || std::env::var_os("GITHUB_ACTIONS").is_some()
}

/// `sessionHasGraphicAccess` from Security/AuthSession.h.
pub(crate) const SESSION_HAS_GRAPHIC_ACCESS: u32 = 0x0010;
/// `sessionHasTTY` from Security/AuthSession.h (tests build SSH-like sets).
#[cfg(test)]
pub(crate) const SESSION_HAS_TTY: u32 = 0x0020;
/// `sessionIsRemote` from Security/AuthSession.h (for example SSH).
pub(crate) const SESSION_IS_REMOTE: u32 = 0x1000;

/// Classifies the session from the automation check and the
/// `SessionGetInfo` result (attribute bits, or the failing status). Only a
/// local session with graphic access is interactive; a probe error, no
/// graphic access, or a remote session fails closed.
pub(crate) fn classify_session(automation: bool, info: Result<u32, i32>) -> SessionState {
    if automation {
        return SessionState::Automation;
    }
    match info {
        Ok(bits) if bits & SESSION_HAS_GRAPHIC_ACCESS != 0 && bits & SESSION_IS_REMOTE == 0 => {
            SessionState::Interactive
        }
        _ => SessionState::NoGraphicSession,
    }
}

/// The caller's security-session attribute bits, or the `SessionGetInfo`
/// status when the session cannot be read.
#[cfg(target_os = "macos")]
pub(crate) fn session_info() -> Result<u32, i32> {
    /// `callerSecuritySession`, `((SecuritySessionId)-1)`.
    const CALLER_SECURITY_SESSION: u32 = u32::MAX;

    #[link(name = "Security", kind = "framework")]
    extern "C" {
        fn SessionGetInfo(session: u32, session_id: *mut u32, attributes: *mut u32) -> i32;
    }

    let mut session_id: u32 = 0;
    let mut attributes: u32 = 0;
    // SAFETY: SessionGetInfo reads the caller's own audit session and writes
    // two UInt32 values; both out-pointers are valid, aligned locals that
    // live for the call.
    let status =
        unsafe { SessionGetInfo(CALLER_SECURITY_SESSION, &mut session_id, &mut attributes) };
    if status == 0 {
        Ok(attributes)
    } else {
        Err(status)
    }
}

/// Test builds off macOS (the module is compiled there only for its pure
/// rules): there is no session to read.
#[cfg(not(target_os = "macos"))]
pub(crate) fn session_info() -> Result<u32, i32> {
    Err(-1)
}

/// What one LocalAuthentication evaluation reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LocalAuthOutcome {
    Success,
    /// `canEvaluatePolicy` refused: no password, no biometry, no hardware.
    CannotEvaluate,
    /// The evaluation failed with this LAError code.
    Error(isize),
    /// No reply within the deadline; the prompt was withdrawn.
    TimedOut,
}

/// Maps an LAError code onto a fail-closed presence error.
pub(crate) fn classify(code: isize) -> PresenceError {
    match code {
        // LAErrorUserCancel, LAErrorSystemCancel, LAErrorAppCancel.
        -2 | -4 | -9 => PresenceError::cancelled(
            "strong user-presence verification was cancelled; STRONG approval fails closed",
        ),
        // PasscodeNotSet, BiometryNotAvailable, BiometryNotEnrolled,
        // Watch/CompanionNotAvailable, BiometryNotPaired, BiometryDisconnected,
        // NotInteractive.
        -5 | -6 | -7 | -11 | -12 | -13 | -1004 => PresenceError::unavailable(
            "LocalAuthentication cannot ask for presence in this session; STRONG approval fails closed",
        ),
        // InvalidContext: the evaluation itself broke.
        -10 => PresenceError::failed(
            "LocalAuthentication context was invalidated; STRONG approval fails closed",
        ),
        // AuthenticationFailed, UserFallback, BiometryLockout and anything
        // unknown: the person was not confirmed.
        _ => PresenceError::denied(
            "strong user-presence verification was denied; STRONG approval fails closed",
        ),
    }
}

/// The text LocalAuthentication shows after "<process> is trying to".
pub(crate) fn strong_reason(ctx: &PresenceContext) -> String {
    let nonce_prefix: String = ctx.nonce.chars().take(8).collect();
    let digest_prefix: String = ctx.digest.chars().take(12).collect();
    format!(
        "approve Orcel STRONG {} {} for {} in workspace {}",
        display_field(&nonce_prefix, 8),
        display_field(&digest_prefix, 12),
        display_field(&ctx.action, 256),
        display_field(&ctx.workspace_id, 128),
    )
}

/// The platform-independent STRONG flow: validate, gate on the session,
/// evaluate once, and bind a success to this context's nonce and digest.
pub(crate) fn verify_with(
    ctx: &PresenceContext,
    lease: &InputLeaseGuard,
    method: &'static str,
    session: SessionState,
    evaluate: impl FnOnce(&str) -> LocalAuthOutcome,
) -> Result<PresenceAttestation, PresenceError> {
    if !lease.is_suspended() {
        return Err(PresenceError::invalid(
            "strong verification requires a suspended input lease",
        ));
    }
    if ctx.nonce.trim().is_empty() || ctx.digest.trim().is_empty() {
        return Err(PresenceError::invalid(
            "strong verification context is malformed",
        ));
    }
    match session {
        SessionState::Interactive => {}
        SessionState::Automation => {
            return Err(PresenceError::unavailable(
                "no person can answer a presence prompt on an automation runner; STRONG approval fails closed",
            ))
        }
        SessionState::NoGraphicSession => {
            return Err(PresenceError::unavailable(
                "no GUI login session (background or SSH); STRONG approval fails closed without SOFT downgrade",
            ))
        }
    }
    match evaluate(&strong_reason(ctx)) {
        LocalAuthOutcome::Success => Ok(PresenceAttestation {
            method: method.to_owned(),
            verified_at_ms: crate::now_ms(),
            nonce: ctx.nonce.clone(),
            digest: ctx.digest.clone(),
        }),
        LocalAuthOutcome::CannotEvaluate => Err(PresenceError::unavailable(
            "this Mac has neither Touch ID nor a login password usable for presence; STRONG approval fails closed",
        )),
        LocalAuthOutcome::Error(code) => Err(classify(code)),
        LocalAuthOutcome::TimedOut => Err(PresenceError::timeout(
            "strong user-presence verification timed out; STRONG approval fails closed",
        )),
    }
}

/// STRONG presence on macOS through LocalAuthentication.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, Default)]
pub struct MacLocalAuthPresenceVerifier;

#[cfg(target_os = "macos")]
impl MacLocalAuthPresenceVerifier {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(target_os = "macos")]
impl PresenceVerifier for MacLocalAuthPresenceVerifier {
    fn method(&self) -> &'static str {
        MAC_LOCAL_AUTH_METHOD
    }

    fn is_available(&self) -> bool {
        session_state() == SessionState::Interactive && macos::can_evaluate()
    }

    fn verify(
        &self,
        ctx: &PresenceContext,
        lease: &InputLeaseGuard,
    ) -> Result<PresenceAttestation, PresenceError> {
        verify_with(ctx, lease, self.method(), session_state(), |reason| {
            macos::evaluate(
                reason,
                std::time::Duration::from_millis(crate::STRONG_VERIFY_TIMEOUT_MS),
            )
        })
    }
}

#[cfg(target_os = "macos")]
mod macos {
    //! `evaluatePolicy:localizedReason:reply:` returns at once and calls the
    //! reply block on a framework queue; the block hands the result back
    //! over a channel and the caller waits with a deadline. The `LAContext`
    //! stays alive across the wait so the evaluation is not cancelled by
    //! its deallocation.

    use std::sync::mpsc;
    use std::time::Duration;

    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};

    use super::LocalAuthOutcome;

    /// Touch ID, Apple Watch, or the login password.
    const POLICY: LAPolicy = LAPolicy::DeviceOwnerAuthentication;

    pub(super) fn can_evaluate() -> bool {
        // SAFETY: `LAContext::new` returns a fresh, owned context.
        let context = unsafe { LAContext::new() };
        // SAFETY: `context` is a valid LAContext; the call only reads state
        // and shows nothing.
        unsafe { context.canEvaluatePolicy_error(POLICY) }.is_ok()
    }

    pub(super) fn evaluate(reason: &str, timeout: Duration) -> LocalAuthOutcome {
        // SAFETY: `LAContext::new` returns a fresh, owned context.
        let context = unsafe { LAContext::new() };
        // Preflight: a policy that cannot be evaluated (no password, no
        // biometry) is unavailable, not a prompt bound to fail.
        // SAFETY: `context` is a valid LAContext; the call only reads state.
        if unsafe { context.canEvaluatePolicy_error(POLICY) }.is_err() {
            return LocalAuthOutcome::CannotEvaluate;
        }

        // LocalAuthentication raises an exception on an empty reason; the
        // caller always supplies one, and this keeps it that way.
        let reason = if reason.trim().is_empty() {
            "approve an Orcel STRONG operation"
        } else {
            reason
        };
        let ns_reason = NSString::from_str(reason);
        let (tx, rx) = mpsc::channel::<LocalAuthOutcome>();

        // The reply block runs on a framework queue; `Sender` is `Send`, so
        // the block is sendable as `evaluatePolicy` requires.
        let reply = RcBlock::new(move |success: Bool, error: *mut NSError| {
            let outcome = if success.as_bool() {
                LocalAuthOutcome::Success
            } else if error.is_null() {
                // A failure without an error object is still a failure.
                LocalAuthOutcome::Error(-1)
            } else {
                // SAFETY: on failure LocalAuthentication passes a valid
                // NSError that lives for the duration of the block; it is
                // only read here.
                LocalAuthOutcome::Error(unsafe { (*error).code() })
            };
            let _ = tx.send(outcome);
        });

        // SAFETY: `context`, `ns_reason` and `reply` are valid and outlive
        // the wait below; the framework copies the block for its own use,
        // and the block only captures a `Send` channel sender.
        unsafe {
            context.evaluatePolicy_localizedReason_reply(POLICY, &ns_reason, &reply);
        }

        match rx.recv_timeout(timeout) {
            Ok(outcome) => outcome,
            Err(_) => {
                // SAFETY: `context` is a valid LAContext; invalidating it
                // withdraws the prompt and makes any late reply a failure,
                // which nobody receives.
                unsafe { context.invalidate() };
                LocalAuthOutcome::TimedOut
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FailureCode, PresenceFailureReason};

    fn ctx() -> PresenceContext {
        PresenceContext::new("nonce-xp09-0001", "d".repeat(64), "default", "delete file")
    }

    fn lease() -> InputLeaseGuard {
        InputLeaseGuard::suspend_for_presence()
    }

    #[test]
    fn xp09_success_is_bound_to_the_context_nonce_and_digest() {
        let ctx = ctx();
        let attestation = verify_with(
            &ctx,
            &lease(),
            MAC_LOCAL_AUTH_METHOD,
            SessionState::Interactive,
            |_| LocalAuthOutcome::Success,
        )
        .expect("verified");
        assert_eq!(attestation.nonce, ctx.nonce);
        assert_eq!(attestation.digest, ctx.digest);
        assert_eq!(attestation.method, MAC_LOCAL_AUTH_METHOD);
    }

    #[test]
    fn xp09_no_gui_session_and_automation_fail_closed_without_prompting() {
        for (session, text) in [
            (SessionState::NoGraphicSession, "no GUI login session"),
            (SessionState::Automation, "automation runner"),
        ] {
            let mut asked = false;
            let error = verify_with(&ctx(), &lease(), MAC_LOCAL_AUTH_METHOD, session, |_| {
                asked = true;
                LocalAuthOutcome::Success
            })
            .expect_err("fails closed");
            assert!(!asked, "{session:?} must not reach LocalAuthentication");
            assert_eq!(error.reason, PresenceFailureReason::Unavailable);
            assert_eq!(error.code, FailureCode::ApprovalUnavailable);
            assert!(error.message.contains(text), "{}", error.message);
        }
    }

    #[test]
    fn xp09_cancel_timeout_and_failures_fail_closed() {
        let cases = [
            (
                LocalAuthOutcome::Error(-2),
                PresenceFailureReason::Cancelled,
            ),
            (
                LocalAuthOutcome::Error(-4),
                PresenceFailureReason::Cancelled,
            ),
            (
                LocalAuthOutcome::Error(-9),
                PresenceFailureReason::Cancelled,
            ),
            (LocalAuthOutcome::Error(-1), PresenceFailureReason::Denied),
            (LocalAuthOutcome::Error(-3), PresenceFailureReason::Denied),
            (LocalAuthOutcome::Error(-8), PresenceFailureReason::Denied),
            (LocalAuthOutcome::Error(-999), PresenceFailureReason::Denied),
            (
                LocalAuthOutcome::Error(-5),
                PresenceFailureReason::Unavailable,
            ),
            (
                LocalAuthOutcome::Error(-1004),
                PresenceFailureReason::Unavailable,
            ),
            (LocalAuthOutcome::Error(-10), PresenceFailureReason::Failed),
            (
                LocalAuthOutcome::CannotEvaluate,
                PresenceFailureReason::Unavailable,
            ),
            (LocalAuthOutcome::TimedOut, PresenceFailureReason::Timeout),
        ];
        for (outcome, reason) in cases {
            let error = verify_with(
                &ctx(),
                &lease(),
                MAC_LOCAL_AUTH_METHOD,
                SessionState::Interactive,
                |_| outcome,
            )
            .expect_err("fails closed");
            assert_eq!(error.reason, reason, "{outcome:?}");
        }
    }

    #[test]
    fn xp09_malformed_context_or_unsuspended_lease_is_refused() {
        let mut released = lease();
        released.suspended = false;
        let error = verify_with(
            &ctx(),
            &released,
            MAC_LOCAL_AUTH_METHOD,
            SessionState::Interactive,
            |_| LocalAuthOutcome::Success,
        )
        .expect_err("lease");
        assert_eq!(error.reason, PresenceFailureReason::InvalidResponse);
        let empty = PresenceContext::new(" ", "digest", "default", "act");
        let error = verify_with(
            &empty,
            &lease(),
            MAC_LOCAL_AUTH_METHOD,
            SessionState::Interactive,
            |_| LocalAuthOutcome::Success,
        )
        .expect_err("nonce");
        assert_eq!(error.reason, PresenceFailureReason::InvalidResponse);
    }

    #[test]
    fn xp09_reason_names_the_request_and_escapes_the_action() {
        let ctx = PresenceContext::new(
            "abcdefgh-rest",
            "0123456789abcdef",
            "ws",
            "rm\nApproved: yes\u{202e}",
        );
        let reason = strong_reason(&ctx);
        assert!(reason.starts_with("approve Orcel STRONG abcdefgh 0123456789ab for "));
        assert!(!reason.contains('\n'));
        assert!(!reason.contains('\u{202e}'));
        assert!(
            reason.contains("rm\\u{a}Approved: yes\\u{202e}"),
            "{reason}"
        );
    }

    #[test]
    fn xp09_session_classification_fails_closed() {
        // The GitHub macos-latest runner reports 0x2030: graphic access, a
        // TTY and an undocumented bit. Only the automation guard stops it.
        let runner = 0x2030;
        assert_eq!(
            classify_session(false, Ok(runner)),
            SessionState::Interactive
        );
        assert_eq!(classify_session(true, Ok(runner)), SessionState::Automation);
        let local_gui = SESSION_HAS_GRAPHIC_ACCESS;
        assert_eq!(
            classify_session(false, Ok(local_gui)),
            SessionState::Interactive
        );
        let cases = [
            // launchd background: no graphic access.
            Ok(0),
            // SSH: a remote TTY session without graphic access.
            Ok(SESSION_HAS_TTY | SESSION_IS_REMOTE),
            // Remote even if it claims graphic access.
            Ok(SESSION_HAS_GRAPHIC_ACCESS | SESSION_IS_REMOTE),
            Ok(SESSION_HAS_TTY),
            // SessionGetInfo failed (errSessionInvalidId and others).
            Err(-60_500),
            Err(-1),
        ];
        for info in cases {
            assert_eq!(
                classify_session(false, info),
                SessionState::NoGraphicSession,
                "{info:?}"
            );
            assert_eq!(classify_session(true, info), SessionState::Automation);
        }
    }

    /// S-24: the donor's two bypass variables are gone from the shipped
    /// code, and the only environment reads in it are the automation
    /// check, which can only make STRONG unavailable.
    #[test]
    fn xp09_donor_bypass_variables_are_not_read_by_shipped_code() {
        // A Windows checkout may have CRLF line endings.
        let source = include_str!("presence_unix.rs").replace("\r\n", "\n");
        let (shipped, tests) = source
            .split_once("#[cfg(test)]\nmod tests {")
            .expect("the test module marker is present");
        // The split really separated the module from its tests.
        assert!(tests.contains("fn xp09_donor_bypass_variables_are_not_read_by_shipped_code"));
        assert!(!shipped.contains("fn xp09_"));
        let donor_prefix = ["CUA", "_ENV"].concat();
        assert!(!shipped.contains(&donor_prefix));
        assert!(!shipped.contains("SENSITIVE"));
        let reads: Vec<&str> = shipped
            .lines()
            .filter(|line| line.contains("env::var"))
            .collect();
        assert_eq!(reads.len(), 1, "{reads:?}");
        assert!(reads[0].contains("\"CI\"") && reads[0].contains("\"GITHUB_ACTIONS\""));
        assert!(!shipped.contains("env::vars"));
        let automation = verify_with(
            &ctx(),
            &lease(),
            MAC_LOCAL_AUTH_METHOD,
            SessionState::Automation,
            |_| LocalAuthOutcome::Success,
        );
        assert!(automation.is_err());
    }
}
