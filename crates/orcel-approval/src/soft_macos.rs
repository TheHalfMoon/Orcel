//! XP-09 SOFT approval on macOS: a system-owned `CFUserNotification`
//! alert (caution level) drawn by the UserNotificationCenter agent, not by
//! Orcel or the Control Room. BUILD_NEW: no donor presents an
//! approval-style system modal.
//!
//! The dialog only reports the person's answer. The answer carries the
//! nonce and digest of the request it was shown for, `decide` refuses it
//! for any other request, and the broker then records it in the existing
//! ledger, which issues the single-use, expiring token exactly as for the
//! Windows `MessageBoxW` prompt.
//!
//! Fail closed: the default button (Return) is Deny; Approve is the
//! alternate button. Cancel, a dismissal and the timeout all deny. No GUI
//! session or an automation runner is `unavailable` without showing
//! anything, and a dialog that cannot be shown is `unavailable`.
//!
//! The body has the same lines as the Windows prompt. Every field from the
//! request is shown exactly but bounded, and control, line-break, bidi and
//! zero-width characters are escaped as `\u{..}` so a field cannot fake
//! another line of the dialog.

// The formatting, escaping and decision rules are compiled and tested on
// every OS; only macOS shows the dialog.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use crate::presence_unix::SessionState;
use crate::{ApprovalClass, ApprovalDecision, ApprovalError, ApprovalPrompt};

/// How long the dialog waits for an answer before it denies.
pub(crate) const SOFT_PROMPT_TIMEOUT_SECS: f64 = 120.0;
pub(crate) const DIALOG_HEADER: &str = "Orcel approval SOFT";
pub(crate) const DENY_BUTTON: &str = "Deny";
pub(crate) const APPROVE_BUTTON: &str = "Approve";

const MAX_WORKSPACE_CHARS: usize = 128;
const MAX_ACTION_CHARS: usize = 512;
const MAX_TARGET_CHARS: usize = 512;
const MAX_SUMMARY_CHARS: usize = 1024;
const MAX_DIGEST_CHARS: usize = 128;

/// `kCFUserNotificationDefaultResponse` .. `kCFUserNotificationCancelResponse`.
const RESPONSE_MASK: usize = 0x3;
const ALTERNATE_RESPONSE: usize = 1;

/// Shows `value` exactly when it is printable and short; otherwise escapes
/// the characters that could change the dialog's layout or reading order
/// and cuts it at `max_chars`, saying how much was left out.
pub(crate) fn display_field(value: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for ch in value.chars().take(max_chars) {
        if ch == '\\' {
            out.push_str("\\\\");
        } else if needs_escape(ch) {
            out.push_str(&format!("\\u{{{:x}}}", ch as u32));
        } else {
            out.push(ch);
        }
    }
    let rest = value.chars().count().saturating_sub(max_chars);
    if rest > 0 {
        out.push_str(&format!(" [{rest} more characters not shown]"));
    }
    out
}

fn needs_escape(ch: char) -> bool {
    ch.is_control()
        || matches!(
            ch,
            // Line and paragraph separators.
            '\u{2028}' | '\u{2029}'
            // Bidi embeddings, overrides, isolates and marks.
            | '\u{200e}' | '\u{200f}' | '\u{061c}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
            // Zero-width and invisible formatting characters.
            | '\u{200b}'..='\u{200d}' | '\u{2060}'..='\u{2064}' | '\u{feff}'
            | '\u{00ad}' | '\u{180e}'
        )
}

/// The dialog text: the Windows prompt's lines over bounded, escaped
/// fields.
pub(crate) fn dialog_body(prompt: &ApprovalPrompt) -> String {
    let nonce_prefix: String = prompt.nonce.chars().take(8).collect();
    format!(
        "Orcel requests a local action.\n\nWorkspace: {}\nAction: {}\nTarget: {}\n{}\nDigest: {}\nApproval: SOFT {} (single use, expires in 5 minutes)\n\nApprove this exact operation?",
        display_field(&prompt.workspace_id, MAX_WORKSPACE_CHARS),
        display_field(&prompt.action, MAX_ACTION_CHARS),
        display_field(&prompt.target, MAX_TARGET_CHARS),
        display_field(&prompt.summary, MAX_SUMMARY_CHARS),
        display_field(&prompt.digest, MAX_DIGEST_CHARS),
        display_field(&nonce_prefix, 8),
    )
}

/// What the system dialog reported, tagged with the request it was shown
/// for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DialogAnswer {
    pub(crate) nonce: String,
    pub(crate) digest: String,
    pub(crate) outcome: DialogOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DialogOutcome {
    /// `responseFlags` from `CFUserNotificationDisplayAlert`.
    Response(usize),
    /// The dialog could not be shown (non-zero status, or the text could
    /// not be converted).
    NotShown(i32),
}

/// Refuses no GUI session and automation runners before anything is shown.
pub(crate) fn session_gate(session: SessionState) -> Result<(), ApprovalError> {
    match session {
        SessionState::Interactive => Ok(()),
        SessionState::Automation => Err(ApprovalError::unavailable(
            "no person can answer the approval dialog on an automation runner; SOFT approval fails closed",
        )),
        SessionState::NoGraphicSession => Err(ApprovalError::unavailable(
            "no GUI login session (background or SSH) to show the approval dialog; SOFT approval fails closed",
        )),
    }
}

/// Binds the dialog's answer to `prompt`. Only the Approve button, for
/// this very request, approves.
pub(crate) fn decide(
    prompt: &ApprovalPrompt,
    answer: &DialogAnswer,
) -> Result<ApprovalDecision, ApprovalError> {
    if prompt.approval_class != ApprovalClass::Soft {
        return Err(ApprovalError::unavailable(
            "the SOFT dialog never answers a STRONG request; STRONG requires presence verification",
        ));
    }
    if answer.nonce != prompt.nonce || answer.digest != prompt.digest {
        return Err(ApprovalError::unavailable(
            "the approval dialog's answer belongs to another request; SOFT approval fails closed",
        ));
    }
    match answer.outcome {
        DialogOutcome::Response(flags) if flags & RESPONSE_MASK == ALTERNATE_RESPONSE => {
            Ok(ApprovalDecision::Approved)
        }
        // Deny (default), the unused other button, cancel and timeout.
        DialogOutcome::Response(_) => Ok(ApprovalDecision::Denied),
        DialogOutcome::NotShown(status) => Err(ApprovalError::unavailable(format!(
            "the macOS approval dialog could not be shown (status {status}); SOFT approval fails closed"
        ))),
    }
}

/// The SOFT prompt the broker calls on macOS.
#[cfg(target_os = "macos")]
pub(crate) fn platform_prompt(prompt: &ApprovalPrompt) -> Result<ApprovalDecision, ApprovalError> {
    if prompt.approval_class != ApprovalClass::Soft {
        return Err(ApprovalError::unavailable(
            "the SOFT dialog never answers a STRONG request; STRONG requires presence verification",
        ));
    }
    session_gate(crate::presence_unix::session_state())?;
    let outcome = cf::display_alert(&dialog_body(prompt), SOFT_PROMPT_TIMEOUT_SECS);
    let answer = DialogAnswer {
        nonce: prompt.nonce.clone(),
        digest: prompt.digest.clone(),
        outcome,
    };
    decide(prompt, &answer)
}

#[cfg(target_os = "macos")]
mod cf {
    use std::ffi::c_void;
    use std::ptr;

    use super::{DialogOutcome, APPROVE_BUTTON, DENY_BUTTON, DIALOG_HEADER};

    type CFTypeRef = *const c_void;
    type CFStringRef = *const c_void;
    type CFUrlRef = *const c_void;
    type CFAllocatorRef = *const c_void;
    type CFOptionFlags = usize;
    type CFIndex = isize;

    const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
    const K_CF_USER_NOTIFICATION_CAUTION_ALERT_LEVEL: CFOptionFlags = 2;

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFStringCreateWithBytes(
            alloc: CFAllocatorRef,
            bytes: *const u8,
            num_bytes: CFIndex,
            encoding: u32,
            is_external_representation: u8,
        ) -> CFStringRef;
        fn CFRelease(cf: CFTypeRef);
        fn CFUserNotificationDisplayAlert(
            timeout: f64,
            flags: CFOptionFlags,
            icon_url: CFUrlRef,
            sound_url: CFUrlRef,
            localization_url: CFUrlRef,
            alert_header: CFStringRef,
            alert_message: CFStringRef,
            default_button_title: CFStringRef,
            alternate_button_title: CFStringRef,
            other_button_title: CFStringRef,
            response_flags: *mut CFOptionFlags,
        ) -> i32;
    }

    /// An owned CFString, released on drop.
    struct CfString(CFStringRef);

    impl CfString {
        fn new(value: &str) -> Option<Self> {
            let len = CFIndex::try_from(value.len()).ok()?;
            // SAFETY: `value` is valid UTF-8 of `len` bytes that lives for
            // the call; CoreFoundation copies the bytes (not external
            // representation) and returns an owned reference or null.
            let string = unsafe {
                CFStringCreateWithBytes(
                    ptr::null(),
                    value.as_ptr(),
                    len,
                    K_CF_STRING_ENCODING_UTF8,
                    0,
                )
            };
            (!string.is_null()).then_some(Self(string))
        }
    }

    impl Drop for CfString {
        fn drop(&mut self) {
            // SAFETY: `self.0` is a non-null CFString this wrapper owns
            // (from a Create call) and releases exactly once.
            unsafe { CFRelease(self.0) };
        }
    }

    /// Shows the caution alert and blocks until the person answers or the
    /// timeout passes.
    pub(super) fn display_alert(body: &str, timeout_secs: f64) -> DialogOutcome {
        let (Some(header), Some(message), Some(deny), Some(approve)) = (
            CfString::new(DIALOG_HEADER),
            CfString::new(body),
            CfString::new(DENY_BUTTON),
            CfString::new(APPROVE_BUTTON),
        ) else {
            return DialogOutcome::NotShown(-1);
        };
        let mut response: CFOptionFlags = 0;
        // SAFETY: every CFString is a live, owned reference for the whole
        // call; the URLs and the other button are null, which the API
        // accepts; `response` is a valid out-pointer.
        let status = unsafe {
            CFUserNotificationDisplayAlert(
                timeout_secs,
                K_CF_USER_NOTIFICATION_CAUTION_ALERT_LEVEL,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                header.0,
                message.0,
                deny.0,
                approve.0,
                ptr::null(),
                &mut response,
            )
        };
        if status == 0 {
            DialogOutcome::Response(response)
        } else {
            DialogOutcome::NotShown(status)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FailureCode;

    fn soft_prompt() -> ApprovalPrompt {
        ApprovalPrompt::new_with_clock(
            "default",
            "rev-1",
            "write file",
            "C:/work/a.txt",
            "Replace 3 lines",
            "e".repeat(64),
            5_000,
        )
    }

    fn answer_for(prompt: &ApprovalPrompt, outcome: DialogOutcome) -> DialogAnswer {
        DialogAnswer {
            nonce: prompt.nonce.clone(),
            digest: prompt.digest.clone(),
            outcome,
        }
    }

    #[test]
    fn xp09_only_approve_for_this_request_approves() {
        let prompt = soft_prompt();
        let approve = answer_for(&prompt, DialogOutcome::Response(1));
        assert_eq!(
            decide(&prompt, &approve).expect("decided"),
            ApprovalDecision::Approved
        );
        // Deny (default / Return), other, cancel and timeout all deny.
        for flags in [0usize, 2, 3, 0x100 | 3] {
            let answer = answer_for(&prompt, DialogOutcome::Response(flags));
            assert_eq!(
                decide(&prompt, &answer).expect("decided"),
                ApprovalDecision::Denied,
                "flags {flags:#x}"
            );
        }
        let error = decide(&prompt, &answer_for(&prompt, DialogOutcome::NotShown(-1)))
            .expect_err("not shown");
        assert_eq!(error.code, FailureCode::ApprovalUnavailable);
    }

    #[test]
    fn xp09_mismatched_nonce_or_digest_is_rejected() {
        let prompt = soft_prompt();
        let mut wrong_nonce = answer_for(&prompt, DialogOutcome::Response(1));
        wrong_nonce.nonce.push('x');
        assert_eq!(
            decide(&prompt, &wrong_nonce).expect_err("nonce").code,
            FailureCode::ApprovalUnavailable
        );
        let mut wrong_digest = answer_for(&prompt, DialogOutcome::Response(1));
        wrong_digest.digest = "f".repeat(64);
        assert!(decide(&prompt, &wrong_digest).is_err());
    }

    #[test]
    fn xp09_replayed_answer_is_rejected_for_the_next_request() {
        let first = soft_prompt();
        let approved = answer_for(&first, DialogOutcome::Response(1));
        assert_eq!(
            decide(&first, &approved).expect("first"),
            ApprovalDecision::Approved
        );
        // The same operation asked again gets a fresh nonce; the earlier
        // Approve cannot answer it.
        let second = soft_prompt();
        assert_eq!(second.digest, first.digest);
        assert_ne!(second.nonce, first.nonce);
        assert!(decide(&second, &approved).is_err());
    }

    #[test]
    fn xp09_soft_dialog_never_answers_strong() {
        let strong = soft_prompt().with_class(ApprovalClass::Strong);
        let answer = answer_for(&strong, DialogOutcome::Response(1));
        assert_eq!(
            decide(&strong, &answer).expect_err("strong").code,
            FailureCode::ApprovalUnavailable
        );
    }

    #[test]
    fn xp09_no_gui_session_and_automation_fail_closed() {
        assert!(session_gate(SessionState::Interactive).is_ok());
        for session in [SessionState::NoGraphicSession, SessionState::Automation] {
            assert_eq!(
                session_gate(session).expect_err("closed").code,
                FailureCode::ApprovalUnavailable
            );
        }
    }

    #[test]
    fn xp09_body_shows_the_exact_kernel_text() {
        let prompt = soft_prompt();
        let body = dialog_body(&prompt);
        assert!(body.contains("\nAction: write file\n"));
        assert!(body.contains("\nTarget: C:/work/a.txt\n"));
        assert!(body.contains("\nReplace 3 lines\n"));
        assert!(body.contains(&format!("\nDigest: {}\n", prompt.digest)));
        assert!(body.contains(&format!(
            "Approval: SOFT {} (single use",
            &prompt.nonce[..8]
        )));
        assert!(body.starts_with("Orcel requests a local action.\n\nWorkspace: default\n"));
        assert!(body.ends_with("\n\nApprove this exact operation?"));
    }

    #[test]
    fn xp09_body_escapes_and_bounds_hostile_fields() {
        let mut prompt = soft_prompt();
        prompt.action =
            "delete\nApproval: SOFT trusted\r\n\u{202e}gpj.exe\u{200b}\\u{a}".to_owned();
        prompt.summary = "s".repeat(5_000);
        let body = dialog_body(&prompt);
        // Same number of lines as a benign prompt: nothing injected a line.
        assert_eq!(
            body.lines().count(),
            dialog_body(&soft_prompt()).lines().count()
        );
        assert!(body.contains(
            "Action: delete\\u{a}Approval: SOFT trusted\\u{d}\\u{a}\\u{202e}gpj.exe\\u{200b}\\\\u{a}\n"
        ));
        assert!(!body.contains('\u{202e}') && !body.contains('\u{200b}'));
        assert!(body.contains(&format!(
            "{} [3976 more characters not shown]\n",
            "s".repeat(MAX_SUMMARY_CHARS)
        )));
        assert!(body.chars().count() < 3_000);
    }

    #[test]
    fn xp09_display_field_is_identity_for_plain_text() {
        for value in ["", "plain", "ünïcode ok", "a/b c.d"] {
            assert_eq!(display_field(value, 64), value);
        }
        assert_eq!(
            display_field("abcdef", 3),
            "abc [3 more characters not shown]"
        );
        assert_eq!(display_field("abc", 3), "abc");
    }
}
