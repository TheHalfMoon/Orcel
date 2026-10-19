//! XP-09 SOFT approval on macOS: a system-owned `CFUserNotification`
//! alert (caution level) drawn by the UserNotificationCenter agent, not by
//! Orcel or the Control Room. BUILD_NEW: no donor presents an
//! approval-style system modal.
//!
//! The dialog only reports the person's answer to the one synchronous call
//! that showed it. This layer does no request binding: the broker records
//! the answer for the prompt it asked about, and the existing ledger binds
//! it to that request's nonce and digest and issues the single-use,
//! expiring token, exactly as for the Windows `MessageBoxW` prompt.
//!
//! Fail closed: the default button (Return) is Deny; Approve is the
//! alternate button. Cancel, a dismissal and the timeout all deny. No GUI
//! session or an automation runner is `unavailable` without showing
//! anything, and a dialog that cannot be shown is `unavailable`.
//!
//! The body has the same lines as the Windows prompt. Every field from the
//! request is shown exactly when it is printable and short. Control,
//! line-break, bidi, zero-width, tag and filler characters are escaped as
//! `\u{..}` so a field cannot fake another line of the dialog, and the
//! bound applies to the escaped text.

// Off macOS this module is compiled only into tests, which run the
// formatting, escaping and decision rules on every OS.
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
/// the characters that could change the dialog's layout or reading order,
/// and stops before the escaped text would exceed `max_chars`, saying how
/// many input characters were left out.
pub(crate) fn display_field(value: &str, max_chars: usize) -> String {
    let mut out = String::new();
    let mut out_chars = 0usize;
    let mut taken = 0usize;
    for ch in value.chars() {
        let piece = if ch == '\\' {
            String::from("\\\\")
        } else if needs_escape(ch) {
            format!("\\u{{{:x}}}", ch as u32)
        } else {
            ch.to_string()
        };
        let len = piece.chars().count();
        if out_chars + len > max_chars {
            break;
        }
        out.push_str(&piece);
        out_chars += len;
        taken += 1;
    }
    let rest = value.chars().count() - taken;
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
            // Zero-width, invisible and deprecated formatting characters.
            | '\u{200b}'..='\u{200d}' | '\u{2060}'..='\u{2064}' | '\u{206a}'..='\u{206f}'
            | '\u{feff}' | '\u{00ad}' | '\u{180e}'
            // Interlinear annotation characters.
            | '\u{fff9}'..='\u{fffb}'
            // Tag characters.
            | '\u{e0000}'..='\u{e007f}'
            // Hangul fillers, which render as blank space.
            | '\u{115f}' | '\u{1160}' | '\u{3164}' | '\u{ffa0}'
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

/// What the system dialog reported.
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

/// Maps the dialog's outcome to a decision. Only the Approve button
/// approves; the broker and the ledger bind the decision to the request.
pub(crate) fn decide(
    prompt: &ApprovalPrompt,
    outcome: DialogOutcome,
) -> Result<ApprovalDecision, ApprovalError> {
    if prompt.approval_class != ApprovalClass::Soft {
        return Err(ApprovalError::unavailable(
            "the SOFT dialog never answers a STRONG request; STRONG requires presence verification",
        ));
    }
    match outcome {
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
    decide(
        prompt,
        cf::display_alert(&dialog_body(prompt), SOFT_PROMPT_TIMEOUT_SECS),
    )
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
            "/Users/me/a.txt",
            "Replace 3 lines",
            "e".repeat(64),
            5_000,
        )
    }

    #[test]
    fn xp09_only_the_approve_button_approves() {
        let prompt = soft_prompt();
        assert_eq!(
            decide(&prompt, DialogOutcome::Response(1)).expect("decided"),
            ApprovalDecision::Approved
        );
        // Deny (default / Return), other, cancel and timeout all deny.
        for flags in [0usize, 2, 3, 0x100 | 3] {
            assert_eq!(
                decide(&prompt, DialogOutcome::Response(flags)).expect("decided"),
                ApprovalDecision::Denied,
                "flags {flags:#x}"
            );
        }
        let error = decide(&prompt, DialogOutcome::NotShown(-1)).expect_err("not shown");
        assert_eq!(error.code, FailureCode::ApprovalUnavailable);
    }

    #[test]
    fn xp09_soft_dialog_never_answers_strong() {
        let strong = soft_prompt().with_class(ApprovalClass::Strong);
        assert_eq!(
            decide(&strong, DialogOutcome::Response(1))
                .expect_err("strong")
                .code,
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
        assert!(body.contains("\nTarget: /Users/me/a.txt\n"));
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
    fn xp09_invisible_tag_and_filler_characters_are_escaped() {
        let hostile = [
            '\u{206a}',
            '\u{206f}',
            '\u{fff9}',
            '\u{fffb}',
            '\u{e0000}',
            '\u{e0041}',
            '\u{e007f}',
            '\u{3164}',
            '\u{115f}',
            '\u{1160}',
            '\u{ffa0}',
            '\u{2066}',
            '\u{2028}',
            '\u{feff}',
        ];
        for ch in hostile {
            let shown = display_field(&format!("a{ch}b"), 64);
            assert_eq!(shown, format!("a\\u{{{:x}}}b", ch as u32));
            assert!(!shown.contains(ch));
        }
    }

    #[test]
    fn xp09_bound_applies_to_the_escaped_text() {
        // 100 newlines escape to 500 characters; a bound of 20 shows four
        // whole escapes and counts the 96 input characters left out.
        let shown = display_field(&"\n".repeat(100), 20);
        assert_eq!(
            shown,
            format!("{} [96 more characters not shown]", "\\u{a}".repeat(4))
        );
        // An escape is never cut in half.
        let shown = display_field("ab\u{202e}", 4);
        assert_eq!(shown, "ab [1 more characters not shown]");
        for max in 0..40 {
            let shown = display_field(&"\u{e0041}x".repeat(30), max);
            let field = shown.split(" [").next().expect("field");
            assert!(field.chars().count() <= max, "{max}: {shown}");
        }
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
