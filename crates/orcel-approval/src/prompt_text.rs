//! The approval prompt's text, the same on every OS: the Windows `MessageBoxW` prompt, the
//! macOS alert, the Linux helper and the STRONG bodies all show these lines.
//!
//! Every field from the request is shown exactly when it is printable and short. Control,
//! line-break, bidi, zero-width, tag and filler characters are escaped as `\u{..}` so a field
//! can't fake another line of the dialog or reorder what is read, and each bound applies to the
//! escaped text. The target is kept to 120 characters around a middle ellipsis, so its start
//! and its file extension both stay visible, and the extension is repeated on its own line: a
//! name such as `invoice\u{202e}txt.js` reads as `Type: .js`.

// Other OSes show no approval UI; tests still run these rules there.
#![cfg_attr(
    not(any(windows, target_os = "macos", target_os = "linux")),
    allow(dead_code)
)]

use crate::ApprovalPrompt;

pub(crate) const MAX_WORKSPACE_CHARS: usize = 128;
pub(crate) const MAX_ACTION_CHARS: usize = 512;
pub(crate) const MAX_TARGET_CHARS: usize = 120;
pub(crate) const MAX_SUMMARY_CHARS: usize = 1024;
pub(crate) const MAX_DIGEST_CHARS: usize = 128;
const MAX_TYPE_CHARS: usize = 24;

/// One input character as it is shown: itself, or an escape.
fn shown(ch: char) -> String {
    if ch == '\\' {
        String::from("\\\\")
    } else if needs_escape(ch) {
        format!("\\u{{{:x}}}", ch as u32)
    } else {
        ch.to_string()
    }
}

fn omitted(rest: usize) -> String {
    format!(
        " [{rest} more {} not shown]",
        if rest == 1 { "character" } else { "characters" }
    )
}

/// Shows `value` exactly when it is printable and short; otherwise escapes the characters that
/// could change the dialog's layout or reading order, and stops before the escaped text would
/// exceed `max_chars`, saying how many input characters were left out.
pub(crate) fn display_field(value: &str, max_chars: usize) -> String {
    let mut out = String::new();
    let mut out_chars = 0usize;
    let mut taken = 0usize;
    for ch in value.chars() {
        let piece = shown(ch);
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
        out.push_str(&omitted(rest));
    }
    out
}

/// The target, escaped as [`display_field`] does, and kept to [`MAX_TARGET_CHARS`] by leaving
/// out the middle: the start and the end, file extension included, stay visible. An escape is
/// never cut in half.
pub(crate) fn display_target(value: &str) -> String {
    let pieces: Vec<String> = value.chars().map(shown).collect();
    let width = |piece: &String| piece.chars().count();
    if pieces.iter().map(width).sum::<usize>() <= MAX_TARGET_CHARS {
        return pieces.concat();
    }
    // One character goes to the ellipsis; the tail gets the smaller half.
    let budget = MAX_TARGET_CHARS - 1;
    let tail_budget = budget / 2;
    let head_budget = budget - tail_budget;
    let mut head = Vec::new();
    let mut used = 0;
    for piece in &pieces {
        if used + width(piece) > head_budget {
            break;
        }
        used += width(piece);
        head.push(piece.as_str());
    }
    let mut tail = Vec::new();
    used = 0;
    for piece in pieces[head.len()..].iter().rev() {
        if used + width(piece) > tail_budget {
            break;
        }
        used += width(piece);
        tail.push(piece.as_str());
    }
    tail.reverse();
    let rest = pieces.len() - head.len() - tail.len();
    format!("{}…{}{}", head.concat(), tail.concat(), omitted(rest))
}

/// The target's file extension, escaped, when its last path part has one: `.js` for
/// `C:\docs\invoice.txt.js`. A leading dot alone (`.bashrc`) or a trailing dot is no extension.
pub(crate) fn target_type(value: &str) -> Option<String> {
    let name = value.rsplit(['/', '\\']).next().unwrap_or(value);
    let dot = name.rfind('.')?;
    if dot == 0 || dot + 1 == name.len() {
        return None;
    }
    Some(display_field(&name[dot..], MAX_TYPE_CHARS))
}

/// The target line, and the type line under it when the target has an extension.
pub(crate) fn target_lines(value: &str) -> String {
    match target_type(value) {
        Some(extension) => format!("Target: {}\nType: {extension}", display_target(value)),
        None => format!("Target: {}", display_target(value)),
    }
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

/// The SOFT dialog's text over bounded, escaped fields.
pub(crate) fn dialog_body(prompt: &ApprovalPrompt) -> String {
    let nonce_prefix: String = prompt.nonce.chars().take(8).collect();
    format!(
        "Orcel requests a local action.\n\nWorkspace: {}\nAction: {}\n{}\n{}\nDigest: {}\nApproval: SOFT {} (single use, expires in 5 minutes)\n\nApprove this exact operation?",
        display_field(&prompt.workspace_id, MAX_WORKSPACE_CHARS),
        display_field(&prompt.action, MAX_ACTION_CHARS),
        target_lines(&prompt.target),
        display_field(&prompt.summary, MAX_SUMMARY_CHARS),
        display_field(&prompt.digest, MAX_DIGEST_CHARS),
        display_field(&nonce_prefix, 8),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_target_is_shown_whole_with_its_type() {
        assert_eq!(
            target_lines("docs/report.pdf"),
            "Target: docs/report.pdf\nType: .pdf"
        );
        assert_eq!(target_lines("docs/Makefile"), "Target: docs/Makefile");
        assert_eq!(target_lines("home/.bashrc"), "Target: home/.bashrc");
        assert_eq!(target_lines("odd."), "Target: odd.");
    }

    #[test]
    fn a_reversed_name_shows_its_real_extension() {
        let lines = target_lines("docs/invoice\u{202e}txt.js");
        assert_eq!(lines, "Target: docs/invoice\\u{202e}txt.js\nType: .js");
        assert!(!lines.contains('\u{202e}'));
    }

    #[test]
    fn a_long_target_keeps_its_start_and_extension() {
        let long = format!("C:\\work\\{}\\secret-plan.exe", "deep\\".repeat(60));
        let shown = display_target(&long);
        let field = shown.split(" [").next().unwrap();
        assert!(field.chars().count() <= MAX_TARGET_CHARS, "{shown}");
        assert!(field.starts_with("C:\\\\work\\\\deep"), "{shown}");
        assert!(field.ends_with("secret-plan.exe"), "{shown}");
        assert!(field.contains('…'));
        assert!(shown.ends_with("characters not shown]"));
        assert_eq!(target_type(&long).as_deref(), Some(".exe"));
    }

    #[test]
    fn the_middle_cut_never_splits_an_escape() {
        for len in 100..140 {
            let hostile = "\u{200b}a".repeat(len);
            let shown = display_target(&hostile);
            let field = shown.split(" [").next().unwrap();
            assert!(field.chars().count() <= MAX_TARGET_CHARS);
            let (head, tail) = field.split_once('…').unwrap_or((field, ""));
            for part in [head, tail] {
                // Every escape that starts also ends.
                assert_eq!(
                    part.matches("\\u{").count(),
                    part.matches('}').count(),
                    "{shown}"
                );
            }
        }
    }

    #[test]
    fn a_hostile_extension_is_escaped_and_bounded() {
        let ty = target_type(&format!("a.{}", "\n".repeat(40))).unwrap();
        assert!(!ty.contains('\n'));
        assert!(ty.contains("not shown"));
    }

    #[test]
    fn the_windows_hello_message_escapes_its_fields() {
        let ctx = crate::PresenceContext::new(
            "abcdefgh-rest",
            "0123456789abcdef",
            "ws\u{2067}",
            "rm\nApproval: STRONG trusted\u{202e}",
        );
        let message = crate::hello_message(&ctx);
        assert_eq!(
            message,
            "Orcel STRONG approval abcdefgh 0123456789ab for rm\\u{a}Approval: STRONG trusted\\u{202e} in workspace ws\\u{2067}"
        );
    }
}
