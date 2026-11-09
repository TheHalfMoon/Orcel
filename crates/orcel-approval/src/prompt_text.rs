//! The approval prompt's text, the same on every OS: the Windows `MessageBoxW` prompt, the
//! macOS alert, the Linux helper and the STRONG bodies all show these lines.
//!
//! Every field from the request is shown exactly when it is printable and short. Control,
//! line-break, bidi, format, zero-width, default-ignorable, tag, filler and blank-looking
//! characters are escaped as `\u{..}`, and so is any combining mark past the second on one
//! character, so a field can't insert a line break, reorder what is read, hide characters or
//! draw over other lines. Each bound applies to the escaped text. A long field can still wrap
//! onto another visual line; every line the prompt itself adds starts with its own label.
//!
//! The target is kept to 120 characters around a middle ellipsis, so its start and its end,
//! where a file's extension is, both stay visible.

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
/// Combining marks kept on one character before the rest are escaped: enough for real
/// scripts, too few to stack over the lines above and below.
const MAX_COMBINING_IN_A_ROW: usize = 2;

/// Each input character as it is shown: itself, or an escape.
fn pieces(value: &str) -> Vec<String> {
    let mut marks_in_a_row = 0usize;
    value
        .chars()
        .map(|ch| {
            let combining = is_combining(ch);
            marks_in_a_row = if combining { marks_in_a_row + 1 } else { 0 };
            if ch == '\\' {
                String::from("\\\\")
            } else if needs_escape(ch) || (combining && marks_in_a_row > MAX_COMBINING_IN_A_ROW) {
                format!("\\u{{{:x}}}", ch as u32)
            } else {
                ch.to_string()
            }
        })
        .collect()
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
    let pieces = pieces(value);
    let mut out = String::new();
    let mut out_chars = 0usize;
    let mut taken = 0usize;
    for piece in &pieces {
        let len = piece.chars().count();
        if out_chars + len > max_chars {
            break;
        }
        out.push_str(piece);
        out_chars += len;
        taken += 1;
    }
    let rest = pieces.len() - taken;
    if rest > 0 {
        out.push_str(&omitted(rest));
    }
    out
}

/// The target, escaped as [`display_field`] does, and kept to [`MAX_TARGET_CHARS`] by leaving
/// out the middle: the start and the end stay visible. An escape is never cut in half.
pub(crate) fn display_target(value: &str) -> String {
    let pieces = pieces(value);
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

/// Combining marks in the common combining blocks.
fn is_combining(ch: char) -> bool {
    matches!(
        ch,
        '\u{0300}'..='\u{036f}'
            | '\u{0483}'..='\u{0489}'
            | '\u{0591}'..='\u{05bd}'
            | '\u{0610}'..='\u{061a}'
            | '\u{064b}'..='\u{065f}'
            | '\u{1ab0}'..='\u{1aff}'
            | '\u{1dc0}'..='\u{1dff}'
            | '\u{20d0}'..='\u{20ff}'
            | '\u{fe20}'..='\u{fe2f}'
    )
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
            // Zero-width, invisible, deprecated formatting and default-ignorable characters.
            | '\u{200b}'..='\u{200d}' | '\u{2060}'..='\u{2064}' | '\u{206a}'..='\u{206f}'
            | '\u{feff}' | '\u{00ad}' | '\u{034f}'
            | '\u{17b4}' | '\u{17b5}'
            | '\u{180b}'..='\u{180f}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{1bca0}'..='\u{1bca3}'
            | '\u{13430}'..='\u{1343f}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0100}'..='\u{e01ef}'
            // Interlinear annotation characters.
            | '\u{fff9}'..='\u{fffb}'
            // Tag characters.
            | '\u{e0000}'..='\u{e007f}'
            // Hangul fillers and blank-looking spaces.
            | '\u{115f}' | '\u{1160}' | '\u{3164}' | '\u{ffa0}'
            | '\u{00a0}' | '\u{2800}' | '\u{3000}'
        )
}

/// The SOFT dialog's text over bounded, escaped fields.
pub(crate) fn dialog_body(prompt: &ApprovalPrompt) -> String {
    let nonce_prefix: String = prompt.nonce.chars().take(8).collect();
    format!(
        "Orcel requests a local action.\n\nWorkspace: {}\nAction: {}\nTarget: {}\n{}\nDigest: {}\nApproval: SOFT {} (single use, expires in 5 minutes)\n\nApprove this exact operation?",
        display_field(&prompt.workspace_id, MAX_WORKSPACE_CHARS),
        display_field(&prompt.action, MAX_ACTION_CHARS),
        display_target(&prompt.target),
        display_field(&prompt.summary, MAX_SUMMARY_CHARS),
        display_field(&prompt.digest, MAX_DIGEST_CHARS),
        display_field(&nonce_prefix, 8),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reversed_name_is_escaped() {
        let shown = display_target("docs/invoice\u{202e}txt.js");
        assert_eq!(shown, "docs/invoice\\u{202e}txt.js");
        assert!(!shown.contains('\u{202e}'));
    }

    #[test]
    fn a_target_of_120_is_whole_and_of_121_is_cut() {
        let fits = "a".repeat(MAX_TARGET_CHARS);
        assert_eq!(display_target(&fits), fits);
        let over = format!("{}.exe", "a".repeat(MAX_TARGET_CHARS - 3));
        let shown = display_target(&over);
        let field = shown.split(" [").next().unwrap();
        assert_eq!(field.chars().count(), MAX_TARGET_CHARS);
        assert!(field.ends_with(".exe"));
        assert!(shown.ends_with("[2 more characters not shown]"));
    }

    #[test]
    fn a_long_target_keeps_its_start_and_end() {
        let long = format!("C:\\work\\{}\\secret-plan.exe", "deep\\".repeat(60));
        let shown = display_target(&long);
        let field = shown.split(" [").next().unwrap();
        assert!(field.chars().count() <= MAX_TARGET_CHARS, "{shown}");
        assert!(field.starts_with("C:\\\\work\\\\deep"), "{shown}");
        assert!(field.ends_with("secret-plan.exe"), "{shown}");
        assert!(field.contains('…'));
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
                // Every escape that starts also ends (the input has no literal brace).
                assert_eq!(
                    part.matches("\\u{").count(),
                    part.matches('}').count(),
                    "{shown}"
                );
            }
        }
    }

    #[test]
    fn hidden_and_blank_looking_characters_are_escaped() {
        for ch in [
            '\u{034f}',
            '\u{fe0f}',
            '\u{e0100}',
            '\u{180f}',
            '\u{17b4}',
            '\u{1d173}',
            '\u{13430}',
            '\u{1bca0}',
            '\u{00a0}',
            '\u{2800}',
            '\u{3000}',
        ] {
            let shown = display_field(&format!("a{ch}b"), 64);
            assert_eq!(shown, format!("a\\u{{{:x}}}b", ch as u32), "{ch:?}");
        }
    }

    #[test]
    fn stacked_combining_marks_are_escaped_past_the_second() {
        // Real text keeps its marks: e with acute and grave stays as it is.
        assert_eq!(display_field("e\u{301}\u{300}x", 64), "e\u{301}\u{300}x");
        // A stack of 50 shows two and escapes the rest.
        let zalgo = format!("a{}", "\u{301}".repeat(50));
        let shown = display_field(&zalgo, 1_000);
        assert!(shown.starts_with("a\u{301}\u{301}\\u{301}"));
        assert_eq!(shown.matches('\u{301}').count(), 2);
        // The count resets at the next ordinary character.
        assert_eq!(display_field("a\u{301}b\u{301}", 64), "a\u{301}b\u{301}");
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
