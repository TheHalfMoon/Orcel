//! The approval prompt's text, the same on every OS: the Windows `MessageBoxW` prompt, the
//! macOS alert, the Linux helper and the STRONG bodies all show these lines.
//!
//! Every field from the request is shown exactly when it is printable and short. Control,
//! line-break, bidi, format, zero-width, default-ignorable, tag, filler and blank-looking
//! characters are escaped as `\u{..}`, so a field can't insert a line break, reorder what is
//! read or hide characters. Any combining mark past the second on one character is escaped
//! too, for the combining blocks listed in `is_combining` (the general blocks and the scripts
//! whose marks stack: Hebrew, Arabic, Devanagari, Thai, Lao, Tibetan, musical notation); a
//! mark outside them is shown as it is. Each bound applies to the escaped text. A long field can still wrap
//! onto another visual line; every line the prompt itself adds starts with its own label.
//!
//! The target is kept to 120 characters around a middle ellipsis, so its start and its end,
//! where a file's extension is, both stay visible.

// Other OSes show no approval UI; tests still run these rules there.
#![cfg_attr(
    not(any(windows, target_os = "macos", target_os = "linux")),
    allow(dead_code)
)]

use crate::{ApprovalPrompt, PresenceContext, Preview, RequestOrigin, TargetKind};

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

/// Combining marks in the general combining blocks and in the scripts whose marks stack.
fn is_combining(ch: char) -> bool {
    matches!(
        ch,
        '\u{0300}'..='\u{036f}'
            | '\u{0483}'..='\u{0489}'
            | '\u{0591}'..='\u{05bd}'
            | '\u{05bf}'
            | '\u{05c1}' | '\u{05c2}' | '\u{05c4}' | '\u{05c5}' | '\u{05c7}'
            | '\u{0610}'..='\u{061a}'
            | '\u{064b}'..='\u{065f}'
            | '\u{0670}'
            | '\u{06d6}'..='\u{06dc}'
            | '\u{06df}'..='\u{06e4}'
            | '\u{0900}'..='\u{0903}'
            | '\u{093a}'..='\u{094f}'
            | '\u{0951}'..='\u{0957}'
            | '\u{0962}' | '\u{0963}'
            | '\u{0e31}'
            | '\u{0e34}'..='\u{0e3a}'
            | '\u{0e47}'..='\u{0e4e}'
            | '\u{0eb1}'
            | '\u{0eb4}'..='\u{0ebc}'
            | '\u{0ec8}'..='\u{0ecd}'
            | '\u{0f71}'..='\u{0f84}'
            | '\u{0f86}' | '\u{0f87}'
            | '\u{1ab0}'..='\u{1aff}'
            | '\u{1dc0}'..='\u{1dff}'
            | '\u{20d0}'..='\u{20ff}'
            | '\u{fe20}'..='\u{fe2f}'
            | '\u{1d165}'..='\u{1d169}'
            | '\u{1d16d}'..='\u{1d172}'
            | '\u{1d17b}'..='\u{1d182}'
            | '\u{1d185}'..='\u{1d18b}'
            | '\u{1d1aa}'..='\u{1d1ad}'
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
            | '\u{00a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}' | '\u{202f}' | '\u{205f}'
            | '\u{2800}' | '\u{3000}'
        )
}

const MAX_ORIGIN_PART_CHARS: usize = 64;
const MAX_TYPE_CHARS: usize = 24;

/// A file's extension, escaped, when its last path part has one: `.js` for
/// `docs/invoice.txt.js`. A leading dot alone (`.bashrc`) or a trailing dot is no extension.
pub(crate) fn file_type(path: &str) -> Option<String> {
    let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
    let dot = name.rfind('.')?;
    if dot == 0 || dot + 1 == name.len() {
        return None;
    }
    Some(display_field(&name[dot..], MAX_TYPE_CHARS))
}

/// The target line; for a file its Type line; and a move's Destination with its own Type.
fn target_lines(kind: TargetKind, target: &str, destination: Option<&str>) -> String {
    let typed = |label: &str, path: &str, is_file: bool| {
        let mut lines = format!("{label}: {}", display_target(path));
        if is_file {
            if let Some(extension) = file_type(path) {
                lines.push_str(&format!("\n{label} type: {extension}"));
            }
        }
        lines
    };
    let target_is_file = kind == TargetKind::File;
    let destination_is_file = matches!(kind, TargetKind::File | TargetKind::Download);
    match destination {
        Some(destination) => format!(
            "{}\n{}",
            typed("Target", target, target_is_file),
            typed("Destination", destination, destination_is_file)
        ),
        None => typed("Target", target, target_is_file),
    }
}
const MAX_PREVIEW_LINE_CHARS: usize = 100;

/// The preview lines, with a leading newline, or nothing. Every content line starts with its
/// marker and a bar (`> │`, `- │`, `+ │`), so none can read as one of the prompt's own lines,
/// and is escaped and cut like any field.
fn preview_lines(preview: Option<&Preview>) -> String {
    let plural =
        |count: usize, word: &str| format!("{count} {word}{}", if count == 1 { "" } else { "s" });
    match preview {
        None => String::new(),
        Some(Preview::Hidden { chars }) => format!(
            "\nPreview: HIDDEN, it may contain a password, key or token ({}). Approve only if you expect that here.",
            plural(*chars, "character")
        ),
        Some(Preview::SizesOnly { chars, lines }) => format!(
            "\nPreview: off, sizes only ({}, {})",
            plural(*chars, "character"),
            plural(*lines, "line")
        ),
        Some(Preview::Content { lines, .. }) if lines.is_empty() => {
            String::from("\nPreview: (empty)")
        }
        Some(Preview::Content { lines, more_lines }) => {
            let mut out = String::from("\nPreview:");
            for (marker, line) in lines {
                let marker = if matches!(marker, '>' | '-' | '+') {
                    *marker
                } else {
                    '?'
                };
                out.push_str(&format!(
                    "\n{marker} │ {}",
                    display_field(line, MAX_PREVIEW_LINE_CHARS)
                ));
            }
            if *more_lines > 0 {
                out.push_str(&format!(
                    "\n({more_lines} more {} not shown)",
                    if *more_lines == 1 { "line" } else { "lines" }
                ));
            }
            out
        }
    }
}

/// Who is asking, from fields orceld set: the opening words and the Origin line.
fn origin_lines(origin: &RequestOrigin) -> (&'static str, String) {
    match origin {
        RequestOrigin::Local => (
            "Orcel requests a local action",
            "Origin: this computer".to_owned(),
        ),
        RequestOrigin::Remote {
            provider,
            device,
            connection,
        } => (
            "Orcel requests an action for a REMOTE session",
            format!(
                "Origin: remote, through {} for device {} (connection {})",
                display_field(provider, MAX_ORIGIN_PART_CHARS),
                display_field(device, MAX_ORIGIN_PART_CHARS),
                display_field(connection, MAX_ORIGIN_PART_CHARS),
            ),
        ),
    }
}

/// The SOFT dialog's text over bounded, escaped fields.
pub(crate) fn dialog_body(prompt: &ApprovalPrompt) -> String {
    let nonce_prefix: String = prompt.nonce.chars().take(8).collect();
    let (opening, origin) = origin_lines(&prompt.origin);
    format!(
        "{opening}.\n\n{origin}\nWorkspace: {}\nAction: {}\n{}\n{}{}\nDigest: {}\nApproval: SOFT {} (single use, expires in 5 minutes)\n\nApprove this exact operation?",
        display_field(&prompt.workspace_id, MAX_WORKSPACE_CHARS),
        display_field(&prompt.action, MAX_ACTION_CHARS),
        target_lines(prompt.target_kind, &prompt.target, prompt.destination.as_deref()),
        display_field(&prompt.summary, MAX_SUMMARY_CHARS),
        preview_lines(prompt.preview.as_ref()),
        display_field(&prompt.digest, MAX_DIGEST_CHARS),
        display_field(&nonce_prefix, 8),
    )
}

/// The STRONG summary: the SOFT body's lines, marked STRONG. Every OS shows it before asking
/// the system to confirm it is the person: Linux before polkit, Windows before Windows Hello,
/// macOS before Touch ID, whose own prompts are too short to show the target.
pub(crate) fn strong_body(ctx: &PresenceContext) -> String {
    let nonce_prefix: String = ctx.nonce.chars().take(8).collect();
    let (opening, origin) = origin_lines(&ctx.origin);
    format!(
        "{opening} that needs STRONG approval.\n\n{origin}\nWorkspace: {}\nAction: {}\n{}\n{}{}\nDigest: {}\nApproval: STRONG {} (single use, expires in 5 minutes)\n\nApprove this exact operation? Your system will then ask you to confirm it is you.",
        display_field(&ctx.workspace_id, MAX_WORKSPACE_CHARS),
        display_field(&ctx.action, MAX_ACTION_CHARS),
        target_lines(ctx.target_kind, &ctx.target, ctx.destination.as_deref()),
        display_field(&ctx.summary, MAX_SUMMARY_CHARS),
        preview_lines(ctx.preview.as_ref()),
        display_field(&ctx.digest, MAX_DIGEST_CHARS),
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
            '\u{2003}',
            '\u{202f}',
            '\u{205f}',
            '\u{1680}',
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
        // Marks from different blocks count together: alternating them doesn't slip past.
        let mixed = format!("a{}", "\u{301}\u{e48}".repeat(100));
        let shown = display_field(&mixed, 5_000);
        assert_eq!(
            shown.matches('\u{301}').count() + shown.matches('\u{e48}').count(),
            2
        );
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

    #[test]
    fn only_yes_at_the_windows_strong_summary_goes_on_to_hello() {
        assert!(crate::windows_summary_decision(crate::WINDOWS_IDYES).is_ok());
        let declined = crate::windows_summary_decision(crate::WINDOWS_IDNO).unwrap_err();
        assert_eq!(declined.reason, crate::PresenceFailureReason::Denied);
        let odd = crate::windows_summary_decision(0).unwrap_err();
        assert_eq!(odd.reason, crate::PresenceFailureReason::Unavailable);
    }

    #[test]
    fn only_approve_at_the_macos_strong_summary_goes_on_to_touch_id() {
        use crate::soft_macos::{summary_decision, DialogOutcome};
        assert!(summary_decision(DialogOutcome::Response(1)).is_ok());
        for refused in [0, 2, 3] {
            let error = summary_decision(DialogOutcome::Response(refused)).unwrap_err();
            assert_eq!(
                error.reason,
                crate::PresenceFailureReason::Denied,
                "{refused}"
            );
        }
        let error = summary_decision(DialogOutcome::NotShown(-1)).unwrap_err();
        assert_eq!(error.reason, crate::PresenceFailureReason::Unavailable);
    }

    #[test]
    fn the_strong_summary_names_the_target_escaped() {
        let ctx =
            crate::PresenceContext::new("nonce-0001", "d".repeat(64), "default", "delete file")
                .with_details("docs/invoice\u{202e}txt.js", "Remove one file");
        let body = strong_body(&ctx);
        assert!(body.contains("\nTarget: docs/invoice\\u{202e}txt.js\n"));
        assert!(body.contains("\nRemove one file\n"));
        assert!(!body.contains('\u{202e}'));
    }

    #[test]
    fn a_remote_request_says_so_and_names_its_route() {
        let remote = RequestOrigin::Remote {
            provider: "chatgpt-tunnel".to_owned(),
            device: "dev-1234\nOrigin: this computer".to_owned(),
            connection: "conn-9".to_owned(),
        };
        let prompt = crate::ApprovalPrompt::new("default", "rev", "delete file", "a.txt", "s", "d")
            .with_origin(remote.clone());
        let body = dialog_body(&prompt);
        assert!(body.starts_with("Orcel requests an action for a REMOTE session.\n\nOrigin: remote, through chatgpt-tunnel for device dev-1234\\u{a}Origin: this computer (connection conn-9)\nWorkspace: default\n"), "{body}");
        let local = dialog_body(&crate::ApprovalPrompt::new(
            "default", "rev", "a", "t", "s", "d",
        ));
        assert!(local.starts_with(
            "Orcel requests a local action.\n\nOrigin: this computer\nWorkspace: default\n"
        ));
        // The same lines either way: a remote field can't add one.
        assert_eq!(body.lines().count(), local.lines().count());
        let ctx = crate::PresenceContext::new("nonce-1", "d", "default", "delete file")
            .with_origin(remote);
        assert!(strong_body(&ctx).starts_with("Orcel requests an action for a REMOTE session that needs STRONG approval.\n\nOrigin: remote, through"));
    }

    #[test]
    fn only_a_file_target_gets_a_type_line() {
        let file = crate::ApprovalPrompt::new(
            "default",
            "rev",
            "edit file",
            "docs/invoice\u{202e}txt.js",
            "s",
            "d",
        )
        .for_file();
        let body = dialog_body(&file);
        assert!(
            body.contains("\nTarget: docs/invoice\\u{202e}txt.js\nTarget type: .js\n"),
            "{body}"
        );
        // A host, a URL or an element id is not a file: no type line, whatever its last dot.
        for other in ["files.zip", "https://x.example/a.pdf?y=1.exe", "uia-1.2"] {
            let body = dialog_body(&crate::ApprovalPrompt::new(
                "default", "rev", "a", other, "s", "d",
            ));
            assert!(!body.contains("type:"), "{body}");
        }
        // A file without an extension, or a dotfile, has none either.
        for name in ["docs/Makefile", "home/.bashrc", "odd."] {
            let body = dialog_body(
                &crate::ApprovalPrompt::new("default", "rev", "a", name, "s", "d").for_file(),
            );
            assert!(!body.contains("type:"), "{body}");
        }
    }

    #[test]
    fn a_move_shows_its_destination_and_the_destinations_type() {
        let moved = crate::ApprovalPrompt::new(
            "default",
            "rev",
            "move or rename",
            "docs/invoice.pdf",
            "s",
            "d",
        )
        .for_file()
        .with_destination(format!("docs/{}invoice.pdf.exe", "x".repeat(2_000)));
        let body = dialog_body(&moved);
        assert!(
            body.contains("\nTarget: docs/invoice.pdf\nTarget type: .pdf\nDestination: docs/"),
            "{body}"
        );
        assert!(body.contains("invoice.pdf.exe ["), "{body}");
        assert!(body.contains("\nDestination type: .exe\n"), "{body}");
        // The STRONG summary carries both too.
        let ctx = crate::PresenceContext::new("nonce-1", "d", "default", "move")
            .with_details("a.txt", "s")
            .with_target(crate::TargetKind::File, Some("b.sh".to_owned()));
        let strong = strong_body(&ctx);
        assert!(
            strong.contains(
                "\nTarget: a.txt\nTarget type: .txt\nDestination: b.sh\nDestination type: .sh\n"
            ),
            "{strong}"
        );
    }

    #[test]
    fn a_download_shows_its_file_and_type_but_no_type_for_the_source() {
        let download = crate::ApprovalPrompt::new(
            "default",
            "rev",
            "download",
            format!("https://x.example/{}", "a".repeat(2_000)),
            "s",
            "d",
        )
        .downloading_to("Downloads/statement.pdf.exe");
        let body = dialog_body(&download);
        assert!(!body.contains("Target type:"), "{body}");
        assert!(
            body.contains("\nDestination: Downloads/statement.pdf.exe\nDestination type: .exe\n"),
            "{body}"
        );
    }

    fn with(preview: Preview) -> String {
        dialog_body(
            &crate::ApprovalPrompt::new("default", "rev", "write", "a.txt", "summary", "d")
                .with_preview(preview),
        )
    }

    #[test]
    fn a_write_previews_its_first_lines_escaped_and_bounded() {
        let content = format!(
            "line one\nDigest: forged\n\u{202e}x\n{}\n5\n6\n7\n8",
            "w".repeat(300)
        );
        let body = with(Preview::of_written(
            &content,
            crate::PreviewMode::Content,
            false,
        ));
        assert!(
            body.contains(
                "\nsummary\nPreview:\n> │ line one\n> │ Digest: forged\n> │ \\u{202e}x\n> │ "
            ),
            "{body}"
        );
        assert!(
            body.contains(&format!(
                "> │ {} [200 more characters not shown]\n",
                "w".repeat(100)
            )),
            "{body}"
        );
        assert!(
            body.contains("\n(2 more lines not shown)\nDigest: d\n"),
            "{body}"
        );
        // No content line starts a line of its own: each is behind its marker.
        assert!(!body.lines().any(|line| line == "Digest: forged"));
    }

    #[test]
    fn an_edit_previews_removed_and_added_lines() {
        let body = with(Preview::of_edit(
            "old a\nold b",
            "new a",
            crate::PreviewMode::Content,
            false,
        ));
        assert!(
            body.contains("\nPreview:\n- │ old a\n- │ old b\n+ │ new a\nDigest: d\n"),
            "{body}"
        );
    }

    #[test]
    fn a_credential_or_sizes_only_shows_no_content() {
        let secret = with(Preview::of_written(
            "AKIAEXAMPLE\nsecond",
            crate::PreviewMode::Content,
            true,
        ));
        assert!(secret.contains("\nPreview: HIDDEN, it may contain a password, key or token (18 characters). Approve only if you expect that here.\nDigest: d\n"), "{secret}");
        assert!(!secret.contains("AKIA"));
        let sizes = with(Preview::of_written(
            "private notes\nmore",
            crate::PreviewMode::SizesOnly,
            false,
        ));
        assert!(
            sizes.contains("\nPreview: off, sizes only (18 characters, 2 lines)\nDigest: d\n"),
            "{sizes}"
        );
        assert!(!sizes.contains("private"));
        // A credential is hidden in sizes-only mode as well, and says so.
        let both = with(Preview::of_written(
            "AKIAEXAMPLE",
            crate::PreviewMode::SizesOnly,
            true,
        ));
        assert!(both.contains("may contain a password, key or token"));
        // An empty write says so.
        assert!(
            with(Preview::of_written("", crate::PreviewMode::Content, false))
                .contains("\nPreview: (empty)\nDigest: d\n")
        );
    }

    #[test]
    fn the_strong_summary_carries_the_preview() {
        let ctx = crate::PresenceContext::new("nonce-1", "d", "default", "remove")
            .with_details("a.txt", "s")
            .with_preview(Some(Preview::of_written(
                "bye",
                crate::PreviewMode::Content,
                false,
            )));
        assert!(strong_body(&ctx).contains("\ns\nPreview:\n> │ bye\nDigest: d\n"));
    }
}
