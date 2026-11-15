//! How the approval prompt shows one character of a field, the same on every OS. The prompt
//! (`orcel-approval`'s `prompt_text`) renders fields through [`pieces`]; SG-000122 measures a
//! browser fill value with [`shown_exactly`], so the value bound and the escapes are the
//! prompt's own, never a copy of its character classes.
//!
//! Control, line-break, bidi, format, zero-width, default-ignorable, tag, filler and
//! blank-looking characters are escaped as `\u{..}`, so a field can't insert a line break,
//! reorder what is read or hide characters. Any combining mark past the second on one character
//! is escaped too, for the combining blocks listed in `is_combining` (the general blocks and the
//! scripts whose marks stack: Hebrew, Arabic, Devanagari, Thai, Lao, Tibetan, musical
//! notation); a mark outside them is shown as it is. A backslash is shown doubled.

/// The most displayed characters of an approval prompt's summary line.
pub const MAX_SUMMARY_CHARS: usize = 1024;

/// Combining marks kept on one character before the rest are escaped: enough for real
/// scripts, too few to stack over the lines above and below.
const MAX_COMBINING_IN_A_ROW: usize = 2;

/// Each input character as the prompt shows it: itself, a doubled backslash, or an escape.
pub fn pieces(value: &str) -> Vec<String> {
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

/// Why a value can't be shown exactly and in full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotShownExactly {
    /// The prompt would escape one of its characters.
    Escaped,
    /// Its displayed text is longer than the bound, so the prompt would cut it.
    TooLong,
}

/// The number of characters the prompt displays for `value` when it shows `value` exactly
/// (every character as itself, a backslash doubled) and in full within `max_chars`; otherwise
/// why it can't. Nothing is ever truncated: a value that doesn't fit is refused.
pub fn shown_exactly(value: &str, max_chars: usize) -> Result<usize, NotShownExactly> {
    let mut shown = 0usize;
    for (ch, piece) in value.chars().zip(pieces(value)) {
        let len = piece.chars().count();
        let exact = len == 1 || (ch == '\\' && piece == "\\\\");
        if !exact {
            return Err(NotShownExactly::Escaped);
        }
        shown += len;
    }
    if shown > max_chars {
        return Err(NotShownExactly::TooLong);
    }
    Ok(shown)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_printable_value_is_shown_exactly_and_a_backslash_counts_double() {
        assert_eq!(shown_exactly("Ada Lovelace", MAX_SUMMARY_CHARS), Ok(12));
        assert_eq!(shown_exactly("C:\\temp", MAX_SUMMARY_CHARS), Ok(8));
        assert_eq!(shown_exactly("", MAX_SUMMARY_CHARS), Ok(0));
        // Two combining marks in a row are shown; a third is escaped.
        assert_eq!(shown_exactly("e\u{301}\u{302}", MAX_SUMMARY_CHARS), Ok(3));
        assert_eq!(
            shown_exactly("e\u{301}\u{302}\u{303}", MAX_SUMMARY_CHARS),
            Err(NotShownExactly::Escaped)
        );
    }

    #[test]
    fn the_bound_is_on_the_displayed_text() {
        let at = "a".repeat(MAX_SUMMARY_CHARS);
        assert_eq!(shown_exactly(&at, MAX_SUMMARY_CHARS), Ok(MAX_SUMMARY_CHARS));
        let past = "a".repeat(MAX_SUMMARY_CHARS + 1);
        assert_eq!(
            shown_exactly(&past, MAX_SUMMARY_CHARS),
            Err(NotShownExactly::TooLong)
        );
        let slashes = "\\".repeat(MAX_SUMMARY_CHARS / 2);
        assert_eq!(
            shown_exactly(&slashes, MAX_SUMMARY_CHARS),
            Ok(MAX_SUMMARY_CHARS)
        );
        let one_more = format!("{slashes}a");
        assert_eq!(
            shown_exactly(&one_more, MAX_SUMMARY_CHARS),
            Err(NotShownExactly::TooLong)
        );
    }

    #[test]
    fn every_escaped_class_is_not_shown_exactly() {
        for ch in [
            '\u{0}',
            '\u{1b}',
            '\u{7f}',
            '\u{85}',
            '\u{9f}',
            '\n',
            '\t',
            '\u{2028}',
            '\u{2029}',
            '\u{200e}',
            '\u{061c}',
            '\u{202e}',
            '\u{2067}',
            '\u{200b}',
            '\u{2060}',
            '\u{feff}',
            '\u{00ad}',
            '\u{180e}',
            '\u{fe0f}',
            '\u{e0100}',
            '\u{fff9}',
            '\u{e0041}',
            '\u{3164}',
            '\u{00a0}',
            '\u{2003}',
            '\u{3000}',
            '\u{2800}',
        ] {
            assert_eq!(
                shown_exactly(&format!("a{ch}b"), MAX_SUMMARY_CHARS),
                Err(NotShownExactly::Escaped),
                "U+{:04X}",
                ch as u32
            );
        }
    }
}
