//! Tokenisation and light normalisation for the local BM25 index.
//!
//! Ported from the REA proof of concept (`orcel-poc/src/text/tokenize.ts`,
//! Orcel-authored). Unicode-aware word splitting, Latin diacritic folding and
//! a conservative English suffix trimmer. No stemming library, no model.

use std::collections::HashSet;
use std::sync::OnceLock;

const STOPWORD_LIST: &str = "a an and are as at be but by for from has have how i if in into is it its of on or that the their \
then there these they this to was were what when where which who will with you your about after all \
also any can could do does did not we our us more most other some such only own same so than too very \
s t just don should now";

fn stopwords() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| STOPWORD_LIST.split_whitespace().collect())
}

/// Base letters for U+0100..=U+017F (Latin Extended-A). `None` where the
/// character has no canonical or compatibility decomposition to a Latin base.
fn latin_extended_a(c: char) -> Option<&'static str> {
    const TABLE: [&str; 128] = [
        "A", "a", "A", "a", "A", "a", "C", "c", "C", "c", "C", "c", "C", "c", "D",
        "d", // 0100
        "", "", "E", "e", "E", "e", "E", "e", "E", "e", "E", "e", "G", "g", "G", "g", // 0110
        "G", "g", "G", "g", "H", "h", "", "", "I", "i", "I", "i", "I", "i", "I", "i", // 0120
        "I", "", "IJ", "ij", "J", "j", "K", "k", "", "L", "l", "L", "l", "L", "l",
        "L\u{b7}", // 0130
        "l\u{b7}", "", "", "N", "n", "N", "n", "N", "n", "\u{2bc}n", "", "", "O", "o", "O",
        "o", // 0140
        "O", "o", "", "", "R", "r", "R", "r", "R", "r", "S", "s", "S", "s", "S", "s", // 0150
        "S", "s", "T", "t", "T", "t", "", "", "U", "u", "U", "u", "U", "u", "U", "u", // 0160
        "U", "u", "U", "u", "W", "w", "Y", "y", "Y", "Z", "z", "Z", "z", "Z", "z",
        "s", // 0170
    ];
    let index = (c as u32).checked_sub(0x100)? as usize;
    let mapped = *TABLE.get(index)?;
    if mapped.is_empty() {
        None
    } else {
        Some(mapped)
    }
}

/// Base letter for a Latin-1 Supplement character with a canonical
/// decomposition (U+00C0..=U+00FF).
fn latin1(c: char) -> Option<char> {
    Some(match c {
        'À'..='Å' => 'A',
        'Ç' => 'C',
        'È'..='Ë' => 'E',
        'Ì'..='Ï' => 'I',
        'Ñ' => 'N',
        'Ò'..='Ö' => 'O',
        'Ù'..='Ü' => 'U',
        'Ý' => 'Y',
        'à'..='å' => 'a',
        'ç' => 'c',
        'è'..='ë' => 'e',
        'ì'..='ï' => 'i',
        'ñ' => 'n',
        'ò'..='ö' => 'o',
        'ù'..='ü' => 'u',
        'ý' | 'ÿ' => 'y',
        _ => return None,
    })
}

/// Folds `café` -> `cafe` without touching non-Latin scripts.
///
/// The proof of concept uses `NFKD` and strips U+0300..=U+036F. This port
/// covers the same result for combining marks, Latin-1 Supplement, Latin
/// Extended-A, the Latin ligatures U+FB00..=U+FB06 and fullwidth ASCII; it
/// is not a full NFKD (no new dependency), which is recorded as a gap.
pub fn fold_diacritics(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        let code = c as u32;
        if (0x300..=0x36f).contains(&code) {
            continue;
        }
        if let Some(base) = latin1(c) {
            out.push(base);
        } else if let Some(base) = latin_extended_a(c) {
            out.push_str(base);
        } else if (0xff01..=0xff5e).contains(&code) {
            out.push(char::from_u32(code - 0xff01 + 0x21).unwrap_or(c));
        } else {
            match c {
                '\u{fb00}' => out.push_str("ff"),
                '\u{fb01}' => out.push_str("fi"),
                '\u{fb02}' => out.push_str("fl"),
                '\u{fb03}' => out.push_str("ffi"),
                '\u{fb04}' => out.push_str("ffl"),
                '\u{fb05}' | '\u{fb06}' => out.push_str("st"),
                '\u{a0}' => out.push(' '),
                _ => out.push(c),
            }
        }
    }
    out
}

/// Lowercase word tokens: letters and numbers in any script.
pub fn tokenize(input: &str) -> Vec<String> {
    if input.is_empty() {
        return Vec::new();
    }
    fold_diacritics(&input.to_lowercase())
        .split(|c: char| !(c.is_alphabetic() || c.is_numeric()))
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect()
}

/// Conservative suffix trimmer, intentionally weaker than Porter.
pub fn stem(token: &str) -> String {
    let len = token.chars().count();
    if len <= 3 {
        return token.to_string();
    }
    for suffix in ["ies", "ing", "ed", "es", "s"] {
        let suffix_len = suffix.chars().count();
        if token.ends_with(suffix) && len - suffix_len >= 3 {
            let base = &token[..token.len() - suffix.len()];
            if suffix == "ies" {
                return format!("{base}y");
            }
            return base.to_string();
        }
    }
    token.to_string()
}

/// Index terms: tokens without stopwords or single characters, stemmed.
pub fn index_terms(input: &str) -> Vec<String> {
    tokenize(input)
        .into_iter()
        .filter(|t| !stopwords().contains(t.as_str()) && t.chars().count() > 1)
        .map(|t| stem(&t))
        .collect()
}

/// Adjacent term pairs joined with `_`.
pub fn bigrams(terms: &[String]) -> Vec<String> {
    terms
        .windows(2)
        .map(|pair| format!("{}_{}", pair[0], pair[1]))
        .collect()
}

/// True when the word is a stopword (case-insensitive).
pub fn is_stopword(word: &str) -> bool {
    stopwords().contains(word.to_lowercase().as_str())
}
