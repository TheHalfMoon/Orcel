//! What the chain keeps of a value a client chose or a path orceld saw
//! (spec 4.8: argv, URLs, query strings and header values appear only as
//! SHA-256 digests).
//!
//! The plain log never wrote a request's arguments; the chain keeps that
//! rule and bounds every client field the same way. A request target is
//! never written as text: the chain keeps a short label (`url`, `path` or
//! `text`), its length and its SHA-256. A caller's executable keeps its file
//! name only when that is a plain name (no directory, so never a user
//! profile path), and its SHA-256.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::borrow::Cow;

pub(crate) const TRUNCATED: &str = "…[truncated]";

/// The longest executable file name the chain keeps.
const MAX_IMAGE_NAME_CHARS: usize = 64;

/// `value`, or its first `max` characters marked as cut.
pub(crate) fn bounded(value: &str, max: usize) -> Cow<'_, str> {
    match value.char_indices().nth(max) {
        None => Cow::Borrowed(value),
        Some((end, _)) => Cow::Owned(format!("{}{TRUNCATED}", &value[..end])),
    }
}

/// Whether `c` could hide or reorder text in a reader: a C0 or C1 control,
/// a line or paragraph separator, or a bidirectional mark or override.
fn is_unsafe(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{2028}' | '\u{2029}' | '\u{061C}' | '\u{200E}' | '\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2066}'..='\u{2069}'
        )
}

/// `value` with every unsafe character replaced by U+FFFD, bounded to
/// `max` characters: what the chain keeps of a client-chosen field.
pub(crate) fn field_text(value: &str, max: usize) -> String {
    let cleaned: Cow<'_, str> = if value.chars().any(is_unsafe) {
        Cow::Owned(
            value
                .chars()
                .map(|c| if is_unsafe(c) { '\u{FFFD}' } else { c })
                .collect(),
        )
    } else {
        Cow::Borrowed(value)
    };
    bounded(&cleaned, max).into_owned()
}

/// SHA-256 of `bytes`, lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Whether `text` (already cut at `?` and `#`) starts with a URL scheme:
/// `[a-z][a-z0-9+.-]*` followed by `:`.
fn is_url(text: &str) -> bool {
    let Some((scheme, _)) = text.split_once(':') else {
        return false;
    };
    let mut chars = scheme.chars();
    chars.next().is_some_and(|first| first.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '+' | '.' | '-'))
        // A drive letter (`C:\`) is a path, not a scheme.
        && scheme.len() > 1
}

/// The chain's form of a request target: a label, the length and the
/// digest of the whole value; never its text.
pub(crate) fn target_detail(target: &str) -> Value {
    let cut = target.split(['?', '#']).next().unwrap_or_default();
    let label = if is_url(cut) {
        "url"
    } else if cut.contains(['/', '\\']) || cut.get(1..2) == Some(":") {
        "path"
    } else {
        "text"
    };
    json!({
        "label": label,
        "chars": target.chars().count(),
        "sha256": sha256_hex(target.as_bytes()),
    })
}

/// A caller executable's file name, when it is a plain name: ASCII letters,
/// digits, `.`, `_`, `-` and spaces, at most 64 characters.
pub(crate) fn image_name(path: &str) -> Option<String> {
    let name = path.rsplit(['/', '\\']).next()?;
    let plain = !name.is_empty()
        && name.chars().count() <= MAX_IMAGE_NAME_CHARS
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ' '));
    plain.then(|| name.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_redaction_keeps_labels_and_digests_only() {
        let url = "https://user:hunter2@example.test:8443/a/b?token=SECRET#frag";
        let shown = target_detail(url);
        assert_eq!(shown["label"], "url");
        assert_eq!(shown["sha256"], sha256_hex(url.as_bytes()));
        let text = shown.to_string();
        for part in ["hunter2", "example.test", "SECRET", "/a/b", "frag"] {
            assert!(!text.contains(part), "{part} in {text}");
        }
        // A scheme hidden after a query is not a URL scheme.
        assert_eq!(target_detail("notes?x=https://evil.test")["label"], "text");
        assert_ne!(target_detail("HTTPS://upper.test")["label"], "url");
        assert_eq!(target_detail(r"C:\Users\alice\secret.txt")["label"], "path");
        assert_eq!(target_detail("src/lib.rs")["label"], "path");
        assert_eq!(target_detail("main")["label"], "text");
        assert!(!target_detail(r"C:\Users\alice\x")
            .to_string()
            .contains("alice"));
        assert_eq!(
            image_name(r"C:\Users\alice\AppData\orcel.exe").as_deref(),
            Some("orcel.exe")
        );
        assert_eq!(
            image_name("/home/alice/bin/agent"),
            Some("agent".to_owned())
        );
        assert_eq!(image_name(r"C:\x\bad|name.exe"), None);
        assert_eq!(image_name(&"a".repeat(65)), None);
        assert_eq!(
            field_text("a\u{7}b\u{85}c\u{2028}d\u{202E}e\u{2067}f\u{200F}", 64),
            "a\u{FFFD}b\u{FFFD}c\u{FFFD}d\u{FFFD}e\u{FFFD}f\u{FFFD}"
        );
        assert_eq!(field_text("plain-id", 64), "plain-id");
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
