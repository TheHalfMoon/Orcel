//! What the chain keeps of a value a client chose (spec 4.8: argv, URLs,
//! query strings and header values appear only as SHA-256 digests).
//!
//! The plain log never wrote a request's arguments; the chain keeps that
//! rule and bounds every client field the same way. A target that is a URL
//! keeps its scheme and host only (never user info, path, query or
//! fragment), with the whole value as a digest beside it.

use sha2::{Digest, Sha256};
use std::borrow::Cow;

pub(crate) const TRUNCATED: &str = "…[truncated]";

/// `value`, or its first `max` characters marked as cut.
pub(crate) fn bounded(value: &str, max: usize) -> Cow<'_, str> {
    match value.char_indices().nth(max) {
        None => Cow::Borrowed(value),
        Some((end, _)) => Cow::Owned(format!("{}{TRUNCATED}", &value[..end])),
    }
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

/// What the chain shows of a request target: a URL's scheme and host only;
/// any other target bounded, cut at a `?` or `#` so a query never shows.
pub(crate) fn shown_target(target: &str, max: usize) -> String {
    if let Some((scheme, rest)) = target.split_once("://") {
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        // User info (`user:password@`) is dropped whole.
        let host = authority.rsplit('@').next().unwrap_or_default();
        let shown = format!("{scheme}://{host}/…");
        return bounded(&shown, max).into_owned();
    }
    let cut = target.split(['?', '#']).next().unwrap_or_default();
    let mut shown = bounded(cut, max).into_owned();
    if cut.len() < target.len() {
        shown.push_str("…[query removed]");
    }
    shown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_redaction_shows_no_url_secret_or_query() {
        let shown = shown_target(
            "https://user:hunter2@example.test:8443/a/b?token=SECRET#frag",
            256,
        );
        assert_eq!(shown, "https://example.test:8443/…");
        let path = shown_target(r"C:\work\file.txt?sig=SECRET", 256);
        assert!(!path.contains("SECRET"), "{path}");
        assert!(path.starts_with(r"C:\work\file.txt"));
        assert_eq!(shown_target("src/lib.rs", 256), "src/lib.rs");
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
