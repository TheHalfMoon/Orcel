//! The orceld <-> helper protocol (XP-10).
//!
//! orceld writes one request, a JSON object on one line, to the helper's
//! stdin and reads one answer line from its stdout; both pipes belong to
//! orceld. The answer repeats the request's channel nonce, which orceld
//! drew for this request alone, so orceld refuses an answer meant for
//! another request, a replayed one, or one printed by anything that does
//! not know the nonce.
//!
//! orcel-approval's tests compile this file too (`linux_helper_protocol`
//! in `crates/orcel-approval/src/lib.rs`), so orceld and the helper are
//! checked against each other on every OS.

// orcel-approval's tests use only part of this module.
#![allow(dead_code)]

use serde::Deserialize;

pub const PROTOCOL: &str = "orcel-approval-helper/1";
/// The largest request the helper reads.
pub const MAX_REQUEST_BYTES: usize = 16 * 1024;
const MAX_TITLE_CHARS: usize = 128;
const MAX_BODY_CHARS: usize = 8 * 1024;
const MAX_TIMEOUT_SECS: u64 = 600;
const NONCE_HEX_CHARS: usize = 32;

/// One approval request.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub protocol: String,
    /// orceld's channel nonce: 32 lowercase hex characters.
    pub nonce: String,
    /// `SOFT` or `STRONG`; only the window text differs.
    pub class: String,
    pub title: String,
    /// The text to show, already bounded and escaped by orceld.
    pub body: String,
    /// The dialog answers deny by itself after this many seconds.
    pub timeout_secs: u64,
}

/// Characters orceld always escapes; a body that still holds one did not
/// come from orceld's escaper and is refused rather than shown.
fn hidden_or_reordering(ch: char) -> bool {
    (ch.is_control() && ch != '\n')
        || matches!(
            ch,
            '\u{2028}' | '\u{2029}'
            | '\u{200e}' | '\u{200f}' | '\u{061c}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
            | '\u{200b}'..='\u{200d}' | '\u{2060}'..='\u{2064}' | '\u{206a}'..='\u{206f}'
            | '\u{feff}' | '\u{00ad}' | '\u{180e}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{e0000}'..='\u{e007f}'
            | '\u{115f}' | '\u{1160}' | '\u{3164}' | '\u{ffa0}'
        )
}

/// Parses and checks a request. Anything unexpected is refused, and the
/// helper then exits without showing a dialog or printing an answer.
pub fn parse_request(input: &[u8]) -> Result<Request, String> {
    if input.len() > MAX_REQUEST_BYTES {
        return Err("request too large".into());
    }
    let text = std::str::from_utf8(input).map_err(|_| String::from("request is not UTF-8"))?;
    let line = text.strip_suffix('\n').unwrap_or(text);
    if line.contains('\n') {
        return Err("request is not one line".into());
    }
    let request: Request =
        serde_json::from_str(line).map_err(|error| format!("request is malformed: {error}"))?;
    if request.protocol != PROTOCOL {
        return Err("unsupported protocol".into());
    }
    if request.nonce.len() != NONCE_HEX_CHARS
        || !request
            .nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("request nonce is malformed".into());
    }
    if request.class != "SOFT" && request.class != "STRONG" {
        return Err("unknown approval class".into());
    }
    let title_chars = request.title.chars().count();
    if title_chars == 0
        || title_chars > MAX_TITLE_CHARS
        || request.title.contains('\n')
        || request.title.chars().any(hidden_or_reordering)
    {
        return Err("request title is not displayable".into());
    }
    if request.body.trim().is_empty()
        || request.body.chars().count() > MAX_BODY_CHARS
        || request.body.chars().any(hidden_or_reordering)
    {
        return Err("request body is not displayable".into());
    }
    if request.timeout_secs == 0 || request.timeout_secs > MAX_TIMEOUT_SECS {
        return Err("request timeout is out of range".into());
    }
    Ok(request)
}

/// The one line the helper prints: `orcel-approval-helper/1 <nonce> approve|deny`.
pub fn answer_line(nonce: &str, approved: bool) -> String {
    let verdict = if approved { "approve" } else { "deny" };
    format!("{PROTOCOL} {nonce} {verdict}\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONCE: &str = "00112233445566778899aabbccddeeff";

    fn request(body: &str) -> String {
        serde_json::json!({
            "protocol": PROTOCOL,
            "nonce": NONCE,
            "class": "SOFT",
            "title": "Orcel approval SOFT",
            "body": body,
            "timeout_secs": 120,
        })
        .to_string()
    }

    #[test]
    fn xp10_accepts_a_well_formed_request() {
        let parsed = parse_request(request("line one\nline two").as_bytes()).expect("ok");
        assert_eq!(parsed.body, "line one\nline two");
        assert_eq!(
            answer_line(&parsed.nonce, true),
            format!("{PROTOCOL} {NONCE} approve\n")
        );
    }

    #[test]
    fn xp10_refuses_unescaped_or_oversized_text() {
        for body in ["a\rb", "a\u{202e}b", "a\u{200b}b", "a\u{e0041}b", "  ", ""] {
            assert!(parse_request(request(body).as_bytes()).is_err(), "{body:?}");
        }
        assert!(parse_request(request(&"x".repeat(MAX_BODY_CHARS + 1)).as_bytes()).is_err());
        let extra = request("b").replace("\"timeout_secs\"", "\"extra\":1,\"timeout_secs\"");
        assert!(parse_request(extra.as_bytes()).is_err());
        let two = format!("{}\n{}\n", request("b"), request("b"));
        assert!(parse_request(two.as_bytes()).is_err());
    }
}
