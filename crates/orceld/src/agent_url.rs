//! SG-000135 OB-07b: every page URL an agent reads goes through here.
//!
//! A page's URL is page-controlled, and after a person signs in it can carry
//! what the person typed: a sign-in form that uses GET puts its fields,
//! password included, in the query, and identity providers put tokens and
//! codes in the query or the fragment. orceld keeps the full URL to apply
//! its route rules and digests it into receipts, but a reply to the agent
//! (and through it the MCP client, and later a remote one) shows only:
//!
//! - the scheme, host and path, never userinfo (`user:password@`);
//! - each query and fragment parameter's name, with its value kept only
//!   when the name does not look secret (`SECRET_PARTS`) and the session has
//!   not shown a sign-in page; otherwise the value is `[redacted]`;
//! - a parameter with no `=` (a bare item) only when it is short and not
//!   token-like, otherwise `[redacted]`;
//! - a fragment that is not `key=value` (a plain anchor such as
//!   `#section-2`) only when it has no `=` and is short and not token-like,
//!   otherwise `[redacted]`.
//!
//! "Strict" (`after_sign_in`) redacts every query and fragment value and
//! every bare query item (a plain anchor fragment keeps the rule above):
//! once a session's page was detected as a sign-in page
//! (OB-07 `sign_in`), any later URL may carry the person's input. The agent
//! keeps the path and the parameter names, enough to know where it is.
//!
//! Tab lists use [`bare`], which drops the query and fragment entirely
//! (OB-03).

/// Parameter name parts that mark a value as secret (case-insensitive,
/// contained anywhere in the name), plus `pin` as a whole word.
const SECRET_PARTS: &[&str] = &[
    "pass",
    "pw",
    "secret",
    "token",
    "otp",
    "code",
    "key",
    "auth",
    "session",
    "sid",
    "sig",
    "signature",
    "credential",
    "cred",
    "saml",
    "assertion",
    "ticket",
    "jwt",
    "bearer",
    "access",
    "refresh",
    "nonce",
];

/// What a redacted value or item shows.
pub(crate) const REDACTED: &str = "[redacted]";

/// The longest plain anchor or bare item shown.
const MAX_PLAIN: usize = 64;
/// A run of at least this many token characters counts as token-like.
const TOKEN_RUN: usize = 16;

/// Whether a parameter name looks secret.
fn secret_name(name: &str) -> bool {
    let lower = percent_decoded(name).to_ascii_lowercase();
    SECRET_PARTS.iter().any(|part| lower.contains(part))
        || lower
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|word| word == "pin")
}

/// Best-effort `%XX` decoding, for matching names only (never shown).
fn percent_decoded(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = (bytes[i] == b'%')
            .then(|| bytes.get(i + 1..i + 3))
            .flatten()
            .and_then(|h| std::str::from_utf8(h).ok())
            .and_then(|h| u8::from_str_radix(h, 16).ok());
        match hex {
            Some(byte) => {
                out.push(byte);
                i += 3;
            }
            None => {
                out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Whether `text` holds a long run of token characters (base64, hex, JWT
/// pieces), or is too long to show plainly.
fn token_like(text: &str) -> bool {
    if text.len() > MAX_PLAIN {
        return true;
    }
    let mut run = 0;
    for c in text.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~' | '%' | '+' | '/') {
            run += 1;
            if run >= TOKEN_RUN {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

/// `a=1&b=2` with each value kept or redacted.
fn parameters(text: &str, strict: bool) -> String {
    text.split('&')
        .map(|item| match item.split_once('=') {
            Some((name, value)) => {
                if strict || secret_name(name) || token_like(name) {
                    let name = if token_like(name) { REDACTED } else { name };
                    format!("{name}={REDACTED}")
                } else {
                    format!("{name}={value}")
                }
            }
            None if item.is_empty() => String::new(),
            None if strict || token_like(item) || secret_name(item) => REDACTED.to_owned(),
            None => item.to_owned(),
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// The fragment as shown: parameters when it has `=`, else a plain anchor
/// kept only when short and not token-like.
fn fragment(text: &str, strict: bool) -> String {
    if text.contains('=') {
        parameters(text, strict)
    } else if token_like(text) || secret_name(text) {
        REDACTED.to_owned()
    } else {
        text.to_owned()
    }
}

/// An http(s) URL's parts, userinfo already dropped from the host.
struct Parts<'a> {
    scheme: &'a str,
    host: &'a str,
    path: &'a str,
    query: Option<&'a str>,
    fragment: Option<&'a str>,
}

/// Split `scheme://authority/path?query#fragment`. None for anything that
/// is not http or https.
fn split(url: &str) -> Option<Parts<'_>> {
    let (scheme, rest) = url.split_once("://")?;
    if !scheme.eq_ignore_ascii_case("https") && !scheme.eq_ignore_ascii_case("http") {
        return None;
    }
    let (rest, fragment) = match rest.split_once('#') {
        Some((rest, fragment)) => (rest, Some(fragment)),
        None => (rest, None),
    };
    let (rest, query) = match rest.split_once('?') {
        Some((rest, query)) => (rest, Some(query)),
        None => (rest, None),
    };
    let (authority, path) = match rest.find('/') {
        Some(slash) => rest.split_at(slash),
        None => (rest, ""),
    };
    let host = authority.rsplit('@').next().unwrap_or(authority);
    Some(Parts {
        scheme,
        host,
        path,
        query,
        fragment,
    })
}

/// A page URL as an agent may read it (see the module header). A URL that
/// is not http or https shows only `about:blank` as itself; anything else
/// shows as its scheme alone.
pub(crate) fn agent_url(url: &str, after_sign_in: bool) -> String {
    let Some(Parts {
        scheme,
        host,
        path,
        query,
        fragment: frag,
    }) = split(url)
    else {
        if url == "about:blank" || url.is_empty() {
            return url.to_owned();
        }
        return url
            .split_once(':')
            .map(|(scheme, _)| format!("{scheme}:"))
            .unwrap_or_default();
    };
    let mut out = format!("{scheme}://{host}{path}");
    if let Some(query) = query {
        out.push('?');
        out.push_str(&parameters(query, after_sign_in));
    }
    if let Some(frag) = frag {
        out.push('#');
        out.push_str(&fragment(frag, after_sign_in));
    }
    out
}

/// A tab's URL as a tab report shows it: scheme, host and path, without
/// userinfo, query or fragment (OB-03). Ported from `sanitize_url` in
/// vercel-labs/agent-browser cli/src/native/tab_binding.rs (see
/// docs/orcel/agent_browser_provenance.json): https only, and no URL
/// parser dependency.
pub(crate) fn bare(url: &str) -> String {
    let Some(rest) = url.strip_prefix("https://") else {
        return String::new();
    };
    let end = rest.find(['?', '#']).unwrap_or(rest.len());
    let rest = &rest[..end];
    let (authority, path) = match rest.find('/') {
        Some(slash) => rest.split_at(slash),
        None => (rest, "/"),
    };
    let host = authority.rsplit('@').next().unwrap_or(authority);
    format!("https://{host}{path}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ob07b_secret_values_userinfo_and_tokens_never_reach_the_agent() {
        for (url, shown) in [
            ("https://fixture.test/a?q=rust&page=2", "https://fixture.test/a?q=rust&page=2"),
            (
                "https://user:hunter2@fixture.test/p?x=1",
                "https://fixture.test/p?x=1",
            ),
            (
                "https://fixture.test/login?user=ann&password=hunter2&next=%2Fhome",
                "https://fixture.test/login?user=ann&password=[redacted]&next=%2Fhome",
            ),
            (
                "https://fixture.test/cb?code=abc&state=xyz&session_state=s1",
                "https://fixture.test/cb?code=[redacted]&state=xyz&session_state=[redacted]",
            ),
            (
                "https://fixture.test/x?PIN=1234&spinner=on&user_pin=9",
                "https://fixture.test/x?PIN=[redacted]&spinner=on&user_pin=[redacted]",
            ),
            (
                "https://fixture.test/x?SAMLResponse=PHNhbWw&RelayState=r&jwt=e.y.z&apiKey=k&X-Amz-Signature=s&sid=1&nonce=n&ticket=t&Bearer=b&access=a&refresh=r&cred=c&otp=1&pwd=p&secret=s&token=t&auth=a",
                "https://fixture.test/x?SAMLResponse=[redacted]&RelayState=r&jwt=[redacted]&apiKey=[redacted]&X-Amz-Signature=[redacted]&sid=[redacted]&nonce=[redacted]&ticket=[redacted]&Bearer=[redacted]&access=[redacted]&refresh=[redacted]&cred=[redacted]&otp=[redacted]&pwd=[redacted]&secret=[redacted]&token=[redacted]&auth=[redacted]",
            ),
            (
                "https://fixture.test/x?p%61ssword=hunter2",
                "https://fixture.test/x?p%61ssword=[redacted]",
            ),
            // OAuth implicit flow: parameters in the fragment.
            (
                "https://fixture.test/cb#access_token=eyJhbGciOi&token_type=bearer&expires_in=3600",
                "https://fixture.test/cb#access_token=[redacted]&token_type=[redacted]&expires_in=3600",
            ),
            // A plain anchor stays; a token-like one does not.
            ("https://fixture.test/doc#section-2", "https://fixture.test/doc#section-2"),
            (
                "https://fixture.test/doc#4f9a8b7c6d5e4f3a2b1c",
                "https://fixture.test/doc#[redacted]",
            ),
            // Bare query items: short words stay, tokens do not.
            ("https://fixture.test/a?print", "https://fixture.test/a?print"),
            (
                "https://fixture.test/a?Zm9vYmFyYmF6cXV4cXV1eA",
                "https://fixture.test/a?[redacted]",
            ),
            // A token-like value under an ordinary name stays (the name
            // decides); a token-like name is itself redacted.
            (
                "https://fixture.test/a?ZXlKaGJHY2lPaUpJVXpJMU5pSjk=1",
                "https://fixture.test/a?[redacted]=[redacted]",
            ),
            ("https://fixture.test", "https://fixture.test"),
            ("about:blank", "about:blank"),
            ("data:text/html,<p>secret</p>", "data:"),
            ("javascript:alert(1)", "javascript:"),
        ] {
            assert_eq!(agent_url(url, false), shown, "{url}");
        }
    }

    #[test]
    fn ob07b_after_a_sign_in_every_value_is_redacted() {
        for (url, shown) in [
            (
                "https://fixture.test/home?user=ann&lang=en",
                "https://fixture.test/home?user=[redacted]&lang=[redacted]",
            ),
            (
                "https://fixture.test/home?welcome",
                "https://fixture.test/home?[redacted]",
            ),
            (
                "https://fixture.test/home#tab=inbox",
                "https://fixture.test/home#tab=[redacted]",
            ),
            (
                "https://fixture.test/home#inbox",
                "https://fixture.test/home#inbox",
            ),
            ("https://fixture.test/home", "https://fixture.test/home"),
        ] {
            assert_eq!(agent_url(url, true), shown, "{url}");
        }
    }

    /// SG-000135 OB-03: a tab report never shows credentials, a query or
    /// a fragment, and nothing but https.
    #[test]
    fn ob03_tab_urls_are_shown_without_query_fragment_or_credentials() {
        for (url, shown) in [
            ("https://fixture.test/a?token=x#f", "https://fixture.test/a"),
            ("https://user:pw@fixture.test/p", "https://fixture.test/p"),
            ("https://fixture.test", "https://fixture.test/"),
            ("https://fixture.test?x=1", "https://fixture.test/"),
            ("about:blank", ""),
            ("http://fixture.test/", ""),
        ] {
            assert_eq!(bare(url), shown, "{url}");
        }
    }
}
