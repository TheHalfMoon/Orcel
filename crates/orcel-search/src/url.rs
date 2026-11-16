//! Minimal URL handling for filters and category inference.
//!
//! The crate takes no URL dependency. These helpers only split an absolute
//! `scheme://authority/path` string; they never resolve, fetch or normalise
//! beyond lowercasing the host. The governed fetch in `orceld` stays the
//! network authority.

/// The parts of an absolute URL the engine reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlParts {
    /// Lowercase scheme without `:`.
    pub scheme: String,
    /// Lowercase host including any `:port` (the WHATWG `host` value).
    pub host: String,
    /// Path starting with `/` (or `/` when absent), without query or fragment.
    pub path: String,
}

/// Splits `scheme://[userinfo@]host[:port][/path][?query][#fragment]`.
/// Returns `None` for anything that is not an absolute URL with an authority.
pub fn parse(url: &str) -> Option<UrlParts> {
    let url = url.trim();
    let (scheme, rest) = url.split_once("://")?;
    let mut scheme_chars = scheme.chars();
    let first = scheme_chars.next()?;
    if !first.is_ascii_alphabetic()
        || !scheme_chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    {
        return None;
    }
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if host.is_empty() && !scheme.eq_ignore_ascii_case("file") {
        return None;
    }
    if host.chars().any(|c| c.is_whitespace() || c == '\\') {
        return None;
    }
    let remainder = &rest[end..];
    let path_end = remainder.find(['?', '#']).unwrap_or(remainder.len());
    let path = &remainder[..path_end];
    Some(UrlParts {
        scheme: scheme.to_ascii_lowercase(),
        host: host.to_lowercase(),
        path: if path.is_empty() {
            "/".to_string()
        } else {
            path.to_string()
        },
    })
}

/// True for `http` and `https` URLs with a host.
pub fn is_http(url: &str) -> bool {
    parse(url).is_some_and(|p| (p.scheme == "http" || p.scheme == "https") && !p.host.is_empty())
}

/// Lowercases, strips `http(s)://`, a leading `www.` and any path.
pub fn normalise_domain(input: &str) -> String {
    let lower = input.trim().to_lowercase();
    let no_scheme = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))
        .unwrap_or(&lower);
    let no_www = no_scheme.strip_prefix("www.").unwrap_or(no_scheme);
    no_www.split('/').next().unwrap_or("").to_string()
}

/// Host-suffix match: `news.bbc.co.uk` matches `bbc.co.uk`;
/// `bbc.co.uk.evil.test` does not.
pub fn domain_matches(host: &str, domain: &str) -> bool {
    if domain.is_empty() {
        return false;
    }
    let lower = host.to_lowercase();
    let clean = lower.strip_prefix("www.").unwrap_or(&lower);
    clean == domain || clean.ends_with(&format!(".{domain}"))
}
