//! WI-01: crawl include and exclude patterns, as path prefixes (the
//! default, unchanged) or as regular expressions with Firecrawl's semantics,
//! and the canonical form a crawl uses to recognise a URL it already has.
//!
//! Adapted from firecrawl/firecrawl at commit
//! f84845c864b6e2af22791c18fcf89ac2a21f1434: `compile_path_regex`, its
//! resource limits and `validate_regexes` from `apps/api/native/src/crawler.rs`
//! (blob 598f14d33703a424748fab15f5087e56b7469776), and `normalizeUrl` from
//! `apps/api/src/lib/canonical-url.ts` (blob
//! 068999d47bcc9300916b80233f72519b9a4a155c). AGPL-3.0 upstream; copied
//! under the founder authorization recorded in
//! `docs/orcel/grants/2026-10-13-founder-source-authorization.md`; notice:
//! `docs/orcel/notices/firecrawl-AGPL-3.0.txt`.
//!
//! Orcel's changes: a pattern that does not compile rejects the crawl
//! instead of being dropped (Firecrawl validates before filtering; here the
//! one check does both); patterns stay bounded by `MAX_PATH_PATTERNS` of
//! `MAX_PATH_PATTERN_BYTES` without control characters; a regex is matched
//! against the URL's path only, never the full URL, since a crawl never
//! leaves its admitted origin; an exclude pattern is also tested against
//! the canonical path, so `^/docs/private$` excludes `/docs/private/` too;
//! the canonical form keeps the path and query on that one origin (scheme
//! and `www.` stripping have nothing to do there) and folds the trailing
//! slash before the query (`/a/?q` and `/a?q` are one URL), where the donor
//! folds only a slash at the very end. As before WI-01, the start URL itself
//! must pass the include patterns, or the crawl is refused (Firecrawl always
//! reads its seed).

use crate::error::HostError;

/// How a crawl's include and exclude patterns are read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PatternKind {
    /// Absolute path prefixes (the default).
    #[default]
    Prefix,
    /// Regular expressions (Rust `regex` syntax: no look-around or
    /// backreferences), matched anywhere in the path unless anchored.
    Regex,
}

/// Approximate upper bound, in bytes, on the compiled program of one path
/// pattern. Patterns are untrusted, and the regex crate's compile time and
/// memory scale with the compiled size, not the pattern's length.
const PATH_REGEX_SIZE_LIMIT: usize = 256 * 1024;

/// Cache capacity of the lazy DFA used when matching one path pattern.
const PATH_REGEX_DFA_SIZE_LIMIT: usize = 256 * 1024;

/// Maximum nesting depth of one path pattern's syntax tree.
const PATH_REGEX_NEST_LIMIT: u32 = 50;

/// Compiles one untrusted path pattern within the limits above. The regex
/// crate has no backtracking, so matching is linear in the input.
fn compile_path_regex(pattern: &str) -> Result<regex::bytes::Regex, regex::Error> {
    regex::bytes::RegexBuilder::new(pattern)
        .unicode(false)
        .size_limit(PATH_REGEX_SIZE_LIMIT)
        .dfa_size_limit(PATH_REGEX_DFA_SIZE_LIMIT)
        .nest_limit(PATH_REGEX_NEST_LIMIT)
        .build()
}

#[derive(Debug, Clone)]
enum Matcher {
    Prefix(String),
    Regex(regex::bytes::Regex),
}

impl Matcher {
    fn matches(&self, path_and_query: &str) -> bool {
        match self {
            Self::Prefix(prefix) => path_and_query.starts_with(prefix.as_str()),
            Self::Regex(regex) => {
                let path = path_and_query.split('?').next().unwrap_or(path_and_query);
                regex.is_match(path.as_bytes())
            }
        }
    }
}

/// A crawl's compiled include and exclude patterns.
#[derive(Debug, Clone)]
pub(crate) struct Patterns {
    include: Vec<Matcher>,
    exclude: Vec<Matcher>,
}

fn invalid(message: &str) -> HostError {
    HostError::Invalid(message.into())
}

fn compile_all(kind: PatternKind, patterns: &[String]) -> Result<Vec<Matcher>, HostError> {
    if patterns.len() > crate::crawl::MAX_PATH_PATTERNS {
        return Err(invalid("too many crawl path patterns"));
    }
    patterns
        .iter()
        .map(|pattern| {
            if pattern.is_empty()
                || pattern.len() > crate::crawl::MAX_PATH_PATTERN_BYTES
                || pattern.chars().any(char::is_control)
            {
                return Err(invalid(
                    "a crawl path pattern must be bounded and without control characters",
                ));
            }
            match kind {
                PatternKind::Prefix => {
                    if !pattern.starts_with('/') || pattern.contains('#') {
                        return Err(invalid(
                            "a crawl path pattern must be a bounded absolute path",
                        ));
                    }
                    Ok(Matcher::Prefix(pattern.clone()))
                }
                PatternKind::Regex => {
                    compile_path_regex(pattern)
                        .map(Matcher::Regex)
                        .map_err(|_| {
                            invalid("a crawl path pattern is not a supported regular expression")
                        })
                }
            }
        })
        .collect()
}

impl Patterns {
    pub(crate) fn compile(
        kind: PatternKind,
        include: &[String],
        exclude: &[String],
    ) -> Result<Self, HostError> {
        Ok(Self {
            include: compile_all(kind, include)?,
            exclude: compile_all(kind, exclude)?,
        })
    }

    /// Whether an in-scope page passes: some include pattern matches (or
    /// there is none) and no exclude pattern does.
    pub(crate) fn admits(&self, path_and_query: &str) -> bool {
        let included = self.include.is_empty()
            || self
                .include
                .iter()
                .any(|matcher| matcher.matches(path_and_query));
        let canonical_path = canonical(path_and_query);
        included
            && !self
                .exclude
                .iter()
                .any(|matcher| matcher.matches(path_and_query) || matcher.matches(&canonical_path))
    }
}

/// The form a crawl uses to recognise a URL it already has: the URL with
/// a trailing `/` after a non-root path removed, so `/docs` and `/docs/`
/// are one page (Firecrawl's `normalizeUrl`). The URL opened is unchanged.
pub(crate) fn canonical(url: &str) -> String {
    let (before, query) = match url.split_once('?') {
        Some((before, query)) => (before, Some(query)),
        None => (url, None),
    };
    let after_scheme = before.find("://").map_or(0, |at| at + 3);
    let root = before[after_scheme..]
        .find('/')
        .map_or(before.len(), |at| after_scheme + at);
    let trimmed = if before.len() > root + 1 {
        before.strip_suffix('/').unwrap_or(before)
    } else {
        before
    };
    match query {
        Some(query) => format!("{trimmed}?{query}"),
        None => trimmed.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn regex(include: &[&str], exclude: &[&str]) -> Patterns {
        let owned = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        Patterns::compile(PatternKind::Regex, &owned(include), &owned(exclude)).unwrap()
    }

    /// The same-origin half of Firecrawl's
    /// `test_filter_links_allow_subdomains_with_include_paths` (crawler.rs):
    /// include `^/pricing$` admits /pricing and refuses /blog. (Subdomains
    /// never reach the patterns here: a crawl stays on its one origin.)
    #[test]
    fn wi01_ported_firecrawl_include_case() {
        let pricing = regex(&["^/pricing$"], &[]);
        assert!(pricing.admits("/pricing"));
        assert!(!pricing.admits("/blog"));
    }

    /// Include and exclude are regexes over the path, unanchored unless
    /// anchored; an anchored exclude also holds for the trailing-slash form.
    #[test]
    fn wi01_regex_patterns_follow_firecrawls_path_semantics() {
        assert!(!regex(&[], &["^/docs/private$"]).admits("/docs/private/"));
        let blog = regex(&["^/blog/"], &[]);
        assert!(blog.admits("/blog/post-1"));
        assert!(!blog.admits("/docs/blog/post-1"), "anchored at the start");
        let anywhere = regex(&["blog"], &[]);
        assert!(
            anywhere.admits("/docs/blog/post-1"),
            "unanchored matches anywhere"
        );
        let excluded = regex(&[], &["/private/", r"\.bak$"]);
        assert!(excluded.admits("/docs/a"));
        assert!(!excluded.admits("/docs/private/x"));
        assert!(!excluded.admits("/notes.bak"));
        let both = regex(&["^/docs/"], &["^/docs/old/"]);
        assert!(both.admits("/docs/new/a"));
        assert!(!both.admits("/docs/old/a"), "exclude wins");
        // The query is not part of the matched path.
        assert!(regex(&["^/search$"], &[]).admits("/search?q=x"));
    }

    #[test]
    fn wi01_prefix_patterns_are_unchanged() {
        let owned = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        let prefix = Patterns::compile(
            PatternKind::Prefix,
            &owned(&["/docs/a"]),
            &owned(&["/docs/a/x"]),
        )
        .unwrap();
        assert!(prefix.admits("/docs/a/b"));
        assert!(!prefix.admits("/docs/a/x/y"));
        assert!(!prefix.admits("/docs/b"));
        // A regex-looking prefix is literal.
        let literal = Patterns::compile(PatternKind::Prefix, &owned(&["/docs/.*"]), &[]).unwrap();
        assert!(!literal.admits("/docs/a"));
        assert!(Patterns::compile(PatternKind::Prefix, &owned(&["no-slash"]), &[]).is_err());
    }

    #[test]
    fn wi01_untrusted_regexes_are_refused_not_dropped() {
        let refuse = |pattern: &str| {
            Patterns::compile(PatternKind::Regex, &[pattern.to_owned()], &[]).is_err()
        };
        // Unsupported syntax: look-around and backreferences.
        assert!(refuse("(?=x)"));
        assert!(refuse(r"(a)\1"));
        // A short pattern whose compiled size explodes.
        assert!(refuse("a{5}{5}{5}{5}{5}{5}"));
        // Nesting beyond the limit.
        assert!(refuse(&format!("{}a{}", "(".repeat(60), ")".repeat(60))));
        // Bounds shared with prefixes.
        assert!(refuse(
            &"a".repeat(crate::crawl::MAX_PATH_PATTERN_BYTES + 1)
        ));
        assert!(refuse("a\u{0007}b"));
        assert!(refuse(""));
        let many = vec!["a".to_owned(); crate::crawl::MAX_PATH_PATTERNS + 1];
        assert!(Patterns::compile(PatternKind::Regex, &many, &[]).is_err());
    }

    #[test]
    fn wi01_matching_stays_linear_on_hostile_input() {
        // A pattern that backtracking engines take exponential time on.
        let hostile = regex(&["(a+)+$"], &[]);
        let path = format!("/{}!", "a".repeat(10_000));
        let started = std::time::Instant::now();
        assert!(!hostile.admits(&path));
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn wi01_canonical_form_folds_a_trailing_slash_only() {
        assert_eq!(canonical("https://h/docs/"), "https://h/docs");
        assert_eq!(canonical("https://h/docs"), "https://h/docs");
        assert_eq!(canonical("https://h/"), "https://h/");
        assert_eq!(canonical("https://h"), "https://h");
        assert_eq!(canonical("https://h/docs/?page=2"), "https://h/docs?page=2");
        assert_eq!(canonical("https://h/a//"), "https://h/a/");
    }
}
