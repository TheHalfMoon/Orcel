//! SG-000108 slice 3a: the host's per-request navigation decisions for the
//! live worker.
//!
//! The worker forwards every request the engine makes (top-level documents,
//! redirects, frames, popups, fetch/XHR and other subresources, service
//! workers) as a `route_request`; this module decides each one with the
//! SG-000075 policy and the worker only applies the answer. Destinations are
//! fixed for an engine lifetime: they were admitted with
//! `validate_navigation` (resolution and public-address pinning) and the
//! engine's resolver is pinned to them, so a request may only name one of
//! those hosts, and the mediation rules (exact-origin frames, popups and
//! subresources, bounded same-origin redirect chains) then apply unchanged.

use crate::confinement::AdmittedDestination;
use crate::error::HostError;
use crate::navigation::{
    mediate_frame, mediate_popup, mediate_service_worker, mediate_subresource,
    parse_navigation_url, NavigationTarget, RedirectChain, SubresourceKind,
};

/// What kind of request the worker is asking about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteKind {
    /// A top-level document of the primary page.
    Document,
    /// A redirect hop of a document, frame or popup navigation.
    Redirect,
    /// A child frame's document.
    Frame,
    /// A popup or new window's document.
    Popup,
    /// `fetch` or XHR.
    Fetch,
    /// Any other subresource (script, style, image, font, media, ...).
    Subresource,
    /// A service-worker script or a request made by a service worker.
    ServiceWorker,
}

impl RouteKind {
    /// The closed wire vocabulary.
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "document" => Self::Document,
            "redirect" => Self::Redirect,
            "frame" => Self::Frame,
            "popup" => Self::Popup,
            "fetch" => Self::Fetch,
            "subresource" => Self::Subresource,
            "service_worker" => Self::ServiceWorker,
            _ => return None,
        })
    }
}

/// Per-lifetime navigation state owned by the host.
#[derive(Debug)]
pub struct NavigationPolicy {
    admitted: Vec<String>,
    expected: Option<String>,
    begun_origin: Option<String>,
    chain: Option<RedirectChain>,
    committed_origin: Option<String>,
    /// During an approved activation: the one page-initiated document the
    /// host accepts, and whether it was requested.
    activation: Option<(String, bool)>,
    /// The expectation matches any query on the expected path (a GET form
    /// submission, whose query the engine builds from every field).
    activation_any_query: bool,
    /// During an approved form submission: what the submitted request must
    /// carry (method and field values), checked at the request.
    submission: Option<Submission>,
}

impl std::fmt::Debug for RedirectChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedirectChain")
            .field("hops", &self.len())
            .finish()
    }
}

impl NavigationPolicy {
    pub fn new(destinations: &[AdmittedDestination]) -> Self {
        Self {
            admitted: destinations.iter().map(|d| d.host().to_owned()).collect(),
            expected: None,
            begun_origin: None,
            chain: None,
            committed_origin: None,
            activation: None,
            activation_any_query: false,
            submission: None,
        }
    }

    /// Parse with the SG-000075 parser and require an admitted host.
    fn admitted_target(&self, url: &str) -> Result<NavigationTarget, HostError> {
        let target = parse_navigation_url(url)?;
        if !self.admitted.iter().any(|host| host == &target.host) {
            return Err(HostError::Invalid(format!(
                "{} is not admitted for this browser lifetime",
                target.host
            )));
        }
        Ok(target)
    }

    /// Start a host-requested top-level navigation.
    pub fn begin(&mut self, url: &str) -> Result<NavigationTarget, HostError> {
        let target = self.admitted_target(url)?;
        self.chain = Some(RedirectChain::start(url)?);
        self.expected = Some(url.to_owned());
        self.begun_origin = Some(target.origin.clone());
        Ok(target)
    }

    /// Record the committed top-level document after a navigation. The
    /// committed origin must be the one the navigation began with, so even a
    /// redirect hop that escaped interception cannot widen the page.
    pub fn commit(&mut self, url: &str) -> Result<(), HostError> {
        let target = self.admitted_target(url)?;
        let begun = self.begun_origin.take();
        if begun.as_deref() != Some(target.origin.as_str()) {
            self.expected = None;
            self.chain = None;
            return Err(HostError::Invalid(
                "the committed document left the navigation's origin".into(),
            ));
        }
        self.committed_origin = Some(target.origin);
        self.expected = None;
        self.chain = None;
        Ok(())
    }

    /// Record a document the page reached itself (for example through an
    /// approved activation): it must be an admitted name on the committed
    /// origin. Any in-progress navigation state is cleared.
    pub fn commit_page_initiated(&mut self, url: &str) -> Result<(), HostError> {
        let target = self.admitted_target(url)?;
        self.abort();
        if self.committed_origin.as_deref() != Some(target.origin.as_str()) {
            return Err(HostError::Invalid(
                "the page left its committed origin".into(),
            ));
        }
        Ok(())
    }

    /// Expect exactly one page-initiated document, `url`, for an approved
    /// activation: any other page-initiated top-level document is refused
    /// while the expectation stands.
    pub fn expect_activation(&mut self, url: &str) -> Result<(), HostError> {
        let target = self.admitted_target(url)?;
        if self.committed_origin.as_deref() != Some(target.origin.as_str()) {
            return Err(HostError::Invalid(
                "activation leaves the page's origin".into(),
            ));
        }
        self.activation = Some((url.to_owned(), false));
        self.activation_any_query = false;
        Ok(())
    }

    /// Expect exactly one page-initiated document for an approved form
    /// submission to `action`: the exact URL for POST; for GET (`any_query`)
    /// the same URL with whatever query the engine builds from the form's
    /// fields, including fields the host never sees.
    pub fn expect_submission(
        &mut self,
        action: &str,
        any_query: bool,
        submission: Submission,
    ) -> Result<(), HostError> {
        let path = action.split('?').next().unwrap_or(action);
        self.expect_activation(if any_query { path } else { action })?;
        self.activation_any_query = any_query;
        self.submission = Some(submission);
        Ok(())
    }

    /// BR-02: while a form action runs, the page opens no document at all:
    /// every page-initiated top-level document and popup is refused until
    /// `finish_activation`.
    pub fn expect_no_document(&mut self) {
        // An expectation already spent matches nothing.
        self.activation = Some((String::new(), true));
        self.activation_any_query = false;
        self.submission = None;
    }

    /// End the activation expectation; true if the expected document was
    /// requested (a click that requested no document, such as a pushState
    /// or a script action, is not a verified activation).
    pub fn finish_activation(&mut self) -> bool {
        self.activation_any_query = false;
        self.submission = None;
        matches!(self.activation.take(), Some((_, true)))
    }

    /// Whether the expected document has been requested so far.
    pub fn activation_opened(&self) -> bool {
        matches!(self.activation, Some((_, true)))
    }

    pub fn committed_origin(&self) -> Option<&str> {
        self.committed_origin.as_deref()
    }

    /// Clear an in-progress navigation that did not commit, so its expected
    /// URL and redirect chain cannot authorize anything later.
    pub fn abort(&mut self) {
        self.expected = None;
        self.begun_origin = None;
        self.chain = None;
    }

    /// The origin the host itself holds for the page: the origin of the
    /// navigation in progress, otherwise the committed one. Requests are
    /// mediated against this, never against an origin the worker reports,
    /// so a page that moved itself without a host decision (for example by
    /// activating a prerender) gains nothing.
    fn current_origin(&self) -> Result<&str, HostError> {
        self.begun_origin
            .as_deref()
            .or(self.committed_origin.as_deref())
            .ok_or_else(|| HostError::Invalid("no page origin is established".into()))
    }

    /// Decide one forwarded request. `origin` is what the worker reports
    /// for the requesting context; it must agree with the host's own page
    /// origin when present (empty for top-level documents and opaque
    /// frames), and the decision itself uses the host's origin.
    pub fn decide(&mut self, kind: RouteKind, url: &str, origin: &str) -> Result<(), HostError> {
        self.decide_request(kind, url, origin, &RequestDetail::default())
    }

    /// `decide`, with the request's method and (bounded) body: an approved
    /// form submission is checked against exactly what it may send.
    pub fn decide_request(
        &mut self,
        kind: RouteKind,
        url: &str,
        origin: &str,
        detail: &RequestDetail,
    ) -> Result<(), HostError> {
        let target = self.admitted_target(url)?;
        // While an approved activation is pending, its document is the only
        // one: a popup (a `target` elsewhere) is refused, and so is a frame
        // document during a submission.
        if self.activation.is_some() && matches!(kind, RouteKind::Popup) {
            return Err(refused("an activation may not open a popup"));
        }
        if self.submission.is_some() && matches!(kind, RouteKind::Frame) {
            return Err(refused("a submission may not open a frame"));
        }
        if !matches!(kind, RouteKind::Document) && !origin.is_empty() {
            let reported = parse_navigation_url(origin)?;
            if reported.origin != self.current_origin()? {
                return Err(HostError::Invalid(
                    "the requesting origin is not the page's origin".into(),
                ));
            }
        }
        match kind {
            RouteKind::Document => {
                if self.expected.as_deref() == Some(url) {
                    return Ok(());
                }
                let any_query = self.activation_any_query;
                if let Some((expected, taken)) = self.activation.as_mut() {
                    // An approved activation opens exactly its destination,
                    // once; a script redirect or a changed href goes nowhere.
                    let matches = if any_query {
                        url.split('?').next() == Some(expected.as_str())
                    } else {
                        expected.as_str() == url
                    };
                    if !matches || *taken {
                        return Err(HostError::Invalid(
                            "the activation opened another document".into(),
                        ));
                    }
                    if let Some(submission) = &self.submission {
                        if let Err(error) = submission.check(url, detail) {
                            // A refused submission spends the expectation:
                            // nothing later opens it, and it is unverified.
                            expected.clear();
                            return Err(error);
                        }
                    }
                    *taken = true;
                    self.chain = Some(RedirectChain::start(url)?);
                    return Ok(());
                }
                // A page-initiated top-level navigation stays within the
                // committed origin and starts its own redirect chain.
                match self.committed_origin.as_deref() {
                    Some(committed) if committed == target.origin => {
                        self.chain = Some(RedirectChain::start(url)?);
                        Ok(())
                    }
                    _ => Err(HostError::Invalid(
                        "top-level navigation widening denied".into(),
                    )),
                }
            }
            RouteKind::Redirect => match self.chain.as_mut() {
                Some(chain) => chain.push(url),
                // A subresource redirect after commit stays on the page's
                // origin (the engine bounds its own redirect count).
                None => {
                    let base = self.current_origin()?.to_owned();
                    mediate_subresource(&base, url, SubresourceKind::Fetch).map(|_| ())
                }
            },
            RouteKind::Frame => mediate_frame(self.current_origin()?, url).map(|_| ()),
            RouteKind::Popup => mediate_popup(self.current_origin()?, url).map(|_| ()),
            RouteKind::Fetch | RouteKind::Subresource => {
                mediate_subresource(self.current_origin()?, url, SubresourceKind::Fetch).map(|_| ())
            }
            RouteKind::ServiceWorker => {
                // Service workers are refused outright (SG-000108 #301); the
                // mediation result is irrelevant.
                let _ = mediate_service_worker(self.current_origin().unwrap_or(""), url);
                Err(HostError::Invalid("service worker denied".into()))
            }
        }
    }
}

/// What the worker reports about a request besides its URL.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestDetail {
    /// Upper-case HTTP method ("GET" when unknown).
    pub method: String,
    pub content_type: String,
    /// The request body, when it fit the worker's bound.
    pub body: Option<String>,
    /// The body's full size in bytes.
    pub body_bytes: u64,
}

/// What one approved field must submit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Submitted {
    /// Exactly these values, in any order.
    Values(Vec<String>),
    /// A checked checkbox: one value, whatever the author declared.
    Present,
    /// An unchecked checkbox: nothing.
    Absent,
}

/// What an approved form submission may send: its method, every approved
/// field's values, and the declared parameters it did not supply (those may
/// appear only empty). Undeclared names (hidden fields the host never sees,
/// such as a CSRF token) may appear with any value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Submission {
    pub method: String,
    pub fields: Vec<(String, Submitted)>,
    pub unsupplied: Vec<String>,
    /// Textarea fields: the engine submits line breaks as CRLF.
    pub multiline: Vec<String>,
    /// The form's own non-parameter names (hidden, read-only, the default
    /// button), with any value; no other undeclared name may appear.
    pub fixed: Vec<String>,
}

fn refused(reason: &str) -> HostError {
    HostError::Invalid(format!(
        "the submission does not match its approval: {reason}"
    ))
}

/// Decode `application/x-www-form-urlencoded` (strict: invalid escapes or
/// UTF-8 refuse).
pub fn decode_form(text: &str) -> Result<Vec<(String, String)>, HostError> {
    fn decode(part: &str) -> Result<String, HostError> {
        let bytes = part.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'+' => out.push(b' '),
                b'%' => {
                    let hex = bytes
                        .get(i + 1..i + 3)
                        .and_then(|h| std::str::from_utf8(h).ok())
                        .and_then(|h| u8::from_str_radix(h, 16).ok())
                        .ok_or_else(|| refused("malformed escape"))?;
                    out.push(hex);
                    i += 2;
                }
                byte => out.push(byte),
            }
            i += 1;
        }
        String::from_utf8(out).map_err(|_| refused("malformed UTF-8"))
    }
    if text.is_empty() {
        return Ok(Vec::new());
    }
    text.split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            Ok((decode(name)?, decode(value)?))
        })
        .collect()
}

impl Submission {
    fn check(&self, url: &str, detail: &RequestDetail) -> Result<(), HostError> {
        let method = if detail.method.is_empty() {
            "GET"
        } else {
            detail.method.as_str()
        };
        if !method.eq_ignore_ascii_case(&self.method) {
            return Err(refused("another method"));
        }
        let pairs = if self.method.eq_ignore_ascii_case("POST") {
            let urlencoded = detail.content_type.split(';').next().is_some_and(|t| {
                t.trim()
                    .eq_ignore_ascii_case("application/x-www-form-urlencoded")
            });
            let body = detail
                .body
                .as_deref()
                .filter(|body| body.len() as u64 == detail.body_bytes)
                .ok_or_else(|| refused("the body is missing or cut"))?;
            if !urlencoded {
                return Err(refused("not a urlencoded body"));
            }
            decode_form(body)?
        } else {
            decode_form(url.split_once('?').map(|(_, q)| q).unwrap_or(""))?
        };
        for (name, expected) in &self.fields {
            let mut sent: Vec<String> = pairs
                .iter()
                .filter(|(key, _)| key == name)
                .map(|(_, value)| {
                    if self.multiline.contains(name) {
                        value.replace("\r\n", "\n")
                    } else {
                        value.clone()
                    }
                })
                .collect();
            let ok = match expected {
                Submitted::Values(values) => {
                    let mut wanted = values.clone();
                    wanted.sort();
                    sent.sort();
                    sent == wanted
                }
                Submitted::Present => sent.len() == 1,
                Submitted::Absent => sent.is_empty(),
            };
            if !ok {
                return Err(refused("an approved field carries other values"));
            }
        }
        for (key, _) in &pairs {
            let known = self.fields.iter().any(|(name, _)| name == key)
                || self.unsupplied.contains(key)
                || self.fixed.contains(key);
            if !known {
                return Err(refused("an undeclared name was added to the submission"));
            }
        }
        for name in &self.unsupplied {
            if pairs
                .iter()
                .any(|(key, value)| key == name && !value.is_empty())
            {
                return Err(refused("an unsupplied parameter carries a value"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn policy() -> NavigationPolicy {
        let a =
            AdmittedDestination::fixture("fixture.test", IpAddr::V4(Ipv4Addr::LOCALHOST)).unwrap();
        let b =
            AdmittedDestination::fixture("other.test", IpAddr::V4(Ipv4Addr::LOCALHOST)).unwrap();
        NavigationPolicy::new(&[a, b])
    }

    const HOME: &str = "https://fixture.test";

    /// BR-02: during a form action the page opens no document, not even on
    /// its own origin, and no popup; afterwards ordinary rules apply again.
    #[test]
    fn br02_a_form_action_opens_no_document() {
        let mut p = policy();
        p.begin("https://fixture.test/form").unwrap();
        p.commit("https://fixture.test/form").unwrap();
        p.expect_no_document();
        assert!(p
            .decide(RouteKind::Document, "https://fixture.test/next", "")
            .is_err());
        assert!(p
            .decide(RouteKind::Popup, "https://fixture.test/x", HOME)
            .is_err());
        // Subresources (for example a field's lookup request) still follow
        // the usual origin rules.
        assert!(p
            .decide(RouteKind::Fetch, "https://fixture.test/api/lookup", HOME)
            .is_ok());
        p.finish_activation();
        assert!(p
            .decide(RouteKind::Document, "https://fixture.test/next", "")
            .is_ok());
    }

    #[test]
    fn only_admitted_https_destinations_can_begin() {
        let mut p = policy();
        assert!(p.begin("https://fixture.test/reports").is_ok());
        for url in [
            "https://example.com/",
            "http://fixture.test/",
            "https://fixture.test:8443/",
            "https://user@fixture.test/",
            "https://127.0.0.1/",
            "file:///C:/x",
            "javascript:alert(1)",
        ] {
            assert!(p.begin(url).is_err(), "{url}");
        }
    }

    #[test]
    fn documents_redirects_and_commits_follow_the_chain() {
        let mut p = policy();
        p.begin("https://fixture.test/a").unwrap();
        assert!(p
            .decide(RouteKind::Document, "https://fixture.test/a", "")
            .is_ok());
        assert!(p
            .decide(RouteKind::Redirect, "https://fixture.test/b", HOME)
            .is_ok());
        // Widening, loops, and other admitted origins are refused.
        assert!(p
            .decide(RouteKind::Redirect, "https://other.test/c", HOME)
            .is_err());
        assert!(p
            .decide(RouteKind::Redirect, "https://fixture.test/b", HOME)
            .is_err());
        // A commit on another (even admitted) origin is refused.
        let mut widened = policy();
        widened.begin("https://fixture.test/a").unwrap();
        assert!(widened.commit("https://other.test/a").is_err());
        assert!(
            widened.commit("https://fixture.test/a").is_err(),
            "no navigation in progress"
        );
        p.commit("https://fixture.test/b").unwrap();
        // The SG-000075 parser normalizes origins with an explicit port.
        assert_eq!(p.committed_origin(), Some("https://fixture.test:443"));
        // Page-initiated same-origin navigation is allowed, cross-origin not.
        assert!(p
            .decide(RouteKind::Document, "https://fixture.test/next", "")
            .is_ok());
        assert!(p
            .decide(RouteKind::Document, "https://other.test/", "")
            .is_err());
        // A redirect needs an active chain.
        let mut fresh = policy();
        assert!(fresh
            .decide(RouteKind::Redirect, "https://fixture.test/x", HOME)
            .is_err());
        // An unrequested document before any commit is refused.
        assert!(fresh
            .decide(RouteKind::Document, "https://fixture.test/x", "")
            .is_err());
    }

    #[test]
    fn redirect_chains_are_bounded() {
        let mut p = policy();
        p.begin("https://fixture.test/0").unwrap();
        let mut refused = false;
        for hop in 1..=10 {
            if p.decide(
                RouteKind::Redirect,
                &format!("https://fixture.test/{hop}"),
                HOME,
            )
            .is_err()
            {
                refused = true;
                break;
            }
        }
        assert!(refused, "the redirect chain was never limited");
    }

    #[test]
    fn frames_popups_and_subresources_are_exact_origin() {
        let mut p = policy();
        // Nothing is mediated before the host has a page origin.
        assert!(p
            .decide(RouteKind::Fetch, "https://fixture.test/x", HOME)
            .is_err());
        p.begin("https://fixture.test/").unwrap();
        p.commit("https://fixture.test/").unwrap();
        for kind in [
            RouteKind::Frame,
            RouteKind::Popup,
            RouteKind::Fetch,
            RouteKind::Subresource,
        ] {
            assert!(
                p.decide(kind, "https://fixture.test/x", HOME).is_ok(),
                "{kind:?}"
            );
            assert!(
                p.decide(kind, "https://other.test/x", HOME).is_err(),
                "{kind:?}"
            );
            assert!(
                p.decide(kind, "https://example.com/x", HOME).is_err(),
                "{kind:?}"
            );
            assert!(
                p.decide(kind, "http://fixture.test/x", HOME).is_err(),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn the_hosts_origin_governs_not_the_reported_one() {
        let mut p = policy();
        p.begin("https://fixture.test/").unwrap();
        p.commit("https://fixture.test/").unwrap();
        // A page that moved itself to other.test (prerender activation)
        // reports other.test as its origin: refused.
        assert!(p
            .decide(
                RouteKind::Fetch,
                "https://other.test/x",
                "https://other.test"
            )
            .is_err());
        assert!(p
            .decide(
                RouteKind::Subresource,
                "https://fixture.test/x",
                "https://other.test"
            )
            .is_err());
        // Opaque frames report no origin and are held to the page's origin.
        assert!(p
            .decide(RouteKind::Fetch, "https://fixture.test/x", "")
            .is_ok());
        assert!(p
            .decide(RouteKind::Fetch, "https://other.test/x", "")
            .is_err());
        // Subresource redirects after commit stay on the page's origin.
        assert!(p
            .decide(RouteKind::Redirect, "https://fixture.test/moved", HOME)
            .is_ok());
        assert!(p
            .decide(RouteKind::Redirect, "https://other.test/moved", HOME)
            .is_err());
    }

    fn any_get() -> Submission {
        Submission {
            method: "GET".into(),
            fields: Vec::new(),
            unsupplied: Vec::new(),
            multiline: Vec::new(),
            fixed: vec!["q".into(), "csrf".into()],
        }
    }

    fn post_note() -> Submission {
        Submission {
            method: "POST".into(),
            fields: vec![("note".into(), Submitted::Values(vec!["a\nb".into()]))],
            unsupplied: Vec::new(),
            multiline: vec!["note".into()],
            fixed: Vec::new(),
        }
    }

    fn post(body: &str) -> RequestDetail {
        RequestDetail {
            method: "POST".into(),
            content_type: "application/x-www-form-urlencoded".into(),
            body: Some(body.into()),
            body_bytes: body.len() as u64,
        }
    }

    #[test]
    fn a_submission_must_send_exactly_its_approved_fields() {
        let search = Submission {
            method: "GET".into(),
            fields: vec![
                ("q".into(), Submitted::Values(vec!["rust lang".into()])),
                (
                    "tags".into(),
                    Submitted::Values(vec!["a".into(), "b".into()]),
                ),
                ("exact".into(), Submitted::Present),
                ("off".into(), Submitted::Absent),
            ],
            unsupplied: vec!["year".into()],
            multiline: Vec::new(),
            fixed: vec!["csrf".into()],
        };
        let get = RequestDetail {
            method: "GET".into(),
            ..RequestDetail::default()
        };
        let check = |url: &str, detail: &RequestDetail| search.check(url, detail);
        assert!(check(
            "https://f.test/s?q=rust+lang&tags=b&tags=a&exact=on&csrf=t&year=",
            &get
        )
        .is_ok());
        for bad in [
            "https://f.test/s?q=evil&tags=a&tags=b&exact=on",
            "https://f.test/s?q=rust+lang&q=x&tags=a&tags=b&exact=on",
            "https://f.test/s?q=rust+lang&tags=a&exact=on",
            "https://f.test/s?q=rust+lang&tags=a&tags=b",
            "https://f.test/s?q=rust+lang&tags=a&tags=b&exact=on&off=on",
            "https://f.test/s?q=rust+lang&tags=a&tags=b&exact=on&year=2026",
            "https://f.test/s?q=%ZZ&tags=a&tags=b&exact=on",
            "https://f.test/s?q=%FF&tags=a&tags=b&exact=on",
        ] {
            assert!(check(bad, &get).is_err(), "{bad}");
        }
        // Another method is refused.
        assert!(check(
            "https://f.test/s?q=rust+lang&tags=a&tags=b&exact=on",
            &post("")
        )
        .is_err());
        // POST: the body is checked; line breaks arrive as CRLF.
        let note = post_note();
        assert!(note
            .check("https://f.test/n", &post("note=a%0D%0Ab"))
            .is_ok());
        assert!(note.check("https://f.test/n", &post("note=evil")).is_err());
        let mut cut = post("note=a%0D%0Ab");
        cut.body_bytes += 1;
        assert!(note.check("https://f.test/n", &cut).is_err(), "a cut body");
        let mut multipart = post("note=a%0D%0Ab");
        multipart.content_type = "multipart/form-data; boundary=x".into();
        assert!(note.check("https://f.test/n", &multipart).is_err());
    }

    #[test]
    fn a_pending_activation_refuses_popups() {
        let mut p = policy();
        p.begin("https://fixture.test/").unwrap();
        p.commit("https://fixture.test/").unwrap();
        assert!(p
            .decide(RouteKind::Popup, "https://fixture.test/a", "")
            .is_ok());
        p.expect_activation("https://fixture.test/a").unwrap();
        assert!(p
            .decide(RouteKind::Popup, "https://fixture.test/a", "")
            .is_err());
        assert!(p
            .decide(RouteKind::Frame, "https://fixture.test/f", "")
            .is_ok());
        assert!(!p.finish_activation());
    }

    #[test]
    fn a_pending_submission_refuses_other_names_frames_and_popups_and_stays_spent() {
        let mut p = policy();
        p.begin("https://fixture.test/").unwrap();
        p.commit("https://fixture.test/").unwrap();
        p.expect_submission("https://fixture.test/search", true, any_get())
            .unwrap();
        assert!(p
            .decide(RouteKind::Popup, "https://fixture.test/search?q=1", "")
            .is_err());
        assert!(p
            .decide(RouteKind::Frame, "https://fixture.test/search?q=1", "")
            .is_err());
        assert!(p
            .decide(
                RouteKind::Document,
                "https://fixture.test/search?q=1&added=x",
                ""
            )
            .is_err());
        assert!(
            p.decide(RouteKind::Document, "https://fixture.test/search?q=1", "")
                .is_err(),
            "a refused submission is spent"
        );
        assert!(!p.finish_activation());
    }

    #[test]
    fn a_submission_opens_its_action_once_with_any_query_for_get() {
        let mut p = policy();
        p.begin("https://fixture.test/").unwrap();
        p.commit("https://fixture.test/").unwrap();
        assert!(p
            .expect_submission("https://other.test/search", true, any_get())
            .is_err());
        p.expect_submission("https://fixture.test/search?ignored=1", true, any_get())
            .unwrap();
        assert!(p
            .decide(RouteKind::Document, "https://fixture.test/searchx?q=1", "")
            .is_err());
        assert!(p
            .decide(
                RouteKind::Document,
                "https://fixture.test/search?q=rust&csrf=t",
                ""
            )
            .is_ok());
        assert!(
            p.decide(
                RouteKind::Document,
                "https://fixture.test/search?q=again",
                ""
            )
            .is_err(),
            "twice"
        );
        assert!(p.finish_activation());
        // POST: the exact action only.
        p.expect_submission("https://fixture.test/post", false, post_note())
            .unwrap();
        assert!(p
            .decide(RouteKind::Document, "https://fixture.test/post?x=1", "")
            .is_err());
        assert!(!p.finish_activation());
        p.expect_submission("https://fixture.test/post", false, post_note())
            .unwrap();
        assert!(p
            .decide_request(
                RouteKind::Document,
                "https://fixture.test/post",
                "",
                &post("note=a%0D%0Ab")
            )
            .is_ok());
        assert!(p.finish_activation());
    }

    #[test]
    fn an_activation_opens_exactly_its_destination_once() {
        let mut p = policy();
        p.begin("https://fixture.test/").unwrap();
        p.commit("https://fixture.test/").unwrap();
        assert!(p.expect_activation("https://other.test/x").is_err());
        p.expect_activation("https://fixture.test/report").unwrap();
        assert!(p
            .decide(RouteKind::Document, "https://fixture.test/evil", "")
            .is_err());
        assert!(!p.activation_opened());
        assert!(p
            .decide(RouteKind::Document, "https://fixture.test/report", "")
            .is_ok());
        assert!(p.activation_opened());
        assert!(
            p.decide(RouteKind::Document, "https://fixture.test/report", "")
                .is_err(),
            "twice"
        );
        assert!(p.finish_activation());
        // A click that requested no document is not verified.
        p.expect_activation("https://fixture.test/report").unwrap();
        assert!(!p.finish_activation());
        // Without an expectation, same-origin page navigation is as before.
        assert!(p
            .decide(RouteKind::Document, "https://fixture.test/next", "")
            .is_ok());
    }

    #[test]
    fn page_initiated_commits_stay_on_the_committed_origin() {
        let mut p = policy();
        assert!(
            p.commit_page_initiated("https://fixture.test/x").is_err(),
            "nothing committed yet"
        );
        p.begin("https://fixture.test/").unwrap();
        p.commit("https://fixture.test/").unwrap();
        assert!(p.commit_page_initiated("https://fixture.test/next").is_ok());
        assert!(p.commit_page_initiated("https://other.test/next").is_err());
        assert!(p.commit_page_initiated("https://example.com/").is_err());
    }

    #[test]
    fn an_aborted_navigation_authorizes_nothing() {
        let mut p = policy();
        p.begin("https://fixture.test/a").unwrap();
        p.abort();
        assert!(p
            .decide(RouteKind::Document, "https://fixture.test/a", "")
            .is_err());
        assert!(p
            .decide(RouteKind::Fetch, "https://fixture.test/x", "")
            .is_err());
        assert!(p.commit("https://fixture.test/a").is_err());
    }

    #[test]
    fn service_workers_and_unknown_kinds_are_refused() {
        let mut p = policy();
        assert!(p
            .decide(RouteKind::ServiceWorker, "https://fixture.test/sw.js", HOME)
            .is_err());
        assert_eq!(RouteKind::parse("websocket"), None);
        assert_eq!(RouteKind::parse("Document"), None);
        assert_eq!(RouteKind::parse("document"), Some(RouteKind::Document));
    }
}
