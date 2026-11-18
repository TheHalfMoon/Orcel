//! SG-000135 OB-08: Full Access browser leases, issued by the SG-000132
//! authority service only (SG-000132 slice 2).
//!
//! A browser lease is an owner-issued, scope- and time-bounded authority for
//! one Orcel Browser broker session: one client, one session (its profile is
//! the session's own, so the profile is session-bound for now), exact
//! canonical origins and named action families. Under a valid lease orceld
//! dispatches a positively classified routine action of a covered family on
//! a covered origin without a per-action SOFT prompt; everything else asks
//! as before.
//!
//! Issuance: only the authority service (`orcel browser grant`: a recorded
//! intent, a service-observed unlock, the service-rendered confirmation and
//! a Windows Hello signature over a challenge bound to the confirmation
//! text). The interim issuance on the user-readable full-control store that
//! OB-08 first used is gone: no build of orceld issues or stores a browser
//! lease, and nothing here can make one. orceld admits a lease only after it
//! checked the service's ECDSA signature with the public key the verified
//! service reported, and the service said the lease is active
//! (`orceld::authority_link`). An agent, MCP, donor, relay or remote caller
//! never issues, widens or renews one.
//!
//! A lease is bound to the Windows user and logon session, the service's
//! authority epoch and its revocation counter at issuance, the session, the
//! client and the session's task label. Any drift, expiry or revoke fails
//! closed.
//!
//! Every scope list narrows and nothing is implied: an origin matches only
//! exactly (after canonicalization), a family only by name, and `download`
//! is never implied by any other family.

use crate::PolicyError;
use orcel_contracts::FailureCode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The longest task label a lease names (the broker's own bound).
pub const MAX_LEASE_TASK_CHARS: usize = 64;
/// The most origins one lease names (the authority service's bound, so the
/// whole scope fits its confirmation).
pub const MAX_BROWSER_LEASE_ORIGINS: usize = 16;
/// The shortest and longest lease.
pub const MIN_BROWSER_LEASE_MS: u64 = 60_000;
pub const MAX_BROWSER_LEASE_MS: u64 = 12 * 60 * 60 * 1_000;
/// The prefix of a client reference (`client_ref`).
pub const CLIENT_REF_PREFIX: &str = "cl-";
/// The prefix of an authority service lease id.
pub const SERVICE_LEASE_ID_PREFIX: &str = "al-";
const LONGEST_HOST: usize = 253;

/// The action families a browser lease may name. `download` is opt-in: no
/// other family implies it, and it is never part of a default scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserFamily {
    /// Navigate the session's page (`browser_open`, a new tab's URL).
    Navigate,
    /// Activate an observed control that is not classified high-impact.
    Click,
    /// Type or fill text into a non-secret field.
    Type,
    /// Choose an option in a list.
    Select,
    /// Scroll the page.
    Scroll,
    /// Read the page (snapshot, verify, extract, screenshot).
    Read,
    /// Open, switch and close the session's tabs.
    Tabs,
    /// Download a file (opt-in only).
    Download,
}

/// The families orceld can enforce under a lease in this build. `read`,
/// `scroll` and `download` are named in the vocabulary but are refused at
/// the grant (the service refuses them too) until a packet implements them.
pub const IMPLEMENTED_FAMILIES: [BrowserFamily; 5] = [
    BrowserFamily::Navigate,
    BrowserFamily::Click,
    BrowserFamily::Type,
    BrowserFamily::Select,
    BrowserFamily::Tabs,
];

impl BrowserFamily {
    pub const ALL: [Self; 8] = [
        Self::Navigate,
        Self::Click,
        Self::Type,
        Self::Select,
        Self::Scroll,
        Self::Read,
        Self::Tabs,
        Self::Download,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Navigate => "navigate",
            Self::Click => "click",
            Self::Type => "type",
            Self::Select => "select",
            Self::Scroll => "scroll",
            Self::Read => "read",
            Self::Tabs => "tabs",
            Self::Download => "download",
        }
    }

    /// The family named exactly `name`, or none.
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|family| family.as_str() == name)
    }
}

/// A browser lease the authority service issued and signed, as orceld
/// admitted it: the signature verified with the service's public key and
/// the service reported it active. orceld never builds one any other way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserLease {
    /// The service's lease id (`al-` and 32 lowercase hex).
    pub lease_id: String,
    /// The client (MCP session) the session belongs to, by reference.
    pub client_ref: String,
    /// The broker session (and so its profile) the lease covers.
    pub session_id: String,
    pub windows_user_sid: String,
    pub logon_session_id: u64,
    /// The service's authority epoch at issuance.
    pub authority_epoch: u64,
    /// The service's revocation counter at issuance (it only grows).
    pub revocations_at_issue: u64,
    /// Exact canonical origins (`https://host[:port]`, no `:443`).
    pub origins: Vec<String>,
    /// Sorted, distinct.
    pub families: Vec<BrowserFamily>,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    /// The session's task label the owner saw (none when it has none).
    pub task: Option<String>,
    /// The principal the service binds Authorize to (the client_ref).
    pub principal_id: String,
    /// Who asked, as the service observed it on its pipe.
    pub requester: String,
}

/// What a lease is checked against right now (read from the service).
#[derive(Debug, Clone, Copy)]
pub struct BrowserLeaseContext<'a> {
    pub windows_user_sid: &'a str,
    pub logon_session_id: u64,
    /// The service's authority epoch, read now.
    pub authority_epoch: u64,
    /// The service's revocation counter, read now.
    pub revocations: u64,
    pub session_id: &'a str,
    pub client_ref: &'a str,
    /// The session's own task label.
    pub task: Option<&'a str>,
    pub now_ms: u64,
}

fn invalid(message: impl Into<String>) -> PolicyError {
    PolicyError {
        code: FailureCode::InvalidRequest,
        message: message.into(),
    }
}

fn denied(message: impl Into<String>) -> PolicyError {
    PolicyError {
        code: FailureCode::CapabilityDenied,
        message: message.into(),
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn is_lower_hex(text: &str, length: usize) -> bool {
    text.len() == length
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The canonical form of an origin an owner or a page names: `https://`
/// (scheme case-insensitive), a lowercase DNS host of letters, digits,
/// hyphens and dots, and an optional port (`:443` dropped). One trailing
/// `/` is accepted and dropped; a path, query, fragment, user info,
/// wildcard, IP literal in brackets or any other character is refused.
pub fn canonical_origin(text: &str) -> Option<String> {
    let scheme = text.get(..8)?;
    if !scheme.eq_ignore_ascii_case("https://") {
        return None;
    }
    let rest = &text[8..];
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    if rest.is_empty() || rest.contains(['/', '?', '#', '@', '[', ']', '\\']) {
        return None;
    }
    let (host, port) = match rest.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (rest, None),
    };
    let host = host.to_ascii_lowercase();
    let label_ok = |label: &str| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    if host.is_empty() || host.len() > LONGEST_HOST || !host.split('.').all(label_ok) {
        return None;
    }
    let port = match port {
        None => None,
        Some(port) => {
            if port.is_empty()
                || port.len() > 5
                || port.starts_with('0')
                || !port.bytes().all(|b| b.is_ascii_digit())
            {
                return None;
            }
            let number: u32 = port.parse().ok()?;
            if number == 0 || number > 65_535 {
                return None;
            }
            (number != 443).then_some(number)
        }
    };
    Some(match port {
        Some(port) => format!("https://{host}:{port}"),
        None => format!("https://{host}"),
    })
}

/// Whether `id` is a broker session id (`bs-<16 hex>-<counter>-<16 hex>`).
pub fn is_session_id(id: &str) -> bool {
    let Some(rest) = id.strip_prefix("bs-") else {
        return false;
    };
    let parts: Vec<&str> = rest.split('-').collect();
    let [instance, counter, random] = parts.as_slice() else {
        return false;
    };
    is_lower_hex(instance, 16)
        && is_lower_hex(random, 16)
        && !counter.is_empty()
        && counter.len() <= 6
        && !counter.starts_with('0')
        && counter.bytes().all(|b| b.is_ascii_digit())
}

/// Whether `text` is a client reference (`cl-` and 32 lowercase hex).
pub fn is_client_ref(text: &str) -> bool {
    text.strip_prefix(CLIENT_REF_PREFIX)
        .is_some_and(|hex| is_lower_hex(hex, 32))
}

/// The client reference of an MCP session id: a domain-separated digest,
/// so the reference names the client without carrying its session id.
pub fn client_ref(client_session_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"orcel/sg000135/browser-lease-client/v1");
    hasher.update((client_session_id.len() as u64).to_le_bytes());
    hasher.update(client_session_id.as_bytes());
    let digest = lower_hex(&hasher.finalize());
    format!("{CLIENT_REF_PREFIX}{}", &digest[..32])
}

fn bounded_field(name: &str, value: &str) -> Result<(), PolicyError> {
    if value.is_empty()
        || value.len() > crate::full_control::MAX_AUTHORITY_FIELD_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(invalid(format!("browser lease {name} malformed")));
    }
    Ok(())
}

/// A task label as a lease names it: 1 to 64 characters on one line.
pub fn check_task(task: Option<&str>) -> Result<(), PolicyError> {
    match task {
        None => Ok(()),
        Some(task)
            if !task.is_empty()
                && task.chars().count() <= MAX_LEASE_TASK_CHARS
                && !task.chars().any(char::is_control) =>
        {
            Ok(())
        }
        Some(_) => Err(invalid("browser lease task label malformed")),
    }
}

/// Check and canonicalize a scope: 1 to 16 distinct canonical origins and
/// 1 to 5 distinct implemented families. Returns the canonical origins in
/// the order given and the families sorted.
pub fn check_scope(
    origins: &[String],
    families: &[BrowserFamily],
) -> Result<(Vec<String>, Vec<BrowserFamily>), PolicyError> {
    if origins.is_empty() || origins.len() > MAX_BROWSER_LEASE_ORIGINS {
        return Err(invalid(format!(
            "a browser lease names 1 to {MAX_BROWSER_LEASE_ORIGINS} origins"
        )));
    }
    let mut canonical = Vec::with_capacity(origins.len());
    for origin in origins {
        let Some(exact) = canonical_origin(origin) else {
            return Err(invalid(
                "a browser lease origin is https://host[:port] exactly, with no path, wildcard or user info",
            ));
        };
        if canonical.contains(&exact) {
            return Err(invalid("a browser lease names each origin once"));
        }
        canonical.push(exact);
    }
    if families.is_empty() || families.len() > IMPLEMENTED_FAMILIES.len() {
        return Err(invalid("a browser lease names 1 to 5 action families"));
    }
    let mut sorted = families.to_vec();
    sorted.sort();
    sorted.dedup();
    if sorted.len() != families.len() {
        return Err(invalid("a browser lease names each action family once"));
    }
    if let Some(missing) = sorted
        .iter()
        .find(|family| !IMPLEMENTED_FAMILIES.contains(family))
    {
        return Err(invalid(format!(
            "the {} family is not implemented under a browser lease yet; a lease names only navigate, click, type, select or tabs",
            missing.as_str()
        )));
    }
    Ok((canonical, sorted))
}

impl BrowserLease {
    /// The admitted shape: a service lease id, bounded fields, a canonical
    /// scope with sorted families and a bounded positive time box. A lease
    /// failing it is refused.
    pub fn check_shape(&self) -> Result<(), PolicyError> {
        let id_ok = self
            .lease_id
            .strip_prefix(SERVICE_LEASE_ID_PREFIX)
            .is_some_and(|hex| is_lower_hex(hex, 32));
        if !id_ok
            || !is_client_ref(&self.client_ref)
            || !is_session_id(&self.session_id)
            || self.logon_session_id == 0
            || self.authority_epoch == 0
        {
            return Err(denied("browser lease record is malformed"));
        }
        bounded_field("Windows user SID", &self.windows_user_sid)?;
        bounded_field("principal", &self.principal_id)?;
        bounded_field("requester", &self.requester)?;
        check_task(self.task.as_deref())?;
        if self.principal_id != self.client_ref {
            return Err(denied("browser lease principal is not its client"));
        }
        let (origins, families) = check_scope(&self.origins, &self.families)?;
        let duration = self.expires_at_ms.checked_sub(self.issued_at_ms);
        if origins != self.origins
            || families != self.families
            || !duration
                .is_some_and(|ms| (MIN_BROWSER_LEASE_MS..=MAX_BROWSER_LEASE_MS).contains(&ms))
        {
            return Err(denied("browser lease record is malformed"));
        }
        Ok(())
    }

    /// Whether the lease names `origin` (canonicalized here) and `family`,
    /// exactly. An origin that does not canonicalize matches nothing.
    pub fn covers(&self, origin: &str, family: BrowserFamily) -> bool {
        let Some(origin) = canonical_origin(origin) else {
            return false;
        };
        self.origins.contains(&origin) && self.families.contains(&family)
    }
}

/// Check a lease against now: its shape, its time box, and every binding
/// (Windows user and logon session, the service's epoch and revocation
/// counter, session, client and task label). Any drift fails closed with
/// `CAPABILITY_DENIED` and a message naming the rule only.
pub fn check_browser_lease(
    lease: &BrowserLease,
    context: &BrowserLeaseContext<'_>,
) -> Result<(), PolicyError> {
    lease.check_shape()?;
    if context.revocations < lease.revocations_at_issue {
        return Err(denied(
            "the authority service's revocation counter went back behind this browser lease",
        ));
    }
    if context.now_ms < lease.issued_at_ms || context.now_ms >= lease.expires_at_ms {
        return Err(denied("browser lease expired or not yet active"));
    }
    if lease.windows_user_sid != context.windows_user_sid
        || lease.logon_session_id != context.logon_session_id
    {
        return Err(denied("browser lease Windows session binding mismatch"));
    }
    if lease.authority_epoch != context.authority_epoch {
        return Err(denied("browser lease authority epoch moved"));
    }
    if lease.session_id != context.session_id {
        return Err(denied("browser lease names another browser session"));
    }
    if lease.client_ref != context.client_ref {
        return Err(denied("browser lease names another client"));
    }
    if lease.task.as_deref() != context.task {
        return Err(denied("browser lease names another task label"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SESSION: &str = "bs-0123456789abcdef-1-0001020304050607";
    const SID: &str = "S-1-5-21-1-2-3-1001";
    const NOW: u64 = 1_800_000_000_000;

    fn lease() -> BrowserLease {
        let client = client_ref("client-a");
        BrowserLease {
            lease_id: format!("al-{}", "0".repeat(32)),
            client_ref: client.clone(),
            session_id: SESSION.into(),
            windows_user_sid: SID.into(),
            logon_session_id: 42,
            authority_epoch: 3,
            revocations_at_issue: 3,
            origins: vec!["https://fixture.test".into()],
            families: vec![BrowserFamily::Navigate, BrowserFamily::Click],
            issued_at_ms: NOW,
            expires_at_ms: NOW + 60 * 60 * 1_000,
            task: Some("Book a table".into()),
            principal_id: client,
            requester: "pid 42 C:\\Orcel\\orcel.exe (via the Orcel authority service)".into(),
        }
    }

    fn context(client: &str) -> BrowserLeaseContext<'_> {
        BrowserLeaseContext {
            windows_user_sid: SID,
            logon_session_id: 42,
            authority_epoch: 3,
            revocations: 3,
            session_id: SESSION,
            client_ref: client,
            task: Some("Book a table"),
            now_ms: NOW + 1,
        }
    }

    #[test]
    fn origins_canonicalize_exactly_and_refuse_everything_else() {
        for (text, canonical) in [
            ("https://fixture.test", "https://fixture.test"),
            ("https://fixture.test/", "https://fixture.test"),
            ("HTTPS://Fixture.Test", "https://fixture.test"),
            ("https://fixture.test:443", "https://fixture.test"),
            ("https://fixture.test:8443", "https://fixture.test:8443"),
            ("https://a-b.example.com", "https://a-b.example.com"),
        ] {
            assert_eq!(canonical_origin(text).as_deref(), Some(canonical), "{text}");
        }
        for text in [
            "",
            "http://fixture.test",
            "https://",
            "https://fixture.test/path",
            "https://fixture.test?q=1",
            "https://fixture.test#f",
            "https://user@fixture.test",
            "https://*.fixture.test",
            "https://fixture.test:0",
            "https://fixture.test:65536",
            "https://fixture.test:0443",
            "https://fixture.test:",
            "https://[::1]",
            "https://-bad.test",
            "https://bad-.test",
            "https://a..b",
        ] {
            assert_eq!(canonical_origin(text), None, "{text}");
        }
    }

    #[test]
    fn scope_matches_origins_exactly_and_families_by_name_only() {
        let lease = lease();
        assert!(lease.covers("https://fixture.test", BrowserFamily::Navigate));
        assert!(lease.covers("https://fixture.test:443", BrowserFamily::Click));
        for origin in [
            "https://fixture.test.evil.example",
            "https://sub.fixture.test",
            "https://fixture.test:8443",
            "http://fixture.test",
            "https://fixture.tes",
            "not an origin",
        ] {
            assert!(!lease.covers(origin, BrowserFamily::Navigate), "{origin}");
        }
        for family in [
            BrowserFamily::Type,
            BrowserFamily::Select,
            BrowserFamily::Tabs,
        ] {
            assert!(!lease.covers("https://fixture.test", family), "{family:?}");
        }
        for family in BrowserFamily::ALL {
            assert_eq!(BrowserFamily::parse(family.as_str()), Some(family));
        }
        assert_eq!(BrowserFamily::parse("submit"), None);
        assert_eq!(BrowserFamily::parse("Navigate"), None);
    }

    #[test]
    fn the_scope_is_bounded_canonical_and_routine_only() {
        let sixteen: Vec<String> = (0..16).map(|n| format!("https://h{n}.test")).collect();
        assert!(check_scope(&sixteen, &[BrowserFamily::Click]).is_ok());
        let seventeen: Vec<String> = (0..17).map(|n| format!("https://h{n}.test")).collect();
        assert!(check_scope(&seventeen, &[BrowserFamily::Click]).is_err());
        assert!(check_scope(&[], &[BrowserFamily::Click]).is_err());
        assert!(check_scope(
            &[
                "https://fixture.test".into(),
                "https://fixture.test:443".into()
            ],
            &[BrowserFamily::Click]
        )
        .is_err());
        assert!(check_scope(&["https://fixture.test".into()], &[]).is_err());
        assert!(check_scope(
            &["https://fixture.test".into()],
            &[BrowserFamily::Click, BrowserFamily::Click]
        )
        .is_err());
        for family in [
            BrowserFamily::Read,
            BrowserFamily::Scroll,
            BrowserFamily::Download,
        ] {
            let refused = check_scope(&["https://fixture.test".into()], &[family]);
            assert!(
                refused.is_err_and(|e| e.message.contains("not implemented")),
                "{family:?}"
            );
        }
        let mut odd = lease();
        odd.families = vec![BrowserFamily::Click, BrowserFamily::Navigate];
        assert!(odd.check_shape().is_err(), "families must be sorted");
        let mut long = lease();
        long.expires_at_ms = long.issued_at_ms + MAX_BROWSER_LEASE_MS + 1;
        assert!(long.check_shape().is_err());
        let mut foreign = lease();
        foreign.lease_id = format!("bl-{}", "0".repeat(64));
        assert!(foreign.check_shape().is_err(), "only service lease ids");
        let mut principal = lease();
        principal.principal_id = "someone-else".into();
        assert!(principal.check_shape().is_err());
        assert!(lease().check_shape().is_ok());
    }

    #[test]
    fn every_binding_drift_expiry_and_revocation_counter_fail_closed() {
        let lease = lease();
        let client = client_ref("client-a");
        assert!(check_browser_lease(&lease, &context(&client)).is_ok());
        let other = client_ref("client-b");
        assert!(check_browser_lease(&lease, &context(&other)).is_err());
        type Change = fn(&mut BrowserLeaseContext<'_>);
        let cases: [(&str, Change); 8] = [
            ("expired", |c| c.now_ms = NOW + 60 * 60 * 1_000),
            ("early", |c| c.now_ms = NOW - 1),
            ("user", |c| c.windows_user_sid = "S-1-5-21-9"),
            ("logon", |c| c.logon_session_id = 43),
            ("epoch", |c| c.authority_epoch = 4),
            ("counter went back", |c| c.revocations = 2),
            ("session", |c| {
                c.session_id = "bs-0123456789abcdef-2-0001020304050607"
            }),
            ("task", |c| c.task = Some("Another task")),
        ];
        for (name, change) in cases {
            let mut at = context(&client);
            change(&mut at);
            assert!(check_browser_lease(&lease, &at).is_err(), "{name}");
        }
        // A later revoke of another lease moves the counter forward: fine.
        let mut later = context(&client);
        later.revocations = 9;
        assert!(check_browser_lease(&lease, &later).is_ok());
    }

    #[test]
    fn client_refs_and_session_ids_have_one_shape() {
        let reference = client_ref("client-a");
        assert!(is_client_ref(&reference));
        assert_ne!(reference, client_ref("client-b"));
        assert!(!is_client_ref("cl-xyz"));
        assert!(is_session_id(SESSION));
        for bad in ["bs-1", "bs-0123456789abcdef-01-0001020304050607", "x"] {
            assert!(!is_session_id(bad), "{bad}");
        }
    }
}
