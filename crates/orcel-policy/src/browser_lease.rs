//! SG-000135 OB-08: Full Access browser leases.
//!
//! A browser lease is an owner-issued, scope- and time-bounded authority for
//! one Orcel Browser broker session: one client, one session (its profile is
//! the session's own, so the profile is session-bound for now), exact
//! canonical origins and named action families. Under a valid lease orceld
//! dispatches a positively classified routine action of a covered family on
//! a covered origin without a per-action SOFT prompt; everything else asks
//! as before.
//!
//! Issuance needs a [`LocalGrantProof`], which only the protected
//! full-control store can make, and the store issues only after a STRONG
//! (Windows Hello) approval in orceld's local lease management path
//! (interim, per SG-000135 decision 8; the lease migrates into the SG-000132
//! authority service with the same scope and no silent widening). An
//! agent, MCP, donor, relay or remote caller never issues, widens or renews
//! one (`full_control::reject_untrusted_grant`).
//!
//! A lease is bound like a `FullControlLease`: the Windows user and logon
//! session, the local device, the policy revision and the store's authority
//! epoch, plus the approval ledger's revoke epoch (an emergency revoke
//! advances it). Any drift, expiry or revoke fails closed.
//!
//! Every scope list narrows and nothing is implied: an origin matches only
//! exactly (after canonicalization), a family only by name, and `download`
//! is never implied by any other family.

use crate::full_control::LocalGrantProof;
use crate::PolicyError;
use orcel_contracts::FailureCode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Version 2 (OB-08 review): the requester, the task label and the store's
/// revocation counter are bound into every lease.
pub const BROWSER_LEASE_SCHEMA: &str = "orcel-browser-lease/2";
/// The longest task label a lease names (the broker's own bound).
pub const MAX_LEASE_TASK_CHARS: usize = 64;
/// The most origins one lease names.
pub const MAX_BROWSER_LEASE_ORIGINS: usize = 64;
/// The shortest and longest lease.
pub const MIN_BROWSER_LEASE_MS: u64 = 60_000;
pub const MAX_BROWSER_LEASE_MS: u64 = 12 * 60 * 60 * 1_000;
/// The most browser leases the store keeps at once.
pub const MAX_BROWSER_LEASES: usize = 16;
/// The prefix of a client reference (`client_ref`).
pub const CLIENT_REF_PREFIX: &str = "cl-";
/// The prefix of a browser lease id.
pub const BROWSER_LEASE_ID_PREFIX: &str = "bl-";
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
/// issuance until a packet implements them (reads ask nothing already; no
/// browser_full tool scrolls or downloads).
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

/// One browser lease, as the protected store keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserLease {
    pub schema: String,
    pub lease_id: String,
    /// The client (MCP session) the session belongs to, by reference.
    pub client_ref: String,
    /// The broker session (and so its profile) the lease covers.
    pub session_id: String,
    pub windows_user_sid: String,
    pub logon_session_id: u64,
    pub device_id: String,
    pub policy_revision: String,
    /// The full-control store's authority epoch at issuance.
    pub authority_epoch: u64,
    /// The approval ledger's verified revoke epoch at issuance.
    pub approval_epoch: u64,
    /// Exact canonical origins (`https://host[:port]`, no `:443`).
    pub origins: Vec<String>,
    pub families: Vec<BrowserFamily>,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    /// The session's task label the owner saw (none when it has none).
    pub task: Option<String>,
    /// Who asked for the lease, as the owner channel identified it.
    pub requester: String,
    /// The store's browser revocation counter at issuance; the store's
    /// counter only grows, so a store that went back behind it is refused.
    pub revocations: u64,
}

/// What an owner asks the store to issue (the store fills the device, the
/// policy revision and the authority epoch).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserLeaseRequest {
    pub client_ref: String,
    pub session_id: String,
    pub windows_user_sid: String,
    pub logon_session_id: u64,
    pub device_id: String,
    pub policy_revision: String,
    pub authority_epoch: u64,
    pub approval_epoch: u64,
    pub origins: Vec<String>,
    pub families: Vec<BrowserFamily>,
    pub issued_at_ms: u64,
    pub duration_ms: u64,
    pub task: Option<String>,
    pub requester: String,
    pub revocations: u64,
}

/// What a lease is checked against right now.
#[derive(Debug, Clone, Copy)]
pub struct BrowserLeaseContext<'a> {
    pub windows_user_sid: &'a str,
    pub logon_session_id: u64,
    pub device_id: &'a str,
    pub policy_revision: &'a str,
    /// The store's authority epoch, read now.
    pub authority_epoch: u64,
    /// The approval ledger's revoke epoch, read and verified now; `None`
    /// when it could not be verified (fails closed).
    pub approval_epoch: Option<u64>,
    pub session_id: &'a str,
    pub client_ref: &'a str,
    /// The session's own task label.
    pub task: Option<&'a str>,
    pub now_ms: u64,
    /// The store's browser revocation counter, read now.
    pub store_revocations: u64,
    /// The store's last-seen time: a clock behind it went backwards.
    pub store_clock_ms: u64,
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

/// Check and canonicalize a requested scope: 1 to 64 distinct canonical
/// origins and 1 to 8 distinct families. Returns the canonical origins in
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
    if families.is_empty() || families.len() > BrowserFamily::ALL.len() {
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

fn hash_part(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn derive_lease_id(
    proof: &LocalGrantProof,
    request: &BrowserLeaseRequest,
    origins: &[String],
    families: &[BrowserFamily],
    expires_at_ms: u64,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"orcel/sg000135/browser-lease/v1");
    hasher.update(proof.id_key());
    for part in [
        request.client_ref.as_str(),
        request.session_id.as_str(),
        request.windows_user_sid.as_str(),
        request.device_id.as_str(),
        request.policy_revision.as_str(),
    ] {
        hash_part(&mut hasher, part.as_bytes());
    }
    hasher.update(request.logon_session_id.to_le_bytes());
    hasher.update(request.authority_epoch.to_le_bytes());
    hasher.update(request.approval_epoch.to_le_bytes());
    hasher.update((origins.len() as u64).to_le_bytes());
    for origin in origins {
        hash_part(&mut hasher, origin.as_bytes());
    }
    hasher.update((families.len() as u64).to_le_bytes());
    for family in families {
        hash_part(&mut hasher, family.as_str().as_bytes());
    }
    hasher.update(request.issued_at_ms.to_le_bytes());
    hasher.update(expires_at_ms.to_le_bytes());
    match &request.task {
        Some(task) => {
            hasher.update([1u8]);
            hash_part(&mut hasher, task.as_bytes());
        }
        None => hasher.update([0u8]),
    }
    hash_part(&mut hasher, request.requester.as_bytes());
    hasher.update(request.revocations.to_le_bytes());
    format!(
        "{BROWSER_LEASE_ID_PREFIX}{}",
        lower_hex(hasher.finalize().as_slice())
    )
}

/// Issue a browser lease. Only the protected store holds a
/// [`LocalGrantProof`]; the scope is checked and canonicalized here, the
/// duration bounded, and the id derived from the proof and every binding.
pub fn issue_browser_lease(
    proof: &LocalGrantProof,
    request: BrowserLeaseRequest,
) -> Result<BrowserLease, PolicyError> {
    if !is_client_ref(&request.client_ref) {
        return Err(invalid("browser lease client reference malformed"));
    }
    if !is_session_id(&request.session_id) {
        return Err(invalid("browser lease session id malformed"));
    }
    bounded_field("Windows user SID", &request.windows_user_sid)?;
    if !request.windows_user_sid.starts_with("S-1-") {
        return Err(invalid(
            "browser lease Windows user SID has an invalid shape",
        ));
    }
    bounded_field("device id", &request.device_id)?;
    bounded_field("policy revision", &request.policy_revision)?;
    bounded_field("requester", &request.requester)?;
    check_task(request.task.as_deref())?;
    if request.logon_session_id == 0 || request.authority_epoch == 0 {
        return Err(invalid(
            "browser lease logon session and authority epoch must be non-zero",
        ));
    }
    if !(MIN_BROWSER_LEASE_MS..=MAX_BROWSER_LEASE_MS).contains(&request.duration_ms) {
        return Err(invalid("browser lease duration is out of bounds"));
    }
    let (origins, families) = check_scope(&request.origins, &request.families)?;
    let expires_at_ms = request
        .issued_at_ms
        .checked_add(request.duration_ms)
        .ok_or_else(|| invalid("browser lease expiry overflow"))?;
    let lease_id = derive_lease_id(proof, &request, &origins, &families, expires_at_ms);
    Ok(BrowserLease {
        schema: BROWSER_LEASE_SCHEMA.to_owned(),
        lease_id,
        client_ref: request.client_ref,
        session_id: request.session_id,
        windows_user_sid: request.windows_user_sid,
        logon_session_id: request.logon_session_id,
        device_id: request.device_id,
        policy_revision: request.policy_revision,
        authority_epoch: request.authority_epoch,
        approval_epoch: request.approval_epoch,
        origins,
        families,
        issued_at_ms: request.issued_at_ms,
        expires_at_ms,
        task: request.task,
        requester: request.requester,
        revocations: request.revocations,
    })
}

impl BrowserLease {
    /// The stored shape is one `issue_browser_lease` could have made: the
    /// schema, the id's form, bounded fields, a canonical sorted scope and
    /// a bounded positive time box. A store entry failing it is refused.
    pub fn check_shape(&self) -> Result<(), PolicyError> {
        let id_ok = self
            .lease_id
            .strip_prefix(BROWSER_LEASE_ID_PREFIX)
            .is_some_and(|hex| is_lower_hex(hex, 64));
        if self.schema != BROWSER_LEASE_SCHEMA
            || !id_ok
            || !is_client_ref(&self.client_ref)
            || !is_session_id(&self.session_id)
            || self.logon_session_id == 0
            || self.authority_epoch == 0
        {
            return Err(denied("browser lease record is malformed"));
        }
        bounded_field("Windows user SID", &self.windows_user_sid)?;
        bounded_field("device id", &self.device_id)?;
        bounded_field("policy revision", &self.policy_revision)?;
        bounded_field("requester", &self.requester)?;
        check_task(self.task.as_deref())?;
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
/// (Windows user and logon session, device, policy revision, authority
/// epoch, verified approval epoch, session and client). Any drift fails
/// closed with `CAPABILITY_DENIED` and a message naming the rule only.
pub fn check_browser_lease(
    lease: &BrowserLease,
    context: &BrowserLeaseContext<'_>,
) -> Result<(), PolicyError> {
    lease.check_shape()?;
    if context.now_ms < context.store_clock_ms {
        return Err(denied(
            "the clock went backwards behind the authority store",
        ));
    }
    if context.store_revocations < lease.revocations {
        return Err(denied(
            "the authority store went back behind this browser lease's revocation counter",
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
    if lease.device_id != context.device_id {
        return Err(denied("browser lease device binding mismatch"));
    }
    if lease.policy_revision != context.policy_revision {
        return Err(denied("browser lease policy revision changed"));
    }
    if lease.authority_epoch != context.authority_epoch {
        return Err(denied("browser lease authority epoch moved"));
    }
    match context.approval_epoch {
        Some(epoch) if epoch == lease.approval_epoch => {}
        Some(_) => return Err(denied("an emergency revoke moved the approval epoch")),
        None => return Err(denied("the approval epoch could not be verified")),
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
    const DEVICE: &str = "device-local-1";
    const NOW: u64 = 1_800_000_000_000;

    fn proof() -> LocalGrantProof {
        LocalGrantProof::from_secret([0xA5; 32]).expect("proof")
    }

    fn request() -> BrowserLeaseRequest {
        BrowserLeaseRequest {
            client_ref: client_ref("client-a"),
            session_id: SESSION.into(),
            windows_user_sid: SID.into(),
            logon_session_id: 42,
            device_id: DEVICE.into(),
            policy_revision: "rev-1".into(),
            authority_epoch: 3,
            approval_epoch: 0,
            origins: vec!["https://fixture.test".into()],
            families: vec![BrowserFamily::Navigate, BrowserFamily::Click],
            issued_at_ms: NOW,
            duration_ms: 60 * 60 * 1_000,
            task: Some("Book a table".into()),
            requester: "pid 42 C:\\Orcel\\orcel.exe (test channel)".into(),
            revocations: 3,
        }
    }

    fn context<'a>(client: &'a str) -> BrowserLeaseContext<'a> {
        BrowserLeaseContext {
            windows_user_sid: SID,
            logon_session_id: 42,
            device_id: DEVICE,
            policy_revision: "rev-1",
            authority_epoch: 3,
            approval_epoch: Some(0),
            session_id: SESSION,
            client_ref: client,
            task: Some("Book a table"),
            now_ms: NOW + 1,
            store_revocations: 3,
            store_clock_ms: NOW,
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
            "https://fixture.test//",
            "https://fixture.test\\x",
            "https://fixture test",
            "https://fixture.test\n",
            "wss://fixture.test",
        ] {
            assert_eq!(canonical_origin(text), None, "{text:?}");
        }
    }

    #[test]
    fn scope_matches_origins_exactly_and_families_by_name_only() {
        let lease = issue_browser_lease(&proof(), request()).expect("issued");
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
    fn issuance_bounds_the_scope_and_the_duration() {
        let mut too_many = request();
        too_many.origins = (0..65).map(|n| format!("https://h{n}.test")).collect();
        let mut duplicate_origin = request();
        duplicate_origin.origins = vec![
            "https://fixture.test".into(),
            "https://fixture.test:443".into(),
        ];
        let mut no_origin = request();
        no_origin.origins.clear();
        let mut wildcard = request();
        wildcard.origins = vec!["https://*.test".into()];
        let mut no_family = request();
        no_family.families.clear();
        let mut duplicate_family = request();
        duplicate_family.families = vec![BrowserFamily::Click, BrowserFamily::Click];
        let mut short = request();
        short.duration_ms = MIN_BROWSER_LEASE_MS - 1;
        let mut long = request();
        long.duration_ms = MAX_BROWSER_LEASE_MS + 1;
        let mut session = request();
        session.session_id = "bs-nope".into();
        let mut client = request();
        client.client_ref = "client-a".into();
        let mut zero_epoch = request();
        zero_epoch.authority_epoch = 0;
        let mut overflow = request();
        overflow.issued_at_ms = u64::MAX - 10;
        let mut long_task = request();
        long_task.task = Some("t".repeat(65));
        let mut odd_task = request();
        odd_task.task = Some("two\nlines".into());
        let mut no_requester = request();
        no_requester.requester = String::new();
        for (name, bad) in [
            ("too many origins", too_many),
            ("duplicate origin", duplicate_origin),
            ("no origin", no_origin),
            ("wildcard", wildcard),
            ("no family", no_family),
            ("duplicate family", duplicate_family),
            ("short", short),
            ("long", long),
            ("session", session),
            ("client", client),
            ("zero epoch", zero_epoch),
            ("overflow", overflow),
            ("long task", long_task),
            ("odd task", odd_task),
            ("no requester", no_requester),
        ] {
            assert!(issue_browser_lease(&proof(), bad).is_err(), "{name}");
        }
        let mut max = request();
        max.origins = (0..64).map(|n| format!("https://h{n}.test")).collect();
        max.duration_ms = MAX_BROWSER_LEASE_MS;
        let lease = issue_browser_lease(&proof(), max).expect("64 origins, 12 hours");
        // OB-08 review: families orceld does not enforce yet are refused.
        for family in [
            BrowserFamily::Read,
            BrowserFamily::Scroll,
            BrowserFamily::Download,
        ] {
            let mut unimplemented = request();
            unimplemented.families.push(family);
            let refused = issue_browser_lease(&proof(), unimplemented).expect_err("refused");
            assert!(refused.message.contains("not implemented"), "{family:?}");
        }
        assert_eq!(lease.origins.len(), 64);
        assert!(lease.check_shape().is_ok());
    }

    #[test]
    fn lease_ids_are_proof_keyed_and_cover_every_binding() {
        let first = issue_browser_lease(&proof(), request()).expect("first");
        assert!(first.lease_id.starts_with(BROWSER_LEASE_ID_PREFIX));
        assert_eq!(first.lease_id.len(), 67);
        let other_proof = LocalGrantProof::from_secret([0x5A; 32]).expect("proof");
        assert_ne!(
            first.lease_id,
            issue_browser_lease(&other_proof, request())
                .expect("other")
                .lease_id
        );
        let mut wider = request();
        wider.families.push(BrowserFamily::Type);
        assert_ne!(
            first.lease_id,
            issue_browser_lease(&proof(), wider)
                .expect("wider")
                .lease_id
        );
        for change in [
            (|r: &mut BrowserLeaseRequest| r.task = None) as fn(&mut BrowserLeaseRequest),
            |r| r.requester = "pid 7 other.exe".into(),
            |r| r.revocations = 4,
        ] {
            let mut changed = request();
            change(&mut changed);
            assert_ne!(
                first.lease_id,
                issue_browser_lease(&proof(), changed)
                    .expect("changed")
                    .lease_id
            );
        }
        let mut epoch = request();
        epoch.approval_epoch = 1;
        assert_ne!(
            first.lease_id,
            issue_browser_lease(&proof(), epoch)
                .expect("epoch")
                .lease_id
        );
    }

    #[test]
    fn every_binding_drift_expiry_and_unverified_epoch_fail_closed() {
        let lease = issue_browser_lease(&proof(), request()).expect("issued");
        let me = client_ref("client-a");
        assert!(check_browser_lease(&lease, &context(&me)).is_ok());
        let other = client_ref("client-b");
        assert!(check_browser_lease(&lease, &context(&other)).is_err());
        let base = context(&me);
        let mut cases = Vec::new();
        let mut c = base;
        c.windows_user_sid = "S-1-5-21-9";
        cases.push(("sid", c));
        let mut c = base;
        c.logon_session_id = 43;
        cases.push(("logon", c));
        let mut c = base;
        c.device_id = "device-local-2";
        cases.push(("device", c));
        let mut c = base;
        c.policy_revision = "rev-2";
        cases.push(("policy", c));
        let mut c = base;
        c.authority_epoch = 4;
        cases.push(("authority epoch", c));
        let mut c = base;
        c.approval_epoch = Some(1);
        cases.push(("approval epoch", c));
        let mut c = base;
        c.approval_epoch = None;
        cases.push(("unverified approval epoch", c));
        let mut c = base;
        c.session_id = "bs-0123456789abcdef-2-0001020304050607";
        cases.push(("session", c));
        let mut c = base;
        c.now_ms = lease.expires_at_ms;
        cases.push(("expired", c));
        let mut c = base;
        c.now_ms = NOW - 1;
        cases.push(("not yet", c));
        let mut c = base;
        c.task = Some("Another task");
        cases.push(("task", c));
        let mut c = base;
        c.task = None;
        cases.push(("no task", c));
        let mut c = base;
        c.store_revocations = 2;
        cases.push(("store went back", c));
        let mut c = base;
        c.store_clock_ms = NOW + 10;
        cases.push(("clock went backwards", c));
        for (name, case) in cases {
            let refused = check_browser_lease(&lease, &case).expect_err(name);
            assert_eq!(refused.code, FailureCode::CapabilityDenied, "{name}");
        }
        // A record tampered into a wider or odd shape is refused.
        let mut tampered = lease.clone();
        tampered.origins.push("https://*.test".into());
        assert!(check_browser_lease(&tampered, &base).is_err());
        let mut unsorted = lease.clone();
        unsorted.families.reverse();
        assert!(check_browser_lease(&unsorted, &base).is_err());
        let mut long = lease.clone();
        long.expires_at_ms = long.issued_at_ms + MAX_BROWSER_LEASE_MS + 1;
        assert!(check_browser_lease(&long, &base).is_err());
    }

    #[test]
    fn client_refs_and_session_ids_have_one_shape() {
        let reference = client_ref("client-a");
        assert!(is_client_ref(&reference));
        assert_ne!(reference, client_ref("client-b"));
        assert!(!reference.contains("client-a"));
        assert!(!is_client_ref("cl-XYZ"));
        assert!(is_session_id(SESSION));
        for bad in [
            "bs-0123456789abcdef-0-0001020304050607",
            "bs-0123456789abcdef-1234567-0001020304050607",
            "bs-0123456789ABCDEF-1-0001020304050607",
            "bs-0123456789abcdef-1-0001020304050607-x",
            "xs-0123456789abcdef-1-0001020304050607",
        ] {
            assert!(!is_session_id(bad), "{bad}");
        }
    }
}
