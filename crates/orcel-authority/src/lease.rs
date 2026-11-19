//! Signed authority leases (spec 4.13, SG-000132 and its SG-000135
//! amendment).
//!
//! Two shapes share one signed body:
//!
//! - [`LeaseScope::DesktopFullUser`]: the Full User lease of spec 4.13 and
//!   4.14. The default request is the narrow scope of spec 4.13 step 3:
//!   desktop input only, no roots, no shells, 30 minutes. Every widening is
//!   an explicit choice in the intent. `Admin` and `Remote` are never
//!   accepted (the service never elevates; SG-000098 and SG-000105).
//! - [`LeaseScope::BrowserFullAccess`]: the SG-000135 browser lease scope
//!   (client, browser session, exact origins, action families, optional
//!   task) with the same family vocabulary as OB-08's
//!   `orcel_policy::browser_lease::BrowserFamily`, so an OB-08 lease scope
//!   moves into the service unchanged. An interim-store lease is ended at
//!   migration, never converted (amendment change 3).
//!
//! The service signs `SIGNING_DOMAIN || canonical_json(body)` with its
//! ECDSA P-256 key (CNG). Anyone holding the published public key verifies
//! the signature without the private key. A valid signature proves only
//! that the service issued the body; whether the lease is still active
//! (revocation, epoch, expiry) is answered by the service, so a verifier
//! that cannot reach it fails closed.

use crate::error::AuthorityError;
use orcel_contracts::ExecutorClass;
use serde::{Deserialize, Serialize};

/// `contract` of a lease body.
pub const LEASE_CONTRACT: &str = "orcel.authority-lease/1";

/// Domain separation prefix of the signing input.
pub const SIGNING_DOMAIN: &[u8] = b"orcel-authority-lease-signature/1\n";

/// Lease id prefix (`al-` and 32 lowercase hex characters).
pub const LEASE_ID_PREFIX: &str = "al-";

/// The narrow default duration (spec 4.13 step 3).
pub const DEFAULT_LEASE_MINUTES: u64 = 30;

/// Shortest and longest lease, in minutes (12 hours, as SG-000093).
pub const MIN_LEASE_MINUTES: u64 = 1;
pub const MAX_LEASE_MINUTES: u64 = 12 * 60;

/// Bounds on scope lists and fields.
/// Lower than OB-08's 64 origins so the whole scope fits the confirmation.
pub const MAX_ROOTS: usize = 8;
pub const MAX_ORIGINS: usize = 16;
/// The longest root path the confirmation shows.
pub const MAX_ROOT_CHARS: usize = 128;
pub const MAX_FIELD_BYTES: usize = 256;
pub const MAX_TASK_CHARS: usize = 64;

/// Executor classes a desktop Full User lease may name. `Admin` and
/// `Remote` never; `Browser` only through the browser shape.
pub const DESKTOP_EXECUTORS: [ExecutorClass; 5] = [
    ExecutorClass::DesktopObservation,
    ExecutorClass::DesktopInput,
    ExecutorClass::ShellProcess,
    ExecutorClass::Filesystem,
    ExecutorClass::VisualAgent,
];

/// Browser action families, spelled as OB-08's `BrowserFamily`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserFamily {
    Navigate,
    Click,
    Type,
    Select,
    Scroll,
    Read,
    Tabs,
    /// Opt-in only; never part of a default.
    Download,
}

/// Slice 2 (SG-000135 OB-08 finding 5): the families orceld enforces under
/// a browser lease. `read`, `scroll` and `download` stay in the vocabulary
/// and are refused at the grant.
pub const LEASABLE_BROWSER_FAMILIES: [BrowserFamily; 5] = [
    BrowserFamily::Navigate,
    BrowserFamily::Click,
    BrowserFamily::Type,
    BrowserFamily::Select,
    BrowserFamily::Tabs,
];

/// What a lease covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LeaseScope {
    DesktopFullUser {
        executors: Vec<ExecutorClass>,
        /// Absolute drive or folder paths the filesystem executor may use.
        roots: Vec<String>,
        /// Whether shells (ShellProcess) are granted.
        shells: bool,
    },
    BrowserFullAccess {
        /// `cl-` client reference of the MCP session (OB-08).
        client_ref: String,
        /// The broker session (and so its Orcel-managed profile).
        session_id: String,
        /// Exact canonical origins (`https://host[:port]`).
        origins: Vec<String>,
        families: Vec<BrowserFamily>,
        task: Option<String>,
    },
}

impl LeaseScope {
    /// Spec 4.13 step 3: desktop input only, no roots, no shells.
    pub fn narrow_default() -> Self {
        Self::DesktopFullUser {
            executors: vec![ExecutorClass::DesktopInput],
            roots: Vec::new(),
            shells: false,
        }
    }

    /// Whether this scope admits `executor`. `Admin` and `Remote` never.
    pub fn admits(&self, executor: ExecutorClass) -> bool {
        if matches!(executor, ExecutorClass::Admin | ExecutorClass::Remote) {
            return false;
        }
        match self {
            Self::DesktopFullUser { executors, .. } => executors.contains(&executor),
            Self::BrowserFullAccess { .. } => executor == ExecutorClass::Browser,
        }
    }

    /// One line for the confirmation and the Event Log.
    pub fn describe(&self) -> String {
        match self {
            Self::DesktopFullUser {
                executors,
                roots,
                shells,
            } => {
                let names: Vec<String> = executors.iter().map(|e| executor_name(*e)).collect();
                format!(
                    "desktop Full User: executors [{}]; roots [{}]; shells {}",
                    names.join(", "),
                    if roots.is_empty() {
                        "none".to_owned()
                    } else {
                        roots.join(", ")
                    },
                    if *shells { "yes" } else { "no" }
                )
            }
            Self::BrowserFullAccess {
                client_ref,
                session_id,
                origins,
                families,
                task,
            } => {
                let families: Vec<&str> = families.iter().map(|f| family_name(*f)).collect();
                format!(
                    "browser Full Access: client {client_ref}; session {session_id}; origins [{}]; families [{}]; task {}",
                    origins.join(", "),
                    families.join(", "),
                    task.as_deref().unwrap_or("none")
                )
            }
        }
    }

    /// Refuse anything out of shape. Called before an intent is recorded.
    pub fn validate(&self) -> Result<(), AuthorityError> {
        match self {
            Self::DesktopFullUser {
                executors,
                roots,
                shells,
            } => {
                if executors.is_empty() {
                    return Err(AuthorityError::invalid(
                        "a desktop lease names at least one executor",
                    ));
                }
                for (index, executor) in executors.iter().enumerate() {
                    if matches!(executor, ExecutorClass::Admin) {
                        return Err(AuthorityError::denied(
                            "the Admin executor is refused: the authority service never elevates (SG-000098)",
                        ));
                    }
                    if !DESKTOP_EXECUTORS.contains(executor) {
                        return Err(AuthorityError::invalid(format!(
                            "executor {} is not available under a desktop Full User lease",
                            executor_name(*executor)
                        )));
                    }
                    if executors[..index].contains(executor) {
                        return Err(AuthorityError::invalid("an executor is named twice"));
                    }
                }
                if *shells != executors.contains(&ExecutorClass::ShellProcess) {
                    return Err(AuthorityError::invalid(
                        "shells and the shell_process executor are granted together or not at all",
                    ));
                }
                if !roots.is_empty() && !executors.contains(&ExecutorClass::Filesystem) {
                    return Err(AuthorityError::invalid(
                        "roots need the filesystem executor",
                    ));
                }
                if roots.len() > MAX_ROOTS {
                    return Err(AuthorityError::invalid("too many roots"));
                }
                for (index, root) in roots.iter().enumerate() {
                    check_root(root)?;
                    if roots[..index]
                        .iter()
                        .any(|other| other.eq_ignore_ascii_case(root))
                    {
                        return Err(AuthorityError::invalid("a root is named twice"));
                    }
                }
                Ok(())
            }
            Self::BrowserFullAccess {
                client_ref,
                session_id,
                origins,
                families,
                task,
            } => {
                if !is_client_ref(client_ref) {
                    return Err(AuthorityError::invalid("the client reference is malformed"));
                }
                if !is_session_id(session_id) {
                    return Err(AuthorityError::invalid(
                        "the browser session id is malformed",
                    ));
                }
                if origins.is_empty() || origins.len() > MAX_ORIGINS {
                    return Err(AuthorityError::invalid(
                        "a browser lease names between 1 and 16 origins",
                    ));
                }
                for (index, origin) in origins.iter().enumerate() {
                    if !is_canonical_origin(origin) {
                        return Err(AuthorityError::invalid(format!(
                            "origin {origin:?} is not a canonical https origin"
                        )));
                    }
                    if origins[..index].contains(origin) {
                        return Err(AuthorityError::invalid("an origin is named twice"));
                    }
                }
                if families.is_empty() {
                    return Err(AuthorityError::invalid(
                        "a browser lease names at least one action family",
                    ));
                }
                for (index, family) in families.iter().enumerate() {
                    if families[..index].contains(family) {
                        return Err(AuthorityError::invalid("an action family is named twice"));
                    }
                    if !LEASABLE_BROWSER_FAMILIES.contains(family) {
                        return Err(AuthorityError::invalid(format!(
                            "the {} family cannot be leased: a browser lease names only navigate, click, type, select or tabs",
                            family_name(*family)
                        )));
                    }
                }
                if let Some(task) = task {
                    check_task(task)?;
                }
                Ok(())
            }
        }
    }
}

/// Snake-case name of an executor class (its serde spelling).
pub fn executor_name(executor: ExecutorClass) -> String {
    serde_json::to_value(executor)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}

fn family_name(family: BrowserFamily) -> &'static str {
    match family {
        BrowserFamily::Navigate => "navigate",
        BrowserFamily::Click => "click",
        BrowserFamily::Type => "type",
        BrowserFamily::Select => "select",
        BrowserFamily::Scroll => "scroll",
        BrowserFamily::Read => "read",
        BrowserFamily::Tabs => "tabs",
        BrowserFamily::Download => "download",
    }
}

/// An absolute Windows drive or folder path, bounded, with no `..`
/// component, never the authority's own state.
fn check_root(root: &str) -> Result<(), AuthorityError> {
    if !is_display_text(root, MAX_ROOT_CHARS) {
        return Err(AuthorityError::invalid(
            "a root is 1 to 128 printable ASCII characters without padding",
        ));
    }
    let bytes = root.as_bytes();
    let drive = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/');
    if !drive {
        return Err(AuthorityError::invalid(
            "a root is an absolute drive path such as C:\\ or D:\\work",
        ));
    }
    if root
        .split(['\\', '/'])
        .any(|part| part == ".." || part == ".")
    {
        return Err(AuthorityError::invalid("a root has a . or .. component"));
    }
    let lower = root.to_ascii_lowercase().replace('/', "\\");
    if lower.contains("\\orcel\\authority") {
        return Err(AuthorityError::denied(
            "the authority service's own state is never a root",
        ));
    }
    Ok(())
}

fn check_task(task: &str) -> Result<(), AuthorityError> {
    if !is_display_text(task, MAX_TASK_CHARS) {
        return Err(AuthorityError::invalid(
            "a task label is 1 to 64 printable ASCII characters without padding",
        ));
    }
    Ok(())
}

/// Text the confirmation may show: 1 to `max_chars` printable ASCII
/// characters (U+0020 to U+007E), so no bidi controls, zero-width
/// characters, line or paragraph separators or other format characters;
/// no leading, trailing or repeated spaces (no padding that pushes content
/// out of view).
pub fn is_display_text(text: &str, max_chars: usize) -> bool {
    !text.is_empty()
        && text.len() <= max_chars
        && text.bytes().all(|b| (0x20..=0x7e).contains(&b))
        && !text.starts_with(' ')
        && !text.ends_with(' ')
        && !text.contains("  ")
}

fn is_lower_hex_of(text: &str, length: usize) -> bool {
    text.len() == length
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// OB-08's client reference: `cl-` and 32 lowercase hex characters.
pub fn is_client_ref(text: &str) -> bool {
    text.strip_prefix("cl-")
        .is_some_and(|rest| is_lower_hex_of(rest, 32))
}

/// OB-01's broker session id: `bs-<16 hex>-<counter>-<16 hex>`.
pub fn is_session_id(text: &str) -> bool {
    let Some(rest) = text.strip_prefix("bs-") else {
        return false;
    };
    let parts: Vec<&str> = rest.split('-').collect();
    let [instance, counter, random] = parts.as_slice() else {
        return false;
    };
    is_lower_hex_of(instance, 16)
        && is_lower_hex_of(random, 16)
        && !counter.is_empty()
        && counter.len() <= 6
        && !counter.starts_with('0')
        && counter.bytes().all(|b| b.is_ascii_digit())
}

/// `https://` plus a lowercase DNS host and an optional port other than
/// 443, nothing else (OB-08's canonical form).
pub fn is_canonical_origin(text: &str) -> bool {
    let Some(rest) = text.strip_prefix("https://") else {
        return false;
    };
    let (host, port) = match rest.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (rest, None),
    };
    let host_ok = !host.is_empty()
        && host.len() <= 253
        && !host.starts_with(['.', '-'])
        && !host.ends_with(['.', '-'])
        && !host.contains("..")
        && host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-');
    let port_ok = match port {
        None => true,
        Some(port) => {
            !port.is_empty()
                && port.len() <= 5
                && port.bytes().all(|b| b.is_ascii_digit())
                && !port.starts_with('0')
                && port.parse::<u32>().is_ok_and(|p| p <= 65_535 && p != 443)
        }
    };
    host_ok && port_ok
}

/// WP1-10: the longest path one Full Control dispatch may name.
pub const MAX_DISPATCH_PATH_CHARS: usize = 1024;

/// WP1-10: the most paths one Full Control dispatch may name.
pub const MAX_DISPATCH_PATHS: usize = 8;

/// WP1-10: a path a Full Control filesystem or git dispatch names, checked
/// lexically (the service never touches the user's files): an absolute
/// drive path (`C:\...`), at most [`MAX_DISPATCH_PATH_CHARS`] characters,
/// no control characters, no `\\?\` or UNC form, no `:` after the drive (no
/// alternate data streams), and no component that is empty, all dots, or
/// ends in a dot or a space (Win32 would rewrite those, so the lexical
/// check and the file system could disagree). `fc-worker` also resolves
/// the path and its root before acting (junctions and links).
pub fn check_dispatch_path(path: &str) -> Result<(), AuthorityError> {
    let invalid = |why: &str| Err(AuthorityError::invalid(format!("a dispatch path {why}")));
    if path.is_empty() || path.chars().count() > MAX_DISPATCH_PATH_CHARS {
        return invalid("is 1 to 1024 characters");
    }
    if path.chars().any(char::is_control) {
        return invalid("has a control character");
    }
    let bytes = path.as_bytes();
    let drive = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/');
    if !drive {
        return invalid("is an absolute drive path such as C:\\work\\file.txt");
    }
    if path[2..].contains(':') {
        return invalid("has a colon after its drive (an alternate data stream)");
    }
    let rest = &path[3..];
    if rest.is_empty() {
        return Ok(());
    }
    for part in rest.trim_end_matches(['\\', '/']).split(['\\', '/']) {
        if part.is_empty()
            || part.bytes().all(|b| b == b'.')
            || part.ends_with('.')
            || part.ends_with(' ')
        {
            return invalid("has an empty, dot or trailing-dot or trailing-space component");
        }
    }
    Ok(())
}

/// WP1-10: whether `path` is one of `roots` or lies under one, compared
/// lexically and case-insensitively on whole components (`C:\work` covers
/// `C:\work\a` and not `C:\workshop`). `path` must pass
/// [`check_dispatch_path`]; the roots passed the grant's own check.
pub fn path_within_roots(path: &str, roots: &[String]) -> bool {
    if check_dispatch_path(path).is_err() {
        return false;
    }
    let normalize = |text: &str| {
        text.replace('/', "\\")
            .trim_end_matches('\\')
            .to_lowercase()
    };
    let path = normalize(path);
    roots.iter().any(|root| {
        let root = normalize(root);
        !root.is_empty()
            && (path == root
                || path
                    .strip_prefix(&root)
                    .is_some_and(|rest| rest.starts_with('\\')))
    })
}

/// Who asked, as the service observed it on the pipe (never a claim).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedRequester {
    pub pid: u32,
    pub image: String,
}

/// How the grant was made (spec 4.13 steps 1 to 5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantEvidence {
    /// SHA-256 of the recorded intent.
    pub intent_digest: String,
    /// SHA-256 of the exact confirmation text the user answered Yes to; the
    /// presence challenge was bound to it.
    pub confirmation_text_digest: String,
    /// Always `"service_rendered"` (WTSSendMessageW).
    pub confirmation: String,
    /// `false` until WP1-10 proves injected input cannot answer it.
    pub confirmation_input_protected: bool,
    /// Always `"windows_hello_key_credential"`.
    pub presence: String,
    /// SHA-256 of the enrolled presence public key that signed.
    pub presence_key_digest: String,
}

/// The signed part of a lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseBody {
    pub contract: String,
    pub lease_id: String,
    pub scope: LeaseScope,
    pub windows_user_sid: String,
    pub logon_session_id: u64,
    /// The Windows terminal-services session the grant was made in.
    pub ts_session_id: u32,
    /// Session-asserted: the client principal the owner named.
    pub principal_id: String,
    /// Session-asserted: the declared task.
    pub task: String,
    pub requester: ObservedRequester,
    pub authority_epoch: u64,
    /// The revocation counter at issuance.
    pub revocations_at_issue: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    /// SHA-256 (hex, first 32 characters) of the signing public key.
    pub key_id: String,
    pub grant: GrantEvidence,
}

/// A lease and the service's signature over it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedLease {
    pub body: LeaseBody,
    /// ECDSA P-256 over SHA-256, `r || s`, lowercase hex.
    pub signature: String,
}

/// The exact bytes the service signs.
pub fn signing_input(body: &LeaseBody) -> Result<Vec<u8>, AuthorityError> {
    let canonical = orcel_contracts::canonical_json(body).map_err(|error| {
        AuthorityError::internal(format!("canonical lease encoding: {error:?}"))
    })?;
    let mut out = Vec::with_capacity(SIGNING_DOMAIN.len() + canonical.len());
    out.extend_from_slice(SIGNING_DOMAIN);
    out.extend_from_slice(canonical.as_bytes());
    Ok(out)
}

/// Checks a signature with a public key.
pub trait SignatureVerifier {
    fn key_id(&self) -> String;
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), AuthorityError>;
}

/// The key id of a public key blob.
pub fn key_id_of(public_key: &[u8]) -> String {
    crate::sha256_hex(public_key)[..32].to_owned()
}

impl SignedLease {
    /// The signature is the service's over exactly this body.
    pub fn verify_signature(&self, verifier: &dyn SignatureVerifier) -> Result<(), AuthorityError> {
        if self.body.contract != LEASE_CONTRACT {
            return Err(AuthorityError::lease_invalid("unknown lease contract"));
        }
        if self.body.key_id != verifier.key_id() {
            return Err(AuthorityError::lease_invalid(
                "the lease was signed by another authority key",
            ));
        }
        let signature = crate::unhex(&self.signature)
            .ok_or_else(|| AuthorityError::lease_invalid("the lease signature is not hex"))?;
        verifier.verify(&signing_input(&self.body)?, &signature)
    }
}

/// What a lease is checked against now.
#[derive(Debug, Clone, Copy)]
pub struct LeaseContext<'a> {
    pub windows_user_sid: &'a str,
    pub logon_session_id: u64,
    pub authority_epoch: u64,
    pub now_ms: u64,
}

impl LeaseBody {
    /// SG132_SLICE6.md: whether the client an `Authorize` names (the calling
    /// MCP client's reference, `cl-` and 32 lowercase hex, as orceld derives
    /// it from the request's client session; or this lease's own principal)
    /// may act under this lease. A lease bound to a client (its principal is
    /// a client reference: every browser lease, and a desktop lease granted
    /// with `--client cl-...`) admits that client only. An unbound desktop
    /// lease (a free label, such as the default `orcel-owner`) admits any
    /// client reference, which the audit then records, and its own
    /// principal, which an orceld from before this rule names.
    pub fn admits_client(&self, client: &str) -> bool {
        client == self.principal_id || (!is_client_ref(&self.principal_id) && is_client_ref(client))
    }

    /// Binding, epoch and time. Revocation is the service's record.
    pub fn check(&self, context: &LeaseContext<'_>) -> Result<(), AuthorityError> {
        if self.windows_user_sid != context.windows_user_sid
            || self.logon_session_id != context.logon_session_id
        {
            return Err(AuthorityError::lease_invalid(
                "the lease is bound to another Windows user or logon session",
            ));
        }
        if self.authority_epoch != context.authority_epoch {
            return Err(AuthorityError::lease_invalid(
                "the authority epoch moved since the lease was issued",
            ));
        }
        if context.now_ms < self.issued_at_ms || context.now_ms >= self.expires_at_ms {
            return Err(AuthorityError::lease_invalid(
                "the lease is not active at this time",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_the_narrow_scope() {
        let scope = LeaseScope::narrow_default();
        assert_eq!(scope.validate(), Ok(()));
        assert!(scope.admits(ExecutorClass::DesktopInput));
        assert!(!scope.admits(ExecutorClass::ShellProcess));
        assert!(!scope.admits(ExecutorClass::Filesystem));
        assert!(!scope.admits(ExecutorClass::Admin));
    }

    #[test]
    fn admin_and_remote_are_refused_in_every_shape() {
        let admin = LeaseScope::DesktopFullUser {
            executors: vec![ExecutorClass::DesktopInput, ExecutorClass::Admin],
            roots: Vec::new(),
            shells: false,
        };
        assert_eq!(
            admin.validate().map_err(|e| e.code),
            Err(orcel_contracts::FailureCode::CapabilityDenied)
        );
        let remote = LeaseScope::DesktopFullUser {
            executors: vec![ExecutorClass::Remote],
            roots: Vec::new(),
            shells: false,
        };
        assert!(remote.validate().is_err());
        let browser = LeaseScope::BrowserFullAccess {
            client_ref: "cl-abc".into(),
            session_id: "s1".into(),
            origins: vec!["https://example.com".into()],
            families: vec![BrowserFamily::Click],
            task: None,
        };
        assert!(!browser.admits(ExecutorClass::Admin));
        assert!(browser.admits(ExecutorClass::Browser));
        assert!(!browser.admits(ExecutorClass::DesktopInput));
    }

    #[test]
    fn widening_is_explicit_and_consistent() {
        let shells_without_executor = LeaseScope::DesktopFullUser {
            executors: vec![ExecutorClass::DesktopInput],
            roots: Vec::new(),
            shells: true,
        };
        assert!(shells_without_executor.validate().is_err());
        let roots_without_fs = LeaseScope::DesktopFullUser {
            executors: vec![ExecutorClass::DesktopInput],
            roots: vec!["D:\\work".into()],
            shells: false,
        };
        assert!(roots_without_fs.validate().is_err());
        let state_root = LeaseScope::DesktopFullUser {
            executors: vec![ExecutorClass::Filesystem],
            roots: vec!["C:\\ProgramData\\Orcel\\authority".into()],
            shells: false,
        };
        assert!(state_root.validate().is_err());
        let relative = LeaseScope::DesktopFullUser {
            executors: vec![ExecutorClass::Filesystem],
            roots: vec!["work\\..\\x".into()],
            shells: false,
        };
        assert!(relative.validate().is_err());
        let wide = LeaseScope::DesktopFullUser {
            executors: vec![
                ExecutorClass::DesktopInput,
                ExecutorClass::Filesystem,
                ExecutorClass::ShellProcess,
            ],
            roots: vec!["D:\\work".into()],
            shells: true,
        };
        assert_eq!(wide.validate(), Ok(()));
    }

    #[test]
    fn origins_are_canonical_only() {
        assert!(is_canonical_origin("https://example.com"));
        assert!(is_canonical_origin("https://a.example.com:8443"));
        for bad in [
            "http://example.com",
            "https://example.com/",
            "https://Example.com",
            "https://example.com:443",
            "https://*.example.com",
            "https://example.com:0",
            "https://[::1]",
            "https://",
        ] {
            assert!(!is_canonical_origin(bad), "{bad}");
        }
    }

    #[test]
    fn the_scope_wire_form_is_tagged_and_strict() {
        let scope = LeaseScope::narrow_default();
        let text = serde_json::to_string(&scope).unwrap_or_default();
        assert!(text.contains("\"kind\":\"desktop_full_user\""), "{text}");
        assert!(text.contains("\"desktop_input\""), "{text}");
        let back: Result<LeaseScope, _> = serde_json::from_str(&text);
        assert_eq!(back.ok(), Some(scope));
    }
}
