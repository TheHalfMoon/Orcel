use orcel_contracts::FailureCode;
use orcel_platform::{paths, PlatformError};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::path::{Component, Path, PathBuf};

pub const BROWSER_PROFILE_SCHEMA: &str = "orcel-browser-profile-v1";
pub const PROFILE_MARKER_FILE: &str = "ORCEL_AUTOMATION_PROFILE";
const PROFILE_MARKER_BODY: &str =
    "orcel-browser-profile-v1\nisolated\nno-personal-data\nno-credential-import\n";

const MAX_URL_BYTES: usize = 2048;
const MAX_HOST_BYTES: usize = 253;

/// Typed denial catalog for browser shapes that remain unauthorized.
/// SG-000021 left navigation, DOM actuation, downloads, uploads,
/// personal-profile access, debugging, scripting, and network egress absent.
/// SG-000022 authorizes only page lifecycle and origin-bound navigation.
/// SG-000023 additionally authorizes read-only snapshot observation.
/// SG-000024 additionally authorizes structured invoke (click) and
/// value-entry (fill) on typed node identities. SG-000025 additionally
/// authorizes scoped bounded download preview and download; every other
/// actuation verb, download-adjacent shape, and every shape listed here must
/// fail closed.
pub const DENIED_BROWSER_SHAPES: &[(&str, &str)] = &[
    ("browser.navigate", "navigate"),
    ("browser.snapshot", "capture"),
    ("browser.snapshot", "actuate"),
    ("browser.dom", "type"),
    ("browser.dom", "press"),
    ("browser.dom", "select"),
    ("browser.dom", "write"),
    ("browser.dom", "snapshot"),
    ("browser.dom", "observe"),
    ("browser.accessibility", "query"),
    ("browser.page", "close"),
    ("browser.navigation", "back"),
    ("browser.download", "execute"),
    ("browser.download", "open"),
    ("browser.download", "extract"),
    ("browser.download", "launch"),
    ("browser.download", "resume"),
    ("browser.file", "execute"),
    ("browser.file", "open"),
    ("browser.archive", "extract"),
    ("browser.shell", "run"),
    ("browser.upload", "upload"),
    ("browser.upload", "directory"),
    ("browser.upload", "multiple"),
    ("browser.upload", "execute"),
    ("browser.upload", "open"),
    ("browser.upload", "extract"),
    ("browser.file", "read"),
    ("browser.file", "list"),
    ("browser.fs", "read"),
    ("browser.directory", "upload"),
    ("browser.profile", "use_personal"),
    ("browser.profile", "attach"),
    ("browser.profile", "launch"),
    ("browser.debug", "attach"),
    ("browser.devtools", "command"),
    ("browser.cdp", "command"),
    ("browser.script", "evaluate"),
    ("browser.launch", "launch"),
    ("browser.attach", "attach"),
    ("browser.clear", "clear_profile"),
    ("browser.external_request", "fetch"),
    ("browser.network", "fetch"),
    ("devtools", "command"),
    ("cdp", "command"),
    ("playwright", "command"),
];

/// The typed operations SG-000025 authorizes: the two SG-000021 reads, the
/// SG-000022 page lifecycle and origin-bound navigation, the SG-000023
/// read-only snapshot observation, structured invoke (click) and value-entry
/// (fill) on typed node identities, plus the SG-000025 scoped download preview
/// and download shapes. Everything else under a browser-like capability must
/// fail closed.
pub fn is_allowed_browser_shape(capability: &str, operation: &str) -> bool {
    matches!(
        (capability, operation),
        ("browser.profile", "status")
            | ("browser.destination", "validate")
            | ("browser.page", "open")
            | ("browser.navigation", "preview")
            | ("browser.navigation", "navigate")
            | ("browser.snapshot", "observe")
            | ("browser.dom", "click")
            | ("browser.dom", "fill")
            | ("browser.download", "preview")
            | ("browser.download", "download")
            | ("browser.upload", "preview")
            | ("browser.upload", "submit")
    )
}

/// Returns true when a request targets browser-like authority outside the
/// allowed SG-000022 shapes. The policy layer denies these shapes; the
/// dispatch layer treats them as unreachable defense in depth.
pub fn is_denied_browser_shape(capability: &str, operation: &str) -> bool {
    if is_allowed_browser_shape(capability, operation) {
        return false;
    }
    if capability == "browser"
        || capability.starts_with("browser.")
        || capability.starts_with("devtools.")
        || capability.starts_with("cdp.")
        || capability.starts_with("playwright.")
        || capability == "devtools"
        || capability == "cdp"
        || capability == "playwright"
    {
        return true;
    }
    DENIED_BROWSER_SHAPES.contains(&(capability, operation))
}

#[derive(Debug)]
pub struct ProviderError {
    pub code: FailureCode,
    pub message: String,
}

impl ProviderError {
    pub fn new(code: FailureCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self::new(FailureCode::InvalidRequest, message)
    }

    fn denied(message: impl Into<String>) -> Self {
        Self::new(FailureCode::CapabilityDenied, message)
    }

    fn io(context: &str, error: std::io::Error) -> Self {
        Self::new(FailureCode::InternalError, format!("{context}: {error}"))
    }
}

/// Canonical bound origin: exact scheme, host, and port with a normalized
/// `scheme://host:port` identity. Origins are compared by this normalized
/// identity, never by naive string prefix logic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserOrigin {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub origin: String,
}

/// A validated browser destination: exact origin binding plus the
/// deterministically pinned post-resolution address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedDestination {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub origin: String,
    pub pinned_address: IpAddr,
}

impl ValidatedDestination {
    pub fn to_json(&self) -> Value {
        json!({
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "origin": self.origin,
            "pinned_address": self.pinned_address.to_string(),
        })
    }
}

pub trait DnsResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, ProviderError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

impl DnsResolver for SystemResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, ProviderError> {
        let mut addresses = Vec::new();
        let candidates = (host, port).to_socket_addrs().map_err(|error| {
            ProviderError::new(
                FailureCode::ProviderUnavailable,
                format!("resolve browser destination host: {error}"),
            )
        })?;
        for candidate in candidates {
            let address = candidate.ip();
            if !addresses.contains(&address) {
                addresses.push(address);
            }
        }
        if addresses.is_empty() {
            return Err(ProviderError::new(
                FailureCode::ProviderUnavailable,
                "browser destination host resolved to no addresses",
            ));
        }
        addresses.sort_by_key(|address| address.to_string());
        Ok(addresses)
    }
}

/// Parse a destination URL and bind its exact origin. This performs no network
/// activity: it validates scheme, host, and port shape only. Address policy is
/// applied after DNS resolution by [`validate_destination`].
pub fn parse_destination_url(url: &str) -> Result<BrowserOrigin, ProviderError> {
    if url.is_empty() || url.len() > MAX_URL_BYTES {
        return Err(ProviderError::invalid(
            "browser destination URL is empty or too large",
        ));
    }
    if url
        .bytes()
        .any(|byte| matches!(byte, 0 | b'\n' | b'\r' | b'\t' | b' ' | 0x0b | 0x0c | 0x7f))
    {
        return Err(ProviderError::invalid(
            "browser destination URL contains unsafe whitespace or control data",
        ));
    }
    let (raw_scheme, rest) = url.split_once("://").ok_or_else(|| {
        ProviderError::invalid("browser destination URL must contain a scheme separator")
    })?;
    let scheme = raw_scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(ProviderError::invalid(
            "browser destination URL must use the http or https scheme",
        ));
    }
    if rest.is_empty() {
        return Err(ProviderError::invalid(
            "browser destination URL is missing a host",
        ));
    }
    if rest.contains('@') {
        return Err(ProviderError::invalid(
            "browser destination URL must not contain userinfo",
        ));
    }
    if rest.contains('\\') {
        return Err(ProviderError::invalid(
            "browser destination URL must not contain a backslash",
        ));
    }
    if rest.contains('#') {
        return Err(ProviderError::invalid(
            "browser destination URL must not contain a fragment",
        ));
    }
    let authority_end = rest.find('/').unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let path = &rest[authority_end..];
    if authority.is_empty() {
        return Err(ProviderError::invalid(
            "browser destination URL is missing a host",
        ));
    }
    if !path.is_empty() && !path.starts_with('/') {
        return Err(ProviderError::invalid(
            "browser destination URL path is invalid",
        ));
    }
    if path.contains("/..") || path.contains('\\') {
        return Err(ProviderError::invalid(
            "browser destination URL path contains an unsafe sequence",
        ));
    }
    let (host, port) = split_authority(authority, &scheme)?;
    let host = normalize_host(&host)?;
    Ok(BrowserOrigin {
        origin: format!("{scheme}://{host}:{port}"),
        scheme,
        host,
        port,
    })
}

fn split_authority(authority: &str, scheme: &str) -> Result<(String, u16), ProviderError> {
    if let Some(bracketed) = authority.strip_prefix('[') {
        let end = bracketed.find(']').ok_or_else(|| {
            ProviderError::invalid("browser destination IPv6 host is missing a closing bracket")
        })?;
        let host = &bracketed[..end];
        let remainder = &bracketed[end + 1..];
        if host.is_empty() {
            return Err(ProviderError::invalid("browser destination host is empty"));
        }
        let port = match remainder.strip_prefix(':') {
            Some(text) => parse_port(text)?,
            None => {
                if !remainder.is_empty() {
                    return Err(ProviderError::invalid(
                        "browser destination authority is invalid",
                    ));
                }
                default_port(scheme)
            }
        };
        return Ok((host.to_owned(), port));
    }
    match authority.rfind(':') {
        Some(index) => {
            let host = &authority[..index];
            let port_text = &authority[index + 1..];
            if host.is_empty() {
                return Err(ProviderError::invalid("browser destination host is empty"));
            }
            if port_text.is_empty() || !port_text.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(ProviderError::invalid(
                    "browser destination authority has an invalid port; IPv6 literals must use brackets",
                ));
            }
            Ok((host.to_owned(), parse_port(port_text)?))
        }
        None => {
            if authority.is_empty() {
                return Err(ProviderError::invalid("browser destination host is empty"));
            }
            Ok((authority.to_owned(), default_port(scheme)))
        }
    }
}

fn default_port(scheme: &str) -> u16 {
    if scheme == "http" {
        80
    } else {
        443
    }
}

fn parse_port(text: &str) -> Result<u16, ProviderError> {
    if text.is_empty() || text.len() > 5 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ProviderError::invalid(
            "browser destination port must be numeric",
        ));
    }
    let port: u32 = text
        .parse()
        .map_err(|_| ProviderError::invalid("browser destination port is invalid"))?;
    if port == 0 || port > 65_535 {
        return Err(ProviderError::invalid(
            "browser destination port is out of range",
        ));
    }
    Ok(port as u16)
}

/// Normalize a host to its canonical lowercase identity while rejecting
/// ambiguous or unsafe representations: wildcards, userinfo remnants, zone
/// identifiers, hex/octal/integer IPv4 disguises, localhost aliases, and
/// malformed DNS names. Comparison-resistant origin identity depends on this
/// function accepting exactly one spelling per host.
fn normalize_host(raw: &str) -> Result<String, ProviderError> {
    if raw.is_empty() || raw.len() > MAX_HOST_BYTES {
        return Err(ProviderError::invalid(
            "browser destination host is empty or too large",
        ));
    }
    if raw.contains('*') {
        return Err(ProviderError::invalid(
            "browser destination host must not contain a wildcard",
        ));
    }
    if raw.contains('%') {
        return Err(ProviderError::invalid(
            "browser destination host must not contain a zone identifier",
        ));
    }
    if raw.contains('@') || raw.contains('/') || raw.contains('\\') || raw.contains('?') {
        return Err(ProviderError::invalid(
            "browser destination host contains unsafe characters",
        ));
    }
    if raw.ends_with('.') {
        return Err(ProviderError::invalid(
            "browser destination host must not use a trailing dot",
        ));
    }
    let host = raw.to_ascii_lowercase();
    reject_localhost_alias(&host)?;
    reject_alternate_numeric_host(&host)?;
    if host.parse::<IpAddr>().is_ok() {
        return Ok(host);
    }
    validate_dns_hostname(&host)?;
    Ok(host)
}

fn reject_localhost_alias(host: &str) -> Result<(), ProviderError> {
    if host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
        || host.ends_with(".lan")
        || host.ends_with(".home")
    {
        return Err(ProviderError::denied(
            "browser destination localhost alias is denied",
        ));
    }
    Ok(())
}

/// Reject alternate numeric host syntaxes that naive parsers may interpret as
/// loopback or private addresses: hexadecimal (`0x7f.0.0.1`), octal
/// (`0177.0.0.1`), and bare-integer (`2130706433`) forms. Standard dotted
/// decimal literals pass through to address policy instead.
fn reject_alternate_numeric_host(host: &str) -> Result<(), ProviderError> {
    if host.contains("0x") || host.contains("0X") {
        return Err(ProviderError::invalid(
            "browser destination host uses an alternate numeric representation",
        ));
    }
    if !host.contains('.') && host.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ProviderError::invalid(
            "browser destination host uses an alternate numeric representation",
        ));
    }
    if host.contains('.')
        && host
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        let all_plain_decimal = host
            .split('.')
            .all(|part| (part.len() == 1 || !part.starts_with('0')) && part.parse::<u8>().is_ok());
        if !all_plain_decimal {
            return Err(ProviderError::invalid(
                "browser destination host uses an alternate numeric representation",
            ));
        }
    }
    Ok(())
}

fn validate_dns_hostname(host: &str) -> Result<(), ProviderError> {
    if host.starts_with('-') || host.starts_with('.') || host.ends_with('-') || host.ends_with('.')
    {
        return Err(ProviderError::invalid(
            "browser destination hostname has an unsafe leading or trailing character",
        ));
    }
    if host.contains("..") {
        return Err(ProviderError::invalid(
            "browser destination hostname contains an empty label",
        ));
    }
    if !host.contains('.') {
        return Err(ProviderError::invalid(
            "browser destination hostname must be a dotted DNS hostname",
        ));
    }
    let mut has_alpha = false;
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(ProviderError::invalid(
                "browser destination hostname label is empty or too large",
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(ProviderError::invalid(
                "browser destination hostname label has an unsafe hyphen",
            ));
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(ProviderError::invalid(
                "browser destination hostname label uses unsafe characters",
            ));
        }
        has_alpha = has_alpha || label.bytes().any(|byte| byte.is_ascii_alphabetic());
    }
    if !has_alpha {
        return Err(ProviderError::invalid(
            "browser destination hostname must contain at least one letter",
        ));
    }
    Ok(())
}

/// Validate a destination URL end to end: bind the exact origin, re-resolve
/// DNS through the provided resolver, and apply post-resolution address
/// policy. Non-public addresses fail closed unless a future explicitly
/// trusted workspace destination allows them; SG-000021 configures no such
/// trust, so every non-public destination is denied.
pub fn validate_destination(
    url: &str,
    resolver: &impl DnsResolver,
) -> Result<ValidatedDestination, ProviderError> {
    let origin = parse_destination_url(url)?;
    let resolved = resolver.resolve(&origin.host, origin.port)?;
    let pinned = select_pinned_address(&resolved)?;
    Ok(ValidatedDestination {
        scheme: origin.scheme,
        host: origin.host,
        port: origin.port,
        origin: origin.origin,
        pinned_address: pinned,
    })
}

/// Validate a redirect target against an already validated base origin. Any
/// target whose exact origin differs from the base fails closed: a permitted
/// public origin can never silently widen into broader authority.
pub fn validate_redirect(
    base_origin: &str,
    target_url: &str,
    resolver: &impl DnsResolver,
) -> Result<ValidatedDestination, ProviderError> {
    let base = parse_destination_url(base_origin)?;
    let target = parse_destination_url(target_url)?;
    if target.origin != base.origin {
        return Err(ProviderError::denied(format!(
            "browser redirect target origin {} does not match validated origin {}; redirect widening is denied",
            target.origin, base.origin
        )));
    }
    validate_destination(target_url, resolver)
}

pub fn is_public_address(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(value) => is_public_ipv4(value),
        IpAddr::V6(value) => is_public_ipv6(value),
    }
}

fn is_public_ipv4(value: &Ipv4Addr) -> bool {
    let octets = value.octets();
    if value.is_loopback()
        || value.is_unspecified()
        || value.is_multicast()
        || value.is_link_local()
        || value.is_private()
    {
        return false;
    }
    if value.is_broadcast() || value.is_documentation() {
        return false;
    }
    if octets[0] == 0 {
        return false;
    }
    if octets[0] == 100 && (octets[1] & 0b1100_0000) == 64 {
        return false;
    }
    if octets[0] == 192 && octets[1] == 0 && (octets[2] == 0 || octets[2] == 2) {
        return false;
    }
    if octets[0] == 192 && octets[1] == 88 && octets[2] == 99 {
        return false;
    }
    if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
        return false;
    }
    if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
        return false;
    }
    if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
        return false;
    }
    if octets[0] >= 240 {
        return false;
    }
    true
}

fn is_public_ipv6(value: &Ipv6Addr) -> bool {
    if value.is_loopback() || value.is_unspecified() || value.is_multicast() {
        return false;
    }
    let segments = value.segments();
    if (segments[0] & 0xffc0) == 0xfe80 {
        return false;
    }
    if (segments[0] & 0xfe00) == 0xfc00 {
        return false;
    }
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return false;
    }
    if segments[0] == 0x2001 && segments[1] == 0x0002 {
        return false;
    }
    if segments[0] == 0x2001 && segments[1] == 0x0001 {
        return false;
    }
    if segments[0] == 0x2002 {
        return false;
    }
    if segments[0] == 0x0064 && (segments[1] & 0xffc0) == 0xff00 {
        return false;
    }
    // NAT64 (64:ff9b::/96, RFC 6052) and its local-use prefix
    // (64:ff9b:1::/48, RFC 8215): a gateway translates them to the embedded
    // IPv4 address, which may be private or the metadata service (judge,
    // PR #428). Never public.
    if segments[0] == 0x0064 && segments[1] == 0xff9b {
        return false;
    }
    // Site-local (fec0::/10, deprecated but still routed by some stacks).
    if (segments[0] & 0xffc0) == 0xfec0 {
        return false;
    }
    // Teredo (2001::/32) tunnels to an embedded IPv4 address.
    if segments[0] == 0x2001 && segments[1] == 0x0000 {
        return false;
    }
    // ORCHID and ORCHIDv2 (2001:10::/28, 2001:20::/28).
    if segments[0] == 0x2001 && matches!(segments[1] & 0xfff0, 0x0010 | 0x0020) {
        return false;
    }
    // Discard-only (100::/64).
    if segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0 {
        return false;
    }
    if value.octets()[0] == 0 && value.octets()[1] == 0 {
        return false;
    }
    if let Some(mapped) = value.to_ipv4_mapped() {
        return is_public_ipv4(&mapped);
    }
    if value.to_ipv4().is_some() {
        return false;
    }
    true
}

pub fn select_pinned_address(addresses: &[IpAddr]) -> Result<IpAddr, ProviderError> {
    if addresses.is_empty() {
        return Err(ProviderError::new(
            FailureCode::ProviderUnavailable,
            "browser destination host resolved to no addresses",
        ));
    }
    let mut public: Vec<IpAddr> = addresses
        .iter()
        .copied()
        .filter(is_public_address)
        .collect();
    if public.is_empty() {
        return Err(ProviderError::denied(
            "browser destination resolved only to non-public addresses; destination is denied",
        ));
    }
    public.sort_by_key(|address| address.to_string());
    public.dedup();
    Ok(public[0])
}

/// Lowercase hex SHA-256 of the exact bytes. Exposed so typed evidence
/// digests are computed by one implementation everywhere.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn profile_identity(root: &Path) -> String {
    sha256_hex(format!("{BROWSER_PROFILE_SCHEMA}\n{}", root.to_string_lossy()).as_bytes())
}

/// Canonical root for the isolated Orcel automation browser profile. Tests
/// override it with `ORCEL_BROWSER_STATE_DIR`; production defaults keep the
/// profile under Orcel protected local state, never inside a workspace and never
/// inside a personal browser directory. The default is `browser-profile` in the
/// private per-user Orcel state root (XP-01B); it fails closed when the override
/// is empty, relative or not in a private directory, or when the root cannot be
/// resolved or is not private, and never falls back to the shared temp
/// directory.
pub fn default_profile_root() -> Result<PathBuf, PlatformError> {
    default_profile_root_from(&|name| std::env::var_os(name))
}

/// [`default_profile_root`] with the environment read through `lookup`.
pub fn default_profile_root_from(
    lookup: &dyn Fn(&str) -> Option<std::ffi::OsString>,
) -> Result<PathBuf, PlatformError> {
    if let Some(path) = lookup("ORCEL_BROWSER_STATE_DIR") {
        let path = paths::absolute_override(path)?;
        let profile = if path.ends_with("browser-profile") {
            path
        } else {
            path.join("browser-profile")
        };
        return paths::private_file(profile);
    }
    let root = paths::state_root_from(lookup)?;
    paths::ensure_private_dir(&root)?;
    Ok(root.join("browser-profile"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserProfile {
    pub root: PathBuf,
    pub identity: String,
    pub fresh_storage: bool,
    pub isolated: bool,
}

impl BrowserProfile {
    pub fn status_json(&self, workspace_id: &str, policy_revision: &str) -> Value {
        json!({
            "profile_root": self.root.to_string_lossy(),
            "profile_identity": self.identity,
            "fresh_storage": self.fresh_storage,
            "isolated": self.isolated,
            "personal_data": false,
            "workspace_id": workspace_id,
            "policy_revision": policy_revision,
        })
    }
}

/// Directory or file names that indicate a personal browser profile. Matching
/// is case-insensitive on whole path components, so the Orcel automation
/// profile directory itself (`browser-profile`) never matches.
fn is_personal_component(component: &str) -> bool {
    matches!(
        component,
        "user data"
            | "user-data"
            | "google"
            | "chrome"
            | "google-chrome"
            | "chromium"
            | "microsoft edge"
            | "edge"
            | "edgemicrosoft"
            | "brave"
            | "brave-browser"
            | "vivaldi"
            | "opera"
            | "firefox"
            | "mozilla"
            | "profiles"
            | "profile"
            | "login data"
            | "cookies"
            | "web data"
            | "secure preferences"
            | "places.sqlite"
            | "logins.json"
    )
}

/// Returns true when a path reaches into a personal browser profile. Used to
/// fail closed before any profile directory is created or touched. Matching
/// splits on both path separators so Windows-style personal paths are
/// recognized on every platform.
pub fn is_personal_profile_path(path: &Path) -> bool {
    for component in path.components() {
        let text = component.as_os_str().to_string_lossy().to_ascii_lowercase();
        for piece in text.split(['/', '\\']) {
            if is_personal_component(piece.trim()) {
                return true;
            }
        }
    }
    false
}

fn reject_unsafe_profile_root(root: &Path) -> Result<(), ProviderError> {
    if is_personal_profile_path(root) {
        return Err(ProviderError::denied(
            "browser profile root reaches into a personal browser profile; personal-profile mode is denied",
        ));
    }
    if !root.is_absolute() {
        return Err(ProviderError::invalid(
            "browser profile root must be an absolute path",
        ));
    }
    let portable = root.to_string_lossy().replace('/', "\\");
    if portable.starts_with("\\\\") && !portable.starts_with("\\\\?\\") {
        return Err(ProviderError::denied(
            "browser profile root cannot use UNC or device namespaces",
        ));
    }
    for component in root.components() {
        match component {
            Component::ParentDir => {
                return Err(ProviderError::invalid(
                    "browser profile root must not contain parent components",
                ));
            }
            Component::Prefix(prefix) => match prefix.kind() {
                std::path::Prefix::Disk(_) | std::path::Prefix::VerbatimDisk(_) => {}
                _ => {
                    return Err(ProviderError::denied(
                        "browser profile root cannot use UNC or device namespaces",
                    ));
                }
            },
            Component::Normal(_) | Component::RootDir | Component::CurDir => {}
        }
    }
    Ok(())
}

/// Create or open the dedicated isolated automation profile. The profile
/// carries fresh Orcel-owned storage only: no personal cookies, passwords,
/// sessions, extensions, or history are ever imported, and caller-selected
/// profile directories are unreachable because dispatch never accepts one.
pub fn ensure_isolated_profile(root: &Path) -> Result<BrowserProfile, ProviderError> {
    reject_unsafe_profile_root(root)?;
    let existed_before = root.is_dir();
    std::fs::create_dir_all(root).map_err(|error| {
        ProviderError::new(
            FailureCode::ProviderUnavailable,
            format!("create isolated browser profile: {error}"),
        )
    })?;
    let canonical = std::fs::canonicalize(root).map_err(|error| {
        ProviderError::new(
            FailureCode::ProviderUnavailable,
            format!("resolve isolated browser profile: {error}"),
        )
    })?;
    reject_unsafe_profile_root(&canonical)?;
    let marker = canonical.join(PROFILE_MARKER_FILE);
    let mut fresh_storage = !existed_before;
    if marker.is_file() {
        let body = std::fs::read_to_string(&marker).map_err(|error| {
            ProviderError::new(
                FailureCode::ProviderUnavailable,
                format!("read browser profile marker: {error}"),
            )
        })?;
        if body != PROFILE_MARKER_BODY {
            return Err(ProviderError::new(
                FailureCode::TargetStale,
                "browser profile storage is not a Orcel automation profile; refusing to reuse it",
            ));
        }
        fresh_storage = false;
    } else {
        if marker.exists() {
            return Err(ProviderError::new(
                FailureCode::TargetStale,
                "browser profile marker path is obstructed; refusing to reuse it",
            ));
        }
        std::fs::write(&marker, PROFILE_MARKER_BODY).map_err(|error| {
            ProviderError::new(
                FailureCode::ProviderUnavailable,
                format!("initialize isolated browser profile: {error}"),
            )
        })?;
    }
    Ok(BrowserProfile {
        identity: profile_identity(&canonical),
        root: canonical,
        fresh_storage,
        isolated: true,
    })
}

/// Caller-selected profile directories are never honored. This function
/// exists so policy and dispatch share one fail-closed denial value.
pub fn reject_caller_profile_root() -> ProviderError {
    ProviderError::denied(
        "browser profile root is owned by Orcel protected state; caller-selected profile directories are denied",
    )
}

/// Compute the deterministic identity for a canonical profile root without
/// creating any directory. Page records bind this identity so a foreign
/// profile directory can never satisfy a page opened on the isolated profile.
pub fn profile_identity_for_root(root: &Path) -> String {
    profile_identity(root)
}

// ---------------------------------------------------------------------------
// SG-000022 typed page lifecycle and origin-bound bounded navigation.
// ---------------------------------------------------------------------------

/// Schema for the page registry file stored under Orcel protected state.
pub const PAGE_REGISTRY_SCHEMA: &str = "orcel-browser-pages-v1";
/// File name for the page registry inside the isolated profile directory.
pub const PAGE_REGISTRY_FILE: &str = "pages.jsonl";
/// Bound on simultaneously allocated pages per workspace.
pub const MAX_PAGES_PER_WORKSPACE: usize = 16;
/// Bound on redirect hops validated for a single navigation.
pub const MAX_REDIRECT_HOPS: usize = 8;
/// Prefix for server-allocated page identities. Callers never choose this
/// value; only identities present in the registry are valid.
pub const PAGE_ID_PREFIX: &str = "pg-";

/// Lifecycle state for a typed page. Pages start open with no origin and
/// become active after the first successful navigation. Closed pages never
/// become valid again; their handles fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageState {
    Open,
    Active,
    Closed,
}

impl PageState {
    pub fn as_str(self) -> &'static str {
        match self {
            PageState::Open => "open",
            PageState::Active => "active",
            PageState::Closed => "closed",
        }
    }
}

/// Server-side page record bound to the isolated profile, one workspace, its
/// current origin, and a lifecycle generation. The generation increments on
/// every successful navigation so replaced pages invalidate old handles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageRecord {
    pub page_id: String,
    pub workspace_id: String,
    pub profile_identity: String,
    pub current_origin: String,
    pub generation: u64,
    pub state: PageState,
    pub policy_revision: String,
}

impl PageRecord {
    pub fn to_json(&self) -> Value {
        json!({
            "page_id": self.page_id,
            "workspace_id": self.workspace_id,
            "profile_identity": self.profile_identity,
            "current_origin": self.current_origin,
            "generation": self.generation,
            "state": self.state.as_str(),
            "policy_revision": self.policy_revision,
        })
    }
}

/// Read-only navigation preview material. Preview performs full origin
/// binding, re-resolution, and post-resolution policy without mutating page
/// state and without requiring approval. The caller uses the preview to
/// build a fresh navigation request with exact expected state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NavigationPreview {
    pub page_id: String,
    pub workspace_id: String,
    pub policy_revision: String,
    pub current_origin: String,
    pub current_generation: u64,
    pub target_origin: String,
    pub pinned_address: IpAddr,
    pub redirect_count: usize,
    pub final_origin: String,
}

impl NavigationPreview {
    pub fn to_json(&self) -> Value {
        json!({
            "page_id": self.page_id,
            "workspace_id": self.workspace_id,
            "policy_revision": self.policy_revision,
            "current_origin": self.current_origin,
            "current_generation": self.current_generation,
            "target_origin": self.target_origin,
            "pinned_address": self.pinned_address.to_string(),
            "redirect_count": self.redirect_count,
            "final_origin": self.final_origin,
        })
    }
}

/// Typed bounded navigation evidence. Contains only origin, identity, and
/// approval linkage material. Cookies, credentials, tokens, headers, DOM
/// content, and raw browser internals never enter this packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NavigationEvidence {
    pub page_id: String,
    pub workspace_id: String,
    pub policy_revision: String,
    pub profile_identity: String,
    pub prior_origin: String,
    pub prior_generation: u64,
    pub target_origin: String,
    pub pinned_address: IpAddr,
    pub redirect_count: usize,
    pub final_origin: String,
    pub new_generation: u64,
}

impl NavigationEvidence {
    pub fn to_json(&self, approval_record_id: &str) -> Value {
        json!({
            "page_id": self.page_id,
            "workspace_id": self.workspace_id,
            "policy_revision": self.policy_revision,
            "profile_identity": self.profile_identity,
            "prior_origin": self.prior_origin,
            "prior_generation": self.prior_generation,
            "target_origin": self.target_origin,
            "pinned_address": self.pinned_address.to_string(),
            "redirect_count": self.redirect_count,
            "final_origin": self.final_origin,
            "new_generation": self.new_generation,
            "approval_record_id": approval_record_id,
            "cookies": false,
            "credentials": false,
        })
    }
}

/// File-backed page registry stored under Orcel protected local state. Only
/// server-allocated identities in this registry are valid; caller-supplied
/// strings that are absent here fail closed as stale handles.
#[derive(Debug)]
pub struct PageStore {
    path: PathBuf,
    pages: std::collections::BTreeMap<String, PageRecord>,
}

impl PageStore {
    pub fn load_or_create(path: PathBuf) -> Self {
        let mut store = Self {
            path,
            pages: std::collections::BTreeMap::new(),
        };
        if store.path.is_file() {
            if let Ok(text) = std::fs::read_to_string(&store.path) {
                for line in text.lines() {
                    if line.trim().is_empty() {
                        continue;
                    }
                    if let Ok(record) = serde_json::from_str::<StoredPage>(line) {
                        if record.schema != PAGE_REGISTRY_SCHEMA {
                            break;
                        }
                        let page = PageRecord {
                            page_id: record.page_id,
                            workspace_id: record.workspace_id,
                            profile_identity: record.profile_identity,
                            current_origin: record.current_origin,
                            generation: record.generation,
                            state: match record.state.as_str() {
                                "active" => PageState::Active,
                                "closed" => PageState::Closed,
                                _ => PageState::Open,
                            },
                            policy_revision: record.policy_revision,
                        };
                        if page.page_id.is_empty() {
                            break;
                        }
                        store.pages.insert(page.page_id.clone(), page);
                    }
                }
            }
        } else if let Some(parent) = store.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        store
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn get(&self, page_id: &str) -> Option<&PageRecord> {
        self.pages.get(page_id)
    }

    pub fn count_for_workspace(&self, workspace_id: &str) -> usize {
        self.pages
            .values()
            .filter(|page| page.workspace_id == workspace_id && page.state != PageState::Closed)
            .count()
    }

    /// Allocate a fresh page bound to the isolated profile, one workspace,
    /// an empty current origin, generation zero, and the current policy
    /// revision. No network activity occurs. Caller-supplied identities are
    /// never accepted; the identity is always server-allocated.
    pub fn open_page(
        &mut self,
        workspace_id: &str,
        profile_identity: &str,
        policy_revision: &str,
    ) -> Result<PageRecord, ProviderError> {
        if workspace_id.trim().is_empty() {
            return Err(ProviderError::invalid("browser page workspace is empty"));
        }
        if profile_identity.trim().is_empty() {
            return Err(ProviderError::invalid(
                "browser page profile identity is empty",
            ));
        }
        if policy_revision.trim().is_empty() {
            return Err(ProviderError::invalid(
                "browser page policy revision is empty",
            ));
        }
        if self.count_for_workspace(workspace_id) >= MAX_PAGES_PER_WORKSPACE {
            return Err(ProviderError::new(
                FailureCode::OutputLimit,
                format!(
                    "browser page bound exceeded for workspace; at most {MAX_PAGES_PER_WORKSPACE} open pages"
                ),
            ));
        }
        let page_id = fresh_page_id(workspace_id, profile_identity);
        if self.pages.contains_key(&page_id) {
            return Err(ProviderError::new(
                FailureCode::InternalError,
                "browser page identity collision; retry page open",
            ));
        }
        let page = PageRecord {
            page_id: page_id.clone(),
            workspace_id: workspace_id.to_owned(),
            profile_identity: profile_identity.to_owned(),
            current_origin: String::new(),
            generation: 0,
            state: PageState::Open,
            policy_revision: policy_revision.to_owned(),
        };
        self.persist(&page)?;
        self.pages.insert(page_id, page.clone());
        Ok(page)
    }

    /// Apply a validated navigation transition. The caller must already have
    /// validated expected state, target origin, pinned address, redirect
    /// chain, and fresh approval. This function re-checks expected state
    /// against current state, bumps the generation, and persists.
    pub fn apply_navigation(
        &mut self,
        page_id: &str,
        expected_origin: &str,
        expected_generation: u64,
        final_origin: &str,
    ) -> Result<(PageRecord, String, u64), ProviderError> {
        let current = self.pages.get(page_id).cloned().ok_or_else(|| {
            ProviderError::new(
                FailureCode::TargetStale,
                "browser page handle is unknown; stale page handles fail closed",
            )
        })?;
        if current.state == PageState::Closed {
            return Err(ProviderError::new(
                FailureCode::TargetStale,
                "browser page is closed; stale page handles fail closed",
            ));
        }
        if current.current_origin != expected_origin {
            return Err(ProviderError::new(
                FailureCode::TargetStale,
                "browser page origin changed since preview; stale page handles fail closed",
            ));
        }
        if current.generation != expected_generation {
            return Err(ProviderError::new(
                FailureCode::TargetStale,
                "browser page generation changed since preview; stale page handles fail closed",
            ));
        }
        let prior_origin = current.current_origin.clone();
        let prior_generation = current.generation;
        let mut next = current;
        next.current_origin = final_origin.to_owned();
        next.generation = next.generation.saturating_add(1);
        next.state = PageState::Active;
        self.persist(&next)?;
        self.pages.insert(page_id.to_owned(), next.clone());
        Ok((next, prior_origin, prior_generation))
    }

    /// Apply a validated structured actuation. The caller must already have
    /// verified the node record, expected role and state, and fresh approval.
    /// This function re-checks expected origin and generation against current
    /// state, keeps the origin, and bumps the generation so every observed
    /// node identity goes stale after mutation and the next action requires
    /// a fresh observation.
    pub fn apply_actuation(
        &mut self,
        page_id: &str,
        expected_origin: &str,
        expected_generation: u64,
    ) -> Result<(PageRecord, u64), ProviderError> {
        let current = self.pages.get(page_id).cloned().ok_or_else(|| {
            ProviderError::new(
                FailureCode::TargetStale,
                "browser page handle is unknown; stale page handles fail closed",
            )
        })?;
        if current.state != PageState::Active {
            return Err(ProviderError::new(
                FailureCode::TargetStale,
                "browser page has no active document; actuation requires a navigated page",
            ));
        }
        if current.current_origin != expected_origin {
            return Err(ProviderError::new(
                FailureCode::TargetStale,
                "browser page origin changed since observation; stale page handles fail closed",
            ));
        }
        if current.generation != expected_generation {
            return Err(ProviderError::new(
                FailureCode::TargetStale,
                "browser page generation changed since observation; stale page handles fail closed",
            ));
        }
        let prior_generation = current.generation;
        let mut next = current;
        next.generation = next.generation.saturating_add(1);
        self.persist(&next)?;
        self.pages.insert(page_id.to_owned(), next.clone());
        Ok((next, prior_generation))
    }

    /// Close a page: it can no longer be navigated, observed or actuated,
    /// and every later use of its handle fails closed as stale. Closing an
    /// already-closed page is a no-op; an unknown handle is stale.
    pub fn close_page(&mut self, page_id: &str) -> Result<PageRecord, ProviderError> {
        let current = self.pages.get(page_id).cloned().ok_or_else(|| {
            ProviderError::new(
                FailureCode::TargetStale,
                "browser page handle is unknown; stale page handles fail closed",
            )
        })?;
        if current.state == PageState::Closed {
            return Ok(current);
        }
        let mut next = current;
        next.state = PageState::Closed;
        next.generation = next.generation.saturating_add(1);
        self.persist(&next)?;
        self.pages.insert(page_id.to_owned(), next.clone());
        Ok(next)
    }

    /// Append the page's new state durably. A failed write fails the
    /// transition before the in-memory state changes, so the registry never
    /// claims a state its file does not hold.
    fn persist(&self, page: &PageRecord) -> Result<(), ProviderError> {
        use std::io::Write as _;
        let stored = StoredPage {
            schema: PAGE_REGISTRY_SCHEMA.to_owned(),
            page_id: page.page_id.clone(),
            workspace_id: page.workspace_id.clone(),
            profile_identity: page.profile_identity.clone(),
            current_origin: page.current_origin.clone(),
            generation: page.generation,
            state: page.state.as_str().to_owned(),
            policy_revision: page.policy_revision.clone(),
        };
        let unavailable = |_| {
            ProviderError::new(
                FailureCode::ProviderUnavailable,
                "browser page registry could not be written",
            )
        };
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(unavailable)?;
        }
        let mut line = serde_json::to_vec(&stored).map_err(|_| {
            ProviderError::new(
                FailureCode::InternalError,
                "browser page record could not be serialized",
            )
        })?;
        line.push(b'\n');
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(unavailable)?;
        file.write_all(&line).map_err(unavailable)?;
        file.sync_data().map_err(unavailable)
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct StoredPage {
    schema: String,
    page_id: String,
    workspace_id: String,
    profile_identity: String,
    current_origin: String,
    generation: u64,
    state: String,
    policy_revision: String,
}

fn fresh_page_id(workspace_id: &str, profile_identity: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher as _};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut hasher = DefaultHasher::new();
    std::process::id().hash(&mut hasher);
    now.hash(&mut hasher);
    count.hash(&mut hasher);
    workspace_id.hash(&mut hasher);
    profile_identity.hash(&mut hasher);
    let digest = Sha256::digest(format!("{:016x}{:016x}", hasher.finish(), count).as_bytes());
    let mut hex = String::with_capacity(32);
    use std::fmt::Write as _;
    for byte in digest.iter().take(16) {
        let _ = write!(&mut hex, "{byte:02x}");
    }
    format!("{PAGE_ID_PREFIX}{hex}")
}

/// Canonical path for the page registry file. Tests override it with
/// `ORCEL_BROWSER_STATE_DIR`; production keeps it inside the isolated
/// profile directory under Orcel protected local state.
pub fn default_page_registry_path(profile_root: &Path) -> PathBuf {
    profile_root.join(PAGE_REGISTRY_FILE)
}

/// Returns true when a navigation target path triggers download handling.
/// Executable, script, and archive suffixes are denied so navigation cannot
/// become a bypass around download policy. Query strings never hide the
/// suffix because only the path component is inspected.
pub fn is_download_trigger_url(url: &str) -> bool {
    let Some((_, rest)) = url.split_once("://") else {
        return false;
    };
    let authority_end = rest.find('/').unwrap_or(rest.len());
    let mut path = &rest[authority_end..];
    if let Some(end) = path.find(['?', '#']) {
        path = &path[..end];
    }
    let file = path.rsplit('/').next().unwrap_or("");
    let lower = file.to_ascii_lowercase();
    if lower.is_empty() {
        return false;
    }
    const SUFFIXES: &[&str] = &[
        ".exe", ".msi", ".msix", ".dll", ".sys", ".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".js",
        ".jse", ".wsf", ".wsh", ".zip", ".7z", ".rar", ".tar", ".gz", ".cab", ".iso", ".img",
    ];
    SUFFIXES.iter().any(|suffix| lower.ends_with(suffix))
}

/// Validate a redirect chain hop by hop. Every hop must parse, must share the
/// exact validated base origin, must re-resolve to a public address, must not
/// repeat a previously seen URL, and must not exceed the hop bound. Scheme
/// downgrade, loops, widening, SSRF, and malformed targets fail closed.
pub fn validate_redirect_chain(
    base_origin: &str,
    hops: &[String],
    resolver: &impl DnsResolver,
) -> Result<(ValidatedDestination, usize, String), ProviderError> {
    let base = parse_destination_url(base_origin).map_err(|e| {
        ProviderError::new(
            FailureCode::TargetStale,
            format!("browser redirect base origin is invalid: {}", e.message),
        )
    })?;
    if hops.len() > MAX_REDIRECT_HOPS {
        return Err(ProviderError::denied(format!(
            "browser redirect chain exceeds at most {MAX_REDIRECT_HOPS} hops"
        )));
    }
    let mut seen: Vec<String> = Vec::new();
    let mut current_origin = base.origin.clone();
    let mut final_validated: Option<ValidatedDestination> = None;
    for hop in hops {
        if is_download_trigger_url(hop) {
            return Err(ProviderError::denied(
                "browser redirect target triggers download handling; downloads remain denied",
            ));
        }
        let target = parse_destination_url(hop)?;
        if target.origin != base.origin {
            return Err(ProviderError::denied(format!(
                "browser redirect target origin {} does not match validated origin {}; redirect widening is denied",
                target.origin, base.origin
            )));
        }
        if seen.iter().any(|seen_url| seen_url == hop) {
            return Err(ProviderError::denied(
                "browser redirect chain contains a loop; redirect loops are denied",
            ));
        }
        seen.push(hop.clone());
        let validated = validate_destination(hop, resolver)?;
        if validated.origin != base.origin {
            return Err(ProviderError::denied(
                "browser redirect hop origin drifted after resolution; redirect widening is denied",
            ));
        }
        current_origin = validated.origin.clone();
        final_validated = Some(validated);
    }
    match final_validated {
        Some(final_destination) => Ok((final_destination, hops.len(), current_origin)),
        None => Err(ProviderError::invalid(
            "browser redirect chain is empty; supply at least one hop or navigate directly",
        )),
    }
}

/// Build a read-only navigation preview for a known page without mutating
/// state. Validates the target URL and optional redirect chain with full
/// re-resolution and post-resolution policy. Download triggers fail closed.
pub fn preview_navigation(
    page: &PageRecord,
    target_url: &str,
    redirect_chain: &[String],
    resolver: &impl DnsResolver,
) -> Result<NavigationPreview, ProviderError> {
    if page.state == PageState::Closed {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser page is closed; stale page handles fail closed",
        ));
    }
    if is_download_trigger_url(target_url) {
        return Err(ProviderError::denied(
            "browser navigation target triggers download handling; downloads remain denied",
        ));
    }
    let target = validate_destination(target_url, resolver)?;
    let (final_origin, pinned, redirect_count) = if redirect_chain.is_empty() {
        (target.origin.clone(), target.pinned_address, 0)
    } else {
        if target.origin.is_empty() {
            return Err(ProviderError::invalid(
                "browser navigation target origin is empty",
            ));
        }
        let (final_destination, count, final_name) =
            validate_redirect_chain(&target.origin, redirect_chain, resolver)?;
        if final_destination.origin != target.origin {
            return Err(ProviderError::denied(
                "browser redirect chain widened beyond the validated target origin",
            ));
        }
        (final_name, final_destination.pinned_address, count)
    };
    Ok(NavigationPreview {
        page_id: page.page_id.clone(),
        workspace_id: page.workspace_id.clone(),
        policy_revision: page.policy_revision.clone(),
        current_origin: page.current_origin.clone(),
        current_generation: page.generation,
        target_origin: target.origin,
        pinned_address: pinned,
        redirect_count,
        final_origin,
    })
}

/// Compute the SOFT approval digest for a navigation transition. The digest
/// binds page identity, expected origin and generation, target origin, pinned
/// address, redirect chain, workspace, profile identity, and policy revision.
/// Any material drift invalidates the approval.
#[allow(clippy::too_many_arguments)]
pub fn navigation_approval_digest(
    workspace_id: &str,
    policy_revision: &str,
    profile_identity: &str,
    page_id: &str,
    expected_origin: &str,
    expected_generation: u64,
    target_origin: &str,
    pinned_address: &IpAddr,
    redirect_chain: &[String],
    final_origin: &str,
) -> String {
    let mut hasher = Sha256::new();
    digest_bytes(&mut hasher, b"ORCEL_BROWSER_NAVIGATION_V1");
    digest_bytes(&mut hasher, workspace_id.as_bytes());
    digest_bytes(&mut hasher, policy_revision.as_bytes());
    digest_bytes(&mut hasher, profile_identity.as_bytes());
    digest_bytes(&mut hasher, page_id.as_bytes());
    digest_bytes(&mut hasher, expected_origin.as_bytes());
    digest_bytes(&mut hasher, expected_generation.to_string().as_bytes());
    digest_bytes(&mut hasher, target_origin.as_bytes());
    digest_bytes(&mut hasher, pinned_address.to_string().as_bytes());
    for hop in redirect_chain {
        digest_bytes(&mut hasher, hop.as_bytes());
    }
    digest_bytes(&mut hasher, final_origin.as_bytes());
    let digest = hasher.finalize();
    let mut output = String::with_capacity(digest.len() * 2);
    use std::fmt::Write as _;
    for byte in digest {
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn digest_bytes(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}
// ---------------------------------------------------------------------------
// SG-000023 read-only DOM and accessibility observation with typed node
// identity. Snapshots are computed read-only from the SG-000022 page
// registry: no browser is launched or attached, no page is loaded, and no
// network activity occurs. Observation is allowed only on active pages with
// a non-empty current origin. Node identities are server-allocated and bind
// profile identity, page identity, page generation, current origin, document
// generation, node index, and policy revision so later structured actuation
// cannot accidentally target a stale or replaced element.
// ---------------------------------------------------------------------------

/// Prefix for server-allocated typed node identities. Callers never choose
/// this value; only identities that recompute against the current page,
/// profile, origin, generation, and policy revision are valid.
pub const SNAPSHOT_NODE_PREFIX: &str = "nd-";
/// Prefix for server-allocated snapshot identities.
pub const SNAPSHOT_ID_PREFIX: &str = "ss-";
/// Hard bound on nodes returned by a single snapshot.
pub const MAX_SNAPSHOT_NODES: u64 = 200;
/// Hard bound on snapshot tree depth.
pub const MAX_SNAPSHOT_DEPTH: u64 = 8;
/// Hard bound on serialized snapshot bytes.
pub const MAX_SNAPSHOT_BYTES: usize = 65_536;
/// Default node bound when the caller supplies no explicit limit.
pub const DEFAULT_SNAPSHOT_NODES: u64 = 50;
/// Default depth bound when the caller supplies no explicit limit.
pub const DEFAULT_SNAPSHOT_DEPTH: u64 = 4;
/// Default byte bound when the caller supplies no explicit limit.
pub const DEFAULT_SNAPSHOT_BYTES: usize = 16_384;
/// Minimum accepted explicit byte bound. Smaller values cannot carry even a
/// single document node and fail closed as invalid requests.
pub const MIN_SNAPSHOT_BYTES: u64 = 256;

/// Roles the synthetic registry-bound snapshot may emit. The set is
/// intentionally small and structural: document metadata, headings, links,
/// buttons, and paragraphs. Password, credential, cookie, and session
/// material never appears under any role.
pub const SNAPSHOT_ROLES: &[&str] = &[
    "document",
    "heading",
    "link",
    "button",
    "paragraph",
    "textbox",
];

/// A typed observed node. The identity is server-allocated; the remaining
/// fields are bounded structural metadata. Values are redacted where
/// sensitive and raw browser-internal handles, cookies, credentials, tokens,
/// headers, and DOM content never enter this packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotNode {
    pub node_id: String,
    pub role: String,
    pub name: String,
    pub value: String,
    pub state: String,
    pub input_type: String,
    pub depth: u32,
    pub index: u64,
    pub page_id: String,
    pub page_generation: u64,
    pub document_generation: u64,
    pub origin: String,
    pub policy_revision: String,
}

impl SnapshotNode {
    pub fn to_json(&self) -> Value {
        json!({
            "node_id": self.node_id,
            "role": self.role,
            "name": self.name,
            "value": self.value,
            "state": self.state,
            "input_type": self.input_type,
            "depth": self.depth,
            "index": self.index,
            "page_id": self.page_id,
            "page_generation": self.page_generation,
            "document_generation": self.document_generation,
            "origin": self.origin,
            "policy_revision": self.policy_revision,
        })
    }
}

/// A typed read-only snapshot bound to one active page. Contains only
/// origin, identity, structural, and approval-free read material. Cookies,
/// credentials, tokens, headers, password values, and raw browser internals
/// never enter this packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageSnapshot {
    pub snapshot_id: String,
    pub page_id: String,
    pub workspace_id: String,
    pub policy_revision: String,
    pub profile_identity: String,
    pub origin: String,
    pub page_generation: u64,
    pub document_generation: u64,
    pub node_count: usize,
    pub truncated: bool,
    pub nodes: Vec<SnapshotNode>,
}

impl PageSnapshot {
    pub fn to_json(&self) -> Value {
        json!({
            "snapshot_id": self.snapshot_id,
            "page_id": self.page_id,
            "workspace_id": self.workspace_id,
            "policy_revision": self.policy_revision,
            "profile_identity": self.profile_identity,
            "origin": self.current_origin(),
            "page_generation": self.page_generation,
            "document_generation": self.document_generation,
            "node_count": self.node_count,
            "truncated": self.truncated,
            "nodes": self.nodes.iter().map(SnapshotNode::to_json).collect::<Vec<_>>(),
            "cookies": false,
            "credentials": false,
        })
    }

    fn current_origin(&self) -> &str {
        &self.origin
    }

    pub fn serialized_bytes(&self) -> usize {
        self.to_json().to_string().len()
    }
}

/// Compute the server-allocated typed identity for a node. The digest binds
/// profile identity, page identity, page generation, current origin,
/// document generation, node index, and policy revision under the
/// `ORCEL_BROWSER_NODE_V1` domain. Any drift in these bindings produces a
/// different identity, so old identities fail closed after navigation,
/// reload, document replacement, origin drift, or policy drift.
pub fn node_id_for(
    profile_identity: &str,
    page_id: &str,
    page_generation: u64,
    origin: &str,
    document_generation: u64,
    node_index: u64,
    policy_revision: &str,
) -> String {
    let mut hasher = Sha256::new();
    digest_bytes(&mut hasher, b"ORCEL_BROWSER_NODE_V1");
    digest_bytes(&mut hasher, profile_identity.as_bytes());
    digest_bytes(&mut hasher, page_id.as_bytes());
    digest_bytes(&mut hasher, page_generation.to_string().as_bytes());
    digest_bytes(&mut hasher, origin.as_bytes());
    digest_bytes(&mut hasher, document_generation.to_string().as_bytes());
    digest_bytes(&mut hasher, node_index.to_string().as_bytes());
    digest_bytes(&mut hasher, policy_revision.as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(32);
    use std::fmt::Write as _;
    for byte in digest.iter().take(16) {
        let _ = write!(&mut hex, "{byte:02x}");
    }
    format!("{SNAPSHOT_NODE_PREFIX}{hex}")
}

/// Compute the server-allocated identity for a snapshot. The digest binds
/// page identity, page generation, document generation, origin, profile
/// identity, and policy revision under the `ORCEL_BROWSER_SNAPSHOT_V1`
/// domain.
pub fn snapshot_id_for(
    page_id: &str,
    page_generation: u64,
    document_generation: u64,
    origin: &str,
    profile_identity: &str,
    policy_revision: &str,
) -> String {
    let mut hasher = Sha256::new();
    digest_bytes(&mut hasher, b"ORCEL_BROWSER_SNAPSHOT_V1");
    digest_bytes(&mut hasher, page_id.as_bytes());
    digest_bytes(&mut hasher, page_generation.to_string().as_bytes());
    digest_bytes(&mut hasher, document_generation.to_string().as_bytes());
    digest_bytes(&mut hasher, origin.as_bytes());
    digest_bytes(&mut hasher, profile_identity.as_bytes());
    digest_bytes(&mut hasher, policy_revision.as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(32);
    use std::fmt::Write as _;
    for byte in digest.iter().take(16) {
        let _ = write!(&mut hex, "{byte:02x}");
    }
    format!("{SNAPSHOT_ID_PREFIX}{hex}")
}

/// Redact a node value where the field is sensitive. Password inputs always
/// redact to `[redacted]` regardless of the stored value; all other values
/// pass through unchanged and are bounded by the snapshot byte cap. Cookie,
/// credential, and session stores are unreachable: they never reach this
/// function because no snapshot node carries them.
pub fn redact_node_value(role: &str, input_type: &str, value: &str) -> String {
    if input_type.eq_ignore_ascii_case("password") || role.eq_ignore_ascii_case("password") {
        return "[redacted]".to_owned();
    }
    value.to_owned()
}

/// Resolve caller-supplied snapshot bounds to effective limits. Missing
/// values fall back to the defaults; out-of-range values fail closed so
/// observation cannot become unrestricted page scraping.
pub fn resolve_snapshot_bounds(
    max_nodes: Option<u64>,
    max_depth: Option<u64>,
    max_bytes: Option<u64>,
) -> Result<(u64, u64, usize), ProviderError> {
    let nodes = max_nodes.unwrap_or(DEFAULT_SNAPSHOT_NODES);
    let depth = max_depth.unwrap_or(DEFAULT_SNAPSHOT_DEPTH);
    let bytes = max_bytes.unwrap_or(DEFAULT_SNAPSHOT_BYTES as u64);
    if !(1..=MAX_SNAPSHOT_NODES).contains(&nodes) {
        return Err(ProviderError::invalid(format!(
            "browser snapshot max_nodes must be between 1 and {MAX_SNAPSHOT_NODES}"
        )));
    }
    if !(1..=MAX_SNAPSHOT_DEPTH).contains(&depth) {
        return Err(ProviderError::invalid(format!(
            "browser snapshot max_depth must be between 1 and {MAX_SNAPSHOT_DEPTH}"
        )));
    }
    if !(MIN_SNAPSHOT_BYTES..=(MAX_SNAPSHOT_BYTES as u64)).contains(&bytes) {
        return Err(ProviderError::invalid(format!(
            "browser snapshot max_bytes must be between {MIN_SNAPSHOT_BYTES} and {MAX_SNAPSHOT_BYTES}"
        )));
    }
    Ok((nodes, depth, bytes as usize))
}

/// Build a read-only snapshot for a known page. The page must be active with
/// a non-empty current origin; open pages with no document fail closed.
/// The returned nodes are deterministic structural metadata bound to the
/// page generation and document generation, never live browser content, and
/// carry no secret material.
pub fn build_snapshot(
    page: &PageRecord,
    profile_identity: &str,
    policy_revision: &str,
    max_nodes: u64,
    max_depth: u32,
    max_bytes: usize,
) -> Result<PageSnapshot, ProviderError> {
    if page.state != PageState::Active {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser page has no active document; snapshot requires a navigated page",
        ));
    }
    if page.current_origin.is_empty() {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser page origin is empty; snapshot requires a navigated page",
        ));
    }
    if !(1..=MAX_SNAPSHOT_NODES).contains(&max_nodes) {
        return Err(ProviderError::invalid(format!(
            "browser snapshot max_nodes must be between 1 and {MAX_SNAPSHOT_NODES}"
        )));
    }
    if !(1..=MAX_SNAPSHOT_DEPTH).contains(&u64::from(max_depth)) {
        return Err(ProviderError::invalid(format!(
            "browser snapshot max_depth must be between 1 and {MAX_SNAPSHOT_DEPTH}"
        )));
    }
    if !(MIN_SNAPSHOT_BYTES as usize..=MAX_SNAPSHOT_BYTES).contains(&max_bytes) {
        return Err(ProviderError::invalid(format!(
            "browser snapshot max_bytes must be between {MIN_SNAPSHOT_BYTES} and {MAX_SNAPSHOT_BYTES}"
        )));
    }
    let document_generation = page.generation;
    // Deterministic structural template bound to the page origin. Depths are
    // fixed so max_depth filtering is observable and testable. Values carry
    // no secret material; the textbox entry uses a non-password input type
    // with an empty value to prove the redaction path stays inert for safe
    // fields. The textbox entry uses a non-password input type with an empty
    // value to prove the redaction path stays inert for safe fields.
    let template: &[(&str, &str, &str, &str, &str, u32)] = &[
        ("document", "page document", "", "none", "", 0),
        ("heading", "Page snapshot", "", "none", "", 1),
        (
            "link",
            "Canonical origin",
            page.current_origin.as_str(),
            "enabled",
            "",
            1,
        ),
        ("button", "Snapshot control", "", "enabled", "", 2),
        (
            "paragraph",
            "Bounded observation",
            "read-only",
            "none",
            "",
            2,
        ),
        ("textbox", "Search field", "", "enabled", "text", 2),
        // The file input is the only admissible upload target. It is a
        // structural observation entry so the typed file-input identity that
        // SG-000026 binds is reachable; SG-000024 explicitly denies filling a
        // file input, so a path can never be typed into it.
        ("textbox", "File upload field", "", "enabled", "file", 2),
    ];
    let mut nodes = Vec::new();
    for (offset, (role, name, value, state, input_type, depth)) in template.iter().enumerate() {
        if *depth > max_depth {
            continue;
        }
        if nodes.len() as u64 >= max_nodes {
            break;
        }
        let index = offset as u64;
        let node_id = node_id_for(
            profile_identity,
            &page.page_id,
            page.generation,
            &page.current_origin,
            document_generation,
            index,
            policy_revision,
        );
        nodes.push(SnapshotNode {
            node_id,
            role: (*role).to_owned(),
            name: (*name).to_owned(),
            value: redact_node_value(role, input_type, value),
            state: (*state).to_owned(),
            input_type: (*input_type).to_owned(),
            depth: *depth,
            index,
            page_id: page.page_id.clone(),
            page_generation: page.generation,
            document_generation,
            origin: page.current_origin.clone(),
            policy_revision: policy_revision.to_owned(),
        });
    }
    if nodes.is_empty() {
        return Err(ProviderError::new(
            FailureCode::OutputLimit,
            "browser snapshot bounds exclude the document node; increase max_nodes and max_depth",
        ));
    }
    let truncated = nodes.len() < template.iter().filter(|entry| entry.5 <= max_depth).count();
    let snapshot = PageSnapshot {
        snapshot_id: snapshot_id_for(
            &page.page_id,
            page.generation,
            document_generation,
            &page.current_origin,
            profile_identity,
            policy_revision,
        ),
        page_id: page.page_id.clone(),
        workspace_id: page.workspace_id.clone(),
        policy_revision: policy_revision.to_owned(),
        profile_identity: profile_identity.to_owned(),
        origin: page.current_origin.clone(),
        page_generation: page.generation,
        document_generation,
        node_count: nodes.len(),
        truncated,
        nodes,
    };
    if snapshot.serialized_bytes() > max_bytes {
        return Err(ProviderError::new(
            FailureCode::OutputLimit,
            "browser snapshot exceeds max_bytes; tighten max_nodes or raise max_bytes within bounds",
        ));
    }
    Ok(snapshot)
}

/// Validate a previously issued node against the current page, profile, and
/// policy revision. Stale page generations, replaced documents, origin
/// drift, foreign profiles, foreign pages, and policy drift all fail closed
/// so later structured actuation cannot target a stale or replaced element.
pub fn validate_snapshot_node(
    node: &SnapshotNode,
    page: &PageRecord,
    profile_identity: &str,
    policy_revision: &str,
) -> Result<(), ProviderError> {
    if node.page_id != page.page_id {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser node belongs to a different page; stale node handles fail closed",
        ));
    }
    if page.state == PageState::Closed {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser page is closed; stale node handles fail closed",
        ));
    }
    if node.page_generation != page.generation {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser node generation changed since observation; stale node handles fail closed",
        ));
    }
    if node.document_generation != page.generation {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser document was replaced since observation; stale node handles fail closed",
        ));
    }
    if node.origin != page.current_origin {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser page origin changed since observation; stale node handles fail closed",
        ));
    }
    if node.policy_revision != policy_revision || page.policy_revision != policy_revision {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser policy revision drifted since observation; stale node handles fail closed",
        ));
    }
    let expected = node_id_for(
        profile_identity,
        &node.page_id,
        node.page_generation,
        &node.origin,
        node.document_generation,
        node.index,
        policy_revision,
    );
    if expected != node.node_id {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser node identity does not match the current profile, page, generation, origin, and policy revision; stale node handles fail closed",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SG-000024 structured DOM actuation on typed node identity. Invoke (click)
// and value-entry (fill) consume SG-000023 server-allocated node identities
// with exact page, generation, origin, document generation, role, state, and
// policy revision binding. Every action requires a fresh SOFT approval with
// digest binding and bumps the page generation so observed identities go
// stale after mutation. Select, toggle, submit, keyboard input, password
// fill, coordinates, scripting, CDP, downloads, and uploads remain absent.
// ---------------------------------------------------------------------------

/// Prefix for server-allocated actuation identities.
pub const ACTUATION_ID_PREFIX: &str = "ac-";
/// Schema for the node registry file stored under Orcel protected state.
pub const NODE_REGISTRY_SCHEMA: &str = "orcel-browser-nodes-v1";
/// File name for the node registry inside the isolated profile directory.
pub const NODE_REGISTRY_FILE: &str = "nodes.jsonl";
/// Bound on fill value bytes. Oversized values fail closed.
pub const MAX_FILL_VALUE_BYTES: usize = 4096;
/// Roles that permit the invoke (click) verb.
pub const CLICK_ROLES: &[&str] = &["link", "button"];
/// Roles that permit the value-entry (fill) verb.
pub const FILL_ROLES: &[&str] = &["textbox"];
/// Node state that permits actuation. Disabled nodes never actuate.
pub const ENABLED_NODE_STATE: &str = "enabled";

/// Returns true when an observed role permits the requested actuation verb.
/// Only invoke on links and buttons and value-entry on text boxes are
/// authorized; every other role and verb combination fails closed.
pub fn role_permits_action(role: &str, action: &str) -> bool {
    match action {
        "click" => CLICK_ROLES.contains(&role),
        "fill" => FILL_ROLES.contains(&role),
        _ => false,
    }
}

/// Returns true when a node is a password target. Password-field fill and
/// credential submission are denied in this grain.
pub fn is_password_target(role: &str, input_type: &str) -> bool {
    input_type.eq_ignore_ascii_case("password") || role.eq_ignore_ascii_case("password")
}

/// Parse a requested actuation verb. Only `click` and `fill` exist; select,
/// toggle, submit, keyboard, and coordinate verbs fail closed.
pub fn parse_actuation_action(action: &str) -> Result<&str, ProviderError> {
    match action {
        "click" | "fill" => Ok(action),
        _ => Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "browser actuation supports only the click and fill verbs; all other verbs are denied",
        )),
    }
}

/// Server-side record of an observed node, persisted at snapshot time so
/// later actuation verifies role and state against server records rather
/// than caller assertions. Records are created only by [`NodeStore`];
/// callers hold identities, never these records. Raw browser-internal
/// handles, cookies, credentials, and session material never enter this
/// record.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoredNode {
    schema: String,
    node_id: String,
    page_id: String,
    workspace_id: String,
    profile_identity: String,
    origin: String,
    page_generation: u64,
    document_generation: u64,
    index: u64,
    role: String,
    input_type: String,
    state: String,
    policy_revision: String,
}

/// File-backed node registry stored under Orcel protected local state.
/// Actuation resolves caller-supplied node identities through this registry;
/// identities absent here fail closed as stale handles.
#[derive(Debug)]
pub struct NodeStore {
    path: PathBuf,
    nodes: std::collections::BTreeMap<String, StoredNode>,
}

impl NodeStore {
    pub fn load_or_create(path: PathBuf) -> Self {
        let mut store = Self {
            path,
            nodes: std::collections::BTreeMap::new(),
        };
        if store.path.is_file() {
            if let Ok(text) = std::fs::read_to_string(&store.path) {
                for line in text.lines() {
                    if line.trim().is_empty() {
                        continue;
                    }
                    if let Ok(record) = serde_json::from_str::<StoredNode>(line) {
                        if record.schema != NODE_REGISTRY_SCHEMA {
                            break;
                        }
                        if record.node_id.is_empty() {
                            break;
                        }
                        store.nodes.insert(record.node_id.clone(), record);
                    }
                }
            }
        } else if let Some(parent) = store.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        store
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn get(&self, node_id: &str) -> Option<&StoredNode> {
        self.nodes.get(node_id)
    }

    /// Persist the nodes of a freshly built snapshot as server-side records.
    /// Records are append-only; newer generations shadow older identities
    /// through the generation checks in [`check_node_for_actuation`].
    pub fn record_snapshot(
        &mut self,
        profile_identity: &str,
        page: &PageRecord,
        policy_revision: &str,
        nodes: &[SnapshotNode],
    ) {
        use std::io::Write as _;
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        else {
            return;
        };
        for node in nodes {
            let stored = StoredNode {
                schema: NODE_REGISTRY_SCHEMA.to_owned(),
                node_id: node.node_id.clone(),
                page_id: page.page_id.clone(),
                workspace_id: page.workspace_id.clone(),
                profile_identity: profile_identity.to_owned(),
                origin: page.current_origin.clone(),
                page_generation: page.generation,
                document_generation: node.document_generation,
                index: node.index,
                role: node.role.clone(),
                input_type: node.input_type.clone(),
                state: node.state.clone(),
                policy_revision: policy_revision.to_owned(),
            };
            self.nodes.insert(stored.node_id.clone(), stored.clone());
            let _ = serde_json::to_writer(&mut file, &stored);
            let _ = file.write_all(b"\n");
        }
        let _ = file.flush();
    }
}

/// Canonical path for the node registry file. Tests override it with
/// `ORCEL_BROWSER_STATE_DIR`; production keeps it inside the isolated
/// profile directory under Orcel protected local state.
pub fn default_node_registry_path(profile_root: &Path) -> PathBuf {
    profile_root.join(NODE_REGISTRY_FILE)
}

/// Verify a server-side node record against the current page, profile,
/// policy revision, caller-expected role and state, and requested verb.
/// Stale generations, replaced documents, origin drift, foreign profiles,
/// foreign pages, forged identities, role or state mismatch, disabled
/// nodes, password targets, and unpermitted role and verb combinations all
/// fail closed.
#[allow(clippy::too_many_arguments)]
pub fn check_node_for_actuation(
    node: &StoredNode,
    page: &PageRecord,
    profile_identity: &str,
    policy_revision: &str,
    expected_role: &str,
    expected_state: &str,
    expected_generation: u64,
    expected_document_generation: u64,
    action: &str,
) -> Result<(), ProviderError> {
    if node.page_id != page.page_id {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser node belongs to a different page; stale node handles fail closed",
        ));
    }
    if page.state == PageState::Closed {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser page is closed; stale node handles fail closed",
        ));
    }
    if node.page_generation != expected_generation || page.generation != expected_generation {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser node generation changed since observation; stale node handles fail closed",
        ));
    }
    if node.document_generation != expected_document_generation
        || page.generation != expected_document_generation
    {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser document was replaced since observation; stale node handles fail closed",
        ));
    }
    if node.origin != page.current_origin {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser page origin changed since observation; stale node handles fail closed",
        ));
    }
    if node.policy_revision != policy_revision || page.policy_revision != policy_revision {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser policy revision drifted since observation; stale node handles fail closed",
        ));
    }
    let expected = node_id_for(
        profile_identity,
        &node.page_id,
        node.page_generation,
        &node.origin,
        node.document_generation,
        node.index,
        policy_revision,
    );
    if expected != node.node_id {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser node identity does not match the current profile, page, generation, origin, and policy revision; stale node handles fail closed",
        ));
    }
    if expected_role != node.role {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser node role changed since observation; stale node handles fail closed",
        ));
    }
    if expected_state != node.state {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser node state changed since observation; stale node handles fail closed",
        ));
    }
    if node.state != ENABLED_NODE_STATE {
        return Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "browser node is not enabled; actuation on disabled nodes is denied",
        ));
    }
    if is_password_target(&node.role, &node.input_type) {
        return Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "browser password-field actuation is denied; credential submission remains absent",
        ));
    }
    if node.input_type.eq_ignore_ascii_case(UPLOAD_INPUT_TYPE) {
        return Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "browser file-input actuation is denied; a file input is reachable only through the scoped upload capability and a path is never typed into it",
        ));
    }
    if !role_permits_action(&node.role, action) {
        return Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "browser node role does not permit the requested actuation verb",
        ));
    }
    Ok(())
}

/// Compute the SOFT approval digest for a structured actuation. The digest
/// binds workspace, policy revision, profile identity, page identity,
/// expected origin and generation, document generation, node identity,
/// expected role and state, requested action, and the bounded value digest.
/// Any material drift invalidates the approval.
#[allow(clippy::too_many_arguments)]
pub fn actuation_approval_digest(
    workspace_id: &str,
    policy_revision: &str,
    profile_identity: &str,
    page_id: &str,
    expected_origin: &str,
    expected_generation: u64,
    expected_document_generation: u64,
    node_id: &str,
    expected_role: &str,
    expected_state: &str,
    action: &str,
    value: &str,
) -> String {
    let mut hasher = Sha256::new();
    digest_bytes(&mut hasher, b"ORCEL_BROWSER_ACTUATION_V1");
    digest_bytes(&mut hasher, workspace_id.as_bytes());
    digest_bytes(&mut hasher, policy_revision.as_bytes());
    digest_bytes(&mut hasher, profile_identity.as_bytes());
    digest_bytes(&mut hasher, page_id.as_bytes());
    digest_bytes(&mut hasher, expected_origin.as_bytes());
    digest_bytes(&mut hasher, expected_generation.to_string().as_bytes());
    digest_bytes(
        &mut hasher,
        expected_document_generation.to_string().as_bytes(),
    );
    digest_bytes(&mut hasher, node_id.as_bytes());
    digest_bytes(&mut hasher, expected_role.as_bytes());
    digest_bytes(&mut hasher, expected_state.as_bytes());
    digest_bytes(&mut hasher, action.as_bytes());
    digest_bytes(&mut hasher, value.as_bytes());
    let digest = hasher.finalize();
    let mut output = String::with_capacity(digest.len() * 2);
    use std::fmt::Write as _;
    for byte in digest {
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

/// Compute the actuation identity for a validated action. The digest binds
/// page identity, node identity, action, value digest, prior generation, and
/// the new generation under the `ORCEL_BROWSER_ACTUATION_ID_V1` domain.
pub fn actuation_id_for(
    page_id: &str,
    node_id: &str,
    action: &str,
    value_digest: &str,
    prior_generation: u64,
    new_generation: u64,
) -> String {
    let mut hasher = Sha256::new();
    digest_bytes(&mut hasher, b"ORCEL_BROWSER_ACTUATION_ID_V1");
    digest_bytes(&mut hasher, page_id.as_bytes());
    digest_bytes(&mut hasher, node_id.as_bytes());
    digest_bytes(&mut hasher, action.as_bytes());
    digest_bytes(&mut hasher, value_digest.as_bytes());
    digest_bytes(&mut hasher, prior_generation.to_string().as_bytes());
    digest_bytes(&mut hasher, new_generation.to_string().as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(32);
    use std::fmt::Write as _;
    for byte in digest.iter().take(16) {
        let _ = write!(&mut hex, "{byte:02x}");
    }
    format!("{ACTUATION_ID_PREFIX}{hex}")
}

/// Digest a bounded fill value for approval binding and evidence. Values
/// larger than the bound fail closed before any digest is produced.
pub fn fill_value_digest(value: &str) -> Result<String, ProviderError> {
    if value.len() > MAX_FILL_VALUE_BYTES {
        return Err(ProviderError::invalid(format!(
            "browser fill value exceeds at most {MAX_FILL_VALUE_BYTES} bytes"
        )));
    }
    Ok(sha256_hex(value.as_bytes()))
}

/// Typed structured actuation evidence. Contains only identity, binding,
/// and approval linkage material. Cookies, credentials, tokens, headers,
/// password values, and raw browser internals never enter this packet; fill
/// evidence carries only the value digest, never the value itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActuationEvidence {
    pub actuation_id: String,
    pub page_id: String,
    pub workspace_id: String,
    pub policy_revision: String,
    pub profile_identity: String,
    pub node_id: String,
    pub action: String,
    pub role: String,
    pub state: String,
    pub origin: String,
    pub prior_generation: u64,
    pub new_generation: u64,
    pub value_digest: String,
}

impl ActuationEvidence {
    pub fn to_json(&self, approval_record_id: &str) -> Value {
        json!({
            "actuation_id": self.actuation_id,
            "page_id": self.page_id,
            "workspace_id": self.workspace_id,
            "policy_revision": self.policy_revision,
            "profile_identity": self.profile_identity,
            "node_id": self.node_id,
            "action": self.action,
            "role": self.role,
            "state": self.state,
            "origin": self.origin,
            "prior_generation": self.prior_generation,
            "new_generation": self.new_generation,
            "value_digest": self.value_digest,
            "approval_record_id": approval_record_id,
            "cookies": false,
            "credentials": false,
        })
    }
}

// ---------------------------------------------------------------------------
// SG-000025 scoped bounded browser downloads. A download is authorized as a
// bounded create-only write of exactly one payload into exactly one canonical
// relative destination under the approved workspace root. No browser is
// launched or attached, Orcel performs no network transfer, and downloaded
// content is never executed, opened, extracted, or launched.
// ---------------------------------------------------------------------------

/// Prefix for server-allocated one-shot download source identities.
pub const DOWNLOAD_SOURCE_PREFIX: &str = "dl-";
/// Number of lowercase hex characters in a download source identity digest.
pub const DOWNLOAD_SOURCE_DIGEST_HEX: usize = 64;
/// Prefix for download identities recorded in download evidence.
pub const DOWNLOAD_ID_PREFIX: &str = "dn-";
/// Revision of the download destination and content-type policy itself.
pub const DOWNLOAD_POLICY_REVISION: &str = "sg-000025-download-v1";
/// Schema for the download registry file stored under Orcel protected state.
pub const DOWNLOAD_REGISTRY_SCHEMA: &str = "orcel-browser-downloads-v1";
/// File name for the download registry inside the isolated profile directory.
pub const DOWNLOAD_REGISTRY_FILE: &str = "downloads.jsonl";
/// Hard bound on the decoded payload of a single download.
pub const MAX_DOWNLOAD_BYTES: u64 = 8 * 1024 * 1024;
/// Bound on one destination path component in bytes.
pub const MAX_DOWNLOAD_COMPONENT_BYTES: usize = 128;
/// Bound on a canonical relative destination in bytes.
pub const MAX_DOWNLOAD_RELATIVE_BYTES: usize = 512;
/// Bound on the encoded body argument accepted by a download request.
pub const MAX_DOWNLOAD_BODY_BYTES: usize = ((MAX_DOWNLOAD_BYTES as usize) / 3 + 1) * 4;
/// Bound on simultaneously pending download sources per workspace.
pub const MAX_PENDING_DOWNLOADS_PER_WORKSPACE: usize = 8;
/// Deterministic lifetime of a download source identity in milliseconds.
pub const DOWNLOAD_SOURCE_TTL_MS: u64 = 120_000;
/// Media types a download may declare and carry. Anything else fails closed.
pub const ALLOWED_DOWNLOAD_MEDIA_TYPES: &[&str] = &[
    "text/plain",
    "text/markdown",
    "text/csv",
    "application/json",
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
];
/// Media type returned when content matches no authorized class.
pub const UNKNOWN_DOWNLOAD_MEDIA_TYPE: &str = "application/octet-stream";
/// Suffix families that always fail closed. Executables, scripts, installers,
/// command files, archives, shortcuts, and macro-capable documents must never
/// become approved download destinations.
pub const DENIED_DOWNLOAD_SUFFIXES: &[&str] = &[
    "exe", "dll", "com", "bat", "cmd", "msi", "msix", "appx", "scr", "pif", "cpl", "sys", "drv",
    "ocx", "ps1", "psm1", "psd1", "vbs", "vbe", "js", "mjs", "cjs", "jse", "wsf", "wsh", "hta",
    "sh", "bash", "py", "rb", "pl", "jar", "class", "lnk", "url", "scf", "reg", "inf", "job",
    "zip", "7z", "rar", "tar", "gz", "bz2", "xz", "tgz", "iso", "img", "vhd", "vhdx", "cab", "deb",
    "rpm", "dmg", "pkg", "apk", "crx", "xpi", "docm", "xlsm", "pptm", "dotm", "xltm", "potm",
    "doc", "xls", "ppt",
];

/// Returns true when a path component names a reserved Windows device. Such
/// names address devices, not files, and must never be written.
pub fn is_reserved_device_name(component: &str) -> bool {
    let base = component.split('.').next().unwrap_or(component);
    let base = base.trim_end_matches(' ').trim_end_matches('.');
    let upper = base.to_ascii_uppercase();
    if matches!(
        upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) {
        return true;
    }
    for prefix in ["COM", "LPT"] {
        if let Some(digit) = upper.strip_prefix(prefix) {
            if digit.len() == 1 && digit.chars().all(|character| character.is_ascii_digit()) {
                return true;
            }
        }
    }
    false
}

/// Validate a caller-proposed canonical relative download destination and
/// return `(canonical_relative, filename)` with forward slashes. Absolute
/// paths, drive prefixes, UNC paths, device paths, NT namespace paths,
/// alternate data streams, parent traversal, empty or duplicate separators,
/// trailing dots and spaces, reserved device names, illegal characters, and
/// over-length components fail closed. The returned value is the exact
/// destination recorded in evidence and bound into approval digests.
pub fn validate_download_relative_path(relative: &str) -> Result<(String, String), ProviderError> {
    if relative.is_empty() {
        return Err(ProviderError::invalid(
            "browser download destination is empty",
        ));
    }
    if relative.len() > MAX_DOWNLOAD_RELATIVE_BYTES {
        return Err(ProviderError::invalid(format!(
            "browser download destination exceeds at most {MAX_DOWNLOAD_RELATIVE_BYTES} bytes"
        )));
    }
    if relative.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return Err(ProviderError::denied(
            "browser download destination contains control characters; caller paths must be canonical relative destinations",
        ));
    }
    let normalized = relative.replace('/', "\\");
    let bytes = normalized.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' {
        return Err(ProviderError::new(
            FailureCode::PathEscape,
            "browser download destination must not carry a drive prefix; absolute destinations are denied",
        ));
    }
    if normalized.starts_with('\\') {
        return Err(ProviderError::new(
            FailureCode::PathEscape,
            "browser download destination must be relative; UNC, device, and NT namespace destinations are denied",
        ));
    }
    if normalized.contains(':') {
        return Err(ProviderError::new(
            FailureCode::PathEscape,
            "browser download destination must not contain ':'; alternate data streams and stream syntax are denied",
        ));
    }
    let mut components: Vec<&str> = Vec::new();
    for component in normalized.split('\\') {
        if component.is_empty() {
            return Err(ProviderError::new(
                FailureCode::PathEscape,
                "browser download destination contains an empty path component",
            ));
        }
        if component == "." || component == ".." {
            return Err(ProviderError::new(
                FailureCode::PathEscape,
                "browser download destination must not contain '.', '..', or parent traversal components",
            ));
        }
        if component.ends_with('.') || component.ends_with(' ') {
            return Err(ProviderError::new(
                FailureCode::PathEscape,
                "browser download destination components must not end with a dot or a space",
            ));
        }
        if component.len() > MAX_DOWNLOAD_COMPONENT_BYTES {
            return Err(ProviderError::invalid(format!(
                "browser download destination component exceeds at most {MAX_DOWNLOAD_COMPONENT_BYTES} bytes"
            )));
        }
        if component
            .bytes()
            .any(|byte| matches!(byte, b'<' | b'>' | b'"' | b'|' | b'?' | b'*'))
        {
            return Err(ProviderError::new(
                FailureCode::PathEscape,
                "browser download destination contains characters that are illegal in Windows path components",
            ));
        }
        if is_reserved_device_name(component) {
            return Err(ProviderError::new(
                FailureCode::PathEscape,
                "browser download destination component is a reserved Windows device name",
            ));
        }
        components.push(component);
    }
    let filename = components.last().copied().unwrap_or("").to_owned();
    let canonical = components.join("/");
    Ok((canonical, filename))
}

/// Map a declared download filename to its authorized media type. The
/// extension allowlist is the authority: executables, scripts, installers,
/// command files, archives, shortcuts, macro-capable documents, extensionless
/// names, and every unlisted extension fail closed.
pub fn download_media_type_for_filename(filename: &str) -> Result<&'static str, ProviderError> {
    let lower = filename.to_ascii_lowercase();
    let extension = lower.rsplit_once('.').map(|(_, extension)| extension);
    let Some(extension) = extension.filter(|extension| !extension.is_empty()) else {
        return Err(ProviderError::denied(
            "browser download filename must carry a recognized authorized extension; extensionless downloads are denied",
        ));
    };
    if DENIED_DOWNLOAD_SUFFIXES.contains(&extension) {
        return Err(ProviderError::denied(format!(
            "browser download extension '{}' is denied; executables, scripts, installers, command files, archives, shortcuts, and macro-capable documents never become approved download destinations",
            extension
        )));
    }
    let media_type = match extension {
        "txt" => "text/plain",
        "md" => "text/markdown",
        "csv" => "text/csv",
        "json" => "application/json",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        _ => {
            return Err(ProviderError::denied(format!(
                "browser download extension '{}' is not in the authorized allowlist; only inert text, JSON, and image downloads are authorized",
                extension
            )))
        }
    };
    Ok(media_type)
}

/// Returns true when a declared media type is in the authorized allowlist.
pub fn is_allowed_download_media_type(media_type: &str) -> bool {
    ALLOWED_DOWNLOAD_MEDIA_TYPES.contains(&media_type)
}

/// Determine the media type of downloaded content from its bytes. Executable,
/// script, archive, and OLE compound signatures return their own class so they
/// can never be mistaken for authorized inert content.
pub fn sniff_download_media_type(bytes: &[u8]) -> &'static str {
    if bytes.starts_with(b"MZ") {
        return "application/x-msdownload";
    }
    if bytes.starts_with(b"\x7fELF") {
        return "application/x-elf";
    }
    if bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xce])
        || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
        || bytes.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
        || bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
    {
        return "application/x-mach-binary";
    }
    if bytes.starts_with(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]) {
        return "application/x-ole-storage";
    }
    if bytes.starts_with(b"#!") {
        return "text/x-shellscript";
    }
    if bytes.starts_with(b"PK\x03\x04")
        || bytes.starts_with(b"PK\x05\x06")
        || bytes.starts_with(b"PK\x07\x08")
    {
        return "application/zip";
    }
    if bytes.starts_with(b"%PDF-") {
        return "application/pdf";
    }
    if bytes.starts_with(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]) {
        return "image/png";
    }
    if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        return "image/jpeg";
    }
    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        return "image/gif";
    }
    if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
        return "image/webp";
    }
    if bytes.is_empty() {
        return UNKNOWN_DOWNLOAD_MEDIA_TYPE;
    }
    let text_like = std::str::from_utf8(bytes).is_ok()
        && !bytes.contains(&0)
        && !bytes
            .iter()
            .any(|byte| *byte < 0x20 && !matches!(*byte, b'\t' | b'\n' | b'\r'));
    if text_like {
        return "text/plain";
    }
    UNKNOWN_DOWNLOAD_MEDIA_TYPE
}
/// Returns true when sniffed content is compatible with the declared media
/// type. Text and JSON declarations require text content; image declarations
/// require the exact matching image class. Any other pairing fails closed.
pub fn content_matches_declared_media_type(declared: &str, sniffed: &str) -> bool {
    if declared.starts_with("image/") {
        declared == sniffed
    } else {
        sniffed == "text/plain"
    }
}

/// Strictly decode one bounded standard-base64 body. Padding shape, alphabet,
/// length, and the decoded size bound are all enforced before any byte is
/// returned so a malformed body can never reach the filesystem.
pub fn decode_download_body(encoded: &str) -> Result<Vec<u8>, ProviderError> {
    if encoded.is_empty() {
        return Err(ProviderError::invalid(
            "browser download body is empty; empty downloads are denied",
        ));
    }
    if encoded.len() > MAX_DOWNLOAD_BODY_BYTES {
        return Err(ProviderError::invalid(format!(
            "browser download body exceeds at most {MAX_DOWNLOAD_BODY_BYTES} encoded bytes"
        )));
    }
    if encoded.len() % 4 != 0 {
        return Err(ProviderError::invalid(
            "browser download body is not a whole number of base64 groups",
        ));
    }
    let bytes = encoded.as_bytes();
    let padding = bytes.iter().rev().take_while(|byte| **byte == b'=').count();
    if padding > 2 {
        return Err(ProviderError::invalid(
            "browser download body carries an invalid base64 padding shape",
        ));
    }
    let body_end = bytes.len() - padding;
    if bytes[..body_end].contains(&b'=') {
        return Err(ProviderError::invalid(
            "browser download body carries padding outside the base64 tail",
        ));
    }
    let decoded_len = (bytes.len() / 4) * 3 - padding;
    if decoded_len as u64 > MAX_DOWNLOAD_BYTES {
        return Err(ProviderError::new(
            FailureCode::OutputLimit,
            format!("decoded browser download exceeds the maximum of {MAX_DOWNLOAD_BYTES} bytes"),
        ));
    }
    let value = |byte: u8| -> Result<u32, ProviderError> {
        match byte {
            b'A'..=b'Z' => Ok(u32::from(byte - b'A')),
            b'a'..=b'z' => Ok(u32::from(byte - b'a') + 26),
            b'0'..=b'9' => Ok(u32::from(byte - b'0') + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(ProviderError::invalid(
                "browser download body contains characters outside the base64 alphabet",
            )),
        }
    };
    let mut out = Vec::with_capacity(decoded_len);
    for group in bytes[..body_end].chunks(4) {
        let mut accum = 0u32;
        for byte in group {
            accum = (accum << 6) | value(*byte)?;
        }
        let octets = match group.len() {
            4 => 3,
            3 => 2,
            2 => 1,
            _ => {
                return Err(ProviderError::invalid(
                    "browser download body carries a truncated base64 group",
                ))
            }
        };
        let padded = accum << ((4 - group.len()) * 6);
        for index in 0..octets {
            out.push(((padded >> (16 - 8 * index)) & 0xff) as u8);
        }
        if out.len() > decoded_len {
            return Err(ProviderError::invalid(
                "browser download body base64 shape does not match its declared length",
            ));
        }
    }
    if out.len() != decoded_len {
        return Err(ProviderError::invalid(
            "browser download body base64 shape does not match its declared length",
        ));
    }

    Ok(out)
}

/// State of a download source identity. Pending sources may be consumed once;
/// consumed sources never authorize a second download.
pub const DOWNLOAD_SOURCE_PENDING: &str = "pending";
/// Consumed source state. A consumed source is permanently spent.
pub const DOWNLOAD_SOURCE_CONSUMED: &str = "consumed";

/// Server-side record of one authorized download source. Records are created
/// only by [`DownloadStore`]; callers hold identities, never these records.
/// Cookies, Authorization headers, credentials, tokens, session material, and
/// personal browser state never enter this record, and the raw source URL is
/// never persisted: only the source origin and a source URL digest are bound.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoredDownload {
    pub schema: String,
    pub source_id: String,
    pub workspace_id: String,
    pub policy_revision: String,
    pub profile_identity: String,
    pub page_id: String,
    pub origin: String,
    pub page_generation: u64,
    pub document_generation: u64,
    pub source_origin: String,
    pub source_url_digest: String,
    pub canonical_relative_destination: String,
    pub declared_filename: String,
    pub declared_media_type: String,
    pub declared_size_bytes: u64,
    pub download_policy_revision: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub state: String,
    pub download_id: String,
    /// Content digest recorded when the download was consumed. Absent on
    /// records written before SG-000026; such records are never eligible as
    /// an upload source because their bytes cannot be re-verified.
    #[serde(default)]
    pub content_sha256: String,
}

/// File-backed download registry stored under Orcel protected local state.
/// Download dispatch resolves caller-supplied source identities through this
/// registry; identities absent here fail closed as stale handles.
#[derive(Debug)]
pub struct DownloadStore {
    path: PathBuf,
    downloads: std::collections::BTreeMap<String, StoredDownload>,
}

impl DownloadStore {
    pub fn load_or_create(path: PathBuf) -> Self {
        let mut store = Self {
            path,
            downloads: std::collections::BTreeMap::new(),
        };
        if store.path.is_file() {
            if let Ok(text) = std::fs::read_to_string(&store.path) {
                for line in text.lines() {
                    if line.trim().is_empty() {
                        continue;
                    }
                    if let Ok(record) = serde_json::from_str::<StoredDownload>(line) {
                        if record.schema != DOWNLOAD_REGISTRY_SCHEMA || record.source_id.is_empty()
                        {
                            break;
                        }
                        store.downloads.insert(record.source_id.clone(), record);
                    }
                }
            }
        } else if let Some(parent) = store.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        store
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn get(&self, source_id: &str) -> Option<&StoredDownload> {
        self.downloads.get(source_id)
    }

    /// Count unconsumed download sources for one workspace so pending hold on
    /// protected state stays bounded.
    pub fn pending_count(&self, workspace_id: &str) -> usize {
        self.downloads
            .values()
            .filter(|record| {
                record.workspace_id == workspace_id && record.state == DOWNLOAD_SOURCE_PENDING
            })
            .count()
    }

    /// Persist a freshly authorized download source as a server-side record.
    /// Records are append-only; the latest record for a source identity wins.
    pub fn record_pending(&mut self, record: StoredDownload) {
        self.persist(&record);
        self.downloads.insert(record.source_id.clone(), record);
    }

    /// Mark one source identity consumed so it never authorizes a second
    /// download. Unknown identities fail closed.
    pub fn mark_consumed(
        &mut self,
        source_id: &str,
        download_id: &str,
    ) -> Result<(), ProviderError> {
        self.mark_consumed_with_digest(source_id, download_id, "")
    }

    /// Mark one source identity consumed and record the verified content digest
    /// so a later consumer can re-verify the exact bytes on disk. Unknown
    /// identities fail closed.
    pub fn mark_consumed_with_digest(
        &mut self,
        source_id: &str,
        download_id: &str,
        content_sha256: &str,
    ) -> Result<(), ProviderError> {
        let mut record = self.downloads.get(source_id).cloned().ok_or_else(|| {
            ProviderError::new(
                FailureCode::TargetStale,
                "browser download source handle is unknown; stale download sources fail closed",
            )
        })?;
        record.state = DOWNLOAD_SOURCE_CONSUMED.to_owned();
        record.download_id = download_id.to_owned();
        record.content_sha256 = content_sha256.to_owned();
        self.persist(&record);
        self.downloads.insert(record.source_id.clone(), record);
        Ok(())
    }

    fn persist(&self, record: &StoredDownload) {
        use std::io::Write as _;
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            let _ = serde_json::to_writer(&mut file, record);
            let _ = file.write_all(b"\n");
            let _ = file.flush();
        }
    }
}

/// Canonical path for the download registry file. Tests override it with
/// `ORCEL_BROWSER_STATE_DIR`; production keeps it inside the isolated profile
/// directory under Orcel protected local state.
pub fn default_download_registry_path(profile_root: &Path) -> PathBuf {
    profile_root.join(DOWNLOAD_REGISTRY_FILE)
}

/// Compute the server-allocated one-shot download source identity. The digest
/// binds workspace, policy revision, profile identity, page identity, origin,
/// page and document generation, source origin, source URL digest, canonical
/// relative destination, declared media type and size, download policy
/// revision, and issue time under `ORCEL_BROWSER_DOWNLOAD_SOURCE_V1`.
/// True when `candidate` is exactly a `ORCEL_BROWSER_DOWNLOAD_SOURCE_V1`
/// identity: the `dl-` prefix followed by 64 lowercase hex characters. A
/// prefix-only check would let a caller-typed path fragment reach the registry
/// lookup, so callers that accept a download source identity must use this
/// instead.
pub fn is_well_formed_download_source_id(candidate: &str) -> bool {
    let Some(digest) = candidate.strip_prefix(DOWNLOAD_SOURCE_PREFIX) else {
        return false;
    };
    digest.len() == DOWNLOAD_SOURCE_DIGEST_HEX
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// True when `candidate` is exactly a `ORCEL_BROWSER_UPLOAD_SOURCE_V1`
/// identity: the `ul-` prefix followed by 64 lowercase hex characters. Submit
/// accepts a source identity, so a caller-typed path fragment must never reach
/// the upload registry.
pub fn is_well_formed_upload_source_id(candidate: &str) -> bool {
    let Some(digest) = candidate.strip_prefix(UPLOAD_SOURCE_PREFIX) else {
        return false;
    };
    digest.len() == UPLOAD_SOURCE_DIGEST_HEX
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[allow(clippy::too_many_arguments)]
pub fn download_source_id_for(
    workspace_id: &str,
    policy_revision: &str,
    profile_identity: &str,
    page_id: &str,
    origin: &str,
    page_generation: u64,
    document_generation: u64,
    source_origin: &str,
    source_url_digest: &str,
    canonical_relative_destination: &str,
    declared_media_type: &str,
    declared_size_bytes: u64,
    download_policy_revision: &str,
    issued_at_ms: u64,
) -> String {
    let mut hasher = Sha256::new();
    digest_bytes(&mut hasher, b"ORCEL_BROWSER_DOWNLOAD_SOURCE_V1");
    digest_bytes(&mut hasher, workspace_id.as_bytes());
    digest_bytes(&mut hasher, policy_revision.as_bytes());
    digest_bytes(&mut hasher, profile_identity.as_bytes());
    digest_bytes(&mut hasher, page_id.as_bytes());
    digest_bytes(&mut hasher, origin.as_bytes());
    digest_bytes(&mut hasher, page_generation.to_string().as_bytes());
    digest_bytes(&mut hasher, document_generation.to_string().as_bytes());
    digest_bytes(&mut hasher, source_origin.as_bytes());
    digest_bytes(&mut hasher, source_url_digest.as_bytes());
    digest_bytes(&mut hasher, canonical_relative_destination.as_bytes());
    digest_bytes(&mut hasher, declared_media_type.as_bytes());
    digest_bytes(&mut hasher, declared_size_bytes.to_string().as_bytes());
    digest_bytes(&mut hasher, download_policy_revision.as_bytes());
    digest_bytes(&mut hasher, issued_at_ms.to_string().as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(32);
    use std::fmt::Write as _;
    for byte in digest.iter().take(16) {
        let _ = write!(&mut hex, "{byte:02x}");
    }
    format!("{DOWNLOAD_SOURCE_PREFIX}{hex}")
}

/// Compute the SOFT approval digest for one download. The digest binds
/// workspace, policy revision, profile identity, page identity, origin, page
/// and document generation, source identity, source origin, canonical relative
/// destination, declared media type and size, the actual content digest, and
/// the download policy revision under `ORCEL_BROWSER_DOWNLOAD_V1`. Preview
/// passes an empty content digest; download passes the real one, so any
/// material drift including payload substitution invalidates the approval.
#[allow(clippy::too_many_arguments)]
pub fn download_approval_digest(
    workspace_id: &str,
    policy_revision: &str,
    profile_identity: &str,
    page_id: &str,
    origin: &str,
    page_generation: u64,
    document_generation: u64,
    source_id: &str,
    source_origin: &str,
    canonical_relative_destination: &str,
    declared_media_type: &str,
    declared_size_bytes: u64,
    content_sha256: &str,
    download_policy_revision: &str,
) -> String {
    let mut hasher = Sha256::new();
    digest_bytes(&mut hasher, b"ORCEL_BROWSER_DOWNLOAD_V1");
    digest_bytes(&mut hasher, workspace_id.as_bytes());
    digest_bytes(&mut hasher, policy_revision.as_bytes());
    digest_bytes(&mut hasher, profile_identity.as_bytes());
    digest_bytes(&mut hasher, page_id.as_bytes());
    digest_bytes(&mut hasher, origin.as_bytes());
    digest_bytes(&mut hasher, page_generation.to_string().as_bytes());
    digest_bytes(&mut hasher, document_generation.to_string().as_bytes());
    digest_bytes(&mut hasher, source_id.as_bytes());
    digest_bytes(&mut hasher, source_origin.as_bytes());
    digest_bytes(&mut hasher, canonical_relative_destination.as_bytes());
    digest_bytes(&mut hasher, declared_media_type.as_bytes());
    digest_bytes(&mut hasher, declared_size_bytes.to_string().as_bytes());
    digest_bytes(&mut hasher, content_sha256.as_bytes());
    digest_bytes(&mut hasher, download_policy_revision.as_bytes());
    let digest = hasher.finalize();
    let mut output = String::with_capacity(digest.len() * 2);
    use std::fmt::Write as _;
    for byte in digest {
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

/// Compute the download identity recorded in evidence. The digest binds the
/// source identity, the canonical relative destination, and the content
/// digest under `ORCEL_BROWSER_DOWNLOAD_ID_V1`.
pub fn download_id_for(
    source_id: &str,
    canonical_relative_destination: &str,
    content_sha256: &str,
) -> String {
    let mut hasher = Sha256::new();
    digest_bytes(&mut hasher, b"ORCEL_BROWSER_DOWNLOAD_ID_V1");
    digest_bytes(&mut hasher, source_id.as_bytes());
    digest_bytes(&mut hasher, canonical_relative_destination.as_bytes());
    digest_bytes(&mut hasher, content_sha256.as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(32);
    use std::fmt::Write as _;
    for byte in digest.iter().take(16) {
        let _ = write!(&mut hex, "{byte:02x}");
    }
    format!("{DOWNLOAD_ID_PREFIX}{hex}")
}

/// Digest the approved destination root so evidence carries a stable root
/// identity without depending on caller-supplied path text.
pub fn download_root_identity(root: &Path) -> String {
    sha256_hex(path_key(root).as_bytes())
}

/// Verify a server-side download source record against the current page,
/// profile, policy revision, download policy revision, and time. Stale
/// generations, replaced documents, origin drift, foreign profiles, foreign
/// pages, forged identities, policy drift, consumed sources, and expired
/// sources all fail closed.
#[allow(clippy::too_many_arguments)]
pub fn check_download_source(
    record: &StoredDownload,
    page: &PageRecord,
    profile_identity: &str,
    policy_revision: &str,
    expected_generation: u64,
    expected_document_generation: u64,
    now_ms: u64,
) -> Result<(), ProviderError> {
    if record.page_id != page.page_id {
        return Err(ProviderError::new(
        FailureCode::TargetStale,
        "browser download source belongs to a different page; stale download sources fail closed",
    ));
    }
    if page.state == PageState::Closed {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser page is closed; stale download sources fail closed",
        ));
    }
    if record.workspace_id != page.workspace_id {
        return Err(ProviderError::new(
        FailureCode::WorkspaceDenied,
        "browser download source belongs to a different workspace; foreign download sources fail closed",
    ));
    }
    if record.profile_identity != profile_identity {
        return Err(ProviderError::denied(
        "browser download source belongs to a different isolated profile; foreign download sources fail closed",
    ));
    }
    if record.page_generation != expected_generation || page.generation != expected_generation {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser page generation changed since preview; stale download sources fail closed",
        ));
    }
    if record.document_generation != expected_document_generation
        || page.generation != expected_document_generation
    {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser document was replaced since preview; stale download sources fail closed",
        ));
    }
    if record.origin != page.current_origin {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser page origin changed since preview; stale download sources fail closed",
        ));
    }
    if record.policy_revision != policy_revision || page.policy_revision != policy_revision {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser policy revision drifted since preview; stale download sources fail closed",
        ));
    }
    if record.download_policy_revision != DOWNLOAD_POLICY_REVISION {
        return Err(ProviderError::new(
        FailureCode::TargetStale,
        "browser download policy revision drifted since preview; stale download sources fail closed",
    ));
    }
    let expected = download_source_id_for(
        &record.workspace_id,
        &record.policy_revision,
        &record.profile_identity,
        &record.page_id,
        &record.origin,
        record.page_generation,
        record.document_generation,
        &record.source_origin,
        &record.source_url_digest,
        &record.canonical_relative_destination,
        &record.declared_media_type,
        record.declared_size_bytes,
        &record.download_policy_revision,
        record.issued_at_ms,
    );
    if expected != record.source_id {
        return Err(ProviderError::new(
        FailureCode::TargetStale,
        "browser download source identity does not match the current profile, page, generation, origin, destination, and policy revision; stale download sources fail closed",
    ));
    }
    if record.source_origin != page.current_origin {
        return Err(ProviderError::denied(
        "browser download source origin is not the authorized current page origin; unauthorized download origins are denied",
    ));
    }
    if record.state == DOWNLOAD_SOURCE_CONSUMED {
        return Err(ProviderError::denied(
        "browser download source was already consumed; downloads are one-shot and replay is denied",
    ));
    }
    if record.state != DOWNLOAD_SOURCE_PENDING {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser download source is not in a pending state; stale download sources fail closed",
        ));
    }
    if now_ms > record.expires_at_ms {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser download source expired before use; stale download sources fail closed",
        ));
    }
    Ok(())
}

/// Typed bounded download preview material. Preview performs full page, origin,
/// generation, destination, and type-policy evaluation without mutating page
/// state and without requiring approval. The caller uses the preview to build
/// one download request with exact expected state plus the server-allocated
/// source identity. Cookies, credentials, tokens, session material, and raw
/// source URL text never enter this packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadPreview {
    pub source_id: String,
    pub page_id: String,
    pub workspace_id: String,
    pub policy_revision: String,
    pub profile_identity: String,
    pub origin: String,
    pub page_generation: u64,
    pub document_generation: u64,
    pub source_origin: String,
    pub source_url_digest: String,
    pub pinned_address: IpAddr,
    pub redirect_count: usize,
    pub declared_filename: String,
    pub declared_media_type: String,
    pub canonical_relative_destination: String,
    pub destination_root_identity: String,
    pub declared_size_bytes: u64,
    pub max_download_bytes: u64,
    pub download_policy_revision: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub preview_digest: String,
}

impl DownloadPreview {
    pub fn to_json(&self) -> Value {
        json!({
            "source_id": self.source_id,
            "page_id": self.page_id,
            "workspace_id": self.workspace_id,
            "policy_revision": self.policy_revision,
            "profile_identity": self.profile_identity,
            "origin": self.origin,
            "page_generation": self.page_generation,
            "document_generation": self.document_generation,
            "source_origin": self.source_origin,
            "source_url_digest": self.source_url_digest,
            "pinned_address": self.pinned_address.to_string(),
            "redirect_count": self.redirect_count,
            "declared_filename": self.declared_filename,
            "declared_media_type": self.declared_media_type,
            "canonical_relative_destination": self.canonical_relative_destination,
            "destination_root_identity": self.destination_root_identity,
            "declared_size_bytes": self.declared_size_bytes,
            "max_download_bytes": self.max_download_bytes,
            "download_policy_revision": self.download_policy_revision,
            "issued_at_ms": self.issued_at_ms,
            "expires_at_ms": self.expires_at_ms,
            "preview_digest": self.preview_digest,
            "executed": false,
            "opened": false,
            "extracted": false,
            "cookies": false,
            "credentials": false,
        })
    }
}

/// Typed bounded download evidence. Contains only identity, binding, origin
/// metadata, bounds, and digest material plus the approval linkage. Cookies,
/// Authorization headers, credentials, tokens, session material, personal
/// browser state, and raw source URL text never enter this packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadEvidence {
    pub download_id: String,
    pub source_id: String,
    pub page_id: String,
    pub workspace_id: String,
    pub policy_revision: String,
    pub profile_identity: String,
    pub origin: String,
    pub page_generation: u64,
    pub document_generation: u64,
    pub source_origin: String,
    pub source_url_digest: String,
    pub canonical_relative_destination: String,
    pub destination_root_identity: String,
    pub declared_filename: String,
    pub declared_media_type: String,
    pub extension_media_type: String,
    pub sniffed_media_type: String,
    pub content_type_consistent: bool,
    pub declared_size_bytes: u64,
    pub actual_size_bytes: u64,
    pub content_sha256: String,
    pub download_policy_revision: String,
    pub state: String,
}

impl DownloadEvidence {
    pub fn to_json(&self, approval_record_id: &str) -> Value {
        json!({
            "download_id": self.download_id,
            "source_id": self.source_id,
            "page_id": self.page_id,
            "workspace_id": self.workspace_id,
            "policy_revision": self.policy_revision,
            "profile_identity": self.profile_identity,
            "origin": self.origin,
            "page_generation": self.page_generation,
            "document_generation": self.document_generation,
            "source_origin": self.source_origin,
            "source_url_digest": self.source_url_digest,
            "canonical_relative_destination": self.canonical_relative_destination,
            "destination_root_identity": self.destination_root_identity,
            "declared_filename": self.declared_filename,
            "declared_media_type": self.declared_media_type,
            "extension_media_type": self.extension_media_type,
            "sniffed_media_type": self.sniffed_media_type,
            "content_type_consistent": self.content_type_consistent,
            "declared_size_bytes": self.declared_size_bytes,
            "actual_size_bytes": self.actual_size_bytes,
            "content_sha256": self.content_sha256,
            "download_policy_revision": self.download_policy_revision,
            "state": self.state,
            "approval_record_id": approval_record_id,
            "executed": false,
            "opened": false,
            "extracted": false,
            "cookies": false,
            "credentials": false,
        })
    }
}

fn real_path(path: &Path) -> Result<PathBuf, ProviderError> {
    std::fs::canonicalize(path)
        .map_err(|error| ProviderError::io("resolve canonical download path", error))
}

fn path_key(path: &Path) -> String {
    let text = path.to_string_lossy().replace('/', "\\");
    let trimmed = text.trim_end_matches('\\');
    if cfg!(windows) {
        trimmed.to_lowercase()
    } else {
        trimmed.to_owned()
    }
}

/// Canonical containment test. Both sides are canonicalized through real
/// filesystem identity first, so reparse points, junctions, and symlinks are
/// already resolved when the comparison runs. Naive string prefix comparison
/// is never trusted on its own: the separator boundary is part of the key.
pub fn path_is_within(root: &Path, candidate: &Path) -> bool {
    let root_key = path_key(root);
    let candidate_key = path_key(candidate);
    candidate_key == root_key || candidate_key.starts_with(&(root_key + "\\"))
}

/// Resolve the approved download root from the policy-provided workspace root.
/// The root is always the workspace root; the caller can never widen it.
pub fn resolve_download_root(workspace_root: &Path) -> Result<PathBuf, ProviderError> {
    let root = real_path(workspace_root)?;
    if !root.is_dir() {
        return Err(ProviderError::invalid(
            "approved workspace download root is not a directory",
        ));
    }
    Ok(root)
}

/// Resolve one canonical relative destination under the approved root and
/// fail closed unless the resolved existing parent directory is genuinely
/// inside that root. Directories are never created by a download.
pub fn resolve_download_destination(
    root: &Path,
    canonical_relative: &str,
) -> Result<PathBuf, ProviderError> {
    let destination = root.join(canonical_relative.replace('/', std::path::MAIN_SEPARATOR_STR));
    let parent = destination.parent().ok_or_else(|| {
        ProviderError::invalid("browser download destination has no parent directory")
    })?;
    if !parent.is_dir() {
        return Err(ProviderError::denied(
        "browser download destination parent directory does not exist; downloads never create directories",
    ));
    }
    let parent_real = real_path(parent)?;
    if !path_is_within(root, &parent_real) {
        return Err(ProviderError::new(
        FailureCode::PathEscape,
        "browser download destination escapes the approved workspace root through a reparse point; destinations outside the approved root are denied",
    ));
    }
    Ok(destination)
}

/// Create exactly one new file at the resolved destination and write the
/// bounded payload. Existing files are never overwritten. After the write the
/// file's real path, byte length, and SHA-256 digest are all re-verified, and
/// a mismatching write is reverted.
pub fn write_download_file(
    root: &Path,
    destination: &Path,
    bytes: &[u8],
) -> Result<(), ProviderError> {
    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| {
            match error.kind() {
        std::io::ErrorKind::AlreadyExists => ProviderError::new(
            FailureCode::PostconditionFailed,
            "browser download destination already exists; downloads never overwrite existing files",
        ),
        _ => ProviderError::io("create browser download destination", error),
    }
        })?;
    file.write_all(bytes)
        .map_err(|error| ProviderError::io("write browser download destination", error))?;
    file.flush()
        .map_err(|error| ProviderError::io("flush browser download destination", error))?;
    drop(file);

    let file_real = real_path(destination)?;
    if !path_is_within(root, &file_real) {
        let _ = std::fs::remove_file(destination);
        return Err(ProviderError::new(
        FailureCode::PathEscape,
        "written download file resolves outside the approved workspace root; the write was reverted and the download is denied",
    ));
    }
    let written = std::fs::read(destination)
        .map_err(|error| ProviderError::io("read back browser download", error))?;
    if written.len() != bytes.len() || sha256_hex(&written) != sha256_hex(bytes) {
        let _ = std::fs::remove_file(destination);
        return Err(ProviderError::new(
            FailureCode::PostconditionFailed,
            "written download does not match the approved payload; the download failed closed",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SG-000026 scoped bounded browser uploads. The only admissible upload source
// is a file already recorded by the SG-000025 download registry inside the
// approved workspace download root, re-verified against that record for
// canonical identity, byte length, and SHA-256. Upload therefore cannot become
// generic filesystem read: credential files, browser profile files, OS secret
// stores, user home files, workspace-authored files, unrelated project files,
// and directories are unreachable by construction. No browser is launched or
// attached, no page byte transfer or form submission is performed, and no
// uploaded or downloaded content is executed, opened, extracted, or launched.
// ---------------------------------------------------------------------------

/// Prefix for server-allocated one-shot upload source identities.
pub const UPLOAD_SOURCE_PREFIX: &str = "ul-";
/// Number of lowercase hex characters in an upload source identity digest. The
/// upload source identity is the leading 128 bits of the
/// `ORCEL_BROWSER_UPLOAD_SOURCE_V1` digest, matching the other browser
/// identities, and is well beyond any realistic collision for a one-shot
/// per-page, per-node, per-artifact source.
pub const UPLOAD_SOURCE_DIGEST_HEX: usize = 32;
/// Prefix for upload identities recorded in upload evidence.
pub const UPLOAD_ID_PREFIX: &str = "up-";
/// Revision of the upload source and target policy itself.
pub const UPLOAD_POLICY_REVISION: &str = "sg-000026-upload-v1";
/// Schema for the upload registry file stored under Orcel protected state.
pub const UPLOAD_REGISTRY_SCHEMA: &str = "orcel-browser-uploads-v1";
/// File name for the upload registry inside the isolated profile directory.
pub const UPLOAD_REGISTRY_FILE: &str = "uploads.jsonl";
/// Hard bound on the bytes one upload may carry.
pub const MAX_UPLOAD_BYTES: u64 = 8 * 1024 * 1024;
/// Bound on simultaneously pending upload sources per workspace.
pub const MAX_PENDING_UPLOADS_PER_WORKSPACE: usize = 8;
/// Deterministic lifetime of an upload source identity in milliseconds.
pub const UPLOAD_SOURCE_TTL_MS: u64 = 120_000;
/// Node role that may receive an upload.
pub const UPLOAD_NODE_ROLE: &str = "textbox";
/// Node input type that may receive an upload.
pub const UPLOAD_INPUT_TYPE: &str = "file";
/// State of an upload source identity.
pub const UPLOAD_SOURCE_PENDING: &str = "pending";
/// Consumed upload source state. A consumed source never authorizes a second
/// upload.
pub const UPLOAD_SOURCE_CONSUMED: &str = "consumed";

/// Server-side record of one authorized upload source. Records are created
/// only by [`UploadStore`]; callers hold identities, never these records. The
/// record never carries file content or file bytes, and the only admissible
/// source it names is a previously recorded approved download artifact.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoredUpload {
    pub schema: String,
    pub source_id: String,
    pub workspace_id: String,
    pub policy_revision: String,
    pub profile_identity: String,
    pub page_id: String,
    pub origin: String,
    pub page_generation: u64,
    pub document_generation: u64,
    pub node_id: String,
    pub node_role: String,
    pub node_input_type: String,
    pub node_state: String,
    pub trust_revision: u64,
    pub artifact_source_id: String,
    pub artifact_download_id: String,
    pub artifact_relative_destination: String,
    pub artifact_media_type: String,
    pub artifact_sha256: String,
    pub artifact_size_bytes: u64,
    pub upload_policy_revision: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub state: String,
    pub upload_id: String,
}

/// File-backed upload registry stored under Orcel protected local state.
/// Upload dispatch resolves caller-supplied source identities through this
/// registry; identities absent here fail closed as stale handles.
#[derive(Debug)]
pub struct UploadStore {
    path: PathBuf,
    uploads: std::collections::BTreeMap<String, StoredUpload>,
}

impl UploadStore {
    pub fn load_or_create(path: PathBuf) -> Self {
        let mut store = Self {
            path,
            uploads: std::collections::BTreeMap::new(),
        };
        if store.path.is_file() {
            if let Ok(text) = std::fs::read_to_string(&store.path) {
                for line in text.lines() {
                    if line.trim().is_empty() {
                        continue;
                    }
                    if let Ok(record) = serde_json::from_str::<StoredUpload>(line) {
                        if record.schema != UPLOAD_REGISTRY_SCHEMA || record.source_id.is_empty() {
                            break;
                        }
                        store.uploads.insert(record.source_id.clone(), record);
                    }
                }
            }
        } else if let Some(parent) = store.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        store
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn get(&self, source_id: &str) -> Option<&StoredUpload> {
        self.uploads.get(source_id)
    }

    /// Count unconsumed upload sources for one workspace so pending holds on
    /// protected state stay bounded.
    pub fn pending_count(&self, workspace_id: &str) -> usize {
        self.uploads
            .values()
            .filter(|record| {
                record.workspace_id == workspace_id && record.state == UPLOAD_SOURCE_PENDING
            })
            .count()
    }

    /// Persist a freshly authorized upload source as a server-side record.
    pub fn record_pending(&mut self, record: StoredUpload) {
        self.persist(&record);
        self.uploads.insert(record.source_id.clone(), record);
    }

    /// Mark one upload source identity consumed so it never authorizes a
    /// second upload. Unknown identities fail closed.
    pub fn mark_consumed(&mut self, source_id: &str, upload_id: &str) -> Result<(), ProviderError> {
        let mut record = self.uploads.get(source_id).cloned().ok_or_else(|| {
            ProviderError::new(
                FailureCode::TargetStale,
                "browser upload source handle is unknown; stale upload sources fail closed",
            )
        })?;
        record.state = UPLOAD_SOURCE_CONSUMED.to_owned();
        record.upload_id = upload_id.to_owned();
        self.persist(&record);
        self.uploads.insert(record.source_id.clone(), record);
        Ok(())
    }

    fn persist(&self, record: &StoredUpload) {
        use std::io::Write as _;
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            let _ = serde_json::to_writer(&mut file, record);
            let _ = file.write_all(b"\n");
            let _ = file.flush();
        }
    }
}

/// Canonical path for the upload registry file. Production keeps it inside the
/// isolated profile directory under Orcel protected local state.
pub fn default_upload_registry_path(profile_root: &Path) -> PathBuf {
    profile_root.join(UPLOAD_REGISTRY_FILE)
}

/// A verified upload artifact: the bounded, digest-confirmed facts about the
/// one admissible source file. It never carries file content or file bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedUploadArtifact {
    pub relative_destination: String,
    pub download_id: String,
    pub media_type: String,
    pub sha256: String,
    pub size_bytes: u64,
}

/// Compute the server-allocated one-shot upload source identity under
/// `ORCEL_BROWSER_UPLOAD_SOURCE_V1`.
#[allow(clippy::too_many_arguments)]
pub fn upload_source_id_for(
    workspace_id: &str,
    policy_revision: &str,
    profile_identity: &str,
    page_id: &str,
    origin: &str,
    page_generation: u64,
    document_generation: u64,
    node_id: &str,
    node_role: &str,
    node_input_type: &str,
    node_state: &str,
    trust_revision: u64,
    artifact_source_id: &str,
    artifact_relative_destination: &str,
    artifact_media_type: &str,
    artifact_sha256: &str,
    artifact_size_bytes: u64,
    upload_policy_revision: &str,
    issued_at_ms: u64,
) -> String {
    let mut hasher = Sha256::new();
    digest_bytes(&mut hasher, b"ORCEL_BROWSER_UPLOAD_SOURCE_V1");
    digest_bytes(&mut hasher, workspace_id.as_bytes());
    digest_bytes(&mut hasher, policy_revision.as_bytes());
    digest_bytes(&mut hasher, profile_identity.as_bytes());
    digest_bytes(&mut hasher, page_id.as_bytes());
    digest_bytes(&mut hasher, origin.as_bytes());
    digest_bytes(&mut hasher, page_generation.to_string().as_bytes());
    digest_bytes(&mut hasher, document_generation.to_string().as_bytes());
    digest_bytes(&mut hasher, node_id.as_bytes());
    digest_bytes(&mut hasher, node_role.as_bytes());
    digest_bytes(&mut hasher, node_input_type.as_bytes());
    digest_bytes(&mut hasher, node_state.as_bytes());
    digest_bytes(&mut hasher, trust_revision.to_string().as_bytes());
    digest_bytes(&mut hasher, artifact_source_id.as_bytes());
    digest_bytes(&mut hasher, artifact_relative_destination.as_bytes());
    digest_bytes(&mut hasher, artifact_media_type.as_bytes());
    digest_bytes(&mut hasher, artifact_sha256.as_bytes());
    digest_bytes(&mut hasher, artifact_size_bytes.to_string().as_bytes());
    digest_bytes(&mut hasher, upload_policy_revision.as_bytes());
    digest_bytes(&mut hasher, issued_at_ms.to_string().as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(32);
    use std::fmt::Write as _;
    for byte in digest.iter().take(16) {
        let _ = write!(&mut hex, "{byte:02x}");
    }
    format!("{UPLOAD_SOURCE_PREFIX}{hex}")
}

/// Compute the SOFT approval digest for one upload under
/// `ORCEL_BROWSER_UPLOAD_V1`, binding the complete binding set including the
/// actual source content digest.
#[allow(clippy::too_many_arguments)]
pub fn upload_approval_digest(
    workspace_id: &str,
    policy_revision: &str,
    profile_identity: &str,
    page_id: &str,
    origin: &str,
    page_generation: u64,
    document_generation: u64,
    node_id: &str,
    node_role: &str,
    node_input_type: &str,
    node_state: &str,
    trust_revision: u64,
    source_id: &str,
    artifact_relative_destination: &str,
    artifact_media_type: &str,
    artifact_sha256: &str,
    artifact_size_bytes: u64,
) -> String {
    let mut hasher = Sha256::new();
    digest_bytes(&mut hasher, b"ORCEL_BROWSER_UPLOAD_V1");
    digest_bytes(&mut hasher, workspace_id.as_bytes());
    digest_bytes(&mut hasher, policy_revision.as_bytes());
    digest_bytes(&mut hasher, profile_identity.as_bytes());
    digest_bytes(&mut hasher, page_id.as_bytes());
    digest_bytes(&mut hasher, origin.as_bytes());
    digest_bytes(&mut hasher, page_generation.to_string().as_bytes());
    digest_bytes(&mut hasher, document_generation.to_string().as_bytes());
    digest_bytes(&mut hasher, node_id.as_bytes());
    digest_bytes(&mut hasher, node_role.as_bytes());
    digest_bytes(&mut hasher, node_input_type.as_bytes());
    digest_bytes(&mut hasher, node_state.as_bytes());
    digest_bytes(&mut hasher, trust_revision.to_string().as_bytes());
    digest_bytes(&mut hasher, source_id.as_bytes());
    digest_bytes(&mut hasher, artifact_relative_destination.as_bytes());
    digest_bytes(&mut hasher, artifact_media_type.as_bytes());
    digest_bytes(&mut hasher, artifact_sha256.as_bytes());
    digest_bytes(&mut hasher, artifact_size_bytes.to_string().as_bytes());
    let digest = hasher.finalize();
    let mut output = String::with_capacity(digest.len() * 2);
    use std::fmt::Write as _;
    for byte in digest {
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

/// Compute the upload identity recorded in evidence under
/// `ORCEL_BROWSER_UPLOAD_ID_V1`.
pub fn upload_id_for(source_id: &str, node_id: &str, artifact_sha256: &str) -> String {
    let mut hasher = Sha256::new();
    digest_bytes(&mut hasher, b"ORCEL_BROWSER_UPLOAD_ID_V1");
    digest_bytes(&mut hasher, source_id.as_bytes());
    digest_bytes(&mut hasher, node_id.as_bytes());
    digest_bytes(&mut hasher, artifact_sha256.as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(32);
    use std::fmt::Write as _;
    for byte in digest.iter().take(16) {
        let _ = write!(&mut hex, "{byte:02x}");
    }
    format!("{UPLOAD_ID_PREFIX}{hex}")
}

/// Verify a server-side node record for an upload target. Only an enabled
/// node whose observed role is `textbox` and whose observed input type is
/// `file` may receive an upload. Stale generations, replaced documents, origin
/// drift, foreign pages, forged identities, policy drift, wrong role, wrong
/// input type, disabled state, and password targets all fail closed.
#[allow(clippy::too_many_arguments)]
pub fn check_node_for_upload(
    node: &StoredNode,
    page: &PageRecord,
    expected_role: &str,
    expected_input_type: &str,
    expected_state: &str,
    profile_identity: &str,
    policy_revision: &str,
    expected_generation: u64,
    expected_document_generation: u64,
) -> Result<(), ProviderError> {
    if node.page_id != page.page_id {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser upload node belongs to a different page; stale node handles fail closed",
        ));
    }
    if node.page_generation != expected_generation || page.generation != expected_generation {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser upload node generation changed since observation; stale node handles fail closed",
        ));
    }
    if node.document_generation != expected_document_generation
        || page.generation != expected_document_generation
    {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser document was replaced since observation; stale node handles fail closed",
        ));
    }
    if node.origin != page.current_origin {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser upload node origin changed since observation; stale node handles fail closed",
        ));
    }
    if node.policy_revision != policy_revision {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser upload node policy revision drifted; stale node handles fail closed",
        ));
    }
    let expected = node_id_for(
        profile_identity,
        &node.page_id,
        node.page_generation,
        &node.origin,
        node.document_generation,
        node.index,
        policy_revision,
    );
    if expected != node.node_id {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser upload node identity does not match the current profile, page, generation, origin, and policy revision; stale node handles fail closed",
        ));
    }
    if node.role != UPLOAD_NODE_ROLE || expected_role != node.role {
        return Err(ProviderError::denied(
            "browser upload target must be an observed textbox node; every other role is denied",
        ));
    }
    if !node.input_type.eq_ignore_ascii_case(UPLOAD_INPUT_TYPE)
        || expected_input_type != node.input_type
    {
        return Err(ProviderError::denied(
            "browser upload target must be an observed file input; every other input type is denied",
        ));
    }
    if node.state != ENABLED_NODE_STATE {
        return Err(ProviderError::denied(
            "browser upload target is not enabled; uploads to disabled nodes are denied",
        ));
    }
    if expected_state != node.state {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser upload node state changed since observation; stale node handles fail closed",
        ));
    }
    if is_password_target(&node.role, &node.input_type) {
        return Err(ProviderError::denied(
            "browser upload to a password target is denied; credential submission remains absent",
        ));
    }
    Ok(())
}

/// Verify the one admissible upload source on disk. The source is resolved
/// from the SG-000025 download registry record, confined to the approved
/// download root by canonical filesystem identity, required to be a regular
/// file rather than a directory, and re-verified for byte length and SHA-256 so
/// a replaced or mutated artifact fails closed. File content is never returned.
pub fn verify_upload_artifact(
    workspace_root: &Path,
    record: &StoredUpload,
    now_ms: u64,
) -> Result<VerifiedUploadArtifact, ProviderError> {
    if record.state == UPLOAD_SOURCE_CONSUMED {
        return Err(ProviderError::denied(
            "browser upload source was already consumed; uploads are one-shot and replay is denied",
        ));
    }
    if record.state != UPLOAD_SOURCE_PENDING {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser upload source is not in a pending state; stale upload sources fail closed",
        ));
    }
    if now_ms > record.expires_at_ms {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser upload source expired before use; stale upload sources fail closed",
        ));
    }
    if !is_allowed_download_media_type(&record.artifact_media_type) {
        return Err(ProviderError::denied(
            "browser upload source media type is not an authorized inert download class",
        ));
    }
    if record.artifact_size_bytes == 0 || record.artifact_size_bytes > MAX_UPLOAD_BYTES {
        return Err(ProviderError::new(
            FailureCode::OutputLimit,
            format!("browser upload source exceeds the maximum of {MAX_UPLOAD_BYTES} bytes"),
        ));
    }
    let root = resolve_download_root(workspace_root)?;
    let destination = resolve_download_destination(&root, &record.artifact_relative_destination)?;
    if !destination.exists() {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser upload source artifact is missing; a removed download fails closed",
        ));
    }
    if destination.is_dir() {
        return Err(ProviderError::denied(
            "browser upload source is a directory; directory and recursive upload are denied",
        ));
    }
    let real = real_path(&destination)?;
    if !path_is_within(&root, &real) {
        return Err(ProviderError::new(
            FailureCode::PathEscape,
            "browser upload source resolves outside the approved download root; a reparse-point redirect is denied",
        ));
    }
    let bytes = std::fs::read(&destination)
        .map_err(|error| ProviderError::io("read upload source", error))?;
    if bytes.len() as u64 != record.artifact_size_bytes {
        return Err(ProviderError::new(
            FailureCode::PostconditionFailed,
            "browser upload source size no longer matches the recorded approved download",
        ));
    }
    if sha256_hex(&bytes) != record.artifact_sha256 {
        return Err(ProviderError::new(
            FailureCode::PostconditionFailed,
            "browser upload source digest no longer matches the recorded approved download",
        ));
    }
    Ok(VerifiedUploadArtifact {
        relative_destination: record.artifact_relative_destination.clone(),
        download_id: record.artifact_download_id.clone(),
        media_type: record.artifact_media_type.clone(),
        sha256: record.artifact_sha256.clone(),
        size_bytes: record.artifact_size_bytes,
    })
}

/// Verify a server-side upload source record against the current page, node,
/// trust state, policy revisions, and time, and then verify the one admissible
/// source artifact on disk. Every material drift fails closed.
#[allow(clippy::too_many_arguments)]
pub fn check_upload_source(
    record: &StoredUpload,
    page: &PageRecord,
    node: &StoredNode,
    profile_identity: &str,
    policy_revision: &str,
    expected_generation: u64,
    expected_document_generation: u64,
    expected_role: &str,
    expected_input_type: &str,
    expected_state: &str,
    trust_revision: u64,
    trust_trusted: bool,
    workspace_root: &Path,
    now_ms: u64,
) -> Result<VerifiedUploadArtifact, ProviderError> {
    if !trust_trusted {
        return Err(ProviderError::new(
            FailureCode::WorkspaceDenied,
            "browser upload requires a trusted workspace; an emergency revoke fails closed",
        ));
    }
    if record.trust_revision != trust_revision {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "workspace trust revision changed since preview; emergency revoke and trust change fail closed",
        ));
    }
    if record.page_id != page.page_id {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser upload source belongs to a different page; stale upload sources fail closed",
        ));
    }
    if page.state == PageState::Closed {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser page is closed; stale upload sources fail closed",
        ));
    }
    if record.workspace_id != page.workspace_id {
        return Err(ProviderError::new(
            FailureCode::WorkspaceDenied,
            "browser upload source belongs to a different workspace; foreign upload sources fail closed",
        ));
    }
    if record.profile_identity != profile_identity {
        return Err(ProviderError::denied(
            "browser upload source belongs to a different isolated profile; foreign upload sources fail closed",
        ));
    }
    if record.origin != page.current_origin {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser page origin changed since preview; stale upload sources fail closed",
        ));
    }
    if record.page_generation != expected_generation || page.generation != expected_generation {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser page generation changed since preview; stale upload sources fail closed",
        ));
    }
    if record.document_generation != expected_document_generation
        || page.generation != expected_document_generation
    {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser document was replaced since preview; stale upload sources fail closed",
        ));
    }
    if record.policy_revision != policy_revision || page.policy_revision != policy_revision {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser policy revision drifted since preview; stale upload sources fail closed",
        ));
    }
    if record.upload_policy_revision != UPLOAD_POLICY_REVISION {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser upload policy revision drifted since preview; stale upload sources fail closed",
        ));
    }
    if record.node_id != node.node_id {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser upload target node was replaced since preview; stale upload sources fail closed",
        ));
    }
    let expected_source = upload_source_id_for(
        &record.workspace_id,
        &record.policy_revision,
        &record.profile_identity,
        &record.page_id,
        &record.origin,
        record.page_generation,
        record.document_generation,
        &record.node_id,
        &record.node_role,
        &record.node_input_type,
        &record.node_state,
        record.trust_revision,
        &record.artifact_source_id,
        &record.artifact_relative_destination,
        &record.artifact_media_type,
        &record.artifact_sha256,
        record.artifact_size_bytes,
        &record.upload_policy_revision,
        record.issued_at_ms,
    );
    if expected_source != record.source_id {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser upload source identity does not match the current binding set; forged upload sources fail closed",
        ));
    }
    check_node_for_upload(
        node,
        page,
        expected_role,
        expected_input_type,
        expected_state,
        profile_identity,
        policy_revision,
        expected_generation,
        expected_document_generation,
    )?;
    verify_upload_artifact(workspace_root, record, now_ms)
}

/// Typed bounded upload preview material. Preview performs full page, node,
/// trust, policy, and artifact evaluation without mutating anything and without
/// requiring approval. It never carries file content or file bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadPreview {
    pub source_id: String,
    pub page_id: String,
    pub workspace_id: String,
    pub policy_revision: String,
    pub profile_identity: String,
    pub origin: String,
    pub page_generation: u64,
    pub document_generation: u64,
    pub node_id: String,
    pub node_role: String,
    pub node_input_type: String,
    pub node_state: String,
    pub trust_revision: u64,
    pub artifact_source_id: String,
    pub artifact_download_id: String,
    pub artifact_relative_destination: String,
    pub artifact_media_type: String,
    pub artifact_sha256: String,
    pub artifact_size_bytes: u64,
    pub max_upload_bytes: u64,
    pub upload_policy_revision: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub preview_digest: String,
}

impl UploadPreview {
    pub fn to_json(&self) -> Value {
        json!({
            "source_id": self.source_id,
            "page_id": self.page_id,
            "workspace_id": self.workspace_id,
            "policy_revision": self.policy_revision,
            "profile_identity": self.profile_identity,
            "origin": self.origin,
            "page_generation": self.page_generation,
            "document_generation": self.document_generation,
            "node_id": self.node_id,
            "node_role": self.node_role,
            "node_input_type": self.node_input_type,
            "node_state": self.node_state,
            "trust_revision": self.trust_revision,
            "artifact_source_id": self.artifact_source_id,
            "artifact_download_id": self.artifact_download_id,
            "artifact_relative_destination": self.artifact_relative_destination,
            "artifact_media_type": self.artifact_media_type,
            "artifact_sha256": self.artifact_sha256,
            "artifact_size_bytes": self.artifact_size_bytes,
            "max_upload_bytes": self.max_upload_bytes,
            "upload_policy_revision": self.upload_policy_revision,
            "issued_at_ms": self.issued_at_ms,
            "expires_at_ms": self.expires_at_ms,
            "preview_digest": self.preview_digest,
            "page_transfer_performed": false,
            "executed": false,
            "opened": false,
            "extracted": false,
            "cookies": false,
            "credentials": false,
        })
    }
}

/// Typed bounded upload evidence. It records the approved upload binding and
/// the verified artifact identity only. It never carries file content or file
/// bytes, and it never claims that a page byte transfer occurred.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadEvidence {
    pub upload_id: String,
    pub source_id: String,
    pub page_id: String,
    pub workspace_id: String,
    pub policy_revision: String,
    pub profile_identity: String,
    pub origin: String,
    pub page_generation: u64,
    pub document_generation: u64,
    pub node_id: String,
    pub node_role: String,
    pub node_input_type: String,
    pub node_state: String,
    pub trust_revision: u64,
    pub artifact_source_id: String,
    pub artifact_download_id: String,
    pub artifact_relative_destination: String,
    pub artifact_media_type: String,
    pub artifact_sha256: String,
    pub artifact_size_bytes: u64,
    pub upload_policy_revision: String,
    pub state: String,
}

impl UploadEvidence {
    pub fn to_json(&self, approval_record_id: &str) -> Value {
        json!({
            "upload_id": self.upload_id,
            "source_id": self.source_id,
            "page_id": self.page_id,
            "workspace_id": self.workspace_id,
            "policy_revision": self.policy_revision,
            "profile_identity": self.profile_identity,
            "origin": self.origin,
            "page_generation": self.page_generation,
            "document_generation": self.document_generation,
            "node_id": self.node_id,
            "node_role": self.node_role,
            "node_input_type": self.node_input_type,
            "node_state": self.node_state,
            "trust_revision": self.trust_revision,
            "artifact_source_id": self.artifact_source_id,
            "artifact_download_id": self.artifact_download_id,
            "artifact_relative_destination": self.artifact_relative_destination,
            "artifact_media_type": self.artifact_media_type,
            "artifact_sha256": self.artifact_sha256,
            "artifact_size_bytes": self.artifact_size_bytes,
            "upload_policy_revision": self.upload_policy_revision,
            "state": self.state,
            "approval_record_id": approval_record_id,
            "page_transfer_performed": false,
            "executed": false,
            "opened": false,
            "extracted": false,
            "cookies": false,
            "credentials": false,
        })
    }
}

#[cfg(test)]
mod tests {
    /// Judge, PR #428: orceld's own destination check refuses the same
    /// non-global IPv6 space as the host's.
    #[test]
    fn translation_tunnel_and_non_global_ipv6_are_never_public() {
        for address in [
            // Judge, PR #428: translation and tunnel prefixes that embed or
            // reach private or metadata addresses, and other non-global
            // IPv6 space.
            "64:ff9b::a00:1",
            "64:ff9b::7f00:1",
            "64:ff9b::a9fe:a9fe",
            "64:ff9b::808:808",
            "64:ff9b:1::a00:1",
            "fec0::1",
            "2001::1",
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
            "2001:10::1",
            "2001:20::1",
            "100::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
            "100.64.0.1",
            "::127.0.0.1",
        ] {
            let parsed: IpAddr = address.parse().unwrap();
            assert!(!is_public_address(&parsed), "{address}");
        }
        for address in [
            "93.184.215.14",
            "2606:4700::6810:85e5",
            "2001:4860:4860::8888",
        ] {
            let parsed: IpAddr = address.parse().unwrap();
            assert!(is_public_address(&parsed), "{address}");
        }
    }

    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct StaticResolver {
        addresses: Vec<IpAddr>,
    }

    impl DnsResolver for StaticResolver {
        fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>, ProviderError> {
            Ok(self.addresses.clone())
        }
    }

    fn public_resolver() -> StaticResolver {
        StaticResolver {
            addresses: vec!["93.184.216.34".parse().unwrap()],
        }
    }

    fn temp_profile_root(label: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "orcel-browser-profile-{label}-{}-{suffix}",
            std::process::id()
        ))
    }

    #[test]
    fn allowed_shapes_are_exactly_profile_status_destination_page_navigation_snapshot_observe_structured_actuation_and_scoped_transfers(
    ) {
        assert!(is_allowed_browser_shape("browser.profile", "status"));
        assert!(is_allowed_browser_shape("browser.destination", "validate"));
        assert!(is_allowed_browser_shape("browser.page", "open"));
        assert!(is_allowed_browser_shape("browser.navigation", "preview"));
        assert!(is_allowed_browser_shape("browser.navigation", "navigate"));
        assert!(is_allowed_browser_shape("browser.snapshot", "observe"));
        assert!(is_allowed_browser_shape("browser.dom", "click"));
        assert!(is_allowed_browser_shape("browser.dom", "fill"));
        assert!(is_allowed_browser_shape("browser.download", "preview"));
        assert!(is_allowed_browser_shape("browser.download", "download"));
        assert!(is_allowed_browser_shape("browser.upload", "preview"));
        assert!(is_allowed_browser_shape("browser.upload", "submit"));
        for (capability, operation) in DENIED_BROWSER_SHAPES {
            assert!(
                !is_allowed_browser_shape(capability, operation),
                "{capability}/{operation} must not be allowed"
            );
            assert!(
                is_denied_browser_shape(capability, operation),
                "{capability}/{operation} must be denied"
            );
        }
    }

    #[test]
    fn unknown_browser_operations_fail_closed() {
        for (capability, operation) in [
            ("browser.navigate", "navigate"),
            ("browser.dom", "type"),
            ("browser.dom", "press"),
            ("browser.dom", "select"),
            ("browser.dom", "snapshot"),
            ("browser.dom", "observe"),
            ("browser.accessibility", "query"),
            ("browser.snapshot", "capture"),
            ("browser.snapshot", "actuate"),
            ("browser.page", "close"),
            ("browser.navigation", "back"),
            // NOTE (SG-000025 and SG-000026 successors): browser.download/
            // preview, browser.download/download, browser.upload/preview, and
            // browser.upload/submit are lawfully authorized by successor
            // grains and are no longer denied shapes. Downloaded-file
            // execution, opening, extraction, generic file read, directory
            // upload, and multiple-file upload remain denied in every successor
            // grain.
            ("browser.download", "execute"),
            ("browser.download", "open"),
            ("browser.download", "extract"),
            ("browser.file", "execute"),
            ("browser.archive", "extract"),
            ("browser.shell", "run"),
            ("browser.file", "read"),
            ("browser.fs", "read"),
            ("browser.directory", "upload"),
            ("browser.upload", "directory"),
            ("browser.upload", "multiple"),
            ("browser.upload", "upload"),
            ("browser.profile", "use_personal"),
            ("browser.debug", "attach"),
            ("browser.script", "evaluate"),
            ("browser.cdp", "command"),
            ("browser.unknown", "unknown"),
            ("devtools", "command"),
            ("cdp", "command"),
            ("playwright", "command"),
        ] {
            assert!(
                is_denied_browser_shape(capability, operation),
                "{capability}/{operation} must fail closed"
            );
        }
        assert!(!is_denied_browser_shape("fs.read", "read"));
        assert!(!is_denied_browser_shape("process.spawn", "spawn"));
    }

    #[test]
    fn origin_binding_normalizes_scheme_host_and_port() {
        let origin = parse_destination_url("https://Example.COM/docs").expect("valid");
        assert_eq!(origin.scheme, "https");
        assert_eq!(origin.host, "example.com");
        assert_eq!(origin.port, 443);
        assert_eq!(origin.origin, "https://example.com:443");

        let http = parse_destination_url("http://example.com/").expect("valid");
        assert_eq!(http.port, 80);
        assert_eq!(http.origin, "http://example.com:80");

        let explicit = parse_destination_url("https://example.com:443/a").expect("valid");
        assert_eq!(explicit.origin, "https://example.com:443");

        let custom = parse_destination_url("https://example.com:8443/a").expect("valid");
        assert_eq!(custom.port, 8443);
        assert_eq!(custom.origin, "https://example.com:8443");
        assert_ne!(custom.origin, explicit.origin);
    }

    #[test]
    fn origin_parsing_rejects_userinfo_fragment_and_malformed_hosts() {
        for bad in [
            "https://user@example.com/",
            "https://user:pass@example.com/",
            "https://example.com/page#section",
            "https://*.example.com/",
            "https://*example.com/",
            "https://exam ple.com/",
            "https://example.com\\evil",
            "https://example.com./",
            "https://[::1/",
            "https://::1/",
            "https://example.com:0/",
            "https://example.com:99999/",
            "https://example.com:/",
            "gopher://example.com/",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "https://",
            "https:///path",
            "",
        ] {
            assert!(
                parse_destination_url(bad).is_err(),
                "must reject destination {bad:?}"
            );
        }
    }

    #[test]
    fn alternate_numeric_hosts_are_rejected_before_address_policy() {
        for bad in [
            "http://0x7f.0.0.1/",
            "http://0X7F.0.0.1/",
            "http://0177.0.0.1/",
            "http://2130706433/",
            "http://0x7f000001/",
            "http://3232235521/",
            "http://0.0.0.0/",
        ] {
            let result = parse_destination_url(bad);
            if bad == "http://0.0.0.0/" {
                let origin = result.expect("dotted decimal parses");
                assert_eq!(origin.host, "0.0.0.0");
            } else {
                assert!(
                    result.is_err(),
                    "must reject alternate numeric host {bad:?}"
                );
            }
        }
    }

    #[test]
    fn localhost_aliases_are_denied() {
        for bad in [
            "http://localhost/",
            "http://localhost:3000/",
            "http://app.localhost/",
            "http://printer.local/",
            "http://service.internal/",
            "http://nas.lan/",
            "http://router.home/",
        ] {
            let error = parse_destination_url(bad).expect_err("localhost alias must fail");
            assert_eq!(error.code, FailureCode::CapabilityDenied, "{bad:?}");
        }
    }

    #[test]
    fn literal_public_addresses_parse_and_survive_policy() {
        let origin = parse_destination_url("http://93.184.216.34/").expect("literal parses");
        assert_eq!(origin.host, "93.184.216.34");
        let validated =
            validate_destination("http://93.184.216.34/", &public_resolver()).expect("public");
        assert_eq!(validated.pinned_address.to_string(), "93.184.216.34");

        let v6 = parse_destination_url("https://[2606:2800:220:1:248:1893:25c8:1946]/")
            .expect("ipv6 parses");
        assert_eq!(v6.host, "2606:2800:220:1:248:1893:25c8:1946");
    }

    #[test]
    fn ssrf_addresses_fail_closed_after_resolution() {
        let loopback_v4: IpAddr = "127.0.0.1".parse().unwrap();
        let loopback_v6: IpAddr = "::1".parse().unwrap();
        let private: IpAddr = "10.0.0.1".parse().unwrap();
        let link_local: IpAddr = "169.254.169.254".parse().unwrap();
        let unspecified: IpAddr = "0.0.0.0".parse().unwrap();
        let multicast: IpAddr = "224.0.0.1".parse().unwrap();
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        for address in [
            loopback_v4,
            loopback_v6,
            private,
            link_local,
            unspecified,
            multicast,
            mapped,
        ] {
            assert!(
                !is_public_address(&address),
                "SSRF address {address} must be non-public"
            );
            let resolver = StaticResolver {
                addresses: vec![address],
            };
            let error = validate_destination("https://example.com/", &resolver)
                .expect_err("SSRF must fail closed");
            assert_eq!(error.code, FailureCode::CapabilityDenied, "{address}");
        }
    }

    #[test]
    fn pinned_selection_is_deterministic_and_requires_public() {
        let private: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(select_pinned_address(&[]).is_err());
        assert!(select_pinned_address(&[private]).is_err());
        let first: IpAddr = "8.8.8.8".parse().unwrap();
        let second: IpAddr = "1.1.1.1".parse().unwrap();
        let pinned = select_pinned_address(&[first, second, private]).expect("pinned");
        assert_eq!(pinned, second);
        assert_eq!(select_pinned_address(&[first, second]).unwrap(), pinned);
    }

    #[test]
    fn redirect_widening_fails_closed() {
        let resolver = public_resolver();
        let same = validate_redirect(
            "https://example.com/",
            "https://example.com/other-path?q=1",
            &resolver,
        )
        .expect("same-origin redirect validates");
        assert_eq!(same.origin, "https://example.com:443");

        for target in [
            "https://evil.example.com/",
            "https://example.com.evil.com/",
            "https://example.com:8443/",
            "http://example.com/",
            "https://example.co/",
        ] {
            let error = validate_redirect("https://example.com/", target, &resolver)
                .expect_err("widening must fail");
            assert_eq!(error.code, FailureCode::CapabilityDenied, "{target}");
        }

        let prefix_trap = validate_redirect(
            "https://example.com/",
            "https://example.com.evil.com/",
            &resolver,
        );
        assert!(
            prefix_trap.is_err(),
            "prefix trap must not compare by prefix"
        );
    }

    #[test]
    fn isolated_profile_has_deterministic_identity_and_no_personal_data() {
        let root = temp_profile_root("isolated");
        let profile = ensure_isolated_profile(&root).expect("profile");
        assert!(profile.isolated);
        assert!(profile.root.is_absolute());
        assert!(marker_body(&profile.root).contains("no-personal-data"));
        let reopened = ensure_isolated_profile(&root).expect("reopen");
        assert_eq!(profile.identity, reopened.identity);
        assert!(!reopened.fresh_storage);
        let status = profile.status_json("default", "sg-000021-v1");
        assert_eq!(status["isolated"], true);
        assert_eq!(status["personal_data"], false);
        assert_eq!(status["workspace_id"], "default");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn personal_profile_paths_are_denied_before_touching_disk() {
        for candidate in [
            "C:\\Users\\Owner\\AppData\\Local\\Google\\Chrome\\User Data\\Default",
            "C:\\Users\\Owner\\AppData\\Local\\Microsoft\\Edge\\User Data",
            "/home/owner/.config/google-chrome/Default",
            "/home/owner/.mozilla/firefox/profiles/abc123",
        ] {
            let path = PathBuf::from(candidate);
            assert!(
                is_personal_profile_path(&path),
                "{candidate:?} must be recognized as personal"
            );
            let error =
                ensure_isolated_profile(&path).expect_err("personal profile must be denied");
            assert_eq!(error.code, FailureCode::CapabilityDenied, "{candidate:?}");
        }
        assert!(!is_personal_profile_path(&PathBuf::from(
            "C:\\ProgramData\\Orcel\\browser-profile"
        )));
    }

    #[test]
    fn caller_profile_roots_and_traversal_are_denied() {
        assert_eq!(
            reject_caller_profile_root().code,
            FailureCode::CapabilityDenied
        );
        let traversal = std::env::temp_dir().join("..").join("escape-profile");
        assert!(ensure_isolated_profile(&traversal).is_err());
        let relative = PathBuf::from("relative/profile");
        assert!(ensure_isolated_profile(&relative).is_err());
    }

    #[test]
    fn foreign_marker_content_is_rejected() {
        let root = temp_profile_root("foreign");
        std::fs::create_dir_all(&root).expect("seed dir");
        std::fs::write(root.join(PROFILE_MARKER_FILE), "foreign browser data")
            .expect("seed marker");
        let error = ensure_isolated_profile(&root).expect_err("foreign storage must fail");
        assert_eq!(error.code, FailureCode::TargetStale);
        let _ = std::fs::remove_dir_all(root);
    }

    fn temp_page_registry(label: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "orcel-browser-pages-{label}-{}-{suffix}.jsonl",
            std::process::id()
        ))
    }

    fn open_test_page(store: &mut PageStore) -> PageRecord {
        store
            .open_page("default", "profile-identity-test", "sg-000022-v1")
            .expect("open page")
    }

    fn open_observation_test_page(store: &mut PageStore) -> PageRecord {
        store
            .open_page("default", "profile-identity-test", "sg-000023-v1")
            .expect("open observation page")
    }

    #[test]
    fn a_closed_page_is_stale_for_good_and_survives_a_reload() {
        let path = temp_page_registry("close");
        let mut store = PageStore::load_or_create(path.clone());
        let page = open_test_page(&mut store);
        let (active, _, _) = store
            .apply_navigation(&page.page_id, "", 0, "https://example.test")
            .expect("navigate");
        let closed = store.close_page(&page.page_id).expect("close");
        assert_eq!(closed.state, PageState::Closed);
        assert_eq!(closed.generation, active.generation + 1);
        // Idempotent, and an unknown handle is stale.
        assert_eq!(store.close_page(&page.page_id).expect("again"), closed);
        assert_eq!(
            store.close_page("page-unknown").unwrap_err().code,
            FailureCode::TargetStale
        );
        let reloaded = PageStore::load_or_create(path.clone());
        assert_eq!(reloaded.get(&page.page_id), Some(&closed));
        let mut reloaded = reloaded;
        for error in [
            reloaded
                .apply_navigation(
                    &page.page_id,
                    "https://example.test",
                    closed.generation,
                    "https://example.test",
                )
                .unwrap_err(),
            reloaded
                .apply_actuation(&page.page_id, "https://example.test", closed.generation)
                .unwrap_err(),
        ] {
            assert_eq!(error.code, FailureCode::TargetStale);
        }
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_failed_registry_write_changes_nothing() {
        // The registry path is a directory: every append fails.
        let path = temp_page_registry("unwritable");
        std::fs::create_dir_all(&path).expect("dir");
        let mut store = PageStore::load_or_create(path.clone());
        let refused = store
            .open_page("default", "profile-identity-test", "sg-000022-v1")
            .unwrap_err();
        assert_eq!(refused.code, FailureCode::ProviderUnavailable);
        assert_eq!(store.count_for_workspace("default"), 0);
        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn page_open_binds_workspace_profile_and_generation() {
        let path = temp_page_registry("open");
        let mut store = PageStore::load_or_create(path.clone());
        let first = open_test_page(&mut store);
        assert!(first.page_id.starts_with(PAGE_ID_PREFIX));
        assert_eq!(first.workspace_id, "default");
        assert_eq!(first.profile_identity, "profile-identity-test");
        assert_eq!(first.current_origin, "");
        assert_eq!(first.generation, 0);
        assert_eq!(first.state, PageState::Open);
        let second = open_test_page(&mut store);
        assert_ne!(first.page_id, second.page_id);
        assert_eq!(store.count_for_workspace("default"), 2);
        assert_eq!(store.count_for_workspace("other"), 0);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn page_open_enforces_per_workspace_bound() {
        let path = temp_page_registry("bound");
        let mut store = PageStore::load_or_create(path.clone());
        for _ in 0..MAX_PAGES_PER_WORKSPACE {
            open_test_page(&mut store);
        }
        let error = store
            .open_page("default", "profile-identity-test", "sg-000022-v1")
            .expect_err("bound must fail closed");
        assert_eq!(error.code, FailureCode::OutputLimit);
        assert!(store
            .open_page("other", "profile-identity-test", "sg-000022-v1")
            .is_ok());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn forged_page_handles_fail_closed() {
        let path = temp_page_registry("forged");
        let mut store = PageStore::load_or_create(path.clone());
        let page = open_test_page(&mut store);
        assert!(store.get(&page.page_id).is_some());
        assert!(store.get("pg-00000000000000000000000000000000").is_none());
        assert!(store.get("").is_none());
        let error = store
            .apply_navigation("pg-forged-handle", "", 0, "https://example.com:443")
            .expect_err("forged handle must fail");
        assert_eq!(error.code, FailureCode::TargetStale);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn stale_generation_and_origin_fail_closed() {
        let path = temp_page_registry("stale");
        let mut store = PageStore::load_or_create(path.clone());
        let page = open_test_page(&mut store);
        let error = store
            .apply_navigation(
                &page.page_id,
                "https://example.com:443",
                0,
                "https://example.com:443",
            )
            .expect_err("wrong origin must fail");
        assert_eq!(error.code, FailureCode::TargetStale);
        let error = store
            .apply_navigation(&page.page_id, "", 7, "https://example.com:443")
            .expect_err("wrong generation must fail");
        assert_eq!(error.code, FailureCode::TargetStale);
        let (next, prior_origin, prior_generation) = store
            .apply_navigation(&page.page_id, "", 0, "https://example.com:443")
            .expect("first navigation");
        assert_eq!(prior_origin, "");
        assert_eq!(prior_generation, 0);
        assert_eq!(next.generation, 1);
        assert_eq!(next.current_origin, "https://example.com:443");
        assert_eq!(next.state, PageState::Active);
        let error = store
            .apply_navigation(&page.page_id, "", 0, "https://example.com:443")
            .expect_err("reused generation must fail");
        assert_eq!(error.code, FailureCode::TargetStale);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn redirect_chain_validates_hop_by_hop_with_loop_and_downgrade_denial() {
        let resolver = public_resolver();
        let base = "https://example.com/";
        let validated = validate_destination(base, &resolver).expect("base");
        let hops = vec![
            "https://example.com/step-one".to_owned(),
            "https://example.com/step-two".to_owned(),
        ];
        let (final_destination, count, final_origin) =
            validate_redirect_chain(&validated.origin, &hops, &resolver).expect("chain");
        assert_eq!(count, 2);
        assert_eq!(final_origin, "https://example.com:443");
        assert_eq!(final_destination.origin, "https://example.com:443");

        let widened = vec!["https://evil.example.com/".to_owned()];
        let error = validate_redirect_chain(&validated.origin, &widened, &resolver)
            .expect_err("widening must fail");
        assert_eq!(error.code, FailureCode::CapabilityDenied);

        let downgrade = vec!["http://example.com/".to_owned()];
        let error = validate_redirect_chain(&validated.origin, &downgrade, &resolver)
            .expect_err("downgrade must fail");
        assert_eq!(error.code, FailureCode::CapabilityDenied);

        let alternate_port = vec!["https://example.com:8443/".to_owned()];
        let error = validate_redirect_chain(&validated.origin, &alternate_port, &resolver)
            .expect_err("alternate port must fail");
        assert_eq!(error.code, FailureCode::CapabilityDenied);

        let looped = vec![
            "https://example.com/a".to_owned(),
            "https://example.com/a".to_owned(),
        ];
        let error = validate_redirect_chain(&validated.origin, &looped, &resolver)
            .expect_err("loop must fail");
        assert_eq!(error.code, FailureCode::CapabilityDenied);

        let userinfo = vec!["https://user@example.com/".to_owned()];
        assert!(validate_redirect_chain(&validated.origin, &userinfo, &resolver).is_err());

        let mut too_many = Vec::new();
        for index in 0..(MAX_REDIRECT_HOPS + 1) {
            too_many.push(format!("https://example.com/hop-{index}"));
        }
        let error = validate_redirect_chain(&validated.origin, &too_many, &resolver)
            .expect_err("too many hops must fail");
        assert_eq!(error.code, FailureCode::CapabilityDenied);
    }

    #[test]
    fn redirect_hops_apply_ssrf_policy_per_hop() {
        let loopback = StaticResolver {
            addresses: vec!["127.0.0.1".parse().unwrap()],
        };
        let base = "https://example.com/";
        let hops = vec!["https://example.com/private".to_owned()];
        let error =
            validate_redirect_chain(base, &hops, &loopback).expect_err("SSRF hop must fail closed");
        assert_eq!(error.code, FailureCode::CapabilityDenied);

        let metadata = StaticResolver {
            addresses: vec!["169.254.169.254".parse().unwrap()],
        };
        let error = validate_redirect_chain(base, &hops, &metadata)
            .expect_err("metadata hop must fail closed");
        assert_eq!(error.code, FailureCode::CapabilityDenied);
    }

    #[test]
    fn download_triggers_are_denied_for_executable_script_and_archive_paths() {
        for url in [
            "https://example.com/tool.exe",
            "https://example.com/setup.msi",
            "https://example.com/run.ps1",
            "https://example.com/run.bat",
            "https://example.com/payload.js",
            "https://example.com/archive.zip",
            "https://example.com/archive.7z",
            "https://example.com/image.iso",
            "https://example.com/TOOL.EXE?download=1",
        ] {
            assert!(
                is_download_trigger_url(url),
                "{url} must be a download trigger"
            );
        }
        for url in [
            "https://example.com/docs",
            "https://example.com/page.html",
            "https://example.com/api/data.json",
            "https://example.com/",
        ] {
            assert!(!is_download_trigger_url(url), "{url} must not be a trigger");
        }
        let resolver = public_resolver();
        let path = temp_page_registry("download");
        let mut store = PageStore::load_or_create(path.clone());
        let page = open_test_page(&mut store);
        assert!(preview_navigation(&page, "https://example.com/tool.exe", &[], &resolver).is_err());
        let chain = vec!["https://example.com/archive.zip".to_owned()];
        assert!(preview_navigation(&page, "https://example.com/docs", &chain, &resolver).is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn navigation_preview_binds_origin_with_ssrf_denial() {
        let resolver = public_resolver();
        let path = temp_page_registry("preview");
        let mut store = PageStore::load_or_create(path.clone());
        let page = open_test_page(&mut store);
        let preview =
            preview_navigation(&page, "https://example.com/docs", &[], &resolver).expect("preview");
        assert_eq!(preview.target_origin, "https://example.com:443");
        assert_eq!(preview.final_origin, "https://example.com:443");
        assert_eq!(preview.redirect_count, 0);
        assert_eq!(preview.pinned_address.to_string(), "93.184.216.34");

        let loopback = StaticResolver {
            addresses: vec!["10.0.0.1".parse().unwrap()],
        };
        let error = preview_navigation(&page, "https://example.com/docs", &[], &loopback)
            .expect_err("private must fail");
        assert_eq!(error.code, FailureCode::CapabilityDenied);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn navigation_digest_changes_for_material_drift() {
        let pinned: IpAddr = "93.184.216.34".parse().unwrap();
        let base = navigation_approval_digest(
            "default",
            "sg-000022-v1",
            "profile-a",
            "pg-abc",
            "",
            0,
            "https://example.com:443",
            &pinned,
            &[],
            "https://example.com:443",
        );
        let drifted_origin = navigation_approval_digest(
            "default",
            "sg-000022-v1",
            "profile-a",
            "pg-abc",
            "https://other.example:443",
            0,
            "https://example.com:443",
            &pinned,
            &[],
            "https://example.com:443",
        );
        assert_ne!(base, drifted_origin);
        let drifted_generation = navigation_approval_digest(
            "default",
            "sg-000022-v1",
            "profile-a",
            "pg-abc",
            "",
            1,
            "https://example.com:443",
            &pinned,
            &[],
            "https://example.com:443",
        );
        assert_ne!(base, drifted_generation);
        let drifted_pin: IpAddr = "1.1.1.1".parse().unwrap();
        let drifted_address = navigation_approval_digest(
            "default",
            "sg-000022-v1",
            "profile-a",
            "pg-abc",
            "",
            0,
            "https://example.com:443",
            &drifted_pin,
            &[],
            "https://example.com:443",
        );
        assert_ne!(base, drifted_address);
    }

    #[test]
    fn navigation_evidence_carries_no_secret_material() {
        let pinned: IpAddr = "93.184.216.34".parse().unwrap();
        let evidence = NavigationEvidence {
            page_id: "pg-test".to_owned(),
            workspace_id: "default".to_owned(),
            policy_revision: "sg-000022-v1".to_owned(),
            profile_identity: "profile-a".to_owned(),
            prior_origin: String::new(),
            prior_generation: 0,
            target_origin: "https://example.com:443".to_owned(),
            pinned_address: pinned,
            redirect_count: 0,
            final_origin: "https://example.com:443".to_owned(),
            new_generation: 1,
        };
        let json = evidence.to_json("apr-1");
        assert!(json["cookies"] == false);
        assert!(json["credentials"] == false);
        assert!(json.get("cookie").is_none());
        assert!(json.get("authorization").is_none());
        assert!(json.get("token").is_none());
        assert!(json.get("password").is_none());
        let preview = NavigationPreview {
            page_id: "pg-test".to_owned(),
            workspace_id: "default".to_owned(),
            policy_revision: "sg-000022-v1".to_owned(),
            current_origin: String::new(),
            current_generation: 0,
            target_origin: "https://example.com:443".to_owned(),
            pinned_address: pinned,
            redirect_count: 0,
            final_origin: "https://example.com:443".to_owned(),
        };
        assert_eq!(
            preview.to_json()["target_origin"],
            "https://example.com:443"
        );
    }

    #[test]
    fn snapshot_observe_binds_active_page_with_typed_node_identity() {
        let path = temp_page_registry("snapshot-bind");
        let mut store = PageStore::load_or_create(path.clone());
        let page = open_observation_test_page(&mut store);
        let open_error = build_snapshot(
            &page,
            "profile-identity-test",
            "sg-000023-v1",
            50,
            4,
            16_384,
        )
        .expect_err("open pages have no document and must fail closed");
        assert_eq!(open_error.code, FailureCode::TargetStale);

        let (active, _, _) = store
            .apply_navigation(&page.page_id, "", 0, "https://example.com:443")
            .expect("navigate");
        let snapshot = build_snapshot(
            &active,
            "profile-identity-test",
            "sg-000023-v1",
            50,
            4,
            16_384,
        )
        .expect("active page snapshots");
        assert!(snapshot.snapshot_id.starts_with(SNAPSHOT_ID_PREFIX));
        assert_eq!(snapshot.page_id, active.page_id);
        assert_eq!(snapshot.origin, "https://example.com:443");
        assert_eq!(snapshot.page_generation, 1);
        assert_eq!(snapshot.document_generation, 1);
        assert!(!snapshot.nodes.is_empty());
        assert_eq!(snapshot.node_count, snapshot.nodes.len());
        for node in &snapshot.nodes {
            assert!(node.node_id.starts_with(SNAPSHOT_NODE_PREFIX));
            assert!(SNAPSHOT_ROLES.contains(&node.role.as_str()));
            assert_eq!(node.page_id, active.page_id);
            assert_eq!(node.page_generation, 1);
            assert_eq!(node.document_generation, 1);
            assert_eq!(node.origin, "https://example.com:443");
            validate_snapshot_node(node, &active, "profile-identity-test", "sg-000023-v1")
                .expect("fresh node validates");
        }
        let json = snapshot.to_json();
        assert!(json["cookies"] == false);
        assert!(json["credentials"] == false);
        assert!(json.get("password").is_none());
        assert!(json.get("token").is_none());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn stale_wrong_profile_origin_generation_and_policy_nodes_fail_closed() {
        let path = temp_page_registry("snapshot-stale");
        let mut store = PageStore::load_or_create(path.clone());
        let page = open_observation_test_page(&mut store);
        let (active, _, _) = store
            .apply_navigation(&page.page_id, "", 0, "https://example.com:443")
            .expect("navigate");
        let snapshot = build_snapshot(
            &active,
            "profile-identity-test",
            "sg-000023-v1",
            50,
            4,
            16_384,
        )
        .expect("snapshot");
        let node = &snapshot.nodes[0];

        let wrong_profile =
            validate_snapshot_node(node, &active, "foreign-profile", "sg-000023-v1")
                .expect_err("foreign profile must fail");
        assert_eq!(wrong_profile.code, FailureCode::TargetStale);

        let wrong_policy =
            validate_snapshot_node(node, &active, "profile-identity-test", "sg-000024-v1")
                .expect_err("policy drift must fail");
        assert_eq!(wrong_policy.code, FailureCode::TargetStale);

        let mut drifted_origin = active.clone();
        drifted_origin.current_origin = "https://other.example:443".to_owned();
        let drifted = validate_snapshot_node(
            node,
            &drifted_origin,
            "profile-identity-test",
            "sg-000023-v1",
        )
        .expect_err("origin drift must fail");
        assert_eq!(drifted.code, FailureCode::TargetStale);

        let mut drifted_generation = active.clone();
        drifted_generation.generation = active.generation + 1;
        let stale = validate_snapshot_node(
            node,
            &drifted_generation,
            "profile-identity-test",
            "sg-000023-v1",
        )
        .expect_err("generation drift must fail");
        assert_eq!(stale.code, FailureCode::TargetStale);

        let mut foreign_node = node.clone();
        foreign_node.page_id = "pg-forged-handle".to_owned();
        let foreign = validate_snapshot_node(
            &foreign_node,
            &active,
            "profile-identity-test",
            "sg-000023-v1",
        )
        .expect_err("foreign page node must fail");
        assert_eq!(foreign.code, FailureCode::TargetStale);

        let mut tampered = node.clone();
        tampered.node_id = "nd-00000000000000000000000000000000".to_owned();
        let forged =
            validate_snapshot_node(&tampered, &active, "profile-identity-test", "sg-000023-v1")
                .expect_err("forged node identity must fail");
        assert_eq!(forged.code, FailureCode::TargetStale);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn snapshot_bounds_are_enforced_and_oversized_requests_fail_closed() {
        assert!(resolve_snapshot_bounds(None, None, None).is_ok());
        for bad in [Some(0), Some(MAX_SNAPSHOT_NODES + 1)] {
            assert!(resolve_snapshot_bounds(bad, None, None).is_err());
        }
        for bad in [Some(0), Some(MAX_SNAPSHOT_DEPTH + 1)] {
            assert!(resolve_snapshot_bounds(None, bad, None).is_err());
        }
        for bad in [Some(0), Some(65_537)] {
            assert!(resolve_snapshot_bounds(None, None, bad).is_err());
        }

        let path = temp_page_registry("snapshot-bounds");
        let mut store = PageStore::load_or_create(path.clone());
        let page = open_observation_test_page(&mut store);
        let (active, _, _) = store
            .apply_navigation(&page.page_id, "", 0, "https://example.com:443")
            .expect("navigate");
        let tiny = build_snapshot(
            &active,
            "profile-identity-test",
            "sg-000023-v1",
            2,
            4,
            16_384,
        )
        .expect("bounded snapshot");
        assert_eq!(tiny.node_count, 2);
        assert!(tiny.truncated);

        let shallow = build_snapshot(
            &active,
            "profile-identity-test",
            "sg-000023-v1",
            50,
            1,
            16_384,
        )
        .expect("shallow snapshot");
        assert!(shallow.nodes.iter().all(|node| node.depth <= 1));

        let small_bytes =
            build_snapshot(&active, "profile-identity-test", "sg-000023-v1", 50, 4, 256)
                .expect_err("tiny byte bound must fail closed");
        assert_eq!(small_bytes.code, FailureCode::OutputLimit);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn snapshot_redaction_denies_password_and_secret_leakage() {
        assert_eq!(
            redact_node_value("textbox", "password", "hunter2"),
            "[redacted]"
        );
        assert_eq!(
            redact_node_value("password", "text", "hunter2"),
            "[redacted]"
        );
        assert_eq!(redact_node_value("textbox", "text", "hello"), "hello");
        assert_eq!(redact_node_value("button", "", ""), "");

        let path = temp_page_registry("snapshot-redact");
        let mut store = PageStore::load_or_create(path.clone());
        let page = open_observation_test_page(&mut store);
        let (active, _, _) = store
            .apply_navigation(&page.page_id, "", 0, "https://example.com:443")
            .expect("navigate");
        let snapshot = build_snapshot(
            &active,
            "profile-identity-test",
            "sg-000023-v1",
            50,
            4,
            16_384,
        )
        .expect("snapshot");
        // Absence is asserted on exact JSON fields, never by substring: the
        // packet legitimately carries `"cookies": false` and
        // `"credentials": false` absence markers, so a substring check for
        // "cookie" would trap on its own marker.
        let json = snapshot.to_json();
        assert!(json["cookies"] == false);
        assert!(json["credentials"] == false);
        assert!(json.get("cookie").is_none());
        assert!(json.get("password").is_none());
        assert!(json.get("token").is_none());
        assert!(json.get("session").is_none());
        assert!(json.get("authorization").is_none());
        let nodes = json["nodes"].as_array().expect("nodes");
        for node in nodes {
            assert_ne!(node["role"], "password");
            assert_ne!(node["value"], "hunter2");
            assert!(node.get("cookie").is_none());
            assert!(node.get("password").is_none());
            assert!(node.get("secret").is_none());
        }
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn snapshot_node_identity_is_deterministic_and_drifts_with_binding() {
        let first = node_id_for(
            "profile-a",
            "pg-x",
            1,
            "https://example.com:443",
            1,
            0,
            "sg-000023-v1",
        );
        let replay = node_id_for(
            "profile-a",
            "pg-x",
            1,
            "https://example.com:443",
            1,
            0,
            "sg-000023-v1",
        );
        assert_eq!(first, replay);
        assert!(first.starts_with(SNAPSHOT_NODE_PREFIX));
        assert_ne!(
            first,
            node_id_for(
                "profile-b",
                "pg-x",
                1,
                "https://example.com:443",
                1,
                0,
                "sg-000023-v1"
            )
        );
        assert_ne!(
            first,
            node_id_for(
                "profile-a",
                "pg-x",
                2,
                "https://example.com:443",
                2,
                0,
                "sg-000023-v1"
            )
        );
        assert_ne!(
            first,
            node_id_for(
                "profile-a",
                "pg-x",
                1,
                "https://other.example:443",
                1,
                0,
                "sg-000023-v1"
            )
        );
        assert_ne!(
            first,
            node_id_for(
                "profile-a",
                "pg-x",
                1,
                "https://example.com:443",
                1,
                1,
                "sg-000023-v1"
            )
        );
    }

    #[test]
    fn actuation_verbs_roles_and_password_targets_are_gated() {
        assert_eq!(parse_actuation_action("click").expect("click"), "click");
        assert_eq!(parse_actuation_action("fill").expect("fill"), "fill");
        for bad in [
            "select",
            "toggle",
            "submit",
            "press",
            "type",
            "scroll",
            "hover",
            "coordinate",
            "",
        ] {
            assert!(
                parse_actuation_action(bad).is_err(),
                "{bad:?} must be denied"
            );
        }
        assert!(role_permits_action("link", "click"));
        assert!(role_permits_action("button", "click"));
        assert!(!role_permits_action("textbox", "click"));
        assert!(!role_permits_action("heading", "click"));
        assert!(!role_permits_action("document", "click"));
        assert!(role_permits_action("textbox", "fill"));
        assert!(!role_permits_action("link", "fill"));
        assert!(!role_permits_action("button", "fill"));
        assert!(!role_permits_action("textbox", "select"));
        assert!(is_password_target("textbox", "password"));
        assert!(is_password_target("password", "text"));
        assert!(!is_password_target("textbox", "text"));
        assert!(!is_password_target("button", ""));
    }

    fn temp_node_registry(label: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "orcel-browser-nodes-{label}-{}-{suffix}.jsonl",
            std::process::id()
        ))
    }

    fn open_actuation_test_page(store: &mut PageStore) -> PageRecord {
        store
            .open_page("default", "profile-identity-test", "sg-000024-v1")
            .expect("open actuation page")
    }

    fn navigated_actuation_page(store: &mut PageStore, page: &PageRecord) -> PageRecord {
        store
            .apply_navigation(&page.page_id, "", 0, "https://example.com:443")
            .expect("navigate")
            .0
    }

    #[test]
    fn node_store_records_snapshot_and_gates_actuation() {
        let page_path = temp_page_registry("actuation-nodes");
        let node_path = temp_node_registry("actuation-nodes");
        let mut pages = PageStore::load_or_create(page_path.clone());
        let page = open_actuation_test_page(&mut pages);
        let active = navigated_actuation_page(&mut pages, &page);
        let snapshot = build_snapshot(
            &active,
            "profile-identity-test",
            "sg-000024-v1",
            50,
            4,
            16_384,
        )
        .expect("snapshot");
        let mut nodes = NodeStore::load_or_create(node_path.clone());
        nodes.record_snapshot(
            "profile-identity-test",
            &active,
            "sg-000024-v1",
            &snapshot.nodes,
        );
        let link = snapshot
            .nodes
            .iter()
            .find(|node| node.role == "link")
            .expect("link node");
        let stored = nodes.get(&link.node_id).expect("recorded link").clone();
        check_node_for_actuation(
            &stored,
            &active,
            "profile-identity-test",
            "sg-000024-v1",
            "link",
            "enabled",
            1,
            1,
            "click",
        )
        .expect("link click validates");
        let fill_on_link = check_node_for_actuation(
            &stored,
            &active,
            "profile-identity-test",
            "sg-000024-v1",
            "link",
            "enabled",
            1,
            1,
            "fill",
        )
        .expect_err("fill on link must fail");
        assert_eq!(fill_on_link.code, FailureCode::CapabilityDenied);
        let wrong_role = check_node_for_actuation(
            &stored,
            &active,
            "profile-identity-test",
            "sg-000024-v1",
            "button",
            "enabled",
            1,
            1,
            "click",
        )
        .expect_err("role mismatch must fail");
        assert_eq!(wrong_role.code, FailureCode::TargetStale);
        let wrong_state = check_node_for_actuation(
            &stored,
            &active,
            "profile-identity-test",
            "sg-000024-v1",
            "link",
            "disabled",
            1,
            1,
            "click",
        )
        .expect_err("state mismatch must fail");
        assert_eq!(wrong_state.code, FailureCode::TargetStale);
        let wrong_profile = check_node_for_actuation(
            &stored,
            &active,
            "foreign-profile",
            "sg-000024-v1",
            "link",
            "enabled",
            1,
            1,
            "click",
        )
        .expect_err("foreign profile must fail");
        assert_eq!(wrong_profile.code, FailureCode::TargetStale);
        let forged = nodes.get("nd-00000000000000000000000000000000").is_none();
        assert!(forged, "unknown node identities are absent");
        let _ = std::fs::remove_file(page_path);
        let _ = std::fs::remove_file(node_path);
    }

    #[test]
    fn password_field_actuation_is_denied() {
        let page_path = temp_page_registry("actuation-password");
        let node_path = temp_node_registry("actuation-password");
        let mut pages = PageStore::load_or_create(page_path.clone());
        let page = open_actuation_test_page(&mut pages);
        let active = navigated_actuation_page(&mut pages, &page);
        let snapshot = build_snapshot(
            &active,
            "profile-identity-test",
            "sg-000024-v1",
            50,
            4,
            16_384,
        )
        .expect("snapshot");
        let mut nodes = NodeStore::load_or_create(node_path.clone());
        nodes.record_snapshot(
            "profile-identity-test",
            &active,
            "sg-000024-v1",
            &snapshot.nodes,
        );
        let textbox = snapshot
            .nodes
            .iter()
            .find(|node| node.role == "textbox")
            .expect("textbox node");
        let base = nodes.get(&textbox.node_id).expect("recorded").clone();
        let password_id = node_id_for(
            "profile-identity-test",
            &base.page_id,
            base.page_generation,
            &base.origin,
            base.document_generation,
            100,
            "sg-000024-v1",
        );
        nodes.nodes.insert(
            password_id.clone(),
            StoredNode {
                schema: NODE_REGISTRY_SCHEMA.to_owned(),
                node_id: password_id.clone(),
                page_id: base.page_id.clone(),
                workspace_id: base.workspace_id.clone(),
                profile_identity: base.profile_identity.clone(),
                origin: base.origin.clone(),
                page_generation: base.page_generation,
                document_generation: base.document_generation,
                index: 100,
                role: "textbox".to_owned(),
                input_type: "password".to_owned(),
                state: "enabled".to_owned(),
                policy_revision: base.policy_revision.clone(),
            },
        );
        let stored = nodes.get(&password_id).expect("password record").clone();
        let denied = check_node_for_actuation(
            &stored,
            &active,
            "profile-identity-test",
            "sg-000024-v1",
            "textbox",
            "enabled",
            1,
            1,
            "fill",
        )
        .expect_err("password fill must fail");
        assert_eq!(denied.code, FailureCode::CapabilityDenied);
        let _ = std::fs::remove_file(page_path);
        let _ = std::fs::remove_file(node_path);
    }

    #[test]
    fn actuation_bumps_generation_and_invalidates_observed_nodes() {
        let page_path = temp_page_registry("actuation-bump");
        let node_path = temp_node_registry("actuation-bump");
        let mut pages = PageStore::load_or_create(page_path.clone());
        let page = open_actuation_test_page(&mut pages);
        let active = navigated_actuation_page(&mut pages, &page);
        let snapshot = build_snapshot(
            &active,
            "profile-identity-test",
            "sg-000024-v1",
            50,
            4,
            16_384,
        )
        .expect("snapshot");
        let mut nodes = NodeStore::load_or_create(node_path.clone());
        nodes.record_snapshot(
            "profile-identity-test",
            &active,
            "sg-000024-v1",
            &snapshot.nodes,
        );
        let link = snapshot
            .nodes
            .iter()
            .find(|node| node.role == "link")
            .expect("link node");
        let stored = nodes.get(&link.node_id).expect("recorded").clone();
        let (next, prior) = pages
            .apply_actuation(&active.page_id, "https://example.com:443", 1)
            .expect("actuation applies");
        assert_eq!(prior, 1);
        assert_eq!(next.generation, 2);
        assert_eq!(next.current_origin, "https://example.com:443");
        let stale = check_node_for_actuation(
            &stored,
            &next,
            "profile-identity-test",
            "sg-000024-v1",
            "link",
            "enabled",
            1,
            1,
            "click",
        )
        .expect_err("pre-actuation node must go stale");
        assert_eq!(stale.code, FailureCode::TargetStale);
        let replay = pages
            .apply_actuation(&active.page_id, "https://example.com:443", 1)
            .expect_err("replayed generation must fail");
        assert_eq!(replay.code, FailureCode::TargetStale);
        let _ = std::fs::remove_file(page_path);
        let _ = std::fs::remove_file(node_path);
    }

    #[test]
    fn fill_value_digest_bounds_values_and_actuation_digest_drifts() {
        assert!(fill_value_digest("hello").is_ok());
        assert!(fill_value_digest("").is_ok());
        let oversized = "x".repeat(MAX_FILL_VALUE_BYTES + 1);
        assert!(fill_value_digest(&oversized).is_err());
        let base = actuation_approval_digest(
            "default",
            "sg-000024-v1",
            "profile-a",
            "pg-abc",
            "https://example.com:443",
            1,
            1,
            "nd-abc",
            "link",
            "enabled",
            "click",
            "",
        );
        let drifted_value = actuation_approval_digest(
            "default",
            "sg-000024-v1",
            "profile-a",
            "pg-abc",
            "https://example.com:443",
            1,
            1,
            "nd-abc",
            "textbox",
            "enabled",
            "fill",
            "hello",
        );
        assert_ne!(base, drifted_value);
        let drifted_node = actuation_approval_digest(
            "default",
            "sg-000024-v1",
            "profile-a",
            "pg-abc",
            "https://example.com:443",
            1,
            1,
            "nd-other",
            "link",
            "enabled",
            "click",
            "",
        );
        assert_ne!(base, drifted_node);
        let evidence = ActuationEvidence {
            actuation_id: "ac-test".to_owned(),
            page_id: "pg-test".to_owned(),
            workspace_id: "default".to_owned(),
            policy_revision: "sg-000024-v1".to_owned(),
            profile_identity: "profile-a".to_owned(),
            node_id: "nd-abc".to_owned(),
            action: "click".to_owned(),
            role: "link".to_owned(),
            state: "enabled".to_owned(),
            origin: "https://example.com:443".to_owned(),
            prior_generation: 1,
            new_generation: 2,
            value_digest: String::new(),
        };
        let json = evidence.to_json("apr-1");
        assert!(json["cookies"] == false);
        assert!(json["credentials"] == false);
        assert!(json.get("cookie").is_none());
        assert!(json.get("password").is_none());
        assert!(json.get("value").is_none());
    }

    fn marker_body(root: &Path) -> String {
        std::fs::read_to_string(root.join(PROFILE_MARKER_FILE)).expect("marker")
    }
    fn temp_download_root(label: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "orcel-download-root-{label}-{}-{suffix}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).expect("root");
        root
    }

    fn temp_download_registry(label: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "orcel-download-registry-{label}-{}-{suffix}.jsonl",
            std::process::id()
        ))
    }

    fn download_test_page() -> PageRecord {
        PageRecord {
            page_id: "pg-1".into(),
            workspace_id: "default".into(),
            profile_identity: "profile-a".into(),
            current_origin: "https://example.com:443".into(),
            generation: 1,
            state: PageState::Active,
            policy_revision: "sg-000025-v1".into(),
        }
    }

    fn download_test_record(index: u64) -> StoredDownload {
        StoredDownload {
            schema: DOWNLOAD_REGISTRY_SCHEMA.into(),
            source_id: String::new(),
            workspace_id: "default".into(),
            policy_revision: "sg-000025-v1".into(),
            profile_identity: "profile-a".into(),
            page_id: "pg-1".into(),
            origin: "https://example.com:443".into(),
            page_generation: 1,
            document_generation: 1,
            source_origin: "https://example.com:443".into(),
            source_url_digest: "digest".into(),
            canonical_relative_destination: "notes.txt".into(),
            declared_filename: "notes.txt".into(),
            declared_media_type: "text/plain".into(),
            declared_size_bytes: 5,
            download_policy_revision: DOWNLOAD_POLICY_REVISION.into(),
            issued_at_ms: 1_000 + index,
            expires_at_ms: 1_000 + index + DOWNLOAD_SOURCE_TTL_MS,
            state: DOWNLOAD_SOURCE_PENDING.into(),
            download_id: String::new(),
            content_sha256: String::new(),
        }
    }

    fn seal_download_record(mut record: StoredDownload) -> StoredDownload {
        record.source_id = download_source_id_for(
            &record.workspace_id,
            &record.policy_revision,
            &record.profile_identity,
            &record.page_id,
            &record.origin,
            record.page_generation,
            record.document_generation,
            &record.source_origin,
            &record.source_url_digest,
            &record.canonical_relative_destination,
            &record.declared_media_type,
            record.declared_size_bytes,
            &record.download_policy_revision,
            record.issued_at_ms,
        );
        record
    }

    #[test]
    fn download_destination_validation_denies_escape_traversal_ads_device_and_reserved_names() {
        let (canonical, filename) = validate_download_relative_path("docs/notes.txt").expect("ok");
        assert_eq!(canonical, "docs/notes.txt");
        assert_eq!(filename, "notes.txt");
        let (mixed, mixed_name) = validate_download_relative_path("docs\\notes.txt").expect("ok");
        assert_eq!(mixed, "docs/notes.txt");
        assert_eq!(mixed_name, "notes.txt");

        for denied in [
            "C:\\Windows\\notes.txt",
            "\\\\server\\share\\notes.txt",
            "\\\\?\\C:\\notes.txt",
            "\\\\.\\C:\\notes.txt",
            "../escape.txt",
            "docs/../../escape.txt",
            "notes.txt:hidden",
            "CON.txt",
            "com1.txt",
            "LPT1",
            "NUL",
            "docs//notes.txt",
            "docs./notes.txt",
            "docs /notes.txt",
            "a<b.txt",
            "a|b.txt",
            "a*b.txt",
            "./notes.txt",
            "docs/./notes.txt",
            "docs/../notes.txt",
        ] {
            let error = validate_download_relative_path(denied).expect_err("must fail closed");
            assert_eq!(
                error.code,
                FailureCode::PathEscape,
                "{denied} must fail closed as a path escape"
            );
        }

        assert!(validate_download_relative_path("").is_err());
        assert!(validate_download_relative_path("notes\n.txt").is_err());
        let long_component = format!("{}.txt", "a".repeat(MAX_DOWNLOAD_COMPONENT_BYTES + 1));
        assert!(validate_download_relative_path(&long_component).is_err());
        let long_path = vec!["d".repeat(MAX_DOWNLOAD_COMPONENT_BYTES); 8].join("/");
        assert!(long_path.len() > MAX_DOWNLOAD_RELATIVE_BYTES);
        assert!(validate_download_relative_path(&long_path).is_err());
        assert!(is_reserved_device_name("con.txt"));
        assert!(is_reserved_device_name("AUX"));
        assert!(!is_reserved_device_name("console.txt"));
    }

    #[test]
    fn download_type_policy_denies_dangerous_extensions_and_unexpected_content() {
        for (name, expected) in [
            ("notes.txt", "text/plain"),
            ("notes.md", "text/markdown"),
            ("notes.csv", "text/csv"),
            ("notes.json", "application/json"),
            ("image.png", "image/png"),
            ("image.JPG", "image/jpeg"),
            ("image.jpeg", "image/jpeg"),
            ("image.gif", "image/gif"),
            ("image.webp", "image/webp"),
        ] {
            assert_eq!(
                download_media_type_for_filename(name).expect("allowlisted"),
                expected
            );
            assert!(is_allowed_download_media_type(expected));
        }
        for denied in [
            "tool.exe",
            "lib.dll",
            "run.bat",
            "cmd.cmd",
            "pkg.msi",
            "bundle.msix",
            "s.ps1",
            "s.vbs",
            "s.js",
            "a.zip",
            "a.7z",
            "a.tar",
            "a.iso",
            "link.lnk",
            "book.docm",
            "sheet.xlsm",
            "noextension",
            "data.bin",
            "shell.sh",
            "app.apk",
        ] {
            let error = download_media_type_for_filename(denied).expect_err("must fail closed");
            assert_eq!(
                error.code,
                FailureCode::CapabilityDenied,
                "{denied} must be denied"
            );
        }

        assert_eq!(
            sniff_download_media_type(b"MZ\x90\x00"),
            "application/x-msdownload"
        );
        assert_eq!(
            sniff_download_media_type(b"\x7fELF\x02"),
            "application/x-elf"
        );
        assert_eq!(
            sniff_download_media_type(b"\xcf\xfa\xed\xfe"),
            "application/x-mach-binary"
        );
        assert_eq!(
            sniff_download_media_type(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),
            "application/x-ole-storage"
        );
        assert_eq!(sniff_download_media_type(b"PK\x03\x04"), "application/zip");
        assert_eq!(
            sniff_download_media_type(b"#!/bin/sh\n"),
            "text/x-shellscript"
        );
        assert_eq!(sniff_download_media_type(b"%PDF-1.7"), "application/pdf");
        assert_eq!(sniff_download_media_type(b"hello\n"), "text/plain");
        assert_eq!(
            sniff_download_media_type(&[
                0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0
            ]),
            "image/png"
        );
        assert_eq!(
            sniff_download_media_type(&[0xff, 0xd8, 0xff, 0xe0]),
            "image/jpeg"
        );
        assert_eq!(sniff_download_media_type(b"GIF89a0000"), "image/gif");
        assert_eq!(sniff_download_media_type(b"RIFF____WEBPVP8 "), "image/webp");
        assert_eq!(
            sniff_download_media_type(&[0u8, 1, 2]),
            UNKNOWN_DOWNLOAD_MEDIA_TYPE
        );
        assert_eq!(sniff_download_media_type(b""), UNKNOWN_DOWNLOAD_MEDIA_TYPE);

        for payload in [
            &b"MZ\x90\x00"[..],
            &b"#!/bin/sh\n"[..],
            &b"PK\x03\x04"[..],
            &b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"[..],
            &b"\x7fELF\x02"[..],
            &b"%PDF-1.7"[..],
            &b"\xcf\xfa\xed\xfe"[..],
        ] {
            let sniffed = sniff_download_media_type(payload);
            assert!(
                !is_allowed_download_media_type(sniffed),
                "{sniffed} must never be an authorized download class"
            );
        }

        assert!(content_matches_declared_media_type(
            "text/plain",
            "text/plain"
        ));
        assert!(content_matches_declared_media_type(
            "text/markdown",
            "text/plain"
        ));
        assert!(content_matches_declared_media_type(
            "application/json",
            "text/plain"
        ));
        assert!(content_matches_declared_media_type(
            "image/png",
            "image/png"
        ));
        assert!(!content_matches_declared_media_type(
            "image/png",
            "text/plain"
        ));
        assert!(!content_matches_declared_media_type(
            "text/plain",
            "image/png"
        ));
    }

    #[test]
    fn download_base64_body_decoding_is_strict_and_bounded() {
        assert_eq!(decode_download_body("QQ==").expect("decode"), &b"A"[..]);
        assert_eq!(decode_download_body("QUI=").expect("decode"), &b"AB"[..]);
        assert_eq!(
            decode_download_body("aGVsbG8=").expect("decode"),
            &b"hello"[..]
        );
        assert_eq!(
            decode_download_body("aGVsbG8h").expect("decode"),
            &b"hello!"[..]
        );
        for denied in [
            "",
            "abc",
            "aGVsbG8",
            "aGVs bG8=",
            "====",
            "A===",
            "aGVsbG8=extra!",
            "****",
        ] {
            assert!(
                decode_download_body(denied).is_err(),
                "{denied} must fail closed"
            );
        }
        let oversized_body = "A".repeat(MAX_DOWNLOAD_BODY_BYTES + 4);
        assert!(decode_download_body(&oversized_body).is_err());
        let over_decoded_bound = "A".repeat(((MAX_DOWNLOAD_BYTES as usize) / 3 + 1) * 4);
        assert_eq!(
            decode_download_body(&over_decoded_bound).unwrap_err().code,
            FailureCode::OutputLimit
        );
    }

    #[test]
    fn download_source_identity_is_one_shot_expiring_and_drift_checked() {
        let page = download_test_page();
        let record = seal_download_record(download_test_record(0));
        assert!(record.source_id.starts_with(DOWNLOAD_SOURCE_PREFIX));
        check_download_source(&record, &page, "profile-a", "sg-000025-v1", 1, 1, 2_000)
            .expect("fresh one-shot source is usable");

        let stale_generation =
            check_download_source(&record, &page, "profile-a", "sg-000025-v1", 2, 1, 2_000)
                .expect_err("generation drift must fail closed");
        assert_eq!(stale_generation.code, FailureCode::TargetStale);
        let replaced_document =
            check_download_source(&record, &page, "profile-a", "sg-000025-v1", 1, 2, 2_000)
                .expect_err("document replacement must fail closed");
        assert_eq!(replaced_document.code, FailureCode::TargetStale);
        let foreign_profile =
            check_download_source(&record, &page, "profile-b", "sg-000025-v1", 1, 1, 2_000)
                .expect_err("foreign profile must fail closed");
        assert_eq!(foreign_profile.code, FailureCode::CapabilityDenied);
        let policy_drift =
            check_download_source(&record, &page, "profile-a", "sg-000024-v1", 1, 1, 2_000)
                .expect_err("policy drift must fail closed");
        assert_eq!(policy_drift.code, FailureCode::TargetStale);
        let expired = check_download_source(
            &record,
            &page,
            "profile-a",
            "sg-000025-v1",
            1,
            1,
            record.expires_at_ms + 1,
        )
        .expect_err("expired source must fail closed");
        assert_eq!(expired.code, FailureCode::TargetStale);

        let mut consumed = record.clone();
        consumed.state = DOWNLOAD_SOURCE_CONSUMED.into();
        let replayed =
            check_download_source(&consumed, &page, "profile-a", "sg-000025-v1", 1, 1, 2_000)
                .expect_err("consumed source must fail closed");
        assert_eq!(replayed.code, FailureCode::CapabilityDenied);

        let mut forged_destination = record.clone();
        forged_destination.canonical_relative_destination = "other.txt".into();
        assert_eq!(
            check_download_source(
                &forged_destination,
                &page,
                "profile-a",
                "sg-000025-v1",
                1,
                1,
                2_000
            )
            .unwrap_err()
            .code,
            FailureCode::TargetStale
        );

        let mut other_page = page.clone();
        other_page.page_id = "pg-2".into();
        assert_eq!(
            check_download_source(
                &record,
                &other_page,
                "profile-a",
                "sg-000025-v1",
                1,
                1,
                2_000
            )
            .unwrap_err()
            .code,
            FailureCode::TargetStale
        );
        let mut drifted_origin = page.clone();
        drifted_origin.current_origin = "https://other.example:443".into();
        assert_eq!(
            check_download_source(
                &record,
                &drifted_origin,
                "profile-a",
                "sg-000025-v1",
                1,
                1,
                2_000
            )
            .unwrap_err()
            .code,
            FailureCode::TargetStale
        );
        let mut closed_page = page.clone();
        closed_page.state = PageState::Closed;
        assert_eq!(
            check_download_source(
                &record,
                &closed_page,
                "profile-a",
                "sg-000025-v1",
                1,
                1,
                2_000
            )
            .unwrap_err()
            .code,
            FailureCode::TargetStale
        );
        let mut foreign_workspace = page.clone();
        foreign_workspace.workspace_id = "other".into();
        assert_eq!(
            check_download_source(
                &record,
                &foreign_workspace,
                "profile-a",
                "sg-000025-v1",
                1,
                1,
                2_000
            )
            .unwrap_err()
            .code,
            FailureCode::WorkspaceDenied
        );
    }

    #[test]
    fn download_registry_is_append_only_one_shot_and_bounded() {
        let path = temp_download_registry("store");
        let page = download_test_page();
        let mut store = DownloadStore::load_or_create(path.clone());
        assert!(store.get("dl-missing").is_none());
        assert_eq!(
            store.mark_consumed("dl-missing", "dn-1").unwrap_err().code,
            FailureCode::TargetStale
        );
        assert_eq!(store.pending_count("default"), 0);

        for index in 0..MAX_PENDING_DOWNLOADS_PER_WORKSPACE as u64 {
            store.record_pending(seal_download_record(download_test_record(index)));
        }
        assert_eq!(
            store.pending_count("default"),
            MAX_PENDING_DOWNLOADS_PER_WORKSPACE
        );

        let reloaded = DownloadStore::load_or_create(path.clone());
        assert_eq!(
            reloaded.pending_count("default"),
            MAX_PENDING_DOWNLOADS_PER_WORKSPACE
        );

        let mut store = DownloadStore::load_or_create(path.clone());
        let first = seal_download_record(download_test_record(0)).source_id;
        let source_id = store
            .get(&first)
            .map(|record| record.source_id.clone())
            .expect("recorded source");
        check_download_source(
            store.get(&source_id).expect("source"),
            &page,
            "profile-a",
            "sg-000025-v1",
            1,
            1,
            2_000,
        )
        .expect("pending source");
        store.mark_consumed(&source_id, "dn-test").expect("consume");
        assert_eq!(
            store.pending_count("default"),
            MAX_PENDING_DOWNLOADS_PER_WORKSPACE - 1
        );
        let spent = DownloadStore::load_or_create(path.clone());
        assert_eq!(
            spent.get(&source_id).expect("source").state,
            DOWNLOAD_SOURCE_CONSUMED
        );
        assert_eq!(
            check_download_source(
                spent.get(&source_id).expect("source"),
                &page,
                "profile-a",
                "sg-000025-v1",
                1,
                1,
                2_000
            )
            .unwrap_err()
            .code,
            FailureCode::CapabilityDenied
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn download_destination_write_is_create_only_and_root_bounded() {
        let root = temp_download_root("write");
        let resolved = resolve_download_root(&root).expect("root");
        assert!(path_is_within(&resolved, &resolved));
        assert!(!path_is_within(
            &resolved,
            &std::env::temp_dir().join("orcel-outside-the-workspace.txt")
        ));

        let destination =
            resolve_download_destination(&resolved, "notes.txt").expect("destination");
        assert!(path_is_within(&resolved, &destination));
        write_download_file(&resolved, &destination, b"hello").expect("write");
        assert_eq!(std::fs::read(&destination).expect("read"), &b"hello"[..]);

        assert_eq!(
            write_download_file(&resolved, &destination, b"other")
                .unwrap_err()
                .code,
            FailureCode::PostconditionFailed
        );
        assert_eq!(
            std::fs::read(&destination).expect("read"),
            &b"hello"[..],
            "an existing file must never be overwritten"
        );

        assert_eq!(
            resolve_download_destination(&resolved, "missing/notes.txt")
                .unwrap_err()
                .code,
            FailureCode::CapabilityDenied
        );

        std::fs::create_dir(resolved.join("docs")).expect("docs");
        let nested_destination =
            resolve_download_destination(&resolved, "docs/report.txt").expect("nested destination");
        assert!(path_is_within(&resolved, &nested_destination));
        write_download_file(&resolved, &nested_destination, b"report").expect("nested write");
        assert_eq!(
            std::fs::read(&nested_destination).expect("read"),
            &b"report"[..]
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn download_junction_escape_out_of_the_workspace_root_fails_closed() {
        let root = temp_download_root("junction-root");
        let outside = temp_download_root("junction-outside");
        let resolved = resolve_download_root(&root).expect("root");
        let link = resolved.join("escape");
        let output = std::process::Command::new("cmd")
            .args([
                "/c",
                "mklink",
                "/J",
                &link.to_string_lossy(),
                &outside.to_string_lossy(),
            ])
            .output()
            .expect("mklink runs");
        assert!(
            output.status.success(),
            "junction creation must succeed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(link.is_dir(), "the junction must resolve as a directory");
        let escaped = resolve_download_destination(&resolved, "escape/notes.txt")
            .expect_err("a reparse point must not extend the approved root");
        assert_eq!(escaped.code, FailureCode::PathEscape);
        assert!(!path_is_within(
            &resolved,
            &std::fs::canonicalize(&link).expect("canonical link")
        ));
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(outside);
    }

    #[cfg(unix)]
    #[test]
    fn download_symlink_escape_out_of_the_workspace_root_fails_closed() {
        let root = temp_download_root("symlink-root");
        let outside = temp_download_root("symlink-outside");
        let resolved = resolve_download_root(&root).expect("root");
        std::os::unix::fs::symlink(&outside, resolved.join("escape")).expect("symlink");
        let escaped = resolve_download_destination(&resolved, "escape/notes.txt")
            .expect_err("a symlink must not extend the approved root");
        assert_eq!(escaped.code, FailureCode::PathEscape);
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(outside);
    }

    #[test]
    fn download_evidence_and_preview_are_bounded_and_secret_free() {
        let preview = DownloadPreview {
            source_id: "dl-1".into(),
            page_id: "pg-1".into(),
            workspace_id: "default".into(),
            policy_revision: "sg-000025-v1".into(),
            profile_identity: "profile-a".into(),
            origin: "https://example.com:443".into(),
            page_generation: 1,
            document_generation: 1,
            source_origin: "https://example.com:443".into(),
            source_url_digest: "digest".into(),
            pinned_address: "93.184.216.34".parse().expect("address"),
            redirect_count: 0,
            declared_filename: "notes.txt".into(),
            declared_media_type: "text/plain".into(),
            canonical_relative_destination: "notes.txt".into(),
            destination_root_identity: "root-identity".into(),
            declared_size_bytes: 5,
            max_download_bytes: MAX_DOWNLOAD_BYTES,
            download_policy_revision: DOWNLOAD_POLICY_REVISION.into(),
            issued_at_ms: 1_000,
            expires_at_ms: 1_000 + DOWNLOAD_SOURCE_TTL_MS,
            preview_digest: "preview-digest".into(),
        };
        let json = preview.to_json();
        assert_eq!(json["executed"], false);
        assert_eq!(json["opened"], false);
        assert_eq!(json["extracted"], false);
        assert_eq!(json["cookies"], false);
        assert_eq!(json["credentials"], false);
        assert!(json.get("source_url").is_none());
        assert!(json.get("url").is_none());

        let evidence = DownloadEvidence {
            download_id: "dn-1".into(),
            source_id: "dl-1".into(),
            page_id: "pg-1".into(),
            workspace_id: "default".into(),
            policy_revision: "sg-000025-v1".into(),
            profile_identity: "profile-a".into(),
            origin: "https://example.com:443".into(),
            page_generation: 1,
            document_generation: 1,
            source_origin: "https://example.com:443".into(),
            source_url_digest: "digest".into(),
            canonical_relative_destination: "notes.txt".into(),
            destination_root_identity: "root-identity".into(),
            declared_filename: "notes.txt".into(),
            declared_media_type: "text/plain".into(),
            extension_media_type: "text/plain".into(),
            sniffed_media_type: "text/plain".into(),
            content_type_consistent: true,
            declared_size_bytes: 5,
            actual_size_bytes: 5,
            content_sha256: "content-digest".into(),
            download_policy_revision: DOWNLOAD_POLICY_REVISION.into(),
            state: DOWNLOAD_SOURCE_CONSUMED.into(),
        };
        let json = evidence.to_json("apr-1");
        assert_eq!(json["approval_record_id"], "apr-1");
        assert_eq!(json["content_type_consistent"], true);
        assert_eq!(json["executed"], false);
        assert_eq!(json["opened"], false);
        assert_eq!(json["extracted"], false);
        for forbidden in [
            "cookie",
            "password",
            "token",
            "authorization",
            "session",
            "content",
            "body",
            "content_base64",
            "source_url",
            "url",
        ] {
            assert!(
                json.get(forbidden).is_none(),
                "download evidence must not carry {forbidden}"
            );
        }
    }

    #[test]
    fn download_approval_digest_binds_destination_origin_source_size_and_content() {
        let base = download_approval_digest(
            "default",
            "sg-000025-v1",
            "profile-a",
            "pg-1",
            "https://example.com:443",
            1,
            1,
            "dl-1",
            "https://example.com:443",
            "notes.txt",
            "text/plain",
            5,
            "content-digest",
            DOWNLOAD_POLICY_REVISION,
        );
        let preview = download_approval_digest(
            "default",
            "sg-000025-v1",
            "profile-a",
            "pg-1",
            "https://example.com:443",
            1,
            1,
            "dl-1",
            "https://example.com:443",
            "notes.txt",
            "text/plain",
            5,
            "",
            DOWNLOAD_POLICY_REVISION,
        );
        assert_ne!(base, preview);
        for drifted in [
            download_approval_digest(
                "default",
                "sg-000025-v1",
                "profile-a",
                "pg-1",
                "https://example.com:443",
                1,
                1,
                "dl-1",
                "https://example.com:443",
                "other.txt",
                "text/plain",
                5,
                "content-digest",
                DOWNLOAD_POLICY_REVISION,
            ),
            download_approval_digest(
                "default",
                "sg-000025-v1",
                "profile-a",
                "pg-1",
                "https://example.com:443",
                1,
                1,
                "dl-1",
                "https://other.example:443",
                "notes.txt",
                "text/plain",
                5,
                "content-digest",
                DOWNLOAD_POLICY_REVISION,
            ),
            download_approval_digest(
                "default",
                "sg-000025-v1",
                "profile-a",
                "pg-1",
                "https://example.com:443",
                1,
                1,
                "dl-2",
                "https://example.com:443",
                "notes.txt",
                "text/plain",
                5,
                "content-digest",
                DOWNLOAD_POLICY_REVISION,
            ),
            download_approval_digest(
                "default",
                "sg-000025-v1",
                "profile-a",
                "pg-1",
                "https://example.com:443",
                1,
                1,
                "dl-1",
                "https://example.com:443",
                "notes.txt",
                "text/plain",
                6,
                "content-digest",
                DOWNLOAD_POLICY_REVISION,
            ),
            download_approval_digest(
                "default",
                "sg-000025-v1",
                "profile-a",
                "pg-1",
                "https://example.com:443",
                1,
                1,
                "dl-1",
                "https://example.com:443",
                "notes.txt",
                "image/png",
                5,
                "content-digest",
                DOWNLOAD_POLICY_REVISION,
            ),
        ] {
            assert_ne!(base, drifted);
        }
        assert!(
            download_id_for("dl-1", "notes.txt", "content-digest").starts_with(DOWNLOAD_ID_PREFIX)
        );
        assert_ne!(
            download_id_for("dl-1", "notes.txt", "content-digest"),
            download_id_for("dl-1", "notes.txt", "other-digest")
        );
    }

    /// XP-01B: the browser profile default resolves under the private per-user Orcel
    /// state root, fails closed without one, and never falls back to the
    /// shared temp directory. State earlier builds left under the shared temp
    /// directory is not migrated and is never read.
    mod xp01b {
        use super::*;
        use std::ffi::OsString;
        use std::path::{Path, PathBuf};

        fn resolve(lookup: &dyn Fn(&str) -> Option<OsString>) -> Result<PathBuf, String> {
            default_profile_root_from(lookup).map_err(|error| error.to_string())
        }

        fn lookup(vars: Vec<(&'static str, OsString)>) -> impl Fn(&str) -> Option<OsString> {
            move |name| {
                vars.iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| value.clone())
            }
        }

        fn sandbox(label: &str) -> PathBuf {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0);
            let dir = std::env::temp_dir().join(format!(
                "orcel-browser-xp01b-{label}-{}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(&dir).expect("sandbox");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                    .expect("chmod sandbox");
            }
            dir
        }

        fn user_root_env(base: &Path) -> Vec<(&'static str, OsString)> {
            #[cfg(windows)]
            let name = "LOCALAPPDATA";
            #[cfg(not(windows))]
            let name = "HOME";
            vec![(name, base.as_os_str().to_owned())]
        }

        #[test]
        fn default_resolves_under_the_private_root() {
            let base = sandbox("resolve");
            let lookup = lookup(user_root_env(&base));
            let root = orcel_platform::paths::state_root_from(&lookup).expect("root");
            let path = resolve(&lookup).expect("default");
            assert_eq!(path, root.join("browser-profile"));
            assert!(path.starts_with(&base));
            assert!(!path.starts_with(std::env::temp_dir().join("orcel")));
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&root).expect("root").permissions().mode();
                assert_eq!(mode & 0o777, 0o700);
            }
            let _ = std::fs::remove_dir_all(base);
        }

        #[test]
        fn missing_state_root_is_an_error_never_temp() {
            let error = resolve(&lookup(Vec::new())).expect_err("no root");
            assert!(error.contains("state root is unavailable"), "{error}");
        }

        #[test]
        fn relative_override_is_refused() {
            for value in ["", "browser-profile", "state/browser-profile"] {
                let error = resolve(&lookup(vec![(
                    "ORCEL_BROWSER_STATE_DIR",
                    OsString::from(value),
                )]))
                .expect_err("relative override");
                assert!(error.contains("is not absolute"), "{value:?}: {error}");
            }
        }

        #[cfg(windows)]
        #[test]
        fn windows_path_is_byte_identical_to_the_previous_default() {
            // A real directory: resolving creates the private state root
            // with an owner-only DACL (#358 item 2).
            let local = sandbox("windows-bytes");
            let path = resolve(&lookup(vec![(
                "LOCALAPPDATA",
                local.clone().into_os_string(),
            )]))
            .expect("default");
            assert_eq!(
                path.as_os_str(),
                format!(r"{}\Orcel\browser-profile", local.display()).as_str()
            );
            let _ = std::fs::remove_dir_all(local);
        }

        #[test]
        fn absolute_override_keeps_its_browser_profile_suffix_rule() {
            let base = sandbox("override");
            let custom = base.join("state");
            let path = resolve(&lookup(vec![(
                "ORCEL_BROWSER_STATE_DIR",
                custom.clone().into_os_string(),
            )]));
            assert_eq!(path, Ok(custom.join("browser-profile")));
            let exact = custom.join("browser-profile");
            let path = resolve(&lookup(vec![(
                "ORCEL_BROWSER_STATE_DIR",
                exact.clone().into_os_string(),
            )]));
            assert_eq!(path, Ok(exact));
            let _ = std::fs::remove_dir_all(base);
        }

        #[cfg(unix)]
        mod unix {
            use super::*;
            use std::os::unix::fs::PermissionsExt;

            fn chmod(path: &Path, mode: u32) {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
                    .expect("chmod");
            }

            /// The state root this OS's layout derives from `HOME=base`, with every
            /// directory between `base` and the root's parent created 0700.
            fn root_under(base: &Path) -> PathBuf {
                let root = orcel_platform::paths::state_root_from(&home_only(base)).expect("root");
                let parent = root.parent().expect("root parent");
                std::fs::create_dir_all(parent).expect("root parent");
                let mut dir = parent;
                while dir != base {
                    chmod(dir, 0o700);
                    dir = dir.parent().expect("below base");
                }
                root
            }

            fn home_only(base: &Path) -> impl Fn(&str) -> Option<OsString> {
                lookup(vec![("HOME", base.as_os_str().to_owned())])
            }

            #[test]
            fn symlinked_root_is_refused() {
                let base = sandbox("symlink");
                let target = base.join("elsewhere");
                std::fs::create_dir(&target).expect("target");
                chmod(&target, 0o700);
                std::os::unix::fs::symlink(&target, root_under(&base)).expect("symlink");
                let error = resolve(&home_only(&base)).expect_err("symlinked root");
                assert!(error.contains("is a symbolic link"), "{error}");
                assert_eq!(std::fs::read_dir(&target).expect("target").count(), 0);
                let _ = std::fs::remove_dir_all(base);
            }

            #[test]
            fn world_writable_root_is_refused_and_left_unrepaired() {
                let base = sandbox("writable-root");
                let root = root_under(&base);
                std::fs::create_dir(&root).expect("root");
                chmod(&root, 0o777);
                let error = resolve(&home_only(&base)).expect_err("writable root");
                assert!(error.contains("grants group or other access"), "{error}");
                let mode = std::fs::metadata(&root).expect("root").permissions().mode();
                assert_eq!(mode & 0o777, 0o777);
                let _ = std::fs::remove_dir_all(base);
            }

            /// An override gets the default location's guarantees: a parent other
            /// users can reach is refused.
            #[test]
            fn override_in_a_shared_directory_is_refused() {
                let base = sandbox("shared-override");
                chmod(&base, 0o755);
                let override_path = base.clone();
                let error = resolve(&lookup(vec![(
                    "ORCEL_BROWSER_STATE_DIR",
                    override_path.into_os_string(),
                )]))
                .expect_err("shared parent");
                assert!(error.contains("grants group or other access"), "{error}");
                let _ = std::fs::remove_dir_all(base);
            }

            #[test]
            fn world_writable_home_is_refused_before_anything_is_created() {
                let base = sandbox("writable-home");
                chmod(&base, 0o777);
                let error = resolve(&home_only(&base)).expect_err("writable home");
                assert!(error.contains("is writable by other users"), "{error}");
                assert_eq!(std::fs::read_dir(&base).expect("base").count(), 0);
                chmod(&base, 0o700);
                let _ = std::fs::remove_dir_all(base);
            }
        }
    }
}

/// SG-000026 scoped bounded browser upload tests, kept in their own module so
/// appending them can never realign this established test module in a diff.
#[cfg(test)]
mod sg000026_tests;
