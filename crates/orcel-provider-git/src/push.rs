use super::{GitProvider, GitProviderError};
use orcel_contracts::FailureCode;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub const PUSH_TRACKING_NAMESPACE: &str = "refs/remotes/orcel";
pub const PUSH_APPROVAL_VERSION: &str = "ORCEL_GIT_PUSH_APPROVAL_V1";
pub const ANONYMOUS_CREDENTIAL: &str = "anonymous";
const CREDENTIAL_ENV_PREFIX: &str = "ORCEL_GIT_CREDENTIAL_";
const PUSH_USERNAME: &str = "orcel";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitPushDestination {
    pub id: String,
    pub canonical_url: String,
    pub hostname: String,
    pub port: u16,
    pub credential_reference: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushPreview {
    pub repository_root: String,
    pub head: String,
    pub branch: Option<String>,
    pub policy_id: String,
    pub canonical_url: String,
    pub hostname: String,
    pub port: u16,
    pub source_branch: String,
    pub dest_branch: String,
    pub source_ref: String,
    pub destination_ref: String,
    pub source_id: String,
    pub prior: String,
    pub credential_reference: String,
}

impl PushPreview {
    pub fn to_json(&self) -> Value {
        json!({
            "repository_root": self.repository_root,
            "head": self.head,
            "branch": self.branch,
            "policy_id": self.policy_id,
            "canonical_url": self.canonical_url,
            "hostname": self.hostname,
            "port": self.port,
            "source_branch": self.source_branch,
            "dest_branch": self.dest_branch,
            "source_ref": self.source_ref,
            "destination_ref": self.destination_ref,
            "source_id": self.source_id,
            "prior": self.prior,
            "credential_reference": self.credential_reference,
            "credential_redacted": true,
        })
    }
}

#[derive(Clone)]
pub struct PushSecret {
    value: String,
}

impl PushSecret {
    pub fn new(value: String) -> Self {
        Self { value }
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.value
    }

    pub fn len(&self) -> usize {
        self.value.len()
    }

    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }
}

impl std::fmt::Display for PushSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("REDACTED")
    }
}

impl std::fmt::Debug for PushSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PushSecret(REDACTED)")
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedCredential {
    pub reference: String,
    pub secret: Option<PushSecret>,
}

impl ResolvedCredential {
    pub fn anonymous() -> Self {
        Self {
            reference: ANONYMOUS_CREDENTIAL.to_owned(),
            secret: None,
        }
    }

    pub fn is_anonymous(&self) -> bool {
        self.secret.is_none()
    }
}

pub trait CredentialResolver {
    fn resolve(&self, reference: &str) -> Result<ResolvedCredential, GitProviderError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct EnvCredentialResolver;

impl CredentialResolver for EnvCredentialResolver {
    fn resolve(&self, reference: &str) -> Result<ResolvedCredential, GitProviderError> {
        validate_credential_reference(reference)?;
        if reference == ANONYMOUS_CREDENTIAL {
            return Ok(ResolvedCredential::anonymous());
        }
        let name = credential_env_name(reference)?;
        match std::env::var(&name) {
            Ok(value) if !value.trim().is_empty() => Ok(ResolvedCredential {
                reference: reference.to_owned(),
                secret: Some(PushSecret::new(value)),
            }),
            _ => Err(GitProviderError::new(
                FailureCode::CapabilityDenied,
                format!(
                    "credential reference '{reference}' is not bound to a usable secret; push is denied"
                ),
            )),
        }
    }
}

pub fn credential_env_name(reference: &str) -> Result<String, GitProviderError> {
    validate_credential_reference(reference)?;
    if reference == ANONYMOUS_CREDENTIAL {
        return Err(invalid(
            "the anonymous credential reference has no backing environment variable",
        ));
    }
    let mut name = String::from(CREDENTIAL_ENV_PREFIX);
    for byte in reference.bytes() {
        if byte == b'-' {
            name.push('_');
        } else {
            name.push(byte.to_ascii_uppercase() as char);
        }
    }
    Ok(name)
}

pub fn validate_credential_reference(value: &str) -> Result<String, GitProviderError> {
    if value.is_empty() || value.len() > 64 {
        return Err(invalid(
            "Git push credential reference must contain 1..=64 characters and must be an opaque reference id, never a raw secret",
        ));
    }
    if value.contains("://")
        || value.contains('@')
        || value.contains('/')
        || value.contains('\\')
        || value.contains(':')
        || value.contains(' ')
        || value.contains('\t')
        || value.contains('\n')
        || value.contains('\r')
        || value.contains('\0')
    {
        return Err(invalid(
            "Git push credential reference must be an opaque reference id, never a raw secret, URL, or userinfo",
        ));
    }
    let bytes = value.as_bytes();
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return Err(invalid(
            "Git push credential reference must start with a lowercase letter or digit",
        ));
    }
    if !bytes
        .iter()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
    {
        return Err(invalid(
            "Git push credential reference must use only lowercase letters, digits, and hyphen",
        ));
    }
    if value.starts_with('-') || value.ends_with('-') || value.contains("--") {
        return Err(invalid(
            "Git push credential reference has an unsafe hyphen placement",
        ));
    }
    Ok(value.to_owned())
}

pub fn validate_push_policy_id(id: &str) -> Result<String, GitProviderError> {
    if id.is_empty() || id.len() > 64 {
        return Err(invalid(
            "Git push destination policy id must contain 1..=64 characters",
        ));
    }
    let bytes = id.as_bytes();
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return Err(invalid(
            "Git push destination policy id must start with a lowercase letter or digit",
        ));
    }
    if !bytes
        .iter()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
    {
        return Err(invalid(
            "Git push destination policy id must use only lowercase letters, digits, and hyphen",
        ));
    }
    if id.starts_with('-') || id.ends_with('-') || id.contains("--") {
        return Err(invalid(
            "Git push destination policy id has an unsafe hyphen placement",
        ));
    }
    Ok(id.to_owned())
}

pub fn validate_push_branch(branch: &str) -> Result<String, GitProviderError> {
    if branch.is_empty() || branch.len() > 255 {
        return Err(invalid("Git push branch is empty or too large"));
    }
    if branch == "refs" || branch.starts_with("refs/") {
        return Err(invalid(
            "Git push branch must be a short name, not a full ref",
        ));
    }
    if branch.bytes().any(|byte| {
        matches!(
            byte,
            0 | b'\n'
                | b'\r'
                | b'\t'
                | b' '
                | b'~'
                | b'^'
                | b':'
                | b'?'
                | b'*'
                | b'['
                | b'\\'
                | b'+'
        )
    }) {
        return Err(invalid("Git push branch contains unsafe characters"));
    }
    if branch.starts_with('-') || branch.starts_with('/') || branch.starts_with('.') {
        return Err(invalid("Git push branch has an unsafe leading component"));
    }
    if branch.ends_with('/') || branch.ends_with('.') || branch.ends_with(".lock") {
        return Err(invalid("Git push branch has an unsafe trailing component"));
    }
    if branch.contains("//") || branch.contains("/.") || branch.contains(".lock/") {
        return Err(invalid("Git push branch contains an unsafe path sequence"));
    }
    for component in branch.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(invalid(
                "Git push branch contains an empty or dot component",
            ));
        }
        if component.starts_with('.') || component.ends_with(".lock") {
            return Err(invalid("Git push branch component is unsafe"));
        }
        if component == "@" {
            return Err(invalid("Git push branch component is unsafe"));
        }
    }
    if branch.contains("..") || branch.contains("@{") {
        return Err(invalid("Git push branch contains an unsafe sequence"));
    }
    Ok(branch.to_owned())
}

pub fn push_source_ref(branch: &str) -> String {
    format!("refs/heads/{branch}")
}

pub fn push_destination_ref(branch: &str) -> String {
    format!("refs/heads/{branch}")
}

pub fn push_tracking_ref(policy_id: &str, branch: &str) -> String {
    format!("{PUSH_TRACKING_NAMESPACE}/{policy_id}/{branch}")
}

pub fn validate_push_canonical_url(url: &str) -> Result<(String, u16, String), GitProviderError> {
    if url.is_empty() || url.len() > 2048 {
        return Err(invalid("Git push destination URL is empty or too large"));
    }
    if url.contains('\0')
        || url.contains('\n')
        || url.contains('\r')
        || url.contains('\t')
        || url.contains(' ')
    {
        return Err(invalid(
            "Git push destination URL contains unsafe whitespace or control data",
        ));
    }
    let lower = url.to_ascii_lowercase();
    if !lower.starts_with("https://") {
        return Err(invalid(
            "Git push destination URL must use the https scheme",
        ));
    }
    let rest = &url["https://".len()..];
    if rest.is_empty() {
        return Err(invalid("Git push destination URL is missing a hostname"));
    }
    if rest.contains('@') {
        return Err(invalid(
            "Git push destination URL must not contain userinfo or embedded credentials",
        ));
    }
    if rest.contains('?') {
        return Err(invalid("Git push destination URL must not contain a query"));
    }
    if rest.contains('#') {
        return Err(invalid(
            "Git push destination URL must not contain a fragment",
        ));
    }
    if rest.contains('\\') {
        return Err(invalid(
            "Git push destination URL must not contain a backslash",
        ));
    }
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return Err(invalid("Git push destination URL is missing a hostname"));
    }
    if path.is_empty() || !path.starts_with('/') {
        return Err(invalid("Git push destination URL path is invalid"));
    }
    if path.contains("/..") || path.contains("/./") || path.ends_with("/.") {
        return Err(invalid(
            "Git push destination URL path contains an unsafe sequence",
        ));
    }
    let (hostname_part, port) = match authority.rfind(':') {
        Some(index) => {
            let host = &authority[..index];
            let port_text = &authority[index + 1..];
            if port_text.is_empty() {
                return Err(invalid("Git push destination URL has an empty port"));
            }
            if !port_text.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(invalid("Git push destination URL port must be numeric"));
            }
            let port: u16 = port_text
                .parse()
                .map_err(|_| invalid("Git push destination URL port is invalid"))?;
            if port != 443 {
                return Err(invalid(
                    "Git push destination URL must use implicit or explicit port 443 only",
                ));
            }
            (host, port)
        }
        None => (authority, 443u16),
    };
    if hostname_part.is_empty() || hostname_part.len() > 253 {
        return Err(invalid(
            "Git push destination hostname is empty or too large",
        ));
    }
    if hostname_part.contains(':') {
        return Err(invalid(
            "Git push destination hostname must be a DNS hostname, not a literal address",
        ));
    }
    validate_push_dns_hostname(hostname_part)?;
    let hostname_lower = hostname_part.to_ascii_lowercase();
    let canonical = if port == 443 && !authority.contains(':') {
        format!("https://{hostname_lower}{path}")
    } else {
        format!("https://{hostname_lower}:443{path}")
    };
    Ok((hostname_lower, 443u16, canonical))
}

fn validate_push_dns_hostname(hostname: &str) -> Result<(), GitProviderError> {
    if hostname.len() > 253 {
        return Err(invalid("Git push destination hostname is too large"));
    }
    if hostname.starts_with('-')
        || hostname.starts_with('.')
        || hostname.ends_with('-')
        || hostname.ends_with('.')
    {
        return Err(invalid(
            "Git push destination hostname has an unsafe leading or trailing character",
        ));
    }
    if hostname.contains("..") {
        return Err(invalid(
            "Git push destination hostname contains an empty label",
        ));
    }
    let has_dot = hostname.contains('.');
    let mut has_alpha = false;
    for label in hostname.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(invalid(
                "Git push destination hostname label is empty or too large",
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(invalid(
                "Git push destination hostname label has an unsafe hyphen",
            ));
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(invalid(
                "Git push destination hostname label uses unsafe characters",
            ));
        }
        has_alpha = has_alpha || label.bytes().any(|byte| byte.is_ascii_alphabetic());
    }
    if !has_dot {
        return Err(invalid(
            "Git push destination hostname must be a dotted DNS hostname",
        ));
    }
    if !has_alpha {
        return Err(invalid(
            "Git push destination hostname must contain at least one letter",
        ));
    }
    if hostname.parse::<IpAddr>().is_ok() {
        return Err(invalid(
            "Git push destination hostname must be a DNS hostname, not a literal address",
        ));
    }
    Ok(())
}

pub fn validate_push_expected_head(value: &str) -> Result<(), GitProviderError> {
    if value.len() != 40
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(invalid(
            "Git push expected_head must be an exact lowercase 40-hex object id",
        ));
    }
    Ok(())
}

pub fn validate_push_expected_prior(value: &str) -> Result<(), GitProviderError> {
    if value == super::fetch::PRIOR_ABSENT {
        return Ok(());
    }
    validate_push_expected_head(value).map_err(|_| {
        invalid("Git push expected_prior must be a lowercase 40-hex object id or ABSENT")
    })
}

pub fn parse_push_destination(
    id: &str,
    url: &str,
    credential_reference: &str,
) -> Result<GitPushDestination, GitProviderError> {
    let policy_id = validate_push_policy_id(id)?;
    let credential = validate_credential_reference(credential_reference)?;
    let (hostname, port, canonical) = validate_push_canonical_url(url)?;
    Ok(GitPushDestination {
        id: policy_id,
        canonical_url: canonical,
        hostname,
        port,
        credential_reference: credential,
    })
}

pub fn select_pinned_push_address(addresses: &[IpAddr]) -> Result<IpAddr, GitProviderError> {
    super::fetch::select_pinned_address(addresses)
        .map_err(|error| GitProviderError::new(error.code, error.message.replace("fetch", "push")))
}

pub fn redact_secret_text(text: &str, secret: Option<&PushSecret>) -> String {
    match secret {
        Some(value) if !value.as_str().is_empty() => text.replace(value.as_str(), "REDACTED"),
        _ => text.to_owned(),
    }
}

pub fn build_child_env(askpass: Option<&Path>) -> Vec<(String, String)> {
    let mut env = Vec::new();
    for name in [
        "PATH",
        "Path",
        "PATHEXT",
        "SystemRoot",
        "WINDIR",
        "TEMP",
        "TMP",
    ] {
        if let Some(value) = std::env::var_os(name) {
            env.push((name.to_owned(), value.to_string_lossy().into_owned()));
        }
    }
    env.push(("NO_PROXY".to_owned(), "*".to_owned()));
    env.push(("no_proxy".to_owned(), "*".to_owned()));
    if let Some(path) = askpass {
        env.push((
            "GIT_ASKPASS".to_owned(),
            path.to_string_lossy().into_owned(),
        ));
    }
    env
}

// libcurl opens this path itself and has no `/dev/null` mapping.
#[cfg(windows)]
fn push_cookie_file() -> &'static str {
    "NUL"
}

#[cfg(not(windows))]
fn push_cookie_file() -> &'static str {
    "/dev/null"
}

pub fn build_push_argv(
    url: &str,
    hostname: &str,
    port: u16,
    pinned: &IpAddr,
    source_ref: &str,
    dest_ref: &str,
) -> Vec<String> {
    let resolve_value = format!("+{hostname}:{port}:{pinned}");
    let refspec = format!("{source_ref}:{dest_ref}");
    let cookie_file = push_cookie_file();
    vec![
        "-c".to_owned(),
        "protocol.https.allow=always".to_owned(),
        "-c".to_owned(),
        "protocol.http.allow=never".to_owned(),
        "-c".to_owned(),
        "protocol.ssh.allow=never".to_owned(),
        "-c".to_owned(),
        "protocol.git.allow=never".to_owned(),
        "-c".to_owned(),
        "protocol.file.allow=never".to_owned(),
        "-c".to_owned(),
        "protocol.ext.allow=never".to_owned(),
        "-c".to_owned(),
        "http.followRedirects=false".to_owned(),
        "-c".to_owned(),
        "http.sslVerify=true".to_owned(),
        "-c".to_owned(),
        "http.proxy=".to_owned(),
        "-c".to_owned(),
        "https.proxy=".to_owned(),
        "-c".to_owned(),
        format!("http.cookieFile={cookie_file}"),
        "-c".to_owned(),
        "http.saveCookies=false".to_owned(),
        "-c".to_owned(),
        "credential.helper=".to_owned(),
        "-c".to_owned(),
        "core.askPass=".to_owned(),
        "-c".to_owned(),
        format!("http.curloptResolve={resolve_value}"),
        "push".to_owned(),
        "--no-recurse-submodules".to_owned(),
        "--no-verify".to_owned(),
        url.to_owned(),
        refspec,
    ]
}

pub fn build_ls_remote_argv(
    url: &str,
    hostname: &str,
    port: u16,
    pinned: &IpAddr,
    dest_ref: &str,
) -> Vec<String> {
    let resolve_value = format!("+{hostname}:{port}:{pinned}");
    let cookie_file = push_cookie_file();
    vec![
        "-c".to_owned(),
        "protocol.https.allow=always".to_owned(),
        "-c".to_owned(),
        "protocol.http.allow=never".to_owned(),
        "-c".to_owned(),
        "protocol.ssh.allow=never".to_owned(),
        "-c".to_owned(),
        "protocol.git.allow=never".to_owned(),
        "-c".to_owned(),
        "protocol.file.allow=never".to_owned(),
        "-c".to_owned(),
        "protocol.ext.allow=never".to_owned(),
        "-c".to_owned(),
        "http.followRedirects=false".to_owned(),
        "-c".to_owned(),
        "http.sslVerify=true".to_owned(),
        "-c".to_owned(),
        "http.proxy=".to_owned(),
        "-c".to_owned(),
        "https.proxy=".to_owned(),
        "-c".to_owned(),
        format!("http.cookieFile={cookie_file}"),
        "-c".to_owned(),
        "http.saveCookies=false".to_owned(),
        "-c".to_owned(),
        "credential.helper=".to_owned(),
        "-c".to_owned(),
        "core.askPass=".to_owned(),
        "-c".to_owned(),
        format!("http.curloptResolve={resolve_value}"),
        "ls-remote".to_owned(),
        url.to_owned(),
        dest_ref.to_owned(),
    ]
}

pub fn assert_no_force_or_delete_semantics(argv: &[String]) -> Result<(), GitProviderError> {
    for arg in argv {
        let lower = arg.to_ascii_lowercase();
        for denied in [
            "--force",
            "--delete",
            "--all",
            "--mirror",
            "--tags",
            "--follow-tags",
            "--prune",
            "--exec",
            "--receive-pack",
            "--upload-pack",
        ] {
            if lower == denied || lower.starts_with(&format!("{denied}=")) {
                return Err(GitProviderError::new(
                    FailureCode::InternalError,
                    format!("hardened Git push argv must never contain {denied}"),
                ));
            }
        }
    }
    let refspecs: Vec<&String> = argv
        .iter()
        .filter(|arg| {
            arg.starts_with("refs/heads/")
                && arg.contains(':')
                && !arg.starts_with('-')
                && !arg.contains('=')
        })
        .collect();
    if refspecs.len() != 1 {
        return Err(GitProviderError::new(
            FailureCode::InternalError,
            "hardened Git push must carry exactly one explicit source:destination refspec",
        ));
    }
    let refspec = refspecs[0];
    if refspec.starts_with('+')
        || refspec.contains('*')
        || refspec.contains('^')
        || refspec.contains("--delete")
    {
        return Err(GitProviderError::new(
            FailureCode::InternalError,
            "hardened Git push refspec must be an exact non-force source:destination pair",
        ));
    }
    let parts: Vec<&str> = refspec.split(':').collect();
    if parts.len() != 2 {
        return Err(GitProviderError::new(
            FailureCode::InternalError,
            "hardened Git push refspec must be exactly source:destination",
        ));
    }
    Ok(())
}

struct DisabledPushHooksDir(PathBuf);

impl DisabledPushHooksDir {
    fn create() -> Result<Self, GitProviderError> {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| {
                provider_error(format!("read clock for push hooks isolation: {error}"))
            })?
            .as_nanos();
        for attempt in 0..16u32 {
            let path = std::env::temp_dir().join(format!(
                "orcel-git-push-no-hooks-{}-{nonce}-{attempt}",
                std::process::id()
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => {
                    let path = std::fs::canonicalize(&path).map_err(|error| {
                        provider_error(format!(
                            "canonicalize push disabled hooks directory: {error}"
                        ))
                    })?;
                    return Ok(Self(path));
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(provider_error(format!(
                        "create push disabled hooks directory: {error}"
                    )))
                }
            }
        }
        Err(provider_error(
            "could not allocate a unique push disabled hooks directory",
        ))
    }
}

impl Drop for DisabledPushHooksDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(&self.0);
    }
}

/// Creates `path` exclusively, owner-only from the first instant (mode 0700 on
/// Unix; on Windows it inherits the per-user temp ACL, as the XP-01B state
/// files do). It fails if the path exists.
fn create_private_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new().mode(0o700).create(path)
    }
    #[cfg(not(unix))]
    {
        std::fs::DirBuilder::new().create(path)
    }
}

/// Writes a new file that is never readable by anyone else: created
/// exclusively with `mode` in the same call (no write-then-chmod window).
fn create_private_file(path: &Path, mode: u32, content: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut file = options.open(path)?;
    file.write_all(content)
}

static ASKPASS_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Creates a fresh, exclusively owned credential directory. The name carries a
/// process-wide sequence so concurrent callers never draw the same name even on
/// clocks with microsecond resolution, and `create_dir` (never
/// `create_dir_all`) fails on an existing directory so one is never reused.
fn create_exclusive_askpass_dir() -> Result<PathBuf, GitProviderError> {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| provider_error(format!("read clock for credential isolation: {error}")))?
        .as_nanos();
    for _ in 0..16u32 {
        let sequence = ASKPASS_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "orcel-git-push-askpass-{}-{nonce}-{sequence}",
            std::process::id()
        ));
        match create_private_dir(&dir) {
            Ok(()) => return Ok(dir),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(provider_error(format!(
                    "create credential isolation directory: {error}"
                )))
            }
        }
    }
    Err(provider_error(
        "could not allocate a unique credential isolation directory",
    ))
}

pub struct ProtectedAskpass {
    dir: PathBuf,
    script: PathBuf,
}

impl ProtectedAskpass {
    pub fn create(secret: &PushSecret) -> Result<Self, GitProviderError> {
        if secret.is_empty() {
            return Err(invalid("protected credential material must not be empty"));
        }
        let dir = create_exclusive_askpass_dir()?;
        let dir = std::fs::canonicalize(&dir).map_err(|error| {
            provider_error(format!(
                "canonicalize credential isolation directory: {error}"
            ))
        })?;
        let secret_path = dir.join("secret");
        create_private_file(&secret_path, 0o600, secret.as_str().as_bytes()).map_err(|error| {
            provider_error(format!("stage protected credential material: {error}"))
        })?;
        #[cfg(windows)]
        let script = dir.join("askpass.bat");
        #[cfg(not(windows))]
        let script = dir.join("askpass.sh");
        let content = askpass_script_content(&secret_path);
        create_private_file(&script, 0o700, content.as_bytes())
            .map_err(|error| provider_error(format!("stage protected askpass helper: {error}")))?;
        Ok(Self { dir, script })
    }

    pub fn path(&self) -> &Path {
        &self.script
    }

    pub fn directory(&self) -> &Path {
        &self.dir
    }
}

impl Drop for ProtectedAskpass {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.dir.join("secret"));
        let _ = std::fs::remove_file(&self.script);
        let _ = std::fs::remove_dir(&self.dir);
    }
}

fn askpass_script_content(secret_path: &Path) -> String {
    let display = secret_path.to_string_lossy();
    #[cfg(windows)]
    {
        format!(
            "@echo off\r\nsetlocal\r\necho %1 | findstr /C:\"Username\" >nul\r\nif not errorlevel 1 (\r\n  echo {PUSH_USERNAME}\r\n) else (\r\n  type \"{display}\"\r\n)\r\n"
        )
    }
    #[cfg(not(windows))]
    {
        format!(
            "#!/bin/sh\ncase \"$1\" in\n  *Username*) printf '%s' '{PUSH_USERNAME}' ;;\n  *) cat \"{display}\" ;;\nesac\n"
        )
    }
}

pub struct RemoteQuery<'a> {
    pub repo: &'a Path,
    pub url: &'a str,
    pub hostname: &'a str,
    pub port: u16,
    pub pinned: &'a IpAddr,
    pub dest_ref: &'a str,
    pub credential: &'a ResolvedCredential,
}

pub struct PushOperation<'a> {
    pub repo: &'a Path,
    pub url: &'a str,
    pub hostname: &'a str,
    pub port: u16,
    pub pinned: &'a IpAddr,
    pub source_ref: &'a str,
    pub dest_ref: &'a str,
    pub credential: &'a ResolvedCredential,
}

pub trait PushTransport {
    fn query_remote_ref(&self, query: &RemoteQuery<'_>) -> Result<String, GitProviderError>;

    fn send_push(&self, operation: &PushOperation<'_>) -> Result<(), GitProviderError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct HardenedPushTransport;

impl PushTransport for HardenedPushTransport {
    fn query_remote_ref(&self, query: &RemoteQuery<'_>) -> Result<String, GitProviderError> {
        let argv = build_ls_remote_argv(
            query.url,
            query.hostname,
            query.port,
            query.pinned,
            query.dest_ref,
        );
        let output = run_push_network_command(
            query.repo,
            &argv,
            query.credential,
            std::time::Duration::from_secs(60),
        )
        .map_err(|error| {
            GitProviderError::new(
                error.code,
                redact_secret_text(&error.message, query.credential.secret.as_ref()),
            )
        })?;
        parse_ls_remote_ref(&output, query.dest_ref)
    }

    fn send_push(&self, operation: &PushOperation<'_>) -> Result<(), GitProviderError> {
        let argv = build_push_argv(
            operation.url,
            operation.hostname,
            operation.port,
            operation.pinned,
            operation.source_ref,
            operation.dest_ref,
        );
        assert_no_force_or_delete_semantics(&argv)?;
        let hooks = DisabledPushHooksDir::create()?;
        let mut full = vec![
            "-c".to_owned(),
            format!("core.hooksPath={}", hooks.0.to_string_lossy()),
        ];
        full.extend(argv);
        let refs: Vec<&str> = full.iter().map(String::as_str).collect();
        run_push_raw(
            operation.repo,
            &refs,
            operation.credential,
            std::time::Duration::from_secs(120),
        )
        .map(|_| ())
        .map_err(|error| {
            let redacted = redact_secret_text(&error.message, operation.credential.secret.as_ref());
            map_push_stderr(&redacted)
        })
    }
}

fn map_push_stderr(message: &str) -> GitProviderError {
    let lower = message.to_ascii_lowercase();
    if lower.contains("non-fast-forward")
        || lower.contains("fetch first")
        || lower.contains("failed to push some refs")
        || (lower.contains("[rejected]") && lower.contains("(non-fast-forward)"))
    {
        return GitProviderError::new(
            FailureCode::TargetStale,
            format!(
                "remote destination ref advanced; push rejected as non-fast-forward: {message}"
            ),
        );
    }
    GitProviderError::new(
        FailureCode::ProviderUnavailable,
        format!("hardened git push failed: {message}"),
    )
}

fn parse_ls_remote_ref(output: &str, dest_ref: &str) -> Result<String, GitProviderError> {
    for line in output.lines() {
        let mut parts = line.split_whitespace();
        let id = parts.next().unwrap_or("");
        let name = parts.next().unwrap_or("");
        if name == dest_ref {
            if id.len() == 40
                && id.bytes().all(|byte| byte.is_ascii_hexdigit())
                && id.bytes().all(|byte| !byte.is_ascii_uppercase())
            {
                return Ok(id.to_owned());
            }
            return Err(provider_error(
                "remote destination returned an invalid object id",
            ));
        }
    }
    Ok(super::fetch::PRIOR_ABSENT.to_owned())
}

fn run_push_network_command(
    repo: &Path,
    argv: &[String],
    credential: &ResolvedCredential,
    timeout: std::time::Duration,
) -> Result<String, GitProviderError> {
    let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
    run_push_raw(repo, &refs, credential, timeout)
}

fn run_push_raw(
    repo: &Path,
    args: &[&str],
    credential: &ResolvedCredential,
    timeout: std::time::Duration,
) -> Result<String, GitProviderError> {
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::Instant;

    let askpass = match credential.secret.as_ref() {
        Some(secret) => Some(ProtectedAskpass::create(secret)?),
        None => None,
    };
    let mut command = Command::new("git");
    command
        .args(["-c", "core.fsmonitor=false", "-c", "core.pager=cat"])
        .args(args)
        .current_dir(repo)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear();
    for (name, value) in build_child_env(askpass.as_ref().map(|helper| helper.path())) {
        command.env(name, value);
    }
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", crate::NULL_GIT_CONFIG)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_PAGER", "cat")
        .env("GIT_EDITOR", null_push_device())
        .env("GIT_SEQUENCE_EDITOR", null_push_device())
        .env("GIT_ALLOW_PROTOCOL", "https")
        .env("GCM_INTERACTIVE", "Never")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_SSH_COMMAND", null_push_device())
        .env("GIT_SSL_NO_VERIFY", "0");

    let mut child = command.spawn().map_err(|error| {
        GitProviderError::new(
            FailureCode::ProviderUnavailable,
            format!("start hardened git push transport: {error}"),
        )
    })?;
    let stdout = child.stdout.take().ok_or_else(|| {
        GitProviderError::new(
            FailureCode::ProviderUnavailable,
            "hardened git push stdout unavailable",
        )
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        GitProviderError::new(
            FailureCode::ProviderUnavailable,
            "hardened git push stderr unavailable",
        )
    })?;
    let stdout_thread = thread::spawn(move || super::read_bounded_for_fetch(stdout));
    let stderr_thread = thread::spawn(move || super::read_bounded_for_fetch(stderr));
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {
                thread::sleep(std::time::Duration::from_millis(25));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_thread.join();
                let _ = stderr_thread.join();
                return Err(GitProviderError::new(
                    FailureCode::ProviderUnavailable,
                    "hardened git push transport exceeded its timeout",
                ));
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_thread.join();
                let _ = stderr_thread.join();
                return Err(GitProviderError::new(
                    FailureCode::ProviderUnavailable,
                    format!("wait for hardened git push transport: {error}"),
                ));
            }
        }
    };
    let (stdout_bytes, _) = stdout_thread.join().map_err(|_| {
        GitProviderError::new(
            FailureCode::InternalError,
            "hardened git push stdout reader panicked",
        )
    })??;
    let (stderr_bytes, _) = stderr_thread.join().map_err(|_| {
        GitProviderError::new(
            FailureCode::InternalError,
            "hardened git push stderr reader panicked",
        )
    })??;
    let stdout_text = String::from_utf8_lossy(&stdout_bytes).into_owned();
    let stderr_text = String::from_utf8_lossy(&stderr_bytes).into_owned();
    if !status.success() {
        let detail: String = stderr_text.trim().chars().take(500).collect();
        return Err(GitProviderError::new(
            FailureCode::ProviderUnavailable,
            format!("hardened git push transport failed: {detail}"),
        ));
    }
    Ok(stdout_text)
}

#[cfg(windows)]
fn null_push_device() -> std::ffi::OsString {
    std::ffi::OsString::from("NUL")
}

#[cfg(not(windows))]
fn null_push_device() -> std::ffi::OsString {
    std::ffi::OsString::from("/dev/null")
}

#[derive(Debug, Clone, Copy)]
pub struct ApprovedPush<'a> {
    pub relative: &'a str,
    pub destination: &'a GitPushDestination,
    pub source_branch: &'a str,
    pub dest_branch: &'a str,
    pub expected_head: &'a str,
    pub expected_prior: &'a str,
    pub credential_reference: &'a str,
    pub pinned: &'a IpAddr,
}

impl GitProvider {
    pub fn push_preview(
        &self,
        relative: &str,
        destination: &GitPushDestination,
        source_branch: &str,
        dest_branch: &str,
        credential_reference: &str,
    ) -> Result<PushPreview, GitProviderError> {
        let validated_source = validate_push_branch(source_branch)?;
        let validated_dest = validate_push_branch(dest_branch)?;
        let validated_credential = validate_credential_reference(credential_reference)?;
        if validated_credential != destination.credential_reference {
            return Err(GitProviderError::new(
                FailureCode::CapabilityDenied,
                "Git push credential reference does not match the configured push destination",
            ));
        }
        let repo = self.repository_root(relative)?;
        let head = self.push_preview_head(&repo)?;
        let branch = self.push_preview_branch(&repo)?;
        let source_ref = push_source_ref(&validated_source);
        let destination_ref = push_destination_ref(&validated_dest);
        let source_id = self.push_ref_id(&repo, &source_ref)?;
        let tracking = push_tracking_ref(&destination.id, &validated_dest);
        let prior = self.push_tracking_prior(&repo, &tracking)?;
        Ok(PushPreview {
            repository_root: self.relative_display(&repo),
            head,
            branch,
            policy_id: destination.id.clone(),
            canonical_url: destination.canonical_url.clone(),
            hostname: destination.hostname.clone(),
            port: destination.port,
            source_branch: validated_source,
            dest_branch: validated_dest,
            source_ref,
            destination_ref,
            source_id,
            prior,
            credential_reference: validated_credential,
        })
    }

    fn push_preview_head(&self, repo: &Path) -> Result<String, GitProviderError> {
        let output = self.run_git(repo, &["rev-parse", "--verify", "HEAD"])?;
        let value = output.stdout.trim().to_owned();
        if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(provider_error("Git returned an invalid HEAD object id"));
        }
        Ok(value.to_ascii_lowercase())
    }

    fn push_preview_branch(&self, repo: &Path) -> Result<Option<String>, GitProviderError> {
        let output = self.run_git(repo, &["branch", "--show-current"])?;
        let branch = output.stdout.trim().to_owned();
        Ok((!branch.is_empty()).then_some(branch))
    }

    fn push_ref_id(&self, repo: &Path, full_ref: &str) -> Result<String, GitProviderError> {
        let output = self
            .run_git(repo, &["rev-parse", "--verify", full_ref])
            .map_err(|_| {
                invalid(format!(
                    "Git push source ref {full_ref} does not exist in the local repository"
                ))
            })?;
        let value = output.stdout.trim().to_owned();
        if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(provider_error(
                "Git returned an invalid source-ref object id",
            ));
        }
        Ok(value.to_ascii_lowercase())
    }

    fn push_tracking_prior(&self, repo: &Path, tracking: &str) -> Result<String, GitProviderError> {
        match self.run_git(repo, &["rev-parse", "--verify", tracking]) {
            Ok(value) => {
                let id = value.stdout.trim().to_owned();
                if id.len() != 40 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return Err(provider_error(
                        "Git returned an invalid push tracking object id",
                    ));
                }
                Ok(id.to_ascii_lowercase())
            }
            Err(_) => Ok(super::fetch::PRIOR_ABSENT.to_owned()),
        }
    }

    pub fn push_approved(
        &self,
        args: &ApprovedPush<'_>,
        resolver: &impl super::fetch::DnsResolver,
        credential_resolver: &impl CredentialResolver,
        transport: &impl PushTransport,
    ) -> Result<Value, GitProviderError> {
        let relative = args.relative;
        let destination = args.destination;
        let source_branch = args.source_branch;
        let dest_branch = args.dest_branch;
        let expected_head = args.expected_head;
        let expected_prior = args.expected_prior;
        let credential_reference = args.credential_reference;
        let pinned = args.pinned;
        let validated_source = validate_push_branch(source_branch)?;
        let validated_dest = validate_push_branch(dest_branch)?;
        let validated_credential = validate_credential_reference(credential_reference)?;
        if validated_credential != destination.credential_reference {
            return Err(GitProviderError::new(
                FailureCode::CapabilityDenied,
                "Git push credential reference does not match the configured push destination",
            ));
        }
        if args_policy_mismatch(destination, source_branch, dest_branch) {
            return Err(invalid("Git push branch binding is invalid"));
        }
        validate_push_expected_head(expected_head)?;
        validate_push_expected_prior(expected_prior)?;
        if !super::fetch::is_public_address(pinned) {
            return Err(GitProviderError::new(
                FailureCode::CapabilityDenied,
                "pinned push destination address is not public; push is denied",
            ));
        }
        let repo = self.repository_root(relative)?;
        self.reject_unsafe_local_push_config(&repo)?;
        self.ensure_supported_push_state(&repo)?;
        let preview = self.push_preview(
            relative,
            destination,
            &validated_source,
            &validated_dest,
            &validated_credential,
        )?;
        if preview.head != expected_head {
            return Err(GitProviderError::new(
                FailureCode::TargetStale,
                "Git HEAD changed after push preview; push is denied",
            ));
        }
        if preview.prior != expected_prior {
            return Err(GitProviderError::new(
                FailureCode::TargetStale,
                "push tracking state changed after push preview; push is denied",
            ));
        }
        let fresh = resolver.resolve(&destination.hostname).map_err(|error| {
            GitProviderError::new(
                error.code,
                format!(
                    "re-resolve push destination after approval: {}",
                    error.message
                ),
            )
        })?;
        if !fresh.contains(pinned) {
            return Err(GitProviderError::new(
                FailureCode::TargetStale,
                "push destination addresses changed after approval; push is denied",
            ));
        }
        let pinned_now = select_pinned_push_address(&fresh)?;
        if pinned_now != *pinned {
            return Err(GitProviderError::new(
                FailureCode::TargetStale,
                "pinned push destination address drifted after approval; push is denied",
            ));
        }
        if destination.canonical_url.is_empty() {
            return Err(invalid("Git push destination URL is empty"));
        }
        let credential = credential_resolver
            .resolve(&validated_credential)
            .map_err(|error| {
                GitProviderError::new(error.code, redact_secret_text(&error.message, None))
            })?;
        if credential.reference != validated_credential {
            return Err(GitProviderError::new(
                FailureCode::TargetStale,
                "credential binding changed after approval; push is denied",
            ));
        }
        let before_head = preview.head.clone();
        let before_branch = preview.branch.clone();
        let before_status = self.push_worktree_status(&repo)?;
        let remote_actual = transport
            .query_remote_ref(&RemoteQuery {
                repo: &repo,
                url: &destination.canonical_url,
                hostname: &destination.hostname,
                port: destination.port,
                pinned,
                dest_ref: &preview.destination_ref,
                credential: &credential,
            })
            .map_err(|error| {
                GitProviderError::new(
                    error.code,
                    redact_secret_text(&error.message, credential.secret.as_ref()),
                )
            })?;
        if remote_actual != expected_prior {
            return Err(GitProviderError::new(
                FailureCode::TargetStale,
                "remote destination ref changed after push preview; push is denied",
            ));
        }
        transport
            .send_push(&PushOperation {
                repo: &repo,
                url: &destination.canonical_url,
                hostname: &destination.hostname,
                port: destination.port,
                pinned,
                source_ref: &preview.source_ref,
                dest_ref: &preview.destination_ref,
                credential: &credential,
            })
            .map_err(|error| {
                GitProviderError::new(
                    error.code,
                    redact_secret_text(&error.message, credential.secret.as_ref()),
                )
            })?;
        let resulting = transport
            .query_remote_ref(&RemoteQuery {
                repo: &repo,
                url: &destination.canonical_url,
                hostname: &destination.hostname,
                port: destination.port,
                pinned,
                dest_ref: &preview.destination_ref,
                credential: &credential,
            })
            .map_err(|error| {
                GitProviderError::new(
                    error.code,
                    redact_secret_text(&error.message, credential.secret.as_ref()),
                )
            })?;
        if resulting != preview.source_id {
            return Err(postcondition(
                "Git push postcondition did not observe the pushed object on the remote destination ref",
            ));
        }
        let tracking = push_tracking_ref(&destination.id, &validated_dest);
        self.run_git(
            &repo,
            &[
                "update-ref",
                "-m",
                "orcel push evidence",
                &tracking,
                &resulting,
            ],
        )?;
        let stored = self.push_tracking_prior(&repo, &tracking)?;
        if stored != resulting {
            return Err(postcondition(
                "Git push did not record the expected remote-tracking evidence",
            ));
        }
        let after_head = self.push_preview_head(&repo)?;
        let after_branch = self.push_preview_branch(&repo)?;
        let after_status = self.push_worktree_status(&repo)?;
        if after_head != before_head {
            return Err(postcondition("Git push changed the checked-out HEAD"));
        }
        if after_branch != before_branch {
            return Err(postcondition("Git push changed the current branch"));
        }
        if after_status != before_status {
            return Err(postcondition(
                "Git push changed index or worktree material state",
            ));
        }
        let evidence = json!({
            "repository_root": self.relative_display(&repo),
            "policy_id": destination.id,
            "canonical_url": destination.canonical_url,
            "hostname": destination.hostname,
            "port": destination.port,
            "pinned_address": pinned.to_string(),
            "source_ref": preview.source_ref,
            "destination_ref": preview.destination_ref,
            "source_id": preview.source_id,
            "prior": expected_prior,
            "result": resulting,
            "head": after_head,
            "branch": after_branch,
            "credential_reference": validated_credential,
            "credential_redacted": true,
        });
        let rendered = evidence.to_string();
        if let Some(secret) = credential.secret.as_ref() {
            if !secret.as_str().is_empty() && rendered.contains(secret.as_str()) {
                return Err(GitProviderError::new(
                    FailureCode::InternalError,
                    "push evidence contains secret material",
                ));
            }
        }
        Ok(evidence)
    }

    fn push_worktree_status(&self, repo: &Path) -> Result<String, GitProviderError> {
        let status = self.run_git(
            repo,
            &[
                "status",
                "--porcelain=v2",
                "--branch",
                "--untracked-files=all",
            ],
        )?;
        if status.stdout_truncated {
            return Err(provider_error(
                "Git push status evidence exceeded its bound",
            ));
        }
        let index = self.run_git(repo, &["ls-files", "--stage", "-z"])?;
        if index.stdout_truncated {
            return Err(provider_error("Git push index evidence exceeded its bound"));
        }
        Ok(format!(
            "STATUS\0{}\0INDEX\0{}",
            status.stdout, index.stdout
        ))
    }

    fn reject_unsafe_local_push_config(&self, repo: &Path) -> Result<(), GitProviderError> {
        let output = self.run_git(repo, &["config", "--local", "--list"])?;
        for line in output.stdout.lines() {
            let key = line
                .split_once('=')
                .map(|(key, _)| key.trim().to_ascii_lowercase())
                .unwrap_or_default();
            if key.starts_with("url.")
                && (key.contains("insteadof") || key.contains("pushinsteadof"))
            {
                return Err(GitProviderError::new(
                    FailureCode::CapabilityDenied,
                    "repository-local URL rewrite widens the approved push destination; push is denied",
                ));
            }
            if key.starts_with("http.")
                && (key.contains("proxy")
                    || key.contains("extraheader")
                    || key.contains("cookie")
                    || key.contains("sslverify")
                    || key.contains("followredirects")
                    || key == "http.proxy")
            {
                return Err(GitProviderError::new(
                    FailureCode::CapabilityDenied,
                    "repository-local HTTP transport configuration widens push authority; push is denied",
                ));
            }
            if key.starts_with("credential.") || key == "credential.helper" {
                return Err(GitProviderError::new(
                    FailureCode::CapabilityDenied,
                    "repository-local credential configuration is denied outside the protected credential-reference path",
                ));
            }
            if key == "core.askpass" || key == "core.sshcommand" {
                return Err(GitProviderError::new(
                    FailureCode::CapabilityDenied,
                    "repository-local helper configuration is denied for push",
                ));
            }
        }
        Ok(())
    }

    fn ensure_supported_push_state(&self, repo: &Path) -> Result<(), GitProviderError> {
        for marker in [
            "MERGE_HEAD",
            "CHERRY_PICK_HEAD",
            "REVERT_HEAD",
            "BISECT_LOG",
            "rebase-merge",
            "rebase-apply",
            "sequencer",
        ] {
            let output = self.run_git(repo, &["rev-parse", "--git-path", marker])?;
            let reported = output.stdout.trim().to_owned();
            let path = Path::new(&reported);
            let path = if path.is_absolute() {
                path.to_path_buf()
            } else {
                repo.join(path)
            };
            if path.exists() {
                return Err(GitProviderError::new(
                    FailureCode::CapabilityDenied,
                    format!("Git push is unavailable while repository state {marker} exists"),
                ));
            }
        }
        Ok(())
    }

    pub fn push_destination_map_for_tests() -> BTreeMap<String, GitPushDestination> {
        BTreeMap::new()
    }
}

fn args_policy_mismatch(destination: &GitPushDestination, source: &str, dest: &str) -> bool {
    destination.id.is_empty() || source.is_empty() || dest.is_empty()
}

fn invalid(message: impl Into<String>) -> GitProviderError {
    GitProviderError::new(FailureCode::InvalidRequest, message)
}

fn provider_error(message: impl Into<String>) -> GitProviderError {
    GitProviderError::new(FailureCode::ProviderUnavailable, message)
}

fn postcondition(message: impl Into<String>) -> GitProviderError {
    GitProviderError::new(FailureCode::PostconditionFailed, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn concurrent_askpass_creations_get_distinct_fresh_directories() {
        let handles: Vec<_> = (0..16)
            .map(|_| {
                std::thread::spawn(|| {
                    ProtectedAskpass::create(&PushSecret::new("token".to_string()))
                        .expect("create askpass")
                })
            })
            .collect();
        let askpasses: Vec<ProtectedAskpass> = handles
            .into_iter()
            .map(|handle| handle.join().expect("thread"))
            .collect();
        let mut dirs: Vec<&Path> = askpasses.iter().map(ProtectedAskpass::directory).collect();
        dirs.sort();
        dirs.dedup();
        assert_eq!(dirs.len(), askpasses.len(), "directories must be distinct");
        for askpass in &askpasses {
            let entries = std::fs::read_dir(askpass.directory())
                .expect("read dir")
                .count();
            assert_eq!(
                entries, 2,
                "each directory holds only its own secret and script"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn askpass_directory_and_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = |path: &Path| {
            std::fs::metadata(path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777
        };
        let askpass =
            ProtectedAskpass::create(&PushSecret::new("token".to_string())).expect("create");
        assert_eq!(mode(askpass.directory()), 0o700);
        assert_eq!(mode(&askpass.directory().join("secret")), 0o600);
        assert_eq!(mode(askpass.path()), 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn private_creation_is_exclusive_and_owner_only_at_creation() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = create_exclusive_askpass_dir().expect("dir");
        let file = dir.join("f");
        create_private_file(&file, 0o600, b"x").expect("create");
        assert_eq!(
            std::fs::metadata(&file).expect("m").permissions().mode() & 0o777,
            0o600
        );
        assert!(
            create_private_file(&file, 0o600, b"y").is_err(),
            "never reuses a file"
        );
        assert!(
            create_private_dir(&dir).is_err(),
            "never reuses a directory"
        );
        std::fs::remove_file(&file).expect("rm");
        std::fs::remove_dir(&dir).expect("rmdir");
    }

    #[test]
    fn askpass_directory_creation_never_reuses_an_existing_directory() {
        let first = create_exclusive_askpass_dir().expect("first");
        let second = create_exclusive_askpass_dir().expect("second");
        assert_ne!(first, second);
        assert_eq!(std::fs::read_dir(&first).expect("read").count(), 0);
        std::fs::remove_dir(&first).expect("cleanup first");
        std::fs::remove_dir(&second).expect("cleanup second");
    }

    #[test]
    fn push_destination_policy_accepts_only_canonical_https_443_with_reference() {
        let destination = parse_push_destination(
            "github-push",
            "https://github.com/TheHalfMoon/Orcel.git",
            "github-push-token",
        )
        .expect("valid");
        assert_eq!(destination.hostname, "github.com");
        assert_eq!(destination.port, 443);
        assert_eq!(
            destination.canonical_url,
            "https://github.com/TheHalfMoon/Orcel.git"
        );
        assert_eq!(destination.credential_reference, "github-push-token");
        let anonymous = parse_push_destination(
            "test-origin",
            "https://example.com:443/repo.git",
            "anonymous",
        )
        .expect("anonymous");
        assert_eq!(anonymous.credential_reference, "anonymous");
        for bad in [
            "http://example.com/repo.git",
            "https://user@example.com/repo.git",
            "https://user:pass@example.com/repo.git",
            "https://example.com/repo.git?x=1",
            "https://example.com/repo.git#frag",
            "https://example.com:80/repo.git",
            "https://example.com:8443/repo.git",
            "git@github.com:TheHalfMoon/Orcel.git",
            "ssh://git@example.com/repo.git",
            "git://example.com/repo.git",
            "file:///tmp/repo.git",
            "ext::sh -c echo",
            "https://192.0.2.1/repo.git",
            "https:///repo.git",
            "https://example/repo.git",
        ] {
            assert!(
                parse_push_destination("ok-id", bad, "anonymous").is_err(),
                "must reject {bad}"
            );
        }
        for bad_id in [
            "",
            "UPPER",
            "has space",
            "-lead",
            "trail-",
            "double--hyphen",
            "under_score",
            "a:b",
        ] {
            assert!(
                parse_push_destination(bad_id, "https://example.com/repo.git", "anonymous")
                    .is_err(),
                "must reject id {bad_id}"
            );
        }
    }

    #[test]
    fn push_branch_validation_rejects_force_delete_and_wildcard_shapes() {
        for good in ["main", "feature/push", "release-1"] {
            validate_push_branch(good).expect("valid branch");
            assert_eq!(push_source_ref(good), format!("refs/heads/{good}"));
            assert_eq!(push_destination_ref(good), format!("refs/heads/{good}"));
        }
        for bad in [
            "",
            "-lead",
            "refs/heads/main",
            "main:other",
            "+main",
            "../escape",
            "main..other",
            "main@{1}",
            "has space",
            "star*",
            "question?",
            "colon:name",
            "plus+name",
            "caret^name",
            "back\\slash",
            ".leading-dot",
            "trailing-dot.",
            "double//slash",
            "a/.b",
            "a.lock",
            "a.lock/b",
            "@",
        ] {
            assert!(
                validate_push_branch(bad).is_err(),
                "must reject branch {bad}"
            );
        }
    }

    #[test]
    fn credential_reference_rejects_raw_secrets_urls_and_tokens() {
        for good in ["anonymous", "github-push-token", "test-1"] {
            validate_credential_reference(good).expect("valid reference");
        }
        for bad in [
            "",
            "UPPER",
            "has space",
            "ghp_abcdef123456",
            "github_token",
            "https://example.com/token",
            "user:pass",
            "user@example.com",
            "token/with/slash",
            "token\\backslash",
            "tab\there",
            "line\nbreak",
            "-lead",
            "trail-",
            "double--hyphen",
        ] {
            assert!(
                validate_credential_reference(bad).is_err(),
                "must reject reference {bad:?}"
            );
        }
        assert_eq!(
            credential_env_name("github-push-token").expect("env name"),
            "ORCEL_GIT_CREDENTIAL_GITHUB_PUSH_TOKEN"
        );
        assert!(credential_env_name("anonymous").is_err());
    }

    #[test]
    fn push_secret_is_redacted_in_debug_display_and_errors() {
        let secret = PushSecret::new("super-secret-token-value".to_owned());
        assert_eq!(format!("{secret}"), "REDACTED");
        assert_eq!(format!("{secret:?}"), "PushSecret(REDACTED)");
        let message = format!("push failed with {}", secret.as_str());
        let redacted = redact_secret_text(&message, Some(&secret));
        assert!(!redacted.contains("super-secret-token-value"));
        assert!(redacted.contains("REDACTED"));
        let untouched = redact_secret_text("clean message", Some(&secret));
        assert_eq!(untouched, "clean message");
        let none = redact_secret_text("clean message", None);
        assert_eq!(none, "clean message");
    }

    #[test]
    fn push_child_env_inherits_no_secrets_or_proxies() {
        std::env::set_var("ORCEL_PUSH_TEST_DECOY_SECRET_XYZ", "decoy-secret-value-xyz");
        std::env::set_var("ORCEL_GIT_CREDENTIAL_DECOY_XYZ", "decoy-credential-xyz");
        std::env::set_var("PUSH_TEST_FAKE_TOKEN", "fake-token-abc");
        let env = build_child_env(None);
        let rendered = format!("{env:?}");
        assert!(!rendered.contains("decoy-secret-value-xyz"));
        assert!(!rendered.contains("decoy-credential-xyz"));
        assert!(!rendered.contains("fake-token-abc"));
        assert!(env
            .iter()
            .any(|(name, value)| name == "NO_PROXY" && value == "*"));
        assert!(env.iter().any(|(name, _)| name == "PATH" || name == "Path"));
        assert!(!env.iter().any(|(name, _)| name == "GIT_ASKPASS"));
        let with_askpass = build_child_env(Some(Path::new("/tmp/askpass-test")));
        assert!(with_askpass.iter().any(|(name, _)| name == "GIT_ASKPASS"));
        let rendered = format!("{with_askpass:?}");
        assert!(!rendered.contains("decoy-secret-value-xyz"));
        std::env::remove_var("ORCEL_PUSH_TEST_DECOY_SECRET_XYZ");
        std::env::remove_var("ORCEL_GIT_CREDENTIAL_DECOY_XYZ");
        std::env::remove_var("PUSH_TEST_FAKE_TOKEN");
    }

    #[test]
    fn push_command_plan_is_hardened_without_force_or_secrets() {
        let pinned: IpAddr = "8.8.8.8".parse().unwrap();
        let secret = PushSecret::new("plan-secret-123".to_owned());
        let argv = build_push_argv(
            "https://example.com/repo.git",
            "example.com",
            443,
            &pinned,
            "refs/heads/main",
            "refs/heads/main",
        );
        assert_no_force_or_delete_semantics(&argv).expect("hardened plan");
        let rendered = argv.join(" ");
        assert!(rendered.contains("protocol.https.allow=always"));
        assert!(rendered.contains("http.followRedirects=false"));
        assert!(rendered.contains("http.sslVerify=true"));
        assert!(rendered.contains("http.proxy="));
        assert!(rendered.contains("credential.helper="));
        assert!(rendered.contains("core.askPass="));
        assert!(rendered.contains("http.curloptResolve=+example.com:443:8.8.8.8"));
        assert!(rendered.contains("refs/heads/main:refs/heads/main"));
        assert!(!rendered.contains("plan-secret-123"));
        assert!(!rendered.to_ascii_lowercase().contains("--force"));
        assert!(!rendered.contains("--delete"));
        assert!(!rendered.contains("--all"));
        assert!(!rendered.contains("--mirror"));
        assert!(!rendered.contains("--tags"));
        let _ = secret;
        let remote = build_ls_remote_argv(
            "https://example.com/repo.git",
            "example.com",
            443,
            &pinned,
            "refs/heads/main",
        );
        let rendered = remote.join(" ");
        assert!(rendered.contains("ls-remote"));
        assert!(rendered.contains("refs/heads/main"));
        assert!(rendered.contains("http.curloptResolve=+example.com:443:8.8.8.8"));
    }

    #[test]
    fn push_address_classification_rejects_non_public() {
        for loopback in ["127.0.0.1", "::1"] {
            assert!(
                !super::super::fetch::is_public_address(&loopback.parse().unwrap()),
                "loopback {loopback}"
            );
        }
        for private in ["10.0.0.1", "172.16.0.1", "192.168.1.1", "fc00::1"] {
            assert!(
                !super::super::fetch::is_public_address(&private.parse().unwrap()),
                "private {private}"
            );
        }
        for documentation in ["192.0.2.1", "198.51.100.2", "203.0.113.3", "2001:db8::1"] {
            assert!(
                !super::super::fetch::is_public_address(&documentation.parse().unwrap()),
                "documentation {documentation}"
            );
        }
        let _ = (
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
        );
    }

    #[test]
    fn protected_askpass_never_embeds_secret_and_cleans_up() {
        let secret = PushSecret::new("askpass-isolation-secret-456".to_owned());
        let helper = ProtectedAskpass::create(&secret).expect("askpass");
        let script_text = std::fs::read_to_string(helper.path()).expect("read script");
        assert!(!script_text.contains("askpass-isolation-secret-456"));
        assert!(helper.directory().join("secret").is_file());
        let dir = helper.directory().to_path_buf();
        let script = helper.path().to_path_buf();
        drop(helper);
        assert!(!dir.join("secret").exists());
        assert!(!script.exists());
        assert!(!dir.exists());
    }
}
