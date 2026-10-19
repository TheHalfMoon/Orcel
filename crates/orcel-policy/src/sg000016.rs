#[path = "sg000015.rs"]
mod sg000015_legacy;

pub use sg000015_legacy::{validate_relative_target, PolicyDecision, PolicyError, Workspace};

use orcel_contracts::{FailureCode, RequestEnvelope};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::path::Component;

pub const POLICY_REVISION: &str = "sg-000016-v1";
const MAX_GIT_PATHS: usize = 128;
const MAX_GIT_PATH_BYTES: usize = 4_096;
const MAX_GIT_COMMIT_MESSAGE_BYTES: usize = 8 * 1_024;
const MAX_FETCH_DESTINATIONS: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchDestination {
    pub workspace_id: String,
    pub id: String,
    pub canonical_url: String,
    pub hostname: String,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct PolicyEngine {
    legacy: sg000015_legacy::PolicyEngine,
    destinations: BTreeMap<(String, String), FetchDestination>,
}

impl PolicyEngine {
    pub fn new(workspaces: Vec<Workspace>) -> Result<Self, PolicyError> {
        let destinations = load_destinations_from_env()?;
        Self::with_destinations(workspaces, destinations)
    }

    pub fn with_destinations(
        workspaces: Vec<Workspace>,
        destinations: Vec<FetchDestination>,
    ) -> Result<Self, PolicyError> {
        if destinations.len() > MAX_FETCH_DESTINATIONS {
            return Err(policy_error(
                FailureCode::InvalidRequest,
                "too many Git fetch destinations",
            ));
        }
        let mut map = BTreeMap::new();
        for destination in destinations {
            validate_policy_id(&destination.id)?;
            if destination.workspace_id.trim().is_empty() {
                return Err(policy_error(
                    FailureCode::InvalidRequest,
                    "Git fetch destination workspace id cannot be empty",
                ));
            }
            let (hostname, port, canonical) = validate_canonical_https(&destination.canonical_url)?;
            if hostname != destination.hostname || port != destination.port {
                return Err(policy_error(
                    FailureCode::InvalidRequest,
                    "Git fetch destination hostname or port does not match its canonical URL",
                ));
            }
            let _ = canonical;
            let key = (destination.workspace_id.clone(), destination.id.clone());
            if map.insert(key, destination).is_some() {
                return Err(policy_error(
                    FailureCode::InvalidRequest,
                    "duplicate Git fetch destination policy id for workspace",
                ));
            }
        }
        Ok(Self {
            legacy: sg000015_legacy::PolicyEngine::new(workspaces)?,
            destinations: map,
        })
    }

    pub fn workspace(&self, id: &str) -> Option<&Workspace> {
        self.legacy.workspace(id)
    }

    pub fn fetch_destination(
        &self,
        workspace_id: &str,
        policy_id: &str,
    ) -> Option<&FetchDestination> {
        self.destinations
            .get(&(workspace_id.to_owned(), policy_id.to_owned()))
    }

    pub fn authorize(&self, request: &RequestEnvelope) -> Result<PolicyDecision, PolicyError> {
        if is_fetch(request) {
            self.validate_fetch(request)?;
            let workspace = self
                .legacy
                .workspace(&request.workspace_id)
                .ok_or_else(|| {
                    policy_error(
                        FailureCode::WorkspaceDenied,
                        "requested workspace is not configured",
                    )
                })?;
            return Ok(PolicyDecision {
                workspace: workspace.clone(),
                policy_revision: POLICY_REVISION,
            });
        }
        if is_push(request) {
            return Err(policy_error(
                FailureCode::CapabilityDenied,
                format!(
                    "capability/operation is denied by {POLICY_REVISION}: {}/{}; git.push remains hard-denied pending its credential-safe successor",
                    request.capability, request.operation
                ),
            ));
        }
        if is_git_mutation(request) {
            self.validate_git_mutation_shape(request)?;
            let workspace = self
                .legacy
                .workspace(&request.workspace_id)
                .ok_or_else(|| {
                    policy_error(
                        FailureCode::WorkspaceDenied,
                        "requested workspace is not configured",
                    )
                })?;
            return Ok(PolicyDecision {
                workspace: workspace.clone(),
                policy_revision: POLICY_REVISION,
            });
        }
        let decision = self.legacy.authorize(request)?;
        Ok(PolicyDecision {
            workspace: decision.workspace,
            policy_revision: POLICY_REVISION,
        })
    }

    fn validate_fetch(&self, request: &RequestEnvelope) -> Result<(), PolicyError> {
        if request.version != orcel_contracts::INTERNAL_PROTOCOL_VERSION {
            return Err(policy_error(
                FailureCode::InvalidRequest,
                "unsupported internal protocol version",
            ));
        }
        if self.legacy.workspace(&request.workspace_id).is_none() {
            return Err(policy_error(
                FailureCode::WorkspaceDenied,
                "requested workspace is not configured",
            ));
        }
        let target = request.target.as_deref().ok_or_else(|| {
            policy_error(
                FailureCode::InvalidRequest,
                "Git fetch requires a workspace-relative repository target",
            )
        })?;
        if target.is_empty() {
            return Err(policy_error(
                FailureCode::InvalidRequest,
                "Git fetch repository target cannot be empty",
            ));
        }
        validate_relative_target(target)?;
        let arguments = request.arguments.as_object().ok_or_else(|| {
            policy_error(
                FailureCode::InvalidRequest,
                "Git fetch arguments must be an object",
            )
        })?;
        match (request.capability.as_str(), request.operation.as_str()) {
            ("git.fetch.preview", "preview") => {
                reject_unknown(arguments, &["policy_id", "branch"])?;
                let policy_id = required_string(arguments, "policy_id")?;
                let branch = required_string(arguments, "branch")?;
                validate_policy_id(policy_id)?;
                validate_branch(branch)?;
                if self
                    .fetch_destination(&request.workspace_id, policy_id)
                    .is_none()
                {
                    return Err(policy_error(
                        FailureCode::CapabilityDenied,
                        "Git fetch destination is not configured for this workspace",
                    ));
                }
            }
            ("git.fetch", "fetch") => {
                reject_unknown(
                    arguments,
                    &["policy_id", "branch", "expected_head", "expected_prior"],
                )?;
                let policy_id = required_string(arguments, "policy_id")?;
                let branch = required_string(arguments, "branch")?;
                let expected_head = required_string(arguments, "expected_head")?;
                let expected_prior = required_string(arguments, "expected_prior")?;
                validate_policy_id(policy_id)?;
                validate_branch(branch)?;
                validate_expected_head(expected_head)?;
                validate_expected_prior(expected_prior)?;
                if self
                    .fetch_destination(&request.workspace_id, policy_id)
                    .is_none()
                {
                    return Err(policy_error(
                        FailureCode::CapabilityDenied,
                        "Git fetch destination is not configured for this workspace",
                    ));
                }
            }
            _ => {
                return Err(policy_error(
                    FailureCode::CapabilityDenied,
                    format!(
                        "capability/operation is not allowed by {POLICY_REVISION}: {}/{}",
                        request.capability, request.operation
                    ),
                ))
            }
        }
        Ok(())
    }

    fn validate_git_mutation_shape(&self, request: &RequestEnvelope) -> Result<(), PolicyError> {
        if request.version != orcel_contracts::INTERNAL_PROTOCOL_VERSION {
            return Err(policy_error(
                FailureCode::InvalidRequest,
                "unsupported internal protocol version",
            ));
        }
        if self.legacy.workspace(&request.workspace_id).is_none() {
            return Err(policy_error(
                FailureCode::WorkspaceDenied,
                "requested workspace is not configured",
            ));
        }
        let target = request.target.as_deref().ok_or_else(|| {
            policy_error(
                FailureCode::InvalidRequest,
                "Git mutation requires a workspace-relative repository target",
            )
        })?;
        if target.is_empty() {
            return Err(policy_error(
                FailureCode::InvalidRequest,
                "Git mutation repository target cannot be empty",
            ));
        }
        validate_relative_target(target)?;
        let arguments = request.arguments.as_object().ok_or_else(|| {
            policy_error(
                FailureCode::InvalidRequest,
                "Git mutation arguments must be an object",
            )
        })?;
        let expected_head = required_string(arguments, "expected_head")?;
        validate_expected_head(expected_head)?;
        match (request.capability.as_str(), request.operation.as_str()) {
            ("git.branch.create", "create") => {
                reject_unknown(arguments, &["expected_head", "branch"])?;
                validate_branch(required_string(arguments, "branch")?)?;
            }
            ("git.stage", "stage") | ("git.unstage", "unstage") => {
                reject_unknown(arguments, &["expected_head", "paths"])?;
                validate_paths(arguments.get("paths"))?;
            }
            ("git.commit", "commit") => {
                reject_unknown(arguments, &["expected_head", "message"])?;
                validate_commit_message(required_string(arguments, "message")?)?;
            }
            _ => {
                return Err(policy_error(
                    FailureCode::CapabilityDenied,
                    format!(
                        "capability/operation is not allowed by {POLICY_REVISION}: {}/{}",
                        request.capability, request.operation
                    ),
                ))
            }
        }
        Ok(())
    }
}

fn is_fetch(request: &RequestEnvelope) -> bool {
    matches!(
        (request.capability.as_str(), request.operation.as_str()),
        ("git.fetch.preview", "preview") | ("git.fetch", "fetch")
    )
}

fn is_push(request: &RequestEnvelope) -> bool {
    request.capability == "git.push"
        || (request.capability == "git.fetch" && request.operation == "push")
        || request.operation == "push"
}

fn is_git_mutation(request: &RequestEnvelope) -> bool {
    matches!(
        (request.capability.as_str(), request.operation.as_str()),
        ("git.branch.create", "create")
            | ("git.stage", "stage")
            | ("git.unstage", "unstage")
            | ("git.commit", "commit")
    )
}

fn load_destinations_from_env() -> Result<Vec<FetchDestination>, PolicyError> {
    let raw = std::env::var("ORCEL_GIT_FETCH_DESTINATIONS_JSON").unwrap_or_default();
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    let parsed: Value = serde_json::from_str(&raw).map_err(|error| {
        policy_error(
            FailureCode::InvalidRequest,
            format!("parse ORCEL_GIT_FETCH_DESTINATIONS_JSON: {error}"),
        )
    })?;
    let items = parsed.as_array().ok_or_else(|| {
        policy_error(
            FailureCode::InvalidRequest,
            "ORCEL_GIT_FETCH_DESTINATIONS_JSON must be an array",
        )
    })?;
    let mut destinations = Vec::with_capacity(items.len());
    for item in items {
        let object = item.as_object().ok_or_else(|| {
            policy_error(
                FailureCode::InvalidRequest,
                "Git fetch destination entries must be objects",
            )
        })?;
        let workspace_id = object
            .get("workspace_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                policy_error(
                    FailureCode::InvalidRequest,
                    "Git fetch destination requires workspace_id",
                )
            })?;
        let id = object.get("id").and_then(Value::as_str).ok_or_else(|| {
            policy_error(
                FailureCode::InvalidRequest,
                "Git fetch destination requires id",
            )
        })?;
        let url = object.get("url").and_then(Value::as_str).ok_or_else(|| {
            policy_error(
                FailureCode::InvalidRequest,
                "Git fetch destination requires url",
            )
        })?;
        validate_policy_id(id)?;
        let (hostname, port, canonical) = validate_canonical_https(url)?;
        destinations.push(FetchDestination {
            workspace_id: workspace_id.to_owned(),
            id: id.to_owned(),
            canonical_url: canonical,
            hostname,
            port,
        });
    }
    Ok(destinations)
}

fn required_string<'a>(
    arguments: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a str, PolicyError> {
    arguments.get(key).and_then(Value::as_str).ok_or_else(|| {
        policy_error(
            FailureCode::InvalidRequest,
            format!("Git operation requires arguments.{key} as a string"),
        )
    })
}

fn reject_unknown(arguments: &Map<String, Value>, allowed: &[&str]) -> Result<(), PolicyError> {
    if let Some(key) = arguments
        .keys()
        .find(|key| !allowed.contains(&key.as_str()))
    {
        return Err(policy_error(
            FailureCode::InvalidRequest,
            format!("Git operation does not accept argument field: {key}"),
        ));
    }
    Ok(())
}

fn validate_policy_id(id: &str) -> Result<(), PolicyError> {
    if id.is_empty() || id.len() > 64 {
        return Err(policy_error(
            FailureCode::InvalidRequest,
            "Git destination policy id must contain 1..=64 characters",
        ));
    }
    let bytes = id.as_bytes();
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return Err(policy_error(
            FailureCode::InvalidRequest,
            "Git destination policy id must start with a lowercase letter or digit",
        ));
    }
    if !bytes
        .iter()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
    {
        return Err(policy_error(
            FailureCode::InvalidRequest,
            "Git destination policy id must use only lowercase letters, digits, and hyphen",
        ));
    }
    if id.starts_with('-') || id.ends_with('-') || id.contains("--") {
        return Err(policy_error(
            FailureCode::InvalidRequest,
            "Git destination policy id has an unsafe hyphen placement",
        ));
    }
    Ok(())
}

fn validate_branch(branch: &str) -> Result<(), PolicyError> {
    if branch.is_empty() || branch.len() > 255 || branch.starts_with('-') {
        return Err(policy_error(
            FailureCode::InvalidRequest,
            "Git branch name is empty, unsafe, or too large",
        ));
    }
    if branch == "refs" || branch.starts_with("refs/") {
        return Err(policy_error(
            FailureCode::InvalidRequest,
            "Git branch name must be a short name, not a full ref",
        ));
    }
    if branch.bytes().any(|byte| {
        matches!(
            byte,
            0 | b'\n' | b'\r' | b'\t' | b' ' | b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\'
        )
    }) {
        return Err(policy_error(
            FailureCode::InvalidRequest,
            "Git branch name contains unsafe characters",
        ));
    }
    if branch.starts_with('/')
        || branch.starts_with('.')
        || branch.ends_with('/')
        || branch.ends_with('.')
        || branch.ends_with(".lock")
    {
        return Err(policy_error(
            FailureCode::InvalidRequest,
            "Git branch name has an unsafe leading or trailing component",
        ));
    }
    if branch.contains("//")
        || branch.contains("/.")
        || branch.contains(".lock/")
        || branch.contains("..")
        || branch.contains("@{")
    {
        return Err(policy_error(
            FailureCode::InvalidRequest,
            "Git branch name contains an unsafe sequence",
        ));
    }
    for component in branch.split('/') {
        if component.is_empty() || component == "." || component == ".." || component == "@" {
            return Err(policy_error(
                FailureCode::InvalidRequest,
                "Git branch name contains an unsafe component",
            ));
        }
        if component.starts_with('.') || component.ends_with(".lock") {
            return Err(policy_error(
                FailureCode::InvalidRequest,
                "Git branch name contains an unsafe component",
            ));
        }
    }
    Ok(())
}

fn validate_expected_head(value: &str) -> Result<(), PolicyError> {
    if value.len() != 40
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(policy_error(
            FailureCode::InvalidRequest,
            "Git expected_head must be an exact lowercase 40-hex object id",
        ));
    }
    Ok(())
}

fn validate_expected_prior(value: &str) -> Result<(), PolicyError> {
    if value == "ABSENT" {
        return Ok(());
    }
    validate_expected_head(value).map_err(|_| {
        policy_error(
            FailureCode::InvalidRequest,
            "Git expected_prior must be a lowercase 40-hex object id or ABSENT",
        )
    })
}

fn validate_canonical_https(url: &str) -> Result<(String, u16, String), PolicyError> {
    if url.is_empty() || url.len() > 2048 {
        return Err(policy_error(
            FailureCode::InvalidRequest,
            "Git destination URL is empty or too large",
        ));
    }
    if url.contains('\0')
        || url.contains('\n')
        || url.contains('\r')
        || url.contains('\t')
        || url.contains(' ')
    {
        return Err(policy_error(
            FailureCode::InvalidRequest,
            "Git destination URL contains unsafe whitespace or control data",
        ));
    }
    if !url.to_ascii_lowercase().starts_with("https://") {
        return Err(policy_error(
            FailureCode::InvalidRequest,
            "Git destination URL must use the https scheme",
        ));
    }
    let rest = &url["https://".len()..];
    if rest.is_empty()
        || rest.contains('@')
        || rest.contains('?')
        || rest.contains('#')
        || rest.contains('\\')
    {
        return Err(policy_error(
            FailureCode::InvalidRequest,
            "Git destination URL must not contain userinfo, query, fragment, or backslash",
        ));
    }
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return Err(policy_error(
            FailureCode::InvalidRequest,
            "Git destination URL is missing a hostname",
        ));
    }
    let (hostname_part, port) = match authority.rfind(':') {
        Some(index) => {
            let host = &authority[..index];
            let port_text = &authority[index + 1..];
            if port_text.is_empty() || !port_text.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(policy_error(
                    FailureCode::InvalidRequest,
                    "Git destination URL port must be numeric",
                ));
            }
            let port: u16 = port_text.parse().map_err(|_| {
                policy_error(
                    FailureCode::InvalidRequest,
                    "Git destination URL port is invalid",
                )
            })?;
            if port != 443 {
                return Err(policy_error(
                    FailureCode::InvalidRequest,
                    "Git destination URL must use implicit or explicit port 443 only",
                ));
            }
            (host, port)
        }
        None => (authority, 443u16),
    };
    if hostname_part.is_empty() || hostname_part.len() > 253 || hostname_part.contains(':') {
        return Err(policy_error(
            FailureCode::InvalidRequest,
            "Git destination hostname must be a DNS hostname",
        ));
    }
    validate_dns_hostname(hostname_part)?;
    let hostname_lower = hostname_part.to_ascii_lowercase();
    let canonical = if authority.contains(':') {
        format!("https://{hostname_lower}:443{path}")
    } else {
        format!("https://{hostname_lower}{path}")
    };
    Ok((hostname_lower, port, canonical))
}

fn validate_dns_hostname(hostname: &str) -> Result<(), PolicyError> {
    if hostname.starts_with('-')
        || hostname.starts_with('.')
        || hostname.ends_with('-')
        || hostname.ends_with('.')
        || hostname.contains("..")
    {
        return Err(policy_error(
            FailureCode::InvalidRequest,
            "Git destination hostname has an unsafe shape",
        ));
    }
    if !hostname.contains('.') {
        return Err(policy_error(
            FailureCode::InvalidRequest,
            "Git destination hostname must be a dotted DNS hostname",
        ));
    }
    let mut has_alpha = false;
    for label in hostname.split('.') {
        if label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-') {
            return Err(policy_error(
                FailureCode::InvalidRequest,
                "Git destination hostname label is empty, too large, or unsafe",
            ));
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(policy_error(
                FailureCode::InvalidRequest,
                "Git destination hostname label uses unsafe characters",
            ));
        }
        has_alpha = has_alpha || label.bytes().any(|byte| byte.is_ascii_alphabetic());
    }
    if !has_alpha {
        return Err(policy_error(
            FailureCode::InvalidRequest,
            "Git destination hostname must contain at least one letter",
        ));
    }
    Ok(())
}

fn validate_paths(value: Option<&Value>) -> Result<(), PolicyError> {
    let paths = value.and_then(Value::as_array).ok_or_else(|| {
        policy_error(
            FailureCode::InvalidRequest,
            "Git mutation requires arguments.paths as an array",
        )
    })?;
    if paths.is_empty() || paths.len() > MAX_GIT_PATHS {
        return Err(policy_error(
            FailureCode::InvalidRequest,
            format!("Git mutation paths must contain 1..={MAX_GIT_PATHS} entries"),
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for value in paths {
        let path = value.as_str().ok_or_else(|| {
            policy_error(
                FailureCode::InvalidRequest,
                "Git mutation path entries must be strings",
            )
        })?;
        if path.is_empty()
            || path.len() > MAX_GIT_PATH_BYTES
            || path.starts_with(':')
            || path
                .chars()
                .any(|character| matches!(character, '\0' | '\n' | '\r' | '\t'))
        {
            return Err(policy_error(
                FailureCode::InvalidRequest,
                "Git mutation path is empty, unsafe, or too large",
            ));
        }
        validate_relative_target(path)?;
        for component in std::path::Path::new(path).components() {
            if let Component::Normal(name) = component {
                if name.to_string_lossy().eq_ignore_ascii_case(".git") {
                    return Err(policy_error(
                        FailureCode::CapabilityDenied,
                        "Git control paths are not mutable",
                    ));
                }
            }
        }
        if path.eq_ignore_ascii_case(".gitmodules") {
            return Err(policy_error(
                FailureCode::CapabilityDenied,
                "submodule metadata mutation is not allowed",
            ));
        }
        if !seen.insert(path) {
            return Err(policy_error(
                FailureCode::InvalidRequest,
                "Git mutation paths contain duplicates",
            ));
        }
    }
    Ok(())
}

fn validate_commit_message(message: &str) -> Result<(), PolicyError> {
    if message.trim().is_empty()
        || message.len() > MAX_GIT_COMMIT_MESSAGE_BYTES
        || message.contains('\0')
    {
        return Err(policy_error(
            FailureCode::InvalidRequest,
            "Git commit message is empty, unsafe, or too large",
        ));
    }
    Ok(())
}

fn policy_error(code: FailureCode, message: impl Into<String>) -> PolicyError {
    PolicyError {
        code,
        message: message.into(),
    }
}

#[cfg(test)]
mod sg000016_tests {
    use super::*;
    use serde_json::json;

    fn engine_with(destination_url: &str) -> (PolicyEngine, std::path::PathBuf) {
        let root = crate::test_support::unique_temp_dir("orcel-policy-sg000016");
        let engine = PolicyEngine::with_destinations(
            vec![Workspace {
                id: "default".into(),
                root: root.clone(),
            }],
            vec![FetchDestination {
                workspace_id: "default".into(),
                id: "github-main".into(),
                canonical_url: "https://github.com/TheHalfMoon/Orcel.git".into(),
                hostname: "github.com".into(),
                port: 443,
            }],
        )
        .expect("policy");
        let _ = destination_url;
        (engine, root)
    }

    fn request(capability: &str, operation: &str, arguments: Value) -> RequestEnvelope {
        RequestEnvelope {
            version: 1,
            request_id: "sg16".into(),
            client_session_id: "session".into(),
            workspace_id: "default".into(),
            capability: capability.into(),
            operation: operation.into(),
            target: Some(".".into()),
            arguments,
        }
    }

    #[test]
    fn authorizes_preview_and_fetch_shapes_with_configured_destination() {
        let (engine, root) = engine_with("https://github.com/TheHalfMoon/Orcel.git");
        let head = "0123456789abcdef0123456789abcdef01234567";
        engine
            .authorize(&request(
                "git.fetch.preview",
                "preview",
                json!({"policy_id": "github-main", "branch": "main"}),
            ))
            .expect("preview authorized");
        engine
            .authorize(&request(
                "git.fetch",
                "fetch",
                json!({"policy_id": "github-main", "branch": "main", "expected_head": head, "expected_prior": "ABSENT"}),
            ))
            .expect("fetch authorized");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn denies_push_credential_and_arbitrary_network_shapes() {
        let (engine, root) = engine_with("https://github.com/TheHalfMoon/Orcel.git");
        let head = "0123456789abcdef0123456789abcdef01234567";
        for (capability, operation, arguments) in [
            (
                "git.push",
                "push",
                json!({"policy_id": "github-main", "branch": "main", "expected_head": head}),
            ),
            ("git.fetch", "push", json!({"policy_id": "github-main"})),
            (
                "network.fetch",
                "fetch",
                json!({"url": "https://example.com"}),
            ),
            (
                "git.fetch",
                "fetch",
                json!({"policy_id": "github-main", "branch": "main", "expected_head": head, "expected_prior": "ABSENT", "proxy": "http://proxy.invalid"}),
            ),
            (
                "git.fetch",
                "fetch",
                json!({"policy_id": "github-main", "branch": "refs/heads/main", "expected_head": head, "expected_prior": "ABSENT"}),
            ),
        ] {
            let error = engine
                .authorize(&request(capability, operation, arguments))
                .expect_err("must be denied");
            assert!(
                matches!(
                    error.code,
                    FailureCode::CapabilityDenied | FailureCode::InvalidRequest
                ),
                "unexpected code for {capability}/{operation}"
            );
        }
        let error = engine
            .authorize(&request(
                "git.fetch",
                "fetch",
                json!({"policy_id": "unknown", "branch": "main", "expected_head": head, "expected_prior": "ABSENT"}),
            ))
            .expect_err("unknown destination denied");
        assert_eq!(error.code, FailureCode::CapabilityDenied);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn preserves_sg000015_local_mutation_shapes() {
        let (engine, root) = engine_with("https://github.com/TheHalfMoon/Orcel.git");
        let head = "0123456789abcdef0123456789abcdef01234567";
        engine
            .authorize(&request(
                "git.stage",
                "stage",
                json!({"expected_head": head, "paths": ["a.txt"]}),
            ))
            .expect("stage still authorized");
        let error = engine
            .authorize(&request("git.push", "push", json!({"expected_head": head})))
            .expect_err("push denied");
        assert_eq!(error.code, FailureCode::CapabilityDenied);
        let _ = std::fs::remove_dir_all(root);
    }
}
