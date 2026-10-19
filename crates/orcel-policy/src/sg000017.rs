#[path = "sg000016.rs"]
mod sg000016_legacy;

pub use sg000016_legacy::{
    validate_relative_target, FetchDestination, PolicyDecision, PolicyError, Workspace,
};

use orcel_contracts::{FailureCode, RequestEnvelope};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const POLICY_REVISION: &str = "sg-000017-v1";
const MAX_PUSH_DESTINATIONS: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushDestination {
    pub workspace_id: String,
    pub id: String,
    pub canonical_url: String,
    pub hostname: String,
    pub port: u16,
    pub credential_reference: String,
}

#[derive(Debug, Clone)]
pub struct PolicyEngine {
    legacy: sg000016_legacy::PolicyEngine,
    push_destinations: BTreeMap<(String, String), PushDestination>,
}

impl PolicyEngine {
    pub fn new(workspaces: Vec<Workspace>) -> Result<Self, PolicyError> {
        let push_destinations = load_push_destinations_from_env()?;
        let legacy = sg000016_legacy::PolicyEngine::new(workspaces)?;
        Self::with_push_destinations(legacy, push_destinations)
    }

    pub fn with_destinations(
        workspaces: Vec<Workspace>,
        fetch_destinations: Vec<FetchDestination>,
        push_destinations: Vec<PushDestination>,
    ) -> Result<Self, PolicyError> {
        let legacy =
            sg000016_legacy::PolicyEngine::with_destinations(workspaces, fetch_destinations)?;
        Self::with_push_destinations(legacy, push_destinations)
    }

    fn with_push_destinations(
        legacy: sg000016_legacy::PolicyEngine,
        push_destinations: Vec<PushDestination>,
    ) -> Result<Self, PolicyError> {
        if push_destinations.len() > MAX_PUSH_DESTINATIONS {
            return Err(policy_error(
                FailureCode::InvalidRequest,
                "too many Git push destinations",
            ));
        }
        let mut map = BTreeMap::new();
        for destination in push_destinations {
            validate_policy_id(&destination.id)?;
            validate_credential_reference(&destination.credential_reference)?;
            if destination.workspace_id.trim().is_empty() {
                return Err(policy_error(
                    FailureCode::InvalidRequest,
                    "Git push destination workspace id cannot be empty",
                ));
            }
            let (hostname, port, canonical) = validate_canonical_https(&destination.canonical_url)?;
            if hostname != destination.hostname || port != destination.port {
                return Err(policy_error(
                    FailureCode::InvalidRequest,
                    "Git push destination hostname or port does not match its canonical URL",
                ));
            }
            let _ = canonical;
            let key = (destination.workspace_id.clone(), destination.id.clone());
            if map.insert(key, destination).is_some() {
                return Err(policy_error(
                    FailureCode::InvalidRequest,
                    "duplicate Git push destination policy id for workspace",
                ));
            }
        }
        Ok(Self {
            legacy,
            push_destinations: map,
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
        self.legacy.fetch_destination(workspace_id, policy_id)
    }

    pub fn push_destination(
        &self,
        workspace_id: &str,
        policy_id: &str,
    ) -> Option<&PushDestination> {
        self.push_destinations
            .get(&(workspace_id.to_owned(), policy_id.to_owned()))
    }

    pub fn authorize(&self, request: &RequestEnvelope) -> Result<PolicyDecision, PolicyError> {
        if is_push(request) {
            self.validate_push(request)?;
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
        if is_push_like(request) {
            return Err(policy_error(
                FailureCode::CapabilityDenied,
                format!(
                    "capability/operation is denied by {POLICY_REVISION}: {}/{}; only git.push.preview/preview and git.push/push with an explicit policy-bound destination, short branches, and credential reference are authorized",
                    request.capability, request.operation
                ),
            ));
        }
        let decision = self.legacy.authorize(request)?;
        Ok(PolicyDecision {
            workspace: decision.workspace,
            policy_revision: POLICY_REVISION,
        })
    }

    fn validate_push(&self, request: &RequestEnvelope) -> Result<(), PolicyError> {
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
                "Git push requires a workspace-relative repository target",
            )
        })?;
        if target.is_empty() {
            return Err(policy_error(
                FailureCode::InvalidRequest,
                "Git push repository target cannot be empty",
            ));
        }
        validate_relative_target(target)?;
        let arguments = request.arguments.as_object().ok_or_else(|| {
            policy_error(
                FailureCode::InvalidRequest,
                "Git push arguments must be an object",
            )
        })?;
        match (request.capability.as_str(), request.operation.as_str()) {
            ("git.push.preview", "preview") => {
                reject_unknown(
                    arguments,
                    &[
                        "policy_id",
                        "source_branch",
                        "dest_branch",
                        "credential_reference",
                    ],
                )?;
                let policy_id = required_string(arguments, "policy_id")?;
                let source_branch = required_string(arguments, "source_branch")?;
                let dest_branch = required_string(arguments, "dest_branch")?;
                let credential_reference = required_string(arguments, "credential_reference")?;
                validate_policy_id(policy_id)?;
                validate_branch(source_branch)?;
                validate_branch(dest_branch)?;
                validate_credential_reference(credential_reference)?;
                let destination = self
                    .push_destination(&request.workspace_id, policy_id)
                    .ok_or_else(|| {
                        policy_error(
                            FailureCode::CapabilityDenied,
                            "Git push destination is not configured for this workspace",
                        )
                    })?;
                if credential_reference != destination.credential_reference {
                    return Err(policy_error(
                        FailureCode::CapabilityDenied,
                        "Git push credential reference does not match the configured push destination",
                    ));
                }
            }
            ("git.push", "push") => {
                reject_unknown(
                    arguments,
                    &[
                        "policy_id",
                        "source_branch",
                        "dest_branch",
                        "expected_head",
                        "expected_prior",
                        "credential_reference",
                    ],
                )?;
                let policy_id = required_string(arguments, "policy_id")?;
                let source_branch = required_string(arguments, "source_branch")?;
                let dest_branch = required_string(arguments, "dest_branch")?;
                let expected_head = required_string(arguments, "expected_head")?;
                let expected_prior = required_string(arguments, "expected_prior")?;
                let credential_reference = required_string(arguments, "credential_reference")?;
                validate_policy_id(policy_id)?;
                validate_branch(source_branch)?;
                validate_branch(dest_branch)?;
                validate_expected_head(expected_head)?;
                validate_expected_prior(expected_prior)?;
                validate_credential_reference(credential_reference)?;
                let destination = self
                    .push_destination(&request.workspace_id, policy_id)
                    .ok_or_else(|| {
                        policy_error(
                            FailureCode::CapabilityDenied,
                            "Git push destination is not configured for this workspace",
                        )
                    })?;
                if credential_reference != destination.credential_reference {
                    return Err(policy_error(
                        FailureCode::CapabilityDenied,
                        "Git push credential reference does not match the configured push destination",
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
}

fn is_push(request: &RequestEnvelope) -> bool {
    matches!(
        (request.capability.as_str(), request.operation.as_str()),
        ("git.push.preview", "preview") | ("git.push", "push")
    )
}

fn is_push_like(request: &RequestEnvelope) -> bool {
    request.capability == "git.push"
        || request.capability == "git.push.preview"
        || (request.capability == "git.fetch" && request.operation == "push")
        || request.operation == "push"
        || request.operation == "force-push"
        || request.operation == "delete"
}

fn load_push_destinations_from_env() -> Result<Vec<PushDestination>, PolicyError> {
    let raw = std::env::var("ORCEL_GIT_PUSH_DESTINATIONS_JSON").unwrap_or_default();
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    let parsed: Value = serde_json::from_str(&raw).map_err(|error| {
        policy_error(
            FailureCode::InvalidRequest,
            format!("parse ORCEL_GIT_PUSH_DESTINATIONS_JSON: {error}"),
        )
    })?;
    let items = parsed.as_array().ok_or_else(|| {
        policy_error(
            FailureCode::InvalidRequest,
            "ORCEL_GIT_PUSH_DESTINATIONS_JSON must be an array",
        )
    })?;
    let mut destinations = Vec::with_capacity(items.len());
    for item in items {
        let object = item.as_object().ok_or_else(|| {
            policy_error(
                FailureCode::InvalidRequest,
                "Git push destination entries must be objects",
            )
        })?;
        let workspace_id = object
            .get("workspace_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                policy_error(
                    FailureCode::InvalidRequest,
                    "Git push destination requires workspace_id",
                )
            })?;
        let id = object.get("id").and_then(Value::as_str).ok_or_else(|| {
            policy_error(
                FailureCode::InvalidRequest,
                "Git push destination requires id",
            )
        })?;
        let url = object.get("url").and_then(Value::as_str).ok_or_else(|| {
            policy_error(
                FailureCode::InvalidRequest,
                "Git push destination requires url",
            )
        })?;
        let credential_reference = object
            .get("credential_reference")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                policy_error(
                    FailureCode::InvalidRequest,
                    "Git push destination requires credential_reference",
                )
            })?;
        validate_policy_id(id)?;
        validate_credential_reference(credential_reference)?;
        let (hostname, port, canonical) = validate_canonical_https(url)?;
        destinations.push(PushDestination {
            workspace_id: workspace_id.to_owned(),
            id: id.to_owned(),
            canonical_url: canonical,
            hostname,
            port,
            credential_reference: credential_reference.to_owned(),
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
            format!("Git push does not accept argument field: {key}"),
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

fn validate_credential_reference(value: &str) -> Result<(), PolicyError> {
    if value.is_empty() || value.len() > 64 {
        return Err(policy_error(
            FailureCode::InvalidRequest,
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
        return Err(policy_error(
            FailureCode::InvalidRequest,
            "Git push credential reference must be an opaque reference id, never a raw secret, URL, or userinfo",
        ));
    }
    let bytes = value.as_bytes();
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return Err(policy_error(
            FailureCode::InvalidRequest,
            "Git push credential reference must start with a lowercase letter or digit",
        ));
    }
    if !bytes
        .iter()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
    {
        return Err(policy_error(
            FailureCode::InvalidRequest,
            "Git push credential reference must use only lowercase letters, digits, and hyphen",
        ));
    }
    if value.starts_with('-') || value.ends_with('-') || value.contains("--") {
        return Err(policy_error(
            FailureCode::InvalidRequest,
            "Git push credential reference has an unsafe hyphen placement",
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

fn policy_error(code: FailureCode, message: impl Into<String>) -> PolicyError {
    PolicyError {
        code,
        message: message.into(),
    }
}

#[cfg(test)]
mod sg000017_tests {
    use super::*;
    use serde_json::json;

    fn engine() -> (PolicyEngine, std::path::PathBuf) {
        let root = crate::test_support::unique_temp_dir("orcel-policy-sg000017");
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
            vec![PushDestination {
                workspace_id: "default".into(),
                id: "github-push".into(),
                canonical_url: "https://github.com/TheHalfMoon/Orcel.git".into(),
                hostname: "github.com".into(),
                port: 443,
                credential_reference: "github-push-token".into(),
            }],
        )
        .expect("policy");
        (engine, root)
    }

    fn request(capability: &str, operation: &str, arguments: Value) -> RequestEnvelope {
        RequestEnvelope {
            version: 1,
            request_id: "sg17".into(),
            client_session_id: "session".into(),
            workspace_id: "default".into(),
            capability: capability.into(),
            operation: operation.into(),
            target: Some(".".into()),
            arguments,
        }
    }

    #[test]
    fn authorizes_preview_and_push_shapes_with_bound_reference() {
        let (engine, root) = engine();
        let head = "0123456789abcdef0123456789abcdef01234567";
        engine
            .authorize(&request(
                "git.push.preview",
                "preview",
                json!({"policy_id": "github-push", "source_branch": "main", "dest_branch": "main", "credential_reference": "github-push-token"}),
            ))
            .expect("preview authorized");
        engine
            .authorize(&request(
                "git.push",
                "push",
                json!({"policy_id": "github-push", "source_branch": "main", "dest_branch": "feature/push", "expected_head": head, "expected_prior": "ABSENT", "credential_reference": "github-push-token"}),
            ))
            .expect("push authorized");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn denies_mismatched_reference_unknown_destination_and_force_shapes() {
        let (engine, root) = engine();
        let head = "0123456789abcdef0123456789abcdef01234567";
        let mismatch = engine
            .authorize(&request(
                "git.push",
                "push",
                json!({"policy_id": "github-push", "source_branch": "main", "dest_branch": "main", "expected_head": head, "expected_prior": "ABSENT", "credential_reference": "other-reference"}),
            ))
            .expect_err("mismatch denied");
        assert_eq!(mismatch.code, FailureCode::CapabilityDenied);
        let unknown = engine
            .authorize(&request(
                "git.push",
                "push",
                json!({"policy_id": "unknown", "source_branch": "main", "dest_branch": "main", "expected_head": head, "expected_prior": "ABSENT", "credential_reference": "github-push-token"}),
            ))
            .expect_err("unknown destination denied");
        assert_eq!(unknown.code, FailureCode::CapabilityDenied);
        for (capability, operation, arguments) in [
            (
                "git.push",
                "push",
                json!({"policy_id": "github-push", "source_branch": "main", "dest_branch": "main", "expected_head": head, "expected_prior": "ABSENT", "credential_reference": "github-push-token", "force": true}),
            ),
            (
                "git.push",
                "push",
                json!({"policy_id": "github-push", "source_branch": "main", "dest_branch": "main", "expected_head": head, "expected_prior": "ABSENT", "credential_reference": "github-push-token", "delete": true}),
            ),
            (
                "git.push",
                "push",
                json!({"policy_id": "github-push", "source_branch": "main", "dest_branch": "main", "expected_head": head, "expected_prior": "ABSENT", "credential_reference": "github-push-token", "proxy": "http://proxy.invalid"}),
            ),
            (
                "git.push",
                "push",
                json!({"policy_id": "github-push", "source_branch": "main", "dest_branch": "main", "expected_head": head, "expected_prior": "ABSENT", "credential_reference": "ghp_rawtoken123"}),
            ),
            (
                "git.push",
                "push",
                json!({"policy_id": "github-push", "source_branch": "refs/heads/main", "dest_branch": "main", "expected_head": head, "expected_prior": "ABSENT", "credential_reference": "github-push-token"}),
            ),
            (
                "git.push",
                "push",
                json!({"policy_id": "github-push", "source_branch": "main", "dest_branch": "main", "expected_head": head, "expected_prior": "ABSENT", "credential_reference": "github-push-token", "url": "https://example.com/evil.git"}),
            ),
            (
                "git.push",
                "push",
                json!({"policy_id": "github-push", "source_branch": "main", "dest_branch": "main", "expected_head": head, "expected_prior": "ABSENT", "credential_reference": "github-push-token", "token": "secret"}),
            ),
            ("git.push", "force-push", json!({})),
            ("git.push", "delete", json!({})),
            ("git.fetch", "push", json!({"policy_id": "github-main"})),
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
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn preserves_fetch_and_local_mutation_shapes() {
        let (engine, root) = engine();
        let head = "0123456789abcdef0123456789abcdef01234567";
        engine
            .authorize(&request(
                "git.fetch.preview",
                "preview",
                json!({"policy_id": "github-main", "branch": "main"}),
            ))
            .expect("fetch preview still authorized");
        engine
            .authorize(&request(
                "git.fetch",
                "fetch",
                json!({"policy_id": "github-main", "branch": "main", "expected_head": head, "expected_prior": "ABSENT"}),
            ))
            .expect("fetch still authorized");
        engine
            .authorize(&request(
                "git.stage",
                "stage",
                json!({"expected_head": head, "paths": ["a.txt"]}),
            ))
            .expect("stage still authorized");
        let _ = std::fs::remove_dir_all(root);
    }
}
