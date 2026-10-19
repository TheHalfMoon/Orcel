#[path = "lib.rs"]
mod legacy;

pub use legacy::{validate_relative_target, PolicyDecision, PolicyError, Workspace};

use orcel_contracts::{FailureCode, RequestEnvelope};
use serde_json::{Map, Value};
use std::path::Component;

pub const POLICY_REVISION: &str = "sg-000015-v1";
const MAX_GIT_PATHS: usize = 128;
const MAX_GIT_PATH_BYTES: usize = 4_096;
const MAX_GIT_COMMIT_MESSAGE_BYTES: usize = 8 * 1_024;

#[derive(Debug, Clone)]
pub struct PolicyEngine {
    legacy: legacy::PolicyEngine,
}

impl PolicyEngine {
    pub fn new(workspaces: Vec<Workspace>) -> Result<Self, PolicyError> {
        Ok(Self {
            legacy: legacy::PolicyEngine::new(workspaces)?,
        })
    }

    pub fn workspace(&self, id: &str) -> Option<&Workspace> {
        self.legacy.workspace(id)
    }

    pub fn authorize(&self, request: &RequestEnvelope) -> Result<PolicyDecision, PolicyError> {
        if is_git_mutation(request) {
            self.validate_git_mutation(request)?;
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

    fn validate_git_mutation(&self, request: &RequestEnvelope) -> Result<(), PolicyError> {
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

fn is_git_mutation(request: &RequestEnvelope) -> bool {
    matches!(
        (request.capability.as_str(), request.operation.as_str()),
        ("git.branch.create", "create")
            | ("git.stage", "stage")
            | ("git.unstage", "unstage")
            | ("git.commit", "commit")
    )
}

fn required_string<'a>(
    arguments: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a str, PolicyError> {
    arguments.get(key).and_then(Value::as_str).ok_or_else(|| {
        policy_error(
            FailureCode::InvalidRequest,
            format!("Git mutation requires arguments.{key} as a string"),
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
            format!("Git mutation does not accept argument field: {key}"),
        ));
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
            "Git mutation expected_head must be an exact lowercase 40-hex object id",
        ));
    }
    Ok(())
}

fn validate_branch(branch: &str) -> Result<(), PolicyError> {
    if branch.is_empty()
        || branch.len() > 255
        || branch.starts_with('-')
        || branch
            .chars()
            .any(|character| matches!(character, '\0' | '\n' | '\r' | '\t'))
    {
        return Err(policy_error(
            FailureCode::InvalidRequest,
            "Git branch name is empty, unsafe, or too large",
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
mod sg000015_tests {
    use super::*;
    use serde_json::json;

    fn engine() -> (PolicyEngine, std::path::PathBuf) {
        let root = crate::test_support::unique_temp_dir("orcel-policy-sg000015");
        let engine = PolicyEngine::new(vec![Workspace {
            id: "default".into(),
            root: root.clone(),
        }])
        .expect("policy");
        (engine, root)
    }

    fn request(capability: &str, operation: &str, arguments: Value) -> RequestEnvelope {
        RequestEnvelope {
            version: 1,
            request_id: "sg15".into(),
            client_session_id: "session".into(),
            workspace_id: "default".into(),
            capability: capability.into(),
            operation: operation.into(),
            target: Some(".".into()),
            arguments,
        }
    }

    #[test]
    fn allows_only_bounded_local_git_mutations() {
        let (engine, root) = engine();
        let head = "0123456789abcdef0123456789abcdef01234567";
        for request in [
            request(
                "git.branch.create",
                "create",
                json!({"expected_head": head, "branch": "orcel/test"}),
            ),
            request(
                "git.stage",
                "stage",
                json!({"expected_head": head, "paths": ["a.txt"]}),
            ),
            request(
                "git.unstage",
                "unstage",
                json!({"expected_head": head, "paths": ["a.txt"]}),
            ),
            request(
                "git.commit",
                "commit",
                json!({"expected_head": head, "message": "approved"}),
            ),
        ] {
            let decision = engine.authorize(&request).expect("authorized mutation");
            assert_eq!(decision.policy_revision, POLICY_REVISION);
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn rejects_network_destructive_and_unsafe_git_requests() {
        let (engine, root) = engine();
        let head = "0123456789abcdef0123456789abcdef01234567";
        for (capability, operation) in [
            ("git.fetch", "fetch"),
            ("git.push", "push"),
            ("git.reset", "reset"),
            ("git.rebase", "rebase"),
        ] {
            let error = engine
                .authorize(&request(
                    capability,
                    operation,
                    json!({"expected_head": head}),
                ))
                .expect_err("must be denied");
            assert_eq!(error.code, FailureCode::CapabilityDenied);
        }
        let error = engine
            .authorize(&request(
                "git.stage",
                "stage",
                json!({"expected_head": head, "paths": [".git/config"]}),
            ))
            .expect_err("git control path denied");
        assert!(matches!(
            error.code,
            FailureCode::CapabilityDenied | FailureCode::InvalidRequest
        ));
        let _ = std::fs::remove_dir_all(root);
    }
}
