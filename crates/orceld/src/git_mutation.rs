use crate::mutation_journal::{self, Postcondition, Reconciled, Sink};
use orcel_approval::{now_ms, ApprovalBroker, ApprovalPrompt, ConsumeExpectation};
use orcel_contracts::{FailureCode, RequestEnvelope};
use orcel_policy::{Workspace, POLICY_REVISION};
use orcel_provider_fs::ProviderError;
use orcel_provider_git::{
    normalized_commit_message, GitMutationState, GitProvider, GitProviderError,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;

pub fn dispatch(
    workspace: &Workspace,
    approval: &impl ApprovalBroker,
    request: &RequestEnvelope,
) -> Result<Option<Value>, ProviderError> {
    dispatch_to(mutation_journal::global(), workspace, approval, request)
}

/// Local Git mutations, journaled to `sink` (SG-000120 RJ-02): `pending`
/// before the approval, `dispatched` before Git runs.
pub(crate) fn dispatch_to(
    sink: Sink,
    workspace: &Workspace,
    approval: &impl ApprovalBroker,
    request: &RequestEnvelope,
) -> Result<Option<Value>, ProviderError> {
    let operation = match (request.capability.as_str(), request.operation.as_str()) {
        ("git.branch.create", "create") => Mutation::BranchCreate {
            branch: required_string(request, "branch")?.to_owned(),
        },
        ("git.stage", "stage") => Mutation::Stage {
            paths: required_paths(request)?,
        },
        ("git.unstage", "unstage") => Mutation::Unstage {
            paths: required_paths(request)?,
        },
        ("git.commit", "commit") => Mutation::Commit {
            message: required_string(request, "message")?.to_owned(),
        },
        _ => return Ok(None),
    };

    let repository = request.target.as_deref().ok_or_else(|| {
        ProviderError::new(
            FailureCode::InvalidRequest,
            "Git mutation repository target is required",
        )
    })?;
    let expected_head = required_string(request, "expected_head")?;
    let provider = GitProvider::new(&workspace.root).map_err(map_git_error)?;
    let approved_state = operation.state(&provider, repository)?;
    require_expected_head(&approved_state, expected_head)?;

    let digest = approval_digest(workspace, request, &approved_state, &operation);
    let prompt = ApprovalPrompt::new(
        workspace.id.clone(),
        POLICY_REVISION,
        operation.action(),
        repository.to_owned(),
        operation.summary(&approved_state),
        digest.clone(),
    );
    let journaled = mutation_journal::Mutation {
        capability: request.capability.clone(),
        operation: request.operation.clone(),
        approval_digest: digest.clone(),
        workspace_id: workspace.id.clone(),
        policy_revision: POLICY_REVISION.to_owned(),
        root: workspace.root.clone(),
        target: repository.to_owned(),
        postcondition: operation.postcondition(&approved_state),
    };
    mutation_journal::journaled(
        sink,
        journaled,
        || {
            let token = require_approval(approval, &prompt)?;
            let current_state = operation.state(&provider, repository)?;
            if current_state != approved_state {
                return Err(ProviderError::new(
                    FailureCode::TargetStale,
                    "Git repository state changed after local approval",
                ));
            }
            require_expected_head(&current_state, expected_head)?;
            approval
                .consume(
                    &token,
                    &ConsumeExpectation::new(digest, workspace.id.clone(), POLICY_REVISION),
                    now_ms(),
                )
                .map_err(|error| ProviderError::new(error.code, error.message))
        },
        || operation.apply(&provider, repository, &approved_state),
    )
    .map(Some)
}

/// SHA-256 of a commit message as Git stores it.
fn message_sha256(message: &str) -> String {
    hex_lower(&Sha256::digest(
        normalized_commit_message(message).as_bytes(),
    ))
}

/// How an exited orceld's dispatched branch creation or commit turned
/// out, read from the repository's refs only. Any read failure is unknown.
pub(crate) fn reconcile(
    root: &Path,
    repository: &str,
    postcondition: &Postcondition,
) -> Reconciled {
    let Ok(provider) = GitProvider::new(root) else {
        return Reconciled::Unknown;
    };
    match postcondition {
        Postcondition::GitBranch { branch, head } => {
            match provider.branch_tip(repository, branch) {
                Ok(None) => Reconciled::NothingDone,
                Ok(Some(tip)) if &tip.head == head => match provider.branch_state(repository) {
                    Ok(state) if state.branch.as_deref() == Some(branch.as_str()) => {
                        Reconciled::Done
                    }
                    _ => Reconciled::Unknown,
                },
                _ => Reconciled::Unknown,
            }
        }
        Postcondition::GitCommit {
            branch,
            parent,
            message_sha256: expected,
        } => match provider.branch_tip(repository, branch) {
            Ok(Some(tip)) if &tip.head == parent => Reconciled::NothingDone,
            Ok(Some(tip))
                if tip.parents == [parent.clone()]
                    && &hex_lower(&Sha256::digest(tip.message.as_bytes())) == expected =>
            {
                Reconciled::Done
            }
            _ => Reconciled::Unknown,
        },
        _ => Reconciled::Unknown,
    }
}

#[derive(Debug)]
enum Mutation {
    BranchCreate { branch: String },
    Stage { paths: Vec<String> },
    Unstage { paths: Vec<String> },
    Commit { message: String },
}

impl Mutation {
    fn state(
        &self,
        provider: &GitProvider,
        repository: &str,
    ) -> Result<GitMutationState, ProviderError> {
        match self {
            Self::BranchCreate { .. } => provider.branch_state(repository),
            Self::Stage { paths } => provider.path_state(repository, paths),
            Self::Unstage { paths } => provider.unstage_state(repository, paths),
            Self::Commit { .. } => provider.staged_state(repository),
        }
        .map_err(map_git_error)
    }

    /// What the effect must leave, as journaled.
    fn postcondition(&self, approved: &GitMutationState) -> Postcondition {
        match self {
            Self::BranchCreate { branch } => Postcondition::GitBranch {
                branch: branch.clone(),
                head: approved.head.clone(),
            },
            Self::Stage { .. } | Self::Unstage { .. } => Postcondition::GitIndex,
            Self::Commit { message } => Postcondition::GitCommit {
                branch: approved.branch.clone().unwrap_or_default(),
                parent: approved.head.clone(),
                message_sha256: message_sha256(message),
            },
        }
    }

    fn action(&self) -> &'static str {
        match self {
            Self::BranchCreate { .. } => "create local Git branch",
            Self::Stage { .. } => "stage local Git paths",
            Self::Unstage { .. } => "unstage local Git paths",
            Self::Commit { .. } => "create local Git commit",
        }
    }

    fn summary(&self, state: &GitMutationState) -> String {
        match self {
            Self::BranchCreate { branch } => format!(
                "branch={branch} expected_head={} current_branch={}",
                state.head,
                state.branch.as_deref().unwrap_or("DETACHED")
            ),
            Self::Stage { paths } => format!(
                "paths={} expected_head={} current_branch={}",
                paths.len(),
                state.head,
                state.branch.as_deref().unwrap_or("DETACHED")
            ),
            Self::Unstage { paths } => format!(
                "paths={} expected_head={} current_branch={}",
                paths.len(),
                state.head,
                state.branch.as_deref().unwrap_or("DETACHED")
            ),
            Self::Commit { message } => format!(
                "staged_state_bound=true message_bytes={} expected_head={} current_branch={}",
                message.len(),
                state.head,
                state.branch.as_deref().unwrap_or("DETACHED")
            ),
        }
    }

    fn apply(
        &self,
        provider: &GitProvider,
        repository: &str,
        approved: &GitMutationState,
    ) -> Result<Value, ProviderError> {
        match self {
            Self::BranchCreate { branch } => provider.create_branch(repository, branch, approved),
            Self::Stage { paths } => provider.stage(repository, paths, approved),
            Self::Unstage { paths } => provider.unstage(repository, paths, approved),
            Self::Commit { message } => provider.commit(repository, message, approved),
        }
        .map_err(map_git_error)
    }

    fn digest_material(&self, hasher: &mut Sha256) {
        match self {
            Self::BranchCreate { branch } => {
                digest_field(hasher, b"BRANCH_CREATE");
                digest_field(hasher, branch.as_bytes());
            }
            Self::Stage { paths } => {
                digest_field(hasher, b"STAGE");
                for path in paths {
                    digest_field(hasher, path.as_bytes());
                }
            }
            Self::Unstage { paths } => {
                digest_field(hasher, b"UNSTAGE");
                for path in paths {
                    digest_field(hasher, path.as_bytes());
                }
            }
            Self::Commit { message } => {
                digest_field(hasher, b"COMMIT");
                let message_digest = Sha256::digest(message.as_bytes());
                digest_field(hasher, &message_digest);
            }
        }
    }
}

fn approval_digest(
    workspace: &Workspace,
    request: &RequestEnvelope,
    state: &GitMutationState,
    mutation: &Mutation,
) -> String {
    let mut hasher = Sha256::new();
    digest_field(&mut hasher, b"ORCEL_GIT_MUTATION_APPROVAL_V1");
    digest_field(&mut hasher, workspace.id.as_bytes());
    digest_field(&mut hasher, POLICY_REVISION.as_bytes());
    digest_field(&mut hasher, request.capability.as_bytes());
    digest_field(&mut hasher, request.operation.as_bytes());
    digest_field(
        &mut hasher,
        request.target.as_deref().unwrap_or_default().as_bytes(),
    );
    digest_field(&mut hasher, state.repository_root.as_bytes());
    digest_field(&mut hasher, state.head.as_bytes());
    digest_field(
        &mut hasher,
        state.branch.as_deref().unwrap_or("DETACHED").as_bytes(),
    );
    let material_digest = Sha256::digest(state.material.as_bytes());
    digest_field(&mut hasher, &material_digest);
    mutation.digest_material(&mut hasher);
    hex_lower(&hasher.finalize())
}

fn require_expected_head(state: &GitMutationState, expected: &str) -> Result<(), ProviderError> {
    if state.head != expected {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "Git HEAD does not match arguments.expected_head",
        ));
    }
    Ok(())
}

fn require_approval(
    approval: &impl ApprovalBroker,
    prompt: &ApprovalPrompt,
) -> Result<orcel_approval::ApprovedToken, ProviderError> {
    match approval.request_token(prompt) {
        Ok(token) => Ok(token),
        Err(error) => Err(ProviderError::new(error.code, error.message)),
    }
}

fn required_string<'a>(request: &'a RequestEnvelope, name: &str) -> Result<&'a str, ProviderError> {
    request
        .arguments
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ProviderError::new(
                FailureCode::InvalidRequest,
                format!("Git mutation requires arguments.{name}"),
            )
        })
}

fn required_paths(request: &RequestEnvelope) -> Result<Vec<String>, ProviderError> {
    request
        .arguments
        .get("paths")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ProviderError::new(
                FailureCode::InvalidRequest,
                "Git mutation requires arguments.paths",
            )
        })?
        .iter()
        .map(|value| {
            value.as_str().map(str::to_owned).ok_or_else(|| {
                ProviderError::new(
                    FailureCode::InvalidRequest,
                    "Git mutation path entries must be strings",
                )
            })
        })
        .collect()
}

fn map_git_error(error: GitProviderError) -> ProviderError {
    ProviderError::new(error.code, error.message)
}

fn digest_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use orcel_approval::test_support::FixedApprovalBroker;
    use orcel_approval::ApprovalDecision;
    use orcel_contracts::INTERNAL_PROTOCOL_VERSION;
    use serde_json::json;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn next_temp_sequence() -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        // macOS clocks tick in microseconds, so a timestamp alone can repeat
        // across parallel tests in one process.
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    }

    fn temp_root() -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let suffix = format!("{suffix}-{}", next_temp_sequence());
        let root = std::env::temp_dir().join(format!(
            "orcel-git-dispatch-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("root");
        root
    }

    fn git(cwd: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .args(args)
            .current_dir(cwd)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", null_device())
            .output()
            .expect("git");
        assert!(
            output.status.success(),
            "git failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    fn repository() -> PathBuf {
        let root = temp_root();
        git(&root, &["init"]);
        git(&root, &["config", "user.name", "Orcel Test"]);
        git(&root, &["config", "user.email", "orcel@example.invalid"]);
        fs::write(root.join("a.txt"), "one\n").expect("a");
        git(&root, &["add", "a.txt"]);
        git(&root, &["commit", "-m", "initial"]);
        root
    }

    fn workspace(root: &Path) -> Workspace {
        Workspace {
            id: "default".into(),
            root: fs::canonicalize(root).expect("canonical"),
        }
    }

    fn request(
        root: &Path,
        capability: &str,
        operation: &str,
        arguments: Value,
    ) -> RequestEnvelope {
        let head = git(root, &["rev-parse", "HEAD"]).trim().to_owned();
        let mut arguments = arguments;
        arguments["expected_head"] = json!(head);
        RequestEnvelope {
            version: INTERNAL_PROTOCOL_VERSION,
            request_id: "git-mutation-test".into(),
            client_session_id: "session".into(),
            workspace_id: "default".into(),
            capability: capability.into(),
            operation: operation.into(),
            target: Some(".".into()),
            arguments,
        }
    }

    #[test]
    fn denied_approval_preserves_git_state() {
        struct Deny;
        impl ApprovalBroker for Deny {
            fn request_token(
                &self,
                _prompt: &ApprovalPrompt,
            ) -> Result<orcel_approval::ApprovedToken, orcel_approval::ApprovalError> {
                Err(orcel_approval::ApprovalError {
                    code: FailureCode::ApprovalDenied,
                    message: "local user denied Git mutation".into(),
                })
            }

            fn consume(
                &self,
                _token: &orcel_approval::ApprovedToken,
                _expected: &ConsumeExpectation,
                _now_ms: u64,
            ) -> Result<(), orcel_approval::ApprovalError> {
                Err(orcel_approval::ApprovalError {
                    code: FailureCode::ApprovalDenied,
                    message: "no approval was granted".into(),
                })
            }
        }

        let root = repository();
        fs::write(root.join("a.txt"), "two\n").expect("modify");
        let request = request(&root, "git.stage", "stage", json!({"paths": ["a.txt"]}));
        let before = git(&root, &["diff", "--cached", "--name-only"]);
        let error = dispatch(&workspace(&root), &Deny, &request).expect_err("denial");
        assert_eq!(error.code, FailureCode::ApprovalDenied);
        assert_eq!(git(&root, &["diff", "--cached", "--name-only"]), before);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn approved_stage_mutates_only_after_bound_approval() {
        let root = repository();
        fs::write(root.join("a.txt"), "two\n").expect("modify");
        let request = request(&root, "git.stage", "stage", json!({"paths": ["a.txt"]}));
        let result = dispatch(
            &workspace(&root),
            &FixedApprovalBroker(ApprovalDecision::Approved),
            &request,
        )
        .expect("dispatch")
        .expect("handled");
        assert_eq!(result["paths"][0], "a.txt");
        assert_eq!(
            git(&root, &["diff", "--cached", "--name-only"]).trim(),
            "a.txt"
        );
        let _ = fs::remove_dir_all(root);
    }

    // Git for Windows maps `/dev/null` to the null device; Git 2.56 rejects `NUL`.
    fn null_device() -> &'static str {
        "/dev/null"
    }
}
