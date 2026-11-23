use orcel_approval::{now_ms, ApprovalBroker, ApprovalPrompt, ConsumeExpectation};
use orcel_contracts::{FailureCode, RequestEnvelope};
use orcel_policy::{FetchDestination, Workspace, POLICY_REVISION};
use orcel_provider_fs::ProviderError;
use orcel_provider_git::{
    fetch::{
        select_pinned_address, validate_branch, validate_expected_head, validate_expected_prior,
        validate_policy_id, DnsResolver, GitFetchDestination, SystemResolver,
    },
    GitProvider, GitProviderError,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::net::IpAddr;

pub fn dispatch(
    workspace: &Workspace,
    approval: &impl ApprovalBroker,
    request: &RequestEnvelope,
    lookup: &impl FetchDestinationLookup,
    resolver: &impl DnsResolver,
) -> Result<Option<Value>, ProviderError> {
    dispatch_to(
        crate::mutation_journal::global(),
        workspace,
        approval,
        request,
        lookup,
        resolver,
    )
}

/// `git.fetch`, journaled to `sink` (SG-000120 RJ-02). The remote is never
/// probed: a fetch that dispatched and did not report is unknown.
pub(crate) fn dispatch_to(
    sink: crate::mutation_journal::Sink,
    workspace: &Workspace,
    approval: &impl ApprovalBroker,
    request: &RequestEnvelope,
    lookup: &impl FetchDestinationLookup,
    resolver: &impl DnsResolver,
) -> Result<Option<Value>, ProviderError> {
    match (request.capability.as_str(), request.operation.as_str()) {
        ("git.fetch.preview", "preview") => {
            let policy_id = required_string(request, "policy_id")?.to_owned();
            let branch = required_string(request, "branch")?.to_owned();
            let repository = required_target(request)?;
            let destination = lookup
                .destination(&request.workspace_id, &policy_id)
                .ok_or_else(|| {
                    ProviderError::new(
                        FailureCode::CapabilityDenied,
                        "Git fetch destination is not configured for this workspace",
                    )
                })?;
            let provider = GitProvider::new(&workspace.root).map_err(map_git_error)?;
            let provider_destination = provider_destination(&destination)?;
            let preview = provider
                .fetch_preview(repository, &policy_id, &branch, &provider_destination)
                .map_err(map_git_error)?;
            Ok(Some(preview.to_json()))
        }
        ("git.fetch", "fetch") => {
            let policy_id = required_string(request, "policy_id")?.to_owned();
            let branch = required_string(request, "branch")?.to_owned();
            let expected_head = required_string(request, "expected_head")?.to_owned();
            let expected_prior = required_string(request, "expected_prior")?.to_owned();
            let repository = required_target(request)?.to_owned();
            validate_policy_id(&policy_id).map_err(map_git_error)?;
            validate_branch(&branch).map_err(map_git_error)?;
            validate_expected_head(&expected_head).map_err(map_git_error)?;
            validate_expected_prior(&expected_prior).map_err(map_git_error)?;
            let destination = lookup
                .destination(&request.workspace_id, &policy_id)
                .ok_or_else(|| {
                    ProviderError::new(
                        FailureCode::CapabilityDenied,
                        "Git fetch destination is not configured for this workspace",
                    )
                })?;
            let provider = GitProvider::new(&workspace.root).map_err(map_git_error)?;
            let provider_destination = provider_destination(&destination)?;
            let preview = provider
                .fetch_preview(&repository, &policy_id, &branch, &provider_destination)
                .map_err(map_git_error)?;
            if preview.head != expected_head {
                return Err(ProviderError::new(
                    FailureCode::TargetStale,
                    "Git HEAD does not match arguments.expected_head from preview",
                ));
            }
            if preview.prior != expected_prior {
                return Err(ProviderError::new(
                    FailureCode::TargetStale,
                    "destination-ref state does not match arguments.expected_prior from preview",
                ));
            }
            let resolved = resolver
                .resolve(&provider_destination.hostname)
                .map_err(map_git_error)?;
            let pinned = select_pinned_address(&resolved).map_err(map_git_error)?;
            let digest = fetch_digest(
                workspace,
                request,
                &destination,
                &provider_destination,
                &pinned,
                &preview,
            );
            let prompt = ApprovalPrompt::new(
                workspace.id.clone(),
                POLICY_REVISION,
                "fetch one approved Git branch over pinned HTTPS",
                repository.clone(),
                fetch_summary(
                    &destination,
                    &provider_destination,
                    &pinned,
                    &branch,
                    &preview,
                ),
                digest.clone(),
            );
            let journaled = crate::mutation_journal::Mutation {
                capability: request.capability.clone(),
                operation: request.operation.clone(),
                approval_digest: digest.clone(),
                workspace_id: workspace.id.clone(),
                policy_revision: POLICY_REVISION.to_owned(),
                root: workspace.root.clone(),
                target: repository.clone(),
                postcondition: crate::mutation_journal::Postcondition::Remote,
            };
            let approve = || {
                let token = require_approval(approval, &prompt)?;
                approval
                    .consume(
                        &token,
                        &ConsumeExpectation::new(digest, workspace.id.clone(), POLICY_REVISION),
                        now_ms(),
                    )
                    .map_err(|error| ProviderError::new(error.code, error.message))
            };
            let fetch_args = orcel_provider_git::fetch::ApprovedFetch {
                relative: &repository,
                destination: &provider_destination,
                policy_id: &policy_id,
                branch: &branch,
                expected_head: &expected_head,
                expected_prior: &expected_prior,
                pinned: &pinned,
            };
            crate::mutation_journal::journaled(sink, journaled, approve, || {
                provider
                    .fetch_approved(&fetch_args, resolver)
                    .map_err(map_git_error)
            })
            .map(Some)
        }
        _ => Ok(None),
    }
}

pub trait FetchDestinationLookup {
    fn destination(&self, workspace_id: &str, policy_id: &str) -> Option<FetchDestination>;
}

pub struct PolicyFetchLookup<'a> {
    pub policy: &'a orcel_policy::PolicyEngine,
}

impl FetchDestinationLookup for PolicyFetchLookup<'_> {
    fn destination(&self, workspace_id: &str, policy_id: &str) -> Option<FetchDestination> {
        self.policy
            .fetch_destination(workspace_id, policy_id)
            .cloned()
    }
}

pub fn provider_destination(
    destination: &FetchDestination,
) -> Result<GitFetchDestination, ProviderError> {
    Ok(GitFetchDestination {
        id: destination.id.clone(),
        canonical_url: destination.canonical_url.clone(),
        hostname: destination.hostname.clone(),
        port: destination.port,
    })
}

pub fn system_resolver() -> SystemResolver {
    SystemResolver
}

fn fetch_summary(
    destination: &FetchDestination,
    provider_destination: &GitFetchDestination,
    pinned: &IpAddr,
    branch: &str,
    preview: &orcel_provider_git::fetch::FetchPreview,
) -> String {
    format!(
        "policy={} url={} host={} port={} pinned={} source={} dest={} expected_head={} expected_prior={} branch={}",
        destination.id,
        provider_destination.canonical_url,
        provider_destination.hostname,
        provider_destination.port,
        pinned,
        preview.source_ref,
        preview.destination_ref,
        preview.head,
        preview.prior,
        branch,
    )
}

fn fetch_digest(
    workspace: &Workspace,
    request: &RequestEnvelope,
    destination: &FetchDestination,
    provider_destination: &GitFetchDestination,
    pinned: &IpAddr,
    preview: &orcel_provider_git::fetch::FetchPreview,
) -> String {
    let mut hasher = Sha256::new();
    digest_field(&mut hasher, b"ORCEL_GIT_FETCH_APPROVAL_V1");
    digest_field(&mut hasher, workspace.id.as_bytes());
    digest_field(&mut hasher, POLICY_REVISION.as_bytes());
    digest_field(&mut hasher, request.capability.as_bytes());
    digest_field(&mut hasher, request.operation.as_bytes());
    digest_field(
        &mut hasher,
        request.target.as_deref().unwrap_or_default().as_bytes(),
    );
    digest_field(&mut hasher, preview.repository_root.as_bytes());
    digest_field(&mut hasher, destination.id.as_bytes());
    digest_field(&mut hasher, provider_destination.canonical_url.as_bytes());
    digest_field(&mut hasher, provider_destination.hostname.as_bytes());
    digest_field(
        &mut hasher,
        provider_destination.port.to_string().as_bytes(),
    );
    digest_field(&mut hasher, pinned.to_string().as_bytes());
    digest_field(&mut hasher, preview.source_ref.as_bytes());
    digest_field(&mut hasher, preview.destination_ref.as_bytes());
    digest_field(&mut hasher, preview.head.as_bytes());
    digest_field(&mut hasher, preview.prior.as_bytes());
    hex_lower(&hasher.finalize())
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

fn required_target(request: &RequestEnvelope) -> Result<&str, ProviderError> {
    request.target.as_deref().ok_or_else(|| {
        ProviderError::new(
            FailureCode::InvalidRequest,
            "Git fetch repository target is required",
        )
    })
}

fn required_string<'a>(request: &'a RequestEnvelope, name: &str) -> Result<&'a str, ProviderError> {
    request
        .arguments
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ProviderError::new(
                FailureCode::InvalidRequest,
                format!("Git fetch requires arguments.{name}"),
            )
        })
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
    use orcel_contracts::INTERNAL_PROTOCOL_VERSION;
    use serde_json::json;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct StaticLookup {
        destination: FetchDestination,
    }

    impl FetchDestinationLookup for StaticLookup {
        fn destination(&self, _workspace_id: &str, policy_id: &str) -> Option<FetchDestination> {
            if policy_id == self.destination.id {
                Some(self.destination.clone())
            } else {
                None
            }
        }
    }

    struct NeverResolves;

    impl DnsResolver for NeverResolves {
        fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>, GitProviderError> {
            Err(resolved(hostname))
        }
    }

    /// Resolving answers `CAPABILITY_DENIED`, which no test here expects.
    fn resolved(hostname: &str) -> GitProviderError {
        GitProviderError {
            code: FailureCode::CapabilityDenied,
            message: format!("{hostname} was resolved"),
        }
    }

    /// Asking answers `APPROVAL_DENIED`, which no test here expects.
    struct NeverAsked;

    impl ApprovalBroker for NeverAsked {
        fn request_token(
            &self,
            _prompt: &ApprovalPrompt,
        ) -> Result<orcel_approval::ApprovedToken, orcel_approval::ApprovalError> {
            Err(orcel_approval::ApprovalError {
                code: FailureCode::ApprovalDenied,
                message: "the person was asked".into(),
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
            "orcel-fetch-dispatch-{}-{suffix}",
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
        fs::write(root.join("a.txt"), "one\n").expect("write");
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

    fn destination() -> FetchDestination {
        FetchDestination {
            workspace_id: "default".into(),
            id: "test-origin".into(),
            canonical_url: "https://example.com/repo.git".into(),
            hostname: "example.com".into(),
            port: 443,
        }
    }

    /// Founder decision of 2026-11-23: Git is off until it runs confined.
    /// Neither the preview nor the fetch asks, resolves or changes anything.
    /// (Before: the preview was local, and a denied approval refused the
    /// fetch.)
    #[test]
    fn preview_and_fetch_are_refused_before_the_prompt_and_the_resolver() {
        let root = repository();
        let head = git(&root, &["rev-parse", "HEAD"]).trim().to_owned();
        let lookup = StaticLookup {
            destination: destination(),
        };
        let before_refs = git(&root, &["show-ref"]);
        for (capability, operation, arguments) in [
            (
                "git.fetch.preview",
                "preview",
                json!({"policy_id": "test-origin", "branch": "main"}),
            ),
            (
                "git.fetch",
                "fetch",
                json!({"policy_id": "test-origin", "branch": "main", "expected_head": head, "expected_prior": "ABSENT"}),
            ),
        ] {
            let request = RequestEnvelope {
                version: INTERNAL_PROTOCOL_VERSION,
                request_id: "fetch-off".into(),
                client_session_id: "session".into(),
                workspace_id: "default".into(),
                capability: capability.into(),
                operation: operation.into(),
                target: Some(".".into()),
                arguments,
            };
            let error = dispatch(
                &workspace(&root),
                &NeverAsked,
                &request,
                &lookup,
                &NeverResolves,
            )
            .expect_err("off");
            assert_eq!(error.code, FailureCode::ProviderUnavailable);
            assert_eq!(error.message, orcel_provider_git::confinement::OFF_MESSAGE);
        }
        assert_eq!(git(&root, &["show-ref"]), before_refs);
        assert_eq!(git(&root, &["rev-parse", "HEAD"]).trim(), head);
        let _ = fs::remove_dir_all(root);
    }

    // Git for Windows maps `/dev/null` to the null device; Git 2.56 rejects `NUL`.
    fn null_device() -> &'static str {
        "/dev/null"
    }
}
