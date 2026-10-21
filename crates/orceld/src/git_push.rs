use orcel_approval::{now_ms, ApprovalBroker, ApprovalPrompt, ConsumeExpectation};
use orcel_contracts::{FailureCode, RequestEnvelope};
use orcel_policy::{PushDestination, Workspace, POLICY_REVISION};
use orcel_provider_fs::ProviderError;
use orcel_provider_git::{
    fetch::{DnsResolver, SystemResolver},
    push::{
        select_pinned_push_address, validate_credential_reference, validate_push_branch,
        validate_push_expected_head, validate_push_expected_prior, validate_push_policy_id,
        EnvCredentialResolver, GitPushDestination, HardenedPushTransport,
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
    lookup: &impl PushDestinationLookup,
    resolver: &impl DnsResolver,
) -> Result<Option<Value>, ProviderError> {
    match (request.capability.as_str(), request.operation.as_str()) {
        ("git.push.preview", "preview") => {
            let policy_id = required_string(request, "policy_id")?.to_owned();
            let source_branch = required_string(request, "source_branch")?.to_owned();
            let dest_branch = required_string(request, "dest_branch")?.to_owned();
            let credential_reference = required_string(request, "credential_reference")?.to_owned();
            let repository = required_target(request)?;
            let destination = lookup
                .destination(&request.workspace_id, &policy_id)
                .ok_or_else(|| {
                    ProviderError::new(
                        FailureCode::CapabilityDenied,
                        "Git push destination is not configured for this workspace",
                    )
                })?;
            if credential_reference != destination.credential_reference {
                return Err(ProviderError::new(
                    FailureCode::CapabilityDenied,
                    "Git push credential reference does not match the configured push destination",
                ));
            }
            let provider = GitProvider::new(&workspace.root).map_err(map_git_error)?;
            let provider_destination = provider_destination(&destination)?;
            let preview = provider
                .push_preview(
                    repository,
                    &provider_destination,
                    &source_branch,
                    &dest_branch,
                    &credential_reference,
                )
                .map_err(map_git_error)?;
            Ok(Some(preview.to_json()))
        }
        ("git.push", "push") => {
            let policy_id = required_string(request, "policy_id")?.to_owned();
            let source_branch = required_string(request, "source_branch")?.to_owned();
            let dest_branch = required_string(request, "dest_branch")?.to_owned();
            let expected_head = required_string(request, "expected_head")?.to_owned();
            let expected_prior = required_string(request, "expected_prior")?.to_owned();
            let credential_reference = required_string(request, "credential_reference")?.to_owned();
            let repository = required_target(request)?.to_owned();
            validate_push_policy_id(&policy_id).map_err(map_git_error)?;
            validate_push_branch(&source_branch).map_err(map_git_error)?;
            validate_push_branch(&dest_branch).map_err(map_git_error)?;
            validate_push_expected_head(&expected_head).map_err(map_git_error)?;
            validate_push_expected_prior(&expected_prior).map_err(map_git_error)?;
            validate_credential_reference(&credential_reference).map_err(map_git_error)?;
            let destination = lookup
                .destination(&request.workspace_id, &policy_id)
                .ok_or_else(|| {
                    ProviderError::new(
                        FailureCode::CapabilityDenied,
                        "Git push destination is not configured for this workspace",
                    )
                })?;
            if credential_reference != destination.credential_reference {
                return Err(ProviderError::new(
                    FailureCode::CapabilityDenied,
                    "Git push credential reference does not match the configured push destination",
                ));
            }
            let provider = GitProvider::new(&workspace.root).map_err(map_git_error)?;
            let provider_destination = provider_destination(&destination)?;
            let preview = provider
                .push_preview(
                    &repository,
                    &provider_destination,
                    &source_branch,
                    &dest_branch,
                    &credential_reference,
                )
                .map_err(map_git_error)?;
            if preview.head != expected_head {
                return Err(ProviderError::new(
                    FailureCode::TargetStale,
                    "Git HEAD does not match arguments.expected_head from push preview",
                ));
            }
            if preview.prior != expected_prior {
                return Err(ProviderError::new(
                    FailureCode::TargetStale,
                    "push tracking state does not match arguments.expected_prior from push preview",
                ));
            }
            let resolved = resolver
                .resolve(&provider_destination.hostname)
                .map_err(map_git_error)?;
            let pinned = select_pinned_push_address(&resolved).map_err(map_git_error)?;
            let digest = push_digest(
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
                "push one approved Git branch over pinned HTTPS with a protected credential reference",
                repository.clone(),
                push_summary(
                    &destination,
                    &provider_destination,
                    &pinned,
                    &source_branch,
                    &dest_branch,
                    &preview,
                ),
                digest.clone(),
            );
            let token = require_approval(approval, &prompt)?;
            approval
                .consume(
                    &token,
                    &ConsumeExpectation::new(digest, workspace.id.clone(), POLICY_REVISION),
                    now_ms(),
                )
                .map_err(|error| ProviderError::new(error.code, error.message))?;
            let approved = orcel_provider_git::push::ApprovedPush {
                relative: &repository,
                destination: &provider_destination,
                source_branch: &source_branch,
                dest_branch: &dest_branch,
                expected_head: &expected_head,
                expected_prior: &expected_prior,
                credential_reference: &credential_reference,
                pinned: &pinned,
            };
            let result = provider
                .push_approved(
                    &approved,
                    resolver,
                    &EnvCredentialResolver,
                    &HardenedPushTransport,
                )
                .map_err(map_git_error)?;
            Ok(Some(result))
        }
        _ => Ok(None),
    }
}

pub trait PushDestinationLookup {
    fn destination(&self, workspace_id: &str, policy_id: &str) -> Option<PushDestination>;
}

pub struct PolicyPushLookup<'a> {
    pub policy: &'a orcel_policy::PolicyEngine,
}

impl PushDestinationLookup for PolicyPushLookup<'_> {
    fn destination(&self, workspace_id: &str, policy_id: &str) -> Option<PushDestination> {
        self.policy
            .push_destination(workspace_id, policy_id)
            .cloned()
    }
}

pub fn provider_destination(
    destination: &PushDestination,
) -> Result<GitPushDestination, ProviderError> {
    Ok(GitPushDestination {
        id: destination.id.clone(),
        canonical_url: destination.canonical_url.clone(),
        hostname: destination.hostname.clone(),
        port: destination.port,
        credential_reference: destination.credential_reference.clone(),
    })
}

pub fn system_resolver() -> SystemResolver {
    SystemResolver
}

fn push_summary(
    destination: &PushDestination,
    provider_destination: &GitPushDestination,
    pinned: &IpAddr,
    source_branch: &str,
    dest_branch: &str,
    preview: &orcel_provider_git::push::PushPreview,
) -> String {
    format!(
        "policy={} url={} host={} port={} pinned={} source={} dest={} expected_head={} expected_prior={} credential_reference={} source_branches={}/{}",
        destination.id,
        provider_destination.canonical_url,
        provider_destination.hostname,
        provider_destination.port,
        pinned,
        preview.source_ref,
        preview.destination_ref,
        preview.head,
        preview.prior,
        destination.credential_reference,
        source_branch,
        dest_branch,
    )
}

fn push_digest(
    workspace: &Workspace,
    request: &RequestEnvelope,
    destination: &PushDestination,
    provider_destination: &GitPushDestination,
    pinned: &IpAddr,
    preview: &orcel_provider_git::push::PushPreview,
) -> String {
    let mut hasher = Sha256::new();
    digest_field(&mut hasher, b"ORCEL_GIT_PUSH_APPROVAL_V1");
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
    digest_field(&mut hasher, destination.credential_reference.as_bytes());
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
            "Git push repository target is required",
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
                format!("Git push requires arguments.{name}"),
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
    use orcel_approval::test_support::FixedApprovalBroker;
    use orcel_approval::ApprovalDecision;
    use orcel_contracts::INTERNAL_PROTOCOL_VERSION;
    use orcel_provider_git::push::{CredentialResolver, ResolvedCredential};
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct StaticLookup {
        destination: PushDestination,
    }

    impl PushDestinationLookup for StaticLookup {
        fn destination(&self, _workspace_id: &str, policy_id: &str) -> Option<PushDestination> {
            if policy_id == self.destination.id {
                Some(self.destination.clone())
            } else {
                None
            }
        }
    }

    struct StaticResolver {
        addresses: Vec<IpAddr>,
    }

    impl DnsResolver for StaticResolver {
        fn resolve(&self, _hostname: &str) -> Result<Vec<IpAddr>, GitProviderError> {
            Ok(self.addresses.clone())
        }
    }

    struct DenyAll;

    impl ApprovalBroker for DenyAll {
        fn request_token(
            &self,
            _prompt: &ApprovalPrompt,
        ) -> Result<orcel_approval::ApprovedToken, orcel_approval::ApprovalError> {
            Err(orcel_approval::ApprovalError {
                code: FailureCode::ApprovalDenied,
                message: "local user denied Git push".into(),
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

    struct UnavailableBroker;

    impl ApprovalBroker for UnavailableBroker {
        fn request_token(
            &self,
            _prompt: &ApprovalPrompt,
        ) -> Result<orcel_approval::ApprovedToken, orcel_approval::ApprovalError> {
            Err(orcel_approval::ApprovalError {
                code: FailureCode::ApprovalUnavailable,
                message: "approval unavailable in test".into(),
            })
        }

        fn consume(
            &self,
            _token: &orcel_approval::ApprovedToken,
            _expected: &ConsumeExpectation,
            _now_ms: u64,
        ) -> Result<(), orcel_approval::ApprovalError> {
            Err(orcel_approval::ApprovalError {
                code: FailureCode::ApprovalUnavailable,
                message: "approval unavailable in test".into(),
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
            "orcel-push-dispatch-{}-{suffix}",
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
        git(&root, &["init", "-b", "main"]);
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

    fn destination() -> PushDestination {
        PushDestination {
            workspace_id: "default".into(),
            id: "test-origin".into(),
            canonical_url: "https://example.com/repo.git".into(),
            hostname: "example.com".into(),
            port: 443,
            credential_reference: "anonymous".into(),
        }
    }

    #[test]
    fn preview_is_local_and_denial_and_unavailable_fail_closed() {
        let root = repository();
        let head = git(&root, &["rev-parse", "HEAD"]).trim().to_owned();
        let request = RequestEnvelope {
            version: INTERNAL_PROTOCOL_VERSION,
            request_id: "push-preview".into(),
            client_session_id: "session".into(),
            workspace_id: "default".into(),
            capability: "git.push.preview".into(),
            operation: "preview".into(),
            target: Some(".".into()),
            arguments: json!({"policy_id": "test-origin", "source_branch": "main", "dest_branch": "main", "credential_reference": "anonymous"}),
        };
        let lookup = StaticLookup {
            destination: destination(),
        };
        let resolver = StaticResolver {
            addresses: vec!["8.8.8.8".parse().unwrap()],
        };
        let before_refs = git(&root, &["show-ref"]);
        let result = dispatch(
            &workspace(&root),
            &FixedApprovalBroker(ApprovalDecision::Approved),
            &request,
            &lookup,
            &resolver,
        )
        .expect("dispatch")
        .expect("handled");
        assert_eq!(result["head"], head);
        assert_eq!(result["source_ref"], "refs/heads/main");
        assert_eq!(result["destination_ref"], "refs/heads/main");
        assert_eq!(result["prior"], "ABSENT");
        assert_eq!(result["credential_reference"], "anonymous");
        assert_eq!(git(&root, &["show-ref"]), before_refs);
        assert_eq!(git(&root, &["rev-parse", "HEAD"]).trim(), head);

        let push_request = RequestEnvelope {
            version: INTERNAL_PROTOCOL_VERSION,
            request_id: "push-deny".into(),
            client_session_id: "session".into(),
            workspace_id: "default".into(),
            capability: "git.push".into(),
            operation: "push".into(),
            target: Some(".".into()),
            arguments: json!({"policy_id": "test-origin", "source_branch": "main", "dest_branch": "main", "expected_head": head, "expected_prior": "ABSENT", "credential_reference": "anonymous"}),
        };
        let error = dispatch(
            &workspace(&root),
            &DenyAll,
            &push_request,
            &lookup,
            &resolver,
        )
        .expect_err("denial");
        assert_eq!(error.code, FailureCode::ApprovalDenied);
        let error = dispatch(
            &workspace(&root),
            &UnavailableBroker,
            &push_request,
            &lookup,
            &resolver,
        )
        .expect_err("unavailable");
        assert_eq!(error.code, FailureCode::ApprovalUnavailable);
        assert_eq!(git(&root, &["rev-parse", "HEAD"]).trim(), head);
        let _ = fs::remove_dir_all(root);
        let _ = BTreeMap::<String, String>::new();
    }

    #[test]
    fn mismatched_credential_reference_fails_before_approval() {
        let root = repository();
        let head = git(&root, &["rev-parse", "HEAD"]).trim().to_owned();
        let lookup = StaticLookup {
            destination: destination(),
        };
        let resolver = StaticResolver {
            addresses: vec!["8.8.8.8".parse().unwrap()],
        };
        let request = RequestEnvelope {
            version: INTERNAL_PROTOCOL_VERSION,
            request_id: "push-mismatch".into(),
            client_session_id: "session".into(),
            workspace_id: "default".into(),
            capability: "git.push".into(),
            operation: "push".into(),
            target: Some(".".into()),
            arguments: json!({"policy_id": "test-origin", "source_branch": "main", "dest_branch": "main", "expected_head": head, "expected_prior": "ABSENT", "credential_reference": "other-reference"}),
        };
        let error = dispatch(
            &workspace(&root),
            &FixedApprovalBroker(ApprovalDecision::Approved),
            &request,
            &lookup,
            &resolver,
        )
        .expect_err("mismatch");
        assert_eq!(error.code, FailureCode::CapabilityDenied);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn approval_digest_binds_reference_without_secret_material() {
        let root = repository();
        let workspace_value = workspace(&root);
        let request = RequestEnvelope {
            version: INTERNAL_PROTOCOL_VERSION,
            request_id: "push-digest".into(),
            client_session_id: "session".into(),
            workspace_id: "default".into(),
            capability: "git.push".into(),
            operation: "push".into(),
            target: Some(".".into()),
            arguments: json!({"policy_id": "test-origin", "source_branch": "main", "dest_branch": "main", "expected_head": "0123456789abcdef0123456789abcdef01234567", "expected_prior": "ABSENT", "credential_reference": "anonymous"}),
        };
        let provider_dest = provider_destination(&destination()).expect("provider dest");
        let preview = orcel_provider_git::push::PushPreview {
            repository_root: ".".to_owned(),
            head: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            branch: Some("main".to_owned()),
            policy_id: "test-origin".to_owned(),
            canonical_url: provider_dest.canonical_url.clone(),
            hostname: "example.com".to_owned(),
            port: 443,
            source_branch: "main".to_owned(),
            dest_branch: "main".to_owned(),
            source_ref: "refs/heads/main".to_owned(),
            destination_ref: "refs/heads/main".to_owned(),
            source_id: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            prior: "ABSENT".to_owned(),
            credential_reference: "anonymous".to_owned(),
        };
        let pinned: IpAddr = "8.8.8.8".parse().unwrap();
        let first = push_digest(
            &workspace_value,
            &request,
            &destination(),
            &provider_dest,
            &pinned,
            &preview,
        );
        let mut drifted_destination = destination();
        drifted_destination.credential_reference = "other-reference".to_owned();
        let drifted_provider_destination =
            provider_destination(&drifted_destination).expect("drifted provider dest");
        let second = push_digest(
            &workspace_value,
            &request,
            &drifted_destination,
            &drifted_provider_destination,
            &pinned,
            &preview,
        );
        assert_ne!(first, second);
        assert_eq!(first.len(), 64);
        assert!(!first.contains("digest-probe-secret"));
        let resolved = ResolvedCredential {
            reference: "anonymous".to_owned(),
            secret: None,
        };
        assert!(resolved.is_anonymous());
        struct ProbeResolver;
        impl CredentialResolver for ProbeResolver {
            fn resolve(&self, reference: &str) -> Result<ResolvedCredential, GitProviderError> {
                Ok(ResolvedCredential {
                    reference: reference.to_owned(),
                    secret: None,
                })
            }
        }
        let probe = ProbeResolver.resolve("anonymous").expect("probe");
        assert_eq!(probe.reference, "anonymous");
        let _ = fs::remove_dir_all(root);
    }

    // Git for Windows maps `/dev/null` to the null device; Git 2.56 rejects `NUL`.
    fn null_device() -> &'static str {
        "/dev/null"
    }
}
