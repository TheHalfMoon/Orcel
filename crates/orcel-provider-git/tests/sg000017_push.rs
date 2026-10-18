use orcel_provider_git::fetch::{DnsResolver, SystemResolver};
use orcel_provider_git::push::{
    parse_push_destination, push_tracking_ref, ApprovedPush, CredentialResolver,
    GitPushDestination, HardenedPushTransport, PushOperation, PushSecret, PushTransport,
    RemoteQuery, ResolvedCredential,
};
use orcel_provider_git::{GitProvider, GitProviderError};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

struct StaticResolver {
    addresses: Vec<IpAddr>,
}

impl DnsResolver for StaticResolver {
    fn resolve(&self, _hostname: &str) -> Result<Vec<IpAddr>, GitProviderError> {
        Ok(self.addresses.clone())
    }
}

struct DriftResolver {
    second: Vec<IpAddr>,
    calls: std::cell::Cell<usize>,
}

impl DnsResolver for DriftResolver {
    fn resolve(&self, _hostname: &str) -> Result<Vec<IpAddr>, GitProviderError> {
        let calls = self.calls.get();
        self.calls.set(calls + 1);
        if calls == 0 {
            Ok(vec!["8.8.8.8".parse().unwrap()])
        } else {
            Ok(self.second.clone())
        }
    }
}

struct StaticCredential {
    reference: String,
    secret: Option<String>,
}

impl CredentialResolver for StaticCredential {
    fn resolve(&self, reference: &str) -> Result<ResolvedCredential, GitProviderError> {
        assert_eq!(reference, self.reference);
        Ok(ResolvedCredential {
            reference: reference.to_owned(),
            secret: self.secret.clone().map(PushSecret::new),
        })
    }
}

struct LeakyTransport {
    secret: String,
}

impl PushTransport for LeakyTransport {
    fn query_remote_ref(&self, _query: &RemoteQuery<'_>) -> Result<String, GitProviderError> {
        Err(GitProviderError {
            code: orcel_contracts::FailureCode::ProviderUnavailable,
            message: format!("simulated transport failure carrying {}", self.secret),
        })
    }

    fn send_push(&self, _operation: &PushOperation<'_>) -> Result<(), GitProviderError> {
        Err(GitProviderError {
            code: orcel_contracts::FailureCode::ProviderUnavailable,
            message: "leaky transport must not reach push".to_owned(),
        })
    }
}

struct LocalPushTransport {
    remote: PathBuf,
}

impl PushTransport for LocalPushTransport {
    fn query_remote_ref(&self, query: &RemoteQuery<'_>) -> Result<String, GitProviderError> {
        assert!(
            query.url.starts_with("https://"),
            "transport must receive the validated canonical HTTPS URL"
        );
        let output = Command::new("git")
            .args(["ls-remote", self.remote.to_str().unwrap(), query.dest_ref])
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", null_device())
            .output()
            .expect("ls-remote helper");
        assert!(
            output.status.success(),
            "ls-remote helper failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8_lossy(&output.stdout).into_owned();
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            if parts.next().is_some() && parts.next() == Some(query.dest_ref) {
                let id = line.split_whitespace().next().unwrap_or("");
                return Ok(id.to_owned());
            }
        }
        Ok("ABSENT".to_owned())
    }

    fn send_push(&self, operation: &PushOperation<'_>) -> Result<(), GitProviderError> {
        assert!(
            operation.url.starts_with("https://"),
            "transport must receive the validated canonical HTTPS URL"
        );
        assert!(
            !operation.source_ref.starts_with('+') && !operation.dest_ref.starts_with('+'),
            "test transport never force-pushes"
        );
        let refspec = format!("{}:{}", operation.source_ref, operation.dest_ref);
        let output = Command::new("git")
            .args(["push", self.remote.to_str().unwrap(), &refspec])
            .current_dir(operation.repo)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", null_device())
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .expect("push helper");
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            let lower = stderr.to_ascii_lowercase();
            if lower.contains("non-fast-forward")
                || lower.contains("fetch first")
                || lower.contains("failed to push some refs")
            {
                return Err(GitProviderError {
                    code: orcel_contracts::FailureCode::TargetStale,
                    message: format!("remote destination ref advanced; push rejected as non-fast-forward: {stderr}"),
                });
            }
            return Err(GitProviderError {
                code: orcel_contracts::FailureCode::ProviderUnavailable,
                message: format!("local test push failed: {stderr}"),
            });
        }
        Ok(())
    }
}

// Unique per call: macOS clocks have microsecond resolution, so parallel
// tests in one process can otherwise draw the same timestamp.
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn temp_root(label: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "orcel-sg17-push-{label}-{}-{suffix}-{sequence}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("create temp root");
    root
}

fn git(cwd: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", null_device())
        .output()
        .expect("start git helper");
    assert!(
        output.status.success(),
        "git helper failed {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn work_repository_with_remote() -> (PathBuf, PathBuf) {
    let base = temp_root("work");
    let remote = base.join("origin.git");
    let work = base.join("work");
    std::fs::create_dir_all(&work).unwrap();
    git(&base, &["init", "--bare", "origin.git"]);
    git(&work, &["init", "-b", "main"]);
    git(&work, &["config", "user.email", "orcel@example.invalid"]);
    git(&work, &["config", "user.name", "Orcel Test"]);
    std::fs::write(work.join("a.txt"), "one\n").unwrap();
    git(&work, &["add", "a.txt"]);
    git(&work, &["commit", "-m", "initial"]);
    (work, remote)
}

fn anonymous_destination() -> GitPushDestination {
    parse_push_destination("test-origin", "https://example.com/repo.git", "anonymous")
        .expect("destination")
}

fn public_ip() -> IpAddr {
    "8.8.8.8".parse().unwrap()
}

fn is_hex40(value: &str) -> bool {
    value.len() == 40
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        && value.bytes().all(|byte| !byte.is_ascii_uppercase())
}

#[test]
fn preview_is_local_read_only_with_stale_protection_material() {
    let (work, remote) = work_repository_with_remote();
    let provider = GitProvider::new(&work).unwrap();
    let head = git(&work, &["rev-parse", "HEAD"]).trim().to_owned();
    let before_refs = git(&work, &["show-ref"]);
    let before_status = git(
        &work,
        &[
            "status",
            "--porcelain=v2",
            "--branch",
            "--untracked-files=all",
        ],
    );
    let preview = provider
        .push_preview(".", &anonymous_destination(), "main", "main", "anonymous")
        .unwrap();
    assert_eq!(preview.head, head);
    assert_eq!(preview.source_id, head);
    assert_eq!(preview.source_ref, "refs/heads/main");
    assert_eq!(preview.destination_ref, "refs/heads/main");
    assert_eq!(preview.prior, "ABSENT");
    assert_eq!(preview.hostname, "example.com");
    assert_eq!(preview.port, 443);
    assert_eq!(preview.credential_reference, "anonymous");
    let rendered = preview.to_json().to_string();
    assert!(rendered.contains("credential_redacted"));
    assert_eq!(git(&work, &["show-ref"]), before_refs);
    assert_eq!(
        git(
            &work,
            &[
                "status",
                "--porcelain=v2",
                "--branch",
                "--untracked-files=all"
            ]
        ),
        before_status
    );
    assert_eq!(git(&work, &["rev-parse", "HEAD"]).trim(), head);
    let _ = std::fs::remove_dir_all(work.parent().unwrap());
    let _ = remote;
}

#[test]
fn preview_rejects_credential_mismatch_without_secret_access() {
    let (work, _remote) = work_repository_with_remote();
    let provider = GitProvider::new(&work).unwrap();
    let error = provider
        .push_preview(
            ".",
            &anonymous_destination(),
            "main",
            "main",
            "other-reference",
        )
        .expect_err("mismatch must fail");
    assert_eq!(error.code, orcel_contracts::FailureCode::CapabilityDenied);
    let _ = std::fs::remove_dir_all(work.parent().unwrap());
}

#[test]
fn approved_push_happy_path_records_evidence_and_tracking() {
    let (work, remote) = work_repository_with_remote();
    let base = work.parent().unwrap().to_path_buf();
    let provider = GitProvider::new(&work).unwrap();
    let destination = anonymous_destination();
    let preview = provider
        .push_preview(".", &destination, "main", "main", "anonymous")
        .unwrap();
    let resolver = StaticResolver {
        addresses: vec![public_ip()],
    };
    let credential = StaticCredential {
        reference: "anonymous".to_owned(),
        secret: None,
    };
    let transport = LocalPushTransport {
        remote: remote.clone(),
    };
    let pinned = public_ip();
    let approved = ApprovedPush {
        relative: ".",
        destination: &destination,
        source_branch: "main",
        dest_branch: "main",
        expected_head: &preview.head,
        expected_prior: &preview.prior,
        credential_reference: "anonymous",
        pinned: &pinned,
    };
    let result = provider
        .push_approved(&approved, &resolver, &credential, &transport)
        .expect("approved push");
    assert_eq!(result["policy_id"], "test-origin");
    assert_eq!(result["hostname"], "example.com");
    assert_eq!(result["port"], 443);
    assert_eq!(result["pinned_address"], "8.8.8.8");
    assert_eq!(result["source_ref"], "refs/heads/main");
    assert_eq!(result["destination_ref"], "refs/heads/main");
    let resulting = result["result"].as_str().expect("result object id");
    assert!(is_hex40(resulting));
    assert_eq!(resulting, preview.head);
    assert_eq!(result["credential_reference"], "anonymous");
    assert_eq!(result["credential_redacted"], true);
    let rendered = result.to_string();
    assert!(!rendered.contains("super-secret"));
    let stored = git(
        &work,
        &[
            "rev-parse",
            "--verify",
            &push_tracking_ref("test-origin", "main"),
        ],
    );
    assert_eq!(stored.trim(), resulting);
    assert_eq!(git(&work, &["rev-parse", "HEAD"]).trim(), preview.head);
    let remote_id = git(&remote, &["rev-parse", "--verify", "refs/heads/main"]);
    assert_eq!(remote_id.trim(), resulting);

    std::fs::write(work.join("b.txt"), "two\n").unwrap();
    git(&work, &["add", "b.txt"]);
    git(&work, &["commit", "-m", "second"]);
    let preview_two = provider
        .push_preview(".", &destination, "main", "main", "anonymous")
        .unwrap();
    assert_eq!(preview_two.prior, resulting);
    let approved_two = ApprovedPush {
        relative: ".",
        destination: &destination,
        source_branch: "main",
        dest_branch: "main",
        expected_head: &preview_two.head,
        expected_prior: &preview_two.prior,
        credential_reference: "anonymous",
        pinned: &pinned,
    };
    let result_two = provider
        .push_approved(&approved_two, &resolver, &credential, &transport)
        .expect("second push");
    assert_ne!(result_two["result"].as_str().unwrap(), resulting);
    let _ = std::fs::remove_dir_all(base);
}

#[test]
fn approved_push_with_credential_reference_keeps_secret_out_of_evidence() {
    let (work, remote) = work_repository_with_remote();
    let base = work.parent().unwrap().to_path_buf();
    let provider = GitProvider::new(&work).unwrap();
    let destination = parse_push_destination(
        "test-origin",
        "https://example.com/repo.git",
        "test-credential",
    )
    .expect("destination");
    let fake_secret = "sg17-fake-secret-9f8e7d6c5b4a";
    let preview = provider
        .push_preview(".", &destination, "main", "main", "test-credential")
        .unwrap();
    let resolver = StaticResolver {
        addresses: vec![public_ip()],
    };
    let credential = StaticCredential {
        reference: "test-credential".to_owned(),
        secret: Some(fake_secret.to_owned()),
    };
    let transport = LocalPushTransport { remote };
    let pinned = public_ip();
    let approved = ApprovedPush {
        relative: ".",
        destination: &destination,
        source_branch: "main",
        dest_branch: "main",
        expected_head: &preview.head,
        expected_prior: &preview.prior,
        credential_reference: "test-credential",
        pinned: &pinned,
    };
    let result = provider
        .push_approved(&approved, &resolver, &credential, &transport)
        .expect("authed push");
    let rendered = result.to_string();
    assert!(!rendered.contains(fake_secret));
    assert_eq!(result["credential_reference"], "test-credential");
    assert_eq!(result["credential_redacted"], true);
    let _ = std::fs::remove_dir_all(base);
}

#[test]
fn transport_secret_leak_is_redacted_from_push_errors() {
    let (work, _remote) = work_repository_with_remote();
    let base = work.parent().unwrap().to_path_buf();
    let provider = GitProvider::new(&work).unwrap();
    let destination = parse_push_destination(
        "test-origin",
        "https://example.com/repo.git",
        "test-credential",
    )
    .expect("destination");
    let fake_secret = "sg17-leak-probe-secret-001";
    let preview = provider
        .push_preview(".", &destination, "main", "main", "test-credential")
        .unwrap();
    let resolver = StaticResolver {
        addresses: vec![public_ip()],
    };
    let credential = StaticCredential {
        reference: "test-credential".to_owned(),
        secret: Some(fake_secret.to_owned()),
    };
    let transport = LeakyTransport {
        secret: fake_secret.to_owned(),
    };
    let pinned = public_ip();
    let approved = ApprovedPush {
        relative: ".",
        destination: &destination,
        source_branch: "main",
        dest_branch: "main",
        expected_head: &preview.head,
        expected_prior: &preview.prior,
        credential_reference: "test-credential",
        pinned: &pinned,
    };
    let error = provider
        .push_approved(&approved, &resolver, &credential, &transport)
        .expect_err("leaky transport must fail redacted");
    assert!(!error.message.contains(fake_secret));
    assert!(error.message.contains("REDACTED"));
    let _ = std::fs::remove_dir_all(base);
}

#[test]
fn push_rejects_non_public_pinned_address_before_network() {
    let (work, remote) = work_repository_with_remote();
    let base = work.parent().unwrap().to_path_buf();
    let provider = GitProvider::new(&work).unwrap();
    let destination = anonymous_destination();
    let preview = provider
        .push_preview(".", &destination, "main", "main", "anonymous")
        .unwrap();
    let loopback: IpAddr = "127.0.0.1".parse().unwrap();
    let resolver = StaticResolver {
        addresses: vec![loopback],
    };
    let credential = StaticCredential {
        reference: "anonymous".to_owned(),
        secret: None,
    };
    let transport = LocalPushTransport { remote };
    let approved = ApprovedPush {
        relative: ".",
        destination: &destination,
        source_branch: "main",
        dest_branch: "main",
        expected_head: &preview.head,
        expected_prior: &preview.prior,
        credential_reference: "anonymous",
        pinned: &loopback,
    };
    let error = provider
        .push_approved(&approved, &resolver, &credential, &transport)
        .expect_err("loopback must fail");
    assert_eq!(error.code, orcel_contracts::FailureCode::CapabilityDenied);
    assert_eq!(git(&work, &["rev-parse", "HEAD"]).trim(), preview.head);
    let _ = std::fs::remove_dir_all(base);
}

#[test]
fn push_fails_closed_on_stale_head_prior_and_drift() {
    let (work, remote) = work_repository_with_remote();
    let base = work.parent().unwrap().to_path_buf();
    let provider = GitProvider::new(&work).unwrap();
    let destination = anonymous_destination();
    let preview = provider
        .push_preview(".", &destination, "main", "main", "anonymous")
        .unwrap();
    let resolver = StaticResolver {
        addresses: vec![public_ip()],
    };
    let credential = StaticCredential {
        reference: "anonymous".to_owned(),
        secret: None,
    };
    let transport = LocalPushTransport {
        remote: remote.clone(),
    };
    let stale_head = "ffffffffffffffffffffffffffffffffffffffff";
    let pinned = public_ip();
    let stale = ApprovedPush {
        relative: ".",
        destination: &destination,
        source_branch: "main",
        dest_branch: "main",
        expected_head: stale_head,
        expected_prior: &preview.prior,
        credential_reference: "anonymous",
        pinned: &pinned,
    };
    let error = provider
        .push_approved(&stale, &resolver, &credential, &transport)
        .expect_err("stale head must fail");
    assert_eq!(error.code, orcel_contracts::FailureCode::TargetStale);

    let stale_prior = ApprovedPush {
        relative: ".",
        destination: &destination,
        source_branch: "main",
        dest_branch: "main",
        expected_head: &preview.head,
        expected_prior: &preview.head,
        credential_reference: "anonymous",
        pinned: &pinned,
    };
    let error = provider
        .push_approved(&stale_prior, &resolver, &credential, &transport)
        .expect_err("stale prior must fail");
    assert_eq!(error.code, orcel_contracts::FailureCode::TargetStale);

    let drift = DriftResolver {
        second: vec!["1.1.1.1".parse().unwrap()],
        calls: std::cell::Cell::new(1),
    };
    let drifted = ApprovedPush {
        relative: ".",
        destination: &destination,
        source_branch: "main",
        dest_branch: "main",
        expected_head: &preview.head,
        expected_prior: &preview.prior,
        credential_reference: "anonymous",
        pinned: &pinned,
    };
    let error = provider
        .push_approved(&drifted, &drift, &credential, &transport)
        .expect_err("drift must fail");
    assert_eq!(error.code, orcel_contracts::FailureCode::TargetStale);

    let mismatched = ApprovedPush {
        relative: ".",
        destination: &destination,
        source_branch: "main",
        dest_branch: "main",
        expected_head: &preview.head,
        expected_prior: &preview.prior,
        credential_reference: "other-reference",
        pinned: &pinned,
    };
    let error = provider
        .push_approved(&mismatched, &resolver, &credential, &transport)
        .expect_err("credential mismatch must fail");
    assert_eq!(error.code, orcel_contracts::FailureCode::CapabilityDenied);
    assert_eq!(git(&work, &["rev-parse", "HEAD"]).trim(), preview.head);
    let _ = std::fs::remove_dir_all(base);
}

#[test]
fn push_fails_closed_when_remote_advanced_after_preview() {
    let (work, remote) = work_repository_with_remote();
    let base = work.parent().unwrap().to_path_buf();
    let provider = GitProvider::new(&work).unwrap();
    let destination = anonymous_destination();
    let preview = provider
        .push_preview(".", &destination, "main", "main", "anonymous")
        .unwrap();
    git(&work, &["push", remote.to_str().unwrap(), "main:main"]);
    let second = base.join("second");
    git(
        &base,
        &["clone", "-b", "main", remote.to_str().unwrap(), "second"],
    );
    git(&second, &["config", "user.email", "orcel@example.invalid"]);
    git(&second, &["config", "user.name", "Orcel Test"]);
    std::fs::write(second.join("remote.txt"), "remote\n").unwrap();
    git(&second, &["add", "remote.txt"]);
    git(&second, &["commit", "-m", "remote advance"]);
    git(&second, &["push", "origin", "main"]);
    std::fs::write(work.join("local.txt"), "local\n").unwrap();
    git(&work, &["add", "local.txt"]);
    git(&work, &["commit", "-m", "local diverge"]);

    let fresh = provider
        .push_preview(".", &destination, "main", "main", "anonymous")
        .unwrap();
    let resolver = StaticResolver {
        addresses: vec![public_ip()],
    };
    let credential = StaticCredential {
        reference: "anonymous".to_owned(),
        secret: None,
    };
    let transport = LocalPushTransport {
        remote: remote.clone(),
    };
    let pinned = public_ip();
    let diverged = ApprovedPush {
        relative: ".",
        destination: &destination,
        source_branch: "main",
        dest_branch: "main",
        expected_head: &fresh.head,
        expected_prior: &preview.prior,
        credential_reference: "anonymous",
        pinned: &pinned,
    };
    let error = provider
        .push_approved(&diverged, &resolver, &credential, &transport)
        .expect_err("diverged push must fail closed");
    assert_eq!(error.code, orcel_contracts::FailureCode::TargetStale);
    let _ = std::fs::remove_dir_all(base);
}

#[test]
fn push_rejects_unsafe_repository_local_config() {
    for (key, value) in [
        ("url.https://evil.invalid.insteadOf", "https://example.com/"),
        ("http.proxy", "http://proxy.invalid"),
        ("http.extraHeader", "Authorization: Bearer x"),
        ("credential.helper", "store"),
        ("core.askPass", "/bin/true"),
    ] {
        let (work, remote) = work_repository_with_remote();
        let base = work.parent().unwrap().to_path_buf();
        git(&work, &["config", "--local", key, value]);
        let provider = GitProvider::new(&work).unwrap();
        let destination = anonymous_destination();
        let preview = provider
            .push_preview(".", &destination, "main", "main", "anonymous")
            .unwrap();
        let resolver = StaticResolver {
            addresses: vec![public_ip()],
        };
        let credential = StaticCredential {
            reference: "anonymous".to_owned(),
            secret: None,
        };
        let transport = LocalPushTransport { remote };
        let pinned = public_ip();
        let guarded = ApprovedPush {
            relative: ".",
            destination: &destination,
            source_branch: "main",
            dest_branch: "main",
            expected_head: &preview.head,
            expected_prior: &preview.prior,
            credential_reference: "anonymous",
            pinned: &pinned,
        };
        let error = provider
            .push_approved(&guarded, &resolver, &credential, &transport)
            .expect_err("unsafe config must fail");
        assert_eq!(
            error.code,
            orcel_contracts::FailureCode::CapabilityDenied,
            "key {key}"
        );
        let _ = std::fs::remove_dir_all(base);
    }
}

#[test]
fn push_denies_arbitrary_refspecs_branches_and_force_shapes() {
    let (work, _remote) = work_repository_with_remote();
    let base = work.parent().unwrap().to_path_buf();
    let provider = GitProvider::new(&work).unwrap();
    let destination = anonymous_destination();
    for bad in [
        "refs/heads/main",
        "main:other",
        "+main",
        "star*",
        "question?",
        "colon:name",
        "plus+name",
        "../escape",
        "main..other",
        "main@{1}",
    ] {
        assert!(
            provider
                .push_preview(".", &destination, bad, "main", "anonymous")
                .is_err(),
            "source {bad} must fail"
        );
        assert!(
            provider
                .push_preview(".", &destination, "main", bad, "anonymous")
                .is_err(),
            "dest {bad} must fail"
        );
    }
    let error = provider
        .push_preview(".", &destination, "missing-branch", "main", "anonymous")
        .expect_err("missing source ref must fail");
    assert_eq!(error.code, orcel_contracts::FailureCode::InvalidRequest);
    let _ = std::fs::remove_dir_all(base);
}

#[test]
fn real_https_push_transport_is_exercised_but_success_remains_unproven() {
    let destination = parse_push_destination(
        "qualification",
        "https://github.com/TheHalfMoon/Orcel.git",
        "anonymous",
    )
    .expect("qualification destination");
    let resolver = SystemResolver;
    let resolved = resolver
        .resolve(&destination.hostname)
        .expect("resolve github.com");
    assert!(!resolved.is_empty());
    let pinned = orcel_provider_git::push::select_pinned_push_address(&resolved).expect("pinned");
    assert!(orcel_provider_git::fetch::is_public_address(&pinned));

    let (work, _remote) = work_repository_with_remote();
    let base = work.parent().unwrap().to_path_buf();
    let provider = GitProvider::new(&work).unwrap();
    let preview = provider
        .push_preview(".", &destination, "main", "main", "anonymous")
        .expect("preview");
    let transport = HardenedPushTransport;
    let credential = ResolvedCredential::anonymous();
    match transport.query_remote_ref(&RemoteQuery {
        repo: work.as_path(),
        url: &destination.canonical_url,
        hostname: &destination.hostname,
        port: destination.port,
        pinned: &pinned,
        dest_ref: "refs/heads/main",
        credential: &credential,
    }) {
        Ok(value) => assert!(is_hex40(&value), "ls-remote returns a valid object id"),
        Err(error) => assert_eq!(
            error.code,
            orcel_contracts::FailureCode::ProviderUnavailable,
            "offline transport failure stays typed"
        ),
    }
    let push_error = transport
        .send_push(&PushOperation {
            repo: work.as_path(),
            url: &destination.canonical_url,
            hostname: &destination.hostname,
            port: destination.port,
            pinned: &pinned,
            source_ref: &preview.source_ref,
            dest_ref: "refs/heads/orcel-sg17-unproven-probe",
            credential: &credential,
        })
        .expect_err("anonymous push to the canonical repository must fail closed");
    assert_eq!(
        push_error.code,
        orcel_contracts::FailureCode::ProviderUnavailable,
        "anonymous push denial stays a typed transport failure"
    );
    assert_eq!(git(&work, &["rev-parse", "HEAD"]).trim(), preview.head);
    let _ = std::fs::remove_dir_all(base);
}

#[test]
fn sg000015_mutation_and_sg000016_fetch_regressions_remain_green() {
    let (work, _remote) = work_repository_with_remote();
    let base = work.parent().unwrap().to_path_buf();
    let provider = GitProvider::new(&work).unwrap();
    let status = provider.status(".").expect("read-only status");
    assert!(status["porcelain_v2"].is_string());
    let log = provider.log(".", 5).expect("read-only log");
    assert_eq!(log["commits"].as_array().unwrap().len(), 1);
    let fetch_destination =
        orcel_provider_git::fetch::parse_destination("test-origin", "https://example.com/repo.git")
            .expect("fetch destination");
    let fetch_preview = provider
        .fetch_preview(".", "test-origin", "main", &fetch_destination)
        .expect("fetch preview");
    assert_eq!(fetch_preview.source_ref, "refs/heads/main");
    let _ = std::fs::remove_dir_all(base);
}

// Git for Windows maps `/dev/null` to the null device; Git 2.56 rejects `NUL`.
fn null_device() -> &'static str {
    "/dev/null"
}
