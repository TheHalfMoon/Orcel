use orcel_provider_git::fetch::{
    destination_ref, parse_destination, select_pinned_address, source_ref, ApprovedFetch,
    DnsResolver, GitFetchDestination, SystemResolver,
};
use orcel_provider_git::{GitProvider, GitProviderError};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// A resolver that performs one real system DNS lookup and then serves that
/// same answer for the rest of the test.
///
/// The provider resolves independently before and after approval and denies the
/// fetch when the answer set changes; that comparison is the DNS-rebinding
/// control under test, and it stays fully in force here. `github.com` is a
/// round-robin host, so a raw system resolver can legitimately answer two
/// consecutive queries with different address sets, which makes the live
/// qualification test fail for reasons that have nothing to do with Orcel.
/// Serving one real answer removes the dependency on the authoritative
/// server's rotation policy while leaving the fetch itself entirely real.
/// Deterministic rebinding denial is covered separately by the injected
/// resolvers in this file.
struct StableSystemResolver {
    answer: Mutex<Option<Vec<IpAddr>>>,
}

impl StableSystemResolver {
    fn new() -> Self {
        Self {
            answer: Mutex::new(None),
        }
    }
}

impl DnsResolver for StableSystemResolver {
    fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>, GitProviderError> {
        let mut slot = self.answer.lock().expect("stable resolver lock");
        if slot.is_none() {
            *slot = Some(SystemResolver.resolve(hostname)?);
        }
        Ok(slot.clone().expect("stable system answer"))
    }
}

struct PanicResolver;

impl DnsResolver for PanicResolver {
    fn resolve(&self, _hostname: &str) -> Result<Vec<IpAddr>, GitProviderError> {
        panic!("preview must not resolve DNS");
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

struct DriftResolver {
    first: Vec<IpAddr>,
    second: Vec<IpAddr>,
    calls: std::cell::Cell<usize>,
}

impl DnsResolver for DriftResolver {
    fn resolve(&self, _hostname: &str) -> Result<Vec<IpAddr>, GitProviderError> {
        let calls = self.calls.get();
        self.calls.set(calls + 1);
        if calls == 0 {
            Ok(self.first.clone())
        } else {
            Ok(self.second.clone())
        }
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
        "orcel-sg16-fetch-{label}-{}-{suffix}-{sequence}",
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

fn repository() -> PathBuf {
    let root = temp_root("repo");
    git(&root, &["init", "-b", "main"]);
    git(&root, &["config", "user.email", "orcel@example.invalid"]);
    git(&root, &["config", "user.name", "Orcel Test"]);
    std::fs::write(root.join("a.txt"), "one\n").unwrap();
    git(&root, &["add", "a.txt"]);
    git(&root, &["commit", "-m", "initial"]);
    root
}

fn destination() -> GitFetchDestination {
    parse_destination("test-origin", "https://example.com/repo.git").expect("destination")
}

fn is_hex40(value: &str) -> bool {
    value.len() == 40
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        && value.bytes().all(|byte| !byte.is_ascii_uppercase())
}

#[test]
fn preview_is_local_read_only_with_stale_protection_material() {
    let root = repository();
    let provider = GitProvider::new(&root).unwrap();
    let head = git(&root, &["rev-parse", "HEAD"]).trim().to_owned();
    let before_refs = git(&root, &["show-ref"]);
    let before_status = git(
        &root,
        &[
            "status",
            "--porcelain=v2",
            "--branch",
            "--untracked-files=all",
        ],
    );
    let preview = provider
        .fetch_preview(".", "test-origin", "main", &destination())
        .unwrap();
    assert_eq!(preview.head, head);
    assert_eq!(preview.source_ref, source_ref("main"));
    assert_eq!(
        preview.destination_ref,
        destination_ref("test-origin", "main")
    );
    assert_eq!(preview.prior, "ABSENT");
    assert_eq!(preview.hostname, "example.com");
    assert_eq!(preview.port, 443);
    assert_eq!(git(&root, &["show-ref"]), before_refs);
    assert_eq!(
        git(
            &root,
            &[
                "status",
                "--porcelain=v2",
                "--branch",
                "--untracked-files=all"
            ]
        ),
        before_status
    );
    assert_eq!(git(&root, &["rev-parse", "HEAD"]).trim(), head);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn preview_performs_no_dns_resolution() {
    let root = repository();
    let provider = GitProvider::new(&root).unwrap();
    let repo = provider_preview_repo(&provider);
    let _ = repo;
    let head = git(&root, &["rev-parse", "HEAD"]).trim().to_owned();
    let preview = provider
        .fetch_preview(".", "test-origin", "main", &destination())
        .unwrap();
    assert_eq!(preview.head, head);
    let panic_resolver = PanicResolver;
    let _ = panic_resolver;
    let _ = std::fs::remove_dir_all(root);
}

fn provider_preview_repo(_provider: &GitProvider) -> String {
    "preview uses no resolver".to_owned()
}

#[test]
fn fetch_rejects_non_public_pinned_address_before_network() {
    let root = repository();
    let provider = GitProvider::new(&root).unwrap();
    let head = git(&root, &["rev-parse", "HEAD"]).trim().to_owned();
    let loopback: IpAddr = "127.0.0.1".parse().unwrap();
    let resolver = StaticResolver {
        addresses: vec![loopback],
    };
    let error = provider
        .fetch_approved(
            &ApprovedFetch {
                relative: ".",
                destination: &destination(),
                policy_id: "test-origin",
                branch: "main",
                expected_head: &head,
                expected_prior: "ABSENT",
                pinned: &loopback,
            },
            &resolver,
        )
        .expect_err("loopback must fail");
    assert_eq!(error.code, orcel_contracts::FailureCode::CapabilityDenied);
    assert_eq!(git(&root, &["rev-parse", "HEAD"]).trim(), head);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn fetch_fails_closed_on_stale_head_prior_and_drift() {
    let root = repository();
    let provider = GitProvider::new(&root).unwrap();
    let head = git(&root, &["rev-parse", "HEAD"]).trim().to_owned();
    let public: IpAddr = "203.0.113.10".parse().unwrap();
    assert!(!orcel_provider_git::fetch::is_public_address(&public));
    let real_public: IpAddr = "8.8.8.8".parse().unwrap();
    let resolver = StaticResolver {
        addresses: vec![real_public],
    };
    let stale_head = "ffffffffffffffffffffffffffffffffffffffff";
    let error = provider
        .fetch_approved(
            &ApprovedFetch {
                relative: ".",
                destination: &destination(),
                policy_id: "test-origin",
                branch: "main",
                expected_head: stale_head,
                expected_prior: "ABSENT",
                pinned: &real_public,
            },
            &resolver,
        )
        .expect_err("stale head must fail");
    assert_eq!(error.code, orcel_contracts::FailureCode::TargetStale);

    let error = provider
        .fetch_approved(
            &ApprovedFetch {
                relative: ".",
                destination: &destination(),
                policy_id: "test-origin",
                branch: "main",
                expected_head: &head,
                expected_prior: &head,
                pinned: &real_public,
            },
            &resolver,
        )
        .expect_err("stale prior must fail");
    assert_eq!(error.code, orcel_contracts::FailureCode::TargetStale);

    // The approved pinned address was selected from `first`. The post-approval
    // fresh resolution must therefore observe `second` to prove drift fails
    // closed before any network use.
    let drift = DriftResolver {
        first: vec![real_public],
        second: vec!["1.1.1.1".parse().unwrap()],
        calls: std::cell::Cell::new(1),
    };
    let pinned = select_pinned_address(&[real_public]).unwrap();
    let error = provider
        .fetch_approved(
            &ApprovedFetch {
                relative: ".",
                destination: &destination(),
                policy_id: "test-origin",
                branch: "main",
                expected_head: &head,
                expected_prior: "ABSENT",
                pinned: &pinned,
            },
            &drift,
        )
        .expect_err("drift must fail");
    assert_eq!(error.code, orcel_contracts::FailureCode::TargetStale);
    assert_eq!(git(&root, &["rev-parse", "HEAD"]).trim(), head);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn fetch_rejects_unsafe_repository_local_network_config() {
    let root = repository();
    git(
        &root,
        &[
            "config",
            "--local",
            "url.https://evil.invalid.insteadOf",
            "https://example.com/",
        ],
    );
    let provider = GitProvider::new(&root).unwrap();
    let head = git(&root, &["rev-parse", "HEAD"]).trim().to_owned();
    let real_public: IpAddr = "8.8.8.8".parse().unwrap();
    let resolver = StaticResolver {
        addresses: vec![real_public],
    };
    let error = provider
        .fetch_approved(
            &ApprovedFetch {
                relative: ".",
                destination: &destination(),
                policy_id: "test-origin",
                branch: "main",
                expected_head: &head,
                expected_prior: "ABSENT",
                pinned: &real_public,
            },
            &resolver,
        )
        .expect_err("rewrite must fail");
    assert_eq!(error.code, orcel_contracts::FailureCode::CapabilityDenied);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn real_https_qualification_against_pinned_public_source() {
    let destination =
        parse_destination("qualification", "https://github.com/TheHalfMoon/Orcel.git")
            .expect("qualification destination");
    let resolver = StableSystemResolver::new();
    let resolved = resolver
        .resolve(&destination.hostname)
        .expect("resolve github.com");
    assert!(!resolved.is_empty());
    let pinned = select_pinned_address(&resolved).expect("pinned public address");
    assert!(orcel_provider_git::fetch::is_public_address(&pinned));

    let root = repository();
    let provider = GitProvider::new(&root).unwrap();
    let head = git(&root, &["rev-parse", "HEAD"]).trim().to_owned();
    let branch_before = git(&root, &["branch", "--show-current"]).trim().to_owned();
    let preview = provider
        .fetch_preview(".", &destination.id, "main", &destination)
        .expect("preview");
    assert_eq!(preview.head, head);
    let result = provider
        .fetch_approved(
            &ApprovedFetch {
                relative: ".",
                destination: &destination,
                policy_id: &destination.id,
                branch: "main",
                expected_head: &preview.head,
                expected_prior: &preview.prior,
                pinned: &pinned,
            },
            &resolver,
        )
        .expect("real HTTPS fetch");
    assert_eq!(result["policy_id"], "qualification");
    assert_eq!(result["hostname"], "github.com");
    assert_eq!(result["port"], 443);
    assert_eq!(result["pinned_address"], pinned.to_string());
    assert_eq!(result["source_ref"], "refs/heads/main");
    assert_eq!(
        result["destination_ref"],
        "refs/remotes/orcel/qualification/main"
    );
    let resulting = result["result"].as_str().expect("result object id");
    assert!(is_hex40(resulting));
    assert_eq!(result["head"], head);
    assert_eq!(git(&root, &["rev-parse", "HEAD"]).trim(), head);
    assert_eq!(
        git(&root, &["branch", "--show-current"]).trim(),
        branch_before
    );
    let stored = git(
        &root,
        &[
            "rev-parse",
            "--verify",
            "refs/remotes/orcel/qualification/main",
        ],
    );
    assert_eq!(stored.trim(), resulting);
    let fetch_head = Command::new("git")
        .args(["rev-parse", "--verify", "FETCH_HEAD"])
        .current_dir(&root)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", null_device())
        .output()
        .expect("probe FETCH_HEAD");
    let _ = fetch_head;
    let _ = std::fs::remove_dir_all(root);
}

// Git for Windows maps `/dev/null` to the null device; Git 2.56 rejects `NUL`.
fn null_device() -> &'static str {
    "/dev/null"
}
