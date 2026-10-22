//! SG-000108 product caller, slices 1a–1b: the real `orcel-browser-host
//! --worker` binary under Orcel supervision, against the loopback HTTPS
//! fixture. Native Windows only, with the built worker and an installed
//! engine; run by `npm run browser-launcher:native`.
#![cfg(all(windows, feature = "live-browser-test"))]

use orcel_browser_host::worker_host::{BindAction, WorkerHostReply, WorkerHostRequest};
use orcel_browser_host::{
    assert_no_managed_policy, discover_engine, LiveWorkerHost, RegistryPolicySource, SearchConfig,
    Supervisor, WorkerHostLaunch,
};
use sha2::{Digest, Sha256};
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

fn host_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_orcel-browser-host"))
}

/// Node and the worker come from the test harness's environment: a source
/// that exists only in test builds (docs/security/SG-000108_PRODUCT_CALLER.md).
fn prerequisites() -> (PathBuf, PathBuf) {
    let node = std::env::var_os("ORCEL_SG108_NODE").expect("ORCEL_SG108_NODE");
    let main = std::env::var_os("ORCEL_SG108_WORKER_MAIN").expect("ORCEL_SG108_WORKER_MAIN");
    (PathBuf::from(node), PathBuf::from(main))
}

fn temp_root(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!(
        "sg108-worker-host-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("temp root");
    dir
}

struct Fixture {
    child: std::process::Child,
    spki: String,
}

impl Fixture {
    fn start() -> Self {
        let (node, main) = prerequisites();
        let app = main.parent().and_then(Path::parent).expect("worker app");
        let mut child = std::process::Command::new(node)
            .arg(app.join("scripts").join("https-fixture.mjs"))
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .expect("start the HTTPS fixture");
        let stdout = child.stdout.take().expect("fixture stdout");
        let (ready, spki) = mpsc::channel();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout)
                .lines()
                .map_while(Result::ok)
            {
                if let Some(value) = line.strip_prefix("READY ") {
                    let _ = ready.send(value.to_owned());
                }
            }
        });
        let spki = spki
            .recv_timeout(Duration::from_secs(30))
            .expect("fixture ready");
        Self { child, spki }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn launch_with(
    label: &str,
    worker_main: Option<PathBuf>,
) -> (Supervisor, WorkerHostLaunch, PathBuf) {
    let (node, main) = prerequisites();
    let root = temp_root(label);
    let launch = WorkerHostLaunch {
        node: Some(node),
        worker_main: Some(worker_main.unwrap_or(main)),
        profile_root: root.join("profiles"),
        temp_dir: root.join("staging"),
        state_root: root.join("state"),
    };
    for dir in [&launch.profile_root, &launch.temp_dir, &launch.state_root] {
        std::fs::create_dir_all(dir).expect("dirs");
    }
    let mut supervisor = Supervisor::new();
    supervisor
        .launch_worker_host(&host_binary(), &launch)
        .expect("launch the worker-mode host");
    (supervisor, launch, root)
}

fn launch(label: &str) -> (Supervisor, WorkerHostLaunch, PathBuf) {
    launch_with(label, None)
}

/// The host binary reads the real registry (SG-000074 managed-policy
/// precondition). On a host with a managed browser policy (CI's runner has
/// one) every open is refused, typed, before anything starts; the tests
/// then require exactly that refusal and no profile left behind.
fn managed_policy_present() -> bool {
    let engine = discover_engine(&SearchConfig::production()).expect("an installed engine");
    assert_no_managed_policy(engine.kind(), &RegistryPolicySource).is_err()
}

/// Under a managed policy: the open is refused with the closed code and the
/// lifetime's profile is gone. Returns true when the test should stop.
fn refused_by_managed_policy(reply: &WorkerHostReply, profile_root: &Path) -> bool {
    if !managed_policy_present() {
        return false;
    }
    assert_eq!(
        reply,
        &WorkerHostReply::Error {
            code: "unavailable:managedpolicy".into()
        },
        "a managed policy is present, yet the open was not refused for it"
    );
    assert!(
        entries(profile_root).is_empty(),
        "the refused open left its profile"
    );
    println!(
        "SG108-EVIDENCE worker host: managed policy present; open refused typed, no profile left"
    );
    true
}

fn entries(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .map(|read| {
            read.filter_map(Result::ok)
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

fn open_request(fixture: &Fixture) -> WorkerHostRequest {
    WorkerHostRequest::Open {
        workspace: "ws-sg108".into(),
        policy_revision: 1,
        host: "fixture.test".into(),
        fixture_spki: fixture.spki.clone(),
    }
}

/// Open a lifetime; None when a managed policy refused it (checked).
fn open(host: &mut LiveWorkerHost, fixture: &Fixture, profile_root: &Path) -> Option<String> {
    let reply = host.request(&open_request(fixture)).expect("open");
    if refused_by_managed_policy(&reply, profile_root) {
        return None;
    }
    match reply {
        WorkerHostReply::Opened { lifetime, pinned } => {
            assert_eq!(lifetime.len(), 32, "a 128-bit lifetime nonce");
            assert!(lifetime.bytes().all(|b| b.is_ascii_hexdigit()));
            assert_eq!(pinned, "127.0.0.1");
            Some(lifetime)
        }
        other => panic!("open refused: {other:?}"),
    }
}

/// The host's binding for an action (Orcel would now prompt and consume a
/// broker approval for it).
fn bind(host: &mut LiveWorkerHost, action: BindAction) -> (String, String) {
    match host
        .request(&WorkerHostRequest::Bind { action })
        .expect("bind")
    {
        WorkerHostReply::Bound { binding, target } => {
            assert_eq!(binding.len(), 64);
            (binding, target)
        }
        other => panic!("bind refused: {other:?}"),
    }
}

fn navigate(host: &mut LiveWorkerHost, url: &str, record: &str) -> WorkerHostReply {
    let (binding, _) = bind(host, BindAction::Navigate { url: url.into() });
    host.request(&WorkerHostRequest::Navigate {
        url: url.into(),
        record_id: record.into(),
        binding,
    })
    .expect("navigate")
}

fn observe(host: &mut LiveWorkerHost) -> WorkerHostReply {
    host.request(&WorkerHostRequest::Observe {})
        .expect("observe")
}

fn select_latest(host: &mut LiveWorkerHost) -> String {
    match host
        .request(&WorkerHostRequest::SelectLatestDatedLink {})
        .expect("select")
    {
        WorkerHostReply::Selected { node_id } => node_id,
        other => panic!("selection refused: {other:?}"),
    }
}

/// Every observed node, depth-first.
fn all_nodes(
    nodes: &[orcel_browser_host::worker_host::WireNode],
) -> Vec<&orcel_browser_host::worker_host::WireNode> {
    let mut out = Vec::new();
    for node in nodes {
        out.push(node);
        out.extend(all_nodes(&node.children));
    }
    out
}

fn error_code(reply: &WorkerHostReply) -> &str {
    match reply {
        WorkerHostReply::Error { code } => code,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// The fixture's report bytes, exactly as scripts/https-fixture.mjs builds
/// them: the independent checker's expectation.
fn fixture_report(path: &str) -> Vec<u8> {
    format!(
        "%PDF-1.4\n% {path}\n1 0 obj << /Type /Catalog >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n"
    )
    .into_bytes()
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
#[ignore = "requires the built browser worker and Edge; run by npm run browser-launcher:native"]
fn a_lifetime_through_the_real_host_binary_navigates_observes_and_closes_clean() {
    let fixture = Fixture::start();
    let (mut supervisor, launch, root) = launch("lifetime");
    let host = supervisor.worker_host().expect("live worker host");
    let pid = host.pid();
    if open(host, &fixture, &launch.profile_root).is_none() {
        assert!(supervisor.shutdown().expect("shutdown"));
        let _ = std::fs::remove_dir_all(&root);
        return;
    }
    // The host made its own pid-named profile under the root (#298).
    let profiles = entries(&launch.profile_root);
    assert_eq!(profiles.len(), 1, "{profiles:?}");
    assert!(
        profiles[0].starts_with(&format!("orcel-sg108-profile-{pid}-")),
        "{profiles:?}"
    );
    // A second lifetime while one is open is refused, typed.
    assert_eq!(
        error_code(&host.request(&open_request(&fixture)).expect("second open")),
        "lifetime_open"
    );
    match navigate(host, "https://fixture.test/reports", "rec-nav-1") {
        WorkerHostReply::Navigated { url, status } => {
            assert_eq!(url, "https://fixture.test/reports");
            assert_eq!(status, 200);
        }
        other => panic!("navigation refused: {other:?}"),
    }
    // Another origin is outside the lifetime's single destination, even
    // with a correct binding.
    let elsewhere = navigate(host, "https://other.test/", "rec-nav-2");
    // The binding matched: the navigation policy itself refused it.
    assert_eq!(error_code(&elsewhere), "invalid");
    let observed = observe(host);
    let text = serde_json::to_string(&observed).expect("reply text");
    match &observed {
        WorkerHostReply::Observed {
            origin,
            nodes,
            node_count,
            ..
        } => {
            assert_eq!(origin, "https://fixture.test:443");
            assert!(*node_count > 0 && !nodes.is_empty());
        }
        other => panic!("observation refused: {other:?}"),
    }
    // Identities and digests only: the page's text never crosses.
    assert!(
        !text.contains("Quarterly report"),
        "raw page text crossed: {text}"
    );
    println!(
        "SG108-EVIDENCE worker host observation: {} bytes, no raw page text",
        text.len()
    );
    match host.request(&WorkerHostRequest::Close {}).expect("close") {
        WorkerHostReply::Closed {
            job_empty,
            profile_removed,
        } => assert!(job_empty && profile_removed),
        other => panic!("close refused: {other:?}"),
    }
    assert!(
        entries(&launch.profile_root).is_empty(),
        "the profile stayed"
    );
    assert_eq!(error_code(&observe(host)), "no_lifetime");
    assert!(
        supervisor.shutdown().expect("shutdown"),
        "the host family stayed"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
#[ignore = "requires the built browser worker and Edge; run by npm run browser-launcher:native"]
fn the_journey_downloads_the_latest_report_through_bound_approvals_and_verifies_it() {
    let fixture = Fixture::start();
    let (mut supervisor, launch, root) = launch("journey");
    let approved = root.join("approved");
    std::fs::create_dir_all(&approved).expect("approved folder");
    let folder = approved.to_string_lossy().into_owned();
    let host = supervisor.worker_host().expect("live worker host");
    if open(host, &fixture, &launch.profile_root).is_none() {
        assert!(supervisor.shutdown().expect("shutdown"));
        let _ = std::fs::remove_dir_all(&root);
        return;
    }
    assert!(matches!(
        navigate(host, "https://fixture.test/reports", "rec-1"),
        WorkerHostReply::Navigated { status: 200, .. }
    ));
    assert!(matches!(observe(host), WorkerHostReply::Observed { .. }));
    let latest = select_latest(host);
    let action = BindAction::Download {
        node_id: latest.clone(),
        role: "link".into(),
        folder: folder.clone(),
        relative: "reports/latest.pdf".into(),
    };
    let (binding, target) = bind(host, action);
    assert_eq!(target, "https://fixture.test/reports/2026-09-30.pdf");
    let download = |host: &mut LiveWorkerHost, record: &str, binding: &str| {
        host.request(&WorkerHostRequest::Download {
            node_id: latest.clone(),
            role: "link".into(),
            folder: folder.clone(),
            relative: "reports/latest.pdf".into(),
            record_id: record.into(),
            binding: binding.into(),
        })
        .expect("download")
    };
    let (sha256, bytes) = match download(host, "rec-2", &binding) {
        WorkerHostReply::Downloaded {
            relative,
            sha256,
            bytes,
            source_url,
        } => {
            assert_eq!(relative, "reports/latest.pdf");
            assert_eq!(source_url, "https://fixture.test/reports/2026-09-30.pdf");
            (sha256, bytes)
        }
        other => panic!("download refused: {other:?}"),
    };
    // The independent checker: the committed file's bytes and digest are
    // the fixture's latest report, exactly.
    let committed = std::fs::read(approved.join("reports").join("latest.pdf")).expect("committed");
    let expected = fixture_report("/reports/2026-09-30.pdf");
    assert_eq!(committed, expected);
    assert_eq!(sha256, sha256_hex(&expected));
    assert_eq!(bytes, expected.len() as u64);
    println!(
        "SG108-EVIDENCE worker host journey: latest report committed create-only, sha256 {sha256}"
    );
    // The same approval again: refused (the record id was spent).
    assert_eq!(
        error_code(&download(host, "rec-2", &binding)),
        "approval_replay"
    );
    // A fresh record with the old binding: the page moved on (the download
    // ended the observation), so the approved action no longer exists.
    assert_eq!(
        error_code(&download(host, "rec-3", &binding)),
        "binding_mismatch"
    );
    // Create-only: the same name is never replaced, even with a fresh binding.
    assert!(matches!(
        navigate(host, "https://fixture.test/reports", "rec-3b"),
        WorkerHostReply::Navigated { status: 200, .. }
    ));
    assert!(matches!(observe(host), WorkerHostReply::Observed { .. }));
    let latest_again = select_latest(host);
    let (fresh, _) = bind(
        host,
        BindAction::Download {
            node_id: latest_again.clone(),
            role: "link".into(),
            folder: folder.clone(),
            relative: "reports/latest.pdf".into(),
        },
    );
    let again = host
        .request(&WorkerHostRequest::Download {
            node_id: latest_again,
            role: "link".into(),
            folder: folder.clone(),
            relative: "reports/latest.pdf".into(),
            record_id: "rec-4".into(),
            binding: fresh,
        })
        .expect("download again");
    // The binding matched: the create-only commit itself refused it.
    assert_eq!(error_code(&again), "invalid");
    assert_eq!(
        std::fs::read(approved.join("reports").join("latest.pdf")).expect("still there"),
        expected
    );
    assert!(supervisor.shutdown().expect("shutdown"));
    assert!(entries(&launch.profile_root).is_empty());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
#[ignore = "requires the built browser worker and Edge; run by npm run browser-launcher:native"]
fn a_bound_click_follows_the_approved_link_once() {
    let fixture = Fixture::start();
    let (mut supervisor, launch, root) = launch("click");
    let host = supervisor.worker_host().expect("live worker host");
    if open(host, &fixture, &launch.profile_root).is_none() {
        assert!(supervisor.shutdown().expect("shutdown"));
        let _ = std::fs::remove_dir_all(&root);
        return;
    }
    assert!(matches!(
        navigate(host, "https://fixture.test/reports", "rec-1"),
        WorkerHostReply::Navigated { status: 200, .. }
    ));
    assert!(matches!(observe(host), WorkerHostReply::Observed { .. }));
    let latest = select_latest(host);
    let (binding, target) = bind(
        host,
        BindAction::Click {
            node_id: latest.clone(),
            role: "link".into(),
        },
    );
    assert_eq!(target, "https://fixture.test/reports/2026-09-30.pdf");
    let activate = |host: &mut LiveWorkerHost, record: &str| {
        host.request(&WorkerHostRequest::Activate {
            node_id: latest.clone(),
            role: "link".into(),
            record_id: record.into(),
            binding: binding.clone(),
        })
        .expect("activate")
    };
    match activate(host, "rec-2") {
        WorkerHostReply::Activated { url, status } => {
            assert_eq!(url, "https://fixture.test/reports/2026-09-30.pdf");
            assert_eq!(status, 200);
        }
        other => panic!("activation refused: {other:?}"),
    }
    // The same approval again, and the old binding with a fresh record:
    // refused (the record is spent; the click opened a new document).
    assert_eq!(error_code(&activate(host, "rec-2")), "approval_replay");
    assert_eq!(error_code(&activate(host, "rec-3")), "binding_mismatch");
    println!(
        "SG108-EVIDENCE worker host click: the bound link opened once, replay and stale refused"
    );
    assert!(supervisor.shutdown().expect("shutdown"));
    assert!(entries(&launch.profile_root).is_empty());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
#[ignore = "requires the built browser worker and Edge; run by npm run browser-launcher:native"]
fn nodes_a_trimmed_observation_dropped_cannot_be_acted_on() {
    let fixture = Fixture::start();
    let (mut supervisor, launch, root) = launch("crowded");
    let host = supervisor.worker_host().expect("live worker host");
    if open(host, &fixture, &launch.profile_root).is_none() {
        assert!(supervisor.shutdown().expect("shutdown"));
        let _ = std::fs::remove_dir_all(&root);
        return;
    }
    assert!(matches!(
        navigate(host, "https://fixture.test/crowded", "rec-1"),
        WorkerHostReply::Navigated { status: 200, .. }
    ));
    let (sent, truncated, node_count) = match observe(host) {
        WorkerHostReply::Observed {
            nodes,
            truncated,
            node_count,
            ..
        } => (
            all_nodes(&nodes)
                .into_iter()
                .map(|node| node.node_id.clone())
                .collect::<std::collections::HashSet<_>>(),
            truncated,
            node_count,
        ),
        other => panic!("{other:?}"),
    };
    // The whole page fit the host's snapshot cap, so the dated link (last)
    // was observed by the host and then dropped from the reply.
    assert!(
        node_count < 512,
        "the page reached the snapshot cap ({node_count}): the dated link may never have been observed"
    );
    // The page is built so that the reply cannot carry every node.
    assert!(
        truncated,
        "the crowded page fit one frame: the test proves nothing"
    );
    assert!(
        sent.len() < node_count,
        "sent {} of {node_count}",
        sent.len()
    );
    // A trimmed reply still carries most of the page (the largest prefix).
    assert!(
        sent.len() * 2 > node_count,
        "sent {} of {node_count}",
        sent.len()
    );
    // The ids the host observed but did not send continue the sent ones'
    // numbering (d<generation>-e<n>): none of them may be bound.
    let highest = sent
        .iter()
        .filter_map(|id| {
            id.rsplit_once("-e")
                .and_then(|(_, n)| n.parse::<u32>().ok())
        })
        .max()
        .expect("numbered node ids");
    let prefix = sent
        .iter()
        .next()
        .and_then(|id| id.rsplit_once("-e").map(|(head, _)| head.to_owned()))
        .expect("an id prefix");
    for n in highest + 1..=highest + 60 {
        let reply = host
            .request(&WorkerHostRequest::Bind {
                action: BindAction::Click {
                    node_id: format!("{prefix}-e{n}"),
                    role: "link".into(),
                },
            })
            .expect("bind");
        assert!(
            matches!(reply, WorkerHostReply::Error { .. }),
            "a node the host never sent was bindable: {prefix}-e{n} -> {reply:?}"
        );
    }
    // Nor may the host select a node it did not send.
    match host
        .request(&WorkerHostRequest::SelectLatestDatedLink {})
        .expect("select")
    {
        WorkerHostReply::Selected { node_id } => {
            assert!(
                sent.contains(&node_id),
                "the host selected a node it never sent: {node_id}"
            )
        }
        WorkerHostReply::Error { code } => assert_eq!(code, "invalid"),
        other => panic!("{other:?}"),
    }
    println!(
        "SG108-EVIDENCE worker host trimmed observation: {} of {node_count} nodes sent; dropped nodes not actionable",
        sent.len()
    );
    assert!(supervisor.shutdown().expect("shutdown"));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
#[ignore = "requires the built browser worker and Edge; run by npm run browser-launcher:native"]
fn a_binding_names_one_lifetime_node_and_file_and_nothing_else() {
    let fixture = Fixture::start();
    let (mut supervisor, launch, root) = launch("binding");
    let approved = root.join("approved");
    std::fs::create_dir_all(&approved).expect("approved folder");
    let folder = approved.to_string_lossy().into_owned();
    let host = supervisor.worker_host().expect("live worker host");
    let Some(lifetime) = open(host, &fixture, &launch.profile_root) else {
        assert!(supervisor.shutdown().expect("shutdown"));
        let _ = std::fs::remove_dir_all(&root);
        return;
    };
    // The binding is exactly the documented digest over the lifetime nonce,
    // the workspace, the policy revision and the action: recomputed here
    // independently, so a host that dropped or replaced any part (the
    // workspace included) fails.
    let url = "https://fixture.test/reports";
    let (binding, _) = bind(host, BindAction::Navigate { url: url.into() });
    let expected = sha256_hex(
        format!(
            "orcel-sg108-host-binding/1
{lifetime}
ws-sg108
1
navigate
{url}
127.0.0.1"
        )
        .as_bytes(),
    );
    assert_eq!(
        binding, expected,
        "the host binding is not the documented digest"
    );
    // A navigation binding names its URL: presented for another URL, refused.
    let (nav_binding, _) = bind(
        host,
        BindAction::Navigate {
            url: "https://fixture.test/reports".into(),
        },
    );
    assert_eq!(
        error_code(
            &host
                .request(&WorkerHostRequest::Navigate {
                    url: "https://fixture.test/".into(),
                    record_id: "rec-a".into(),
                    binding: nav_binding.clone(),
                })
                .expect("navigate")
        ),
        "binding_mismatch"
    );
    assert!(matches!(
        navigate(host, "https://fixture.test/reports", "rec-b"),
        WorkerHostReply::Navigated { .. }
    ));
    assert!(matches!(observe(host), WorkerHostReply::Observed { .. }));
    let latest = select_latest(host);
    let (binding, _) = bind(
        host,
        BindAction::Download {
            node_id: latest.clone(),
            role: "link".into(),
            folder: folder.clone(),
            relative: "a.pdf".into(),
        },
    );
    let present = |host: &mut LiveWorkerHost, node: &str, relative: &str, record: &str| {
        host.request(&WorkerHostRequest::Download {
            node_id: node.into(),
            role: "link".into(),
            folder: folder.clone(),
            relative: relative.into(),
            record_id: record.into(),
            binding: binding.clone(),
        })
        .expect("download")
    };
    // Another file name, or another node, under the same binding: refused.
    assert_eq!(
        error_code(&present(host, &latest, "b.pdf", "rec-c")),
        "binding_mismatch"
    );
    let other = match observe(host) {
        WorkerHostReply::Observed { nodes, .. } => all_nodes(&nodes)
            .into_iter()
            .find(|node| node.role == "link" && node.node_id != latest)
            .map(|node| node.node_id.clone())
            .expect("another link"),
        other => panic!("{other:?}"),
    };
    assert_eq!(
        error_code(&present(host, &other, "a.pdf", "rec-d")),
        "binding_mismatch"
    );
    // A binding from another lifetime: close, reopen, present it again.
    assert!(matches!(
        host.request(&WorkerHostRequest::Close {}).expect("close"),
        WorkerHostReply::Closed { .. }
    ));
    assert!(open(host, &fixture, &launch.profile_root).is_some());
    assert_eq!(
        error_code(
            &host
                .request(&WorkerHostRequest::Navigate {
                    url: "https://fixture.test/reports".into(),
                    record_id: "rec-e".into(),
                    binding: nav_binding,
                })
                .expect("navigate")
        ),
        "binding_mismatch"
    );
    // Nothing was written by any refused frame.
    assert!(entries(&approved).is_empty(), "{:?}", entries(&approved));
    println!("SG108-EVIDENCE worker host binding: other URL, file, node and lifetime refused");
    assert!(supervisor.shutdown().expect("shutdown"));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
#[ignore = "requires the built browser worker and Edge; run by npm run browser-launcher:native"]
fn a_refused_open_leaves_no_profile_behind() {
    let fixture = Fixture::start();
    let (mut supervisor, launch, root) = launch("refused-open");
    let host = supervisor.worker_host().expect("live worker host");
    for (host_name, spki) in [
        ("not a host", fixture.spki.clone()),
        ("fixture.test", "short".to_string()),
    ] {
        assert!(matches!(
            host.request(&WorkerHostRequest::Open {
                workspace: "ws-sg108".into(),
                policy_revision: 1,
                host: host_name.into(),
                fixture_spki: spki,
            })
            .expect("open"),
            WorkerHostReply::Error { .. }
        ));
    }
    assert!(
        entries(&launch.profile_root).is_empty(),
        "a refused open left a profile"
    );
    assert!(supervisor.shutdown().expect("shutdown"));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
#[ignore = "requires the built browser worker and Edge; run by npm run browser-launcher:native"]
fn a_launch_refused_after_the_profile_exists_removes_it() {
    // The worker entry is an existing file that is not `main.js`: the open
    // passes every check that needs no profile, makes the lifetime's
    // profile, and is then refused by the launch (typed). The profile it
    // made must be gone.
    let fixture = Fixture::start();
    let (node, _) = prerequisites();
    let (mut supervisor, launch, root) = launch_with("refused-launch", Some(node));
    let host = supervisor.worker_host().expect("live worker host");
    assert_eq!(
        error_code(&host.request(&open_request(&fixture)).expect("open")),
        "unavailable:unsupportedruntime"
    );
    assert!(
        entries(&launch.profile_root).is_empty(),
        "the refused launch left its profile"
    );
    assert!(supervisor.shutdown().expect("shutdown"));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
#[ignore = "requires the built browser worker and Edge; run by npm run browser-launcher:native"]
fn shutting_the_host_down_mid_lifetime_takes_the_worker_and_profile_with_it() {
    let fixture = Fixture::start();
    let (mut supervisor, launch, root) = launch("shutdown");
    let host = supervisor.worker_host().expect("live worker host");
    // Under a managed policy there is no lifetime; the single-host rule and
    // the shutdown below still hold for the live host.
    let _ = open(host, &fixture, &launch.profile_root);
    // Only one host at a time, of either mode.
    assert!(supervisor
        .launch_worker_host(&host_binary(), &launch)
        .is_err());
    // The supervisor's own shutdown covers the worker-mode host.
    assert!(
        supervisor.shutdown().expect("shutdown"),
        "the host family stayed"
    );
    assert!(!supervisor.is_live());
    assert!(
        entries(&launch.profile_root).is_empty(),
        "the lifetime's profile stayed"
    );
    let _ = std::fs::remove_dir_all(&root);
}
