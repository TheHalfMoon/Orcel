//! SG-000108 slice 3b-ii: the real `orcel-browser-host --worker` binary of
//! a `live-browser-dev` build, under Orcel supervision, on a public HTTPS
//! destination. The binary runs only the worker runtime its build pinned
//! (decision 7). Native Windows only, with the built worker and an
//! installed engine; run by `npm run browser-launcher:native`, which builds
//! this binary twice: once with the runtime's real pin
//! (`ORCEL_SG108_DEV_PIN=match`) and once with a pin of another tree
//! (`ORCEL_SG108_DEV_PIN=mismatch`).
#![cfg(all(windows, feature = "live-browser-dev"))]

use orcel_browser_host::worker_host::{BindAction, WorkerHostReply, WorkerHostRequest};
use orcel_browser_host::{
    assert_no_managed_policy, discover_engine, LiveWorkerHost, RegistryPolicySource, SearchConfig,
    Supervisor, WorkerHostLaunch,
};
use sha2::Digest;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// A stable public HTTPS page (IANA's reserved example domain).
const PUBLIC_URL: &str = "https://example.com/";

fn host_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_orcel-browser-host"))
}

/// What the launcher built this binary with: the runtime's real pin, or a
/// pin of another tree.
fn expected_pin() -> String {
    std::env::var("ORCEL_SG108_DEV_PIN").expect("ORCEL_SG108_DEV_PIN (match or mismatch)")
}

fn temp_root(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!(
        "sg108-dev-host-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("temp root");
    dir
}

fn launch_args(root: &Path, runtime: Option<(PathBuf, PathBuf)>) -> WorkerHostLaunch {
    let (node, worker_main) = match runtime {
        Some((node, main)) => (Some(node), Some(main)),
        None => (None, None),
    };
    let launch = WorkerHostLaunch {
        node,
        worker_main,
        profile_root: root.join("profiles"),
        temp_dir: root.join("staging"),
        state_root: root.join("state"),
    };
    for dir in [&launch.profile_root, &launch.temp_dir, &launch.state_root] {
        std::fs::create_dir_all(dir).expect("dirs");
    }
    launch
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

fn managed_policy_present() -> bool {
    let engine = discover_engine(&SearchConfig::production()).expect("an installed engine");
    assert_no_managed_policy(engine.kind(), &RegistryPolicySource).is_err()
}

fn open_public(host: &mut LiveWorkerHost, url: &str) -> WorkerHostReply {
    host.request(&WorkerHostRequest::OpenPublic {
        workspace: "ws-sg108".into(),
        policy_revision: 1,
        url: url.into(),
    })
    .expect("open_public")
}

fn error_code(reply: &WorkerHostReply) -> &str {
    match reply {
        WorkerHostReply::Error { code } => code,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// Whether `path` can be opened for writing now (a held runtime file
/// cannot).
fn writable(path: &Path) -> bool {
    std::fs::OpenOptions::new().append(true).open(path).is_ok()
}

/// The worker entry point the launcher pinned (for the hold check only;
/// the host itself takes nothing from the environment).
fn pinned_worker_main() -> PathBuf {
    PathBuf::from(std::env::var_os("ORCEL_SG108_WORKER_MAIN").expect("ORCEL_SG108_WORKER_MAIN"))
}

#[test]
#[ignore = "requires the built browser worker and Edge; run by npm run browser-launcher:native"]
fn a_development_host_takes_no_runtime_from_its_caller() {
    // Node and the worker are never arguments of a development host: it
    // exits on either one, so the supervised hello never completes. Each is
    // tried alone (judge, PR #428), and the same launch without them starts.
    let node = PathBuf::from(std::env::var_os("ORCEL_SG108_NODE").expect("ORCEL_SG108_NODE"));
    for (label, node, main) in [
        ("--node", Some(node), None),
        ("--worker-main", None, Some(pinned_worker_main())),
    ] {
        let root = temp_root("arguments");
        let mut launch = launch_args(&root, None);
        launch.node = node;
        launch.worker_main = main;
        let mut supervisor = Supervisor::new();
        assert!(
            supervisor
                .launch_worker_host(&host_binary(), &launch)
                .is_err(),
            "a development host accepted {label}"
        );
        assert!(entries(&launch.profile_root).is_empty());
        let _ = supervisor.shutdown();
        let _ = std::fs::remove_dir_all(&root);
    }
    let root = temp_root("no-arguments");
    let launch = launch_args(&root, None);
    let mut supervisor = Supervisor::new();
    supervisor
        .launch_worker_host(&host_binary(), &launch)
        .expect("the same launch without runtime arguments starts");
    assert!(supervisor.shutdown().expect("shutdown"));
    let _ = std::fs::remove_dir_all(&root);
    println!("SG108-EVIDENCE dev host: --node and --worker-main refused");
}

/// Judge, PR #428: in the build with the real pin, the compiled pin is the
/// host's own measurement of the runtime on disk (`runtime_files` and
/// `tree_digest` over the files' SHA-256), so dev-pin.mjs and runtime_pin.rs
/// agree on the real tree, not only on the framing's fixed vector. Runs in
/// every environment (CI included), whatever refuses the lifetime there.
#[test]
#[ignore = "requires the built browser worker and Edge; run by npm run browser-launcher:native"]
fn the_compiled_pin_is_the_runtime_on_disk() {
    let pinned_tree =
        std::env::var("ORCEL_LIVE_BROWSER_TREE_SHA256").expect("the build's tree pin");
    let pinned_node =
        std::env::var("ORCEL_LIVE_BROWSER_NODE_SHA256").expect("the build's node pin");
    let main = pinned_worker_main();
    let root = orcel_browser_host::worker_root(&main).expect("worker root");
    let sha256 = |path: &Path| -> String {
        let bytes = std::fs::read(path).expect("read a runtime file");
        sha2::Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    };
    let entries: Vec<(String, String)> = orcel_browser_host::runtime_files(&root)
        .expect("the runtime tree")
        .into_iter()
        .map(|relative| {
            let digest = sha256(&root.join(&relative));
            (relative, digest)
        })
        .collect();
    let measured = orcel_browser_host::tree_digest(&entries);
    let node = PathBuf::from(std::env::var_os("ORCEL_SG108_NODE").expect("ORCEL_SG108_NODE"));
    if expected_pin() == "match" {
        assert_eq!(
            measured, pinned_tree,
            "dev-pin.mjs and runtime_pin.rs disagree on the tree"
        );
        assert_eq!(
            sha256(&node),
            pinned_node,
            "dev-pin.mjs and runtime_pin.rs disagree on node.exe"
        );
        println!(
            "SG108-EVIDENCE dev host pin agreement: {} files, tree {measured}",
            entries.len()
        );
    } else {
        assert_ne!(
            measured, pinned_tree,
            "the mismatch build carries the real pin"
        );
        println!("SG108-EVIDENCE dev host pin agreement: mismatch build carries another tree");
    }
}

#[test]
#[ignore = "requires the built browser worker and Edge; run by npm run browser-launcher:native"]
fn a_development_host_runs_only_its_pinned_runtime_on_one_public_destination() {
    let root = temp_root("public");
    let launch = launch_args(&root, None);
    let mut supervisor = Supervisor::new();
    supervisor
        .launch_worker_host(&host_binary(), &launch)
        .expect("launch the development host");
    let host = supervisor.worker_host().expect("live worker host");
    // Destinations outside SG-000075 are refused before any profile, in
    // every build: not HTTPS, another port, an IP literal, a single label.
    for url in [
        "http://example.com/",
        "https://example.com:8443/",
        "https://93.184.215.14/",
        "https://localhost/",
    ] {
        assert_eq!(error_code(&open_public(host, url)), "invalid", "{url}");
    }
    assert!(entries(&launch.profile_root).is_empty());
    let reply = open_public(host, PUBLIC_URL);
    // The runtime is checked first, before the engine is probed or a
    // profile exists (judge, PR #428): a build pinned to another tree, or a
    // node.exe in a folder the user can change (CI's toolcache), is refused
    // typed whatever else holds.
    let node = PathBuf::from(std::env::var_os("ORCEL_SG108_NODE").expect("ORCEL_SG108_NODE"));
    let refusal = if expected_pin() == "mismatch" {
        Some("pin mismatch")
    } else if orcel_browser_host::node_folder_writable(&node) {
        Some("node folder writable")
    } else {
        None
    };
    if let Some(why) = refusal {
        assert_eq!(error_code(&reply), "unavailable:unsupportedruntime");
        assert!(
            entries(&launch.profile_root).is_empty(),
            "the refused open left its profile"
        );
        assert!(supervisor.shutdown().expect("shutdown"));
        let _ = std::fs::remove_dir_all(&root);
        println!("SG108-EVIDENCE dev host refused: {why}; open refused typed, no profile");
        return;
    }
    if managed_policy_present() {
        assert_eq!(error_code(&reply), "unavailable:managedpolicy");
        assert!(entries(&launch.profile_root).is_empty());
        println!(
            "SG108-EVIDENCE dev host: managed policy present; open refused typed, no profile left"
        );
        assert!(supervisor.shutdown().expect("shutdown"));
        let _ = std::fs::remove_dir_all(&root);
        return;
    }
    let pinned = match reply {
        WorkerHostReply::Opened { lifetime, pinned } => {
            assert_eq!(lifetime.len(), 32);
            pinned
        }
        other => panic!("the public open was refused: {other:?}"),
    };
    // The pin is the host's own public resolution of the name.
    let address: IpAddr = pinned.parse().expect("a pinned address");
    assert!(
        !address.is_loopback() && !address.is_unspecified(),
        "{address}"
    );
    // The pinned runtime is held for the lifetime: its entry point cannot
    // be opened for writing while the worker runs.
    let main = pinned_worker_main();
    assert!(
        !writable(&main),
        "the pinned worker entry point was writable"
    );
    let (binding, target) = match host
        .request(&WorkerHostRequest::Bind {
            action: BindAction::Navigate {
                url: PUBLIC_URL.into(),
            },
        })
        .expect("bind")
    {
        WorkerHostReply::Bound { binding, target } => (binding, target),
        other => panic!("bind refused: {other:?}"),
    };
    assert_eq!(target, PUBLIC_URL);
    match host
        .request(&WorkerHostRequest::Navigate {
            url: PUBLIC_URL.into(),
            record_id: "rec-dev-nav-1".into(),
            binding,
        })
        .expect("navigate")
    {
        WorkerHostReply::Navigated { url, status } => {
            assert_eq!(url, PUBLIC_URL);
            assert_eq!(status, 200);
        }
        other => panic!("the public navigation was refused: {other:?}"),
    }
    let observed = host
        .request(&WorkerHostRequest::Observe {})
        .expect("observe");
    let text = serde_json::to_string(&observed).expect("reply text");
    match &observed {
        WorkerHostReply::Observed {
            origin, node_count, ..
        } => {
            assert_eq!(origin, "https://example.com:443");
            assert!(*node_count > 0);
        }
        other => panic!("observation refused: {other:?}"),
    }
    assert!(!text.contains("Example Domain"), "raw page text crossed");
    // One destination per lifetime: another public origin is refused.
    let (binding, _) = match host
        .request(&WorkerHostRequest::Bind {
            action: BindAction::Navigate {
                url: "https://www.iana.org/".into(),
            },
        })
        .expect("bind")
    {
        WorkerHostReply::Bound { binding, target } => (binding, target),
        other => panic!("bind refused: {other:?}"),
    };
    assert_eq!(
        error_code(
            &host
                .request(&WorkerHostRequest::Navigate {
                    url: "https://www.iana.org/".into(),
                    record_id: "rec-dev-nav-2".into(),
                    binding,
                })
                .expect("navigate")
        ),
        "invalid"
    );
    match host.request(&WorkerHostRequest::Close {}).expect("close") {
        WorkerHostReply::Closed {
            job_empty,
            profile_removed,
        } => assert!(job_empty && profile_removed),
        other => panic!("close refused: {other:?}"),
    }
    assert!(
        writable(&main),
        "the runtime stayed held after the lifetime"
    );
    assert!(entries(&launch.profile_root).is_empty());
    assert!(supervisor.shutdown().expect("shutdown"));
    let _ = std::fs::remove_dir_all(&root);
    println!(
        "SG108-EVIDENCE dev host public lifetime: pinned {address}, navigated 200, runtime held then released"
    );
}
