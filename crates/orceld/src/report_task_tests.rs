//! SG-000126 tests: the report task through the real workspace provider and
//! the real approval broker over its own ledger. Only the SOFT consent (the
//! system dialog) is scripted.

use super::*;
use orcel_approval::{ApprovalDecision, LocalApprovalBroker, NoPresenceVerifier};
use orcel_contracts::{RemoteContext, INTERNAL_PROTOCOL_VERSION};
use std::collections::{BTreeMap, VecDeque};
use std::path::Path;
use std::sync::atomic::AtomicUsize;

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Three regions' Q3 revenue in cents; the total is 3,730,075 cents.
pub(crate) const Q3_CSV: &str =
    "region,quarter,revenue_cents\nnorth,Q3,1250000\nsouth,Q3,980050\neast,Q3,1500025\n";
pub(crate) const Q3_TOTAL: &str = "37300.75";

pub(crate) struct Scene {
    pub dir: PathBuf,
    pub workspace: Workspace,
}

impl Scene {
    pub(crate) fn new(label: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "orcel-sg126-{label}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scene dir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let root = dir.join("ws");
        std::fs::create_dir_all(root.join("data")).unwrap();
        std::fs::create_dir_all(root.join("reports")).unwrap();
        std::fs::write(root.join("data").join("q3.csv"), Q3_CSV).unwrap();
        Self {
            workspace: Workspace {
                id: "default".into(),
                root,
            },
            dir,
        }
    }

    fn root(&self) -> &Path {
        &self.workspace.root
    }

    /// Every file under the workspace with its bytes.
    pub(crate) fn tree(&self) -> BTreeMap<String, Vec<u8>> {
        fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                let relative = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                if path.is_dir() {
                    out.insert(format!("{relative}/"), Vec::new());
                    walk(root, &path, out);
                } else {
                    out.insert(relative, std::fs::read(&path).unwrap());
                }
            }
        }
        let mut out = BTreeMap::new();
        walk(self.root(), self.root(), &mut out);
        out
    }
}

impl Drop for Scene {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The real broker over a private ledger, with scripted SOFT decisions and
/// a record of every prompt it showed.
pub(crate) struct Consent {
    pub broker: LocalApprovalBroker,
    pub prompts: Arc<Mutex<Vec<ApprovalPrompt>>>,
}

pub(crate) fn consent(scene: &Scene, decisions: &[ApprovalDecision]) -> Consent {
    let queue = Arc::new(Mutex::new(
        decisions.iter().copied().collect::<VecDeque<_>>(),
    ));
    let prompts = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&prompts);
    let broker = LocalApprovalBroker::with_path_and_soft_decider(
        scene.dir.join("approvals.json"),
        Arc::new(NoPresenceVerifier),
        Arc::new(move |prompt: &ApprovalPrompt| {
            seen.lock().unwrap().push(prompt.clone());
            // An unscripted prompt is a test failure, so it is denied.
            queue
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(ApprovalDecision::Denied)
        }),
    );
    Consent { broker, prompts }
}

impl Consent {
    fn shown(&self) -> usize {
        self.prompts.lock().unwrap().len()
    }
}

pub(crate) fn request(operation: &str, arguments: Value) -> RequestEnvelope {
    RequestEnvelope {
        version: INTERNAL_PROTOCOL_VERSION,
        request_id: format!("sg126-{operation}"),
        client_session_id: "sg126".into(),
        workspace_id: "default".into(),
        capability: REPORT_CAPABILITY.into(),
        operation: operation.into(),
        target: None,
        arguments,
    }
}

pub(crate) fn sha256_of(text: &str) -> String {
    sha256_hex(text.as_bytes())
}

pub(crate) fn start_q3(scene: &Scene, tasks: &TaskRegistry) -> Value {
    let approval = consent(scene, &[]);
    dispatch(
        &scene.workspace,
        &approval.broker,
        tasks,
        &request(
            "start",
            json!({"title": "Q3 revenue", "sources": ["data/q3.csv"], "folder": "reports"}),
        ),
    )
    .expect("start")
}

/// The deterministic test planner: reads the figures the kernel observed
/// and writes a Markdown summary that cites its source.
pub(crate) fn plan_report(started: &Value) -> String {
    let source = &started["sources"][0];
    let text = source["text"].as_str().unwrap();
    let mut total: i64 = 0;
    let mut rows = String::new();
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split(',').collect();
        let cents: i64 = fields[2].parse().unwrap();
        total += cents;
        rows.push_str(&format!(
            "| {} | {}.{:02} |\n",
            fields[0],
            cents / 100,
            cents % 100
        ));
    }
    format!(
        "# Q3 revenue summary\n\nSource: {} (SHA-256 {})\n\n| region | revenue |\n|---|---|\n{rows}\nTotal: {}.{:02}\n",
        source["path"].as_str().unwrap(),
        source["sha256"].as_str().unwrap(),
        total / 100,
        total % 100
    )
}

/// The test harness's own checker: parses the saved report and recomputes
/// the total from the fixture on disk, sharing nothing with orceld.
pub(crate) fn independent_figures_check(report: &str, fixture: &str) {
    let mut expected: i64 = 0;
    for line in fixture.lines().skip(1) {
        expected += line.rsplit(',').next().unwrap().parse::<i64>().unwrap();
    }
    let reported = report
        .lines()
        .find_map(|line| line.strip_prefix("Total: "))
        .expect("the report states a total");
    let (units, cents) = reported.split_once('.').unwrap();
    assert_eq!(
        units.parse::<i64>().unwrap() * 100 + cents.parse::<i64>().unwrap(),
        expected
    );
    assert!(report.contains(&format!("SHA-256 {}", sha256_hex(fixture.as_bytes()))));
}

fn preview(
    scene: &Scene,
    tasks: &TaskRegistry,
    task: &str,
    name: &str,
    content: &str,
) -> Result<Value, ProviderError> {
    let approval = consent(scene, &[]);
    dispatch(
        &scene.workspace,
        &approval.broker,
        tasks,
        &request(
            "preview",
            json!({"task_id": task, "name": name, "content": content}),
        ),
    )
}

fn commit_request(task: &str, name: &str, content: &str) -> RequestEnvelope {
    request(
        "commit",
        json!({"task_id": task, "name": name, "content": content, "expected_sha256": sha256_hex(content.as_bytes())}),
    )
}

fn state(tasks: &TaskRegistry, task: &str) -> String {
    tasks.get(task).unwrap()["state"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn sg126_journey_denied_once_then_a_fresh_approval_creates_the_verified_report() {
    let scene = Scene::new("journey");
    let tasks = TaskRegistry::new();
    let before = scene.tree();
    let started = start_q3(&scene, &tasks);
    let task = started["task_id"].as_str().unwrap().to_owned();
    assert!(orcel_policy::report::is_report_task_id(&task));
    assert_eq!(
        started["sources"][0]["sha256"],
        sha256_hex(Q3_CSV.as_bytes())
    );
    assert_eq!(started["content_label"], SOURCE_LABEL);

    let report = plan_report(&started);
    let previewed = preview(&scene, &tasks, &task, "q3-summary.md", &report).expect("preview");
    assert_eq!(previewed["destination"], "reports/q3-summary.md");
    assert_eq!(previewed["sha256"], sha256_hex(report.as_bytes()));
    assert_eq!(previewed["create_only"], true);
    assert_eq!(state(&tasks, &task), "proposed");

    let consent = consent(
        &scene,
        &[ApprovalDecision::Denied, ApprovalDecision::Approved],
    );
    let denied = dispatch(
        &scene.workspace,
        &consent.broker,
        &tasks,
        &commit_request(&task, "q3-summary.md", &report),
    )
    .unwrap_err();
    assert_eq!(denied.code, FailureCode::ApprovalDenied);
    assert_eq!(state(&tasks, &task), "approval_denied");
    assert_eq!(scene.tree(), before, "a denied commit writes nothing");

    let created = dispatch(
        &scene.workspace,
        &consent.broker,
        &tasks,
        &commit_request(&task, "q3-summary.md", &report),
    )
    .expect("approved commit");
    assert_eq!(created["state"], "verified");
    assert_eq!(created["check"]["checker"], report_check::CHECKER);
    assert_eq!(created["check"]["passed"], true);

    // Two prompts, each for the exact report, each its own approval.
    let prompts = consent.prompts.lock().unwrap().clone();
    assert_eq!(prompts.len(), 2);
    assert_eq!(prompts[0].digest, prompts[1].digest);
    assert_ne!(prompts[0].nonce, prompts[1].nonce);
    assert_eq!(prompts[0].target, "reports/q3-summary.md");
    assert!(prompts[0].summary.contains(&sha256_hex(report.as_bytes())));
    assert!(prompts[0].summary.contains("data/q3.csv"));

    // Exactly one file was added, with exactly the approved bytes.
    let mut expected = before.clone();
    expected.insert("reports/q3-summary.md".into(), report.clone().into_bytes());
    assert_eq!(scene.tree(), expected);
    let saved = std::fs::read_to_string(scene.root().join("reports/q3-summary.md")).unwrap();
    independent_figures_check(&saved, Q3_CSV);
    assert!(saved.contains(&format!("Total: {Q3_TOTAL}")));

    // The finished task refuses further work; the record holds no content.
    let again = dispatch(
        &scene.workspace,
        &consent.broker,
        &tasks,
        &commit_request(&task, "q3-summary.md", &report),
    )
    .unwrap_err();
    assert_eq!(again.code, FailureCode::InvalidRequest);
    assert_eq!(consent.shown(), 2);
    let record = tasks.get(&task).unwrap();
    assert_eq!(record["state"], "verified");
    assert_eq!(record["report"]["sha256"], sha256_hex(report.as_bytes()));
    let text = record.to_string();
    assert!(
        !text.contains("north,Q3"),
        "no source content in the record"
    );
    assert!(
        !text.contains("Q3 revenue summary"),
        "no report content in the record"
    );
    let kinds: Vec<&str> = record["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|step| step["kind"].as_str().unwrap())
        .collect();
    assert_eq!(
        kinds,
        ["observe", "preview", "approval", "approval", "verify"]
    );
}

#[test]
fn sg126_an_existing_destination_is_never_overwritten() {
    let scene = Scene::new("exists");
    let tasks = TaskRegistry::new();
    let started = start_q3(&scene, &tasks);
    let task = started["task_id"].as_str().unwrap().to_owned();
    let report = plan_report(&started);
    let theirs = scene.root().join("reports/q3.md");

    // Present at preview.
    std::fs::write(&theirs, b"the user's own file").unwrap();
    let refused = preview(&scene, &tasks, &task, "q3.md", &report).unwrap_err();
    assert_eq!(refused.code, FailureCode::TargetStale);
    assert!(refused.message.contains("never overwrites"));
    assert_eq!(state(&tasks, &task), "observed", "the task stays open");
    std::fs::remove_file(&theirs).unwrap();

    // Created after the preview: refused before any approval.
    preview(&scene, &tasks, &task, "q3.md", &report).expect("preview");
    std::fs::write(&theirs, b"the user's own file").unwrap();
    let consent = consent(&scene, &[ApprovalDecision::Approved]);
    let refused = dispatch(
        &scene.workspace,
        &consent.broker,
        &tasks,
        &commit_request(&task, "q3.md", &report),
    )
    .unwrap_err();
    assert_eq!(refused.code, FailureCode::TargetStale);
    assert_eq!(consent.shown(), 0, "no approval is asked for");
    assert_eq!(std::fs::read(&theirs).unwrap(), b"the user's own file");
    std::fs::remove_file(&theirs).unwrap();

    // Created between the approval and the write: refused, unchanged, and
    // the spent approval is not reused.
    let race = scene.root().join("reports/q3.md");
    let refused = dispatch_with(
        &scene.workspace,
        &consent.broker,
        &tasks,
        &commit_request(&task, "q3.md", &report),
        &Hooks {
            after_approval: &|| std::fs::write(&race, b"created during the approval").unwrap(),
            before_write: &|| {},
            after_preview_check: &|| {},
        },
    )
    .unwrap_err();
    assert_eq!(refused.code, FailureCode::TargetStale);
    assert_eq!(consent.shown(), 1);
    assert_eq!(
        std::fs::read(&race).unwrap(),
        b"created during the approval"
    );
    assert_eq!(state(&tasks, &task), "proposed");

    // A different name needs its own preview and its own approval.
    let other = consent_for_one_more(&scene);
    preview(&scene, &tasks, &task, "q3-v2.md", &report).expect("preview new name");
    dispatch(
        &scene.workspace,
        &other.broker,
        &tasks,
        &commit_request(&task, "q3-v2.md", &report),
    )
    .expect("commit new name");
    assert_eq!(other.shown(), 1);
    assert_eq!(
        std::fs::read(&race).unwrap(),
        b"created during the approval"
    );
}

fn consent_for_one_more(scene: &Scene) -> Consent {
    consent(scene, &[ApprovalDecision::Approved])
}

#[test]
fn sg126_commit_needs_the_exact_previewed_report() {
    let scene = Scene::new("exact");
    let tasks = TaskRegistry::new();
    let started = start_q3(&scene, &tasks);
    let task = started["task_id"].as_str().unwrap().to_owned();
    let report = plan_report(&started);
    let consent = consent(&scene, &[ApprovalDecision::Approved]);
    // Not previewed yet.
    let refused = dispatch(
        &scene.workspace,
        &consent.broker,
        &tasks,
        &commit_request(&task, "q3.md", &report),
    )
    .unwrap_err();
    assert_eq!(refused.code, FailureCode::TargetStale);
    preview(&scene, &tasks, &task, "q3.md", &report).unwrap();
    // Other bytes, another name, or a hash that does not match.
    for request in [
        commit_request(&task, "q3.md", "Total: 1.00\n"),
        commit_request(&task, "q4.md", &report),
        request(
            "commit",
            json!({"task_id": task, "name": "q3.md", "content": report, "expected_sha256": "0".repeat(64)}),
        ),
    ] {
        let refused = dispatch(&scene.workspace, &consent.broker, &tasks, &request).unwrap_err();
        assert_eq!(refused.code, FailureCode::TargetStale);
    }
    assert_eq!(consent.shown(), 0);
    assert!(!scene.root().join("reports/q3.md").exists());
    assert!(!scene.root().join("reports/q4.md").exists());
    // A task id this run never issued.
    let refused = preview(
        &scene,
        &tasks,
        "rpt-0123456789abcdef0123456789abcdef",
        "q3.md",
        &report,
    )
    .unwrap_err();
    assert_eq!(refused.code, FailureCode::TargetStale);
}

#[test]
fn sg126_a_changed_source_makes_the_task_stale_and_writes_nothing() {
    for when in [
        "before preview",
        "before commit",
        "after approval",
        "removed",
    ] {
        let scene = Scene::new("stale");
        let tasks = TaskRegistry::new();
        let started = start_q3(&scene, &tasks);
        let task = started["task_id"].as_str().unwrap().to_owned();
        let report = plan_report(&started);
        let source = scene.root().join("data/q3.csv");
        let change = || std::fs::write(&source, format!("{Q3_CSV}west,Q3,1\n")).unwrap();
        let consent = consent(&scene, &[ApprovalDecision::Approved]);
        let outcome = match when {
            "before preview" => {
                change();
                preview(&scene, &tasks, &task, "q3.md", &report).map(|_| json!(null))
            }
            "removed" => {
                std::fs::remove_file(&source).unwrap();
                preview(&scene, &tasks, &task, "q3.md", &report).map(|_| json!(null))
            }
            "before commit" => {
                preview(&scene, &tasks, &task, "q3.md", &report).unwrap();
                change();
                dispatch(
                    &scene.workspace,
                    &consent.broker,
                    &tasks,
                    &commit_request(&task, "q3.md", &report),
                )
            }
            _ => {
                preview(&scene, &tasks, &task, "q3.md", &report).unwrap();
                dispatch_with(
                    &scene.workspace,
                    &consent.broker,
                    &tasks,
                    &commit_request(&task, "q3.md", &report),
                    &Hooks {
                        after_approval: &change,
                        before_write: &|| {},
                        after_preview_check: &|| {},
                    },
                )
            }
        };
        let refused = outcome.unwrap_err();
        assert_eq!(refused.code, FailureCode::TargetStale, "{when}");
        assert!(
            refused.message.contains("data/q3.csv"),
            "{when}: {}",
            refused.message
        );
        assert_eq!(state(&tasks, &task), "stale", "{when}");
        assert!(!scene.root().join("reports/q3.md").exists(), "{when}");
        assert_eq!(
            consent.shown(),
            usize::from(when == "after approval"),
            "{when}"
        );
        // A stale task stays stale; a new task observes the sources again.
        let again = preview(&scene, &tasks, &task, "q3.md", &report).unwrap_err();
        assert_eq!(again.code, FailureCode::TargetStale, "{when}");
        assert_eq!(
            again.message, refused.message,
            "{when}: it still says which"
        );
    }
}

#[test]
fn a_source_that_cannot_be_read_is_named_in_the_refusal() {
    let scene = Scene::new("named");
    let approval = consent(&scene, &[]);
    let tasks = TaskRegistry::new();
    std::fs::write(scene.root().join("data/binary.csv"), [0xff, 0xfe, 0x00]).unwrap();
    let provider = FsProvider::new(&scene.workspace.root).unwrap();
    for second in ["data/missing.csv", "data/binary.csv"] {
        let direct = provider.read_text(second).unwrap_err();
        let refused = dispatch(
            &scene.workspace,
            &approval.broker,
            &tasks,
            &request(
                "start",
                json!({"title": "Q3", "sources": ["data/q3.csv", second], "folder": "reports"}),
            ),
        )
        .unwrap_err();
        assert_eq!(
            refused.message,
            format!("report source {second}: {}", direct.message)
        );
        assert_eq!(refused.code, direct.code, "the code is unchanged");
    }
}

#[test]
fn sg126_the_folder_must_be_an_existing_plain_workspace_directory() {
    let scene = Scene::new("folder");
    let tasks = TaskRegistry::new();
    let approval = consent(&scene, &[]);
    let start = |folder: &str| {
        dispatch(
            &scene.workspace,
            &approval.broker,
            &tasks,
            &request(
                "start",
                json!({"title": "t", "sources": ["data/q3.csv"], "folder": folder}),
            ),
        )
    };
    assert!(start("missing").is_err());
    assert_eq!(
        start("data/q3.csv").unwrap_err().code,
        FailureCode::InvalidRequest
    );
    let outside = scene.dir.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&outside, scene.root().join("linked")).unwrap();
        assert!(start("linked").is_err(), "a linked folder is refused");
        std::os::unix::fs::symlink(&outside, scene.root().join("reports/up")).unwrap();
        assert!(start("reports/up").is_err());
    }
    // The folder replaced by a link after start: the task becomes stale.
    #[cfg(unix)]
    {
        let started = start_q3(&scene, &tasks);
        let task = started["task_id"].as_str().unwrap().to_owned();
        std::fs::rename(scene.root().join("reports"), scene.root().join("moved")).unwrap();
        std::os::unix::fs::symlink(&outside, scene.root().join("reports")).unwrap();
        let refused = preview(&scene, &tasks, &task, "q3.md", "x").unwrap_err();
        assert_eq!(refused.code, FailureCode::TargetStale);
        assert_eq!(state(&tasks, &task), "stale");
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
    }
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
    assert_eq!(approval.shown(), 0);
}

#[test]
fn sg126_the_checker_fails_on_tampered_bytes_size_folder_and_sources() {
    let scene = Scene::new("checker");
    let root = scene.root().to_path_buf();
    let folder = std::fs::canonicalize(root.join("reports")).unwrap();
    let folder_path = root.join("reports");
    let report = "Total: 37300.75\n";
    std::fs::write(root.join("reports/r.md"), report).unwrap();
    let sources = vec![SourceRecord {
        path: "data/q3.csv".into(),
        sha256: sha256_hex(Q3_CSV.as_bytes()),
        bytes: Q3_CSV.len() as u64,
    }];
    let sha = sha256_hex(report.as_bytes());
    let expect = |destination: &'static str, sha256: &str, bytes: u64, folder: &Path| {
        report_check::check(&report_check::Expectation {
            root: &root,
            folder_path: &folder_path,
            folder,
            destination,
            sha256,
            bytes,
            sources: &sources,
        })
    };
    let passed = expect("reports/r.md", &sha, report.len() as u64, &folder).expect("pass");
    assert_eq!(passed["passed"], true);
    assert_eq!(passed["sources_unchanged"], 1);

    // Other bytes of the same size.
    std::fs::write(root.join("reports/r.md"), "Total: 99999.75\n").unwrap();
    assert!(expect("reports/r.md", &sha, report.len() as u64, &folder)
        .unwrap_err()
        .contains("SHA-256"));
    // A different size.
    std::fs::write(root.join("reports/r.md"), format!("{report}x")).unwrap();
    assert!(expect("reports/r.md", &sha, report.len() as u64, &folder).is_err());
    std::fs::write(root.join("reports/r.md"), "short").unwrap();
    assert!(expect("reports/r.md", &sha, report.len() as u64, &folder)
        .unwrap_err()
        .contains("bytes"));
    // Not in the task's folder.
    std::fs::write(root.join("data/r.md"), report).unwrap();
    assert!(expect("data/r.md", &sha, report.len() as u64, &folder)
        .unwrap_err()
        .contains("folder"));
    // Missing, or a directory.
    assert!(expect("reports/none.md", &sha, 1, &folder).is_err());
    std::fs::create_dir(root.join("reports/d.md")).unwrap();
    assert!(expect("reports/d.md", &sha, 1, &folder).is_err());
    // A changed source.
    std::fs::write(root.join("reports/r.md"), report).unwrap();
    std::fs::write(root.join("data/q3.csv"), "changed").unwrap();
    assert!(expect("reports/r.md", &sha, report.len() as u64, &folder)
        .unwrap_err()
        .contains("data/q3.csv"));
    // A link at the destination.
    #[cfg(unix)]
    {
        std::fs::write(root.join("data/q3.csv"), Q3_CSV).unwrap();
        std::os::unix::fs::symlink(root.join("reports/r.md"), root.join("reports/l.md")).unwrap();
        assert!(expect("reports/l.md", &sha, report.len() as u64, &folder)
            .unwrap_err()
            .contains("link"));
    }
}

#[test]
fn sg126_report_requests_are_local_only_and_policy_admitted() {
    let scene = Scene::new("entry");
    let tasks = TaskRegistry::new();
    let approval = consent(&scene, &[ApprovalDecision::Approved]);
    let policy = PolicyEngine::new(vec![scene.workspace.clone()]).unwrap();
    let audit = AuditLogger::new(scene.dir.join("audit.jsonl")).unwrap();
    let envelope = |request: RequestEnvelope, remote: bool| RemoteRequestEnvelope {
        request,
        remote: remote.then(|| RemoteContext {
            principal: "p".into(),
            remote_connection_id: "rc".into(),
            connection_id: "c".into(),
            device_id: "d".into(),
            device_epoch: 1,
            provider_kind: "generic".into(),
            client_profile_id: "cp".into(),
            client_profile_revision: 1,
            tool_surface_profile: "core".into(),
            scopes: vec!["orcel.local.write".into()],
        }),
        profile: None,
    };
    let start = request(
        "start",
        json!({"title": "Q3 revenue", "sources": ["data/q3.csv"], "folder": "reports"}),
    );
    let remote = handle_envelope(
        &policy,
        &audit,
        &approval.broker,
        &tasks,
        envelope(start.clone(), true),
    );
    assert!(!remote.ok);
    assert_eq!(
        remote.error.as_ref().unwrap().code,
        FailureCode::CapabilityDenied
    );
    assert_eq!(
        tasks.list()["tasks"],
        json!([]),
        "a remote start opens no task"
    );

    let started = handle_envelope(
        &policy,
        &audit,
        &approval.broker,
        &tasks,
        envelope(start, false),
    );
    assert!(started.ok, "{:?}", started.error);
    let task = tasks.list()["tasks"][0]["task_id"]
        .as_str()
        .unwrap()
        .to_owned();
    for (name, folder_escape) in [
        ("../q3.md", false),
        ("q3.exe", false),
        ("a/b.md", false),
        ("x", true),
    ] {
        let request = if folder_escape {
            request(
                "start",
                json!({"title": "t", "sources": ["data/q3.csv"], "folder": "../outside"}),
            )
        } else {
            commit_request(&task, name, "x")
        };
        let refused = handle_envelope(
            &policy,
            &audit,
            &approval.broker,
            &tasks,
            envelope(request, false),
        );
        assert_eq!(
            refused.error.as_ref().map(|error| error.code.clone()),
            Some(FailureCode::PathEscape),
            "{name}"
        );
    }
    let remote_commit = handle_envelope(
        &policy,
        &audit,
        &approval.broker,
        &tasks,
        envelope(commit_request(&task, "q3.md", "x"), true),
    );
    assert_eq!(
        remote_commit.error.as_ref().map(|error| error.code.clone()),
        Some(FailureCode::CapabilityDenied)
    );
    assert_eq!(approval.shown(), 0);
    let audit_log = std::fs::read_to_string(scene.dir.join("audit.jsonl")).unwrap();
    assert!(audit_log.contains("REMOTE_DENIED"));
    assert!(
        !audit_log.contains("north,Q3"),
        "no content in the audit log"
    );
}

#[test]
fn sg126_the_registry_is_bounded_and_evicts_only_finished_tasks() {
    let scene = Scene::new("bounds");
    let tasks = TaskRegistry::new();
    let mut ids = Vec::new();
    for _ in 0..MAX_TASKS {
        ids.push(
            start_q3(&scene, &tasks)["task_id"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }
    let mut unique = ids.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), MAX_TASKS, "ids are not reused");
    let approval = consent(&scene, &[]);
    let full = dispatch(
        &scene.workspace,
        &approval.broker,
        &tasks,
        &request(
            "start",
            json!({"title": "t", "sources": ["data/q3.csv"], "folder": "reports"}),
        ),
    )
    .unwrap_err();
    assert_eq!(full.code, FailureCode::OutputLimit);
    // Make the third task stale; the next start evicts it and only it.
    std::fs::write(scene.root().join("data/q3.csv"), "changed").unwrap();
    assert!(preview(&scene, &tasks, &ids[2], "q3.md", "x").is_err());
    std::fs::write(scene.root().join("data/q3.csv"), Q3_CSV).unwrap();
    start_q3(&scene, &tasks);
    assert!(tasks.get(&ids[2]).is_none());
    assert!(tasks.get(&ids[0]).is_some());
    assert_eq!(tasks.list()["tasks"].as_array().unwrap().len(), MAX_TASKS);
}

/// A directory link: a junction on Windows (no privilege needed), a
/// symbolic link elsewhere.
pub(crate) fn link_dir(link: &Path, target: &Path) {
    #[cfg(windows)]
    {
        let output = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output()
            .expect("run mklink");
        assert!(output.status.success(), "mklink /J failed: {output:?}");
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, link).expect("symlink");
}

#[test]
fn sg126_the_write_itself_never_opens_an_existing_entry() {
    let scene = Scene::new("write-race");
    let tasks = TaskRegistry::new();
    let started = start_q3(&scene, &tasks);
    let task = started["task_id"].as_str().unwrap().to_owned();
    let report = plan_report(&started);
    preview(&scene, &tasks, &task, "q3.md", &report).unwrap();
    let consent = consent(
        &scene,
        &[ApprovalDecision::Approved, ApprovalDecision::Approved],
    );
    // A regular file planted after every check, immediately before the
    // create: refused by the create-new open, unchanged, task reopened.
    let planted = scene.root().join("reports/q3.md");
    let refused = dispatch_with(
        &scene.workspace,
        &consent.broker,
        &tasks,
        &commit_request(&task, "q3.md", &report),
        &Hooks {
            after_approval: &|| {},
            before_write: &|| std::fs::write(&planted, b"planted").unwrap(),
            after_preview_check: &|| {},
        },
    )
    .unwrap_err();
    assert_eq!(refused.code, FailureCode::TargetStale);
    assert_eq!(std::fs::read(&planted).unwrap(), b"planted");
    assert_eq!(state(&tasks, &task), "proposed");
    assert!(tasks.get(&task).unwrap()["check"].is_null());
    // The same bytes planted there still never verify: orceld did not
    // write them.
    preview(&scene, &tasks, &task, "q3-b.md", &report).unwrap();
    let same = scene.root().join("reports/q3-b.md");
    let refused = dispatch_with(
        &scene.workspace,
        &consent.broker,
        &tasks,
        &commit_request(&task, "q3-b.md", &report),
        &Hooks {
            after_approval: &|| {},
            before_write: &|| std::fs::write(&same, report.as_bytes()).unwrap(),
            after_preview_check: &|| {},
        },
    )
    .unwrap_err();
    assert_eq!(refused.code, FailureCode::TargetStale);
    assert_ne!(state(&tasks, &task), "verified");
    // A link planted at the name is refused and its target untouched.
    #[cfg(unix)]
    {
        let theirs = scene.dir.join("theirs.md");
        std::fs::write(&theirs, b"theirs").unwrap();
        preview(&scene, &tasks, &task, "q3-c.md", &report).unwrap();
        let link = scene.root().join("reports/q3-c.md");
        let consent = consent_for_one_more(&scene);
        let refused = dispatch_with(
            &scene.workspace,
            &consent.broker,
            &tasks,
            &commit_request(&task, "q3-c.md", &report),
            &Hooks {
                after_approval: &|| {},
                before_write: &|| std::os::unix::fs::symlink(&theirs, &link).unwrap(),
                after_preview_check: &|| {},
            },
        )
        .unwrap_err();
        assert_eq!(refused.code, FailureCode::TargetStale);
        assert_eq!(std::fs::read(&theirs).unwrap(), b"theirs");
    }
}

#[test]
fn sg126_a_folder_linked_away_before_the_write_never_verifies() {
    let scene = Scene::new("folder-swap");
    let tasks = TaskRegistry::new();
    let started = start_q3(&scene, &tasks);
    let task = started["task_id"].as_str().unwrap().to_owned();
    let report = plan_report(&started);
    preview(&scene, &tasks, &task, "q3.md", &report).unwrap();
    let consent = consent(&scene, &[ApprovalDecision::Approved]);
    let other = scene.root().join("other");
    std::fs::create_dir(&other).unwrap();
    let reports = scene.root().join("reports");
    let moved = scene.root().join("moved");
    let outcome = dispatch_with(
        &scene.workspace,
        &consent.broker,
        &tasks,
        &commit_request(&task, "q3.md", &report),
        &Hooks {
            after_approval: &|| {},
            before_write: &|| {
                std::fs::rename(&reports, &moved).unwrap();
                link_dir(&reports, &other);
            },
            after_preview_check: &|| {},
        },
    );
    let refused = outcome.unwrap_err();
    assert_ne!(state(&tasks, &task), "verified");
    // The provider followed the link to a folder inside the workspace (it
    // refuses anything outside the root); the checker refused the result.
    assert!(other.join("q3.md").exists());
    assert_eq!(refused.code, FailureCode::PostconditionFailed);
    assert_eq!(state(&tasks, &task), "verification_failed");
    assert_eq!(tasks.get(&task).unwrap()["check"]["passed"], false);
    assert!(!moved.join("q3.md").exists());
}

#[test]
fn sg126_linked_folders_are_refused_on_every_os() {
    let scene = Scene::new("linked-folder");
    let tasks = TaskRegistry::new();
    let approval = consent(&scene, &[]);
    let inside = scene.root().join("inside");
    std::fs::create_dir(&inside).unwrap();
    link_dir(&scene.root().join("linked"), &inside);
    let refused = dispatch(
        &scene.workspace,
        &approval.broker,
        &tasks,
        &request(
            "start",
            json!({"title": "t", "sources": ["data/q3.csv"], "folder": "linked"}),
        ),
    )
    .unwrap_err();
    assert_ne!(refused.code, FailureCode::InternalError);
    assert_eq!(tasks.list()["tasks"], json!([]));
    // A folder replaced by a link after start makes the task stale.
    let started = start_q3(&scene, &tasks);
    let task = started["task_id"].as_str().unwrap().to_owned();
    std::fs::rename(scene.root().join("reports"), scene.root().join("moved")).unwrap();
    link_dir(&scene.root().join("reports"), &inside);
    let refused = preview(&scene, &tasks, &task, "q3.md", "x").unwrap_err();
    assert_eq!(refused.code, FailureCode::TargetStale);
    assert_eq!(state(&tasks, &task), "stale");
    // The checker refuses a linked folder even when the bytes match.
    let report = "x";
    std::fs::write(inside.join("r.md"), report).unwrap();
    let canonical = std::fs::canonicalize(scene.root().join("moved")).unwrap();
    let checked = report_check::check(&report_check::Expectation {
        root: scene.root(),
        folder_path: &scene.root().join("reports"),
        folder: &canonical,
        destination: "reports/r.md",
        sha256: &sha256_hex(report.as_bytes()),
        bytes: 1,
        sources: &[],
    });
    assert!(checked.is_err());
    assert_eq!(std::fs::read_dir(&inside).unwrap().count(), 1);
}

#[test]
fn sg126_a_source_grown_past_the_read_bound_is_stale() {
    let scene = Scene::new("big-source");
    let tasks = TaskRegistry::new();
    let started = start_q3(&scene, &tasks);
    let task = started["task_id"].as_str().unwrap().to_owned();
    let big = std::fs::File::create(scene.root().join("data/q3.csv")).unwrap();
    // Past the provider read bound (1 MiB); start read the source through
    // that same bound.
    big.set_len(4 << 20).unwrap();
    drop(big);
    let began = std::time::Instant::now();
    let refused = preview(&scene, &tasks, &task, "q3.md", "x").unwrap_err();
    assert_eq!(refused.code, FailureCode::TargetStale);
    assert!(began.elapsed() < std::time::Duration::from_secs(10));
    assert_eq!(state(&tasks, &task), "stale");
}

#[cfg(unix)]
#[test]
fn sg126_a_backslash_in_a_unix_folder_name_stays_in_that_folder() {
    let scene = Scene::new("backslash");
    let tasks = TaskRegistry::new();
    std::fs::create_dir(scene.root().join("rep\\")).unwrap();
    let approval = consent(&scene, &[ApprovalDecision::Approved]);
    let started = dispatch(
        &scene.workspace,
        &approval.broker,
        &tasks,
        &request(
            "start",
            json!({"title": "t", "sources": ["data/q3.csv"], "folder": "rep\\"}),
        ),
    )
    .unwrap();
    let task = started["task_id"].as_str().unwrap().to_owned();
    let previewed = preview(&scene, &tasks, &task, "q3.md", "x").unwrap();
    assert_eq!(previewed["destination"], "rep\\/q3.md");
    dispatch(
        &scene.workspace,
        &approval.broker,
        &tasks,
        &commit_request(&task, "q3.md", "x"),
    )
    .expect("commit");
    assert!(scene.root().join("rep\\").join("q3.md").exists());
    assert!(!scene.root().join("rep").exists());
}

#[test]
fn sg126_linked_sources_are_refused_before_any_approval() {
    let scene = Scene::new("linked-source");
    let tasks = TaskRegistry::new();
    let approval = consent(&scene, &[ApprovalDecision::Approved]);
    // A source named through a link is refused at start.
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(
            scene.root().join("data/q3.csv"),
            scene.root().join("data/alias.csv"),
        )
        .unwrap();
        let refused = dispatch(
            &scene.workspace,
            &approval.broker,
            &tasks,
            &request(
                "start",
                json!({"title": "t", "sources": ["data/alias.csv"], "folder": "reports"}),
            ),
        )
        .unwrap_err();
        assert_eq!(refused.code, FailureCode::CapabilityDenied);
    }
    // Replaced by a link after start: stale at preview, before approval.
    let started = start_q3(&scene, &tasks);
    let task = started["task_id"].as_str().unwrap().to_owned();
    let original = scene.root().join("data/q3.csv");
    let copy = scene.root().join("data/copy.csv");
    std::fs::write(&copy, Q3_CSV).unwrap();
    std::fs::remove_file(&original).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&copy, &original).unwrap();
    #[cfg(windows)]
    {
        let outcome = std::process::Command::new("cmd")
            .args(["/C", "mklink"])
            .arg(&original)
            .arg(&copy)
            .output()
            .expect("run mklink");
        if !outcome.status.success() {
            // File symbolic links need the privilege or Developer Mode on
            // Windows; without them the replacement is a plain copy, which
            // still leaves the task valid.
            std::fs::write(&original, Q3_CSV).unwrap();
            assert!(preview(&scene, &tasks, &task, "q3.md", "x").is_ok());
            assert_eq!(approval.shown(), 0);
            return;
        }
    }
    let refused = preview(&scene, &tasks, &task, "q3.md", "x").unwrap_err();
    assert_eq!(refused.code, FailureCode::TargetStale);
    assert_eq!(state(&tasks, &task), "stale");
    assert_eq!(approval.shown(), 0);
}

#[test]
fn sg126_the_normal_request_path_refuses_report_requests() {
    let scene = Scene::new("normal-path");
    let approval = consent(&scene, &[ApprovalDecision::Approved]);
    let policy = PolicyEngine::new(vec![scene.workspace.clone()]).unwrap();
    let audit = AuditLogger::new(scene.dir.join("audit.jsonl")).unwrap();
    let workspace_set = crate::remote_lease::WorkspaceSet {
        ids: vec!["default".into()],
        roots: vec![scene.root().to_path_buf()],
        digest: "test".into(),
    };
    let start = request(
        "start",
        json!({"title": "t", "sources": ["data/q3.csv"], "folder": "reports"}),
    );
    let refused = crate::handle_envelope(
        &policy,
        &audit,
        &approval.broker,
        &workspace_set,
        RemoteRequestEnvelope {
            request: start,
            remote: None,
            profile: None,
        },
    );
    assert_eq!(
        refused.error.as_ref().map(|error| error.code.clone()),
        Some(FailureCode::CapabilityDenied)
    );
    assert_eq!(approval.shown(), 0);
}

// ---------------------------------------------------------------------------
// F4 slice 5 (prep/F4_TASK_STOP.md). The only surface is the local app API's
// `task.stop` (founder decision of 2026-11-13, #446); see app_api/tests.rs.
// ---------------------------------------------------------------------------

/// Answers one prompt after running `during`, as if it happened while the
/// system dialog was open.
fn consent_during(
    scene: &Scene,
    decision: ApprovalDecision,
    during: impl Fn() + Send + Sync + 'static,
) -> LocalApprovalBroker {
    LocalApprovalBroker::with_path_and_soft_decider(
        scene.dir.join("approvals.json"),
        Arc::new(NoPresenceVerifier),
        Arc::new(move |_: &ApprovalPrompt| {
            during();
            decision
        }),
    )
}

const STOP_REPORT: &str = "The Q3 total is 37300.75.";

fn proposed_task(scene: &Scene, tasks: &TaskRegistry) -> String {
    let task = start_q3(scene, tasks)["task_id"]
        .as_str()
        .unwrap()
        .to_owned();
    preview(scene, tasks, &task, "q3.md", STOP_REPORT).expect("preview");
    task
}

#[test]
fn f4_stop_from_every_open_state_is_final_and_writes_nothing() {
    for open in ["observed", "proposed", "approval_denied"] {
        let scene = Scene::new("stop-open");
        let before = scene.tree();
        let tasks = TaskRegistry::new();
        let task = start_q3(&scene, &tasks)["task_id"]
            .as_str()
            .unwrap()
            .to_owned();
        if open != "observed" {
            preview(&scene, &tasks, &task, "q3.md", STOP_REPORT).expect("preview");
        }
        if open == "approval_denied" {
            let denied = consent(&scene, &[ApprovalDecision::Denied]);
            let request = commit_request(&task, "q3.md", STOP_REPORT);
            dispatch(&scene.workspace, &denied.broker, &tasks, &request).unwrap_err();
        }
        assert_eq!(state(&tasks, &task), open);
        let stopped = tasks.stop(&task, "default").expect("stop");
        assert_eq!(stopped["state"], "stopped");
        assert_eq!(state(&tasks, &task), "stopped");
        // Idempotent.
        assert_eq!(
            tasks.stop(&task, "default").expect("again")["state"],
            "stopped"
        );
        // Every later request is refused, and no prompt is ever shown.
        let approval = consent(&scene, &[ApprovalDecision::Approved]);
        let failure = preview(&scene, &tasks, &task, "q3.md", STOP_REPORT).unwrap_err();
        assert_eq!(failure.code, FailureCode::TargetStale, "{open}");
        let request = commit_request(&task, "q3.md", STOP_REPORT);
        let failure = dispatch(&scene.workspace, &approval.broker, &tasks, &request).unwrap_err();
        assert_eq!(failure.code, FailureCode::TargetStale, "{open}");
        assert_eq!(approval.shown(), 0, "{open}");
        assert_eq!(scene.tree(), before, "{open}: nothing was written");
    }
}

#[test]
fn f4_an_approval_granted_after_a_stop_writes_nothing_and_stays_spent() {
    let scene = Scene::new("stop-prompt");
    let before = scene.tree();
    let tasks = Arc::new(TaskRegistry::new());
    let task = proposed_task(&scene, &tasks);
    let (during, id) = (Arc::clone(&tasks), task.clone());
    let broker = Recording {
        inner: consent_during(&scene, ApprovalDecision::Approved, move || {
            during.stop(&id, "default").expect("stop during the prompt");
        }),
        seen: Mutex::new(None),
    };
    let request = commit_request(&task, "q3.md", STOP_REPORT);
    let failure = dispatch(&scene.workspace, &broker, &tasks, &request).unwrap_err();
    assert_eq!(failure.code, FailureCode::TargetStale);
    assert!(failure.message.contains("stopped"), "{}", failure.message);
    assert_eq!(state(&tasks, &task), "stopped");
    assert_eq!(scene.tree(), before, "nothing was written");
    // The approval was consumed before the refusal: it cannot be used again.
    let (token, expected) = broker.seen.lock().unwrap().clone().expect("consumed once");
    assert!(
        broker
            .inner
            .consume(&token, &expected, orcel_approval::now_ms())
            .is_err(),
        "a second consume of the spent approval fails"
    );
}

#[test]
fn f4_a_denial_after_a_stop_leaves_the_task_stopped() {
    let scene = Scene::new("stop-denied");
    let tasks = Arc::new(TaskRegistry::new());
    let task = proposed_task(&scene, &tasks);
    let (during, id) = (Arc::clone(&tasks), task.clone());
    let broker = consent_during(&scene, ApprovalDecision::Denied, move || {
        during.stop(&id, "default").expect("stop during the prompt");
    });
    let request = commit_request(&task, "q3.md", STOP_REPORT);
    let failure = dispatch(&scene.workspace, &broker, &tasks, &request).unwrap_err();
    assert_eq!(failure.code, FailureCode::ApprovalDenied);
    assert_eq!(state(&tasks, &task), "stopped");
}

#[test]
fn f4_stop_is_refused_while_a_commit_writes_and_the_commit_finishes() {
    let scene = Scene::new("stop-committing");
    let tasks = TaskRegistry::new();
    let task = proposed_task(&scene, &tasks);
    let approval = consent(&scene, &[ApprovalDecision::Approved]);
    let check_stop = || {
        let failure = tasks.stop(&task, "default").unwrap_err();
        assert_eq!(failure.code, FailureCode::InvalidRequest);
        assert!(
            failure.message.contains("committing"),
            "{}",
            failure.message
        );
    };
    let hooks = Hooks {
        after_approval: &check_stop,
        before_write: &check_stop,
        after_preview_check: &|| {},
    };
    let request = commit_request(&task, "q3.md", STOP_REPORT);
    dispatch_with(&scene.workspace, &approval.broker, &tasks, &request, &hooks).expect("commit");
    assert_eq!(state(&tasks, &task), "verified");
    // Stop of a finished task names its state and changes nothing.
    let failure = tasks.stop(&task, "default").unwrap_err();
    assert_eq!(failure.code, FailureCode::InvalidRequest);
    assert!(failure.message.contains("verified"), "{}", failure.message);
    assert_eq!(state(&tasks, &task), "verified");
}

#[test]
fn f4_stop_in_this_run_uses_the_tasks_own_workspace() {
    let scene = Scene::new("stop-own-workspace");
    let tasks = TaskRegistry::new();
    let started = start_q3(&scene, &tasks);
    let task = started["task_id"].as_str().unwrap().to_owned();
    assert_eq!(
        tasks.stop_in_this_run(&task).expect("stop")["state"],
        "stopped"
    );
    assert_eq!(state(&tasks, &task), "stopped");
    let unknown = tasks.stop_in_this_run("report_unknown").unwrap_err();
    assert_eq!(unknown.code, FailureCode::TargetStale);
}

#[test]
fn f4_stop_isnt_a_report_operation() {
    let scene = Scene::new("stop-not-dispatched");
    let approval = consent(&scene, &[]);
    let tasks = TaskRegistry::new();
    let started = start_q3(&scene, &tasks);
    let task = started["task_id"].as_str().unwrap().to_owned();
    let refused = dispatch(
        &scene.workspace,
        &approval.broker,
        &tasks,
        &request("stop", json!({"task_id": task})),
    )
    .unwrap_err();
    assert_eq!(refused.code, FailureCode::CapabilityDenied);
    assert_ne!(state(&tasks, &task), "stopped");
}

#[test]
fn f4_stop_of_an_unknown_or_foreign_task_is_refused_alike() {
    let scene = Scene::new("stop-foreign");
    let tasks = TaskRegistry::new();
    let task = proposed_task(&scene, &tasks);
    let unknown = tasks.stop("report_unknown", "default").unwrap_err();
    let foreign = tasks.stop(&task, "another-workspace").unwrap_err();
    assert_eq!(unknown.code, FailureCode::TargetStale);
    assert_eq!(foreign.code, FailureCode::TargetStale);
    assert_eq!(
        unknown.message, foreign.message,
        "no oracle for another workspace's task"
    );
    assert_eq!(state(&tasks, &task), "proposed");
}

#[test]
fn f4_a_stop_during_a_preview_is_not_overwritten() {
    let scene = Scene::new("stop-preview");
    let tasks = TaskRegistry::new();
    let task = start_q3(&scene, &tasks)["task_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let stop = || {
        tasks
            .stop(&task, "default")
            .expect("stop during the preview");
    };
    let hooks = Hooks {
        after_approval: &|| {},
        before_write: &|| {},
        after_preview_check: &stop,
    };
    let approval = consent(&scene, &[]);
    let request = RequestEnvelope {
        operation: "preview".into(),
        ..commit_request(&task, "q3.md", STOP_REPORT)
    };
    let failure =
        dispatch_with(&scene.workspace, &approval.broker, &tasks, &request, &hooks).unwrap_err();
    assert_eq!(failure.code, FailureCode::TargetStale);
    assert_eq!(state(&tasks, &task), "stopped");
    assert!(
        tasks.get(&task).unwrap()["proposal"].is_null(),
        "the preview left no proposal"
    );
}

#[test]
fn f4_a_stale_check_after_a_stop_leaves_the_task_stopped() {
    let scene = Scene::new("stop-stale");
    let tasks = TaskRegistry::new();
    let task = proposed_task(&scene, &tasks);
    tasks.stop(&task, "default").expect("stop");
    let _ = blocked(
        &tasks,
        &task,
        "preview",
        &OPEN_STATES,
        Blocked::Stale(error(FailureCode::TargetStale, "a source changed")),
    );
    assert_eq!(state(&tasks, &task), "stopped");
}

#[test]
fn f4_two_commits_of_one_task_write_once_and_the_loser_writes_nothing() {
    let scene = Scene::new("two-commits");
    let tasks = Arc::new(TaskRegistry::new());
    let task = proposed_task(&scene, &tasks);
    // While the first commit's prompt is open, a second commit of the same
    // task runs to the end.
    let inner_scene = scene.workspace.clone();
    let inner_ledger = scene.dir.join("inner-approvals.json");
    let (during, id) = (Arc::clone(&tasks), task.clone());
    let broker = consent_during(&scene, ApprovalDecision::Approved, move || {
        let inner = LocalApprovalBroker::with_path_and_soft_decider(
            inner_ledger.clone(),
            Arc::new(NoPresenceVerifier),
            Arc::new(|_: &ApprovalPrompt| ApprovalDecision::Approved),
        );
        let request = commit_request(&id, "q3.md", STOP_REPORT);
        dispatch(&inner_scene, &inner, &during, &request).expect("the inner commit");
    });
    let request = commit_request(&task, "q3.md", STOP_REPORT);
    let failure = dispatch(&scene.workspace, &broker, &tasks, &request).unwrap_err();
    assert_eq!(failure.code, FailureCode::TargetStale);
    assert!(failure.message.contains("changed"), "{}", failure.message);
    assert_eq!(
        state(&tasks, &task),
        "verified",
        "the winner's state stands"
    );
    let written = scene.tree();
    assert_eq!(
        written.get("reports/q3.md").map(Vec::as_slice),
        Some(STOP_REPORT.as_bytes())
    );
}

#[test]
fn f4_a_preview_during_the_prompt_means_the_approved_report_is_not_written() {
    let scene = Scene::new("preview-during-prompt");
    let before = scene.tree();
    let tasks = Arc::new(TaskRegistry::new());
    let task = proposed_task(&scene, &tasks);
    let inner_scene = scene.workspace.clone();
    let (during, id) = (Arc::clone(&tasks), task.clone());
    let broker = consent_during(&scene, ApprovalDecision::Approved, move || {
        let unused = NeverAsked;
        let request = RequestEnvelope {
            operation: "preview".into(),
            ..commit_request(&id, "other.md", "another report")
        };
        dispatch(&inner_scene, &unused, &during, &request).expect("the newer preview");
    });
    let request = commit_request(&task, "q3.md", STOP_REPORT);
    let failure = dispatch(&scene.workspace, &broker, &tasks, &request).unwrap_err();
    assert_eq!(failure.code, FailureCode::TargetStale);
    assert_eq!(state(&tasks, &task), "proposed");
    assert_eq!(scene.tree(), before, "neither report was written");
}

#[test]
fn f4_a_task_evicted_during_the_prompt_writes_nothing() {
    let scene = Scene::new("evicted");
    let before = scene.tree();
    let tasks = Arc::new(TaskRegistry::new());
    let task = proposed_task(&scene, &tasks);
    let (during, id) = (Arc::clone(&tasks), task.clone());
    let broker = consent_during(&scene, ApprovalDecision::Approved, move || {
        during.lock().retain(|candidate| candidate.id != id);
    });
    let request = commit_request(&task, "q3.md", STOP_REPORT);
    let failure = dispatch(&scene.workspace, &broker, &tasks, &request).unwrap_err();
    assert_eq!(failure.code, FailureCode::TargetStale);
    assert_eq!(scene.tree(), before, "nothing was written");
}

#[test]
fn f4_a_stop_during_the_prompt_abandons_the_intent_and_is_journaled() {
    let scene = Scene::new("stop-restart");
    let path = scene.dir.join("report-tasks.jsonl");
    let tasks = Arc::new(TaskRegistry::with_journal(path.clone()));
    let task = proposed_task(&scene, &tasks);
    let (during, id) = (Arc::clone(&tasks), task.clone());
    let broker = consent_during(&scene, ApprovalDecision::Approved, move || {
        during.stop(&id, "default").expect("stop during the prompt");
    });
    let request = commit_request(&task, "q3.md", STOP_REPORT);
    dispatch(&scene.workspace, &broker, &tasks, &request).unwrap_err();
    let journal = std::fs::read_to_string(&path).expect("journal");
    let lines: Vec<Value> = journal
        .lines()
        .map(|line| serde_json::from_str(line).expect("a journal line"))
        .collect();
    let closed: Vec<&Value> = lines
        .iter()
        .filter(|line| line["event"] == "abandoned")
        .collect();
    assert_eq!(closed.len(), 1, "one intent, closed once:\n{journal}");
    assert_eq!(closed[0]["outcome"], "stopped", "{journal}");
    assert!(
        !lines.iter().any(|line| line["event"] == "dispatched"),
        "the write never started:\n{journal}"
    );
    let newest = lines
        .iter()
        .rev()
        .find(|line| line["event"] == "task")
        .unwrap();
    assert_eq!(newest["task"]["state"], "stopped", "{journal}");
}

/// Passes through to the real broker and keeps what it consumed.
struct Recording {
    inner: LocalApprovalBroker,
    seen: Mutex<Option<(orcel_approval::ApprovedToken, ConsumeExpectation)>>,
}

impl ApprovalBroker for Recording {
    fn request_token(
        &self,
        prompt: &ApprovalPrompt,
    ) -> Result<orcel_approval::ApprovedToken, orcel_approval::ApprovalError> {
        self.inner.request_token(prompt)
    }

    fn consume(
        &self,
        token: &orcel_approval::ApprovedToken,
        expected: &ConsumeExpectation,
        now_ms: u64,
    ) -> Result<(), orcel_approval::ApprovalError> {
        *self.seen.lock().unwrap() = Some((token.clone(), expected.clone()));
        self.inner.consume(token, expected, now_ms)
    }
}

/// A broker for requests that must never ask.
struct NeverAsked;

impl ApprovalBroker for NeverAsked {
    fn request_token(
        &self,
        _: &ApprovalPrompt,
    ) -> Result<orcel_approval::ApprovedToken, orcel_approval::ApprovalError> {
        panic!("this request must not prompt")
    }

    fn consume(
        &self,
        _: &orcel_approval::ApprovedToken,
        _: &ConsumeExpectation,
        _: u64,
    ) -> Result<(), orcel_approval::ApprovalError> {
        panic!("this request must not consume")
    }
}
