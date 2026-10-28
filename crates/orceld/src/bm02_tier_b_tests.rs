//! BM-02 Tier B (tests/benchmarks/ORCEL_EXECUTION_PLAN.md): mutating
//! benchmark tasks through orceld's own request entry (`handle_envelope`:
//! profile gate, policy, dispatch, audit) and the real approval broker over
//! its own ledger (nonce, expiry, single use). Only the SOFT consent, the
//! person answering the system dialog, is scripted; the report says so in
//! its planner version (`scripted-consent`). The shipped orceld has no
//! scripted consent: `orcel-approval/test-support` is a dev-dependency.
//!
//! Each episode: a fresh workspace built by the variant's setup; a
//! deterministic plan that observes and acts only through orceld; then an
//! independent check of the whole workspace against the expected tree, of
//! the approval prompts shown (one per approved mutation, none for a
//! refusal before approval), of the refusal the plan ended on, and of
//! orceld's audit (one record per call). Nothing outside the workspace may
//! change. Three episodes per variant; the per-case results are printed as
//! `BM02B-EVIDENCE` lines and, with `ORCEL_BM02B_REPORT`, written as an
//! `orcel-benchmark-report/1` report.

use super::*;
use orcel_approval::{ApprovalDecision, ApprovalPrompt, NoPresenceVerifier};
use std::collections::{BTreeMap, VecDeque};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use ApprovalDecision::{Approved, Denied};

static SEQUENCE: AtomicUsize = AtomicUsize::new(0);
const EPISODES: usize = 3;

type Tree = BTreeMap<String, Vec<u8>>;

/// One episode's private orceld: policy, audit and workspace set over a
/// fresh workspace, as `run` builds them.
struct Bench {
    dir: PathBuf,
    root: PathBuf,
    policy: PolicyEngine,
    audit: AuditLogger,
    workspaces: remote_lease::WorkspaceSet,
}

impl Bench {
    fn new() -> Self {
        // orceld refuses state that another account can reach; a machine
        // whose temp folder is like that names a private parent.
        let parent = std::env::var_os("ORCEL_BM02_STATE_PARENT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let dir = parent.join(format!(
            "orcel-bm02b-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("workspace")).expect("workspace");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let root = std::fs::canonicalize(dir.join("workspace")).expect("canonical");
        let policy = PolicyEngine::new(vec![Workspace {
            id: "default".into(),
            root: root.clone(),
        }])
        .expect("policy");
        let audit = AuditLogger::new(dir.join("audit.jsonl")).expect("audit");
        let workspaces =
            remote_lease::WorkspaceSet::from_pairs(&[("default".into(), root.clone())]);
        Self {
            dir,
            root,
            policy,
            audit,
            workspaces,
        }
    }

    fn audit_records(&self) -> usize {
        std::fs::read_to_string(self.dir.join("audit.jsonl"))
            .map(|text| text.lines().count())
            .unwrap_or(0)
    }

    /// Everything in the episode directory outside the workspace.
    fn outside(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name != "workspace")
            .collect();
        names.sort();
        names
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn tree(root: &Path) -> Tree {
    fn walk(root: &Path, dir: &Path, out: &mut Tree) {
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
    let mut out = Tree::new();
    walk(root, root, &mut out);
    out
}

fn put(root: &Path, relative: &str, text: &str) {
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn sha256(text: &str) -> String {
    hex_lower(&Sha256::digest(text.as_bytes()))
}

/// What a plan holds: orceld's request entry with the episode's broker,
/// and a log of its calls (capability, operation, outcome, latency).
struct Agent<'a> {
    bench: &'a Bench,
    broker: &'a LocalApprovalBroker,
    calls: Vec<(String, bool, f64)>,
    /// For the stale-target variants only: another actor's edit, made
    /// between the plan's observation and its mutation.
    external: Option<fn(&Path)>,
}

impl Agent<'_> {
    fn call(
        &mut self,
        capability: &str,
        operation: &str,
        target: &str,
        arguments: Value,
    ) -> Result<Value, String> {
        let started = Instant::now();
        let response = handle_envelope(
            &self.bench.policy,
            &self.bench.audit,
            self.broker,
            &self.bench.workspaces,
            RemoteRequestEnvelope {
                request: RequestEnvelope {
                    version: INTERNAL_PROTOCOL_VERSION,
                    request_id: format!("bm02b-{}", self.calls.len() + 1),
                    client_session_id: "bm02b".into(),
                    workspace_id: "default".into(),
                    capability: capability.into(),
                    operation: operation.into(),
                    target: Some(target.into()),
                    arguments,
                },
                remote: None,
                profile: None,
            },
        );
        let millis = started.elapsed().as_secs_f64() * 1000.0;
        self.calls
            .push((format!("{capability}/{operation}"), response.ok, millis));
        if response.ok {
            Ok(response.result.unwrap_or(Value::Null))
        } else {
            let code = response.error.map(|e| e.code).expect("a failure");
            Err(serde_json::to_value(code)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_else(|| "UNKNOWN".into()))
        }
    }

    fn external_change(&self) {
        if let Some(change) = self.external {
            change(&self.bench.root);
        }
    }

    // The deterministic planner's moves, each built from what orceld
    // returned.

    /// Create or replace `target` with `content`, through preview and the
    /// approved write.
    fn write(&mut self, target: &str, content: &str) -> Result<(), String> {
        let preview = self.call("fs.write", "preview", target, json!({ "content": content }))?;
        self.external_change();
        let mut arguments = json!({ "content": content });
        match preview["current_sha256"].as_str() {
            Some(current) => arguments["expected_current_sha256"] = json!(current),
            None => arguments["create_if_missing"] = json!(true),
        }
        self.call("fs.write", "write", target, arguments).map(drop)
    }

    fn names(&mut self, folder: &str) -> Result<Vec<String>, String> {
        let listed = self.call("fs.list", "list", folder, json!({}))?;
        Ok(listed["entries"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|entry| entry["name"].as_str().map(str::to_owned))
            .collect())
    }

    fn edit(&mut self, target: &str, old: &str, new: &str) -> Result<(), String> {
        let text = self.call("fs.read", "read", target, json!({}))?["text"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        self.external_change();
        self.call(
            "fs.edit",
            "edit",
            target,
            json!({ "old": old, "new": new, "expected_sha256": sha256(&text) }),
        )
        .map(drop)
    }
}

struct Variant {
    case: &'static str,
    setup: fn(&Path),
    /// The scripted answers to the prompts, in order; an unscripted prompt
    /// is denied and fails the episode.
    consent: &'static [ApprovalDecision],
    plan: fn(&mut Agent) -> Result<(), String>,
    /// The refusal the plan must end on (orceld's own code), if any.
    refusal: Option<&'static str>,
    /// The tree after setup, changed as the task requires.
    expect: fn(&mut Tree),
    external: Option<fn(&Path)>,
}

const CONFIG: &str = "# app settings\nport = 8417\nmode = offline\n";

fn nothing(_: &Path) {}
fn unchanged(_: &mut Tree) {}
fn file(tree: &mut Tree, relative: &str, text: &str) {
    tree.insert(relative.into(), text.as_bytes().to_vec());
}

fn reports(root: &Path) {
    put(root, "reports/q3-draft.md", "# Q3\n");
    put(root, "reports/q2-final.md", "# Q2\n");
}

fn variants() -> Vec<Variant> {
    vec![
        // Create a new file.
        Variant {
            case: "orcel-write/hello-file/greeting",
            setup: nothing,
            consent: &[Approved],
            plan: |a| a.write("hello.txt", "Hello from Orcel\n"),
            refusal: None,
            expect: |t| file(t, "hello.txt", "Hello from Orcel\n"),
            external: None,
        },
        Variant {
            case: "orcel-write/hello-file/notes",
            setup: nothing,
            consent: &[Approved],
            plan: |a| a.write("notes.md", "# Notes\n\n- first\n"),
            refusal: None,
            expect: |t| file(t, "notes.md", "# Notes\n\n- first\n"),
            external: None,
        },
        Variant {
            case: "orcel-write/hello-file/nested",
            setup: |r| std::fs::create_dir_all(r.join("docs")).unwrap(),
            consent: &[Approved],
            plan: |a| a.write("docs/readme.txt", "docs\n"),
            refusal: None,
            expect: |t| file(t, "docs/readme.txt", "docs\n"),
            external: None,
        },
        // Replace a file the plan observed first.
        Variant {
            case: "orcel-write/overwrite/small",
            setup: |r| put(r, "todo.txt", "old\n"),
            consent: &[Approved],
            plan: |a| a.write("todo.txt", "new\n"),
            refusal: None,
            expect: |t| file(t, "todo.txt", "new\n"),
            external: None,
        },
        Variant {
            case: "orcel-write/overwrite/multiline",
            setup: |r| put(r, "log/summary.txt", "a\nb\n"),
            consent: &[Approved],
            plan: |a| a.write("log/summary.txt", "a\nb\nc\n"),
            refusal: None,
            expect: |t| file(t, "log/summary.txt", "a\nb\nc\n"),
            external: None,
        },
        // Find the draft report and finalize it by renaming.
        Variant {
            case: "orcel-write/report-rename/draft-to-final",
            setup: reports,
            consent: &[Approved],
            plan: |a| {
                let draft = a
                    .names("reports")?
                    .into_iter()
                    .find(|n| n.ends_with("-draft.md"))
                    .ok_or("NO_DRAFT")?;
                let to = format!("reports/{}", draft.replace("-draft.md", "-final.md"));
                a.call(
                    "fs.move",
                    "move",
                    &format!("reports/{draft}"),
                    json!({ "to": to }),
                )
                .map(drop)
            },
            refusal: None,
            expect: |t| {
                let bytes = t.remove("reports/q3-draft.md").unwrap();
                t.insert("reports/q3-final.md".into(), bytes);
            },
            external: None,
        },
        Variant {
            case: "orcel-write/report-rename/into-archive",
            setup: |r| {
                reports(r);
                std::fs::create_dir_all(r.join("archive")).unwrap();
            },
            consent: &[Approved],
            plan: |a| {
                let finals: Vec<String> = a
                    .names("reports")?
                    .into_iter()
                    .filter(|n| n.ends_with("-final.md"))
                    .collect();
                for name in finals {
                    a.call(
                        "fs.move",
                        "move",
                        &format!("reports/{name}"),
                        json!({ "to": format!("archive/{name}") }),
                    )?;
                }
                Ok(())
            },
            refusal: None,
            expect: |t| {
                let bytes = t.remove("reports/q2-final.md").unwrap();
                t.insert("archive/q2-final.md".into(), bytes);
            },
            external: None,
        },
        Variant {
            case: "orcel-write/report-rename/two-drafts",
            setup: |r| {
                put(r, "reports/a-draft.md", "A\n");
                put(r, "reports/b-draft.md", "B\n");
            },
            consent: &[Approved, Approved],
            plan: |a| {
                let drafts: Vec<String> = a
                    .names("reports")?
                    .into_iter()
                    .filter(|n| n.ends_with("-draft.md"))
                    .collect();
                for name in drafts {
                    a.call(
                        "fs.move",
                        "move",
                        &format!("reports/{name}"),
                        json!({ "to": format!("reports/{}", name.replace("-draft", "-final")) }),
                    )?;
                }
                Ok(())
            },
            refusal: None,
            expect: |t| {
                for x in ["a", "b"] {
                    let bytes = t.remove(&format!("reports/{x}-draft.md")).unwrap();
                    t.insert(format!("reports/{x}-final.md"), bytes);
                }
            },
            external: None,
        },
        // Make folders.
        Variant {
            case: "orcel-write/mkdir/single",
            setup: nothing,
            consent: &[Approved],
            plan: |a| a.call("fs.mkdir", "mkdir", "out", json!({})).map(drop),
            refusal: None,
            expect: |t| {
                t.insert("out/".into(), Vec::new());
            },
            external: None,
        },
        Variant {
            case: "orcel-write/mkdir/parents",
            setup: nothing,
            consent: &[Approved],
            plan: |a| {
                a.call(
                    "fs.mkdir",
                    "mkdir",
                    "out/2026/q3",
                    json!({ "parents": true }),
                )
                .map(drop)
            },
            refusal: None,
            expect: |t| {
                for dir in ["out/", "out/2026/", "out/2026/q3/"] {
                    t.insert(dir.into(), Vec::new());
                }
            },
            external: None,
        },
        // Change one setting in place.
        Variant {
            case: "orcel-write/edit-config/port",
            setup: |r| put(r, "config/app.ini", CONFIG),
            consent: &[Approved],
            plan: |a| a.edit("config/app.ini", "port = 8417", "port = 9000"),
            refusal: None,
            expect: |t| {
                file(
                    t,
                    "config/app.ini",
                    &CONFIG.replace("port = 8417", "port = 9000"),
                )
            },
            external: None,
        },
        Variant {
            case: "orcel-write/edit-config/mode",
            setup: |r| put(r, "config/app.ini", CONFIG),
            consent: &[Approved],
            plan: |a| a.edit("config/app.ini", "mode = offline", "mode = online"),
            refusal: None,
            expect: |t| {
                file(
                    t,
                    "config/app.ini",
                    &CONFIG.replace("mode = offline", "mode = online"),
                )
            },
            external: None,
        },
        // Removing a file is a STRONG operation: it needs platform user
        // presence (Windows Hello, Touch ID, polkit), which no test can
        // supply honestly. Without it orceld refuses before any prompt and
        // nothing changes; a solved removal needs the founder's machine.
        Variant {
            case: "orcel-write/remove-needs-presence/one",
            setup: |r| {
                put(r, "tmp/build.tmp", "x");
                put(r, "tmp/keep.txt", "k");
            },
            consent: &[],
            plan: remove_temp,
            refusal: Some("APPROVAL_UNAVAILABLE"),
            expect: unchanged,
            external: None,
        },
        Variant {
            case: "orcel-write/remove-needs-presence/two",
            setup: |r| {
                put(r, "tmp/a.tmp", "a");
                put(r, "tmp/b.tmp", "b");
            },
            consent: &[],
            plan: remove_temp,
            refusal: Some("APPROVAL_UNAVAILABLE"),
            expect: unchanged,
            external: None,
        },
        // The person says no: orceld refuses and nothing changes.
        Variant {
            case: "orcel-write/denied/write",
            setup: nothing,
            consent: &[Denied],
            plan: |a| a.write("hello.txt", "Hello\n"),
            refusal: Some("APPROVAL_DENIED"),
            expect: unchanged,
            external: None,
        },
        Variant {
            case: "orcel-write/denied/move",
            setup: reports,
            consent: &[Denied],
            plan: |a| {
                a.call(
                    "fs.move",
                    "move",
                    "reports/q3-draft.md",
                    json!({ "to": "reports/q3-final.md" }),
                )
                .map(drop)
            },
            refusal: Some("APPROVAL_DENIED"),
            expect: unchanged,
            external: None,
        },
        Variant {
            case: "orcel-write/denied/edit",
            setup: |r| put(r, "config/app.ini", CONFIG),
            consent: &[Denied],
            plan: |a| a.edit("config/app.ini", "port = 8417", "port = 9000"),
            refusal: Some("APPROVAL_DENIED"),
            expect: unchanged,
            external: None,
        },
        // Another actor changes the file after the plan observed it:
        // orceld refuses before asking, and the other actor's edit stands.
        Variant {
            case: "orcel-write/stale-target/write",
            setup: |r| put(r, "todo.txt", "old\n"),
            consent: &[],
            plan: |a| a.write("todo.txt", "new\n"),
            refusal: Some("TARGET_STALE"),
            expect: |t| file(t, "todo.txt", "theirs\n"),
            external: Some(|r| put(r, "todo.txt", "theirs\n")),
        },
        Variant {
            case: "orcel-write/stale-target/edit",
            setup: |r| put(r, "config/app.ini", CONFIG),
            consent: &[],
            plan: |a| a.edit("config/app.ini", "port = 8417", "port = 9000"),
            refusal: Some("TARGET_STALE"),
            expect: |t| file(t, "config/app.ini", &format!("{CONFIG}owner = ops\n")),
            external: Some(|r| put(r, "config/app.ini", &format!("{CONFIG}owner = ops\n"))),
        },
        // A write outside the workspace is refused before any prompt.
        Variant {
            case: "orcel-write/escape-refused/parent",
            setup: nothing,
            consent: &[],
            plan: |a| a.write("../outside.txt", "x"),
            refusal: Some("PATH_ESCAPE"),
            expect: unchanged,
            external: None,
        },
        Variant {
            case: "orcel-write/escape-refused/nested-parent",
            setup: |r| std::fs::create_dir_all(r.join("docs")).unwrap(),
            consent: &[],
            plan: |a| a.write("docs/../../outside.txt", "x"),
            refusal: Some("PATH_ESCAPE"),
            expect: unchanged,
            external: None,
        },
    ]
}

fn remove_temp(a: &mut Agent) -> Result<(), String> {
    let temps: Vec<String> = a
        .names("tmp")?
        .into_iter()
        .filter(|n| n.ends_with(".tmp"))
        .collect();
    for name in temps {
        a.call("fs.remove", "remove", &format!("tmp/{name}"), json!({}))?;
    }
    Ok(())
}

struct Episode {
    observed: &'static str,
    millis: f64,
    calls: usize,
}

fn episode(variant: &Variant) -> Episode {
    let bench = Bench::new();
    (variant.setup)(&bench.root);
    let before = tree(&bench.root);
    let script = Arc::new(Mutex::new(
        variant.consent.iter().copied().collect::<VecDeque<_>>(),
    ));
    let shown: Arc<Mutex<Vec<ApprovalPrompt>>> = Arc::new(Mutex::new(Vec::new()));
    let unscripted = Arc::new(AtomicUsize::new(0));
    let broker = {
        let (script, shown, unscripted) = (script.clone(), shown.clone(), unscripted.clone());
        LocalApprovalBroker::with_path_and_soft_decider(
            bench.dir.join("approvals.json"),
            Arc::new(NoPresenceVerifier),
            Arc::new(move |prompt: &ApprovalPrompt| {
                shown.lock().unwrap().push(prompt.clone());
                script.lock().unwrap().pop_front().unwrap_or_else(|| {
                    unscripted.fetch_add(1, Ordering::SeqCst);
                    Denied
                })
            }),
        )
    };
    let mut agent = Agent {
        bench: &bench,
        broker: &broker,
        calls: Vec::new(),
        external: variant.external,
    };
    let started = Instant::now();
    let ended = (variant.plan)(&mut agent);
    let millis = started.elapsed().as_secs_f64() * 1000.0;
    let calls = agent.calls.len();

    let mut expected = before;
    (variant.expect)(&mut expected);
    let prompts = shown.lock().unwrap().clone();
    let observed = if ended.as_ref().err().map(String::as_str) != variant.refusal {
        "unexpected-outcome"
    } else if tree(&bench.root) != expected {
        "workspace-wrong"
    } else if unscripted.load(Ordering::SeqCst) > 0
        || !script.lock().unwrap().is_empty()
        || prompts.len() != variant.consent.len()
    {
        "prompts-wrong"
    } else if prompts.iter().any(|p| {
        p.workspace_id != "default" || p.target.starts_with('/') || p.target.contains("..")
    }) {
        "prompt-target-wrong"
    } else if calls == 0 || bench.audit_records() < calls {
        "unaudited"
    } else if !bench.outside().iter().all(|name| {
        ["approvals.json", "approvals.json.lock", "audit.jsonl"].contains(&name.as_str())
    }) {
        "outside-changed"
    } else if variant.refusal.is_some() {
        "refused-as-expected"
    } else {
        "solved"
    };
    Episode {
        observed,
        millis,
        calls,
    }
}

fn percentile(sorted: &[f64], q: f64) -> f64 {
    let index = ((sorted.len() as f64 - 1.0) * q).round() as usize;
    (sorted[index] * 1000.0).round() / 1000.0
}

#[test]
fn bm02_tier_b_mutating_tasks_are_solved_through_orceld_with_scripted_consent() {
    let variants = variants();
    assert!(variants.len() >= 20, "{} variants", variants.len());
    let mut rows = Vec::new();
    let mut failed = Vec::new();
    for variant in &variants {
        let episodes: Vec<Episode> = (0..EPISODES).map(|_| episode(variant)).collect();
        let bad = episodes
            .iter()
            .find(|e| e.observed != "solved" && e.observed != "refused-as-expected");
        let observed = bad.unwrap_or(&episodes[0]).observed;
        let mut millis: Vec<f64> = episodes.iter().map(|e| e.millis).collect();
        millis.sort_by(f64::total_cmp);
        let steps = episodes.iter().map(|e| e.calls).max().unwrap_or(0);
        let status = if bad.is_some() { "fail" } else { "pass" };
        eprintln!(
            "BM02B-EVIDENCE {} {status} {observed} steps={steps} p50={}ms p95={}ms",
            variant.case,
            percentile(&millis, 0.5),
            percentile(&millis, 0.95)
        );
        if bad.is_some() {
            failed.push(variant.case);
        }
        rows.push(json!({
            "case": variant.case,
            "status": status,
            "observed": observed,
            "latency_ms": {"p50": percentile(&millis, 0.5), "p95": percentile(&millis, 0.95)},
            "steps": steps,
            "model_calls": 0,
            "tokens_in": 0,
            "tokens_out": 0,
        }));
    }
    if let Some(path) = std::env::var_os("ORCEL_BM02B_REPORT") {
        let commit = std::env::var("ORCEL_BM02_COMMIT")
            .or_else(|_| std::env::var("GITHUB_SHA"))
            .ok()
            .filter(|sha| sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_hexdigit()))
            .map(|sha| sha.to_ascii_lowercase())
            .unwrap_or_else(|| "0".repeat(40));
        let os = match std::env::consts::OS {
            "windows" => "windows",
            "macos" => "macos",
            _ => "linux",
        };
        let arch = if std::env::consts::ARCH == "aarch64" {
            "arm64"
        } else {
            "x86_64"
        };
        let report = json!({
            "schema": "orcel-benchmark-report/1",
            "orcel_commit": commit,
            "suite": "journeys",
            "machine": {"os": os, "os_version": "unrecorded", "arch": arch},
            "planner": {
                "kind": "deterministic",
                "name": "orcel-fs-mutation-planner",
                "version": "1-scripted-consent"
            },
            "rows": rows,
        });
        std::fs::write(path, serde_json::to_string_pretty(&report).unwrap()).expect("report");
    }
    assert!(failed.is_empty(), "not solved: {failed:?}");
}
