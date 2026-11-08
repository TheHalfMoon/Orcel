//! SG-000127 slice 4: the kit around the one step only a person can do.
//!
//! One supported client runs the report journey against an installed orceld
//! over local stdio, and a person answers Orcel's local approval prompt. This
//! tool never approves anything and never talks to the client. Its one contact
//! with orceld is `ready` asking `orcel doctor`, which reads a status. It
//! prepares a scratch workspace, changes its source when the runbook says so,
//! and afterwards checks the evidence from orceld's own journal and the
//! workspace, and redacts the transcript with the product's redactor.
//!
//! ```text
//! cargo run -p orcel-lifecycle --example f4_journey -- prepare <dir>
//! cargo run -p orcel-lifecycle --example f4_journey -- ready <dir> [--release-candidate <folder>]
//! cargo run -p orcel-lifecycle --example f4_journey -- change-source <dir>
//! cargo run -p orcel-lifecycle --example f4_journey -- history <dir> [--journal <file>]
//! cargo run -p orcel-lifecycle --example f4_journey -- evidence <dir> \
//!     --client "Claude Code 2.x.y" --transcript <file> [--journal <file>]
//! ```
//!
//! Runbook: docs/orcel/implementation-readiness/prep/F4_SLICE4_CLIENT_JOURNEY.md

use orcel_lifecycle::logs::redact_line;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const SOURCE: &str =
    "region,quarter,revenue_cents\nnorth,Q3,1250000\nsouth,Q3,980050\neast,Q3,1500025\n";
const CHANGED_SOURCE: &str = "region,quarter,revenue_cents\nnorth,Q3,1\n";
const TAKEN: &str = "A file the user already has. Orcel must never overwrite it.\n";
/// What a client transcript must not carry: a tool result never contains an
/// approval, a token or a way to approve (SG-000127 acceptance 3).
const FORBIDDEN_IN_TRANSCRIPT: [&str; 3] = ["approval_id", "approval_token", "approve_url"];

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn prepare(dir: &Path) -> Result<(), String> {
    if dir.exists() && fs::read_dir(dir).map_err(text)?.next().is_some() {
        return Err(format!("{} is not empty; use a new folder", dir.display()));
    }
    fs::create_dir_all(dir.join("data")).map_err(text)?;
    fs::create_dir_all(dir.join("reports")).map_err(text)?;
    fs::write(dir.join("data").join("q3.csv"), SOURCE).map_err(text)?;
    fs::write(dir.join("reports").join("taken.md"), TAKEN).map_err(text)?;
    fs::write(
        dir.join(".mcp.json"),
        "{\n  \"mcpServers\": {\n    \"orcel\": { \"type\": \"stdio\", \"command\": \"orcel\", \"args\": [\"mcp\", \"stdio\"] }\n  }\n}\n",
    )
    .map_err(text)?;
    println!("Prepared {}", dir.display());
    println!("Next: orcel workspace add default \"{}\"", dir.display());
    println!("Then run `ready`, and follow prep/F4_SLICE4_CLIENT_JOURNEY.md.");
    Ok(())
}

/// What must hold before the client starts. `workspaces` is the output of
/// `orcel workspace list --json`, whose report is the configuration: a second
/// workspace or the wrong folder would send the journey somewhere else.
fn ready_checks(dir: &Path, workspaces: &str) -> Vec<Check> {
    let canonical = fs::canonicalize(dir).ok();
    let listed: Vec<PathBuf> = serde_json::from_str::<Value>(workspaces)
        .ok()
        .and_then(|value| value["workspaces"].as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|row| row["root"].as_str().map(PathBuf::from))
        .collect();
    let only_this =
        listed.len() == 1 && canonical.is_some() && fs::canonicalize(&listed[0]).ok() == canonical;
    let file = |parts: &[&str]| {
        let mut path = dir.to_owned();
        path.extend(parts);
        fs::read(path).unwrap_or_default()
    };
    vec![
        check(
            "the scratch folder is the only workspace",
            only_this.then(|| "one workspace, this folder".to_owned()),
            &format!("orcel lists {listed:?}; remove the others and restore them afterwards"),
        ),
        check(
            "the source is unchanged",
            (file(&["data", "q3.csv"]) == SOURCE.as_bytes()).then(|| "data/q3.csv".to_owned()),
            "data/q3.csv isn't the prepared one; prepare a new folder",
        ),
        check(
            "the existing file is in place",
            (file(&["reports", "taken.md"]) == TAKEN.as_bytes())
                .then(|| "reports/taken.md".to_owned()),
            "reports/taken.md isn't the prepared one; prepare a new folder",
        ),
        check(
            "the client's server entry is in place",
            (!file(&[".mcp.json"]).is_empty()).then(|| ".mcp.json".to_owned()),
            ".mcp.json is missing; prepare a new folder",
        ),
    ]
}

/// Whether `orceld` started and answered. `doctor` is the output of
/// `orcel doctor --json`. Listing workspaces doesn't need `orceld`, so without this
/// a machine whose state folder `orceld` refuses passes, and the journey first fails
/// at the report tools.
fn orceld_check(doctor: &str) -> Check {
    let report: Value = serde_json::from_str(doctor).unwrap_or(Value::Null);
    let ipc = report["doctor"]["checks"]
        .as_array()
        .and_then(|checks| checks.iter().find(|check| check["name"] == "ipc"));
    let detail = ipc
        .and_then(|ipc| ipc["detail"].as_str())
        .unwrap_or("no result");
    check(
        "orceld starts and answers",
        ipc.filter(|ipc| ipc["status"] == "pass")
            .map(|_| detail.to_owned()),
        &format!("{detail}; see \"If orceld won't start\" in the runbook"),
    )
}

/// Whether the downloaded release candidate is the one this kit or checkout builds: its
/// provenance names this commit, and its zip is the file the provenance hashed.
/// A journey run against another commit's build is evidence about neither.
fn release_checks(provenance: &str, head: &str, zips: &[(String, Vec<u8>)]) -> Vec<Check> {
    let record: Value = serde_json::from_str(provenance).unwrap_or(Value::Null);
    let revision = record["source"]["revision"].as_str().unwrap_or_default();
    let same_commit = !head.is_empty() && revision == head;
    let hashed = record["artifacts"].as_array();
    let intact = !zips.is_empty()
        && zips.iter().all(|(name, bytes)| {
            let digest = sha256(bytes);
            hashed.is_some_and(|artifacts| {
                artifacts.iter().any(|artifact| {
                    artifact["name"] == name.as_str() && artifact["sha256"] == digest.as_str()
                })
            })
        });
    vec![
        check(
            "the release candidate was built from this commit",
            same_commit.then(|| format!("both at {head}")),
            &format!("its provenance says {revision:?}, this kit expects {head:?}"),
        ),
        check(
            "the release candidate's zip matches its provenance",
            intact.then(|| format!("{} file checked", zips.len())),
            "the zip is missing or its SHA-256 differs from the provenance",
        ),
    ]
}

fn release_candidate(folder: &Path) -> Result<Vec<Check>, String> {
    let mut provenance = None;
    let mut zips = Vec::new();
    for entry in fs::read_dir(folder).map_err(text)? {
        let path = entry.map_err(text)?.path();
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        if name.ends_with(".provenance.json") {
            provenance = Some(fs::read_to_string(&path).map_err(text)?);
        } else if name.ends_with(".zip") {
            zips.push((name, fs::read(&path).map_err(text)?));
        }
    }
    let provenance = provenance.ok_or_else(|| format!("no provenance in {}", folder.display()))?;
    // CI's kit knows the commit it was built from. A kit built by hand asks the checkout.
    let head = match option_env!("ORCEL_F4_KIT_COMMIT") {
        Some(commit) => commit.to_owned(),
        None => {
            let head = std::process::Command::new("git")
                .args(["rev-parse", "HEAD"])
                .output()
                .map_err(|error| format!("git didn't run ({error}); run this from the checkout"))?;
            String::from_utf8_lossy(&head.stdout).trim().to_owned()
        }
    };
    Ok(release_checks(&provenance, &head, &zips))
}

/// Reads the configuration through the installed `orcel`, and asks `orcel doctor`
/// whether `orceld` answers, which starts it for a moment. Approves nothing and starts
/// no client.
fn ready(dir: &Path, candidate: Option<&Path>) -> Result<bool, String> {
    let orcel = |args: &[&str]| {
        std::process::Command::new("orcel")
            .args(args)
            .output()
            .map_err(|error| {
                format!("`orcel` didn't run ({error}); open a new terminal after install")
            })
    };
    let version = orcel(&["version"])?;
    println!(
        "Installed: {}",
        String::from_utf8_lossy(&version.stdout).trim()
    );
    let listed = orcel(&["workspace", "list", "--json"])?;
    let mut results = ready_checks(dir, &String::from_utf8_lossy(&listed.stdout));
    let doctor = orcel(&["doctor", "--json"])?;
    results.push(orceld_check(&String::from_utf8_lossy(&doctor.stdout)));
    if let Some(folder) = candidate {
        results.extend(release_candidate(folder)?);
    }
    for result in &results {
        println!(
            "{} {}: {}",
            if result.passed { "PASS" } else { "FAIL" },
            result.name,
            result.detail
        );
    }
    Ok(results.iter().all(|result| result.passed))
}

fn change_source(dir: &Path) -> Result<(), String> {
    fs::write(dir.join("data").join("q3.csv"), CHANGED_SOURCE).map_err(text)?;
    println!("Changed data/q3.csv. Now ask the client to commit the stale report.");
    Ok(())
}

fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}

/// The newest snapshot of every task in the journal, by task id.
fn tasks_in(journal: &str) -> BTreeMap<String, Value> {
    let mut tasks = BTreeMap::new();
    for line in journal.lines() {
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue; // a torn line left by a crash
        };
        if value["event"] == "task" {
            if let Some(id) = value["task"]["id"].as_str() {
                let mut task = value["task"].clone();
                task["owner"] = value["owner"].clone();
                tasks.insert(id.to_owned(), task);
            }
        }
    }
    tasks
}

fn has_step(task: &Value, kind: &str, outcome: &str) -> bool {
    task["steps"].as_array().is_some_and(|steps| {
        steps
            .iter()
            .any(|step| step["kind"] == kind && step["outcome"] == outcome)
    })
}

/// One line per required path of the journey.
#[derive(Debug, PartialEq, Eq)]
struct Check {
    name: &'static str,
    passed: bool,
    detail: String,
}

fn check(name: &'static str, found: Option<String>, missing: &str) -> Check {
    Check {
        name,
        passed: found.is_some(),
        detail: found.unwrap_or_else(|| missing.to_owned()),
    }
}

/// Every check the evidence must pass. Reads the journal text and the
/// workspace; `tasks` are only those of this journey's folder.
fn checks(dir: &Path, tasks: &[&Value], transcript: &str) -> Vec<Check> {
    let verified = tasks.iter().find_map(|task| {
        if task["state"] != "verified" || task["check"]["passed"] != true {
            return None;
        }
        let name = task["report"]["name"].as_str()?;
        let bytes = fs::read(dir.join("reports").join(name)).ok()?;
        (sha256(&bytes) == task["report"]["sha256"].as_str()?).then(|| {
            format!(
                "{}: {name} verified by the independent checker, SHA-256 matches on disk",
                task["id"].as_str().unwrap_or_default()
            )
        })
    });
    // A denial retried to a Yes, as the runbook allows at B, isn't the denied path.
    let denied = tasks
        .iter()
        .find(|task| task["state"] == "approval_denied" && has_step(task, "approval", "denied"))
        .and_then(|task| task["id"].as_str().map(str::to_owned));
    let by_step = |kind: &str, outcome: &str| {
        tasks
            .iter()
            .find(|task| has_step(task, kind, outcome))
            .and_then(|task| task["id"].as_str().map(str::to_owned))
    };
    // Left mid-task by the orceld that died, then read back by the client, and a later
    // orceld started a task: a new orceld writes no line until it has one. The summary's
    // own fields must follow the tool's name, since the prompt names the tool too.
    let lowered = transcript.to_lowercase();
    let read_back = lowered
        .find("task_resume_summary")
        .map_or("", |at| &lowered[at..]);
    let recovered = tasks.iter().find_map(|task| {
        let id = task["id"].as_str()?;
        let cut_off = has_step(task, "preview", "ok")
            && !task["steps"]
                .as_array()?
                .iter()
                .any(|step| step["kind"] == "commit" || step["kind"] == "approval");
        let ended = task["updated_at_ms"].as_u64()?;
        let later_orceld = tasks.iter().any(|other| {
            other["owner"] != task["owner"]
                && other["created_at_ms"]
                    .as_u64()
                    .is_some_and(|at| at >= ended)
        });
        (cut_off
            && later_orceld
            && read_back.contains(id)
            && ["completed", "unknown", "observe", "preview"]
                .iter()
                .all(|field| read_back.contains(field)))
        .then(|| format!("{id}: cut off after its preview, and read back by the client"))
    });
    let taken = fs::read(dir.join("reports").join("taken.md")).unwrap_or_default();
    let forbidden: Vec<&str> = FORBIDDEN_IN_TRANSCRIPT
        .into_iter()
        .filter(|word| transcript.contains(word))
        .collect();
    vec![
        check(
            "approved report written and verified",
            verified,
            "no verified task whose report matches the file on disk",
        ),
        check(
            "denied approval refused",
            denied,
            "no task recorded a denied approval",
        ),
        check(
            "changed source refused as stale",
            by_step("commit", "stale").or_else(|| by_step("preview", "stale")),
            "no task recorded a stale source",
        ),
        check(
            "existing destination refused",
            by_step("preview", "destination_exists")
                .or_else(|| by_step("commit", "destination_exists")),
            "no task recorded an existing destination",
        ),
        check(
            "an interrupted task read back after orceld died",
            recovered,
            "no task cut off after its preview, read back in the transcript, with a later orceld's task after it",
        ),
        check(
            "the user's existing file is untouched",
            (taken == TAKEN.as_bytes()).then(|| "reports/taken.md is byte-identical".to_owned()),
            "reports/taken.md changed",
        ),
        check(
            "no approval material in the transcript",
            forbidden.is_empty().then(|| "none found".to_owned()),
            &format!("found: {forbidden:?}"),
        ),
        check(
            "the transcript is not empty",
            (!transcript.trim().is_empty())
                .then(|| format!("{} lines", transcript.lines().count())),
            "empty transcript",
        ),
    ]
}

fn redacted(transcript: &str) -> String {
    let mut out = String::new();
    for line in transcript.lines() {
        out.push_str(&redact_line(line));
        out.push('\n');
    }
    out
}

fn default_journal() -> Option<PathBuf> {
    let root = std::env::var_os("USERPROFILE")?;
    Some(
        PathBuf::from(root)
            .join(".orcel")
            .join("report-tasks.jsonl"),
    )
}

/// Whether the task's folder is inside this journey's scratch workspace.
fn in_journey(task: &Value, canonical: &Path) -> bool {
    task["folder_canonical"]
        .as_str()
        .is_some_and(|folder| Path::new(folder).starts_with(canonical))
}

/// The observable history: each task's steps and outcomes from orceld's own journal.
/// The journal holds no file contents, and this keeps no source or report text either.
fn history_of(tasks: &[&Value]) -> Value {
    let mut ordered: Vec<&&Value> = tasks.iter().collect();
    ordered.sort_by_key(|task| task["created_at_ms"].as_u64().unwrap_or(0));
    Value::Array(
        ordered
            .iter()
            .map(|task| {
                json!({
                    "id": task["id"],
                    "state": task["state"],
                    "report": task["report"]["name"],
                    "steps": task["steps"].as_array().map(|steps| steps.iter().map(|step| json!({
                        "kind": step["kind"],
                        "outcome": step["outcome"],
                        "at_ms": step["at_ms"],
                    })).collect::<Vec<_>>()).unwrap_or_default(),
                })
            })
            .collect(),
    )
}

fn journey_tasks(dir: &Path, journal: &Path) -> Result<BTreeMap<String, Value>, String> {
    let canonical = fs::canonicalize(dir).map_err(text)?;
    let journal_text = fs::read_to_string(journal)
        .map_err(|error| format!("the journal {}: {error}", journal.display()))?;
    let mut all = tasks_in(&journal_text);
    all.retain(|_, task| in_journey(task, &canonical));
    Ok(all)
}

fn history(dir: &Path, journal: &Path) -> Result<bool, String> {
    let all = journey_tasks(dir, journal)?;
    let tasks: Vec<&Value> = all.values().collect();
    for task in history_of(&tasks).as_array().into_iter().flatten() {
        println!(
            "{} {}",
            task["id"].as_str().unwrap_or("?"),
            task["state"].as_str().unwrap_or("?")
        );
        for step in task["steps"].as_array().into_iter().flatten() {
            println!(
                "    {} {}",
                step["kind"].as_str().unwrap_or("?"),
                step["outcome"].as_str().unwrap_or("?")
            );
        }
    }
    Ok(!tasks.is_empty())
}

fn evidence(dir: &Path, client: &str, transcript: &Path, journal: &Path) -> Result<bool, String> {
    let all = journey_tasks(dir, journal)?;
    let transcript_text = fs::read_to_string(transcript)
        .map_err(|error| format!("the transcript {}: {error}", transcript.display()))?;
    let tasks: Vec<&Value> = all.values().collect();
    let results = checks(dir, &tasks, &transcript_text);
    let passed = results.iter().all(|result| result.passed);
    for result in &results {
        println!(
            "{} {}: {}",
            if result.passed { "PASS" } else { "FAIL" },
            result.name,
            result.detail
        );
    }
    let out = dir.join("evidence");
    fs::create_dir_all(&out).map_err(text)?;
    fs::write(
        out.join("transcript.redacted.txt"),
        redacted(&transcript_text),
    )
    .map_err(text)?;
    fs::write(
        out.join("history.json"),
        serde_json::to_string_pretty(&history_of(&tasks)).map_err(text)?,
    )
    .map_err(text)?;
    let summary = json!({
        "schema": "orcel-f4-slice4-evidence/1",
        "client": client,
        "passed": passed,
        "tasks": tasks.iter().map(|task| json!({"id": task["id"], "state": task["state"]})).collect::<Vec<_>>(),
        "checks": results.iter().map(|result| json!({"name": result.name, "passed": result.passed, "detail": result.detail})).collect::<Vec<_>>(),
        "scope": "This client version only, not every client. A person answered the approval prompts; this tool approves nothing.",
    });
    fs::write(
        out.join("summary.json"),
        serde_json::to_string_pretty(&summary).map_err(text)?,
    )
    .map_err(text)?;
    println!("Evidence written to {}", out.display());
    Ok(passed)
}

fn value_of(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|arg| arg == flag)
        .and_then(|at| args.get(at + 1))
        .cloned()
}

fn run(args: &[String]) -> Result<bool, String> {
    let usage = "usage: f4_journey prepare <dir> | ready <dir> [--release-candidate <folder>] | change-source <dir> | history <dir> [--journal <file>] | evidence <dir> --client <name version> --transcript <file> [--journal <file>]";
    let (Some(command), Some(dir)) = (args.first(), args.get(1)) else {
        return Err(usage.to_owned());
    };
    let dir = Path::new(dir);
    match command.as_str() {
        "prepare" => prepare(dir).map(|()| true),
        "ready" => {
            let candidate = value_of(args, "--release-candidate").map(PathBuf::from);
            ready(dir, candidate.as_deref())
        }
        "change-source" => change_source(dir).map(|()| true),
        "history" => {
            let journal = value_of(args, "--journal")
                .map(PathBuf::from)
                .or_else(default_journal)
                .ok_or("name the journal with --journal")?;
            history(dir, &journal)
        }
        "evidence" => {
            let client = value_of(args, "--client").ok_or(usage)?;
            let transcript = value_of(args, "--transcript").ok_or(usage)?;
            let journal = value_of(args, "--journal")
                .map(PathBuf::from)
                .or_else(default_journal)
                .ok_or("name the journal with --journal")?;
            evidence(dir, &client, Path::new(&transcript), &journal)
        }
        _ => Err(usage.to_owned()),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("orcel-f4-kit-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn task(id: &str, state: &str, steps: &[(&str, &str)], report: Value) -> Value {
        json!({
            "id": id,
            "state": state,
            "steps": steps.iter().map(|(kind, outcome)| json!({"kind": kind, "outcome": outcome})).collect::<Vec<_>>(),
            "report": report,
            "check": {"passed": state == "verified"},
            "owner": {"run": "the second orceld"},
            "created_at_ms": 20,
            "updated_at_ms": 20,
        })
    }

    /// A complete, passing journey on disk.
    fn complete(dir: &Path) -> Vec<Value> {
        prepare(dir).unwrap();
        fs::write(dir.join("reports").join("q3.md"), "the report").unwrap();
        vec![
            task(
                "rpt-a",
                "verified",
                &[("verify", "passed")],
                json!({"name": "q3.md", "sha256": sha256(b"the report")}),
            ),
            task(
                "rpt-b",
                "approval_denied",
                &[("approval", "denied")],
                Value::Null,
            ),
            task("rpt-c", "stale", &[("commit", "stale")], Value::Null),
            task(
                "rpt-d",
                "proposed",
                &[("preview", "destination_exists")],
                Value::Null,
            ),
            cut_off(),
        ]
    }

    /// A task its orceld left after the preview.
    fn cut_off() -> Value {
        let mut task = task(
            "rpt-e",
            "proposed",
            &[("observe", "ok"), ("preview", "ok")],
            Value::Null,
        );
        task["owner"] = json!({"run": "the first orceld"});
        task["created_at_ms"] = json!(5);
        task["updated_at_ms"] = json!(10);
        task
    }

    const TRANSCRIPT: &str =
        "a transcript: task_resume_summary for rpt-e: completed observe, preview; unknown none\n";

    fn failed(results: &[Check]) -> Vec<&'static str> {
        results
            .iter()
            .filter(|r| !r.passed)
            .map(|r| r.name)
            .collect()
    }

    #[test]
    fn a_complete_journey_passes_every_check() {
        let dir = scratch("complete");
        let tasks = complete(&dir);
        let refs: Vec<&Value> = tasks.iter().collect();
        assert_eq!(failed(&checks(&dir, &refs, TRANSCRIPT)), Vec::<&str>::new());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn each_missing_path_fails_its_own_check() {
        let dir = scratch("missing");
        let tasks = complete(&dir);
        for (drop, name) in [
            (0, "approved report written and verified"),
            (1, "denied approval refused"),
            (2, "changed source refused as stale"),
            (3, "existing destination refused"),
            (4, "an interrupted task read back after orceld died"),
        ] {
            let refs: Vec<&Value> = tasks
                .iter()
                .enumerate()
                .filter(|(at, _)| *at != drop)
                .map(|(_, task)| task)
                .collect();
            assert_eq!(failed(&checks(&dir, &refs, TRANSCRIPT)), vec![name]);
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_denial_retried_to_a_yes_is_not_the_denied_path() {
        let dir = scratch("retried");
        let mut tasks = complete(&dir);
        tasks[1]["state"] = json!("verified");
        let refs: Vec<&Value> = tasks.iter().collect();
        assert_eq!(
            failed(&checks(&dir, &refs, TRANSCRIPT)),
            vec!["denied approval refused"]
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_report_that_differs_on_disk_is_not_verified() {
        let dir = scratch("tampered");
        let tasks = complete(&dir);
        fs::write(dir.join("reports").join("q3.md"), "changed afterwards").unwrap();
        let refs: Vec<&Value> = tasks.iter().collect();
        assert_eq!(
            failed(&checks(&dir, &refs, TRANSCRIPT)),
            vec!["approved report written and verified"]
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_overwritten_file_and_approval_material_fail() {
        let dir = scratch("overwritten");
        let tasks = complete(&dir);
        fs::write(dir.join("reports").join("taken.md"), "overwritten").unwrap();
        let refs: Vec<&Value> = tasks.iter().collect();
        assert_eq!(
            failed(&checks(
                &dir,
                &refs,
                "task_resume_summary rpt-e completed observe preview unknown, the tool returned approval_id 123\n"
            )),
            vec![
                "the user's existing file is untouched",
                "no approval material in the transcript"
            ]
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn recovery_needs_a_cut_off_task_another_orceld_and_the_client_reading_it() {
        let name = "an interrupted task read back after orceld died";
        let dir = scratch("recovery");
        let mut tasks = complete(&dir);
        let fails = |tasks: &[Value], transcript: &str| {
            let refs: Vec<&Value> = tasks.iter().collect();
            failed(&checks(&dir, &refs, transcript)).contains(&name)
        };
        assert!(!fails(&tasks, TRANSCRIPT));
        // The client never read it, or read another task.
        assert!(fails(&tasks, "a transcript\n"));
        assert!(fails(&tasks, "task_resume_summary for rpt-other\n"));
        assert!(fails(&tasks, "rpt-e\n"));
        // The prompt and the id alone aren't a read-back: it was refused.
        assert!(fails(
            &tasks,
            "call task_resume_summary for rpt-e: refused\n"
        ));
        assert!(fails(
            &tasks,
            "task_resume_summary for rpt-e could not be completed and the outcome is unknown\n"
        ));
        // The summary's words before the call don't count.
        assert!(fails(
            &tasks,
            "completed unknown observe preview rpt-e, then task_resume_summary\n"
        ));
        // Every task from one orceld: nothing died.
        tasks[4]["owner"] = tasks[0]["owner"].clone();
        assert!(fails(&tasks, TRANSCRIPT));
        // Another orceld, but nothing started after this task ended.
        tasks[4] = cut_off();
        tasks[4]["updated_at_ms"] = json!(30);
        assert!(fails(&tasks, TRANSCRIPT));
        // A task that went on to commit wasn't cut off after its preview.
        tasks[4] = cut_off();
        tasks[4]["steps"]
            .as_array_mut()
            .unwrap()
            .push(json!({"kind": "commit", "outcome": "stale"}));
        assert!(fails(&tasks, TRANSCRIPT));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_release_candidate_must_be_this_commits_and_intact() {
        let zip = ("orcel.zip".to_owned(), b"the bytes".to_vec());
        let provenance = json!({
            "source": {"revision": "abc123"},
            "artifacts": [{"name": "orcel.zip", "sha256": sha256(b"the bytes")}],
        })
        .to_string();
        let good = release_checks(&provenance, "abc123", std::slice::from_ref(&zip));
        assert_eq!(failed(&good), Vec::<&str>::new());
        let commit = "the release candidate was built from this commit";
        let bytes = "the release candidate's zip matches its provenance";
        assert_eq!(
            failed(&release_checks(
                &provenance,
                "def456",
                std::slice::from_ref(&zip)
            )),
            vec![commit]
        );
        // A checkout git couldn't read isn't a match, even against an empty revision.
        assert_eq!(
            failed(&release_checks(
                &json!({"artifacts": []}).to_string(),
                "",
                &[]
            )),
            vec![commit, bytes]
        );
        let changed = ("orcel.zip".to_owned(), b"other bytes".to_vec());
        assert_eq!(
            failed(&release_checks(&provenance, "abc123", &[changed])),
            vec![bytes]
        );
        let renamed = ("other.zip".to_owned(), b"the bytes".to_vec());
        assert_eq!(
            failed(&release_checks(&provenance, "abc123", &[renamed])),
            vec![bytes]
        );
        assert_eq!(
            failed(&release_checks(&provenance, "abc123", &[])),
            vec![bytes]
        );
        assert_eq!(
            failed(&release_checks("not json", "abc123", &[zip])),
            vec![commit, bytes]
        );
    }

    #[test]
    fn ready_needs_orceld_to_answer() {
        let doctor = |status: &str| {
            json!({"ok": false, "doctor": {"checks": [
                {"name": "install", "status": "pass", "detail": "fine"},
                {"name": "ipc", "status": status, "detail": "the state folder is refused"},
            ]}})
            .to_string()
        };
        assert!(orceld_check(&doctor("pass")).passed);
        // Not answering isn't a pass, nor is not knowing.
        for status in ["fail", "unknown", "warn"] {
            let result = orceld_check(&doctor(status));
            assert!(!result.passed, "{status}");
            assert!(result.detail.contains("the state folder is refused"));
        }
        assert!(!orceld_check("not json").passed);
        assert!(!orceld_check(&json!({"doctor": {"checks": []}}).to_string()).passed);
    }

    #[test]
    fn ready_needs_only_this_folder_and_the_prepared_files() {
        let dir = scratch("ready");
        prepare(&dir).unwrap();
        let root = dir.to_str().unwrap();
        let one = json!({"workspaces": [{"id": "default", "root": root}]}).to_string();
        assert_eq!(failed(&ready_checks(&dir, &one)), Vec::<&str>::new());
        let name = "the scratch folder is the only workspace";
        let other = std::env::temp_dir();
        let other = other.to_str().unwrap();
        for wrong in [
            json!({"workspaces": []}).to_string(),
            json!({"workspaces": [{"id": "default", "root": other}]}).to_string(),
            json!({"workspaces": [{"id": "default", "root": root}, {"id": "mine", "root": other}]})
                .to_string(),
            "not json".to_owned(),
        ] {
            assert_eq!(failed(&ready_checks(&dir, &wrong)), vec![name], "{wrong}");
        }
        fs::write(dir.join("data").join("q3.csv"), CHANGED_SOURCE).unwrap();
        assert_eq!(
            failed(&ready_checks(&dir, &one)),
            vec!["the source is unchanged"]
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_history_holds_steps_and_no_file_text() {
        let dir = scratch("history");
        let mut tasks = complete(&dir);
        tasks[0]["sources"] = json!([{"path": "data/q3.csv", "text": "north,Q3,1250000"}]);
        let refs: Vec<&Value> = tasks.iter().collect();
        let history = history_of(&refs).to_string();
        assert!(
            history.contains("rpt-e") && history.contains("preview"),
            "{history}"
        );
        assert!(!history.contains("north,Q3"), "{history}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_journal_keeps_the_newest_snapshot_and_skips_torn_lines() {
        let journal = concat!(
            r#"{"event":"task","task":{"id":"rpt-a","state":"proposed"}}"#,
            "\n",
            r#"{"event":"pending","intent":"x"}"#,
            "\n",
            r#"{"event":"task","task":{"id":"rpt-a","state":"verified"}}"#,
            "\n",
            r#"{"event":"task","task":{"id":"#,
        );
        let tasks = tasks_in(journal);
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks["rpt-a"]["state"], "verified");
    }

    #[test]
    fn only_this_journeys_folder_counts() {
        let inside = json!({"folder_canonical": "/tmp/journey/reports"});
        let outside = json!({"folder_canonical": "/tmp/journey-other/reports"});
        assert!(in_journey(&inside, Path::new("/tmp/journey")));
        assert!(!in_journey(&outside, Path::new("/tmp/journey")));
    }

    #[test]
    fn the_transcript_goes_through_the_product_redactor() {
        let out = redacted("Authorization: Bearer abc123secret\nplain line\n");
        assert!(!out.contains("abc123secret"), "{out}");
        assert!(out.contains("plain line"), "{out}");
    }

    #[test]
    fn prepare_refuses_a_folder_in_use() {
        let dir = scratch("in-use");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("something"), "x").unwrap();
        assert!(prepare(&dir).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }
}
