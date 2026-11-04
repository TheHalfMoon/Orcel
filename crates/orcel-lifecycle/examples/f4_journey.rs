//! SG-000127 slice 4: the kit around the one step only a person can do.
//!
//! One supported client runs the report journey against an installed orceld
//! over local stdio, and a person answers Orcel's local approval prompt. This
//! tool never approves anything and never talks to orceld or the client. It
//! prepares a scratch workspace, changes its source when the runbook says so,
//! and afterwards checks the evidence from orceld's own journal and the
//! workspace, and redacts the transcript with the product's redactor.
//!
//! ```text
//! cargo run -p orcel-lifecycle --example f4_journey -- prepare <dir>
//! cargo run -p orcel-lifecycle --example f4_journey -- change-source <dir>
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
        "{\n  \"mcpServers\": {\n    \"orcel\": { \"command\": \"orcel\", \"args\": [\"mcp\", \"stdio\"] }\n  }\n}\n",
    )
    .map_err(text)?;
    println!("Prepared {}", dir.display());
    println!("Next: orcel workspace add default \"{}\"", dir.display());
    println!("Then follow prep/F4_SLICE4_CLIENT_JOURNEY.md.");
    Ok(())
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
                tasks.insert(id.to_owned(), value["task"].clone());
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
    let by_step = |kind: &str, outcome: &str| {
        tasks
            .iter()
            .find(|task| has_step(task, kind, outcome))
            .and_then(|task| task["id"].as_str().map(str::to_owned))
    };
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
            by_step("approval", "denied"),
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
    let root = std::env::var_os("LOCALAPPDATA")?;
    Some(PathBuf::from(root).join("Orcel").join("report-tasks.jsonl"))
}

/// Whether the task's folder is inside this journey's scratch workspace.
fn in_journey(task: &Value, canonical: &Path) -> bool {
    task["folder_canonical"]
        .as_str()
        .is_some_and(|folder| Path::new(folder).starts_with(canonical))
}

fn evidence(dir: &Path, client: &str, transcript: &Path, journal: &Path) -> Result<bool, String> {
    let canonical = fs::canonicalize(dir).map_err(text)?;
    let journal_text = fs::read_to_string(journal)
        .map_err(|error| format!("the journal {}: {error}", journal.display()))?;
    let transcript_text = fs::read_to_string(transcript)
        .map_err(|error| format!("the transcript {}: {error}", transcript.display()))?;
    let all = tasks_in(&journal_text);
    let tasks: Vec<&Value> = all
        .values()
        .filter(|task| in_journey(task, &canonical))
        .collect();
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
    let usage = "usage: f4_journey prepare <dir> | change-source <dir> | evidence <dir> --client <name version> --transcript <file> [--journal <file>]";
    let (Some(command), Some(dir)) = (args.first(), args.get(1)) else {
        return Err(usage.to_owned());
    };
    let dir = Path::new(dir);
    match command.as_str() {
        "prepare" => prepare(dir).map(|()| true),
        "change-source" => change_source(dir).map(|()| true),
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
        ]
    }

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
        assert_eq!(
            failed(&checks(&dir, &refs, "a transcript\n")),
            Vec::<&str>::new()
        );
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
        ] {
            let refs: Vec<&Value> = tasks
                .iter()
                .enumerate()
                .filter(|(at, _)| *at != drop)
                .map(|(_, task)| task)
                .collect();
            assert_eq!(failed(&checks(&dir, &refs, "a transcript\n")), vec![name]);
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_report_that_differs_on_disk_is_not_verified() {
        let dir = scratch("tampered");
        let tasks = complete(&dir);
        fs::write(dir.join("reports").join("q3.md"), "changed afterwards").unwrap();
        let refs: Vec<&Value> = tasks.iter().collect();
        assert_eq!(
            failed(&checks(&dir, &refs, "a transcript\n")),
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
            failed(&checks(&dir, &refs, "the tool returned approval_id 123\n")),
            vec![
                "the user's existing file is untouched",
                "no approval material in the transcript"
            ]
        );
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
