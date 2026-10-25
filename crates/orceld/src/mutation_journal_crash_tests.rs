//! SG-000120 RJ-02 fault injection: a real child process performs one
//! approved mutation through the real dispatch and is killed (abort) right
//! after `pending`, right after `dispatched`, or right after the effect,
//! before its outcome is written. A new orceld then restores the journal:
//! the dead child is told apart by its real process identity, every
//! interrupted step is reconciled, and nothing is dispatched again.

use super::test_support::journal;
use super::*;
use orcel_approval::test_support::{
    broker_with_presence, FixedApprovalBroker, TestPresenceVerifier,
};
use orcel_approval::ApprovalDecision;
use orcel_contracts::RequestEnvelope;
use orcel_policy::Workspace;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::process::Command;

const SCENARIOS: &[&str] = &[
    "fs_mkdir",
    "fs_edit",
    "fs_write",
    "fs_move",
    "fs_remove",
    "git_branch",
    "git_commit",
    "opaque",
];
const TRANSITIONS: &[&str] = &["pending", "dispatched", "effect"];

fn sha(text: &str) -> String {
    format!("{:x}", Sha256::digest(text.as_bytes()))
}

fn workspace(dir: &Path) -> Workspace {
    Workspace {
        id: "default".into(),
        root: std::fs::canonicalize(dir.join("ws")).unwrap(),
    }
}

fn request(capability: &str, operation: &str, target: &str, arguments: Value) -> RequestEnvelope {
    RequestEnvelope {
        version: 1,
        request_id: "rj02-crash".into(),
        client_session_id: "s".into(),
        workspace_id: "default".into(),
        capability: capability.into(),
        operation: operation.into(),
        target: Some(target.into()),
        arguments,
    }
}

fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(output.status.success(), "git {args:?}");
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// The state each scenario starts from.
fn prepare(scenario: &str, dir: &Path) {
    let ws = dir.join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    match scenario {
        "fs_edit" | "fs_move" | "fs_remove" => {
            std::fs::write(ws.join("a.txt"), "alpha").unwrap();
        }
        "git_branch" | "git_commit" => {
            git(&ws, &["init", "-q", "-b", "main"]);
            git(&ws, &["config", "user.name", "Orcel Test"]);
            git(&ws, &["config", "user.email", "orcel@example.invalid"]);
            std::fs::write(ws.join("a.txt"), "one\n").unwrap();
            git(&ws, &["add", "a.txt"]);
            git(&ws, &["commit", "-q", "-m", "initial"]);
            if scenario == "git_commit" {
                std::fs::write(ws.join("a.txt"), "two\n").unwrap();
                git(&ws, &["add", "a.txt"]);
            }
        }
        _ => {}
    }
}

/// The child: one approved mutation, journaled to `dir`'s journal.
fn run_child(scenario: &str, dir: &Path) {
    let journal: &'static MutationJournal = Box::leak(Box::new(journal(
        dir.join("state").join("mutations.jsonl"),
        "child",
    )));
    let sink = Sink::Journal(journal);
    let ws = workspace(dir);
    let approved = FixedApprovalBroker(ApprovalDecision::Approved);
    let fs = |request: RequestEnvelope| {
        crate::fs_mutation::dispatch_fs_mutation_to(sink, &ws, &approved, &request).map(|_| ())
    };
    let head = || git(&ws.root, &["rev-parse", "HEAD"]);
    let result = match scenario {
        "fs_mkdir" => fs(request("fs.mkdir", "mkdir", "made", json!({}))),
        "fs_edit" => fs(request(
            "fs.edit",
            "edit",
            "a.txt",
            json!({ "old": "alpha", "new": "beta", "expected_sha256": sha("alpha") }),
        )),
        "fs_move" => fs(request(
            "fs.move",
            "move",
            "a.txt",
            json!({ "to": "b.txt" }),
        )),
        "fs_remove" => crate::fs_mutation::dispatch_fs_mutation_to(
            sink,
            &ws,
            &broker_with_presence(dir.join("approval.jsonl"), TestPresenceVerifier::verified()),
            &request("fs.remove", "remove", "a.txt", json!({})),
        )
        .map(|_| ()),
        "fs_write" => crate::legacy::write_file_to(
            sink,
            &ws,
            &approved,
            &request(
                "fs.write",
                "write",
                "w.txt",
                json!({ "content": "written", "create_if_missing": true }),
            ),
        )
        .map(|_| ()),
        "git_branch" => crate::git_mutation::dispatch_to(
            sink,
            &ws,
            &approved,
            &request(
                "git.branch.create",
                "create",
                ".",
                json!({ "branch": "feature", "expected_head": head() }),
            ),
        )
        .map(|_| ()),
        "git_commit" => crate::git_mutation::dispatch_to(
            sink,
            &ws,
            &approved,
            &request(
                "git.commit",
                "commit",
                ".",
                json!({ "message": "rj02 commit", "expected_head": head() }),
            ),
        )
        .map(|_| ()),
        "opaque" => journaled(
            sink,
            opaque(
                &ws,
                &request("desktop.input", "execute", "window-1", json!({})),
                &"d".repeat(64),
                "window-1",
            ),
            || Ok(()),
            || {
                use std::io::Write as _;
                let mut marker = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(ws.root.join("effects.log"))
                    .unwrap();
                writeln!(marker, "ran").unwrap();
                Ok(())
            },
        ),
        other => Err(ProviderError::new(
            FailureCode::InvalidRequest,
            other.to_owned(),
        )),
    };
    result.unwrap();
}

/// The parent's view of the scenario's target after the restart.
fn effect_state(scenario: &str, dir: &Path) -> String {
    let ws = dir.join("ws");
    let read = |name: &str| std::fs::read_to_string(ws.join(name)).ok();
    match scenario {
        "fs_mkdir" => ws.join("made").is_dir().to_string(),
        "fs_edit" => read("a.txt").unwrap_or_default(),
        "fs_write" => read("w.txt").unwrap_or_else(|| "absent".into()),
        "fs_move" => format!("{:?}/{:?}", read("a.txt"), read("b.txt")),
        "fs_remove" => ws.join("a.txt").exists().to_string(),
        "git_branch" => git(
            &ws,
            &[
                "for-each-ref",
                "--format=%(refname:short)",
                "refs/heads/feature",
            ],
        ),
        "git_commit" => git(&ws, &["log", "--format=%s", "-1"]),
        "opaque" => read("effects.log").unwrap_or_default(),
        _ => String::new(),
    }
}

/// (outcome after restart, target state) for a crash at `transition`.
fn expected(scenario: &str, transition: &str) -> (&'static str, String) {
    let ran = transition == "effect";
    let outcome = match (scenario, transition) {
        (_, "pending") => "reconciled_nothing_done",
        ("opaque", _) => "reconciled_unknown",
        (_, "dispatched") => "reconciled_nothing_done",
        _ => "reconciled_done",
    };
    let state = match scenario {
        "fs_mkdir" => ran.to_string(),
        "fs_edit" => if ran { "beta" } else { "alpha" }.into(),
        "fs_write" => if ran { "written" } else { "absent" }.into(),
        "fs_move" => if ran {
            "None/Some(\"alpha\")"
        } else {
            "Some(\"alpha\")/None"
        }
        .into(),
        "fs_remove" => (!ran).to_string(),
        "git_branch" => if ran { "feature" } else { "" }.into(),
        "git_commit" => if ran { "rj02 commit" } else { "initial" }.into(),
        "opaque" => if ran { "ran\n" } else { "" }.into(),
        _ => String::new(),
    };
    (outcome, state)
}

/// The child entry point; a no-op unless the suite started this process.
#[test]
fn rj02_crash_child() {
    let (Ok(scenario), Ok(dir)) = (
        std::env::var("ORCEL_RJ02_CHILD"),
        std::env::var("ORCEL_RJ02_DIR"),
    ) else {
        return;
    };
    run_child(&scenario, Path::new(&dir));
}

#[test]
fn rj02_fault_injection_kills_each_provider_at_each_transition() {
    let exe = std::env::current_exe().unwrap();
    for scenario in SCENARIOS {
        for transition in TRANSITIONS {
            let dir = std::env::temp_dir().join(format!(
                "orceld-rj02-crash-{scenario}-{transition}-{}-{}",
                std::process::id(),
                orcel_approval::now_ms()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            prepare(scenario, &dir);
            let status = Command::new(&exe)
                .args([
                    "--exact",
                    "mutation_journal::crash_tests::rj02_crash_child",
                    "--test-threads=1",
                ])
                .env("ORCEL_RJ02_CHILD", scenario)
                .env("ORCEL_RJ02_DIR", &dir)
                .env("ORCEL_RJ02_CRASH_AT", transition)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .unwrap();
            assert!(
                !status.success(),
                "{scenario}/{transition}: the child must die at the transition"
            );
            let path = dir.join("state").join("mutations.jsonl");
            let next = journal(path.clone(), "next");
            let restored = next.restore().unwrap();
            let outcomes: Vec<String> = orcel_journal::read_lines::<Line>(&path)
                .unwrap()
                .lines
                .into_iter()
                .filter_map(|line| match line {
                    Line::Outcome { outcome, .. } => Some(outcome),
                    _ => None,
                })
                .collect();
            let (outcome, state) = expected(scenario, transition);
            assert_eq!(restored.reconciled, 1, "{scenario}/{transition}");
            assert_eq!(outcomes, [outcome], "{scenario}/{transition}");
            assert_eq!(
                effect_state(scenario, &dir),
                state,
                "{scenario}/{transition}: the effect ran at most once"
            );
            // Closed for good: another start reconciles and dispatches nothing.
            assert_eq!(
                journal(path, "third").restore().unwrap().reconciled,
                0,
                "{scenario}/{transition}"
            );
            assert_eq!(effect_state(scenario, &dir), state);
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}
