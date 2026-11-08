//! BM-02 Tier A through the real `orceld` binary, on every OS: the benchmark
//! runner (`tests/benchmarks`, `python -m orcel_bench orcel`) solves the
//! read-only Orcel task set by driving this build's orceld over its stdio
//! protocol, and the report it writes must show every variant solved. The
//! per-case results are printed as evidence. Needs Python 3.10+ (CI installs
//! it); without it the test is skipped locally and fails in CI.
//!
//! orceld refuses state that another account can reach, including through a
//! parent folder. Where the system temp folder is like that (some Windows
//! profiles), name a private parent with `ORCEL_BM02_STATE_PARENT`; outside
//! CI the test otherwise reports the refusal and skips, in CI it fails.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn python() -> Option<String> {
    for candidate in ["python3", "python"] {
        let probe = Command::new(candidate)
            .args([
                "-c",
                "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)",
            ])
            .output();
        if matches!(probe, Ok(output) if output.status.success()) {
            return Some(candidate.to_owned());
        }
    }
    None
}

fn private_dir(path: &Path) {
    std::fs::create_dir_all(path).expect("create dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    }
}

#[test]
fn bm02_orcel_task_set_is_solved_through_the_real_orceld() {
    let Some(python) = python() else {
        assert!(
            std::env::var_os("CI").is_none(),
            "Python 3.10+ is required in CI"
        );
        eprintln!("BM02 skipped: no Python 3.10+");
        return;
    };
    let bench = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/benchmarks");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let parent = std::env::var_os("ORCEL_BM02_STATE_PARENT")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let base: PathBuf = parent.join(format!("orcel-bm02-{}-{nanos}", std::process::id()));
    private_dir(&base);
    let report = base.join("orcel.report.json");
    let trace = base.join("orcel.trace.jsonl");
    // CI names the commit it built (a pull request's head, not GITHUB_SHA,
    // which is the merge commit there).
    let commit = std::env::var("ORCEL_BM02_COMMIT")
        .or_else(|_| std::env::var("GITHUB_SHA"))
        .ok()
        .filter(|sha| sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(|sha| sha.to_ascii_lowercase())
        .unwrap_or_else(|| "0".repeat(40));
    let output = Command::new(&python)
        .current_dir(&bench)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .args(["-m", "orcel_bench", "orcel", "--orceld"])
        .arg(env!("CARGO_BIN_EXE_orceld"))
        .args(["--commit", &commit, "--out"])
        .arg(&report)
        .arg("--trace")
        .arg(&trace)
        .args(["--repeat", "3", "--temp-root"])
        .arg(base.join("episodes"))
        .output()
        .expect("run the benchmark");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let produced: Value =
        serde_json::from_str(&std::fs::read_to_string(&report).unwrap_or_default())
            .unwrap_or(Value::Null);
    for row in produced["rows"].as_array().into_iter().flatten() {
        eprintln!(
            "BM02-EVIDENCE {} {} {} steps={} p50={}ms p95={}ms",
            row["case"].as_str().unwrap_or("?"),
            row["status"].as_str().unwrap_or("?"),
            row["observed"].as_str().unwrap_or("?"),
            row["steps"],
            row["latency_ms"]["p50"],
            row["latency_ms"]["p95"]
        );
    }
    eprintln!("BM02-EVIDENCE machine {}", produced["machine"]);
    // The first failing episode, by its fixed codes only: orceld's stderr
    // line (which can name local paths) stays in the trace file.
    let traced = std::fs::read_to_string(&trace).unwrap_or_default();
    let episodes: Vec<Value> = traced
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();
    if let Some(failed) = episodes.iter().find(|e| e["status"] != "pass") {
        eprintln!(
            "BM02-FIRST-FAILURE {} episode={} {} {}",
            failed["case"].as_str().unwrap_or("?"),
            failed["episode"],
            failed["status"].as_str().unwrap_or("?"),
            failed["observed"].as_str().unwrap_or("?")
        );
    }
    let state_refused = episodes.iter().any(|e| {
        e["detail"]
            .as_str()
            .is_some_and(|d| d.contains("could be reached or changed by another user"))
    });
    if state_refused && std::env::var_os("CI").is_none() {
        eprintln!(
            "BM02 skipped: orceld refused state under {} because another account can reach it; set ORCEL_BM02_STATE_PARENT to a private folder",
            parent.display()
        );
        let _ = std::fs::remove_dir_all(&base);
        return;
    }
    assert!(
        output.status.success(),
        "benchmark failed:\n{stdout}\n{stderr}"
    );
    let rows = produced["rows"].as_array().expect("rows");
    assert!(rows.len() >= 20, "{} rows", rows.len());
    assert!(rows
        .iter()
        .all(|row| row["status"] == "pass" && row["observed"] == "solved"));
    assert_eq!(produced["planner"]["name"], "orcel-fs-planner");
    assert_eq!(produced["schema"], "orcel-benchmark-report/1");
    // Every episode left nothing behind in its temp root.
    let left = std::fs::read_dir(base.join("episodes"))
        .map(|entries| entries.count())
        .unwrap_or(0);
    assert_eq!(
        left, 0,
        "episode workspaces or orceld state were left behind"
    );
    // CI keeps the report for the schema check and the job log.
    if let Some(keep) = std::env::var_os("ORCEL_BM02_REPORT") {
        std::fs::copy(&report, keep).expect("keep the report");
    }
    let _ = std::fs::remove_dir_all(&base);
}
