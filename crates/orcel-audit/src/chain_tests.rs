//! WP1-03 chain tests (`cargo test -p orcel-audit chain_`): linking,
//! tamper detection (edit, delete, reorder, truncation), writers in several
//! processes, torn-write recovery, size bounds, anchors and redaction.

use crate::anchor::{AnchorOutcome, Anchorer, UNANCHORED_NOTE};
use crate::chain::{ChainError, ChainWriter, EventDraft, MAX_EVENT_BYTES};
use crate::verify::{verify_file, verify_with_anchors, Verdict};
use crate::{AuditLogger, ORCELD_LOG};
use orcel_contracts::event::{
    AnchorRef, AuditEvent, AuditEventKind, ANCHOR_INTERVAL_EVENTS, GENESIS_PREV_DIGEST,
};
use orcel_contracts::RequestEnvelope;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

type TestResult = Result<(), String>;

fn sandbox(label: &str) -> Result<PathBuf, String> {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "orcel-audit-chain-{label}-{}-{}-{}",
        std::process::id(),
        crate::chain::now_ms(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| e.to_string())?;
    }
    Ok(dir)
}

fn draft(n: u64) -> EventDraft {
    EventDraft {
        request_id: Some(format!("r-{n}")),
        capability: Some("fs.search".to_owned()),
        operation: Some("search".to_owned()),
        ..EventDraft::new(AuditEventKind::Request, json!({"n": n}))
    }
}

fn write(path: &Path, count: u64) -> Result<ChainWriter, String> {
    let writer = ChainWriter::open(path, ORCELD_LOG).map_err(|e| e.to_string())?;
    for n in 0..count {
        writer.append(draft(n)).map_err(|e| e.to_string())?;
    }
    Ok(writer)
}

fn lines(path: &Path) -> Result<Vec<String>, String> {
    Ok(std::fs::read_to_string(path)
        .map_err(|e| e.to_string())?
        .lines()
        .map(str::to_owned)
        .collect())
}

fn events(path: &Path) -> Result<Vec<AuditEvent>, String> {
    lines(path)?
        .iter()
        .map(|line| serde_json::from_str(line).map_err(|e| e.to_string()))
        .collect()
}

fn rewrite(path: &Path, lines: &[String]) -> TestResult {
    let mut text = lines.join("\n");
    text.push('\n');
    std::fs::write(path, text).map_err(|e| e.to_string())
}

#[test]
fn chain_links_every_event_to_the_one_before() -> TestResult {
    let dir = sandbox("links")?;
    let path = dir.join("audit-chain.jsonl");
    write(&path, 5)?;
    let events = events(&path)?;
    assert_eq!(events.len(), 6, "an opening event and five");
    assert_eq!(events[0].kind, AuditEventKind::Rotation);
    assert_eq!(events[0].prev_digest, GENESIS_PREV_DIGEST);
    assert!(!events[0].asserted_by_session);
    for (index, event) in events.iter().enumerate() {
        assert_eq!(event.seq, index as u64);
        assert_eq!(event.contract, "orcel.audit-event/1");
        assert_eq!(event.digest.len(), 64);
        if index > 0 {
            assert_eq!(event.prev_digest, events[index - 1].digest);
            assert!(event.asserted_by_session);
        }
    }
    let report = verify_file(&path).map_err(|e| e.to_string())?;
    assert_eq!(report.verdict, Verdict::Intact, "{report:?}");
    assert_eq!(report.events, 6);
    assert_eq!(report.file_id.as_deref(), Some(events[0].digest.as_str()));
    assert_eq!(report.head_seq, Some(5));
    // A second writer, as a later orceld, continues the same chain.
    write(&path, 2)?;
    let report = verify_file(&path).map_err(|e| e.to_string())?;
    assert_eq!((report.verdict, report.events), (Verdict::Intact, 8));
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

#[test]
fn chain_an_edit_is_detected_and_refused() -> TestResult {
    let dir = sandbox("edit")?;
    let path = dir.join("audit-chain.jsonl");
    write(&path, 4)?;
    let mut all = lines(&path)?;
    all[2] = all[2].replace("\"n\":1", "\"n\":9");
    rewrite(&path, &all)?;
    let report = verify_file(&path).map_err(|e| e.to_string())?;
    assert_eq!(report.verdict, Verdict::Broken);
    let broken = report.broken.ok_or("a break")?;
    assert_eq!((broken.line, broken.seq), (3, 2));
    assert!(broken.reason.contains("edited"), "{}", broken.reason);
    // A new writer refuses to append after it.
    let writer = ChainWriter::open(&path, ORCELD_LOG).map_err(|e| e.to_string())?;
    let refused = writer.append(draft(99));
    assert!(
        matches!(refused, Err(ChainError::Broken { seq: 2, .. })),
        "{refused:?}"
    );
    assert_eq!(lines(&path)?.len(), 5, "nothing appended");
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

#[test]
fn chain_a_deleted_record_is_detected() -> TestResult {
    let dir = sandbox("delete")?;
    let path = dir.join("audit-chain.jsonl");
    write(&path, 4)?;
    let mut all = lines(&path)?;
    all.remove(2);
    rewrite(&path, &all)?;
    let report = verify_file(&path).map_err(|e| e.to_string())?;
    assert_eq!(report.verdict, Verdict::Broken);
    let reason = report.broken.ok_or("a break")?.reason;
    assert!(reason.contains("seq 3 where 2"), "{reason}");
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

#[test]
fn chain_reordered_records_are_detected() -> TestResult {
    let dir = sandbox("reorder")?;
    let path = dir.join("audit-chain.jsonl");
    write(&path, 4)?;
    let mut all = lines(&path)?;
    all.swap(2, 3);
    rewrite(&path, &all)?;
    let report = verify_file(&path).map_err(|e| e.to_string())?;
    assert_eq!(report.verdict, Verdict::Broken);
    assert_eq!(report.broken.ok_or("a break")?.seq, 2);
    // Moving the opening record is refused too.
    let mut all = lines(&path)?;
    all.swap(0, 1);
    rewrite(&path, &all)?;
    assert_eq!(
        verify_file(&path).map_err(|e| e.to_string())?.verdict,
        Verdict::Broken
    );
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

/// A cut inside a line is a torn tail. A cut of whole records verifies on
/// its own (the report says so), and is caught by an anchor held outside
/// the file; a running writer refuses a file that shrank under it.
#[test]
fn chain_truncation_is_reported() -> TestResult {
    let dir = sandbox("truncate")?;
    let path = dir.join("audit-chain.jsonl");
    let writer = write(&path, 6)?;
    let all = lines(&path)?;
    let last: AuditEvent = serde_json::from_str(&all[6]).map_err(|e| e.to_string())?;
    let held = AnchorRef {
        log: ORCELD_LOG.to_owned(),
        file_id: serde_json::from_str::<AuditEvent>(&all[0])
            .map_err(|e| e.to_string())?
            .digest,
        seq: last.seq,
        digest: last.digest.clone(),
    };
    let report =
        verify_with_anchors(&path, std::slice::from_ref(&held)).map_err(|e| e.to_string())?;
    assert_eq!(report.verdict, Verdict::Intact, "{report:?}");
    assert_eq!(report.anchor_checks[0].result, "match");

    // Whole records cut.
    rewrite(&path, &all[..4])?;
    let alone = verify_file(&path).map_err(|e| e.to_string())?;
    assert_eq!(alone.verdict, Verdict::Intact);
    assert_eq!(alone.tamper_evidence, UNANCHORED_NOTE);
    let anchored =
        verify_with_anchors(&path, std::slice::from_ref(&held)).map_err(|e| e.to_string())?;
    assert_eq!(anchored.verdict, Verdict::Broken);
    assert_eq!(anchored.anchor_checks[0].result, "beyond_end");
    let refused = writer.append(draft(7));
    assert!(
        matches!(&refused, Err(ChainError::Broken { reason, .. }) if reason.contains("shrank")),
        "{refused:?}"
    );

    // A cut inside a line.
    let mut text = all[..4].join("\n");
    text.push('\n');
    text.push_str(&all[4][..20]);
    std::fs::write(&path, text).map_err(|e| e.to_string())?;
    let torn = verify_file(&path).map_err(|e| e.to_string())?;
    assert_eq!(torn.verdict, Verdict::TornTail);
    assert_eq!((torn.events, torn.torn_tail_bytes), (4, 20));

    // A conflicting anchor.
    let conflicting = AnchorRef { seq: 2, ..held };
    rewrite(&path, &all)?;
    let report = verify_with_anchors(&path, &[conflicting]).map_err(|e| e.to_string())?;
    assert_eq!(report.verdict, Verdict::Broken);
    assert_eq!(report.anchor_checks[0].result, "conflict");
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

/// A crash mid-write leaves a torn line: the next append moves it to a
/// quarantine file, cuts it, and records the cut in the chain.
#[test]
fn chain_a_torn_write_is_quarantined_and_recorded() -> TestResult {
    let dir = sandbox("torn")?;
    let path = dir.join("audit-chain.jsonl");
    write(&path, 3)?;
    let mut text = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    text.push_str("{\"contract\":\"orcel.audit-event/1\",\"seq\":4,\"prev");
    std::fs::write(&path, &text).map_err(|e| e.to_string())?;
    let appended = write(&path, 0)?
        .append(draft(10))
        .map_err(|e| e.to_string())?;
    assert_eq!(appended.event.seq, 5, "after the recovery record");
    let events = events(&path)?;
    assert_eq!(events[4].kind, AuditEventKind::Rotation);
    assert_eq!(events[4].detail["action"], "quarantined_torn_tail");
    let name = events[4].detail["quarantine_file"]
        .as_str()
        .ok_or("quarantine name")?;
    let kept = std::fs::read_to_string(dir.join(name)).map_err(|e| e.to_string())?;
    assert!(kept.starts_with("{\"contract\""), "{kept}");
    assert_eq!(events[4].detail["bytes"], kept.len());
    let report = verify_file(&path).map_err(|e| e.to_string())?;
    assert_eq!(report.verdict, Verdict::Intact, "{report:?}");
    assert_eq!(report.quarantined_tails, 1);
    // A torn opening record: the file starts over from a new opening.
    let fresh = dir.join("fresh-chain.jsonl");
    std::fs::write(&fresh, "{\"contr").map_err(|e| e.to_string())?;
    write(&fresh, 1)?;
    let events = self::events(&fresh)?;
    assert_eq!(events[0].detail["action"], "open");
    assert_eq!(events[1].detail["action"], "quarantined_torn_tail");
    assert_eq!(
        verify_file(&fresh).map_err(|e| e.to_string())?.verdict,
        Verdict::Intact
    );
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

/// Removing only the last line end is not what a crash does; cutting the
/// record would delete it, so the writer refuses.
#[test]
fn chain_a_whole_record_without_its_line_end_is_refused() -> TestResult {
    let dir = sandbox("no-newline")?;
    let path = dir.join("audit-chain.jsonl");
    write(&path, 2)?;
    let text = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    std::fs::write(&path, text.trim_end()).map_err(|e| e.to_string())?;
    let refused = ChainWriter::open(&path, ORCELD_LOG)
        .map_err(|e| e.to_string())?
        .append(draft(3));
    assert!(
        matches!(&refused, Err(ChainError::Broken { reason, .. }) if reason.contains("line end")),
        "{refused:?}"
    );
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

#[test]
fn chain_records_are_bounded() -> TestResult {
    let dir = sandbox("bounded")?;
    let path = dir.join("audit-chain.jsonl");
    let writer = ChainWriter::open(&path, ORCELD_LOG).map_err(|e| e.to_string())?;
    let big = "x".repeat(200_000);
    let appended = writer
        .append(EventDraft {
            request_id: Some("é".repeat(10_000)),
            caller_image: Some("p".repeat(10_000)),
            ..EventDraft::new(AuditEventKind::Request, json!({"blob": big}))
        })
        .map_err(|e| e.to_string())?;
    let detail = &appended.event.detail["oversized_detail"];
    assert!(detail["bytes"]
        .as_u64()
        .is_some_and(|bytes| bytes > 200_000));
    assert_eq!(detail["sha256"].as_str().map(str::len), Some(64));
    let id = appended.event.request_id.as_deref().ok_or("request id")?;
    assert_eq!(
        id.chars().count(),
        crate::MAX_FIELD_CHARS + "…[truncated]".chars().count()
    );
    for line in lines(&path)? {
        assert!(line.len() < MAX_EVENT_BYTES, "{} bytes", line.len());
    }
    assert_eq!(
        verify_file(&path).map_err(|e| e.to_string())?.verdict,
        Verdict::Intact
    );
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

struct HeldAnchors(std::sync::Mutex<Vec<AnchorRef>>);

impl Anchorer for HeldAnchors {
    fn anchor(&self, anchor: &AnchorRef) -> AnchorOutcome {
        if let Ok(mut held) = self.0.lock() {
            held.push(anchor.clone());
        }
        AnchorOutcome::Anchored {
            by: "test holder".to_owned(),
            receipt: json!({"held": true}),
        }
    }
}

/// Without a holder every 32nd event gets a local marker that says it is
/// unanchored; with one, the marker records the holder's answer, and the
/// held anchors verify against the file.
#[test]
fn chain_anchors_every_interval_and_never_overclaims() -> TestResult {
    let dir = sandbox("anchors")?;
    let path = dir.join("audit-chain.jsonl");
    let writer = ChainWriter::open(&path, ORCELD_LOG).map_err(|e| e.to_string())?;
    let mut due = Vec::new();
    for n in 0..ANCHOR_INTERVAL_EVENTS {
        let appended = writer.append(draft(n)).map_err(|e| e.to_string())?;
        if appended.anchor.is_some() {
            due.push(appended);
        }
    }
    assert_eq!(
        due.len(),
        1,
        "one anchor in the first {ANCHOR_INTERVAL_EVENTS} events"
    );
    assert_eq!(due[0].at.seq, ANCHOR_INTERVAL_EVENTS - 1);
    assert!(matches!(
        due[0].anchor,
        Some(Ok(AnchorOutcome::Unanchored { .. }))
    ));
    let marker = events(&path)?
        .into_iter()
        .find(|event| event.kind == AuditEventKind::Anchor)
        .ok_or("an anchor event")?;
    assert_eq!(marker.detail["status"], "unanchored");
    assert_eq!(marker.detail["note"], UNANCHORED_NOTE);
    assert_eq!(marker.detail["anchor"]["seq"], ANCHOR_INTERVAL_EVENTS - 1);
    let report = verify_file(&path).map_err(|e| e.to_string())?;
    assert_eq!((report.anchors_local, report.anchors_external), (1, 0));
    assert_eq!(report.tamper_evidence, UNANCHORED_NOTE);

    let holder = Arc::new(HeldAnchors(std::sync::Mutex::new(Vec::new())));
    writer.set_anchorer(holder.clone());
    for n in 0..ANCHOR_INTERVAL_EVENTS {
        writer.append(draft(100 + n)).map_err(|e| e.to_string())?;
    }
    let held = holder.0.lock().map_err(|e| e.to_string())?.clone();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].log, ORCELD_LOG);
    let report = verify_with_anchors(&path, &held).map_err(|e| e.to_string())?;
    assert_eq!(report.verdict, Verdict::Intact, "{report:?}");
    assert_eq!(report.anchors_external, 1);
    assert_eq!(report.last_external_anchor_seq, Some(held[0].seq));
    assert!(report.tamper_evidence.contains("test holder"));

    // An anchor record that names another digest breaks the chain even when
    // it is re-hashed to fit.
    let mut all = events(&path)?;
    let index = all
        .iter()
        .position(|event| event.kind == AuditEventKind::Anchor)
        .ok_or("anchor")?;
    all[index].detail["anchor"]["digest"] = Value::from("0".repeat(64));
    let mut previous = all[index - 1].digest.clone();
    for event in &mut all[index..] {
        event.prev_digest = previous;
        event.digest = crate::chain::digest_of(event)?;
        previous = event.digest.clone();
    }
    let text: Vec<String> = all
        .iter()
        .map(|event| serde_json::to_string(event).map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;
    rewrite(&path, &text)?;
    let report = verify_file(&path).map_err(|e| e.to_string())?;
    assert_eq!(report.verdict, Verdict::Broken);
    assert!(report
        .broken
        .ok_or("a break")?
        .reason
        .contains("anchor record"));
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

/// Threads with writers of their own and child processes append to one
/// chain at once; it stays one gapless, verifying chain.
#[test]
fn chain_concurrent_writers_across_processes_keep_one_chain() -> TestResult {
    const CHILDREN: u64 = 3;
    const THREADS: u64 = 3;
    const EACH: u64 = 40;
    let dir = sandbox("processes")?;
    let path = dir.join("audit-chain.jsonl");
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let children: Vec<std::process::Child> = (0..CHILDREN)
        .map(|_| {
            std::process::Command::new(&exe)
                .args([
                    "--exact",
                    "chain_tests::chain_child_writer",
                    "--test-threads=1",
                ])
                .env("ORCEL_AUDIT_CHAIN_CHILD", &path)
                .env("ORCEL_AUDIT_CHAIN_CHILD_EVENTS", EACH.to_string())
                .stdout(std::process::Stdio::null())
                .spawn()
                .map_err(|e| e.to_string())
        })
        .collect::<Result<_, _>>()?;
    let threads: Vec<_> = (0..THREADS)
        .map(|_| {
            let path = path.clone();
            std::thread::spawn(move || write(&path, EACH).map(|_| ()))
        })
        .collect();
    for thread in threads {
        thread.join().map_err(|_| "a writer thread failed")??;
    }
    for mut child in children {
        let status = child.wait().map_err(|e| e.to_string())?;
        assert!(status.success(), "a child writer failed: {status}");
    }
    let report = verify_file(&path).map_err(|e| e.to_string())?;
    assert_eq!(report.verdict, Verdict::Intact, "{report:?}");
    let written = (CHILDREN + THREADS) * EACH;
    let requests = events(&path)?
        .iter()
        .filter(|event| event.kind == AuditEventKind::Request)
        .count() as u64;
    assert_eq!(requests, written);
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

/// The child half of the test above; does nothing in a normal run.
#[test]
fn chain_child_writer() -> TestResult {
    let Some(path) = std::env::var_os("ORCEL_AUDIT_CHAIN_CHILD") else {
        return Ok(());
    };
    let count = std::env::var("ORCEL_AUDIT_CHAIN_CHILD_EVENTS")
        .ok()
        .and_then(|count| count.parse().ok())
        .unwrap_or(1);
    write(Path::new(&path), count).map(|_| ())
}

fn request(target: &str) -> RequestEnvelope {
    RequestEnvelope {
        version: 1,
        request_id: "req-1".into(),
        client_session_id: "session-1".into(),
        workspace_id: "w".into(),
        capability: "browser.read".into(),
        operation: "open".into(),
        target: Some(target.into()),
        arguments: json!({"password": "ARGUMENT-SECRET", "query": "TOP-SECRET-VALUE"}),
    }
}

/// The logger writes the chain first with the plain record's fields; the
/// chain shows no argument, URL path, query or user info.
#[test]
fn chain_logger_records_keep_their_fields_and_no_secret() -> TestResult {
    let dir = sandbox("logger")?;
    let plain = dir.join("audit.jsonl");
    let logger = AuditLogger::new(&plain).map_err(|e| e.to_string())?;
    assert_eq!(logger.chain().path(), dir.join("audit-chain.jsonl"));
    let target = "https://alice:PASSWORD-SECRET@example.test/private/path?token=QUERY-SECRET";
    logger
        .record(&request(target), "p1", "SUCCESS")
        .map_err(|e| e.to_string())?;
    let caller = crate::AuditCaller {
        pid: 77,
        start_generation: 5,
        generation_source: "test".into(),
        executable: Ok(r"C:\tools\caller.exe".into()),
    };
    logger
        .record_with_caller(&request("src/lib.rs"), "p1", "DENIED", &caller)
        .map_err(|e| e.to_string())?;
    let chain_text = std::fs::read_to_string(logger.chain().path()).map_err(|e| e.to_string())?;
    for secret in [
        "ARGUMENT-SECRET",
        "TOP-SECRET-VALUE",
        "PASSWORD-SECRET",
        "QUERY-SECRET",
        "private/path",
        "alice",
    ] {
        assert!(!chain_text.contains(secret), "{secret} reached the chain");
    }
    let events = events(logger.chain().path())?;
    let success = &events[1];
    assert_eq!(success.kind, AuditEventKind::Request);
    assert_eq!(success.request_id.as_deref(), Some("req-1"));
    assert_eq!(success.capability.as_deref(), Some("browser.read"));
    assert_eq!(success.operation.as_deref(), Some("open"));
    assert_eq!(success.detail["client_session_id"], "session-1");
    assert_eq!(success.detail["workspace_id"], "w");
    assert_eq!(success.detail["policy_revision"], "p1");
    assert_eq!(success.detail["outcome"], "SUCCESS");
    assert_eq!(success.detail["target"], "https://example.test/…");
    assert_eq!(
        success.detail["target_sha256"],
        crate::sha256_hex(target.as_bytes())
    );
    let denied = &events[2];
    assert_eq!(denied.kind, AuditEventKind::Decision);
    assert_eq!(denied.caller_pid, Some(77));
    assert_eq!(denied.caller_image.as_deref(), Some(r"C:\tools\caller.exe"));
    assert_eq!(denied.detail["caller"]["start_generation"], 5);
    assert_eq!(denied.detail["target"], "src/lib.rs");
    // The plain log is unchanged in shape.
    let plain_text = std::fs::read_to_string(&plain).map_err(|e| e.to_string())?;
    assert_eq!(plain_text.lines().count(), 2);
    assert!(plain_text.contains("\"outcome\":\"SUCCESS\""));
    assert!(!plain_text.contains("ARGUMENT-SECRET"));
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

/// A chain that does not verify makes the record fail (the plain line is
/// still written), so a caller that refuses on a failed record refuses.
#[test]
fn chain_a_broken_chain_fails_the_record() -> TestResult {
    let dir = sandbox("logger-broken")?;
    let plain = dir.join("audit.jsonl");
    let logger = AuditLogger::new(&plain).map_err(|e| e.to_string())?;
    logger
        .record(&request("a"), "p1", "SUCCESS")
        .map_err(|e| e.to_string())?;
    let chain = logger.chain().path().to_path_buf();
    let mut all = lines(&chain)?;
    all[1] = all[1].replace("SUCCESS", "FAILURE");
    rewrite(&chain, &all)?;
    let fresh = AuditLogger::new(&plain).map_err(|e| e.to_string())?;
    let error = fresh
        .record(&request("b"), "p1", "SUCCESS")
        .err()
        .ok_or("the record should fail")?;
    assert!(error.to_string().contains("broken"), "{error}");
    assert_eq!(lines(&plain)?.len(), 2, "the plain line is still written");
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

/// The chain beside the default audit log is the registered store.
#[test]
fn chain_beside_the_default_log_is_the_registered_store() {
    use orcel_platform::stores::{AUDIT, AUDIT_CHAIN};
    let root = Path::new("root");
    assert_eq!(
        crate::chain_path_for(&AUDIT.path(root)),
        AUDIT_CHAIN.path(root)
    );
    assert_eq!(
        crate::chain_path_for(Path::new("/x/custom-audit.jsonl")),
        Path::new("/x/custom-audit-chain.jsonl")
    );
}
