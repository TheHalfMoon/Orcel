//! WP1-03 chain tests (`cargo test -p orcel-audit chain_`): linking,
//! tamper detection (edit, delete, reorder, truncation), writers in several
//! processes, torn-write recovery, size bounds, anchors and redaction.

use crate::anchor::{AnchorOutcome, Anchorer, UNANCHORED_NOTE};
use crate::chain::forced::{self, Collisions};
use crate::chain::{
    move_aside, ChainError, ChainLink, ChainWriter, EventDraft, ASIDE_ATTEMPTS, MAX_EVENT_BYTES,
};
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
    assert!(alone.tamper_evidence.starts_with(UNANCHORED_NOTE));
    let anchored =
        verify_with_anchors(&path, std::slice::from_ref(&held)).map_err(|e| e.to_string())?;
    assert_eq!(anchored.verdict, Verdict::Truncated);
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
    assert_eq!(report.verdict, Verdict::Recovered, "{report:?}");
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
        Verdict::Recovered
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

/// A holder like the authority service: it holds anchors per log, refuses
/// a file that does not continue the held one, and answers what it holds.
struct StrictHolder(std::sync::Mutex<Option<AnchorRef>>);

impl Anchorer for StrictHolder {
    fn anchor(
        &self,
        anchor: &AnchorRef,
        link: Option<&ChainLink>,
        _reset: Option<&str>,
    ) -> AnchorOutcome {
        let Ok(mut held) = self.0.lock() else {
            return AnchorOutcome::Unanchored {
                reason: "poisoned".to_owned(),
            };
        };
        if let Some(current) = held.as_ref() {
            if let Some(reason) = crate::chain::held_conflict(
                current,
                &anchor.file_id,
                link,
                anchor.seq + 1,
                Some(
                    if anchor.file_id == current.file_id && anchor.seq == current.seq {
                        anchor.digest.as_str()
                    } else {
                        current.digest.as_str()
                    },
                ),
            ) {
                return AnchorOutcome::Refused { reason };
            }
        }
        *held = Some(anchor.clone());
        AnchorOutcome::Anchored {
            by: "strict holder".to_owned(),
            receipt: json!({}),
        }
    }

    fn held(&self, _log: &str) -> Option<crate::HeldState> {
        let anchor = self.0.lock().ok().and_then(|held| held.clone());
        Some(crate::HeldState {
            anchor,
            reset: None,
        })
    }
}

impl Anchorer for HeldAnchors {
    fn anchor(
        &self,
        anchor: &AnchorRef,
        _link: Option<&ChainLink>,
        _reset: Option<&str>,
    ) -> AnchorOutcome {
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
    assert_eq!((report.anchors_local, report.anchors_claimed), (1, 0));
    assert!(report.tamper_evidence.starts_with(UNANCHORED_NOTE));

    let holder = Arc::new(HeldAnchors(std::sync::Mutex::new(Vec::new())));
    writer.set_anchorer(holder.clone());
    for n in 0..ANCHOR_INTERVAL_EVENTS {
        writer.append(draft(100 + n)).map_err(|e| e.to_string())?;
    }
    let held = holder.0.lock().map_err(|e| e.to_string())?.clone();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].log, ORCELD_LOG);
    // Without the held copy, the anchor record is only a claim.
    let claimed = verify_file(&path).map_err(|e| e.to_string())?;
    assert_eq!((claimed.anchors_claimed, claimed.anchors_verified), (1, 0));
    assert!(
        claimed.tamper_evidence.contains("claim test holder")
            && claimed.tamper_evidence.contains("unverified"),
        "{}",
        claimed.tamper_evidence
    );
    let report = verify_with_anchors(&path, &held).map_err(|e| e.to_string())?;
    assert_eq!(report.verdict, Verdict::Intact, "{report:?}");
    assert_eq!(report.anchors_verified, 1);
    assert_eq!(report.last_verified_anchor_seq, Some(held[0].seq));
    assert!(report
        .tamper_evidence
        .starts_with("verified against held anchors"));

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
        executable: Ok(r"C:\Users\alice-profile\tools\caller.exe".into()),
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
    assert_eq!(success.detail["phase"], "outcome");
    assert_eq!(success.detail["target"]["label"], "url");
    assert_eq!(
        success.detail["target"]["sha256"],
        crate::sha256_hex(target.as_bytes())
    );
    let denied = &events[2];
    assert_eq!(denied.kind, AuditEventKind::Decision);
    assert_eq!(denied.caller_pid, Some(77));
    assert_eq!(denied.caller_image.as_deref(), Some("caller.exe"));
    assert_eq!(denied.detail["caller"]["start_generation"], 5);
    assert_eq!(denied.detail["caller"]["executable_name"], "caller.exe");
    assert_eq!(denied.detail["target"]["label"], "path");
    assert!(!chain_text.contains("alice-profile"));
    assert!(!chain_text.contains("src/lib.rs"));
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

/// Spec 4.8 write before dispatch: the dispatch record reaches the chain
/// (and only the chain) before the outcome, and fails when the chain does.
#[test]
fn chain_dispatch_records_come_first_and_fail_with_the_chain() -> TestResult {
    let dir = sandbox("dispatch")?;
    let plain = dir.join("audit.jsonl");
    let logger = AuditLogger::new(&plain).map_err(|e| e.to_string())?;
    logger
        .record_dispatch(&request("a"), "p1")
        .map_err(|e| e.to_string())?;
    logger
        .record(&request("a"), "p1", "SUCCESS")
        .map_err(|e| e.to_string())?;
    let events = events(logger.chain().path())?;
    assert_eq!(events[1].kind, AuditEventKind::Dispatch);
    assert_eq!(events[1].detail["phase"], "before_dispatch");
    assert!(events[1].detail["outcome"].is_null());
    assert_eq!(events[2].detail["phase"], "outcome");
    assert_eq!(lines(&plain)?.len(), 1, "the plain log keeps outcomes only");
    let chain = logger.chain().path().to_path_buf();
    let mut all = lines(&chain)?;
    all[1] = all[1].replace("before_dispatch", "after_dispatch");
    rewrite(&chain, &all)?;
    let fresh = AuditLogger::new(&plain).map_err(|e| e.to_string())?;
    let error = fresh
        .record_dispatch(&request("b"), "p1")
        .err()
        .ok_or("the dispatch record should fail")?;
    assert!(error.to_string().contains("audit-move-aside"), "{error}");
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

/// Moving a broken chain aside keeps it and opens a new file linked to its
/// last verifiable record; a running writer follows the linked file; held
/// anchors of the old file check against the link; an unlinked replacement
/// is refused by writers and is a break for held anchors.
#[test]
fn chain_move_aside_links_the_new_file_and_an_unlinked_one_breaks() -> TestResult {
    let dir = sandbox("move-aside")?;
    let path = dir.join("audit-chain.jsonl");
    let running = write(&path, 5)?;
    let old = events(&path)?;
    let old_id = old[0].digest.clone();
    let held_old_head = AnchorRef {
        log: ORCELD_LOG.to_owned(),
        file_id: old_id.clone(),
        seq: 3,
        digest: old[3].digest.clone(),
    };
    let held_old_early = AnchorRef {
        seq: 1,
        digest: old[1].digest.clone(),
        ..held_old_head.clone()
    };
    // Break record 4, then move the file aside.
    let mut all = lines(&path)?;
    all[4] = all[4].replace("\"n\":3", "\"n\":8");
    rewrite(&path, &all)?;
    assert!(matches!(
        write(&path, 0)?.append(draft(50)),
        Err(ChainError::Broken { seq: 4, .. })
    ));
    let moved = move_aside(&path, ORCELD_LOG).map_err(|e| e.to_string())?;
    assert!(dir.join(&moved.moved_to).is_file(), "the old file is kept");
    assert!(moved.moved_to.contains(".quarantine-moved-"));
    let link = moved.link.clone().ok_or("a link")?;
    assert_eq!(
        link,
        ChainLink {
            previous_file_id: old_id.clone(),
            previous_head_seq: 3,
            previous_head_digest: old[3].digest.clone(),
        }
    );
    let fresh = events(&path)?;
    assert_eq!(
        fresh[0].prev_digest, old[3].digest,
        "continues the old head"
    );
    assert_eq!(fresh[0].detail["previous_file_id"], old_id.as_str());
    assert!(fresh[0].detail["moved_aside"]["stopped"]
        .as_str()
        .is_some_and(|stopped| stopped.contains("broken at seq 4")));
    // The writer that verified records past the new file's head (seq 4 and
    // 5) refuses to follow it; a new writer continues the linked file.
    assert!(matches!(
        running.append(draft(51)),
        Err(ChainError::Broken { .. })
    ));
    let appended = write(&path, 0)?
        .append(draft(51))
        .map_err(|e| e.to_string())?;
    assert_eq!(appended.at.file_id, moved.file_id);
    assert_eq!(appended.event.seq, 1);
    let report = verify_with_anchors(&path, &[held_old_head.clone(), held_old_early.clone()])
        .map_err(|e| e.to_string())?;
    assert_eq!(report.verdict, Verdict::Intact, "{report:?}");
    assert_eq!(report.previous_file_id.as_deref(), Some(old_id.as_str()));
    // Both held anchors of the old file are checked in the moved-aside file
    // itself, which ends at the head the new file claims.
    assert_eq!(report.anchor_checks[0].result, "match");
    assert_eq!(report.anchor_checks[1].result, "match");
    assert_eq!(report.predecessors.len(), 1);
    assert_eq!(report.predecessors[0].file, moved.moved_to);
    assert!(report.tamper_evidence.contains("follows"));
    // An earlier record of the old file that does not match is caught.
    let wrong_early = AnchorRef {
        digest: "0".repeat(64),
        ..held_old_early.clone()
    };
    let report = verify_with_anchors(&path, &[wrong_early]).map_err(|e| e.to_string())?;
    assert_eq!(report.verdict, Verdict::Broken);
    assert_eq!(report.anchor_checks[0].result, "conflict");
    // A held anchor past the linked head: the old file was cut first.
    let past = AnchorRef {
        seq: 4,
        ..held_old_head.clone()
    };
    let report = verify_with_anchors(&path, &[past]).map_err(|e| e.to_string())?;
    assert_eq!(report.verdict, Verdict::Truncated);
    assert_eq!(report.anchor_checks[0].result, "beyond_end");
    // The moved-aside file must exist and end at the claimed head.
    let aside = dir.join(&moved.moved_to);
    let kept = std::fs::read_to_string(&aside).map_err(|e| e.to_string())?;
    let kept_lines: Vec<String> = kept.lines().map(str::to_owned).collect();
    rewrite(&aside, &kept_lines[..3])?;
    let report = verify_file(&path).map_err(|e| e.to_string())?;
    assert_eq!(report.verdict, Verdict::Broken, "{report:?}");
    assert!(report
        .broken
        .as_ref()
        .is_some_and(|broken| broken.reason.contains("does not end at the head")));
    std::fs::remove_file(&aside).map_err(|e| e.to_string())?;
    let report = verify_file(&path).map_err(|e| e.to_string())?;
    assert_eq!(report.verdict, Verdict::Broken, "{report:?}");
    std::fs::write(&aside, kept).map_err(|e| e.to_string())?;
    assert_eq!(
        verify_file(&path).map_err(|e| e.to_string())?.verdict,
        Verdict::Intact
    );

    // An unlinked replacement (the file deleted and a new one opened).
    std::fs::remove_file(&path).map_err(|e| e.to_string())?;
    write(&path, 1)?;
    let replaced = events(&path)?;
    assert_eq!(replaced[0].detail["previous_file_id"], "none");
    let refused = running.append(draft(52));
    assert!(
        matches!(&refused, Err(ChainError::Broken { reason, .. }) if reason.contains("does not link")),
        "{refused:?}"
    );
    let held_new = AnchorRef {
        file_id: moved.file_id.clone(),
        seq: 1,
        digest: appended.event.digest.clone(),
        ..held_old_head
    };
    let report = verify_with_anchors(&path, &[held_new]).map_err(|e| e.to_string())?;
    assert_eq!(report.verdict, Verdict::Broken);
    assert_eq!(report.anchor_checks[0].result, "unlinked_file");
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

/// Review: a chain deleted and opened fresh still fails when a holder holds
/// anchors. A writer reading the new file from the start refuses to append
/// (fail closed), and the verifier with the held anchor reports Broken.
#[test]
fn chain_a_deleted_chain_is_refused_when_anchors_are_held() -> TestResult {
    let dir = sandbox("deleted-held")?;
    let path = dir.join("audit-chain.jsonl");
    let holder = Arc::new(StrictHolder(std::sync::Mutex::new(None)));
    let first = ChainWriter::open(&path, ORCELD_LOG).map_err(|e| e.to_string())?;
    first.set_anchorer(holder.clone());
    for n in 0..ANCHOR_INTERVAL_EVENTS {
        first.append(draft(n)).map_err(|e| e.to_string())?;
    }
    let held = holder
        .held(ORCELD_LOG)
        .and_then(|state| state.anchor)
        .ok_or("an anchor is held")?;
    // A restart on the intact file appends.
    let again = ChainWriter::open(&path, ORCELD_LOG).map_err(|e| e.to_string())?;
    again.set_anchorer(holder.clone());
    again.append(draft(100)).map_err(|e| e.to_string())?;
    // The file deleted; a restart opens a fresh one and refuses.
    std::fs::remove_file(&path).map_err(|e| e.to_string())?;
    let restarted = ChainWriter::open(&path, ORCELD_LOG).map_err(|e| e.to_string())?;
    restarted.set_anchorer(holder.clone());
    let refused = restarted.append(draft(101));
    assert!(
        matches!(&refused, Err(ChainError::Broken { reason, .. }) if reason.contains("does not continue")),
        "{refused:?}"
    );
    let report = verify_with_anchors(&path, &[held]).map_err(|e| e.to_string())?;
    assert_eq!(report.verdict, Verdict::Broken);
    assert_eq!(report.anchor_checks[0].result, "unlinked_file");
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

/// Review: a holder's link refusal is recorded as `link_refused`, every
/// later record is refused, and the verifier marks the chain Broken.
#[test]
fn chain_a_link_refusal_fails_closed() -> TestResult {
    let dir = sandbox("link-refused")?;
    let path = dir.join("audit-chain.jsonl");
    let holder = Arc::new(StrictHolder(std::sync::Mutex::new(Some(AnchorRef {
        log: ORCELD_LOG.to_owned(),
        file_id: "f".repeat(64),
        seq: 31,
        digest: "d".repeat(64),
    }))));
    // A writer that never asked the holder at start (as before it was set).
    let writer = ChainWriter::open(&path, ORCELD_LOG).map_err(|e| e.to_string())?;
    writer.append(draft(0)).map_err(|e| e.to_string())?;
    writer.set_anchorer(holder);
    let mut outcome = None;
    for n in 1..ANCHOR_INTERVAL_EVENTS {
        let appended = writer.append(draft(n)).map_err(|e| e.to_string())?;
        if appended.anchor.is_some() {
            outcome = appended.anchor;
            break;
        }
    }
    assert!(
        matches!(outcome, Some(Ok(AnchorOutcome::Refused { .. }))),
        "{outcome:?}"
    );
    let marker = events(&path)?
        .into_iter()
        .find(|event| event.kind == AuditEventKind::Anchor)
        .ok_or("an anchor record")?;
    assert_eq!(marker.detail["status"], "link_refused");
    assert!(matches!(
        writer.append(draft(99)),
        Err(ChainError::Broken { .. })
    ));
    // Another writer reading the file refuses too.
    let other = ChainWriter::open(&path, ORCELD_LOG).map_err(|e| e.to_string())?;
    assert!(matches!(
        other.append(draft(98)),
        Err(ChainError::Broken { .. })
    ));
    let report = verify_file(&path).map_err(|e| e.to_string())?;
    assert_eq!(report.verdict, Verdict::Broken);
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

/// Review: a writer follows a linked replacement only when the link keeps
/// every record it verified.
#[test]
fn chain_a_linked_file_that_drops_verified_records_is_refused() -> TestResult {
    let dir = sandbox("link-head")?;
    let path = dir.join("audit-chain.jsonl");
    let running = write(&path, 6)?;
    let all = lines(&path)?;
    // Keep only the first records, then move aside: the new file links to
    // seq 3 while the running writer verified up to seq 6.
    rewrite(&path, &all[..4])?;
    move_aside(&path, ORCELD_LOG).map_err(|e| e.to_string())?;
    let refused = running.append(draft(60));
    assert!(
        matches!(&refused, Err(ChainError::Broken { reason, .. }) if reason.contains("records were dropped")),
        "{refused:?}"
    );
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

/// Review: control, separator and bidi characters in client fields never
/// reach the chain as such.
#[test]
fn chain_client_fields_lose_control_and_bidi_characters() -> TestResult {
    let dir = sandbox("fields")?;
    let logger = AuditLogger::new(dir.join("audit.jsonl")).map_err(|e| e.to_string())?;
    let mut sneaky = request("x");
    sneaky.request_id = "id\u{85}\u{2028}\u{202E}gpj.exe".into();
    sneaky.workspace_id = "w\u{7}\u{2066}".into();
    sneaky.capability = "fs.read\u{1b}[2J".into();
    logger
        .record(&sneaky, "p1", "SUCCESS")
        .map_err(|e| e.to_string())?;
    let events = events(logger.chain().path())?;
    let event = &events[1];
    for text in [
        event.request_id.clone().unwrap_or_default(),
        event.capability.clone().unwrap_or_default(),
        event.detail["workspace_id"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
    ] {
        assert!(
            !text
                .chars()
                .any(|c| c.is_control() || matches!(c, '\u{2028}' | '\u{202E}' | '\u{2066}')),
            "{text:?}"
        );
    }
    assert_eq!(
        event.request_id.as_deref(),
        Some("id\u{FFFD}\u{FFFD}\u{FFFD}gpj.exe")
    );
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

/// An owner anchor reset: the current file is kept aside, a new first file
/// opens naming the reset, writers continue it, and the verifier reports it
/// as `reset_by_owner` rather than intact.
#[test]
fn chain_an_owner_reset_opens_a_visible_first_file() -> TestResult {
    let dir = sandbox("reset")?;
    let path = dir.join("audit-chain.jsonl");
    write(&path, 3)?;
    let reset = json!({"event_digest": "c".repeat(64), "authority_seq": 9});
    let opened =
        crate::open_after_reset(&path, ORCELD_LOG, reset.clone()).map_err(|e| e.to_string())?;
    let moved = opened.moved_to.clone().ok_or("the old file is kept")?;
    assert!(dir.join(&moved).is_file());
    assert!(moved.contains(".quarantine-reset-"));
    let events = events(&path)?;
    assert_eq!(events[0].digest, opened.file_id);
    assert_eq!(events[0].detail["previous_file_id"], "none");
    assert_eq!(events[0].detail["anchor_reset"], reset);
    write(&path, 2)?;
    let report = verify_file(&path).map_err(|e| e.to_string())?;
    assert_eq!(report.verdict, Verdict::ResetByOwner, "{report:?}");
    assert_eq!(report.reset_by_owner, Some(reset));
    assert!(report.tamper_evidence.contains("owner anchor reset"));
    // Without an existing file the reset just opens one.
    let fresh = dir.join("fresh-chain.jsonl");
    let opened = crate::open_after_reset(&fresh, ORCELD_LOG, json!({"event_digest": "d"}))
        .map_err(|e| e.to_string())?;
    assert_eq!(opened.moved_to, None);
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

/// The files kept beside the chain in `dir`, by name.
fn kept_files(dir: &Path) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|e| e.to_string())? {
        let name = entry.map_err(|e| e.to_string())?.file_name();
        let name = name.to_string_lossy().into_owned();
        if name.contains(".quarantine-") {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

/// What each operation that keeps the chain aside is called with and returns.
type MoveAside = fn(&Path) -> Result<(String, String), ChainError>;

/// `move_aside` and `open_after_reset`: the kept name and the new file's id.
const MOVERS: [(&str, MoveAside); 2] = [
    ("moved", |path| {
        move_aside(path, ORCELD_LOG).map(|moved| (moved.moved_to, moved.file_id))
    }),
    ("reset", |path| {
        let reset = json!({"event_digest": "c".repeat(64), "authority_seq": 9});
        crate::open_after_reset(path, ORCELD_LOG, reset)
            .map(|opened| (opened.moved_to.unwrap_or_default(), opened.file_id))
    }),
];

fn aside(what: &str, ms: u64, token: &str) -> String {
    format!(
        "audit-chain.jsonl.quarantine-{what}{ms}-{}-{token}",
        std::process::id()
    )
}

/// Two files moved aside in one millisecond and process, the second first
/// trying the very name of the first: both are kept whole, under different
/// names, and the files opened after them have different ids.
#[test]
fn chain_a_colliding_aside_name_never_replaces_kept_evidence() -> TestResult {
    for (what, run) in MOVERS {
        let dir = sandbox("aside-collision")?;
        let path = dir.join("audit-chain.jsonl");
        let same = Collisions::at(1_700_000_000_000);
        write(&path, 2)?;
        let first_bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
        same.tokens(&["same"]);
        let (first, first_id) = run(&path).map_err(|e| e.to_string())?;
        let second_bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
        same.tokens(&["same", "fresh"]);
        let (second, second_id) = run(&path).map_err(|e| e.to_string())?;
        assert_eq!(same.tokens_left(), 0, "{what}: the taken name was tried");
        let prefix = format!("{what}-");
        assert_eq!(first, aside(&prefix, 1_700_000_000_000, "same"));
        assert_eq!(second, aside(&prefix, 1_700_000_000_000, "fresh"));
        assert_eq!(
            std::fs::read(dir.join(&first)).map_err(|e| e.to_string())?,
            first_bytes,
            "{what}: the first kept file survives"
        );
        assert_eq!(
            std::fs::read(dir.join(&second)).map_err(|e| e.to_string())?,
            second_bytes
        );
        assert_eq!(kept_files(&dir)?.len(), 2);
        assert_ne!(first_id, second_id, "{what}");
        let opening = events(&path)?.remove(0);
        assert_eq!(opening.digest, second_id);
        assert_eq!(opening.detail["moved_aside"]["file"], second.as_str());
        let verdict = verify_file(&path).map_err(|e| e.to_string())?.verdict;
        let expected = match what {
            "reset" => Verdict::ResetByOwner,
            _ => Verdict::Intact,
        };
        assert_eq!(verdict, expected, "{what}");
        let _ = std::fs::remove_dir_all(dir);
    }
    Ok(())
}

/// Without forced tokens, names taken in one millisecond differ by
/// themselves.
#[test]
fn chain_aside_names_in_one_millisecond_differ() -> TestResult {
    for (what, run) in MOVERS {
        let dir = sandbox("aside-names")?;
        let path = dir.join("audit-chain.jsonl");
        let _same = Collisions::at(1_700_000_000_000);
        write(&path, 1)?;
        let mut names = std::collections::BTreeSet::new();
        for _ in 0..8 {
            names.insert(run(&path).map_err(|e| e.to_string())?.0);
        }
        assert_eq!(names.len(), 8, "{what}: {names:?}");
        assert_eq!(kept_files(&dir)?, names.into_iter().collect::<Vec<_>>());
        let _ = std::fs::remove_dir_all(dir);
    }
    Ok(())
}

/// When every name tried is taken the operation fails, and the chain and
/// every kept file are as they were.
#[test]
fn chain_aside_fails_closed_when_every_name_is_taken() -> TestResult {
    for (what, run) in MOVERS {
        let dir = sandbox("aside-taken")?;
        let path = dir.join("audit-chain.jsonl");
        let same = Collisions::at(1_700_000_000_000);
        write(&path, 2)?;
        let before = std::fs::read(&path).map_err(|e| e.to_string())?;
        let taken = aside(&format!("{what}-"), 1_700_000_000_000, "same");
        std::fs::write(dir.join(&taken), b"kept").map_err(|e| e.to_string())?;
        // One more than may be tried, so an unbounded loop would go past them.
        same.tokens(&vec!["same"; ASIDE_ATTEMPTS + 1]);
        let error = run(&path).err().ok_or("every name is taken")?;
        assert!(
            matches!(&error, ChainError::Io(reason) if reason.contains("names tried are taken")),
            "{what}: {error}"
        );
        assert_eq!(same.tokens_left(), 1, "{what}: {ASIDE_ATTEMPTS} tried");
        assert_eq!(
            std::fs::read(dir.join(&taken)).map_err(|e| e.to_string())?,
            b"kept"
        );
        assert_eq!(std::fs::read(&path).map_err(|e| e.to_string())?, before);
        assert_eq!(kept_files(&dir)?, vec![taken]);
        // The chain still works, and the next try succeeds.
        same.tokens(&[]);
        write(&path, 1)?;
        run(&path).map_err(|e| e.to_string())?;
        let _ = std::fs::remove_dir_all(dir);
    }
    Ok(())
}

/// A symbolic link at the aside name, dangling or not, is neither replaced
/// nor followed.
#[cfg(unix)]
#[test]
fn chain_aside_never_replaces_or_follows_a_symlink() -> TestResult {
    for (what, run) in MOVERS {
        for exists in [true, false] {
            let dir = sandbox("aside-link")?;
            let path = dir.join("audit-chain.jsonl");
            let same = Collisions::at(1_700_000_000_000);
            write(&path, 2)?;
            let before = std::fs::read(&path).map_err(|e| e.to_string())?;
            let victim = dir.join("victim");
            if exists {
                std::fs::write(&victim, b"keep").map_err(|e| e.to_string())?;
            }
            let link = dir.join(aside(&format!("{what}-"), 1_700_000_000_000, "same"));
            std::os::unix::fs::symlink(&victim, &link).map_err(|e| e.to_string())?;
            same.tokens(&["same", "fresh"]);
            let (kept, _) = run(&path).map_err(|e| e.to_string())?;
            assert_eq!(
                kept,
                aside(&format!("{what}-"), 1_700_000_000_000, "fresh"),
                "{what}"
            );
            assert_eq!(
                std::fs::read(dir.join(&kept)).map_err(|e| e.to_string())?,
                before
            );
            assert_eq!(
                std::fs::read_link(&link).map_err(|e| e.to_string())?,
                victim
            );
            assert_eq!(victim.exists(), exists);
            if exists {
                assert_eq!(std::fs::read(&victim).map_err(|e| e.to_string())?, b"keep");
            }
            let _ = std::fs::remove_dir_all(dir);
        }
    }
    Ok(())
}

/// A torn tail whose first name is taken is kept under another; when every
/// name is taken nothing is cut and nothing appended.
#[test]
fn chain_a_torn_tail_is_kept_under_a_name_nothing_has() -> TestResult {
    let dir = sandbox("aside-tail")?;
    let path = dir.join("audit-chain.jsonl");
    let same = Collisions::at(1_700_000_000_000);
    write(&path, 2)?;
    let mut torn = std::fs::read(&path).map_err(|e| e.to_string())?;
    torn.extend_from_slice(b"{\"torn");
    std::fs::write(&path, &torn).map_err(|e| e.to_string())?;
    let taken = dir.join(aside("", 1_700_000_000_000, "same"));
    std::fs::write(&taken, b"kept").map_err(|e| e.to_string())?;
    same.tokens(&vec!["same"; ASIDE_ATTEMPTS + 1]);
    assert!(write(&path, 1).is_err());
    assert_eq!(same.tokens_left(), 1);
    assert_eq!(std::fs::read(&path).map_err(|e| e.to_string())?, torn);
    same.tokens(&["same", "fresh"]);
    write(&path, 1)?;
    assert_eq!(std::fs::read(&taken).map_err(|e| e.to_string())?, b"kept");
    let kept = aside("", 1_700_000_000_000, "fresh");
    assert_eq!(
        std::fs::read(dir.join(&kept)).map_err(|e| e.to_string())?,
        b"{\"torn"
    );
    assert_eq!(events(&path)?[3].detail["quarantine_file"], kept.as_str());
    let verdict = verify_file(&path).map_err(|e| e.to_string())?.verdict;
    assert_eq!(verdict, Verdict::Recovered);
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

/// Files opened in the same millisecond, with everything else the same, have
/// different ids: no log's first file, and no file opened after one reset, is
/// taken for another.
#[test]
fn chain_files_opened_in_one_millisecond_have_different_ids() -> TestResult {
    let dir = sandbox("opening-ids")?;
    let _same = Collisions::at(1_700_000_000_000);
    let reset = json!({"event_digest": "c".repeat(64), "authority_seq": 9});
    let mut ids = std::collections::BTreeSet::new();
    let mut openings = Vec::new();
    for n in 0..4 {
        let path = dir.join(format!("first-{n}.jsonl"));
        write(&path, 1)?;
        openings.push(events(&path)?.remove(0));
        let path = dir.join(format!("reset-{n}.jsonl"));
        crate::open_after_reset(&path, ORCELD_LOG, reset.clone()).map_err(|e| e.to_string())?;
        openings.push(events(&path)?.remove(0));
    }
    for opening in &openings {
        ids.insert(opening.digest.clone());
        assert!(opening.detail["nonce"]
            .as_str()
            .is_some_and(|nonce| nonce.len() == 32));
    }
    assert_eq!(ids.len(), openings.len());
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

/// An opening record as orceld wrote it before opening records had a nonce
/// (made by the code at commit ad5d6d7f).
const OPENING_WITHOUT_NONCE: &str = concat!(
    r#"{"contract":"orcel.audit-event/1","seq":0,"prev_digest":""#,
    "0000000000000000000000000000000000000000000000000000000000000000",
    r#"","at_ms":1795456832364,"kind":"rotation","request_id":null,"job_id":null,"#,
    r#""principal_id":null,"capability":null,"operation":null,"authority":null,"state":null,"#,
    r#""asserted_by_session":false,"caller_pid":null,"caller_image":null,"detail":{"#,
    r#""action":"open","anchor_interval_events":32,"anchor_reset":null,"#,
    r#""contract":"orcel.audit-event/1","log":"orceld","moved_aside":null,"#,
    r#""previous_file_id":"none","previous_head_digest":null,"previous_head_seq":null},"#,
    r#""digest":"f88152a5bafb6b0d05ae50f737bd93c0c81f26440602a773b100c3f665269bff"}"#,
    "
"
);

/// A chain written before opening records had a nonce: it verifies, is
/// continued and is moved aside as before.
#[test]
fn chain_a_file_opened_without_a_nonce_verifies_and_is_continued() -> TestResult {
    let dir = sandbox("no-nonce")?;
    let path = dir.join("audit-chain.jsonl");
    std::fs::write(&path, OPENING_WITHOUT_NONCE).map_err(|e| e.to_string())?;
    let report = verify_file(&path).map_err(|e| e.to_string())?;
    assert_eq!(report.verdict, Verdict::Intact, "{report:?}");
    let old_id = report.file_id.ok_or("a file id")?;
    assert!(events(&path)?[0].detail.get("nonce").is_none());
    write(&path, 2)?;
    let report = verify_file(&path).map_err(|e| e.to_string())?;
    assert_eq!((report.verdict, report.events), (Verdict::Intact, 3));
    assert_eq!(report.file_id.as_deref(), Some(old_id.as_str()));
    let moved = move_aside(&path, ORCELD_LOG).map_err(|e| e.to_string())?;
    assert_eq!(moved.link.ok_or("a link")?.previous_file_id, old_id);
    let report = verify_file(&path).map_err(|e| e.to_string())?;
    assert_eq!(report.verdict, Verdict::Intact, "{report:?}");
    assert_eq!(report.predecessors.len(), 1);
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

/// A holder in its reset state: it holds no anchor but the reset record the
/// next first file must name.
struct ResetHolder(String);

impl Anchorer for ResetHolder {
    fn anchor(
        &self,
        _anchor: &AnchorRef,
        _link: Option<&ChainLink>,
        reset: Option<&str>,
    ) -> AnchorOutcome {
        if reset == Some(self.0.as_str()) {
            AnchorOutcome::Anchored {
                by: "reset holder".to_owned(),
                receipt: json!({}),
            }
        } else {
            AnchorOutcome::Refused {
                reason: "not the reset file".to_owned(),
            }
        }
    }

    fn held(&self, _log: &str) -> Option<crate::HeldState> {
        Some(crate::HeldState {
            anchor: None,
            reset: Some(self.0.clone()),
        })
    }
}

/// Review: after the owner's Yes, only the file that reset opened is
/// continued. A dropped-in unlinked file (or one naming another reset) is
/// refused by writers and Broken for the verifier given the holder's reset.
#[test]
fn chain_after_a_reset_only_the_reset_file_is_accepted() -> TestResult {
    let dir = sandbox("after-reset")?;
    let digest = "e".repeat(64);
    // The file the reset opened: writers continue it and pass the digest
    // to the holder.
    let path = dir.join("audit-chain.jsonl");
    crate::open_after_reset(&path, ORCELD_LOG, json!({"event_digest": digest}))
        .map_err(|e| e.to_string())?;
    let writer = ChainWriter::open(&path, ORCELD_LOG).map_err(|e| e.to_string())?;
    writer.set_anchorer(Arc::new(ResetHolder(digest.clone())));
    let mut outcome = None;
    for n in 0..ANCHOR_INTERVAL_EVENTS {
        let appended = writer.append(draft(n)).map_err(|e| e.to_string())?;
        if appended.anchor.is_some() {
            outcome = appended.anchor;
        }
    }
    assert!(
        matches!(outcome, Some(Ok(AnchorOutcome::Anchored { .. }))),
        "{outcome:?}"
    );
    // The opening record was anchored before anything else was appended.
    let written = events(&path)?;
    assert_eq!(written[1].kind, AuditEventKind::Anchor);
    assert_eq!(written[1].detail["anchor"]["seq"], 0);
    assert_eq!(written[1].detail["status"], "anchored");
    let report = crate::verify_with_holder(&path, &[], Some(&digest)).map_err(|e| e.to_string())?;
    assert_eq!(report.verdict, Verdict::ResetByOwner, "{report:?}");
    // A dropped-in unlinked file.
    let dropped = dir.join("dropped-chain.jsonl");
    write(&dropped, 1)?;
    let refused = ChainWriter::open(&dropped, ORCELD_LOG).map_err(|e| e.to_string())?;
    refused.set_anchorer(Arc::new(ResetHolder(digest.clone())));
    let attempt = refused.append(draft(1));
    assert!(
        matches!(&attempt, Err(ChainError::Broken { reason, .. }) if reason.contains("does not start from that reset")),
        "{attempt:?}"
    );
    let report =
        crate::verify_with_holder(&dropped, &[], Some(&digest)).map_err(|e| e.to_string())?;
    assert_eq!(report.verdict, Verdict::Broken);
    // A file naming another reset.
    let other = dir.join("other-chain.jsonl");
    crate::open_after_reset(&other, ORCELD_LOG, json!({"event_digest": "f".repeat(64)}))
        .map_err(|e| e.to_string())?;
    let report =
        crate::verify_with_holder(&other, &[], Some(&digest)).map_err(|e| e.to_string())?;
    assert_eq!(report.verdict, Verdict::Broken);
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

/// A holder in its reset state that cannot be reached right now.
struct UnreachableResetHolder(String);

impl Anchorer for UnreachableResetHolder {
    fn anchor(
        &self,
        _anchor: &AnchorRef,
        _link: Option<&ChainLink>,
        _reset: Option<&str>,
    ) -> AnchorOutcome {
        AnchorOutcome::Unanchored {
            reason: "unreachable".to_owned(),
        }
    }

    fn held(&self, _log: &str) -> Option<crate::HeldState> {
        Some(crate::HeldState {
            anchor: None,
            reset: Some(self.0.clone()),
        })
    }
}

/// Re-review: the file a reset opened gets its opening anchored before any
/// other record; while the holder cannot hold it, nothing is appended.
#[test]
fn chain_the_reset_files_opening_is_anchored_before_anything_else() -> TestResult {
    let dir = sandbox("reset-opening")?;
    let digest = "e".repeat(64);
    let path = dir.join("audit-chain.jsonl");
    crate::open_after_reset(&path, ORCELD_LOG, json!({"event_digest": digest}))
        .map_err(|e| e.to_string())?;
    let writer = ChainWriter::open(&path, ORCELD_LOG).map_err(|e| e.to_string())?;
    writer.set_anchorer(Arc::new(UnreachableResetHolder(digest.clone())));
    assert!(matches!(writer.append(draft(1)), Err(ChainError::Io(_))));
    assert_eq!(events(&path)?.len(), 1, "only the opening record");
    writer.set_anchorer(Arc::new(ResetHolder(digest)));
    writer.append(draft(2)).map_err(|e| e.to_string())?;
    let written = events(&path)?;
    assert_eq!(written[1].detail["anchor"]["seq"], 0);
    assert_eq!(written[2].kind, AuditEventKind::Request);
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

/// A holder in its reset state that takes far longer than a writer waits.
struct SlowResetHolder(String);

impl Anchorer for SlowResetHolder {
    fn anchor(
        &self,
        _anchor: &AnchorRef,
        _link: Option<&ChainLink>,
        _reset: Option<&str>,
    ) -> AnchorOutcome {
        std::thread::sleep(std::time::Duration::from_secs(12));
        AnchorOutcome::Unanchored {
            reason: "slow".to_owned(),
        }
    }

    fn held(&self, _log: &str) -> Option<crate::HeldState> {
        Some(crate::HeldState {
            anchor: None,
            reset: Some(self.0.clone()),
        })
    }
}

/// Final review: the holder is asked for the reset file's opening without
/// the file lock held and for a bounded time, so a hung holder stalls
/// neither another writer nor this one beyond the wait.
#[test]
fn chain_a_slow_holder_never_holds_the_lock_or_stalls_the_writer() -> TestResult {
    let dir = sandbox("slow-holder")?;
    let path = dir.join("audit-chain.jsonl");
    crate::open_after_reset(&path, ORCELD_LOG, json!({"event_digest": "e".repeat(64)}))
        .map_err(|e| e.to_string())?;
    let slow_path = path.clone();
    let started = std::time::Instant::now();
    let slow = std::thread::spawn(move || -> Result<bool, String> {
        let writer = ChainWriter::open(&slow_path, ORCELD_LOG).map_err(|e| e.to_string())?;
        writer.set_anchorer(Arc::new(SlowResetHolder("e".repeat(64))));
        Ok(matches!(writer.append(draft(1)), Err(ChainError::Io(_))))
    });
    std::thread::sleep(std::time::Duration::from_millis(500));
    // Another writer (no holder) appends while the slow one waits.
    let other_started = std::time::Instant::now();
    write(&path, 1)?;
    assert!(
        other_started.elapsed() < std::time::Duration::from_secs(2),
        "the lock was held during the holder call: {:?}",
        other_started.elapsed()
    );
    let refused = slow.join().map_err(|_| "the slow writer panicked")??;
    assert!(refused, "no answer in time refuses the append");
    let waited = started.elapsed();
    assert!(
        waited < crate::chain::OPENING_ANCHOR_WAIT + std::time::Duration::from_secs(3),
        "the writer waited {waited:?}"
    );
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

/// Answers `held` as told, and never anchors.
#[derive(Default)]
struct Holding(std::sync::Mutex<Option<crate::HeldState>>);

impl Holding {
    fn now(&self, held: Option<crate::HeldState>) {
        *self.0.lock().expect("held") = held;
    }
}

impl Anchorer for Holding {
    fn anchor(
        &self,
        _anchor: &AnchorRef,
        _link: Option<&ChainLink>,
        _reset: Option<&str>,
    ) -> AnchorOutcome {
        AnchorOutcome::Unanchored {
            reason: "the holder is busy".to_owned(),
        }
    }

    fn held(&self, _log: &str) -> Option<crate::HeldState> {
        self.0.lock().expect("held").clone()
    }
}

/// A holder whose anchor at seq 1 of `file_id` is another record's.
fn conflicting(file_id: &str) -> Option<crate::HeldState> {
    Some(crate::HeldState {
        anchor: Some(AnchorRef {
            log: ORCELD_LOG.to_owned(),
            file_id: file_id.to_owned(),
            seq: 1,
            digest: "0".repeat(64),
        }),
        reset: None,
    })
}

/// A holder in the reset state.
fn resetting(digest: &str) -> Option<crate::HeldState> {
    Some(crate::HeldState {
        anchor: None,
        reset: Some(digest.to_owned()),
    })
}

fn held_by(
    path: &Path,
    held: Option<crate::HeldState>,
) -> Result<(ChainWriter, Arc<Holding>), String> {
    let writer = ChainWriter::open(path, ORCELD_LOG).map_err(|e| e.to_string())?;
    let holder = Arc::new(Holding::default());
    holder.now(held);
    writer.set_anchorer(Arc::clone(&holder) as Arc<dyn Anchorer>);
    Ok((writer, holder))
}

/// Ends the file in a torn line whose first copy cannot be kept: the first
/// sync reads every record and then fails.
fn tear_and_block_the_tail(path: &Path, forced: &Collisions) -> TestResult {
    let mut bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    bytes.extend_from_slice(b"{\"torn");
    std::fs::write(path, bytes).map_err(|e| e.to_string())?;
    let taken = path.with_file_name(aside("", 1_700_000_000_000, "same"));
    std::fs::write(taken, b"kept").map_err(|e| e.to_string())?;
    forced.tokens(&vec!["same"; ASIDE_ATTEMPTS]);
    Ok(())
}

/// Adds a line that is no record to the file.
fn add_garbage(path: &Path) -> TestResult {
    let mut now = lines(path)?;
    now.push("garbage".to_owned());
    rewrite(path, &now)
}

/// `writer` refuses every append with an error that says `why`, and leaves
/// the file as it is.
fn refuses(writer: &ChainWriter, path: &Path, why: &str) -> TestResult {
    let before = std::fs::read(path).ok();
    for n in 0..3 {
        let attempt = writer.append(draft(n));
        if !matches!(&attempt, Err(error) if error.to_string().contains(why)) {
            return Err(format!("try {n}, {why}: {attempt:?}"));
        }
        assert_eq!(std::fs::read(path).ok(), before, "try {n}, {why}");
    }
    Ok(())
}

fn reset_file(path: &Path, digest: &str) -> Result<String, String> {
    crate::open_after_reset(path, ORCELD_LOG, json!({"event_digest": digest}))
        .map(|opened| opened.file_id)
        .map_err(|e| e.to_string())
}

/// A first sync that read the records and then failed has not checked the
/// file against the held anchor: the next append still does.
#[test]
fn chain_a_failed_first_sync_does_not_skip_the_held_anchor() -> TestResult {
    let dir = sandbox("held-recheck")?;
    let path = dir.join("audit-chain.jsonl");
    let forced = Collisions::at(1_700_000_000_000);
    write(&path, 3)?;
    let (writer, _) = held_by(&path, conflicting(&events(&path)?[0].digest))?;
    tear_and_block_the_tail(&path, &forced)?;
    assert!(matches!(writer.append(draft(50)), Err(ChainError::Io(_))));
    assert_eq!(forced.tokens_left(), 0, "the sync failed at the torn tail");
    for n in 51..53 {
        let error = writer.append(draft(n)).err().ok_or("a held conflict")?;
        assert!(
            matches!(&error, ChainError::Broken { reason, .. } if reason.contains("anchor holder")),
            "{error}"
        );
    }
    let kinds: Vec<_> = events(&path)?.into_iter().map(|e| e.kind).collect();
    assert_eq!(kinds.len(), 5, "an opening, three, the recorded cut");
    assert_eq!(kinds[4], AuditEventKind::Rotation);
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

/// Nor does it skip the rule that a reset file's opening record is anchored
/// before anything else is appended.
#[test]
fn chain_a_failed_first_sync_does_not_skip_the_opening_anchor() -> TestResult {
    let dir = sandbox("opening-recheck")?;
    let path = dir.join("audit-chain.jsonl");
    let forced = Collisions::at(1_700_000_000_000);
    let digest = "e".repeat(64);
    reset_file(&path, &digest)?;
    let (writer, _) = held_by(&path, resetting(&digest))?;
    tear_and_block_the_tail(&path, &forced)?;
    assert!(writer.append(draft(50)).is_err());
    assert_eq!(forced.tokens_left(), 0, "the sync failed at the torn tail");
    refuses_after_cut(&writer, &path)?;
    assert_eq!(events(&path)?.len(), 2, "the opening and the recorded cut");
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

fn refuses_after_cut(writer: &ChainWriter, path: &Path) -> TestResult {
    let error = writer.append(draft(51)).err().ok_or("not anchored yet")?;
    assert!(
        error.to_string().contains("must be anchored first"),
        "{error}"
    );
    refuses(writer, path, "must be anchored first")
}

/// However many syncs fail, and at whichever record, and also when an opening
/// was anchored in the part that a failed sync read.
#[test]
fn chain_the_held_check_stays_owed_until_it_is_made() -> TestResult {
    let dir = sandbox("held-owed")?;
    let path = dir.join("audit-chain.jsonl");
    write(&path, 5)?;
    let whole = lines(&path)?;
    let (writer, holder) = held_by(&path, conflicting(&events(&path)?[0].digest))?;
    for broken in [3, 4] {
        let mut now = whole.clone();
        now[broken] = "garbage".to_owned();
        rewrite(&path, &now)?;
        refuses(&writer, &path, "not an audit event")?;
    }
    rewrite(&path, &whole)?;
    refuses(&writer, &path, "not the one the anchor holder holds")?;
    // The right record, which only a failed sync read, passes the check.
    let (writer, holder_2) = held_by(&path, None)?;
    let mut held = conflicting(&events(&path)?[0].digest);
    if let Some(anchor) = held.as_mut().and_then(|held| held.anchor.as_mut()) {
        anchor.digest.clone_from(&events(&path)?[1].digest);
    }
    holder_2.now(held);
    add_garbage(&path)?;
    refuses(&writer, &path, "not an audit event")?;
    rewrite(&path, &whole)?;
    writer.append(draft(9)).map_err(|e| e.to_string())?;
    // And is not made again.
    holder_2.now(conflicting(&events(&path)?[0].digest));
    writer.append(draft(10)).map_err(|e| e.to_string())?;
    drop(holder);
    let _ = std::fs::remove_dir_all(dir);

    let dir = sandbox("opening-owed")?;
    let path = dir.join("audit-chain.jsonl");
    let digest = "e".repeat(64);
    reset_file(&path, &digest)?;
    let first = ChainWriter::open(&path, ORCELD_LOG).map_err(|e| e.to_string())?;
    first.set_anchorer(Arc::new(ResetHolder(digest.clone())));
    first.append(draft(1)).map_err(|e| e.to_string())?;
    let whole = lines(&path)?;
    let (writer, _) = held_by(&path, resetting(&digest))?;
    add_garbage(&path)?;
    refuses(&writer, &path, "not an audit event")?;
    rewrite(&path, &whole)?;
    writer.append(draft(2)).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

/// A holder that answered is not done without, whatever happens before the
/// check is made; one that never answered is.
#[test]
fn chain_a_holder_that_answered_is_waited_for() -> TestResult {
    for how in ["again", "lost view", "followed"] {
        let dir = sandbox("held-waits")?;
        let path = dir.join("audit-chain.jsonl");
        write(&path, 3)?;
        let whole = lines(&path)?;
        let file_id = events(&path)?[0].digest.clone();
        let (writer, holder) = held_by(&path, conflicting(&file_id))?;
        add_garbage(&path)?;
        refuses(&writer, &path, "not an audit event")?;
        holder.now(None);
        match how {
            "followed" => {
                move_aside(&path, ORCELD_LOG).map_err(|e| e.to_string())?;
            }
            _ => rewrite(&path, &whole)?,
        }
        if how == "lost view" {
            writer.lose_view();
        }
        refuses(&writer, &path, "answered before")?;
        holder.now(conflicting(&file_id));
        if how != "followed" {
            refuses(&writer, &path, "not the one the anchor holder holds")?;
        } else {
            // It links past the held record, which is all the holder can say.
            writer.append(draft(9)).map_err(|e| e.to_string())?;
        }
        // One that never answered: as without a holder.
        let (silent, _) = held_by(&path, None)?;
        add_garbage(&path)?;
        let now = lines(&path)?;
        refuses(&silent, &path, "not an audit event")?;
        rewrite(&path, &now[..now.len() - 1])?;
        silent.append(draft(9)).map_err(|e| e.to_string())?;
        let _ = std::fs::remove_dir_all(dir);
    }
    Ok(())
}

/// The check is made of the records the writer read, not of others put in
/// their place.
#[test]
fn chain_the_held_check_is_of_the_records_that_were_read() -> TestResult {
    let dir = sandbox("held-rewritten")?;
    let path = dir.join("audit-chain.jsonl");
    write(&path, 3)?;
    let whole = lines(&path)?;
    let (writer, _) = held_by(&path, Some(crate::HeldState::default()))?;
    add_garbage(&path)?;
    refuses(&writer, &path, "not an audit event")?;
    rewrite(&path, &whole[..1])?;
    let other = ChainWriter::open(&path, ORCELD_LOG).map_err(|e| e.to_string())?;
    for n in 4..7 {
        other.append(draft(n)).map_err(|e| e.to_string())?;
    }
    let length = |lines: &[String]| lines.iter().map(String::len).sum::<usize>();
    assert_eq!(length(&lines(&path)?), length(&whole));
    refuses(&writer, &path, "not the ones this writer read")?;
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

/// A failed sync forgets no record it read: they are neither cut nor
/// rewritten unseen.
#[test]
fn chain_records_a_failed_sync_read_are_not_cut_or_rewritten() -> TestResult {
    let dir = sandbox("read-cut")?;
    let path = dir.join("audit-chain.jsonl");
    let writer = write(&path, 3)?;
    let verified = lines(&path)?;
    write(&path, 2)?;
    let read = lines(&path)?;
    add_garbage(&path)?;
    refuses(&writer, &path, "not an audit event")?;
    rewrite(&path, &verified)?;
    refuses(&writer, &path, "records were cut")?;
    write(&path, 4)?;
    refuses(&writer, &path, "broken at seq 6")?;
    rewrite(&path, &read)?;
    let appended = writer.append(draft(9)).map_err(|e| e.to_string())?;
    assert_eq!(appended.event.seq, 6);
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

/// Nor the linked file it followed: the file before it is not put back, also
/// when that is the reset file the holder holds. Moving the linked file
/// aside is followed.
#[test]
fn chain_a_file_a_failed_sync_followed_is_not_undone() -> TestResult {
    for reset in [false, true] {
        let dir = sandbox("followed-undone")?;
        let path = dir.join("audit-chain.jsonl");
        let digest = "e".repeat(64);
        if reset {
            reset_file(&path, &digest)?;
        }
        write(&path, 2)?;
        let first = lines(&path)?;
        let file_id = events(&path)?[0].digest.clone();
        let mut held = conflicting(&file_id);
        if let Some(anchor) = held.as_mut().and_then(|held| held.anchor.as_mut()) {
            anchor.seq = 0;
            anchor.digest.clone_from(&file_id);
        }
        let (writer, _) = held_by(&path, held.filter(|_| reset))?;
        writer.append(draft(1)).map_err(|e| e.to_string())?;
        let first_grown = lines(&path)?;
        move_aside(&path, ORCELD_LOG).map_err(|e| e.to_string())?;
        write(&path, 2)?;
        add_garbage(&path)?;
        let linked = lines(&path)?;
        refuses(&writer, &path, "not an audit event")?;
        for put_back in [&first, &first_grown] {
            rewrite(&path, put_back)?;
            refuses(&writer, &path, "does not link to it")?;
        }
        rewrite(&path, &linked)?;
        refuses(&writer, &path, "not an audit event")?;
        let moved = move_aside(&path, ORCELD_LOG).map_err(|e| e.to_string())?;
        if !reset {
            let appended = writer.append(draft(9)).map_err(|e| e.to_string())?;
            assert_eq!(appended.at.file_id, moved.file_id);
        }
        let _ = std::fs::remove_dir_all(dir);
    }
    Ok(())
}

/// Nor the reset file: another one that names the same reset record is not
/// taken for it.
#[test]
fn chain_a_reset_file_a_failed_sync_read_is_not_replaced() -> TestResult {
    let dir = sandbox("reset-forged")?;
    let path = dir.join("audit-chain.jsonl");
    let digest = "e".repeat(64);
    reset_file(&path, &digest)?;
    let (writer, _) = held_by(&path, resetting(&digest))?;
    add_garbage(&path)?;
    refuses(&writer, &path, "not an audit event")?;
    let forged = dir.join("forged.jsonl");
    reset_file(&forged, &digest)?;
    rewrite(&path, &lines(&forged)?)?;
    refuses(&writer, &path, "does not link to it")?;
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

/// A writer that starts over keeps a refusal, and that an opening is not
/// anchored, for the same file, until the holder answers.
#[test]
fn chain_starting_over_keeps_what_the_holder_said() -> TestResult {
    let dir = sandbox("carried")?;
    let path = dir.join("audit-chain.jsonl");
    write(&path, 3)?;
    let whole = lines(&path)?;
    let (writer, holder) = held_by(&path, conflicting(&events(&path)?[0].digest))?;
    refuses(&writer, &path, "not the one the anchor holder holds")?;
    holder.now(None);
    for _ in 0..2 {
        writer.lose_view();
        refuses(&writer, &path, "not the one the anchor holder holds")?;
        // Also when nothing of the file could be read in between.
        rewrite(&path, &["garbage".to_owned()])?;
        writer.lose_view();
        assert!(writer.append(draft(1)).is_err());
        writer.lose_view();
        rewrite(&path, &whole)?;
    }
    refuses(&writer, &path, "not the one the anchor holder holds")?;
    holder.now(Some(crate::HeldState::default()));
    writer.append(draft(1)).map_err(|e| e.to_string())?;
    // Another file is not the one that was refused.
    holder.now(conflicting(&events(&path)?[0].digest));
    writer.lose_view();
    refuses(&writer, &path, "not the one the anchor holder holds")?;
    holder.now(None);
    writer.lose_view();
    std::fs::remove_file(&path).map_err(|e| e.to_string())?;
    writer.append(draft(1)).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_dir_all(dir);

    let dir = sandbox("carried-opening")?;
    let path = dir.join("audit-chain.jsonl");
    let digest = "e".repeat(64);
    reset_file(&path, &digest)?;
    let (writer, holder) = held_by(&path, resetting(&digest))?;
    refuses(&writer, &path, "must be anchored first")?;
    holder.now(None);
    for _ in 0..2 {
        writer.lose_view();
        refuses(&writer, &path, "must be anchored first")?;
    }
    // Another writer had it anchored.
    let whole = lines(&path)?;
    let other = ChainWriter::open(&path, ORCELD_LOG).map_err(|e| e.to_string())?;
    other.set_anchorer(Arc::new(ResetHolder(digest)));
    other.append(draft(1)).map_err(|e| e.to_string())?;
    writer.lose_view();
    writer.append(draft(2)).map_err(|e| e.to_string())?;
    // Another file has no opening to wait for, also when a failed sync read
    // part of it first.
    for fails in [false, true] {
        rewrite(&path, &whole)?;
        let (writer, holder) = held_by(&path, resetting(&"e".repeat(64)))?;
        refuses(&writer, &path, "must be anchored first")?;
        holder.now(None);
        writer.lose_view();
        std::fs::remove_file(&path).map_err(|e| e.to_string())?;
        if fails {
            write(&path, 1)?;
            let other = lines(&path)?;
            add_garbage(&path)?;
            refuses(&writer, &path, "not an audit event")?;
            rewrite(&path, &other)?;
            writer.lose_view();
        }
        writer.append(draft(1)).map_err(|e| e.to_string())?;
    }
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

/// Without a conflict after all, nothing is kept of what was refused; nor of
/// an opening to wait for, when the holder holds an anchor and no reset.
#[test]
fn chain_the_holders_answer_ends_what_was_kept() -> TestResult {
    let dir = sandbox("carried-ends")?;
    let path = dir.join("audit-chain.jsonl");
    write(&path, 3)?;
    let (writer, holder) = held_by(&path, conflicting(&events(&path)?[0].digest))?;
    refuses(&writer, &path, "not the one the anchor holder holds")?;
    writer.lose_view();
    holder.now(None);
    refuses(&writer, &path, "not the one the anchor holder holds")?;
    holder.now(Some(crate::HeldState::default()));
    writer.append(draft(1)).map_err(|e| e.to_string())?;
    writer.lose_view();
    holder.now(None);
    writer.append(draft(2)).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_dir_all(dir);

    let dir = sandbox("opening-ends")?;
    let path = dir.join("audit-chain.jsonl");
    let digest = "e".repeat(64);
    let file_id = reset_file(&path, &digest)?;
    let (writer, holder) = held_by(&path, resetting(&digest))?;
    refuses(&writer, &path, "must be anchored first")?;
    writer.lose_view();
    holder.now(Some(crate::HeldState {
        anchor: Some(AnchorRef {
            log: ORCELD_LOG.to_owned(),
            digest: file_id.clone(),
            file_id,
            seq: 0,
        }),
        reset: None,
    }));
    writer.append(draft(1)).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

/// Answers as told, and counts how often it is asked. While it hangs, an
/// answer comes only once the hang ends; while it is slow, a long time passes
/// on the asking thread's clock first.
#[derive(Default)]
struct Hanging {
    held: std::sync::Mutex<Option<crate::HeldState>>,
    hangs: std::sync::Mutex<bool>,
    over: std::sync::Condvar,
    slow: std::sync::atomic::AtomicBool,
    asked: AtomicU64,
    asked_by: std::sync::Mutex<Option<std::thread::ThreadId>>,
}

impl Hanging {
    fn set(&self, held: Option<crate::HeldState>, hangs: bool) {
        *self.held.lock().expect("held") = held;
        *self.hangs.lock().expect("hangs") = hangs;
        self.over.notify_all();
    }

    fn asked(&self) -> u64 {
        self.asked.load(Ordering::SeqCst)
    }

    /// Waits until it was asked `times` times: an ask may still be on its way
    /// when its time is up.
    fn is_asked(&self, times: u64) -> bool {
        wait_until(|| self.asked() >= times) && self.asked() == times
    }

    /// Ends the hang, so that the late answer is `held` and `then` what it
    /// answers when it is asked again.
    fn late(
        &self,
        writer: &ChainWriter,
        held: Option<crate::HeldState>,
        then: Option<crate::HeldState>,
    ) -> TestResult {
        self.set(held, false);
        if !wait_until(|| !writer.asking()) {
            return Err("the late answer did not come".to_owned());
        }
        self.set(then, false);
        Ok(())
    }

    /// Whether the writer itself asked last: it waits without a bound.
    fn asked_by_this_thread(&self) -> bool {
        *self.asked_by.lock().expect("asked by") == Some(std::thread::current().id())
    }
}

impl Anchorer for Hanging {
    fn anchor(
        &self,
        _anchor: &AnchorRef,
        _link: Option<&ChainLink>,
        _reset: Option<&str>,
    ) -> AnchorOutcome {
        AnchorOutcome::Unanchored {
            reason: "the holder is busy".to_owned(),
        }
    }

    fn held(&self, _log: &str) -> Option<crate::HeldState> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        *self.asked_by.lock().expect("asked by") = Some(std::thread::current().id());
        if self.slow.load(Ordering::SeqCst) {
            forced::pass(2 * forced::PATIENT);
        }
        let mut hangs = self.hangs.lock().expect("hangs");
        while *hangs {
            hangs = self.over.wait(hangs).expect("hangs");
        }
        self.held.lock().expect("held").clone()
    }
}

/// Whether `done` is in a minute; without a fixed wait.
fn wait_until(done: impl Fn() -> bool) -> bool {
    let end = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while !done() {
        if std::time::Instant::now() > end {
            return false;
        }
        std::thread::yield_now();
    }
    true
}

fn hanging(path: &Path) -> Result<(ChainWriter, Arc<Hanging>), String> {
    let writer = ChainWriter::open(path, ORCELD_LOG).map_err(|e| e.to_string())?;
    let holder = Arc::new(Hanging::default());
    writer.set_anchorer(Arc::clone(&holder) as Arc<dyn Anchorer>);
    Ok((writer, holder))
}

/// The bounds that let other writers have the lock.
#[test]
fn chain_a_holder_asked_again_is_waited_for_less_than_the_lock() {
    assert!(crate::chain::HELD_WAIT * 3 <= std::time::Duration::from_secs(10));
    assert!(crate::chain::HELD_BACK_OFF >= crate::chain::HELD_WAIT * 3);
}

/// A holder that answered and then hangs is waited for shortly, and then not
/// asked for a while: every append is refused, none is made unchecked, and
/// another writer has the lock.
#[test]
fn chain_a_hung_holder_is_waited_for_shortly_and_not_asked_again_at_once() -> TestResult {
    let second = std::time::Duration::from_secs(1);
    for how in ["again", "lost view", "followed"] {
        let dir = sandbox("held-hangs")?;
        let path = dir.join("audit-chain.jsonl");
        write(&path, 3)?;
        let whole = lines(&path)?;
        let (writer, holder) = hanging(&path)?;
        let file_id = events(&path)?[0].digest.clone();
        holder.set(conflicting(&file_id), false);
        add_garbage(&path)?;
        refuses(&writer, &path, "not an audit event")?;
        assert_eq!(holder.asked(), 3, "each time the check is owed");
        if how == "followed" {
            move_aside(&path, ORCELD_LOG).map_err(|e| e.to_string())?;
        } else {
            rewrite(&path, &whole)?;
        }
        if how == "lost view" {
            writer.lose_view();
        }
        holder.set(None, true);
        let impatient = forced::Impatient::new();
        let started = std::time::Instant::now();
        refuses(&writer, &path, "start the authority service")?;
        assert!(started.elapsed() < forced::PATIENT / 2, "it waits shortly");
        assert!(holder.is_asked(4), "{how}: once, and then not again");
        // Also starting over does not ask sooner.
        writer.lose_view();
        refuses(&writer, &path, "restart orceld")?;
        assert_eq!(holder.asked(), 4, "{how}");
        // Nor does it ask again while the earlier ask goes on.
        forced::pass(crate::chain::HELD_BACK_OFF);
        refuses(&writer, &path, "asked again soon")?;
        assert_eq!(holder.asked(), 4, "{how}");
        drop(impatient);
        // An answer that came late is not taken for one of now.
        holder.late(
            &writer,
            Some(crate::HeldState::default()),
            conflicting(&file_id),
        )?;
        writer.lose_view();
        forced::pass(second);
        if how == "followed" {
            writer.append(draft(9)).map_err(|e| e.to_string())?;
        } else {
            refuses(&writer, &path, "not the one the anchor holder holds")?;
        }
        assert_eq!(holder.asked(), 5, "{how}");
        let _ = std::fs::remove_dir_all(dir);
    }
    Ok(())
}

/// One that never answered and then hangs is not gone without either, not
/// even when it gives no answer after that; each back-off begins anew. The
/// first time it is asked, however long it takes, no answer is no holder, as
/// it always was.
#[test]
fn chain_a_holder_that_hangs_when_asked_again_is_no_missing_holder() -> TestResult {
    let dir = sandbox("held-never")?;
    let path = dir.join("audit-chain.jsonl");
    write(&path, 3)?;
    let whole = lines(&path)?;
    let (writer, holder) = hanging(&path)?;
    add_garbage(&path)?;
    refuses(&writer, &path, "not an audit event")?;
    assert_eq!(holder.asked(), 3, "a quick no answer costs nothing");
    rewrite(&path, &whole)?;
    for asked in [4, 5] {
        holder.set(None, true);
        let impatient = forced::Impatient::new();
        refuses(&writer, &path, "start the authority service")?;
        assert!(holder.is_asked(asked));
        drop(impatient);
        holder.late(&writer, None, None)?;
        refuses(&writer, &path, "asked again soon")?;
        forced::pass(crate::chain::HELD_BACK_OFF);
    }
    refuses(&writer, &path, "took too long to, and does not now")?;
    assert_eq!(holder.asked(), 8, "a quick no answer has no back-off");
    holder.set(Some(crate::HeldState::default()), false);
    writer.append(draft(9)).map_err(|e| e.to_string())?;
    assert_eq!(holder.asked(), 9);
    assert!(!holder.asked_by_this_thread());
    // The check is made: the next one is asked for without a bound again,
    // and at once also after a slow one.
    holder.set(None, false);
    holder.slow.store(true, Ordering::SeqCst);
    for asked in [10, 11] {
        writer.lose_view();
        writer.append(draft(asked)).map_err(|e| e.to_string())?;
        assert_eq!(holder.asked(), asked);
        assert!(holder.asked_by_this_thread());
    }
    // A slow one is not asked again at once by syncs that fail.
    let whole = lines(&path)?;
    let (writer, holder) = hanging(&path)?;
    holder.slow.store(true, Ordering::SeqCst);
    add_garbage(&path)?;
    let attempt = writer.append(draft(1));
    assert!(attempt.is_err());
    rewrite(&path, &whole)?;
    forced::pass(crate::chain::HELD_BACK_OFF);
    holder.slow.store(false, Ordering::SeqCst);
    writer.append(draft(11)).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

/// What a holder that was not given the time to answer, or not asked, would
/// have answered is not known: that it gives no answer later does not let an
/// append go unchecked. Nothing was read before in any of these.
#[test]
fn chain_an_answer_that_was_not_waited_for_is_not_gone_without() -> TestResult {
    for reset in [false, true] {
        for late in [false, true] {
            let dir = sandbox("held-missed")?;
            let path = dir.join("audit-chain.jsonl");
            write(&path, 3)?;
            let whole = lines(&path)?;
            let held = || match reset {
                true => resetting(&"e".repeat(64)),
                false => conflicting(&"f".repeat(64)),
            };
            let why = match reset {
                true => "does not start from that reset",
                false => "does not continue the file",
            };
            let (writer, holder) = hanging(&path)?;
            // Asked once, without an answer: promptly, or after a long time.
            holder.slow.store(!late, Ordering::SeqCst);
            rewrite(&path, &["garbage".to_owned()])?;
            assert!(writer.append(draft(1)).is_err());
            assert_eq!(holder.asked(), 1);
            holder.slow.store(false, Ordering::SeqCst);
            rewrite(&path, &whole)?;
            if late {
                holder.set(None, true);
                let _impatient = forced::Impatient::new();
                let error = writer.append(draft(1)).err().ok_or("no answer")?;
                assert!(error.to_string().contains("did not answer"), "{error}");
                assert!(holder.is_asked(2));
                holder.late(&writer, held(), None)?;
            } else {
                // It would answer now, and is not asked.
                holder.set(held(), false);
                refuses(&writer, &path, "asked again soon")?;
                assert_eq!(holder.asked(), 1);
                holder.set(None, false);
            }
            forced::pass(crate::chain::HELD_BACK_OFF);
            refuses(&writer, &path, "start the authority service")?;
            writer.lose_view();
            refuses(&writer, &path, "start the authority service")?;
            holder.set(held(), false);
            refuses(&writer, &path, why)?;
            let _ = std::fs::remove_dir_all(dir);
        }
    }
    Ok(())
}

/// A holder that panics is not one that took too long.
#[test]
fn chain_a_panicking_holder_is_reported_as_what_it_is() -> TestResult {
    struct Panics(AtomicU64);
    impl Anchorer for Panics {
        fn anchor(
            &self,
            _anchor: &AnchorRef,
            _link: Option<&ChainLink>,
            _reset: Option<&str>,
        ) -> AnchorOutcome {
            std::panic::panic_any("holder")
        }

        fn held(&self, _log: &str) -> Option<crate::HeldState> {
            match self.0.fetch_add(1, Ordering::SeqCst) {
                0 => None,
                1 => std::panic::panic_any("holder"),
                _ => resetting(&"e".repeat(64)),
            }
        }
    }
    let dir = sandbox("held-panics")?;
    let path = dir.join("audit-chain.jsonl");
    reset_file(&path, &"e".repeat(64))?;
    let whole = lines(&path)?;
    let writer = ChainWriter::open(&path, ORCELD_LOG).map_err(|e| e.to_string())?;
    writer.set_anchorer(Arc::new(Panics(AtomicU64::new(0))));
    add_garbage(&path)?;
    assert!(writer.append(draft(1)).is_err());
    rewrite(&path, &whole)?;
    let error = writer.append(draft(1)).err().ok_or("no answer")?;
    assert!(error.to_string().contains("panicked"), "{error}");
    // So it is when it panics asked to hold an opening.
    let error = writer.append(draft(1)).err().ok_or("not anchored")?;
    assert!(error.to_string().contains("panicked"), "{error}");
    assert_eq!(lines(&path)?, whole);
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

/// The holder's refusal of a due anchor stops the chain also when it could
/// not be recorded: the file cannot be read to its end, or not written.
#[test]
fn chain_a_refusal_that_cannot_be_recorded_stops_the_chain() -> TestResult {
    struct Spoils(PathBuf, bool);
    impl Anchorer for Spoils {
        fn anchor(
            &self,
            _anchor: &AnchorRef,
            _link: Option<&ChainLink>,
            _reset: Option<&str>,
        ) -> AnchorOutcome {
            if self.1 {
                read_only(&self.0, true).expect("read-only");
            } else {
                add_garbage(&self.0).expect("garbage");
            }
            AnchorOutcome::Refused {
                reason: "not this one".to_owned(),
            }
        }
    }
    fn read_only(path: &Path, on: bool) -> Result<(), String> {
        let mut permissions = std::fs::metadata(path)
            .map_err(|e| e.to_string())?
            .permissions();
        permissions.set_readonly(on);
        std::fs::set_permissions(path, permissions).map_err(|e| e.to_string())
    }
    for unwritable in [false, true] {
        let dir = sandbox("refusal-lost")?;
        let path = dir.join("audit-chain.jsonl");
        let writer = write(&path, ANCHOR_INTERVAL_EVENTS - 2)?;
        writer.set_anchorer(Arc::new(Spoils(path.clone(), unwritable)));
        let appended = writer.append(draft(90)).map_err(|e| e.to_string())?;
        if unwritable {
            read_only(&path, false)?;
            // The superuser writes to it all the same.
            if events(&path)?.len() as u64 > ANCHOR_INTERVAL_EVENTS {
                continue;
            }
        } else {
            let mut now = lines(&path)?;
            now.pop();
            rewrite(&path, &now)?;
        }
        assert!(matches!(appended.anchor, Some(Err(_))), "{appended:?}");
        refuses(&writer, &path, "refused this file: not this one")?;
        writer.lose_view();
        refuses(&writer, &path, "refused this file: not this one")?;
        let _ = std::fs::remove_dir_all(dir);
    }
    Ok(())
}

/// It does so too when the writer lost its view while the holder was asked:
/// after a check that passed, or when nothing of the file can be read.
#[test]
fn chain_a_refusal_stops_a_writer_that_lost_its_view() -> TestResult {
    struct Loses {
        writer: std::sync::OnceLock<std::sync::Weak<ChainWriter>>,
        garbage: bool,
    }
    impl Anchorer for Loses {
        fn anchor(
            &self,
            _anchor: &AnchorRef,
            _link: Option<&ChainLink>,
            _reset: Option<&str>,
        ) -> AnchorOutcome {
            let writer = self.writer.get().and_then(std::sync::Weak::upgrade);
            let writer = writer.expect("writer");
            writer.lose_view();
            if self.garbage {
                std::fs::write(writer.path(), b"garbage\n").expect("garbage");
                assert!(writer.append(draft(1)).is_err());
            }
            AnchorOutcome::Refused {
                reason: "not this one".to_owned(),
            }
        }

        fn held(&self, _log: &str) -> Option<crate::HeldState> {
            (!self.garbage).then(crate::HeldState::default)
        }
    }
    for garbage in [false, true] {
        let dir = sandbox("refusal-view")?;
        let path = dir.join("audit-chain.jsonl");
        let writer = Arc::new(write(&path, ANCHOR_INTERVAL_EVENTS - 3)?);
        let holder = Arc::new(Loses {
            writer: std::sync::OnceLock::new(),
            garbage,
        });
        let _ = holder.writer.set(Arc::downgrade(&writer));
        writer.set_anchorer(holder);
        writer.append(draft(89)).map_err(|e| e.to_string())?;
        let mut whole = lines(&path)?;
        let appended = writer.append(draft(90)).map_err(|e| e.to_string())?;
        assert_eq!(appended.event.seq + 1, ANCHOR_INTERVAL_EVENTS);
        assert_eq!(matches!(appended.anchor, Some(Ok(_))), !garbage);
        if garbage {
            let last = serde_json::to_string(&appended.event).map_err(|e| e.to_string())?;
            whole.push(last);
            rewrite(&path, &whole)?;
        }
        refuses(&writer, &path, "refused this file: not this one")?;
        let _ = std::fs::remove_dir_all(dir);
    }
    Ok(())
}

/// A file that continues a refused one is judged by itself.
#[test]
fn chain_a_followed_file_is_not_refused_for_the_one_before() -> TestResult {
    let dir = sandbox("followed-refused")?;
    let path = dir.join("audit-chain.jsonl");
    write(&path, 3)?;
    let (writer, _) = held_by(&path, conflicting(&events(&path)?[0].digest))?;
    refuses(&writer, &path, "not the one the anchor holder holds")?;
    // It links past the held record, which is all the holder can say.
    let moved = move_aside(&path, ORCELD_LOG).map_err(|e| e.to_string())?;
    let appended = writer.append(draft(1)).map_err(|e| e.to_string())?;
    assert_eq!(appended.at.file_id, moved.file_id);
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

/// Syncs that fail read what earlier ones read again only once they got to
/// the end, and before anything is cut from the file.
#[test]
fn chain_records_read_before_are_compared_before_a_tail_is_cut() -> TestResult {
    let dir = sandbox("compare-cut")?;
    let path = dir.join("audit-chain.jsonl");
    write(&path, 3)?;
    let whole = lines(&path)?;
    let (writer, _) = held_by(&path, Some(crate::HeldState::default()))?;
    add_garbage(&path)?;
    refuses(&writer, &path, "not an audit event")?;
    rewrite(&path, &whole[..1])?;
    let other = ChainWriter::open(&path, ORCELD_LOG).map_err(|e| e.to_string())?;
    for n in 4..7 {
        other.append(draft(n)).map_err(|e| e.to_string())?;
    }
    let mut bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
    bytes.extend_from_slice(b"{\"torn");
    std::fs::write(&path, bytes).map_err(|e| e.to_string())?;
    refuses(&writer, &path, "not the ones this writer read")?;
    assert_eq!(kept_files(&dir)?, Vec::<String>::new());
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}
