//! WP1-03: orceld's hash-chained audit log.
//!
//! Every `AuditLogger` record is written first to the chain beside the
//! plain log (`orcel_audit::chain`), with no flag: it is an append-only log
//! and the plain log keeps its lines. This module gives the chain its
//! anchor holder, shares it with the browser broker's receipts (OB-05 step
//! 1), and serves `orceld audit-verify`.
//!
//! Anchors: every 32 events the chain asks [`ServiceAnchorer`], which asks
//! the installed authority service (SG-000132) to hold `(log, file id, seq,
//! digest)`; the service records it in its own chain and writes Event Log
//! event 4100 under its registered source. Where the service is absent or
//! refuses, the chain records a local marker that says `unanchored`; orceld
//! never calls its chain tamper-proof without the service.

use orcel_audit::{AnchorOutcome, Anchorer, ChainLink, ChainWriter};
use orcel_authority::client::AuthorityClient;
use orcel_contracts::event::AnchorRef;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

/// What the receipts of the browser broker are chained to (set once at
/// start; `None` in tests and before start).
static CHAIN: OnceLock<Arc<ChainWriter>> = OnceLock::new();

/// orceld's chain, once [`install`] ran. Its one caller is the live browser
/// broker, which only the Windows development build compiles, so other builds
/// leave it unused (the release sweep keeps that feature's name to its listed files).
#[allow(dead_code)]
pub(crate) fn shared() -> Option<Arc<ChainWriter>> {
    CHAIN.get().cloned()
}

/// Gives `chain` its anchor holder and shares it for the browser broker.
pub(crate) fn install(chain: &Arc<ChainWriter>) {
    chain.set_anchorer(Arc::new(ServiceAnchorer));
    let _ = CHAIN.set(Arc::clone(chain));
}

/// The installed authority service, asked per anchor (it may be installed,
/// started or stopped while orceld runs).
pub(crate) struct ServiceAnchorer;

/// Who holds an anchor the service accepted, as the chain records it.
pub(crate) const SERVICE_HOLDER: &str =
    "Orcel authority service (its audit chain and Event Log event 4100)";

impl Anchorer for ServiceAnchorer {
    fn anchor(&self, anchor: &AnchorRef, link: Option<&ChainLink>) -> AnchorOutcome {
        let link = link.map(|link| orcel_authority::protocol::ChainLink {
            previous_file_id: link.previous_file_id.clone(),
            previous_head_seq: link.previous_head_seq,
            previous_head_digest: link.previous_head_digest.clone(),
        });
        let answer = AuthorityClient::installed().and_then(|client| client.anchor(anchor, link));
        outcome(answer)
    }
}

fn outcome(answer: Result<serde_json::Value, orcel_authority::AuthorityError>) -> AnchorOutcome {
    match answer {
        Ok(receipt) if receipt["anchored"] == true => AnchorOutcome::Anchored {
            by: SERVICE_HOLDER.to_owned(),
            receipt,
        },
        Ok(other) => AnchorOutcome::Unanchored {
            reason: format!("the authority service did not confirm the anchor: {other}"),
        },
        Err(error) => AnchorOutcome::Unanchored {
            reason: format!("authority service: {error}"),
        },
    }
}

/// The chain `orceld audit-verify` reads by default: beside the audit log.
fn default_chain() -> Result<PathBuf, String> {
    orcel_audit::default_audit_path()
        .map(|plain| orcel_audit::chain_path_for(&plain))
        .map_err(|error| format!("resolve the audit log: {error}"))
}

/// Exit codes of `orceld audit-verify`.
pub(crate) const EXIT_INTACT: i32 = 0;
pub(crate) const EXIT_USAGE: i32 = 2;
pub(crate) const EXIT_TORN_TAIL: i32 = 3;
pub(crate) const EXIT_BROKEN: i32 = 4;
pub(crate) const EXIT_MISSING: i32 = 5;
pub(crate) const EXIT_RECOVERED: i32 = 6;
pub(crate) const EXIT_TRUNCATED: i32 = 7;

/// `orceld audit-verify [--chain <path>]` verifies the chain and prints the
/// report as JSON; `orceld audit-move-aside [--chain <path>]` keeps a chain
/// that does not verify and opens a new file linked to its last verifiable
/// record (the operator's recovery when every dispatch is refused). `None`
/// when `args` is neither command.
pub(crate) fn run_cli(args: &[String]) -> Option<i32> {
    let command = args.first().map(String::as_str)?;
    if command != "audit-verify" && command != "audit-move-aside" {
        return None;
    }
    let path = match args.get(1..).unwrap_or_default() {
        [] => default_chain(),
        [flag, path] if flag == "--chain" => Ok(PathBuf::from(path)),
        _ => Err(format!("usage: orceld {command} [--chain <path>]")),
    };
    let path = match path {
        Ok(path) => path,
        Err(message) => {
            eprintln!("orceld {command}: {message}");
            return Some(EXIT_USAGE);
        }
    };
    let result = if command == "audit-verify" {
        verify(&path)
    } else {
        move_aside(&path)
    };
    Some(match result {
        Ok((text, code)) => {
            println!("{text}");
            code
        }
        Err(message) => {
            eprintln!("orceld {command}: {message}");
            EXIT_USAGE
        }
    })
}

/// Moves the chain at `path` aside and opens the linked file.
pub(crate) fn move_aside(path: &std::path::Path) -> Result<(String, i32), String> {
    let moved = orcel_audit::move_aside(path, orcel_audit::ORCELD_LOG)
        .map_err(|error| error.to_string())?;
    let text = serde_json::to_string_pretty(&serde_json::json!({
        "moved_to": moved.moved_to,
        "new_file_id": moved.file_id,
        "previous_file_id": moved.link.as_ref().map(|link| link.previous_file_id.clone()),
        "previous_head_seq": moved.link.as_ref().map(|link| link.previous_head_seq),
        "note": "the old file is kept beside the chain; the new file continues it from its \
                 last verifiable record (not a clean slate)",
    }))
    .map_err(|error| format!("encode the result: {error}"))?;
    Ok((text, EXIT_INTACT))
}

/// The report as JSON text and the exit code it earns.
pub(crate) fn verify(path: &std::path::Path) -> Result<(String, i32), String> {
    let report = orcel_audit::verify_file(path)
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    let code = match report.verdict {
        orcel_audit::Verdict::Intact => EXIT_INTACT,
        orcel_audit::Verdict::TornTail => EXIT_TORN_TAIL,
        orcel_audit::Verdict::Broken => EXIT_BROKEN,
        orcel_audit::Verdict::Missing => EXIT_MISSING,
        orcel_audit::Verdict::Recovered => EXIT_RECOVERED,
        orcel_audit::Verdict::Truncated => EXIT_TRUNCATED,
    };
    let text = serde_json::to_string_pretty(&report)
        .map_err(|error| format!("encode the report: {error}"))?;
    Ok((text, code))
}

#[cfg(test)]
mod tests {
    use super::*;
    use orcel_audit::AuditLogger;
    use orcel_contracts::RequestEnvelope;
    use serde_json::{json, Value};

    fn sandbox(label: &str) -> Result<PathBuf, String> {
        let dir = std::env::temp_dir().join(format!(
            "orceld-audit-chain-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        Ok(dir)
    }

    fn request(n: u64) -> RequestEnvelope {
        RequestEnvelope {
            version: 1,
            request_id: format!("r-{n}"),
            client_session_id: "s".into(),
            workspace_id: "w".into(),
            capability: "fs.search".into(),
            operation: "search".into(),
            target: Some(".".into()),
            arguments: json!({"query": "SECRET-ARGUMENT"}),
        }
    }

    /// The verify command reports an intact chain, a torn tail, a broken
    /// chain and a missing one with their own exit codes.
    #[test]
    fn audit_chain_verify_cli_reports_each_verdict() -> Result<(), String> {
        let dir = sandbox("cli")?;
        let logger = AuditLogger::new(dir.join("audit.jsonl")).map_err(|e| e.to_string())?;
        for n in 0..3 {
            logger
                .record(&request(n), "p1", "SUCCESS")
                .map_err(|e| e.to_string())?;
        }
        let chain = logger.chain().path().to_path_buf();
        let args = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        let (text, code) = verify(&chain)?;
        assert_eq!(code, EXIT_INTACT, "{text}");
        let report: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
        assert_eq!(report["verdict"], "intact");
        assert_eq!(report["events"], 4);
        assert!(report["tamper_evidence"]
            .as_str()
            .is_some_and(|text| text.starts_with("local marker only")));
        assert!(!text.contains("SECRET-ARGUMENT"));

        let original = std::fs::read_to_string(&chain).map_err(|e| e.to_string())?;
        std::fs::write(&chain, format!("{original}{{\"torn")).map_err(|e| e.to_string())?;
        assert_eq!(verify(&chain)?.1, EXIT_TORN_TAIL);
        std::fs::write(&chain, original.replacen("r-1", "r-9", 1)).map_err(|e| e.to_string())?;
        let (text, code) = verify(&chain)?;
        assert_eq!(code, EXIT_BROKEN, "{text}");
        assert_eq!(verify(&dir.join("absent.jsonl"))?.1, EXIT_MISSING);
        // The operator's recovery: the broken file is kept and a linked file
        // opens; the chain then verifies and accepts records again.
        let chain_arg = chain.display().to_string();
        assert_eq!(
            run_cli(&args(&["audit-move-aside", "--chain", &chain_arg])),
            Some(EXIT_INTACT)
        );
        let (text, code) = verify(&chain)?;
        assert_eq!(code, EXIT_INTACT, "{text}");
        let report: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
        assert_eq!(report["previous_head_seq"], 1, "the last verifiable record");
        logger
            .record(&request(9), "p1", "SUCCESS")
            .map_err(|e| e.to_string())?;
        std::fs::write(&chain, original.replacen("r-1", "r-9", 1)).map_err(|e| e.to_string())?;

        assert_eq!(run_cli(&args(&["authority-status"])), None);
        assert_eq!(
            run_cli(&args(&["audit-verify", "--chain"])),
            Some(EXIT_USAGE)
        );
        assert_eq!(
            run_cli(&args(&["audit-verify", "--chain", &chain_arg])),
            Some(EXIT_BROKEN)
        );
        let _ = std::fs::remove_dir_all(dir);
        Ok(())
    }

    /// Without the service the anchor is a local marker that says so; the
    /// service's answer is recorded only when it confirms.
    #[test]
    fn audit_chain_anchor_outcome_never_overclaims() {
        let absent = outcome(Err(orcel_authority::AuthorityError::unavailable(
            "the Orcel authority service is not installed",
        )));
        assert!(
            matches!(&absent, AnchorOutcome::Unanchored { reason } if reason.contains("not installed")),
            "{absent:?}"
        );
        let unconfirmed = outcome(Ok(json!({"anchored": false})));
        assert!(matches!(unconfirmed, AnchorOutcome::Unanchored { .. }));
        let held = outcome(Ok(
            json!({"anchored": true, "event_id": 4100, "authority_seq": 9}),
        ));
        assert!(
            matches!(&held, AnchorOutcome::Anchored { by, receipt } if by == SERVICE_HOLDER && receipt["authority_seq"] == 9),
            "{held:?}"
        );
    }

    /// The anchorer orceld installs reaches the installed service only; on
    /// a machine without it (every test runner) the 32nd event's anchor is
    /// recorded as unanchored, and the chain still verifies.
    #[test]
    fn audit_chain_anchor_without_the_service_is_a_local_marker() -> Result<(), String> {
        let dir = sandbox("anchor")?;
        let chain = Arc::new(
            ChainWriter::open(dir.join("audit-chain.jsonl"), orcel_audit::ORCELD_LOG)
                .map_err(|e| e.to_string())?,
        );
        chain.set_anchorer(Arc::new(ServiceAnchorer));
        let mut anchored = None;
        for n in 0..orcel_contracts::event::ANCHOR_INTERVAL_EVENTS {
            let appended = chain
                .append(orcel_audit::EventDraft::new(
                    orcel_contracts::event::AuditEventKind::Request,
                    json!({"n": n}),
                ))
                .map_err(|e| e.to_string())?;
            if appended.anchor.is_some() {
                anchored = appended.anchor;
            }
        }
        match anchored {
            Some(Ok(AnchorOutcome::Unanchored { .. })) => {}
            // A runner with the service installed and orceld trusted.
            Some(Ok(AnchorOutcome::Anchored { by, .. })) => assert_eq!(by, SERVICE_HOLDER),
            other => return Err(format!("no anchor outcome: {other:?}")),
        }
        let report = orcel_audit::verify_file(chain.path()).map_err(|e| e.to_string())?;
        assert_eq!(report.verdict, orcel_audit::Verdict::Intact);
        assert_eq!(report.anchors_local + report.anchors_claimed, 1);
        let _ = std::fs::remove_dir_all(dir);
        Ok(())
    }

    /// The policy protects the chain beside an audit override by the same
    /// naming rule the chain writer uses.
    #[test]
    fn wp103_policy_protects_the_chain_beside_an_audit_override() {
        for plain in ["/a/audit.jsonl", "/a/custom.log", "/a/x"] {
            let plain = std::path::Path::new(plain);
            assert_eq!(
                orcel_policy::protected_state::audit_chain_beside(plain),
                orcel_audit::chain_path_for(plain)
            );
        }
    }
    /// Spec 4.8 write before dispatch: the guard writes the dispatch record
    /// first, and a chain that cannot be written refuses the request with
    /// nothing dispatched (the refusal is still in the plain log).
    #[test]
    fn audit_chain_dispatch_is_refused_when_the_record_fails() -> Result<(), String> {
        let dir = sandbox("before-dispatch")?;
        let plain = dir.join("audit.jsonl");
        let logger = AuditLogger::new(&plain).map_err(|e| e.to_string())?;
        crate::audit_before_dispatch(&logger, &request(1), "p1")
            .map_err(|refused| format!("{:?}", refused.error))?;
        let chain = logger.chain().path().to_path_buf();
        let text = std::fs::read_to_string(&chain).map_err(|e| e.to_string())?;
        assert!(text.contains("\"kind\":\"dispatch\""), "{text}");
        assert!(text.contains("before_dispatch"));
        std::fs::write(&chain, text.replacen("r-1", "r-7", 1)).map_err(|e| e.to_string())?;
        let fresh = AuditLogger::new(&plain).map_err(|e| e.to_string())?;
        let refused = crate::audit_before_dispatch(&fresh, &request(2), "p1")
            .err()
            .ok_or("the dispatch should be refused")?;
        let error = refused.error.ok_or("an error")?;
        assert_eq!(error.code, orcel_contracts::FailureCode::InternalError);
        assert!(
            error.message.contains("nothing was dispatched"),
            "{}",
            error.message
        );
        assert!(
            error.message.contains("audit-move-aside"),
            "{}",
            error.message
        );
        let plain_text = std::fs::read_to_string(&plain).map_err(|e| e.to_string())?;
        assert!(plain_text.contains("AUDIT_REFUSED"), "{plain_text}");
        let _ = std::fs::remove_dir_all(dir);
        Ok(())
    }

    /// Every dispatch call in orceld's request path is preceded by the
    /// write-before-dispatch guard.
    #[test]
    fn audit_chain_every_dispatch_site_writes_its_record_first() {
        let main = include_str!("sg000039_main.rs");
        let production = main
            .split("#[cfg(test)]\nmod tests {")
            .next()
            .unwrap_or_default();
        let report = include_str!("report_task.rs");
        for (source, call) in [
            (production, "remote_lease::authorize_enrollment("),
            (production, "executable_admin::dispatch_registry("),
            (production, "remote_lease::dispatch_lease_management("),
            (production, "secret_store::dispatch("),
            (production, "live_dispatch::dispatch(&"),
            (production, "live_dispatch::dispatch_full("),
            (production, "let result = dispatch_with("),
            (report, "match dispatch(&decision.workspace"),
        ] {
            let lines: Vec<&str> = source.lines().collect();
            let sites: Vec<usize> = lines
                .iter()
                .enumerate()
                .filter(|(_, line)| line.contains(call))
                .map(|(index, _)| index)
                .collect();
            assert_eq!(sites.len(), 1, "{call}");
            let before = &lines[sites[0].saturating_sub(12)..sites[0]];
            assert!(
                before
                    .iter()
                    .any(|line| line.contains("audit_before_dispatch(")),
                "{call} runs without its dispatch record first"
            );
        }
    }
}
