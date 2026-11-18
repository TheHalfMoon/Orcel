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

use orcel_audit::{AnchorOutcome, Anchorer, ChainWriter};
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
    fn anchor(&self, anchor: &AnchorRef) -> AnchorOutcome {
        let answer = AuthorityClient::installed().and_then(|client| client.anchor(anchor));
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

/// `orceld audit-verify [--chain <path>]`: verifies the chain and prints the
/// report as JSON. `None` when `args` is not this command.
pub(crate) fn run_cli(args: &[String]) -> Option<i32> {
    if args.first().map(String::as_str) != Some("audit-verify") {
        return None;
    }
    let path = match args.get(1..).unwrap_or_default() {
        [] => default_chain(),
        [flag, path] if flag == "--chain" => Ok(PathBuf::from(path)),
        _ => Err("usage: orceld audit-verify [--chain <path>]".to_owned()),
    };
    let path = match path {
        Ok(path) => path,
        Err(message) => {
            eprintln!("orceld audit-verify: {message}");
            return Some(EXIT_USAGE);
        }
    };
    Some(match verify(&path) {
        Ok((text, code)) => {
            println!("{text}");
            code
        }
        Err(message) => {
            eprintln!("orceld audit-verify: {message}");
            EXIT_USAGE
        }
    })
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

        let args = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert_eq!(run_cli(&args(&["authority-status"])), None);
        assert_eq!(
            run_cli(&args(&["audit-verify", "--chain"])),
            Some(EXIT_USAGE)
        );
        let chain_arg = chain.display().to_string();
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
        assert_eq!(report.anchors_local + report.anchors_external, 1);
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
}
