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

    /// What the installed service holds of this account's chain; `None`
    /// when the service is absent or does not answer (the chain is then
    /// unanchored and says so).
    fn held(&self, log: &str) -> Option<AnchorRef> {
        let answer = AuthorityClient::installed()
            .and_then(|client| client.anchor_status(log))
            .ok()?;
        held_of(&answer)
    }
}

/// The held anchor in an `AnchorStatus` answer.
fn held_of(answer: &serde_json::Value) -> Option<AnchorRef> {
    serde_json::from_value(answer.get("held")?.clone()).ok()
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
        // A rule refusal (an unlinked file, a rewrite, a file the log left)
        // fails the chain closed; anything else leaves it unanchored.
        Err(error)
            if error
                .message
                .starts_with(orcel_authority::core::chain_anchor::REFUSED_PREFIX) =>
        {
            AnchorOutcome::Refused {
                reason: error.message,
            }
        }
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
        verify_with_held(&path, ServiceAnchorer.held(orcel_audit::ORCELD_LOG))
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

/// The report as JSON text and the exit code it earns, checked against
/// `held`, the anchor the authority service holds (when it is present): a
/// chain replaced by a fresh file is then Broken, not Intact.
pub(crate) fn verify_with_held(
    path: &std::path::Path,
    held: Option<AnchorRef>,
) -> Result<(String, i32), String> {
    let report = orcel_audit::verify_with_anchors(path, held.as_slice())
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    let code = match report.verdict {
        orcel_audit::Verdict::Intact => EXIT_INTACT,
        orcel_audit::Verdict::TornTail => EXIT_TORN_TAIL,
        orcel_audit::Verdict::Broken => EXIT_BROKEN,
        orcel_audit::Verdict::Missing => EXIT_MISSING,
        orcel_audit::Verdict::Recovered => EXIT_RECOVERED,
        orcel_audit::Verdict::Truncated => EXIT_TRUNCATED,
    };
    let mut value =
        serde_json::to_value(&report).map_err(|error| format!("encode the report: {error}"))?;
    if let serde_json::Value::Object(map) = &mut value {
        map.insert(
            "held_anchor_source".into(),
            serde_json::Value::from(if held.is_some() {
                SERVICE_HOLDER
            } else {
                "none: the authority service is absent or holds no anchor of this chain; \
                 anchor records in the file are claims only"
            }),
        );
    }
    let text = serde_json::to_string_pretty(&value)
        .map_err(|error| format!("encode the report: {error}"))?;
    Ok((text, code))
}

#[cfg(test)]
mod tests {
    use super::*;
    use orcel_audit::AuditLogger;
    use orcel_contracts::RequestEnvelope;
    use serde_json::{json, Value};

    fn verify(path: &std::path::Path) -> Result<(String, i32), String> {
        verify_with_held(path, None)
    }

    /// A holder that holds one anchor and answers it, as the service does.
    struct Holds(AnchorRef);

    impl Anchorer for Holds {
        fn anchor(&self, _anchor: &AnchorRef, _link: Option<&ChainLink>) -> AnchorOutcome {
            AnchorOutcome::Unanchored {
                reason: "test".to_owned(),
            }
        }
        fn held(&self, _log: &str) -> Option<AnchorRef> {
            Some(self.0.clone())
        }
    }

    /// Re-review: with the service holding an anchor, a chain deleted and
    /// reopened fresh verifies Broken, and after a restart every dispatch
    /// is refused (fail closed).
    #[test]
    fn audit_chain_a_deleted_chain_is_broken_and_refuses_dispatch_when_anchors_are_held(
    ) -> Result<(), String> {
        let dir = sandbox("deleted")?;
        let plain = dir.join("audit.jsonl");
        let logger = AuditLogger::new(&plain).map_err(|e| e.to_string())?;
        let mut last = None;
        for n in 0..3 {
            last = Some(
                logger
                    .chain()
                    .append(orcel_audit::EventDraft::new(
                        orcel_contracts::event::AuditEventKind::Request,
                        json!({"n": n}),
                    ))
                    .map_err(|e| e.to_string())?,
            );
        }
        let held = last.ok_or("records")?.at;
        let chain = logger.chain().path().to_path_buf();
        assert_eq!(verify_with_held(&chain, Some(held.clone()))?.1, EXIT_INTACT);
        std::fs::remove_file(&chain).map_err(|e| e.to_string())?;
        // A restarted orceld: a new logger whose anchor holder holds the
        // old file's anchor.
        let restarted = AuditLogger::new(&plain).map_err(|e| e.to_string())?;
        restarted
            .chain()
            .set_anchorer(std::sync::Arc::new(Holds(held.clone())));
        let refused = crate::audit_before_dispatch(&restarted, &request(7), "p1")
            .err()
            .ok_or("the dispatch should be refused")?;
        let error = refused.error.ok_or("an error")?;
        assert!(
            error.message.contains("does not continue"),
            "{}",
            error.message
        );
        let (text, code) = verify_with_held(&chain, Some(held))?;
        assert_eq!(code, EXIT_BROKEN, "{text}");
        assert!(text.contains("unlinked_file"));
        assert!(text.contains(SERVICE_HOLDER));
        // Without a held anchor the same file only verifies as claims.
        let (text, code) = verify(&chain)?;
        assert_eq!(code, EXIT_INTACT, "{text}");
        assert!(text.contains("claims only"));
        let _ = std::fs::remove_dir_all(dir);
        Ok(())
    }

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
        // A new orceld continues the linked file (the logger above verified
        // records the new file does not keep, so it refuses).
        AuditLogger::new(dir.join("audit.jsonl"))
            .map_err(|e| e.to_string())?
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
        let refused = outcome(Err(orcel_authority::AuthorityError::denied(format!(
            "{}the chain file does not link",
            orcel_authority::core::chain_anchor::REFUSED_PREFIX
        ))));
        assert!(
            matches!(refused, AnchorOutcome::Refused { .. }),
            "{refused:?}"
        );
        let rate = outcome(Err(orcel_authority::AuthorityError::denied(
            "more than 120 anchors of this log in a minute",
        )));
        assert!(matches!(rate, AnchorOutcome::Unanchored { .. }));
        assert_eq!(held_of(&json!({"held": null})), None);
        assert_eq!(
            held_of(&json!({"held": {"log": "orceld", "file_id": "a", "seq": 3, "digest": "b"}}))
                .map(|held| held.seq),
            Some(3)
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

    /// Every call to a dispatch function (any `dispatch*` function or
    /// `authorize_enrollment`) inside one of orceld's request entry points
    /// (any `handle_*` function), discovered by scanning the source, is
    /// preceded by the write-before-dispatch guard in the same function. A
    /// new entry point or call site without it fails here.
    #[test]
    fn audit_chain_every_dispatch_site_writes_its_record_first() {
        let main = include_str!("sg000039_main.rs");
        let report = include_str!("report_task.rs");
        let mut found = 0;
        for (file, source) in [("sg000039_main.rs", main), ("report_task.rs", report)] {
            let production = source
                .split("\n#[cfg(test)]\nmod tests {")
                .next()
                .unwrap_or_default();
            let mut function = String::new();
            let mut body: Vec<&str> = Vec::new();
            for line in production.lines() {
                let top = ["fn ", "pub fn ", "pub(crate) fn ", "pub(super) fn "]
                    .iter()
                    .find_map(|prefix| line.strip_prefix(prefix));
                if let Some(rest) = top {
                    function = rest
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect();
                    body.clear();
                }
                if function.starts_with("handle_") {
                    for call in dispatch_calls(line) {
                        found += 1;
                        let recent = &body[body.len().saturating_sub(12)..];
                        assert!(
                            recent.iter().any(|line| line.contains("audit_before_dispatch(")),
                            "{file}: {function} calls {call} without writing its dispatch record first"
                        );
                    }
                }
                body.push(line);
            }
        }
        assert!(
            found >= 8,
            "only {found} dispatch sites were found; the scan is broken"
        );
    }

    /// The dispatch functions `line` calls (not defines).
    fn dispatch_calls(line: &str) -> Vec<String> {
        let code = line.split("//").next().unwrap_or_default();
        let mut calls = Vec::new();
        let mut word = String::new();
        let mut previous = String::new();
        for c in code.chars().chain(std::iter::once(' ')) {
            if c.is_alphanumeric() || c == '_' {
                word.push(c);
                continue;
            }
            if !word.is_empty() {
                if c == '('
                    && previous != "fn"
                    && (word.starts_with("dispatch") || word == "authorize_enrollment")
                {
                    calls.push(word.clone());
                }
                previous = std::mem::take(&mut word);
            }
        }
        calls
    }
}
