//! Verifying a chain file (spec 4.8, WP1-03): every record is recomputed
//! and checked against the one before; every `anchor` record must name a
//! record of this file with that record's digest; anchors held outside the
//! file ([`verify_with_anchors`]) must match the record they name, and one
//! naming a record past the file's end means the file was cut.
//!
//! What the file alone cannot show is said in the report's
//! `tamper_evidence`: without an anchor held outside the session, a rewrite
//! of the whole file, or a cut of whole records at its end, verifies.

use crate::anchor::UNANCHORED_NOTE;
use crate::chain::{anchor_due, Scanner, Step};
use orcel_contracts::event::{AnchorRef, AuditEventKind, GENESIS_PREV_DIGEST};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufReader};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Every record chains and every anchor matches.
    Intact,
    /// Every whole record chains; the file ends in a torn line, which the
    /// next append quarantines and records.
    TornTail,
    /// A record or an anchor does not verify.
    Broken,
    /// There is no chain file.
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BreakInfo {
    /// 1-based line of the file.
    pub line: u64,
    /// The seq the chain expected there.
    pub seq: u64,
    pub reason: String,
}

/// An anchor held outside the file, checked against it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnchorCheck {
    pub seq: u64,
    pub digest: String,
    /// `match`, `conflict` (the record there has another digest),
    /// `beyond_end` (the file was cut) or `other_file`.
    pub result: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifyReport {
    pub path: String,
    pub verdict: Verdict,
    /// Whole records that chain.
    pub events: u64,
    pub file_id: Option<String>,
    pub head_seq: Option<u64>,
    pub head_digest: Option<String>,
    pub broken: Option<BreakInfo>,
    pub torn_tail_bytes: u64,
    /// Torn tails earlier appends moved aside (recorded in the chain).
    pub quarantined_tails: u64,
    /// Anchor records whose anchor is held outside the session.
    pub anchors_external: u64,
    /// Anchor records that are local markers only.
    pub anchors_local: u64,
    pub last_external_anchor_seq: Option<u64>,
    /// Anchors supplied by the caller, checked.
    pub anchor_checks: Vec<AnchorCheck>,
    pub tamper_evidence: String,
}

/// [`verify_with_anchors`] with no anchor held outside the file.
pub fn verify_file(path: &Path) -> io::Result<VerifyReport> {
    verify_with_anchors(path, &[])
}

/// Verifies the chain at `path`, and `held` (anchors kept outside the
/// file, such as the authority service's) against it.
pub fn verify_with_anchors(path: &Path, held: &[AnchorRef]) -> io::Result<VerifyReport> {
    let mut report = VerifyReport {
        path: path.display().to_string(),
        verdict: Verdict::Intact,
        events: 0,
        file_id: None,
        head_seq: None,
        head_digest: None,
        broken: None,
        torn_tail_bytes: 0,
        quarantined_tails: 0,
        anchors_external: 0,
        anchors_local: 0,
        last_external_anchor_seq: None,
        anchor_checks: Vec::new(),
        tamper_evidence: String::new(),
    };
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            report.verdict = Verdict::Missing;
            report.tamper_evidence = "no chain file".to_owned();
            return Ok(report);
        }
        Err(error) => return Err(error),
    };
    // Digests of the records an anchor may name: anchor-due records, and
    // any record a held anchor names.
    let wanted: Vec<u64> = held.iter().map(|anchor| anchor.seq).collect();
    let mut digests: BTreeMap<u64, String> = BTreeMap::new();
    let mut by = String::new();
    let mut scanner = Scanner::new(
        BufReader::new(file),
        0,
        GENESIS_PREV_DIGEST.to_owned(),
        None,
    );
    let mut line = 0u64;
    loop {
        line += 1;
        let event = match scanner.step()? {
            Step::Event(event, _) => event,
            Step::End => break,
            Step::Torn(bytes) => {
                report.torn_tail_bytes = bytes.len() as u64;
                report.verdict = Verdict::TornTail;
                break;
            }
            Step::Broken(reason) => {
                report.broken = Some(BreakInfo {
                    line,
                    seq: scanner.next_seq,
                    reason,
                });
                report.verdict = Verdict::Broken;
                break;
            }
        };
        if anchor_due(&event) || wanted.contains(&event.seq) {
            digests.insert(event.seq, event.digest.clone());
        }
        if event.kind == AuditEventKind::Rotation
            && event.detail["action"] == "quarantined_torn_tail"
        {
            report.quarantined_tails += 1;
        }
        if event.kind == AuditEventKind::Anchor {
            let anchor = &event.detail["anchor"];
            let named = anchor["seq"].as_u64();
            let matches = named.is_some_and(|seq| {
                seq < event.seq
                    && anchor["file_id"].as_str() == scanner.file_id.as_deref()
                    && anchor["digest"].as_str() == digests.get(&seq).map(String::as_str)
            });
            if !matches {
                report.broken = Some(BreakInfo {
                    line,
                    seq: event.seq,
                    reason: "an anchor record names a record this file does not hold".to_owned(),
                });
                report.verdict = Verdict::Broken;
                break;
            }
            if event.detail["status"] == "anchored" {
                report.anchors_external += 1;
                report.last_external_anchor_seq = named;
                event.detail["by"]
                    .as_str()
                    .unwrap_or_default()
                    .clone_into(&mut by);
            } else {
                report.anchors_local += 1;
            }
        }
    }
    report.events = scanner.next_seq;
    report.file_id = scanner.file_id.clone();
    if scanner.next_seq > 0 {
        report.head_seq = Some(scanner.next_seq - 1);
        report.head_digest = Some(scanner.head.clone());
    }
    for anchor in held {
        let result = if Some(&anchor.file_id) != report.file_id.as_ref() {
            "other_file"
        } else if anchor.seq >= report.events {
            "beyond_end"
        } else if digests.get(&anchor.seq) == Some(&anchor.digest) {
            "match"
        } else {
            "conflict"
        };
        if matches!(result, "beyond_end" | "conflict") && report.broken.is_none() {
            report.broken = Some(BreakInfo {
                line: 0,
                seq: anchor.seq,
                reason: if result == "beyond_end" {
                    "a held anchor names a record past the file's end (the file was cut)"
                } else {
                    "a held anchor conflicts with the record it names"
                }
                .to_owned(),
            });
            report.verdict = Verdict::Broken;
        }
        report.anchor_checks.push(AnchorCheck {
            seq: anchor.seq,
            digest: anchor.digest.clone(),
            result,
        });
    }
    report.tamper_evidence = match report.last_external_anchor_seq {
        Some(seq) => format!(
            "anchored outside the session up to seq {seq} by {by}; a cut or rewrite is evident \
             against the holder's copy of an anchor (Event Log read-back is not in this slice), \
             records after seq {seq} only against the next anchor"
        ),
        None => UNANCHORED_NOTE.to_owned(),
    };
    Ok(report)
}
