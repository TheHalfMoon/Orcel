//! Verifying a chain file (spec 4.8, WP1-03): every record is recomputed
//! and checked against the one before; the opening record's link to the
//! file it follows is reported; every `anchor` record must name a record of
//! this file with that record's digest; anchors held outside the file
//! ([`verify_with_anchors`]) must match the record they name.
//!
//! Anchor records in the file are claims the writer made about what the
//! authority service answered: the report counts them as claimed, and only
//! a held anchor that matches makes one verified. What the file alone
//! cannot show is said in the report's `tamper_evidence`.

use crate::anchor::UNANCHORED_NOTE;
use crate::chain::{anchor_due, ChainLink, Scanner, Step, LINK_REFUSED, NO_PREVIOUS_FILE};
use orcel_contracts::event::{AnchorRef, AuditEventKind};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufReader};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Every record chains and every anchor matches.
    Intact,
    /// As intact, and the writer cut a torn tail (a crash mid-write) at
    /// least once; each cut is a recorded event naming the bytes it moved
    /// aside.
    Recovered,
    /// Every whole record chains; the file ends in a torn line, which the
    /// next append quarantines and records.
    TornTail,
    /// Every record present chains, but a held anchor names a record past
    /// the file's end (or past the head the file says it follows): whole
    /// records were cut.
    Truncated,
    /// A record, an anchor record, or a held anchor does not verify, or a
    /// held anchor names a file this one does not link to.
    Broken,
    /// There is no chain file.
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BreakInfo {
    /// 1-based line of the file; 0 for a held anchor.
    pub line: u64,
    /// The seq the chain expected there.
    pub seq: u64,
    pub reason: String,
}

/// An anchor held outside the file, checked against it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnchorCheck {
    pub file_id: String,
    pub seq: u64,
    pub digest: String,
    /// `match` (this file or a moved-aside file it continues holds that
    /// record); `conflict` (the record there has another digest);
    /// `beyond_end` (past the file's end, or past the head its successor
    /// claims: whole records were cut); `unlinked_file` (a file of the log
    /// this chain does not continue).
    pub result: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifyReport {
    pub path: String,
    pub verdict: Verdict,
    /// Whole records that chain.
    pub events: u64,
    pub file_id: Option<String>,
    /// The file this one follows (`"none"` for a log's first file), its
    /// head seq and digest, as the opening record states them.
    pub previous_file_id: Option<String>,
    pub previous_head_seq: Option<u64>,
    pub previous_head_digest: Option<String>,
    pub head_seq: Option<u64>,
    pub head_digest: Option<String>,
    pub broken: Option<BreakInfo>,
    pub torn_tail_bytes: u64,
    /// Torn tails earlier appends moved aside (recorded in the chain).
    pub quarantined_tails: u64,
    /// Anchor records claiming the authority service holds the anchor.
    /// Claims until a held anchor matches.
    pub anchors_claimed: u64,
    /// Anchor records that are local markers only.
    pub anchors_local: u64,
    pub last_claimed_anchor_seq: Option<u64>,
    /// Held anchors that matched a record of this file.
    pub anchors_verified: u64,
    pub last_verified_anchor_seq: Option<u64>,
    /// Anchors supplied by the caller, checked.
    pub anchor_checks: Vec<AnchorCheck>,
    /// The moved-aside files this one continues, newest first, each checked
    /// to end at the head its successor claims.
    pub predecessors: Vec<Predecessor>,
    pub tamper_evidence: String,
}

/// A moved-aside file the chain continues.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Predecessor {
    pub file: String,
    pub file_id: String,
    pub head_seq: u64,
}

/// The most moved-aside files the verifier follows back.
const MAX_PREDECESSORS: usize = 16;

/// What one file holds for the checks: its id, its link and the file its
/// opening names, its verifiable prefix, and the digests of wanted records.
struct FileScan {
    file_id: Option<String>,
    link: Option<ChainLink>,
    moved: Option<String>,
    next_seq: u64,
    head: String,
    digests: BTreeMap<u64, String>,
}

/// The verifiable prefix of a moved-aside file (it may end in the break
/// that got it moved aside).
fn scan_prefix(path: &Path, wanted: &[u64]) -> io::Result<FileScan> {
    let mut scanner = Scanner::new(BufReader::new(File::open(path)?));
    let mut moved = None;
    let mut digests = BTreeMap::new();
    while let Step::Event(event, _) = scanner.step()? {
        if event.seq == 0 {
            moved = moved_name(&event.detail);
        }
        if wanted.contains(&event.seq) {
            digests.insert(event.seq, event.digest.clone());
        }
    }
    Ok(FileScan {
        file_id: scanner.file_id,
        link: scanner.link,
        moved,
        next_seq: scanner.next_seq,
        head: scanner.head,
        digests,
    })
}

/// The moved-aside file an opening record names, if it is a plain name
/// beside the chain.
fn moved_name(detail: &serde_json::Value) -> Option<String> {
    detail["moved_aside"]["file"]
        .as_str()
        .filter(|name| !name.is_empty() && !name.contains(['/', '\\']) && *name != "..")
        .map(str::to_owned)
}

/// [`verify_with_anchors`] with no anchor held outside the file.
pub fn verify_file(path: &Path) -> io::Result<VerifyReport> {
    verify_with_anchors(path, &[])
}

fn worst(report: &mut VerifyReport, verdict: Verdict) {
    if verdict > report.verdict {
        report.verdict = verdict;
    }
}

fn record_break(report: &mut VerifyReport, verdict: Verdict, line: u64, seq: u64, reason: &str) {
    if report.broken.is_none() {
        report.broken = Some(BreakInfo {
            line,
            seq,
            reason: reason.to_owned(),
        });
    }
    worst(report, verdict);
}

/// Verifies the chain at `path`, and `held` (anchors kept outside the
/// file, such as the authority service's) against it.
pub fn verify_with_anchors(path: &Path, held: &[AnchorRef]) -> io::Result<VerifyReport> {
    let mut report = VerifyReport {
        path: path.display().to_string(),
        verdict: Verdict::Intact,
        events: 0,
        file_id: None,
        previous_file_id: None,
        previous_head_seq: None,
        previous_head_digest: None,
        head_seq: None,
        head_digest: None,
        broken: None,
        torn_tail_bytes: 0,
        quarantined_tails: 0,
        anchors_claimed: 0,
        anchors_local: 0,
        last_claimed_anchor_seq: None,
        anchors_verified: 0,
        last_verified_anchor_seq: None,
        anchor_checks: Vec::new(),
        predecessors: Vec::new(),
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
    let mut moved: Option<String> = None;
    let mut scanner = Scanner::new(BufReader::new(file));
    let mut line = 0u64;
    loop {
        line += 1;
        let event = match scanner.step()? {
            Step::Event(event, _) => event,
            Step::End => break,
            Step::Torn(bytes) => {
                report.torn_tail_bytes = bytes.len() as u64;
                worst(&mut report, Verdict::TornTail);
                break;
            }
            Step::Broken(reason) => {
                let seq = scanner.next_seq;
                record_break(&mut report, Verdict::Broken, line, seq, &reason);
                break;
            }
        };
        if anchor_due(&event) || wanted.contains(&event.seq) {
            digests.insert(event.seq, event.digest.clone());
        }
        if event.seq == 0 {
            moved = moved_name(&event.detail);
        }
        if event.kind == AuditEventKind::Rotation
            && event.detail["action"] == "quarantined_torn_tail"
        {
            report.quarantined_tails += 1;
            worst(&mut report, Verdict::Recovered);
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
                record_break(
                    &mut report,
                    Verdict::Broken,
                    line,
                    event.seq,
                    "an anchor record names a record this file does not hold",
                );
                break;
            }
            if event.detail["status"] == LINK_REFUSED {
                record_break(
                    &mut report,
                    Verdict::Broken,
                    line,
                    event.seq,
                    "the anchor holder refused this file: it does not continue the file the \
                     holder holds anchors of",
                );
            }
            if event.detail["status"] == "anchored" {
                report.anchors_claimed += 1;
                report.last_claimed_anchor_seq = named;
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
    if scanner.file_id.is_some() {
        match &scanner.link {
            Some(link) => {
                report.previous_file_id = Some(link.previous_file_id.clone());
                report.previous_head_seq = Some(link.previous_head_seq);
                report.previous_head_digest = Some(link.previous_head_digest.clone());
            }
            None => report.previous_file_id = Some(NO_PREVIOUS_FILE.to_owned()),
        }
    }
    if scanner.next_seq > 0 {
        report.head_seq = Some(scanner.next_seq - 1);
        report.head_digest = Some(scanner.head.clone());
    }
    // Each file the held anchors may name: this one, then every moved-aside
    // file it continues (claimed head, digests of wanted records).
    let mut files: BTreeMap<String, (u64, BTreeMap<u64, String>)> = BTreeMap::new();
    if let Some(file_id) = &report.file_id {
        files.insert(
            file_id.clone(),
            (report.events.saturating_sub(1), digests.clone()),
        );
    }
    let mut next = scanner.link.clone().map(|link| (link, moved));
    let dir = path.parent().unwrap_or(Path::new("."));
    while let Some((link, moved)) = next.take() {
        if report.predecessors.len() >= MAX_PREDECESSORS {
            break;
        }
        let Some(name) = moved else {
            record_break(
                &mut report,
                Verdict::Broken,
                1,
                0,
                "the opening record links to a previous file but names no moved-aside file",
            );
            break;
        };
        let scan = match scan_prefix(&dir.join(&name), &wanted) {
            Ok(scan) => scan,
            Err(error) => {
                record_break(
                    &mut report,
                    Verdict::Broken,
                    0,
                    link.previous_head_seq,
                    &format!(
                        "the moved-aside file {name} this chain continues cannot be read: {error}"
                    ),
                );
                break;
            }
        };
        let ends_at_head = scan.file_id.as_deref() == Some(link.previous_file_id.as_str())
            && scan.next_seq == link.previous_head_seq + 1
            && scan.head == link.previous_head_digest;
        if !ends_at_head {
            record_break(
                &mut report,
                Verdict::Broken,
                0,
                link.previous_head_seq,
                &format!(
                    "the moved-aside file {name} does not end at the head this chain says it \
                     continues"
                ),
            );
            break;
        }
        report.predecessors.push(Predecessor {
            file: name,
            file_id: link.previous_file_id.clone(),
            head_seq: link.previous_head_seq,
        });
        files.insert(
            link.previous_file_id.clone(),
            (link.previous_head_seq, scan.digests),
        );
        next = scan.link.map(|link| (link, scan.moved));
    }
    for anchor in held {
        let result = check_held(anchor, &files);
        match result {
            "match" => {
                report.anchors_verified += 1;
                report.last_verified_anchor_seq =
                    report.last_verified_anchor_seq.max(Some(anchor.seq));
            }
            "beyond_end" => record_break(
                &mut report,
                Verdict::Truncated,
                0,
                anchor.seq,
                "a held anchor names a record past the end (whole records were cut)",
            ),
            "conflict" => record_break(
                &mut report,
                Verdict::Broken,
                0,
                anchor.seq,
                "a held anchor conflicts with the record it names",
            ),
            "unlinked_file" => record_break(
                &mut report,
                Verdict::Broken,
                0,
                anchor.seq,
                "a held anchor names a file of this log that this file does not link to \
                 (the chain was replaced)",
            ),
            _ => {}
        }
        report.anchor_checks.push(AnchorCheck {
            file_id: anchor.file_id.clone(),
            seq: anchor.seq,
            digest: anchor.digest.clone(),
            result,
        });
    }
    report.tamper_evidence = tamper_evidence(&report, &by);
    Ok(report)
}

/// A held anchor against the files the chain holds: `files` maps a file id
/// to its head (for a moved-aside file, the head its successor claims) and
/// the digests of the wanted records.
fn check_held(
    anchor: &AnchorRef,
    files: &BTreeMap<String, (u64, BTreeMap<u64, String>)>,
) -> &'static str {
    let Some((head, digests)) = files.get(&anchor.file_id) else {
        return "unlinked_file";
    };
    if anchor.seq > *head {
        return "beyond_end";
    }
    if digests.get(&anchor.seq) == Some(&anchor.digest) {
        "match"
    } else {
        "conflict"
    }
}

fn tamper_evidence(report: &VerifyReport, by: &str) -> String {
    let link = match report.previous_file_id.as_deref() {
        Some(NO_PREVIOUS_FILE) | None => "this is the log's first file".to_owned(),
        Some(previous) => format!(
            "this file follows {previous} at seq {}",
            report.previous_head_seq.unwrap_or(0)
        ),
    };
    let anchors = match (
        report.last_verified_anchor_seq,
        report.last_claimed_anchor_seq,
    ) {
        (Some(seq), _) => format!(
            "verified against held anchors up to seq {seq}; records after it are evident only \
             against a later held anchor"
        ),
        (None, Some(seq)) => format!(
            "{} anchor record(s) up to seq {seq} claim {by} holds them; claims are unverified \
             until checked against the held anchors (Event Log read-back is not in this slice)",
            report.anchors_claimed
        ),
        (None, None) => UNANCHORED_NOTE.to_owned(),
    };
    format!("{anchors}; {link}")
}
