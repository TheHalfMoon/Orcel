//! The Full Control audit chain (spec 4.8, C-27 e, C-29).
//!
//! One JSON record per line in the service's protected state directory.
//! Each record carries the previous record's digest and its own
//! (SHA-256 over `prev_digest || canonical_json(record without digest)`),
//! so a removed, reordered or edited line breaks the chain. A record keeps
//! what the user session claimed (`asserted_by_session`: the action,
//! capability, principal and task as the caller stated them) apart from
//! what the service observed itself (`observed`: the caller's SID, logon
//! session, terminal-services session, process id and image). The chain is
//! tamper-evident out-of-session storage of claims plus observed facts,
//! never proof of what ran (C-27 e).
//!
//! Write before dispatch: [`AuditChain::append`] flushes the line to disk
//! (`sync_data`) before it returns, and a failed append refuses the request
//! that needed it.

use crate::error::AuthorityError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};

pub const AUDIT_CONTRACT: &str = "orcel.authority-audit/1";

/// The digest that precedes the first record.
pub const GENESIS_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Anchor to the Event Log every this many records (spec 4.8).
pub const ANCHOR_EVERY: u64 = 32;

/// The longest audit line the reader accepts.
const MAX_LINE_BYTES: usize = 64 * 1024;

/// What the service observed about the caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observed {
    pub caller_sid: String,
    pub logon_session_id: u64,
    pub ts_session_id: u32,
    pub caller_pid: u32,
    pub caller_image: String,
    /// The role the service assigned (`orceld`, `owner_tool`, `other`,
    /// `service` for the service's own events).
    pub role: String,
}

impl Observed {
    /// The service itself (session change, expiry, start).
    pub fn service() -> Self {
        Self {
            caller_sid: String::new(),
            logon_session_id: 0,
            ts_session_id: 0,
            caller_pid: std::process::id(),
            caller_image: String::new(),
            role: "service".to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRecord {
    pub contract: String,
    pub seq: u64,
    pub prev_digest: String,
    pub at_ms: u64,
    /// `request`, `decision`, `lease`, `intent`, `enroll`, `authorize`,
    /// `emergency_stop`, `anchor`, `start`.
    pub kind: String,
    /// Everything the caller claimed, as claimed. `Null` when the record
    /// holds no claim.
    pub asserted_by_session: Value,
    pub observed: Observed,
    /// The service's own facts and decision.
    pub detail: Value,
    pub digest: String,
}

#[derive(Serialize)]
struct Unsigned<'a> {
    contract: &'a str,
    seq: u64,
    prev_digest: &'a str,
    at_ms: u64,
    kind: &'a str,
    asserted_by_session: &'a Value,
    observed: &'a Observed,
    detail: &'a Value,
}

fn digest_of(record: &AuditRecord) -> Result<String, AuthorityError> {
    let unsigned = Unsigned {
        contract: &record.contract,
        seq: record.seq,
        prev_digest: &record.prev_digest,
        at_ms: record.at_ms,
        kind: &record.kind,
        asserted_by_session: &record.asserted_by_session,
        observed: &record.observed,
        detail: &record.detail,
    };
    let canonical = orcel_contracts::canonical_json(&unsigned).map_err(|error| {
        AuthorityError::internal(format!("canonical audit encoding: {error:?}"))
    })?;
    let mut input = Vec::with_capacity(64 + canonical.len());
    input.extend_from_slice(record.prev_digest.as_bytes());
    input.extend_from_slice(canonical.as_bytes());
    Ok(crate::sha256_hex(&input))
}

/// The append-only chain.
pub struct AuditChain {
    path: PathBuf,
    file: File,
    next_seq: u64,
    head: String,
}

impl AuditChain {
    /// Opens (or creates) the chain at `path` and verifies every record. A
    /// broken chain refuses to open: the service then does not start.
    pub fn open(path: &Path) -> Result<Self, AuthorityError> {
        let (next_seq, head) = if path.exists() {
            verify_file(path)?
        } else {
            (1, GENESIS_DIGEST.to_owned())
        };
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|error| AuthorityError::internal(format!("open the audit chain: {error}")))?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            next_seq,
            head,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The last record's sequence number (0 when empty).
    pub fn last_seq(&self) -> u64 {
        self.next_seq.saturating_sub(1)
    }

    /// The last record's digest.
    pub fn head(&self) -> &str {
        &self.head
    }

    /// Appends one record and flushes it to disk before returning.
    pub fn append(
        &mut self,
        at_ms: u64,
        kind: &str,
        asserted_by_session: Value,
        observed: Observed,
        detail: Value,
    ) -> Result<AuditRecord, AuthorityError> {
        let mut record = AuditRecord {
            contract: AUDIT_CONTRACT.to_owned(),
            seq: self.next_seq,
            prev_digest: self.head.clone(),
            at_ms,
            kind: kind.to_owned(),
            asserted_by_session,
            observed,
            detail,
            digest: String::new(),
        };
        record.digest = digest_of(&record)?;
        let mut line = serde_json::to_string(&record).map_err(|error| {
            AuthorityError::internal(format!("encode an audit record: {error}"))
        })?;
        if line.len() >= MAX_LINE_BYTES {
            return Err(AuthorityError::internal("an audit record is too long"));
        }
        line.push('\n');
        self.file
            .write_all(line.as_bytes())
            .and_then(|()| self.file.sync_data())
            .map_err(|error| AuthorityError::internal(format!("write the audit chain: {error}")))?;
        self.next_seq += 1;
        self.head = record.digest.clone();
        Ok(record)
    }

    /// Whether the record just written is due an Event Log anchor.
    pub fn anchor_due(record: &AuditRecord) -> bool {
        record.seq % ANCHOR_EVERY == 0
            || matches!(
                record.kind.as_str(),
                "lease" | "emergency_stop" | "enroll" | "start"
            )
    }
}

/// Verifies the whole file; returns the next sequence number and the head.
pub fn verify_file(path: &Path) -> Result<(u64, String), AuthorityError> {
    let file = File::open(path)
        .map_err(|error| AuthorityError::internal(format!("read the audit chain: {error}")))?;
    let mut reader = BufReader::new(file);
    let mut expected_seq = 1u64;
    let mut head = GENESIS_DIGEST.to_owned();
    let mut line = String::new();
    loop {
        line.clear();
        let read = reader
            .by_ref()
            .take(MAX_LINE_BYTES as u64 + 1)
            .read_line(&mut line)
            .map_err(|error| AuthorityError::internal(format!("read the audit chain: {error}")))?;
        if read == 0 {
            break;
        }
        if read > MAX_LINE_BYTES || !line.ends_with('\n') {
            return Err(AuthorityError::internal(format!(
                "audit chain break at record {expected_seq}: a truncated or oversized line"
            )));
        }
        let record: AuditRecord = serde_json::from_str(line.trim_end()).map_err(|error| {
            AuthorityError::internal(format!(
                "audit chain break at record {expected_seq}: {error}"
            ))
        })?;
        if record.seq != expected_seq
            || record.prev_digest != head
            || record.contract != AUDIT_CONTRACT
            || digest_of(&record)? != record.digest
        {
            return Err(AuthorityError::internal(format!(
                "audit chain break at record {expected_seq}"
            )));
        }
        head = record.digest;
        expected_seq += 1;
    }
    Ok((expected_seq, head))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn temp_dir(name: &str) -> Result<PathBuf, String> {
        let dir = std::env::temp_dir().join(format!(
            "orcel-authority-audit-{name}-{}-{}",
            std::process::id(),
            crate::now_ms()
        ));
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        Ok(dir)
    }

    #[test]
    fn records_chain_and_verify_and_a_tamper_breaks_the_chain() -> Result<(), String> {
        let dir = temp_dir("chain")?;
        let path = dir.join("audit.jsonl");
        {
            let mut chain = AuditChain::open(&path).map_err(|e| e.to_string())?;
            for i in 0..3 {
                chain
                    .append(
                        i,
                        "authorize",
                        json!({"capability": "desktop.input", "task": "t"}),
                        Observed::service(),
                        json!({"decision": "allow"}),
                    )
                    .map_err(|e| e.to_string())?;
            }
            assert_eq!(chain.last_seq(), 3);
        }
        let reopened = AuditChain::open(&path).map_err(|e| e.to_string())?;
        assert_eq!(reopened.last_seq(), 3);
        drop(reopened);
        let text = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
        let tampered = text.replacen("\"allow\"", "\"deny\"", 1);
        std::fs::write(&path, tampered).map_err(|e| e.to_string())?;
        assert!(AuditChain::open(&path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    #[test]
    fn a_removed_record_breaks_the_chain() -> Result<(), String> {
        let dir = temp_dir("removed")?;
        let path = dir.join("audit.jsonl");
        {
            let mut chain = AuditChain::open(&path).map_err(|e| e.to_string())?;
            for i in 0..3 {
                chain
                    .append(i, "lease", Value::Null, Observed::service(), json!({}))
                    .map_err(|e| e.to_string())?;
            }
        }
        let text = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
        let kept: Vec<&str> = text
            .lines()
            .enumerate()
            .filter(|(i, _)| *i != 1)
            .map(|(_, l)| l)
            .collect();
        std::fs::write(&path, format!("{}\n", kept.join("\n"))).map_err(|e| e.to_string())?;
        assert!(AuditChain::open(&path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }
}
