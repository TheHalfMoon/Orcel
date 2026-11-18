//! WP1-03: the service holds anchors of orceld's own audit chain (spec 4.8,
//! C-29). A child module of `core`, so an anchor goes through the core's
//! audit chain (written first) and its signed Event Log path.
//!
//! The service keeps, per caller account and log, the chain file it knows
//! (its id, the highest anchored seq and that record's digest), the files
//! that log left, and the times of recent anchors, in `chain-anchors.json`
//! in its protected state directory. It refuses:
//! - an anchor whose seq is below the highest it holds for that file, or
//!   equal with another digest (a rewrite);
//! - an anchor for a different file of the same log unless that file's link
//!   names the known file and a head at or past the highest anchored record
//!   (with that record's digest when it is the head): a replaced chain does
//!   not get a fresh start here;
//! - an anchor for a file the log already left;
//! - more than [`ANCHORS_PER_MINUTE`] anchors per log in a minute.
//!
//! The same anchor twice is answered as held without a second record.
//! Everything the caller sends is its claim (`asserted_by_session`).

use super::{is_lower_hex, observed, write_atomically, AuthorityCore};
use crate::caller::{CallerFacts, CallerRole};
use crate::error::AuthorityError;
use crate::protocol::ChainLink;
use orcel_contracts::event::AnchorRef;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// The file in the service's state directory.
pub const CHAIN_ANCHORS_FILE: &str = "chain-anchors.json";
/// The most anchors one log may ask for in a minute.
pub const ANCHORS_PER_MINUTE: usize = 120;
/// The only log anchored here.
const ORCELD_LOG: &str = "orceld";
/// Files a log left that are still refused by id.
const MAX_LEFT_FILES: usize = 64;
const CONTRACT: &str = "orcel.authority-chain-anchors/1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LogState {
    file_id: String,
    seq: u64,
    digest: String,
    left_files: Vec<String>,
    recent_ms: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChainAnchors {
    contract: String,
    /// Keyed `<caller SID>|<log>`: every account has its own chain.
    logs: BTreeMap<String, LogState>,
}

enum Decision {
    /// Recorded and written to the Event Log; `new_file` when it moved the
    /// log to a linked file.
    Hold { new_file: bool },
    /// The anchor the service already holds.
    Duplicate,
}

fn check_link(link: &ChainLink) -> Result<(), AuthorityError> {
    if !is_lower_hex(&link.previous_file_id, 64) || !is_lower_hex(&link.previous_head_digest, 64) {
        return Err(AuthorityError::invalid(
            "a chain link's file id and digest are SHA-256s in lowercase hex",
        ));
    }
    Ok(())
}

/// What the service does with `anchor` given what it holds for the log.
fn decide(
    held: Option<&LogState>,
    anchor: &AnchorRef,
    link: Option<&ChainLink>,
) -> Result<Decision, AuthorityError> {
    let Some(held) = held else {
        return Ok(Decision::Hold { new_file: true });
    };
    if anchor.file_id == held.file_id {
        return if anchor.seq > held.seq {
            Ok(Decision::Hold { new_file: false })
        } else if anchor.seq == held.seq && anchor.digest == held.digest {
            Ok(Decision::Duplicate)
        } else {
            Err(AuthorityError::denied(format!(
                "the service holds seq {} of this chain file; an anchor at or below it with \
                 another record is a rewrite",
                held.seq
            )))
        };
    }
    if held.left_files.contains(&anchor.file_id) {
        return Err(AuthorityError::denied(
            "this log already moved on from that chain file",
        ));
    }
    let linked = link.is_some_and(|link| {
        link.previous_file_id == held.file_id
            && link.previous_head_seq >= held.seq
            && (link.previous_head_seq > held.seq || link.previous_head_digest == held.digest)
    });
    if !linked {
        return Err(AuthorityError::denied(
            "the chain file does not link to the file the service holds anchors of (replaced, \
             not continued); move the old file aside so the new one links to it",
        ));
    }
    Ok(Decision::Hold { new_file: true })
}

impl AuthorityCore {
    fn chain_anchors_path(&self) -> std::path::PathBuf {
        self.state_dir.join(CHAIN_ANCHORS_FILE)
    }

    fn load_chain_anchors(&self) -> Result<ChainAnchors, AuthorityError> {
        match std::fs::read_to_string(self.chain_anchors_path()) {
            Ok(text) => serde_json::from_str(&text).map_err(|error| {
                AuthorityError::internal(format!("parse the chain anchors: {error}"))
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(ChainAnchors {
                contract: CONTRACT.to_owned(),
                logs: BTreeMap::new(),
            }),
            Err(error) => Err(AuthorityError::internal(format!(
                "read the chain anchors: {error}"
            ))),
        }
    }

    /// `Request::Anchor`.
    pub(super) fn anchor_chain(
        &mut self,
        caller: &CallerFacts,
        role: CallerRole,
        anchor: &AnchorRef,
        link: Option<&ChainLink>,
    ) -> Result<Value, AuthorityError> {
        if role != CallerRole::Orceld {
            return Err(AuthorityError::denied(
                "only orceld (a configured trusted image) may anchor its audit chain",
            ));
        }
        Self::require_known(role, caller)?;
        if anchor.log != ORCELD_LOG {
            return Err(AuthorityError::invalid(
                "only orceld's audit chain is anchored here",
            ));
        }
        if !is_lower_hex(&anchor.file_id, 64) || !is_lower_hex(&anchor.digest, 64) {
            return Err(AuthorityError::invalid(
                "an anchor's file id and digest are SHA-256s in lowercase hex",
            ));
        }
        if let Some(link) = link {
            check_link(link)?;
        }
        let insertion = anchor
            .event_log_insertion()
            .ok_or_else(|| AuthorityError::invalid("an anchor part is empty or ambiguous"))?;
        let key = format!("{}|{}", caller.user_sid, anchor.log);
        let mut anchors = self.load_chain_anchors()?;
        let held = anchors.logs.get(&key).cloned();
        let new_file = match decide(held.as_ref(), anchor, link)? {
            Decision::Duplicate => {
                return Ok(json!({
                    "anchored": true,
                    "duplicate": true,
                    "event_id": crate::EVENT_ANCHOR,
                }))
            }
            Decision::Hold { new_file } => new_file,
        };
        let now = self.now();
        let mut recent: Vec<u64> = held
            .as_ref()
            .map(|state| state.recent_ms.clone())
            .unwrap_or_default();
        recent.retain(|at| now.saturating_sub(*at) < 60_000);
        if recent.len() >= ANCHORS_PER_MINUTE {
            return Err(AuthorityError::denied(format!(
                "more than {ANCHORS_PER_MINUTE} anchors of this log in a minute"
            )));
        }
        recent.push(now);
        let mut left_files = held
            .as_ref()
            .map(|state| state.left_files.clone())
            .unwrap_or_default();
        if let (true, Some(state)) = (new_file, held.as_ref()) {
            left_files.push(state.file_id.clone());
            if left_files.len() > MAX_LEFT_FILES {
                left_files.remove(0);
            }
        }
        // Write before the answer: the record, then the state, then the
        // Event Log entry.
        let record = self.audit(
            "anchor",
            json!({
                "log": anchor.log,
                "file_id": anchor.file_id,
                "seq": anchor.seq,
                "digest": anchor.digest,
                "link": link,
            }),
            observed(caller, role),
            json!({
                "decision": "recorded",
                "event_id": crate::EVENT_ANCHOR,
                "new_file": new_file,
                "previous_known_file": held.as_ref().map(|state| state.file_id.clone()),
            }),
        )?;
        anchors.logs.insert(
            key,
            LogState {
                file_id: anchor.file_id.clone(),
                seq: anchor.seq,
                digest: anchor.digest.clone(),
                left_files,
                recent_ms: recent,
            },
        );
        let bytes = serde_json::to_vec_pretty(&anchors).map_err(|error| {
            AuthorityError::internal(format!("encode the chain anchors: {error}"))
        })?;
        write_atomically(&self.chain_anchors_path(), &bytes)?;
        self.event(crate::EVENT_ANCHOR, false, &insertion)?;
        Ok(json!({
            "anchored": true,
            "event_id": crate::EVENT_ANCHOR,
            "authority_seq": record.seq,
            "authority_digest": record.digest,
            "new_file": new_file,
        }))
    }
}
