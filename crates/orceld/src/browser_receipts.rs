//! SG-000135 OB-05: evidence receipts on orceld's audit chain.
//!
//! Every `browser_full` page action of a broker session is written to
//! orceld's hash-chained audit log twice:
//!
//! 1. **Intent, before anything is sent** (`browser_intent`): the session,
//!    profile and mode, the action and its target (node id, role and the
//!    host's keyed name digest), the page and generation it was planned on,
//!    the page's origin, the requested URL as a digest only, and the
//!    approval epoch the action was checked against. If the chain cannot
//!    take it, the action is refused and nothing is sent.
//! 2. **Receipt, after the outcome is known** (`browser_receipt`): the
//!    intent's digest and its place in the chain, the authority that
//!    covered the action (the approval record id, or the Full Access lease
//!    id and its service epoch), the outcome (`sent`, `refused`, `failed`,
//!    `superseded` or `unknown`, plus the earlier `outcome` word), whether
//!    the effect happened, whether the person is needed, the page and
//!    generation before and after, the committed URL as a digest only,
//!    pre- and post-action evidence digests, the evidence files stored, and
//!    the time the intent and the receipt were written.
//!
//! An intent with no receipt after it is an action whose outcome was never
//! recorded (orceld stopped, or the chain refused the receipt):
//! `orceld audit-verify --receipts` lists it under `dispatched_unrecorded`.
//!
//! What a receipt never holds: a URL, a query or a fragment in clear text,
//! a typed value or a digest of one, an option label, a cookie, a
//! credential, page text or an image. Evidence files (the snapshot frame
//! of node identities and keyed digests the agent acted on, and the masked
//! screenshot) are content-addressed files under orceld's private browser
//! state, never inline; the receipt keeps their digests.

use orcel_contracts::event::AnchorRef;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// The receipt contract a reply and the chain carry.
pub(crate) const RECEIPT_CONTRACT: &str = "orcel.browser-receipt/1";
/// The intent contract.
pub(crate) const INTENT_CONTRACT: &str = "orcel.browser-intent/1";
/// Domain separation for receipt digests. Version 4: OB-05 (canonical JSON
/// of every field but the digest itself and the chain place of the receipt).
pub(crate) const RECEIPT_DOMAIN: &str = "orcel-ob05-receipt/4";
/// Domain separation for intent digests.
pub(crate) const INTENT_DOMAIN: &str = "orcel-ob05-intent/1";
/// `detail.source` of an intent event.
pub(crate) const SOURCE_INTENT: &str = "browser_intent";
/// `detail.source` of a receipt event.
pub(crate) const SOURCE_RECEIPT: &str = "browser_receipt";
/// `detail.source` of a session's start and end events.
pub(crate) const SOURCE_SESSION: &str = "browser_session";
/// Receipt fields its digest does not cover: the digest itself, where the
/// receipt landed in the chain and whether it did (known only after it is
/// written), and the legacy flag.
const RECEIPT_UNCOVERED: [&str; 4] = ["receipt_sha256", "audit", "recorded", "provisional"];
/// Intent fields its digest does not cover.
const INTENT_UNCOVERED: [&str; 2] = ["intent_sha256", "audit"];
/// The largest evidence file kept (a masked screenshot is at most 2 MiB).
pub(crate) const MAX_EVIDENCE_FILE_BYTES: usize = 4 * 1024 * 1024;
/// The most evidence files kept; past it, the oldest are pruned.
pub(crate) const MAX_EVIDENCE_FILES: usize = 4096;
/// The most evidence bytes kept; past it, the oldest files are pruned.
pub(crate) const MAX_EVIDENCE_BYTES: u64 = 512 * 1024 * 1024;
/// The most node targets remembered from one snapshot.
const MAX_TARGETS: usize = 4096;

/// SHA-256 of `bytes`, lowercase hex.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Whether `text` is a SHA-256 digest in lowercase hex.
pub(crate) fn is_sha256(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The digest of `value` (an object) without its `uncovered` fields:
/// SHA-256 of `domain`, a newline, and the canonical JSON (RFC 8785) of the
/// rest. `None` for a non-object or a value canonical JSON refuses.
pub(crate) fn covered_digest(domain: &str, value: &Value, uncovered: &[&str]) -> Option<String> {
    let Value::Object(map) = value else {
        return None;
    };
    let mut core = map.clone();
    for key in uncovered {
        core.remove(*key);
    }
    let text = orcel_contracts::canonical_json_value(&Value::Object(core)).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update(b"\n");
    hasher.update(text.as_bytes());
    Some(
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    )
}

/// A receipt's digest, from its JSON form.
pub(crate) fn receipt_digest_of(receipt: &Value) -> Option<String> {
    covered_digest(RECEIPT_DOMAIN, receipt, &RECEIPT_UNCOVERED)
}

/// An intent's digest, from its JSON form.
pub(crate) fn intent_digest_of(intent: &Value) -> Option<String> {
    covered_digest(INTENT_DOMAIN, intent, &INTENT_UNCOVERED)
}

/// Where a receipt or an intent sits in orceld's audit chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReceiptAudit {
    /// No audit chain was given to the broker (tests and validation builds).
    NotConfigured,
    /// Written: `(log, file id, seq, digest)` of the event.
    Chained(AnchorRef),
    /// The chain refused or failed the write.
    Failed(String),
}

impl ReceiptAudit {
    pub(crate) fn to_json(&self) -> Value {
        match self {
            Self::NotConfigured => Value::Null,
            Self::Chained(at) => json!({
                "log": at.log,
                "file_id": at.file_id,
                "seq": at.seq,
                "digest": at.digest,
            }),
            Self::Failed(error) => json!({"error": error}),
        }
    }
}

/// What an action acted on: its page, and for a node action the node id,
/// its role and the host's keyed digest of its name (never the name).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ReceiptTarget {
    pub page_id: Option<String>,
    pub node_id: Option<String>,
    pub role: Option<String>,
    pub name_digest: Option<String>,
}

impl ReceiptTarget {
    pub(crate) fn to_json(&self) -> Value {
        json!({
            "page_id": self.page_id,
            "node_id": self.node_id,
            "role": self.role,
            "name_digest": self.name_digest,
        })
    }
}

/// The page evidence an action was planned on: the session's latest
/// snapshot of that page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreEvidence {
    pub page_id: String,
    pub generation: u64,
    pub sha256: String,
}

impl PreEvidence {
    pub(crate) fn to_json(&self) -> Value {
        json!({
            "kind": "snapshot",
            "page_id": self.page_id,
            "generation": self.generation,
            "sha256": self.sha256,
        })
    }
}

/// The kinds of evidence file kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EvidenceKind {
    /// The snapshot frame (node identities, roles, keyed digests and the
    /// bounded untrusted names of form controls) as the reply carried it.
    Snapshot,
    /// The masked PNG screenshot as the reply carried it.
    Screenshot,
}

impl EvidenceKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Snapshot => "snapshot",
            Self::Screenshot => "screenshot",
        }
    }

    fn extension(self) -> &'static str {
        match self {
            Self::Snapshot => "json",
            Self::Screenshot => "png",
        }
    }

    fn parse(kind: &str) -> Option<Self> {
        match kind {
            "snapshot" => Some(Self::Snapshot),
            "screenshot" => Some(Self::Screenshot),
            _ => None,
        }
    }
}

/// One evidence file a receipt names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EvidenceFile {
    pub kind: EvidenceKind,
    /// Whose evidence it is: the ephemeral session's id (removed when the
    /// session ends) or `p-<profile>` (removed with the persistent profile).
    pub scope: String,
    pub sha256: String,
    pub bytes: u64,
    /// Whether the file is in the evidence store; the digest binds it either
    /// way.
    pub stored: bool,
    /// Why it was not stored: `too_large`, `no_store`, `quota`, `conflict`
    /// or `write_failed`.
    pub reason: Option<&'static str>,
}

impl EvidenceFile {
    pub(crate) fn to_json(&self) -> Value {
        json!({
            "kind": self.kind.as_str(),
            "scope": self.scope,
            "sha256": self.sha256,
            "bytes": self.bytes,
            "stored": self.stored,
            "reason": self.reason,
        })
    }

    /// A file named by digest only, never stored, and why.
    pub(crate) fn digest_only(
        kind: EvidenceKind,
        scope: &str,
        bytes: &[u8],
        reason: &'static str,
    ) -> Self {
        Self {
            kind,
            scope: scope.to_owned(),
            sha256: sha256_hex(bytes),
            bytes: bytes.len() as u64,
            stored: false,
            reason: Some(reason),
        }
    }
}

/// One evidence file the store removed to stay within its bounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PrunedFile {
    pub scope: String,
    pub kind: EvidenceKind,
    pub sha256: String,
}

impl PrunedFile {
    pub(crate) fn to_json(&self) -> Value {
        json!({"scope": self.scope, "kind": self.kind.as_str(), "sha256": self.sha256})
    }
}

/// Whether `scope` names an evidence owner: a broker session id (`bs-`) or
/// a persistent profile (`p-`), lowercase letters, digits and hyphens only.
pub(crate) fn is_scope(scope: &str) -> bool {
    (scope.starts_with("bs-") || scope.starts_with("p-"))
        && scope.len() <= 96
        && scope
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The evidence scope of a persistent profile.
pub(crate) fn profile_scope(name: &str) -> String {
    format!("p-{name}")
}

/// orceld's content-addressed evidence files, `<scope>/<sha256>.<json|png>`
/// under one private directory (owner-only on Windows: created by
/// `orcel_platform::paths::ensure_private_dir` in production), never
/// following a link. An ephemeral session's folder is removed when the
/// session ends and a persistent profile's with the profile. The store
/// keeps at most [`MAX_EVIDENCE_BYTES`] and [`MAX_EVIDENCE_FILES`], pruning
/// the oldest files first; each prune is reported so the chain records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EvidenceStore {
    dir: PathBuf,
    max_bytes: u64,
    max_files: usize,
}

/// One file in the store, as a prune considers it.
struct Kept {
    path: PathBuf,
    scope: String,
    kind: EvidenceKind,
    sha256: String,
    bytes: u64,
    modified: std::time::SystemTime,
}

impl EvidenceStore {
    /// The store at `dir`, created as a private directory (owner-only).
    pub(crate) fn open_private(dir: PathBuf) -> Option<Self> {
        orcel_platform::paths::ensure_private_dir(&dir).ok()?;
        Some(Self::at(dir))
    }

    /// The store at `dir`, which must already be a real directory (tests
    /// and the verifier).
    pub(crate) fn at(dir: PathBuf) -> Self {
        Self {
            dir,
            max_bytes: MAX_EVIDENCE_BYTES,
            max_files: MAX_EVIDENCE_FILES,
        }
    }

    /// The same store with other bounds (tests).
    #[cfg(test)]
    pub(crate) fn bounded(mut self, max_bytes: u64, max_files: usize) -> Self {
        self.max_bytes = max_bytes;
        self.max_files = max_files;
        self
    }

    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    fn path_of(&self, scope: &str, kind: EvidenceKind, sha256: &str) -> PathBuf {
        self.dir
            .join(scope)
            .join(format!("{sha256}.{}", kind.extension()))
    }

    /// Keep `bytes` as evidence of `kind` for `scope`, and the files pruned
    /// to make room. Never fails: a file that cannot be kept is named by its
    /// digest with `stored: false` and the reason.
    pub(crate) fn put(
        &self,
        scope: &str,
        kind: EvidenceKind,
        bytes: &[u8],
    ) -> (EvidenceFile, Vec<PrunedFile>) {
        let digest_only = |reason| EvidenceFile::digest_only(kind, scope, bytes, reason);
        if !is_scope(scope) {
            return (digest_only("no_store"), Vec::new());
        }
        if bytes.len() > MAX_EVIDENCE_FILE_BYTES || bytes.len() as u64 > self.max_bytes {
            return (digest_only("too_large"), Vec::new());
        }
        if !real_dir(&self.dir) {
            return (digest_only("no_store"), Vec::new());
        }
        let mut file = digest_only("write_failed");
        file.reason = None;
        let path = self.path_of(scope, kind, &file.sha256);
        match read_regular(&path) {
            // The same content is already kept (content-addressed).
            Some(Ok(existing)) if sha256_hex(&existing) == file.sha256 => {
                file.stored = true;
                return (file, Vec::new());
            }
            // Something else is at the name: it is never adopted.
            Some(_) => {
                file.reason = Some("conflict");
                return (file, Vec::new());
            }
            None => {}
        }
        let pruned = self.make_room(bytes.len() as u64);
        let folder = self.dir.join(scope);
        let folder_ok = match std::fs::symlink_metadata(&folder) {
            Ok(metadata) => metadata.is_dir() && !crate::browser_broker::is_reparse(&metadata),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&folder).is_ok() && real_dir(&folder)
            }
            Err(_) => false,
        };
        let fits = self.usage().is_some_and(|(total, count)| {
            total + bytes.len() as u64 <= self.max_bytes && count < self.max_files
        });
        if !folder_ok {
            file.reason = Some("no_store");
            return (file, pruned);
        }
        if !fits {
            file.reason = Some("quota");
            return (file, pruned);
        }
        let temp = folder.join(format!(
            ".{}.{}.{}.tmp",
            file.sha256,
            std::process::id(),
            now_nanos()
        ));
        let written = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .and_then(|mut out| {
                out.write_all(bytes)?;
                out.sync_all()
            })
            .and_then(|()| std::fs::rename(&temp, &path));
        if written.is_err() {
            let _ = std::fs::remove_file(&temp);
            file.reason = Some("write_failed");
        }
        file.stored = written.is_ok();
        (file, pruned)
    }

    /// Every evidence file kept, by scope folder (links and odd names are
    /// skipped, never followed).
    fn kept(&self) -> Option<Vec<Kept>> {
        let mut kept = Vec::new();
        for scope in std::fs::read_dir(&self.dir).ok()?.flatten() {
            let name = scope.file_name().to_string_lossy().into_owned();
            if !is_scope(&name) || !real_dir(&scope.path()) {
                continue;
            }
            for entry in std::fs::read_dir(scope.path()).ok()?.flatten() {
                let file_name = entry.file_name().to_string_lossy().into_owned();
                let Some((sha256, extension)) = file_name.split_once('.') else {
                    continue;
                };
                let kind = match extension {
                    "json" => EvidenceKind::Snapshot,
                    "png" => EvidenceKind::Screenshot,
                    _ => continue,
                };
                let Ok(metadata) = std::fs::symlink_metadata(entry.path()) else {
                    continue;
                };
                if !is_sha256(sha256)
                    || !metadata.is_file()
                    || crate::browser_broker::is_reparse(&metadata)
                {
                    continue;
                }
                kept.push(Kept {
                    path: entry.path(),
                    scope: name.clone(),
                    kind,
                    sha256: sha256.to_owned(),
                    bytes: metadata.len(),
                    modified: metadata.modified().unwrap_or(std::time::UNIX_EPOCH),
                });
            }
        }
        Some(kept)
    }

    /// Total bytes and count of the files kept.
    fn usage(&self) -> Option<(u64, usize)> {
        let kept = self.kept()?;
        Some((kept.iter().map(|file| file.bytes).sum(), kept.len()))
    }

    /// Remove the oldest files until `incoming` more bytes and one more file
    /// fit; the files removed.
    fn make_room(&self, incoming: u64) -> Vec<PrunedFile> {
        let Some(mut kept) = self.kept() else {
            return Vec::new();
        };
        kept.sort_by_key(|file| (file.modified, file.path.clone()));
        let mut total: u64 = kept.iter().map(|file| file.bytes).sum();
        let mut count = kept.len();
        let mut pruned = Vec::new();
        for file in kept {
            if total + incoming <= self.max_bytes && count < self.max_files {
                break;
            }
            if std::fs::remove_file(&file.path).is_ok() {
                total = total.saturating_sub(file.bytes);
                count -= 1;
                pruned.push(PrunedFile {
                    scope: file.scope,
                    kind: file.kind,
                    sha256: file.sha256,
                });
            }
        }
        pruned
    }

    /// Remove every evidence file of `scope` (an ephemeral session that
    /// ended, a deleted profile). True when nothing of it is left.
    pub(crate) fn remove_scope(&self, scope: &str) -> bool {
        is_scope(scope) && crate::browser_broker::remove_tree(&self.dir.join(scope))
    }

    /// What is at the evidence file `scope`/`kind`/`sha256` now.
    pub(crate) fn check(&self, scope: &str, kind: &str, sha256: &str) -> EvidenceCheck {
        let Some(kind) = EvidenceKind::parse(kind) else {
            return EvidenceCheck::Malformed;
        };
        if !is_sha256(sha256) || !is_scope(scope) {
            return EvidenceCheck::Malformed;
        }
        match read_regular(&self.path_of(scope, kind, sha256)) {
            None => EvidenceCheck::Missing,
            Some(Err(())) => EvidenceCheck::Unreadable,
            Some(Ok(bytes)) if sha256_hex(&bytes) == sha256 => EvidenceCheck::Intact,
            Some(Ok(_)) => EvidenceCheck::Mismatch,
        }
    }
}

/// Whether `dir` is a real directory (not a link or junction).
fn real_dir(dir: &Path) -> bool {
    matches!(
        std::fs::symlink_metadata(dir),
        Ok(metadata) if metadata.is_dir() && !crate::browser_broker::is_reparse(&metadata)
    )
}

/// The bytes of the regular file at `path`: `None` when nothing is there,
/// `Some(Err)` for a link, a directory or an unreadable file.
fn read_regular(path: &Path) -> Option<Result<Vec<u8>, ()>> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => Some(Err(())),
        Ok(metadata) if !metadata.is_file() || crate::browser_broker::is_reparse(&metadata) => {
            Some(Err(()))
        }
        Ok(metadata) if metadata.len() > MAX_EVIDENCE_FILE_BYTES as u64 => Some(Err(())),
        Ok(_) => Some(std::fs::read(path).map_err(|_| ())),
    }
}

pub(crate) fn now_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0)
}

/// What the verifier found at one evidence file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EvidenceCheck {
    Intact,
    Missing,
    Mismatch,
    Unreadable,
    Malformed,
}

impl EvidenceCheck {
    fn as_str(self) -> &'static str {
        match self {
            Self::Intact => "intact",
            Self::Missing => "missing",
            Self::Mismatch => "mismatch",
            Self::Unreadable => "unreadable",
            Self::Malformed => "malformed",
        }
    }
}

/// How an action ended, as a receipt says it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Disposition {
    /// `sent`, `refused`, `failed`, `superseded` or `unknown`.
    pub result: &'static str,
    /// `applied`, `none` or `unknown`: whether the action took effect.
    pub effect: &'static str,
    /// Whether a person is needed: a page that waits for them, a person
    /// using the window, or an outcome only they can reconcile.
    pub needs_person: bool,
}

/// The receipt's disposition from the broker's `outcome` word (`done`,
/// `denied`, `refused`, `not_dispatched`, `failed` or `unknown`), the
/// refusal's failure code, and whether a person's input arrived while the
/// action was in flight (`superseded`).
pub(crate) fn disposition(
    outcome: &str,
    failure_code: Option<&str>,
    superseded: bool,
) -> Disposition {
    let person = matches!(
        failure_code,
        Some("HUMAN_TAKEOVER" | "HUMAN_VERIFICATION_REQUIRED")
    );
    let (result, effect) = match outcome {
        // The frame ran, and the person acted during it: the person's edits
        // win and the agent must observe again.
        "done" if superseded => ("superseded", "applied"),
        "done" => ("sent", "applied"),
        "denied" | "refused" => ("refused", "none"),
        // A late takeover refusal (after the approval was spent, before the
        // frame) is a refusal: nothing reached the page.
        "failed" if person => ("refused", "none"),
        // The host refused before acting, or orceld could not send it.
        "failed" | "not_dispatched" => ("failed", "none"),
        _ => ("unknown", "unknown"),
    };
    Disposition {
        result,
        effect,
        needs_person: person || superseded || result == "unknown",
    }
}

/// The digest a receipt keeps of a URL: the whole URL's SHA-256 (spec 4.8:
/// URLs and query strings appear in the chain only as digests).
pub(crate) fn url_digest(url: &str) -> String {
    sha256_hex(url.as_bytes())
}

/// The committed URL a page action's reply names (`url`, or a new tab's
/// `navigation.url`), as a digest. Nothing else of the reply is kept.
pub(crate) fn reply_url_digest(reply: &Value) -> Option<String> {
    reply
        .get("url")
        .and_then(Value::as_str)
        .or_else(|| reply.pointer("/navigation/url").and_then(Value::as_str))
        .filter(|url| !url.is_empty())
        .map(url_digest)
}

/// The node targets of a snapshot frame: node id to (role, keyed name
/// digest), at most [`MAX_TARGETS`].
pub(crate) fn targets_from_nodes(nodes: &Value) -> BTreeMap<String, (String, String)> {
    let mut targets = BTreeMap::new();
    let mut stack: Vec<&Value> = vec![nodes];
    while let Some(value) = stack.pop() {
        if targets.len() >= MAX_TARGETS {
            break;
        }
        match value {
            Value::Array(items) => stack.extend(items.iter()),
            Value::Object(node) => {
                if let (Some(id), Some(role), Some(name)) = (
                    node.get("node_id").and_then(Value::as_str),
                    node.get("role").and_then(Value::as_str),
                    node.get("name_digest").and_then(Value::as_str),
                ) {
                    targets.insert(id.to_owned(), (role.to_owned(), name.to_owned()));
                }
                if let Some(children) = node.get("children") {
                    stack.push(children);
                }
            }
            _ => {}
        }
    }
    targets
}

/// What live dispatch knows of an action before it runs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct IntentDraft {
    pub action: String,
    pub page_id: Option<String>,
    pub generation_before: Option<u64>,
    pub origin_before: Option<String>,
    /// The URL the action asks for (an open, a new tab), as a digest.
    pub url_sha256: Option<String>,
    pub target: Option<ReceiptTarget>,
    /// The approval epoch the action is checked against before it runs.
    pub approval_epoch: Option<u64>,
}

/// An action's intent as written to the chain before anything is sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Intent {
    pub seq: u64,
    pub session_id: String,
    pub mode: String,
    /// SG-000135 OB-09: the session's caller (local, or the remote
    /// provider, device and paired connection).
    pub caller: crate::browser_remote::Caller,
    pub profile: Option<String>,
    pub draft: IntentDraft,
    pub at_ms: u64,
    /// The session's receipt chain head when the intent was written.
    pub previous_receipt_sha256: String,
    pub intent_sha256: String,
    pub audit: ReceiptAudit,
}

impl Intent {
    pub(crate) fn to_json(&self) -> Value {
        json!({
            "contract": INTENT_CONTRACT,
            "seq": self.seq,
            "session_id": self.session_id,
            "action": self.draft.action,
            "mode": self.mode,
            "caller": self.caller.to_json(),
            "profile": self.profile,
            "page_id": self.draft.page_id,
            "generation_before": self.draft.generation_before,
            "origin_before": self.draft.origin_before,
            "url_sha256": self.draft.url_sha256,
            "target": self.draft.target.as_ref().map(ReceiptTarget::to_json),
            "approval_epoch": self.draft.approval_epoch,
            "at_ms": self.at_ms,
            "previous_receipt_sha256": self.previous_receipt_sha256,
            "intent_sha256": self.intent_sha256,
            "audit": self.audit.to_json(),
        })
    }

    pub(crate) fn digest(&self) -> String {
        intent_digest_of(&self.to_json()).unwrap_or_default()
    }

    /// The chain event of the intent (without its own chain place).
    pub(crate) fn audit_draft(&self, client: &str) -> orcel_audit::EventDraft {
        let mut intent = self.to_json();
        if let Value::Object(map) = &mut intent {
            map.remove("audit");
        }
        orcel_audit::EventDraft {
            principal_id: Some(client.to_owned()),
            capability: Some("browser.session".to_owned()),
            operation: Some(self.draft.action.clone()),
            ..orcel_audit::EventDraft::new(
                orcel_contracts::event::AuditEventKind::Dispatch,
                json!({"source": SOURCE_INTENT, "intent": intent}),
            )
        }
    }
}

/// Exit code `orceld audit-verify --receipts` gives when a receipt, intent
/// or evidence file does not verify (unless the chain itself is broken or
/// missing, whose code wins).
pub(crate) const EXIT_RECEIPTS_BROKEN: i32 = 9;
/// ...or, with the chain intact, every receipt verifies but some intent has
/// no receipt.
pub(crate) const EXIT_RECEIPTS_UNRECORDED: i32 = 10;

/// What the receipt verifier found.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ReceiptReport {
    pub value: Value,
    pub broken: bool,
    pub unrecorded: bool,
}

/// One intent seen in the chain, waiting for its receipt.
struct OpenIntent {
    event_seq: u64,
    event_digest: String,
    intent_sha256: String,
    action: String,
    at_ms: u64,
}

/// What the verifier knows of one session while it reads the chain.
#[derive(Default)]
struct SessionSeen {
    /// Its `session_start` is in this file.
    started: bool,
    /// Its `session_end` is in this file (the event's seq).
    ended: Option<u64>,
    /// The highest intent seq seen.
    last_intent: u64,
    /// The receipt chain head.
    head: String,
    /// An OB-05 intent or receipt of the session was seen.
    ob05: bool,
    /// SG-000135 SH-2: the mode its start named, why it ended, and whether
    /// a later session already continues it.
    mode: Option<String>,
    end_reason: Option<String>,
    continued: bool,
}

/// One evidence file a receipt names, checked once the whole file is read
/// (a later event may say it was pruned or its scope removed).
struct NamedFile {
    event_seq: u64,
    session: String,
    seq: u64,
    scope: String,
    kind: String,
    sha256: String,
    stored: bool,
    reason: Option<String>,
}

/// Verify every browser intent and receipt in the chain file at `chain`:
///
/// - each digest recomputes from its fields, and each receipt's result,
///   effect and needs-person words follow from its outcome and code;
/// - each receipt names the intent written before it (same session, seq and
///   action, the intent's digest and its place in the chain);
/// - each session's intents are numbered in order with no repeat (and no gap
///   once its start is in the file), and its receipts chain by digest;
/// - a session's end names its last receipt and its count of actions, and
///   nothing of the session follows its end;
/// - every stored evidence file in `evidence` hashes to its name, unless the
///   chain records it pruned or its scope removed.
///
/// Intents with no receipt are listed as `dispatched_unrecorded`. With
/// `only`, the report also says whether the receipt with that digest is in
/// the file and whether it lies at or below `anchored_through`, the last
/// event the authority service's held anchor covers.
///
/// This checks receipts, not the chain: the chain's own digests and anchors
/// are `orcel_audit::verify_with_holder`'s.
pub(crate) fn verify_receipts(
    chain: &Path,
    evidence: Option<&EvidenceStore>,
    only: Option<&str>,
    anchored_through: Option<u64>,
) -> Result<ReceiptReport, String> {
    let text = std::fs::read_to_string(chain).map_err(|error| error.to_string())?;
    let mut intents = 0u64;
    let mut receipts = 0u64;
    let mut legacy = 0u64;
    let mut digest_errors = Vec::new();
    let mut link_errors: Vec<Value> = Vec::new();
    let mut open: BTreeMap<(String, u64), OpenIntent> = BTreeMap::new();
    let mut seen_intents: std::collections::BTreeSet<(String, u64)> = Default::default();
    let mut sessions: BTreeMap<String, SessionSeen> = BTreeMap::new();
    let mut named: Vec<NamedFile> = Vec::new();
    let mut pruned: std::collections::BTreeSet<(String, String)> = Default::default();
    let mut removed: std::collections::BTreeSet<String> = Default::default();
    let mut found: Option<Value> = None;
    let mut link = |event_seq: u64, session: &str, seq: u64, reason: &str| {
        link_errors.push(json!({
            "event_seq": event_seq, "session_id": session, "seq": seq, "reason": reason,
        }));
    };
    for line in text.lines() {
        let Ok(event) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let event_seq = event["seq"].as_u64().unwrap_or(u64::MAX);
        let event_digest = event["digest"].as_str().unwrap_or_default().to_owned();
        let detail = &event["detail"];
        match detail["source"].as_str() {
            Some(SOURCE_SESSION) => {
                let session = detail["session_id"].as_str().unwrap_or_default().to_owned();
                match detail["event"].as_str() {
                    Some("session_start") => {
                        let state = sessions.entry(session.clone()).or_default();
                        if state.started || state.ob05 {
                            link(
                                event_seq,
                                &session,
                                0,
                                "the session starts twice or after its actions",
                            );
                        }
                        state.started = true;
                        state.mode = detail["mode"].as_str().map(str::to_owned);
                        // SG-000135 SH-2: a session that continues another
                        // after a mode switch names it; when that session is
                        // in this file, it ended for the switch, in the other
                        // mode, with the last receipt named here, and no
                        // other session continues it. A session outside
                        // this file is unverifiable: not checked, and never
                        // counted as verified.
                        let link_to = &detail["continued_from"];
                        if !link_to.is_null() {
                            let from = link_to["session_id"].as_str().unwrap_or_default();
                            let mode = state.mode.clone();
                            if let Some(previous) =
                                sessions.get_mut(from).filter(|previous| previous.started)
                            {
                                let broken = previous.end_reason.as_deref() != Some("mode_switch")
                                    || previous.continued
                                    || link_to["mode"].as_str() != previous.mode.as_deref()
                                    || previous.mode == mode
                                    || link_to["last_receipt_sha256"].as_str()
                                        != Some(previous.head.as_str());
                                previous.continued = true;
                                if broken {
                                    link(
                                        event_seq,
                                        &session,
                                        0,
                                        "the session continues a session that did not end for a mode switch to it",
                                    );
                                }
                            }
                        }
                    }
                    Some("session_end") => {
                        let state = sessions.entry(session.clone()).or_default();
                        if state.ended.is_some() {
                            link(event_seq, &session, 0, "the session ends twice");
                        }
                        if detail["actions_recorded"].as_u64() != Some(state.last_intent) {
                            link(event_seq, &session, state.last_intent, "the session's end counts another number of actions than its intents");
                        }
                        if detail["last_receipt_sha256"].as_str() != Some(state.head.as_str()) {
                            link(
                                event_seq,
                                &session,
                                state.last_intent,
                                "the session's end names another last receipt",
                            );
                        }
                        state.ended = Some(event_seq);
                        state.end_reason = detail["reason"].as_str().map(str::to_owned);
                        if detail["evidence_removed"] == Value::Bool(true) {
                            removed.insert(session.clone());
                        }
                    }
                    Some("evidence_swept") => {
                        for scope in detail["scopes"].as_array().into_iter().flatten() {
                            if let Some(scope) = scope.as_str() {
                                removed.insert(scope.to_owned());
                            }
                        }
                    }
                    Some("profile_evidence_removed") => {
                        if let Some(profile) = detail["profile"].as_str() {
                            removed.insert(profile_scope(profile));
                        }
                    }
                    Some("evidence_pruned") => {
                        for file in detail["files"].as_array().into_iter().flatten() {
                            pruned.insert((
                                file["scope"].as_str().unwrap_or_default().to_owned(),
                                file["sha256"].as_str().unwrap_or_default().to_owned(),
                            ));
                        }
                    }
                    _ => {}
                }
            }
            Some(SOURCE_INTENT) => {
                intents += 1;
                let intent = &detail["intent"];
                let session = intent["session_id"].as_str().unwrap_or_default().to_owned();
                let seq = intent["seq"].as_u64().unwrap_or(0);
                let claimed = intent["intent_sha256"].as_str().unwrap_or_default();
                if intent_digest_of(intent).as_deref() != Some(claimed) {
                    digest_errors.push(json!({
                        "event_seq": event_seq, "kind": "intent", "session_id": session, "seq": seq,
                    }));
                }
                let state = sessions.entry(session.clone()).or_default();
                state.ob05 = true;
                if state.ended.is_some() {
                    link(
                        event_seq,
                        &session,
                        seq,
                        "an intent follows the session's end",
                    );
                }
                if !seen_intents.insert((session.clone(), seq)) {
                    link(
                        event_seq,
                        &session,
                        seq,
                        "a second intent with the same seq",
                    );
                } else if (state.started && seq != state.last_intent + 1)
                    || seq <= state.last_intent
                {
                    link(
                        event_seq,
                        &session,
                        seq,
                        "the intent is out of order or leaves a gap",
                    );
                }
                state.last_intent = state.last_intent.max(seq);
                if intent["previous_receipt_sha256"].as_str() != Some(state.head.as_str()) {
                    link(
                        event_seq,
                        &session,
                        seq,
                        "the intent does not follow the session's last receipt",
                    );
                }
                open.insert(
                    (session, seq),
                    OpenIntent {
                        event_seq,
                        event_digest,
                        intent_sha256: claimed.to_owned(),
                        action: intent["action"].as_str().unwrap_or_default().to_owned(),
                        at_ms: intent["at_ms"].as_u64().unwrap_or(0),
                    },
                );
            }
            Some(SOURCE_RECEIPT) => {
                let receipt = &detail["receipt"];
                let session = receipt["session_id"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned();
                let seq = receipt["seq"].as_u64().unwrap_or(0);
                let state = sessions.entry(session.clone()).or_default();
                if receipt["contract"].as_str() != Some(RECEIPT_CONTRACT) {
                    // Written before OB-05 (provisional, another digest
                    // scheme): covered by the chain's digests only, and
                    // never inside a session that has OB-05 records.
                    if state.ob05 || state.started {
                        link(
                            event_seq,
                            &session,
                            seq,
                            "a receipt without the OB-05 contract in an OB-05 session",
                        );
                    } else {
                        legacy += 1;
                    }
                    continue;
                }
                receipts += 1;
                state.ob05 = true;
                let claimed = receipt["receipt_sha256"].as_str().unwrap_or_default();
                let digest_ok = receipt_digest_of(receipt).as_deref() == Some(claimed);
                if !digest_ok {
                    digest_errors.push(json!({
                        "event_seq": event_seq, "kind": "receipt", "session_id": session, "seq": seq,
                    }));
                }
                let mut problems: Vec<&str> = Vec::new();
                if state.ended.is_some() {
                    problems.push("a receipt follows the session's end");
                }
                if receipt["previous_sha256"].as_str() != Some(state.head.as_str()) {
                    problems.push("the receipt does not follow the session's last receipt");
                }
                let words = disposition(
                    receipt["outcome"].as_str().unwrap_or_default(),
                    receipt["failure_code"].as_str(),
                    receipt["result"].as_str() == Some("superseded"),
                );
                if receipt["result"].as_str() != Some(words.result)
                    || receipt["effect"].as_str() != Some(words.effect)
                    || receipt["needs_person"].as_bool() != Some(words.needs_person)
                {
                    problems.push("the receipt's result, effect or needs_person does not follow from its outcome");
                }
                match open.remove(&(session.clone(), seq)) {
                    Some(intent) => {
                        if receipt["intent_sha256"].as_str() != Some(intent.intent_sha256.as_str())
                        {
                            problems.push("the receipt names another intent digest");
                        }
                        if receipt["action"].as_str() != Some(intent.action.as_str()) {
                            problems.push("the receipt's action is not its intent's");
                        }
                        let place = &receipt["intent_audit"];
                        if place["seq"].as_u64() != Some(intent.event_seq)
                            || place["digest"].as_str() != Some(intent.event_digest.as_str())
                        {
                            problems.push(
                                "the receipt names no place, or another place, for its intent",
                            );
                        }
                    }
                    None => problems.push("no intent was written before the receipt"),
                }
                for reason in &problems {
                    link(event_seq, &session, seq, reason);
                }
                for file in receipt["evidence_files"].as_array().into_iter().flatten() {
                    named.push(NamedFile {
                        event_seq,
                        session: session.clone(),
                        seq,
                        scope: file["scope"].as_str().unwrap_or_default().to_owned(),
                        kind: file["kind"].as_str().unwrap_or_default().to_owned(),
                        sha256: file["sha256"].as_str().unwrap_or_default().to_owned(),
                        stored: file["stored"] == Value::Bool(true),
                        reason: file["reason"].as_str().map(str::to_owned),
                    });
                }
                if only == Some(claimed) {
                    let anchoring = match anchored_through {
                        Some(through) if event_seq <= through => json!({
                            "state": "anchored",
                            "note": "at or below the last event the authority service's held anchor covers",
                        }),
                        Some(through) => json!({
                            "state": "unanchored_tail",
                            "anchored_through": through,
                            "note": "after the last held anchor (anchors come every 32 events): up to 31 events here are protected by the chain's digests only, which anyone who can write orceld's state folder could recompute",
                        }),
                        None => json!({
                            "state": "unanchored",
                            "note": "the authority service holds no anchor of this chain (without the installed service there are no anchors at all): the receipt is protected by the chain's digests only, which anyone who can write orceld's state folder could recompute",
                        }),
                    };
                    found = Some(json!({
                        "found": true,
                        "event_seq": event_seq,
                        "event_digest": event_digest,
                        "session_id": session,
                        "seq": seq,
                        "action": receipt["action"],
                        "result": receipt["result"],
                        "digest_recomputes": digest_ok,
                        "link_errors": problems,
                        "anchoring": anchoring,
                    }));
                }
                if let Some(state) = sessions.get_mut(&session) {
                    state.head = claimed.to_owned();
                }
            }
            _ => {}
        }
    }
    // Evidence files, now that every prune and removal is known.
    let mut evidence_checked = 0u64;
    let mut not_stored = 0u64;
    let mut pruned_count = 0u64;
    let mut removed_count = 0u64;
    let mut evidence_errors = Vec::new();
    let mut found_files = Vec::new();
    for file in &named {
        let check = if !file.stored {
            not_stored += 1;
            "not_stored"
        } else {
            match evidence {
                None => "not_checked",
                Some(store) => {
                    evidence_checked += 1;
                    match store.check(&file.scope, &file.kind, &file.sha256) {
                        EvidenceCheck::Intact => "intact",
                        EvidenceCheck::Missing
                            if pruned.contains(&(file.scope.clone(), file.sha256.clone())) =>
                        {
                            pruned_count += 1;
                            "pruned"
                        }
                        EvidenceCheck::Missing if removed.contains(&file.scope) => {
                            removed_count += 1;
                            "removed"
                        }
                        other => {
                            evidence_errors.push(json!({
                                "event_seq": file.event_seq, "session_id": file.session, "seq": file.seq,
                                "scope": file.scope, "kind": file.kind, "sha256": file.sha256,
                                "check": other.as_str(),
                            }));
                            other.as_str()
                        }
                    }
                }
            }
        };
        if found
            .as_ref()
            .is_some_and(|found| found["event_seq"].as_u64() == Some(file.event_seq))
        {
            found_files.push(json!({
                "scope": file.scope, "kind": file.kind, "sha256": file.sha256,
                "check": check, "reason": file.reason,
            }));
        }
    }
    if let Some(Value::Object(map)) = found.as_mut() {
        map.insert("evidence".into(), Value::Array(found_files));
    }
    let unrecorded: Vec<Value> = open
        .iter()
        .map(|((session, seq), intent)| {
            json!({
                "event_seq": intent.event_seq,
                "session_id": session,
                "seq": seq,
                "action": intent.action,
                "intent_at_ms": intent.at_ms,
                "state": "DISPATCHED_UNRECORDED",
            })
        })
        .collect();
    let broken =
        !(digest_errors.is_empty() && link_errors.is_empty() && evidence_errors.is_empty())
            || (only.is_some()
                && found.as_ref().is_none_or(|found| {
                    found["digest_recomputes"] != Value::Bool(true)
                        || found["link_errors"]
                            .as_array()
                            .is_some_and(|errors| !errors.is_empty())
                }));
    let unrecorded_any = !unrecorded.is_empty();
    let mut value = Map::new();
    value.insert(
        "verdict".into(),
        json!(if broken {
            "broken"
        } else if unrecorded_any {
            "unrecorded"
        } else {
            "intact"
        }),
    );
    value.insert("intents".into(), json!(intents));
    value.insert("receipts".into(), json!(receipts));
    value.insert("legacy_receipts".into(), json!(legacy));
    value.insert("sessions".into(), json!(sessions.len()));
    value.insert("digest_errors".into(), Value::Array(digest_errors));
    value.insert("link_errors".into(), Value::Array(link_errors));
    value.insert("dispatched_unrecorded".into(), Value::Array(unrecorded));
    value.insert(
        "evidence".into(),
        json!({
            "dir": evidence.map(|store| store.dir().display().to_string()),
            "checked": evidence_checked,
            "not_stored": not_stored,
            "pruned": pruned_count,
            "removed": removed_count,
            "errors": evidence_errors,
        }),
    );
    if let Some(digest) = only {
        value.insert(
            "receipt".into(),
            found.unwrap_or_else(|| json!({"found": false, "receipt_sha256": digest})),
        );
    }
    value.insert(
        "note".into(),
        json!("receipts and intents are checked here; the chain's own digests, links and anchors are in the report above. dispatched_unrecorded lists actions whose intent was written but whose outcome was not (orceld stopped, or the chain refused the receipt): the action may have run. Events after the last anchor the authority service holds (and every event, without the installed service) are protected by digests only: a writer of orceld's state folder could append or rewrite them consistently. A forged receipt appended after a session's end is found; one inside an unanchored tail is not."),
    );
    Ok(ReceiptReport {
        value: Value::Object(value),
        broken,
        unrecorded: unrecorded_any,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ob05_disposition_states_what_completed_what_is_uncertain_and_who_is_needed() {
        let cases = [
            ("done", None, false, ("sent", "applied", false)),
            ("done", None, true, ("superseded", "applied", true)),
            (
                "denied",
                Some("APPROVAL_DENIED"),
                false,
                ("refused", "none", false),
            ),
            (
                "refused",
                Some("HUMAN_TAKEOVER"),
                false,
                ("refused", "none", true),
            ),
            (
                "refused",
                Some("HUMAN_VERIFICATION_REQUIRED"),
                false,
                ("refused", "none", true),
            ),
            // A takeover after the approval was spent, before the frame.
            (
                "failed",
                Some("HUMAN_TAKEOVER"),
                false,
                ("refused", "none", true),
            ),
            (
                "failed",
                Some("TARGET_STALE"),
                false,
                ("failed", "none", false),
            ),
            (
                "not_dispatched",
                Some("PROVIDER_UNAVAILABLE"),
                false,
                ("failed", "none", false),
            ),
            (
                "unknown",
                Some("TARGET_STALE"),
                false,
                ("unknown", "unknown", true),
            ),
            ("anything", None, false, ("unknown", "unknown", true)),
        ];
        for (outcome, code, superseded, (result, effect, person)) in cases {
            let got = disposition(outcome, code, superseded);
            assert_eq!(
                (got.result, got.effect, got.needs_person),
                (result, effect, person),
                "{outcome} {code:?} {superseded}"
            );
        }
    }

    #[test]
    fn ob05_urls_are_kept_as_digests_only() {
        let reply = json!({"url": "https://fixture.test/a?token=SECRET#frag", "value": "typed"});
        let digest = reply_url_digest(&reply).unwrap_or_default();
        assert!(is_sha256(&digest));
        assert_eq!(
            digest,
            url_digest("https://fixture.test/a?token=SECRET#frag")
        );
        let tab = json!({"navigation": {"url": "https://fixture.test/b?code=1"}});
        assert_eq!(
            reply_url_digest(&tab),
            Some(url_digest("https://fixture.test/b?code=1"))
        );
        assert_eq!(reply_url_digest(&json!({"url": ""})), None);
        assert_eq!(reply_url_digest(&json!({})), None);
    }

    #[test]
    fn ob05_targets_come_from_the_snapshot_frame() {
        let nodes = json!([
            {"node_id": "n1", "role": "form", "name_digest": "d1", "value_digest": "v", "redacted": false,
             "children": [
                {"node_id": "n2", "role": "textbox", "name_digest": "d2", "value_digest": "v", "redacted": true, "children": []}
             ]}
        ]);
        let targets = targets_from_nodes(&nodes);
        assert_eq!(
            targets.get("n2"),
            Some(&("textbox".to_owned(), "d2".to_owned()))
        );
        assert_eq!(targets.len(), 2);
    }

    #[test]
    fn ob05_digests_cover_every_field_but_their_own() {
        let value = json!({"a": 1, "b": null, "receipt_sha256": "x", "audit": {"seq": 1}});
        let base = receipt_digest_of(&value).unwrap_or_default();
        let mut moved = value.clone();
        moved["audit"] = json!({"seq": 2});
        moved["receipt_sha256"] = json!("y");
        assert_eq!(receipt_digest_of(&moved).as_deref(), Some(base.as_str()));
        for (key, changed) in [("a", json!(2)), ("b", json!("")), ("c", json!(null))] {
            let mut other = value.clone();
            other[key] = changed;
            assert_ne!(
                receipt_digest_of(&other).as_deref(),
                Some(base.as_str()),
                "{key}"
            );
        }
        assert_ne!(intent_digest_of(&value), receipt_digest_of(&value));
        assert_eq!(receipt_digest_of(&json!([])), None);
    }

    fn sandbox(label: &str) -> Result<PathBuf, String> {
        let dir = std::env::temp_dir().join(format!(
            "orceld-ob05-{label}-{}-{}",
            std::process::id(),
            now_nanos()
        ));
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        Ok(dir)
    }

    const SCOPE: &str = "bs-0123456789abcdef-1-0001020304050607";

    /// SG-000135 OB-05 re-review: the e2e harness recomputes receipt digests
    /// leaving out exactly the fields the Rust digest leaves out.
    #[test]
    fn ob05_the_e2e_harness_leaves_out_the_same_receipt_fields() {
        let script = include_str!("../../../scripts/browser-full-e2e.mjs");
        let body = script
            .split("function receiptDigest(receipt) {")
            .nth(1)
            .and_then(|rest| rest.split("\n}\n").next())
            .unwrap_or_default();
        let deleted: Vec<&str> = body
            .lines()
            .filter_map(|line| line.trim().strip_prefix("delete core."))
            .map(|rest| rest.trim_end_matches(';'))
            .collect();
        let mut expected = RECEIPT_UNCOVERED.to_vec();
        let mut got = deleted.clone();
        expected.sort_unstable();
        got.sort_unstable();
        assert_eq!(got, expected, "{body}");
        assert!(script.contains(&format!("const RECEIPT_DOMAIN = \"{RECEIPT_DOMAIN}\";")));
    }

    #[test]
    fn ob05_the_evidence_store_is_content_addressed_and_detects_tampering() -> Result<(), String> {
        let dir = sandbox("evidence")?;
        let store = EvidenceStore::at(dir.clone());
        let (shot, pruned) =
            store.put(SCOPE, EvidenceKind::Screenshot, b"\x89PNG fake image bytes");
        assert!(shot.stored && shot.reason.is_none() && pruned.is_empty());
        assert_eq!(shot.sha256, sha256_hex(b"\x89PNG fake image bytes"));
        assert_eq!(shot.to_json()["scope"], SCOPE);
        assert_eq!(
            store.check(SCOPE, "screenshot", &shot.sha256),
            EvidenceCheck::Intact
        );
        // The same bytes again: one file.
        assert!(
            store
                .put(SCOPE, EvidenceKind::Screenshot, b"\x89PNG fake image bytes")
                .0
                .stored
        );
        let files = std::fs::read_dir(dir.join(SCOPE))
            .map_err(|e| e.to_string())?
            .count();
        assert_eq!(files, 1);
        let path = dir.join(SCOPE).join(format!("{}.png", shot.sha256));
        std::fs::write(&path, b"edited").map_err(|e| e.to_string())?;
        assert_eq!(
            store.check(SCOPE, "screenshot", &shot.sha256),
            EvidenceCheck::Mismatch
        );
        // A tampered file is never adopted as the evidence it claims.
        let (again, _) = store.put(SCOPE, EvidenceKind::Screenshot, b"\x89PNG fake image bytes");
        assert!(!again.stored);
        assert_eq!(again.reason, Some("conflict"));
        std::fs::remove_file(&path).map_err(|e| e.to_string())?;
        assert_eq!(
            store.check(SCOPE, "screenshot", &shot.sha256),
            EvidenceCheck::Missing
        );
        assert_eq!(
            store.check(SCOPE, "screenshot", "../x"),
            EvidenceCheck::Malformed
        );
        assert_eq!(
            store.check("..", "screenshot", &shot.sha256),
            EvidenceCheck::Malformed
        );
        assert_eq!(
            store.check(SCOPE, "cookies", &shot.sha256),
            EvidenceCheck::Malformed
        );
        let large = vec![0u8; MAX_EVIDENCE_FILE_BYTES + 1];
        let (kept, _) = store.put(SCOPE, EvidenceKind::Snapshot, &large);
        assert_eq!((kept.stored, kept.reason), (false, Some("too_large")));
        assert_eq!(kept.sha256, sha256_hex(&large));
        // A bad scope or a store whose folder is gone keeps nothing and says so.
        assert_eq!(
            store.put("../up", EvidenceKind::Snapshot, b"{}").0.reason,
            Some("no_store")
        );
        let gone = EvidenceStore::at(dir.join("absent"));
        assert_eq!(
            gone.put(SCOPE, EvidenceKind::Snapshot, b"{}").0.reason,
            Some("no_store")
        );
        let _ = std::fs::remove_dir_all(dir);
        Ok(())
    }

    /// SG-000135 OB-05 review: the store keeps a byte quota and a file cap,
    /// pruning the oldest files first and naming each; a scope is removed as
    /// a whole.
    #[test]
    fn ob05_the_evidence_store_prunes_the_oldest_and_removes_a_scope() -> Result<(), String> {
        let dir = sandbox("quota")?;
        let store = EvidenceStore::at(dir.clone()).bounded(10, 2);
        let other = "p-work";
        let (a, _) = store.put(SCOPE, EvidenceKind::Snapshot, b"aaaa");
        std::thread::sleep(std::time::Duration::from_millis(20));
        let (b, _) = store.put(other, EvidenceKind::Snapshot, b"bbbb");
        assert!(a.stored && b.stored);
        std::thread::sleep(std::time::Duration::from_millis(20));
        // A third file passes the cap of 2: the oldest goes, and is named.
        let (c, pruned) = store.put(SCOPE, EvidenceKind::Snapshot, b"cccc");
        assert!(c.stored);
        assert_eq!(
            pruned,
            vec![PrunedFile {
                scope: SCOPE.to_owned(),
                kind: EvidenceKind::Snapshot,
                sha256: a.sha256.clone()
            }]
        );
        assert_eq!(
            store.check(SCOPE, "snapshot", &a.sha256),
            EvidenceCheck::Missing
        );
        // Larger than the quota itself: never stored.
        let (big, _) = store.put(SCOPE, EvidenceKind::Snapshot, b"0123456789a");
        assert_eq!(big.reason, Some("too_large"));
        // A whole scope goes at once; the other stays.
        assert!(store.remove_scope(SCOPE));
        assert_eq!(
            store.check(SCOPE, "snapshot", &c.sha256),
            EvidenceCheck::Missing
        );
        assert_eq!(
            store.check(other, "snapshot", &b.sha256),
            EvidenceCheck::Intact
        );
        assert!(!store.remove_scope(".."));
        assert!(is_scope(&profile_scope("work")));
        let _ = std::fs::remove_dir_all(dir);
        Ok(())
    }
}
