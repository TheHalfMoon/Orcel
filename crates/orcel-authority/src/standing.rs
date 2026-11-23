//! WP1-14: standing approvals (spec 4.15, founder decision FD-UP-10;
//! SG132_SLICE10.md).
//!
//! A standing approval lets one identified client skip the per-action
//! approval of the operations it names, for one declared task, inside its
//! folders, until it ends. It is bound to one Full User lease and to that
//! lease's client (a `cl-` client reference) and task, never covers the
//! `Admin` or `Remote` executors, a remote caller (orceld never names one for
//! a remote request, and the `fc.*` tools are local-only), a browser action
//! (high-impact browser actions keep their own approval in this slice), an
//! operation, folder or program outside it, or another client or task.
//!
//! Issuance: grants are refused while a lease is active (spec 4.13, and the
//! SG-000132 acceptance "Grant, renewal and standing approval fail without a
//! valid Hello signature, and while a lease is active"), and a session lock
//! ends every lease, so a standing approval cannot be added to a running
//! lease through a fresh unlock. It is therefore requested together with its
//! lease (`StandingBegin`) and goes through exactly the lease's gate: the
//! installed owner CLI's image, a recorded intent, a service-observed unlock,
//! the service-rendered confirmation showing the lease scope and the standing
//! approval's client, task, operations, folders, programs and expiry, then
//! Windows Hello (`StandingComplete`), which issues both.
//!
//! The indicator (spec 4.14, WP1-12) is not built. Spec 4.15 says a standing
//! approval is "shown on the indicator", and WP1-14 depends on WP1-12 (spec
//! 8.2), so the service fails closed: `StandingBegin`, `StandingComplete` and
//! an `Authorize` that names a standing approval are refused with
//! `INDICATOR_UNAVAILABLE` unless an indicator heartbeat of the caller's
//! logon session is under [`INDICATOR_HEARTBEAT_MS`] old. No request records
//! a heartbeat yet (`Heartbeat` is WP1-12), so today no standing approval is
//! issued or used and every action keeps its own approval. The heartbeat is
//! disclosure only and proves nothing against a same-user agent (C-27 c).
//!
//! Ending: revoke (`StandingRevoke`, or its lease's `Revoke`), Stop, session
//! lock, sign-out or disconnect, expiry (its own or its lease's) and an epoch
//! move all end it, because each ends or invalidates its lease or it; the
//! service records each end in its audit chain.

use super::{observed, AuthorityCore, LeaseRecord};
use crate::caller::{CallerFacts, CallerRole};
use crate::error::AuthorityError;
use crate::hex;
use crate::lease::{
    check_dispatch_path, executor_name, is_client_ref, is_display_text, path_within_roots,
    LeaseScope, SignedLease, MAX_ROOTS, MAX_ROOT_CHARS,
};
use crate::protocol::{AuthorizeClaims, StandingClaim};
use orcel_contracts::{ExecutorClass, FailureCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// `contract` of a standing approval.
pub const STANDING_CONTRACT: &str = "orcel.standing-approval/1";

/// Standing approval id prefix (`sa-` and 32 lowercase hex characters).
pub const STANDING_ID_PREFIX: &str = "sa-";

/// Spec 4.14: the service treats the indicator as gone 5 s after its last
/// heartbeat.
pub const INDICATOR_HEARTBEAT_MS: u64 = 5_000;

/// The operations a standing approval may name: the ones that otherwise ask
/// a fresh per-action approval on every call (SG-000096 A3, the SG-000132
/// amendment of 2026-11-19): a process run and the four Git changes.
pub const STANDING_OPERATIONS: [&str; 5] = [
    "run",
    "git_add",
    "git_unstage",
    "git_commit",
    "git_branch_create",
];

/// The most programs a standing approval may name.
pub const MAX_STANDING_COMMANDS: usize = 8;

/// Ended standing approval records kept for `List`.
pub const MAX_STANDING_RECORDS: usize = 64;

/// The `fc.*` capability an operation belongs to.
pub fn operation_capability(operation: &str) -> Option<&'static str> {
    match operation {
        "run" => Some("fc.process"),
        "git_add" | "git_unstage" | "git_commit" | "git_branch_create" => Some("fc.git"),
        _ => None,
    }
}

/// Whether two program paths name the same file, compared as the roots are
/// (case-insensitive, either slash).
pub fn same_program(left: &str, right: &str) -> bool {
    let normalize = |text: &str| text.replace('/', "\\").to_lowercase();
    normalize(left) == normalize(right)
}

/// What the owner asks a standing approval to cover (`StandingBegin`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandingScope {
    /// `shell_process` only in this slice (process runs and Git changes);
    /// never `admin` or `remote`.
    pub executors: Vec<ExecutorClass>,
    /// Some of [`STANDING_OPERATIONS`].
    pub operations: Vec<String>,
    /// Folders inside the lease's roots; every path a covered dispatch
    /// names must lie inside one of them.
    pub roots: Vec<String>,
    /// Must be empty: browser actions keep their own approval.
    #[serde(default)]
    pub origins: Vec<String>,
    /// When present, the only programs (absolute `.exe` paths inside
    /// `roots`) a covered `run` may start; requires `run`.
    #[serde(default)]
    pub commands: Option<Vec<String>>,
    /// At most the lease's minutes; absent means the lease's.
    #[serde(default)]
    pub minutes: Option<u64>,
}

fn invalid(message: &str) -> AuthorityError {
    AuthorityError::invalid(message)
}

/// `INDICATOR_UNAVAILABLE`: no live indicator heartbeat (WP1-12).
pub fn indicator_unavailable() -> AuthorityError {
    AuthorityError::new(
        FailureCode::IndicatorUnavailable,
        "standing approvals need the Orcel indicator (spec 4.15: shown on the indicator), and no indicator heartbeat of this logon session is live; the indicator (WP1-12) is not built yet, so each action keeps its own approval",
    )
}

impl StandingScope {
    /// Refuses anything out of shape for `lease` (the lease it is granted
    /// with), its client `principal_id` and its `lease_minutes`. Called
    /// before an intent is recorded.
    pub fn validate(
        &self,
        lease: &LeaseScope,
        principal_id: &str,
        lease_minutes: u64,
    ) -> Result<(), AuthorityError> {
        if self.executors.contains(&ExecutorClass::Admin) {
            return Err(AuthorityError::denied(
                "a standing approval never covers the Admin executor: the authority service never elevates (SG-000098)",
            ));
        }
        if self.executors.contains(&ExecutorClass::Remote) {
            return Err(AuthorityError::denied(
                "a standing approval never covers remote callers (spec 4.15; SG-000105)",
            ));
        }
        if !self.origins.is_empty() {
            return Err(AuthorityError::denied(
                "a standing approval for browser actions is not available: browser actions keep their own approval",
            ));
        }
        let LeaseScope::DesktopFullUser {
            executors: lease_executors,
            roots: lease_roots,
            ..
        } = lease
        else {
            return Err(AuthorityError::denied(
                "a standing approval is granted with a desktop Full User lease; browser actions keep their own approval",
            ));
        };
        if !is_client_ref(principal_id) {
            return Err(invalid(
                "a standing approval is for one identified client: name its client reference (cl- and 32 hex characters, as fc_status reports it)",
            ));
        }
        if self.executors.is_empty() {
            return Err(invalid("a standing approval names its executor"));
        }
        for (index, executor) in self.executors.iter().enumerate() {
            if *executor != ExecutorClass::ShellProcess {
                return Err(invalid(&format!(
                    "a standing approval covers the shell_process executor only (process runs and Git changes), not {}",
                    executor_name(*executor)
                )));
            }
            if self.executors[..index].contains(executor) {
                return Err(invalid("an executor is named twice"));
            }
            if !lease_executors.contains(executor) {
                return Err(invalid(
                    "a standing approval names only executors its lease grants",
                ));
            }
        }
        if self.operations.is_empty() {
            return Err(invalid("a standing approval names at least one operation"));
        }
        for (index, operation) in self.operations.iter().enumerate() {
            if !STANDING_OPERATIONS.contains(&operation.as_str()) {
                return Err(invalid(
                    "a standing approval names only run, git_add, git_unstage, git_commit or git_branch_create",
                ));
            }
            if self.operations[..index].contains(operation) {
                return Err(invalid("an operation is named twice"));
            }
        }
        if self.roots.is_empty() || self.roots.len() > MAX_ROOTS {
            return Err(invalid(
                "a standing approval names 1 to 8 folders inside its lease's roots",
            ));
        }
        for (index, root) in self.roots.iter().enumerate() {
            check_shown_path(root)?;
            if !path_within_roots(root, lease_roots) {
                return Err(AuthorityError::denied(
                    "a standing approval's folder lies outside its lease's roots",
                ));
            }
            if self.roots[..index]
                .iter()
                .any(|other| other.eq_ignore_ascii_case(root))
            {
                return Err(invalid("a folder is named twice"));
            }
        }
        if let Some(commands) = &self.commands {
            if !self.operations.iter().any(|operation| operation == "run") {
                return Err(invalid("programs are named only for the run operation"));
            }
            if commands.is_empty() || commands.len() > MAX_STANDING_COMMANDS {
                return Err(invalid("a standing approval names 1 to 8 programs"));
            }
            for (index, command) in commands.iter().enumerate() {
                check_shown_path(command)?;
                if !command.to_ascii_lowercase().ends_with(".exe") {
                    return Err(invalid("a program is an absolute .exe path"));
                }
                if !path_within_roots(command, &self.roots) {
                    return Err(AuthorityError::denied(
                        "a standing approval's program lies outside its folders",
                    ));
                }
                if commands[..index]
                    .iter()
                    .any(|other| same_program(other, command))
                {
                    return Err(invalid("a program is named twice"));
                }
            }
        }
        if let Some(minutes) = self.minutes {
            if minutes == 0 || minutes > lease_minutes {
                return Err(invalid(
                    "a standing approval lasts 1 minute to its lease's minutes",
                ));
            }
        }
        Ok(())
    }

    /// One line for the confirmation and the Event Log.
    pub fn describe(&self) -> String {
        let programs = match &self.commands {
            Some(commands) => commands.join(", "),
            None => "any program inside those folders".to_owned(),
        };
        format!(
            "operations [{}]; folders [{}]; programs [{}]",
            self.operations.join(", "),
            self.roots.join(", "),
            programs
        )
    }
}

/// A folder or program the confirmation shows: printable ASCII within the
/// root bound, and a path the dispatch check accepts.
fn check_shown_path(path: &str) -> Result<(), AuthorityError> {
    if !is_display_text(path, MAX_ROOT_CHARS) {
        return Err(invalid(
            "a standing approval's folder or program is 1 to 128 printable ASCII characters without padding",
        ));
    }
    check_dispatch_path(path)
}

/// A standing approval as the service issued it (spec 4.15's
/// `StandingApproval`, plus the operations it names). Held only by the
/// service; orceld reads it through `List` and names its id in `Authorize`,
/// where the service checks it again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandingApproval {
    pub contract: String,
    pub id: String,
    pub lease_id: String,
    /// The identified client (`cl-` client reference).
    pub principal_id: String,
    /// The declared task (the lease's).
    pub task: String,
    /// Never `admin`.
    pub executors: Vec<ExecutorClass>,
    pub operations: Vec<String>,
    pub roots: Vec<String>,
    /// Always empty in this slice.
    pub origins: Vec<String>,
    pub commands: Option<Vec<String>>,
    pub issued_at_ms: u64,
    /// At most the lease's expiry.
    pub expires_at_ms: u64,
}

/// One dispatch a standing approval may cover, as orceld describes it (and
/// as the service reads it from `Authorize`).
#[derive(Debug, Clone, Copy)]
pub struct Cover<'a> {
    pub lease_id: &'a str,
    pub principal_id: &'a str,
    pub task: &'a str,
    pub executor: ExecutorClass,
    pub capability: &'a str,
    pub operation: &'a str,
    pub paths: &'a [String],
    /// The program a run starts (one of `paths`); `None` for Git.
    pub program: Option<&'a str>,
    /// Must be `None`: browser actions are never covered.
    pub origin: Option<&'a str>,
    pub now_ms: u64,
}

impl StandingApproval {
    /// Whether this approval covers `cover`. The same rule runs in orceld
    /// (to decide whether to ask) and in the service's `Authorize` (which
    /// decides). Every mismatch refuses.
    pub fn check_cover(&self, cover: &Cover<'_>) -> Result<(), AuthorityError> {
        let refuse = |why: &str| {
            Err(AuthorityError::denied(format!(
                "the standing approval does not cover this action: {why}"
            )))
        };
        if matches!(cover.executor, ExecutorClass::Admin | ExecutorClass::Remote) {
            return refuse("it never covers the Admin or Remote executors");
        }
        if cover.lease_id != self.lease_id {
            return refuse("it is bound to another lease");
        }
        if cover.principal_id != self.principal_id {
            return refuse("it was granted to another client");
        }
        if cover.task != self.task {
            return refuse("it was granted for another task");
        }
        if !self.executors.contains(&cover.executor) {
            return refuse("it does not name this executor");
        }
        if !self.operations.iter().any(|op| op == cover.operation) {
            return refuse("it does not name this operation");
        }
        if operation_capability(cover.operation) != Some(cover.capability) {
            return refuse("the operation does not belong to this capability");
        }
        if cover.origin.is_some() || !self.origins.is_empty() {
            return refuse("browser actions keep their own approval");
        }
        if cover.paths.is_empty() {
            return refuse("the action names no paths");
        }
        if !cover
            .paths
            .iter()
            .all(|path| path_within_roots(path, &self.roots))
        {
            return refuse("a path lies outside its folders");
        }
        match (cover.operation, cover.program) {
            ("run", Some(program)) => {
                if !cover.paths.iter().any(|path| same_program(path, program)) {
                    return refuse("the program is not one of the action's paths");
                }
                if let Some(commands) = &self.commands {
                    if !commands
                        .iter()
                        .any(|command| same_program(command, program))
                    {
                        return refuse("it does not name this program");
                    }
                }
            }
            ("run", None) => return refuse("a run names its program"),
            (_, Some(_)) => return refuse("only a run names a program"),
            (_, None) => {}
        }
        if cover.now_ms >= self.expires_at_ms {
            return Err(AuthorityError::lease_invalid(
                "the standing approval has expired",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StandingState {
    Active,
    Ended,
}

/// A standing approval in the service's state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandingRecord {
    pub approval: StandingApproval,
    pub windows_user_sid: String,
    pub logon_session_id: u64,
    pub ts_session_id: u32,
    pub state: StandingState,
    pub ended_at_ms: Option<u64>,
    /// `revoked`, `expired`, `stopped`, `epoch_moved`, ...
    pub ended_by: Option<String>,
}

/// One indicator heartbeat the service observed (in memory only). Only the
/// test seam makes one until WP1-12 adds the indicator's `Heartbeat`, so
/// outside tests the list stays empty and standing approvals fail closed.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct IndicatorBeat {
    pub sid: String,
    pub logon_session_id: u64,
    pub at_ms: u64,
}

impl AuthorityCore {
    /// Whether an indicator heartbeat of this user's logon session is live.
    pub(super) fn indicator_alive(&self, sid: &str, logon_session_id: u64, now: u64) -> bool {
        self.indicator_beats.iter().any(|beat| {
            beat.sid == sid
                && beat.logon_session_id == logon_session_id
                && now.saturating_sub(beat.at_ms) < INDICATOR_HEARTBEAT_MS
        })
    }

    /// TEST SEAM: stands in for the indicator's `Heartbeat` (WP1-12), which
    /// no request records yet.
    #[cfg(test)]
    pub(crate) fn indicator_heartbeat_for_test(&mut self, caller: &CallerFacts) {
        let now = self.now();
        self.indicator_beats.retain(|beat| {
            !(beat.sid == caller.user_sid && beat.logon_session_id == caller.logon_session_id)
        });
        self.indicator_beats.push(IndicatorBeat {
            sid: caller.user_sid.clone(),
            logon_session_id: caller.logon_session_id,
            at_ms: now,
        });
    }

    /// Why a standing record is not in force now (`None` when it is).
    fn standing_ended_by(&self, record: &StandingRecord, now: u64) -> Option<&'static str> {
        if record.state != StandingState::Active {
            return Some("ended");
        }
        if now >= record.approval.expires_at_ms {
            return Some("expired");
        }
        let lease = self
            .state
            .leases
            .iter()
            .find(|lease: &&LeaseRecord| lease.lease.body.lease_id == record.approval.lease_id);
        match lease {
            None => Some("lease_gone"),
            Some(lease) => match self.effective_state(lease, now) {
                "active" => None,
                other => Some(other),
            },
        }
    }

    /// Builds the standing approval issued with `lease` (not yet stored).
    pub(super) fn make_standing(
        &self,
        lease: &SignedLease,
        scope: &StandingScope,
        lease_minutes: u64,
        now: u64,
    ) -> Result<StandingRecord, AuthorityError> {
        let id = format!("{STANDING_ID_PREFIX}{}", hex(&self.random(16)?));
        let minutes = scope.minutes.unwrap_or(lease_minutes);
        let expires_at_ms = now
            .saturating_add(minutes.saturating_mul(60_000))
            .min(lease.body.expires_at_ms);
        Ok(StandingRecord {
            approval: StandingApproval {
                contract: STANDING_CONTRACT.to_owned(),
                id,
                lease_id: lease.body.lease_id.clone(),
                principal_id: lease.body.principal_id.clone(),
                task: lease.body.task.clone(),
                executors: scope.executors.clone(),
                operations: scope.operations.clone(),
                roots: scope.roots.clone(),
                origins: Vec::new(),
                commands: scope.commands.clone(),
                issued_at_ms: now,
                expires_at_ms,
            },
            windows_user_sid: lease.body.windows_user_sid.clone(),
            logon_session_id: lease.body.logon_session_id,
            ts_session_id: lease.body.ts_session_id,
            state: StandingState::Active,
            ended_at_ms: None,
            ended_by: None,
        })
    }

    /// Records an issued standing approval in the audit chain and the Event
    /// Log (4101, beside its lease's entry).
    pub(super) fn record_standing_issued(
        &mut self,
        approval: &StandingApproval,
        intent_id: &str,
    ) -> Result<(), AuthorityError> {
        self.audit_service(
            "standing",
            json!({
                "decision": "issued",
                "standing": approval,
                "intent_id": intent_id,
                "epoch": self.state.epoch,
            }),
        )?;
        let programs = approval
            .commands
            .as_ref()
            .map(|commands| commands.join(", "))
            .unwrap_or_else(|| "any in the folders".to_owned());
        self.event(
            crate::EVENT_GRANTED_SCOPE,
            false,
            &format!(
                "orcel-standing/1|{}|lease {}|operations [{}]|folders [{}]|programs [{}]|client {}|task {}|expires {}|epoch {}",
                approval.id,
                approval.lease_id,
                approval.operations.join(", "),
                approval.roots.join(", "),
                programs,
                approval.principal_id,
                approval.task,
                approval.expires_at_ms,
                self.state.epoch
            ),
        )
    }

    /// Ends every standing approval that is no longer in force (its lease
    /// revoked, stopped, expired or from another epoch, or its own expiry)
    /// and records each end. Runs after every request and every tick.
    pub(super) fn sweep_standing(&mut self, now: u64) {
        let mut ended = Vec::new();
        for index in 0..self.state.standing.len() {
            if self.state.standing[index].state != StandingState::Active {
                continue;
            }
            if let Some(reason) = self.standing_ended_by(&self.state.standing[index], now) {
                let record = &mut self.state.standing[index];
                record.state = StandingState::Ended;
                record.ended_at_ms = Some(now);
                record.ended_by = Some(reason.to_owned());
                ended.push((record.approval.id.clone(), reason));
            }
        }
        if ended.is_empty() {
            return;
        }
        self.prune_standing();
        // An end that cannot be persisted or recorded is still in force in
        // memory, and its lease's end already refuses every use.
        let _ = self.persist();
        for (id, reason) in ended {
            let _ = self.audit_service(
                "standing",
                json!({ "decision": "ended", "standing_id": id, "reason": reason }),
            );
        }
    }

    fn prune_standing(&mut self) {
        while self.state.standing.len() > MAX_STANDING_RECORDS {
            match self
                .state
                .standing
                .iter()
                .position(|record| record.state != StandingState::Active)
            {
                Some(index) => {
                    self.state.standing.remove(index);
                }
                None => break,
            }
        }
    }

    fn standing_bound_to(caller: &CallerFacts, record: &StandingRecord) -> bool {
        record.windows_user_sid == caller.user_sid
            && record.logon_session_id == caller.logon_session_id
    }

    /// The caller's standing approvals for `List`: each with its state and
    /// whether it is in effect now (in force and an indicator alive).
    pub(super) fn standing_list(&self, caller: &CallerFacts, now: u64) -> Vec<Value> {
        let alive = self.indicator_alive(&caller.user_sid, caller.logon_session_id, now);
        self.state
            .standing
            .iter()
            .filter(|record| Self::standing_bound_to(caller, record))
            .map(|record| {
                let ended_by = self.standing_ended_by(record, now);
                let state = match (record.state, ended_by) {
                    (StandingState::Active, None) => "active",
                    _ => "ended",
                };
                json!({
                    "approval": record.approval,
                    "state": state,
                    "ended_by": record.ended_by.as_deref().or(ended_by),
                    "ended_at_ms": record.ended_at_ms,
                    "in_effect": state == "active" && alive,
                })
            })
            .collect()
    }

    /// `StandingRevoke`: ends one of the caller's standing approvals; its
    /// lease stays.
    pub(super) fn standing_revoke(
        &mut self,
        caller: &CallerFacts,
        role: CallerRole,
        standing_id: &str,
    ) -> Result<Value, AuthorityError> {
        Self::require_known(role, caller)?;
        let now = self.now();
        let index = self
            .state
            .standing
            .iter()
            .position(|record| {
                record.approval.id == standing_id && Self::standing_bound_to(caller, record)
            })
            .ok_or_else(|| {
                AuthorityError::lease_invalid(
                    "no such standing approval bound to this Windows user and logon session",
                )
            })?;
        if self
            .standing_ended_by(&self.state.standing[index], now)
            .is_some()
        {
            return Err(AuthorityError::lease_invalid(
                "the standing approval has already ended",
            ));
        }
        let record = &mut self.state.standing[index];
        record.state = StandingState::Ended;
        record.ended_at_ms = Some(now);
        record.ended_by = Some("revoked".to_owned());
        self.state.revocations = self.state.revocations.saturating_add(1);
        self.persist()?;
        self.audit(
            "standing",
            Value::Null,
            observed(caller, role),
            json!({
                "decision": "revoked",
                "standing_id": standing_id,
                "revocations": self.state.revocations,
            }),
        )?;
        Ok(json!({
            "standing_id": standing_id,
            "state": "revoked",
            "revocations": self.state.revocations,
        }))
    }

    /// `Authorize` with a standing approval: the approval is the caller's,
    /// in force, an indicator is alive, and it covers exactly this dispatch.
    /// Returns its id for the audit record.
    pub(super) fn check_standing_authorize(
        &self,
        caller: &CallerFacts,
        lease_id: &str,
        executor: ExecutorClass,
        claims: &AuthorizeClaims,
        claim: &StandingClaim,
        now: u64,
    ) -> Result<String, AuthorityError> {
        let record = self
            .state
            .standing
            .iter()
            .find(|record| {
                record.approval.id == claim.standing_id && Self::standing_bound_to(caller, record)
            })
            .ok_or_else(|| {
                AuthorityError::lease_invalid(
                    "no such standing approval bound to this Windows user and logon session",
                )
            })?;
        if let Some(reason) = self.standing_ended_by(record, now) {
            return Err(AuthorityError::lease_invalid(format!(
                "the standing approval is {reason}"
            )));
        }
        if !self.indicator_alive(&caller.user_sid, caller.logon_session_id, now) {
            return Err(indicator_unavailable());
        }
        let paths = claims.paths.clone().unwrap_or_default();
        record.approval.check_cover(&Cover {
            lease_id,
            principal_id: &claims.principal_id,
            task: &claims.task,
            executor,
            capability: &claims.capability,
            operation: &claims.operation,
            paths: &paths,
            program: claim.program.as_deref(),
            origin: claims.origin.as_deref(),
            now_ms: now,
        })?;
        Ok(record.approval.id.clone())
    }

    /// `StandingBegin` and `StandingComplete` need a live indicator of the
    /// caller's logon session.
    pub(super) fn require_indicator(&self, caller: &CallerFacts) -> Result<(), AuthorityError> {
        if self.indicator_alive(&caller.user_sid, caller.logon_session_id, self.now()) {
            Ok(())
        } else {
            Err(indicator_unavailable())
        }
    }
}

/// The confirmation's standing approval paragraph.
pub(super) fn confirmation_paragraph(scope: &StandingScope, lease_minutes: u64) -> String {
    let minutes = scope.minutes.unwrap_or(lease_minutes);
    format!(
        "STANDING APPROVAL: while it lasts, Orcel does NOT ask you before each of these actions by this client for this task:\n{}\nStanding approval expires: {minutes} minutes after approval (never after the lease)\nIt never covers Admin, remote callers, browser actions or another client, and it ends with Stop, locking the PC, sign-out, revoke or the lease's end.",
        scope.describe()
    )
}
