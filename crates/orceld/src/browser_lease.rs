//! SG-000135 OB-08: Full Access browser leases in orceld, issued by the
//! SG-000132 authority service only (SG-000132 slice 2).
//!
//! Two halves:
//!
//! - The owner's local management path (`browser.lease.list`, `.revoke`,
//!   and `.issue`, which is refused): local only, never under a tool surface
//!   profile, never for a remote caller (`full_control::reject_untrusted_grant`).
//!   orceld issues nothing: a lease comes from `orcel browser grant`, which
//!   runs the service's grant flow (recorded intent, service-observed unlock,
//!   service-rendered confirmation, Windows Hello). List and revoke go to the
//!   service. There is no MCP tool for any of them; agents read their
//!   session's lease status through `browser_task_status` only.
//! - [`FullAccess`]: the per-session lease cache the live browser consults
//!   before it would prompt. A lease reaches it only through a
//!   [`LeaseSource`]: in orceld, the authority service, whose ECDSA signature
//!   on every lease is checked with the public key the verified service
//!   reported (`authority_link::ServiceLeaseSource`); no key orceld or the
//!   user can read signs one. A valid cached lease covering the session, the
//!   committed origin and the action's family, for an action positively
//!   classified routine, dispatches without the SOFT prompt; anything else
//!   asks as before. Right before dispatch the lease is checked once more
//!   against one fresh read of the service, the verified approval epoch, the
//!   clock and the takeover gate, and the service's audit-first `Authorize`
//!   admits that one action. A revoke, an epoch move (authority or approval),
//!   expiry, a session end or a human interruption ends the lease's use at
//!   once: that action is refused `lease_invalid` with nothing sent, and later
//!   actions ask as before.
//!
//! The lease grants nothing the action would not get with a SOFT approval:
//! policy, the profile gate, the takeover gate, the secret-field refusal
//! and the host's binding (GET-only covered clicks, non-GET requests blocked
//! while covered actions run) all still apply, and the receipt names the
//! lease. OB-07's human verification wait refuses
//! (HUMAN_VERIFICATION_REQUIRED) before any lease is consulted or used.
//! Nothing is covered without the takeover gate (on for every browser_full
//! session since OB-07), only implemented
//! families can be leased, and a value that looks secret or holds a stored
//! secret is never typed under a lease.
//!
//! SG-000135 OB-09: a remote `browser_full` caller's session
//! (`FullAccess::for_remote_caller`) is never covered by a Full Access lease.
//! FOUNDER DECISION 2026-11-23: no remote lease coverage, and spec 4.15
//! stands unamended for remote callers (a standing approval never covers
//! one). So every consequential remote action asks on the owner's Windows
//! dialog: the decision always asks and the check right before dispatch
//! always refuses, both before the service is read, and there is no setting,
//! file, caller or constant that changes it. The rule is structural as well:
//! a remote session's client reference (`cl-remote-...`) is one that no lease
//! scope, at the CLI, the service or orceld's admission, accepts
//! (`orcel_policy::browser_lease::client_ref`).

use orcel_contracts::browser_impact::Impact;
use orcel_contracts::{FailureCode, RequestEnvelope};
use orcel_policy::browser_lease::{
    canonical_origin, check_browser_lease, BrowserFamily, BrowserLease, BrowserLeaseContext,
};
use orcel_policy::full_control::{reject_untrusted_grant, UntrustedGrantOrigin};
use orcel_provider_fs::ProviderError;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

/// The capability prefix of the owner's lease management shapes.
pub(crate) const MANAGEMENT_PREFIX: &str = "browser.lease.";

/// Why a remote session's action is never dispatched under a lease
/// (FOUNDER DECISION 2026-11-23).
const NO_REMOTE_COVERAGE: &str = "a Full Access lease never covers a remote caller";

/// The message prefix of every lease invalidation refusal.
pub(crate) const LEASE_INVALID: &str = "lease_invalid";

/// Whether `capability` is one of the owner's browser lease management
/// shapes.
pub(crate) fn is_management(capability: &str) -> bool {
    capability.starts_with(MANAGEMENT_PREFIX)
}

fn invalid(message: impl Into<String>) -> ProviderError {
    ProviderError::new(FailureCode::InvalidRequest, message)
}

/// Refuse a management request from anything but the owner's local path:
/// a remote caller, or a request that names a tool surface profile (an MCP
/// edge always does). Reuses the authority self-grant refusal.
pub(crate) fn refuse_untrusted(remote: bool, profile: Option<&str>) -> Result<(), ProviderError> {
    let origin = if remote {
        Some(UntrustedGrantOrigin::RemotePrincipal)
    } else if profile.is_some() {
        Some(UntrustedGrantOrigin::McpCaller)
    } else {
        None
    };
    match origin {
        Some(origin) => reject_untrusted_grant(origin).map_err(|error| {
            ProviderError::new(
                error.code,
                format!(
                    "{}; Full Access browser leases are managed only by the owner, locally",
                    error.message
                ),
            )
        }),
        None => Ok(()),
    }
}

/// What the authority service says now, for one check: its epoch and
/// revocation counter, and the browser leases of this Windows user and
/// logon session it reported active, each admitted after its signature
/// verified with the service's public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthorityView {
    pub epoch: u64,
    pub revocations: u64,
    pub leases: Vec<BrowserLease>,
}

/// One covered action as the service's `Authorize` records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CoveredAction {
    pub lease_id: String,
    pub principal_id: String,
    pub task: String,
    pub record_id: String,
    pub family: BrowserFamily,
    pub origin: String,
    pub page_id: String,
}

/// Where a session's lease comes from: the authority service in orceld, a
/// scripted one in tests.
pub(crate) trait LeaseSource {
    /// One read of the service. `Ok(None)`: no service lease can apply here
    /// (the service is not installed, or this orceld is not its trusted
    /// image). An error fails closed.
    fn read(&self) -> Result<Option<AuthorityView>, ProviderError>;
    /// The service's audit-first `Authorize` of one covered action.
    fn authorize(&self, action: &CoveredAction) -> Result<(), ProviderError>;
    /// The session ended: revoke its leases at the service (authority
    /// reducing, best effort).
    fn end_session(&self, session_id: &str);
}

/// The owner's management path: list and revoke through the service.
pub(crate) trait LeaseManager {
    fn list(&self) -> Result<Vec<BrowserLease>, ProviderError>;
    /// Revokes `lease_id`, or every browser lease when `None`; returns how
    /// many were revoked.
    fn revoke(&self, lease_id: Option<&str>) -> Result<usize, ProviderError>;
}

fn exact_fields(
    request: &RequestEnvelope,
    fields: &[&str],
) -> Result<Map<String, Value>, ProviderError> {
    if request.target.is_some() {
        return Err(invalid("browser lease management takes no target"));
    }
    let empty = Map::new();
    let arguments = match &request.arguments {
        Value::Object(map) => map,
        Value::Null => &empty,
        _ => return Err(invalid("browser lease arguments must be an object")),
    };
    if arguments.len() != fields.len() || !fields.iter().all(|field| arguments.contains_key(*field))
    {
        return Err(invalid(format!(
            "{} accepts exactly these argument fields: {}",
            request.capability,
            fields.join(", ")
        )));
    }
    Ok(arguments.clone())
}

fn family_names(families: &[BrowserFamily]) -> Vec<&'static str> {
    families.iter().map(|family| family.as_str()).collect()
}

/// A lease as the owner's list and an agent's status show it: no Windows
/// user or logon session.
pub(crate) fn lease_summary(lease: &BrowserLease, now_ms: u64) -> Value {
    json!({
        "lease_id": lease.lease_id,
        "session_id": lease.session_id,
        "client_ref": lease.client_ref,
        "origins": lease.origins,
        "families": family_names(&lease.families),
        "issued_at_ms": lease.issued_at_ms,
        "expires_at_ms": lease.expires_at_ms,
        "active": now_ms >= lease.issued_at_ms && now_ms < lease.expires_at_ms,
        "routine_only": true,
        "task": lease.task,
        "issued_by": "orcel_authority_service",
    })
}

/// The owner's local lease management. The caller has already refused
/// remote and profiled requests (`refuse_untrusted`) and checked the
/// workspace.
pub(crate) fn dispatch_management(
    manager: &dyn LeaseManager,
    request: &RequestEnvelope,
    now_ms: u64,
) -> Result<Value, ProviderError> {
    match (request.capability.as_str(), request.operation.as_str()) {
        ("browser.lease.issue", "issue") => Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "orceld issues no browser lease: Full Access leases come from the Orcel authority service only (run `orcel browser grant` in your own terminal)",
        )),
        ("browser.lease.list", "list") => {
            exact_fields(request, &[])?;
            let leases = manager.list()?;
            Ok(json!({
                "leases": leases.iter().map(|lease| lease_summary(lease, now_ms)).collect::<Vec<_>>(),
            }))
        }
        ("browser.lease.revoke", "revoke") => {
            let arguments = exact_fields(request, &["lease_id"])?;
            let lease_id = match arguments.get("lease_id") {
                Some(Value::Null) => None,
                Some(Value::String(id)) => Some(id.clone()),
                _ => return Err(invalid("lease_id must be a string or null")),
            };
            let revoked = manager.revoke(lease_id.as_deref())?;
            Ok(json!({ "revoked": revoked }))
        }
        _ => Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "unknown browser lease operation",
        )),
    }
}

// ---------------------------------------------------------------------
// The per-session lease cache.
// ---------------------------------------------------------------------

/// OB-08 review: whether a value matches a secret the secret store holds.
pub(crate) trait SecretMatcher {
    /// `Ok(true)` when `value` holds a stored secret; `Err` when the store
    /// could not be checked (the fill then asks: the person sees it).
    fn matches(&self, value: &str) -> Result<bool, ()>;
}

/// The XP-19 secret store of this account: every fixed secret name, read
/// inside orceld only for this comparison and wiped after it.
pub(crate) struct StoredSecrets;

impl SecretMatcher for StoredSecrets {
    fn matches(&self, value: &str) -> Result<bool, ()> {
        let store = crate::secret_store::SecretStore::open_default().map_err(|_| ())?;
        let value = value.trim().as_bytes();
        for name in crate::secret_store::SecretName::ALL {
            match store.get(name) {
                Ok(secret) => {
                    let secret = secret.as_slice();
                    let contained = secret.len() >= 8
                        && value.windows(secret.len()).any(|window| window == secret);
                    if value == secret || contained {
                        return Ok(true);
                    }
                }
                Err(crate::secret_store::SecretError::NotFound) => {}
                Err(_) => return Err(()),
            }
        }
        Ok(false)
    }
}

/// OB-08 review: what a value an agent would type under a lease is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FillValue {
    /// Neither secret-looking nor a stored secret.
    Ordinary,
    /// Looks secret or is a stored secret: never typed under a lease.
    Secret,
    /// The secret store could not be checked: not covered, so it asks.
    Unverified,
}

/// What the live browser knows about one action at the point it would
/// prompt for it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct LeaseQuery<'a> {
    /// The action's family, and a second one it also needs (a new tab to a
    /// URL needs `tabs` and `navigate`).
    pub family: BrowserFamily,
    pub also: Option<BrowserFamily>,
    /// The origin the action's effect lands on.
    pub effect_origin: &'a str,
    /// The page's committed origin now, if it has a document. An effect on
    /// any other origin is cross-origin and never routine.
    pub committed_origin: Option<&'a str>,
    /// The target's routine classification.
    pub impact: Impact,
    /// The page the action is on (its takeover-gate intervention epoch).
    pub page_id: &'a str,
}

/// What is true right now, read by the live browser for one decision.
#[derive(Debug, Clone)]
pub(crate) struct LeaseMoment {
    /// The approval ledger's revoke epoch, verified now (`None`: not
    /// verifiable, which fails closed). An emergency revoke moves it.
    pub approval_epoch: Option<u64>,
    pub now_ms: u64,
    /// The takeover gate's intervention epoch of every page it tracks;
    /// `None` when the gate is off. Without a gate no person's input can be
    /// seen, so nothing is covered.
    pub interventions: Option<BTreeMap<String, u64>>,
}

/// A lease covering one action: what is checked again right before it is
/// dispatched, and what its receipt names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LeaseUse {
    pub lease_id: String,
    /// SG-000135 OB-05: the authority service's epoch the lease was checked
    /// at (the receipt names it with the lease).
    pub authority_epoch: u64,
    /// The one-shot record id the host frame carries (unique per session).
    pub record_id: String,
    page_id: String,
    family: BrowserFamily,
    origin: String,
}

impl LeaseUse {
    /// The page the covered action is on.
    pub(crate) fn page_id(&self) -> &str {
        &self.page_id
    }
}

#[cfg(test)]
impl LeaseUse {
    /// Tests only: a use that names no lease, standing in for an expected
    /// covered decision that did not come (it then fails every check).
    pub(crate) fn missing(decision: &str) -> Self {
        Self {
            lease_id: format!("missing: {decision}"),
            authority_epoch: 0,
            record_id: String::new(),
            page_id: String::new(),
            family: BrowserFamily::Read,
            origin: String::new(),
        }
    }
}

/// The decision for one action.
#[derive(Debug)]
pub(crate) enum LeaseDecision {
    /// A valid lease covers it: dispatch without the SOFT prompt, after
    /// [`FullAccess::confirm`].
    Covered(LeaseUse),
    /// No lease covers it: ask as before.
    Ask,
    /// The session's lease just became invalid: refuse, nothing sent.
    Refuse(ProviderError),
}

#[cfg(test)]
impl LeaseDecision {
    /// Tests only: the covered use, if the decision is one.
    pub(crate) fn covered(self) -> Option<LeaseUse> {
        match self {
            Self::Covered(used) => Some(used),
            _ => None,
        }
    }
}

/// The cached lease of one session, as last validated.
struct Cached {
    lease: BrowserLease,
    epoch: u64,
    /// The approval ledger's revoke epoch when the lease was cached: an
    /// emergency revoke since moves it and ends the lease's use.
    approval_epoch: u64,
    /// The takeover gate's intervention epoch of every page, taken when the
    /// lease was cached and when a page opens afterwards: any move since is
    /// a person's input, and ends the lease's use.
    baseline: BTreeMap<String, u64>,
}

/// SG-000135 OB-08: one broker session's Full Access lease cache.
pub(crate) struct FullAccess {
    session_id: String,
    client_ref: String,
    /// The session's own task label (the lease must name the same).
    task: Option<String>,
    source: Box<dyn LeaseSource>,
    secrets: Box<dyn SecretMatcher>,
    /// This process's Windows user and logon session; `None` (no native
    /// identity) never covers anything.
    identity: Option<(String, u64)>,
    cached: Option<Cached>,
    /// Leases that became invalid for this session: never used again, so
    /// later actions ask.
    dead: BTreeSet<String>,
    /// An invalidation that happened between actions (`invalidate`), for
    /// the next action to report.
    pending: Option<String>,
    uses: u64,
    /// The highest service revocation counter seen: a service behind it
    /// was restored from an older state.
    revocation_floor: u64,
    /// The latest time seen: a clock behind it went backwards.
    clock_floor: u64,
    /// SG-000135 OB-09: the session belongs to a remote caller, so no lease
    /// ever covers it.
    remote: bool,
    /// SG-000135 SH-2: while set, no lease covers anything and every action
    /// asks (a mode switch's reopened pages always ask the owner).
    held: bool,
}

fn lease_invalid(reason: &str) -> ProviderError {
    ProviderError::new(
        FailureCode::CapabilityDenied,
        format!(
            "{LEASE_INVALID}: {reason}; Full Access stopped for this browser session and nothing was sent; later actions ask for approval"
        ),
    )
}

impl FullAccess {
    pub(crate) fn new(
        session_id: &str,
        client_ref: &str,
        task: Option<&str>,
        source: Box<dyn LeaseSource>,
        secrets: Box<dyn SecretMatcher>,
        identity: Option<(String, u64)>,
    ) -> Self {
        Self {
            session_id: session_id.to_owned(),
            client_ref: client_ref.to_owned(),
            task: task.map(str::to_owned),
            source,
            secrets,
            identity,
            cached: None,
            dead: BTreeSet::new(),
            pending: None,
            uses: 0,
            revocation_floor: 0,
            clock_floor: 0,
            remote: false,
            held: false,
        }
    }

    /// SG-000135 SH-2: hold (or release) the lease: while held, every
    /// decision asks, even when a lease would cover the action. Nothing is
    /// cached or invalidated by the hold itself.
    pub(crate) fn hold(&mut self, held: bool) {
        self.held = held;
    }

    /// SG-000135 OB-09: this session belongs to a remote caller: no lease
    /// ever covers it. Its end still revokes at the service any lease naming
    /// the session (authority reducing).
    pub(crate) fn for_remote_caller(mut self) -> Self {
        self.remote = true;
        self
    }

    /// The authority service and the secret store, with this process's
    /// native identity.
    pub(crate) fn service_backed(
        session_id: &str,
        client_session_id: &str,
        task: Option<&str>,
    ) -> Self {
        let identity = orcel_policy::full_control::current_windows_identity()
            .ok()
            .map(|identity| (identity.windows_user_sid, identity.logon_session_id));
        Self::new(
            session_id,
            &orcel_policy::browser_lease::client_ref(client_session_id),
            task,
            Box::new(crate::authority_link::ServiceLeaseSource::for_this_build()),
            Box::new(StoredSecrets),
            identity,
        )
    }

    fn kill(&mut self, lease_id: &str) {
        self.dead.insert(lease_id.to_owned());
        self.cached = None;
    }

    /// End the cached lease's use from outside an action (a human took
    /// over the page, the session is ending). The next action reports it.
    pub(crate) fn invalidate(&mut self, reason: &str) {
        if let Some(cached) = self.cached.take() {
            self.dead.insert(cached.lease.lease_id);
            self.pending = Some(reason.to_owned());
        }
    }

    /// A page opened (a tab, a popup the session adopted): its intervention
    /// epoch joins the cached lease's baseline now, not at its first use.
    pub(crate) fn page_opened(&mut self, page_id: &str, epoch: Option<u64>) {
        if let (Some(cached), Some(epoch)) = (self.cached.as_mut(), epoch) {
            cached.baseline.entry(page_id.to_owned()).or_insert(epoch);
        }
    }

    /// Check `lease` against the service's epoch and counter and the moment,
    /// and move the clock and revocation floors.
    fn check(
        &mut self,
        lease: &BrowserLease,
        epoch: u64,
        revocations: u64,
        moment: &LeaseMoment,
    ) -> Result<(), String> {
        if moment.now_ms < self.clock_floor {
            return Err("the clock went backwards".into());
        }
        if revocations < self.revocation_floor {
            return Err("the authority service went back behind a revoke it had shown".into());
        }
        if moment.approval_epoch.is_none() {
            return Err("the approval epoch could not be verified".into());
        }
        let Some((sid, logon)) = &self.identity else {
            return Err("this process's Windows session could not be read".into());
        };
        check_browser_lease(
            lease,
            &BrowserLeaseContext {
                windows_user_sid: sid,
                logon_session_id: *logon,
                authority_epoch: epoch,
                revocations,
                session_id: &self.session_id,
                client_ref: &self.client_ref,
                task: self.task.as_deref(),
                now_ms: moment.now_ms,
            },
        )
        .map_err(|error| error.message)?;
        self.clock_floor = self.clock_floor.max(moment.now_ms);
        self.revocation_floor = self.revocation_floor.max(revocations);
        Ok(())
    }

    /// Whether the takeover gate saw a person on any page since the lease
    /// was cached (or the page opened). Pages opened since join the
    /// baseline here at the latest.
    fn interrupted(cached: &mut Cached, interventions: &BTreeMap<String, u64>) -> bool {
        let mut moved = false;
        for (page, epoch) in interventions {
            match cached.baseline.get(page) {
                Some(mark) if mark != epoch => moved = true,
                Some(_) => {}
                None => {
                    cached.baseline.insert(page.clone(), *epoch);
                }
            }
        }
        moved
    }

    /// Before the prompt: whether this session's lease covers `query` now.
    /// Uses the cached lease when there is one (the service is read again
    /// in [`Self::confirm`]); otherwise reads the service once.
    pub(crate) fn decide(&mut self, query: &LeaseQuery<'_>, moment: &LeaseMoment) -> LeaseDecision {
        // SG-000135 OB-09: no lease covers a remote caller's session;
        // nothing is read or cached for one.
        if self.remote {
            return LeaseDecision::Ask;
        }
        if let Some(reason) = self.pending.take() {
            return LeaseDecision::Refuse(lease_invalid(&reason));
        }
        if self.held {
            return LeaseDecision::Ask;
        }
        // Without the takeover gate no person's input can be seen: nothing
        // is covered, and a page the gate does not track asks too. Since
        // OB-07 every browser_full session runs with the gate on, so this
        // is a defense that should never fire there; browser_structured has
        // no lease at all. HUMAN_VERIFICATION_REQUIRED is decided by the
        // gate before this is consulted and again before a lease is used.
        let Some(interventions) = moment.interventions.as_ref() else {
            return LeaseDecision::Ask;
        };
        if !interventions.contains_key(query.page_id) {
            return LeaseDecision::Ask;
        }
        if self.cached.is_none() {
            let view = match self.source.read() {
                Ok(Some(view)) => view,
                // No service lease can apply, or the service could not be
                // read: no lease is in force, so the action asks (nothing was
                // cached, nothing is lost).
                Ok(None) | Err(_) => return LeaseDecision::Ask,
            };
            let Some(lease) = view
                .leases
                .iter()
                .find(|lease| {
                    lease.session_id == self.session_id && !self.dead.contains(&lease.lease_id)
                })
                .cloned()
            else {
                return LeaseDecision::Ask;
            };
            if let Err(reason) = self.check(&lease, view.epoch, view.revocations, moment) {
                // A lease for this session that does not hold now is never
                // used; it is reported once.
                self.kill(&lease.lease_id);
                return LeaseDecision::Refuse(lease_invalid(&reason));
            }
            self.cached = Some(Cached {
                lease,
                epoch: view.epoch,
                approval_epoch: moment.approval_epoch.unwrap_or(u64::MAX),
                // Every tracked page's epoch, now: the lease is cached.
                baseline: interventions.clone(),
            });
        }
        let Some(cached) = self.cached.as_ref() else {
            return LeaseDecision::Ask;
        };
        let lease = cached.lease.clone();
        let (epoch, approval_epoch) = (cached.epoch, cached.approval_epoch);
        if moment.approval_epoch != Some(approval_epoch) {
            self.kill(&lease.lease_id);
            return LeaseDecision::Refuse(lease_invalid(
                "an emergency revoke moved the approval epoch",
            ));
        }
        let floor = self.revocation_floor;
        if let Err(reason) = self.check(&lease, epoch, floor, moment) {
            self.kill(&lease.lease_id);
            return LeaseDecision::Refuse(lease_invalid(&reason));
        }
        let interrupted = match self.cached.as_mut() {
            Some(cached) => Self::interrupted(cached, interventions),
            None => true,
        };
        if interrupted {
            self.kill(&lease.lease_id);
            return LeaseDecision::Refuse(lease_invalid(
                "a person interrupted this browser session",
            ));
        }
        let Some(origin) = covers(&lease, query) else {
            return LeaseDecision::Ask;
        };
        self.uses += 1;
        LeaseDecision::Covered(LeaseUse {
            record_id: format!(
                "lease-{}-{}",
                self.uses,
                lease.lease_id.get(3..19).unwrap_or("")
            ),
            lease_id: lease.lease_id,
            authority_epoch: epoch,
            page_id: query.page_id.to_owned(),
            family: query.family,
            origin,
        })
    }

    /// Right before dispatch: one fresh read of the service, the verified
    /// approval epoch, the clock and the takeover gate, then the service's
    /// audit-first `Authorize` of this one action. The lease must be the
    /// cached one, unchanged and still valid. Anything else ends it and
    /// refuses the action (nothing sent).
    pub(crate) fn confirm(
        &mut self,
        used: &LeaseUse,
        moment: &LeaseMoment,
    ) -> Result<(), ProviderError> {
        let refuse = |this: &mut Self, reason: &str| {
            this.kill(&used.lease_id);
            Err(lease_invalid(reason))
        };
        // SG-000135 OB-09: the same rule as in `decide`, checked again.
        if self.remote {
            return refuse(self, NO_REMOTE_COVERAGE);
        }
        let read = self.source.read();
        let Some(interventions) = moment.interventions.as_ref() else {
            return refuse(self, "the takeover gate is not available");
        };
        let Some(cached) = self.cached.as_ref() else {
            return refuse(self, "the browser lease is no longer cached");
        };
        if cached.lease.lease_id != used.lease_id {
            return refuse(self, "the browser lease changed");
        }
        if moment.approval_epoch != Some(cached.approval_epoch) {
            return refuse(self, "an emergency revoke moved the approval epoch");
        }
        let view = match read {
            Ok(Some(view)) => view,
            Ok(None) => return refuse(self, "the authority service no longer applies"),
            Err(_) => return refuse(self, "the authority service could not be read"),
        };
        let Some(current) = view
            .leases
            .iter()
            .find(|lease| lease.lease_id == used.lease_id)
            .cloned()
        else {
            return refuse(self, "the browser lease was revoked");
        };
        if current != cached.lease || view.epoch != cached.epoch {
            return refuse(self, "the browser lease or the authority epoch changed");
        }
        if let Err(reason) = self.check(&current, view.epoch, view.revocations, moment) {
            return refuse(self, &reason);
        }
        let interrupted = match self.cached.as_mut() {
            Some(cached) => Self::interrupted(cached, interventions),
            None => true,
        };
        if interrupted {
            return refuse(self, "a person interrupted this browser session");
        }
        let action = CoveredAction {
            lease_id: current.lease_id.clone(),
            principal_id: current.principal_id.clone(),
            task: current
                .task
                .clone()
                .unwrap_or_else(|| "browser Full Access".to_owned()),
            record_id: used.record_id.clone(),
            family: used.family,
            origin: used.origin.clone(),
            page_id: used.page_id.clone(),
        };
        if let Err(error) = self.source.authorize(&action) {
            return refuse(
                self,
                &format!(
                    "the authority service refused Authorize ({})",
                    error.message
                ),
            );
        }
        Ok(())
    }

    /// OB-08 review: whether `value` may be typed under the lease: never a
    /// value that looks secret or holds a stored secret; a secret store
    /// that cannot be checked leaves it to the person (it asks).
    pub(crate) fn fill_value(&self, value: &str) -> FillValue {
        if orcel_contracts::browser_impact::value_looks_secret(value) {
            return FillValue::Secret;
        }
        match self.secrets.matches(value) {
            Ok(true) => FillValue::Secret,
            Ok(false) => FillValue::Ordinary,
            Err(()) => FillValue::Unverified,
        }
    }

    /// `browser_task_status`'s read-only view of this session's lease: its
    /// scope and expiry, never anything an agent could use to issue or
    /// widen one. A remote session has none (OB-09).
    pub(crate) fn status(&self, now_ms: u64) -> Value {
        if self.remote {
            return json!({ "active": false, "client_ref": self.client_ref });
        }
        let view = match self.source.read() {
            Ok(Some(view)) => view,
            _ => return json!({ "active": false, "client_ref": self.client_ref }),
        };
        match view.leases.iter().find(|lease| {
            lease.session_id == self.session_id && lease.client_ref == self.client_ref
        }) {
            Some(lease) => {
                let mut summary = lease_summary(lease, now_ms);
                if let Value::Object(map) = &mut summary {
                    let usable = !self.dead.contains(&lease.lease_id)
                        && map.get("active") == Some(&Value::Bool(true));
                    map.insert("active".into(), Value::Bool(usable));
                }
                summary
            }
            None => json!({ "active": false, "client_ref": self.client_ref }),
        }
    }

    /// The session ended: the cache goes, and the service revokes its lease.
    pub(crate) fn session_ended(&mut self) {
        self.cached = None;
        self.source.end_session(&self.session_id);
    }
}

/// The canonical effect origin when `lease` covers `query`: the action's
/// family (and the second one it needs), its effect's origin, no
/// cross-origin effect, and a target positively classified routine.
fn covers(lease: &BrowserLease, query: &LeaseQuery<'_>) -> Option<String> {
    if query.impact != Impact::Routine {
        return None;
    }
    let effect = canonical_origin(query.effect_origin)?;
    if let Some(committed) = query.committed_origin {
        if canonical_origin(committed).as_deref() != Some(effect.as_str()) {
            return None;
        }
    }
    let covered = lease.covers(&effect, query.family)
        && query.also.is_none_or(|also| lease.covers(&effect, also));
    covered.then_some(effect)
}
