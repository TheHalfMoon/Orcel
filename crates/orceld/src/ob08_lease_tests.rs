//! SG-000135 OB-08 tests: Full Access browser leases in orceld. The lease
//! cache's scope matching and every invalidation, the owner's management
//! path (STRONG issuance, list, revoke) and its refusal for agent, MCP and
//! remote callers. No SOFT prompt is ever shown: the management tests use
//! the real approval broker with a test presence verifier (STRONG only) and
//! the cache tests a scripted lease source.

use crate::browser_lease::{
    dispatch_management, refuse_untrusted, FullAccess, LeaseDecision, LeaseMoment, LeaseQuery,
    LeaseSource, ManagementEnv, StoreView, LEASE_INVALID, LEASE_ISSUE_ACTION,
};
use orcel_approval::test_support::{
    broker_with_presence, FixedApprovalBroker, TestPresenceVerifier,
};
use orcel_approval::{
    ApprovalBroker, ApprovalDecision, ApprovalError, ApprovalPrompt, ApprovedToken,
    ConsumeExpectation, LocalApprovalBroker,
};
use orcel_contracts::browser_impact::Impact;
use orcel_contracts::{FailureCode, RequestEnvelope, INTERNAL_PROTOCOL_VERSION};
use orcel_policy::browser_lease::{client_ref, BrowserFamily, BrowserLease, BrowserLeaseRequest};
use orcel_policy::full_control_store;
use orcel_policy::POLICY_REVISION;
use orcel_provider_fs::ProviderError;
use serde_json::{json, Value};
use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::Rc;

const SESSION: &str = "bs-0123456789abcdef-1-0001020304050607";
const OTHER_SESSION: &str = "bs-0123456789abcdef-2-0001020304050607";
const CLIENT: &str = "mcp-client-a";
const SID: &str = "S-1-5-21-1-2-3-1001";
const LOGON: u64 = 42;
const DEVICE: &str = "device-local-ob08";
const ORIGIN: &str = "https://fixture.test";
const PAGE: &str = "pg-0123456789abcdef0123456789abcdef";
const NOW: u64 = 1_800_000_000_000;
const KEY: [u8; 32] = [0xA5; 32];

// ---------------------------------------------------------------------
// The lease cache.
// ---------------------------------------------------------------------

/// A scripted store: what the next read returns, how many reads there
/// were, and which sessions ended.
#[derive(Default)]
struct Scripted {
    view: RefCell<Option<Result<Option<StoreView>, ()>>>,
    reads: Cell<usize>,
    ended: RefCell<Vec<String>>,
}

#[derive(Clone)]
struct Source(Rc<Scripted>);

impl LeaseSource for Source {
    fn read(&self) -> Result<Option<StoreView>, ProviderError> {
        self.0.reads.set(self.0.reads.get() + 1);
        match self.0.view.borrow().clone() {
            Some(Ok(view)) => Ok(view),
            Some(Err(())) | None => Err(ProviderError::new(
                FailureCode::ProviderUnavailable,
                "scripted store unreadable",
            )),
        }
    }

    fn end_session(&self, session_id: &str) {
        self.0.ended.borrow_mut().push(session_id.to_owned());
    }
}

fn proof_lease(
    families: &[BrowserFamily],
    change: impl FnOnce(&mut BrowserLeaseRequest),
) -> BrowserLease {
    let mut request = BrowserLeaseRequest {
        client_ref: client_ref(CLIENT),
        session_id: SESSION.into(),
        windows_user_sid: SID.into(),
        logon_session_id: LOGON,
        device_id: DEVICE.into(),
        policy_revision: POLICY_REVISION.into(),
        authority_epoch: 5,
        approval_epoch: 2,
        origins: vec![ORIGIN.into()],
        families: families.to_vec(),
        issued_at_ms: NOW,
        duration_ms: 60 * 60 * 1_000,
    };
    change(&mut request);
    // The store's proof is crate-private to orcel-policy: issue through the
    // store itself into a scratch file, then read it back.
    let dir = scratch("proof");
    let path = dir.join("state.json");
    let status = full_control_store::AuthorityStatus {
        authority_epoch: request.authority_epoch,
        lease: None,
        browser_leases: Vec::new(),
    };
    full_control_store::save_store(&path, &KEY, &status).expect("seed store");
    let lease = full_control_store::grant_browser_lease_at_epoch(
        &path,
        &KEY,
        request.authority_epoch,
        full_control_store::BrowserLeaseGrant {
            client_ref: request.client_ref.clone(),
            session_id: request.session_id.clone(),
            windows_user_sid: request.windows_user_sid.clone(),
            logon_session_id: request.logon_session_id,
            approval_epoch: request.approval_epoch,
            origins: request.origins.clone(),
            families: request.families.clone(),
            duration_ms: request.duration_ms,
        },
        request.issued_at_ms,
    )
    .expect("lease");
    let _ = std::fs::remove_dir_all(dir);
    // Fields the store derives itself are overridden to the request's, so
    // a test can model drift (the shape stays valid).
    BrowserLease {
        device_id: request.device_id,
        policy_revision: request.policy_revision,
        ..lease
    }
}

fn view_of(leases: Vec<BrowserLease>) -> StoreView {
    StoreView {
        authority_epoch: 5,
        device_id: DEVICE.into(),
        leases,
    }
}

fn routine_families() -> Vec<BrowserFamily> {
    vec![
        BrowserFamily::Navigate,
        BrowserFamily::Click,
        BrowserFamily::Type,
        BrowserFamily::Select,
        BrowserFamily::Read,
        BrowserFamily::Tabs,
    ]
}

struct Scene {
    store: Rc<Scripted>,
    access: FullAccess,
    lease: BrowserLease,
}

impl Scene {
    fn new() -> Self {
        Self::with(proof_lease(&routine_families(), |_| {}))
    }

    fn with(lease: BrowserLease) -> Self {
        let store = Rc::new(Scripted::default());
        *store.view.borrow_mut() = Some(Ok(Some(view_of(vec![lease.clone()]))));
        let access = FullAccess::new(
            SESSION,
            &client_ref(CLIENT),
            Box::new(Source(Rc::clone(&store))),
            Some((SID.into(), LOGON)),
        );
        Self {
            store,
            access,
            lease,
        }
    }

    fn set_view(&self, view: Result<Option<StoreView>, ()>) {
        *self.store.view.borrow_mut() = Some(view);
    }
}

fn moment() -> LeaseMoment {
    LeaseMoment {
        approval_epoch: Some(2),
        now_ms: NOW + 1_000,
        intervention: None,
    }
}

fn query(family: BrowserFamily, impact: Impact) -> LeaseQuery<'static> {
    LeaseQuery {
        family,
        also: None,
        effect_origin: "https://fixture.test:443",
        committed_origin: Some("https://fixture.test:443"),
        impact,
        page_id: PAGE,
    }
}

fn covered(decision: LeaseDecision) -> crate::browser_lease::LeaseUse {
    let shown = format!("{decision:?}");
    assert!(
        matches!(decision, LeaseDecision::Covered(_)),
        "expected covered: {shown}"
    );
    decision
        .covered()
        .unwrap_or_else(|| crate::browser_lease::LeaseUse::missing(&shown))
}

fn is_ask(decision: &LeaseDecision) -> bool {
    matches!(decision, LeaseDecision::Ask)
}

fn is_lease_invalid(decision: &LeaseDecision) -> bool {
    matches!(decision, LeaseDecision::Refuse(error)
        if error.code == FailureCode::CapabilityDenied && error.message.starts_with(LEASE_INVALID))
}

/// FA-E: routine actions of every leased family on the leased origin are
/// covered, each with its own one-shot record id, and each is confirmed
/// against exactly one fresh store read.
#[test]
fn ob08_routine_actions_in_scope_are_covered_and_confirmed_with_one_read() {
    let mut scene = Scene::new();
    let mut records = std::collections::BTreeSet::new();
    for family in [
        BrowserFamily::Navigate,
        BrowserFamily::Click,
        BrowserFamily::Type,
        BrowserFamily::Select,
    ] {
        for _ in 0..7 {
            let used = covered(
                scene
                    .access
                    .decide(&query(family, Impact::Routine), &moment()),
            );
            assert_eq!(used.lease_id, scene.lease.lease_id);
            let before = scene.store.reads.get();
            scene.access.confirm(&used, &moment()).expect("confirmed");
            assert_eq!(
                scene.store.reads.get(),
                before + 1,
                "one read right before dispatch"
            );
            assert!(
                records.insert(used.record_id.clone()),
                "record ids are one-shot"
            );
            // A host record id: bounded, no control, path or traversal.
            assert!(
                used.record_id.len() <= 64
                    && !used.record_id.contains(['/', '\\'])
                    && !used.record_id.contains("..")
                    && !used.record_id.chars().any(char::is_control),
                "{}",
                used.record_id
            );
        }
    }
    // The first decision read the store once; the rest used the cache.
    assert_eq!(scene.store.reads.get(), 28 + 1);
    // A new tab to a URL needs both families.
    let mut tab = query(BrowserFamily::Navigate, Impact::Routine);
    tab.also = Some(BrowserFamily::Tabs);
    covered(scene.access.decide(&tab, &moment()));
}

/// FX-4: a high-impact or unclassified target, another origin, a
/// cross-origin effect, a family the lease does not name and download
/// (opt-in) all ask; nothing is widened.
#[test]
fn ob08_anything_not_positively_routine_or_out_of_scope_asks() {
    let mut scene = Scene::new();
    for impact in [Impact::HighImpact, Impact::Unknown] {
        assert!(is_ask(
            &scene
                .access
                .decide(&query(BrowserFamily::Click, impact), &moment())
        ));
        assert!(is_ask(
            &scene
                .access
                .decide(&query(BrowserFamily::Type, impact), &moment())
        ));
    }
    for family in [BrowserFamily::Download, BrowserFamily::Scroll] {
        assert!(
            is_ask(
                &scene
                    .access
                    .decide(&query(family, Impact::Routine), &moment())
            ),
            "{family:?}"
        );
    }
    let mut other_site = query(BrowserFamily::Navigate, Impact::Routine);
    other_site.effect_origin = "https://other.test";
    other_site.committed_origin = None;
    assert!(is_ask(&scene.access.decide(&other_site, &moment())));
    let mut cross = query(BrowserFamily::Navigate, Impact::Routine);
    cross.committed_origin = Some("https://other.test");
    assert!(
        is_ask(&scene.access.decide(&cross, &moment())),
        "a move from another origin asks"
    );
    let mut cross_click = query(BrowserFamily::Click, Impact::Routine);
    cross_click.effect_origin = "https://other.test";
    assert!(
        is_ask(&scene.access.decide(&cross_click, &moment())),
        "a link off the page's origin asks"
    );
    let mut unparsed = query(BrowserFamily::Navigate, Impact::Routine);
    unparsed.effect_origin = "";
    assert!(is_ask(&scene.access.decide(&unparsed, &moment())));
    let mut first = query(BrowserFamily::Navigate, Impact::Routine);
    first.committed_origin = None;
    covered(scene.access.decide(&first, &moment()));
    let mut tab_without_tabs = Scene::with(proof_lease(&[BrowserFamily::Navigate], |_| {}));
    let mut tab = query(BrowserFamily::Navigate, Impact::Routine);
    tab.also = Some(BrowserFamily::Tabs);
    assert!(is_ask(&tab_without_tabs.access.decide(&tab, &moment())));
}

/// No lease, another session's lease, an unreadable store, or no native
/// identity: nothing is covered.
#[test]
fn ob08_no_lease_means_every_action_asks_as_before() {
    let mut scene = Scene::new();
    scene.set_view(Ok(None));
    assert!(is_ask(&scene.access.decide(
        &query(BrowserFamily::Click, Impact::Routine),
        &moment()
    )));
    scene.set_view(Err(()));
    assert!(is_ask(&scene.access.decide(
        &query(BrowserFamily::Click, Impact::Routine),
        &moment()
    )));
    let other = proof_lease(&routine_families(), |request| {
        request.session_id = OTHER_SESSION.into();
    });
    scene.set_view(Ok(Some(view_of(vec![other]))));
    assert!(is_ask(&scene.access.decide(
        &query(BrowserFamily::Click, Impact::Routine),
        &moment()
    )));

    let lease = proof_lease(&routine_families(), |_| {});
    let store = Rc::new(Scripted::default());
    *store.view.borrow_mut() = Some(Ok(Some(view_of(vec![lease]))));
    let mut nobody = FullAccess::new(SESSION, &client_ref(CLIENT), Box::new(Source(store)), None);
    let first = nobody.decide(&query(BrowserFamily::Click, Impact::Routine), &moment());
    assert!(is_lease_invalid(&first), "{first:?}");
    assert!(is_ask(&nobody.decide(
        &query(BrowserFamily::Click, Impact::Routine),
        &moment()
    )));
}

/// FX-4: another client's session never uses the lease; a lease that does
/// not hold is reported once and then never used (later actions ask).
#[test]
fn ob08_another_client_or_any_binding_drift_is_refused_once_then_asks() {
    let lease = proof_lease(&routine_families(), |_| {});
    let store = Rc::new(Scripted::default());
    *store.view.borrow_mut() = Some(Ok(Some(view_of(vec![lease.clone()]))));
    let mut stranger = FullAccess::new(
        SESSION,
        &client_ref("mcp-client-b"),
        Box::new(Source(Rc::clone(&store))),
        Some((SID.into(), LOGON)),
    );
    assert!(is_lease_invalid(&stranger.decide(
        &query(BrowserFamily::Click, Impact::Routine),
        &moment()
    )));
    assert!(is_ask(&stranger.decide(
        &query(BrowserFamily::Click, Impact::Routine),
        &moment()
    )));

    type Drift = (
        &'static str,
        BrowserLease,
        LeaseMoment,
        Option<(String, u64)>,
    );
    let drifts: Vec<Drift> = vec![
        (
            "policy revision",
            proof_lease(&routine_families(), |r| {
                r.policy_revision = "sg-older".into()
            }),
            moment(),
            Some((SID.into(), LOGON)),
        ),
        (
            "device",
            proof_lease(&routine_families(), |r| r.device_id = "device-other".into()),
            moment(),
            Some((SID.into(), LOGON)),
        ),
        (
            "approval epoch",
            lease.clone(),
            LeaseMoment {
                approval_epoch: Some(3),
                ..moment()
            },
            Some((SID.into(), LOGON)),
        ),
        (
            "unverified approval epoch",
            lease.clone(),
            LeaseMoment {
                approval_epoch: None,
                ..moment()
            },
            Some((SID.into(), LOGON)),
        ),
        (
            "expired",
            lease.clone(),
            LeaseMoment {
                now_ms: lease.expires_at_ms,
                ..moment()
            },
            Some((SID.into(), LOGON)),
        ),
        (
            "windows user",
            lease.clone(),
            moment(),
            Some(("S-1-5-21-9".into(), LOGON)),
        ),
        (
            "logon session",
            lease.clone(),
            moment(),
            Some((SID.into(), LOGON + 1)),
        ),
    ];
    for (name, lease, at, identity) in drifts {
        let store = Rc::new(Scripted::default());
        *store.view.borrow_mut() = Some(Ok(Some(view_of(vec![lease]))));
        let mut access = FullAccess::new(
            SESSION,
            &client_ref(CLIENT),
            Box::new(Source(store)),
            identity,
        );
        let first = access.decide(&query(BrowserFamily::Navigate, Impact::Routine), &at);
        assert!(is_lease_invalid(&first), "{name}: {first:?}");
        assert!(
            is_ask(&access.decide(&query(BrowserFamily::Navigate, Impact::Routine), &at)),
            "{name}"
        );
    }
}

/// FX-4: a revoke stops the very next action, even with the lease cached:
/// the check right before dispatch reads the store once more and refuses
/// (nothing sent); later actions ask.
#[test]
fn ob08_revoke_between_decision_and_dispatch_refuses_at_once() {
    let mut scene = Scene::new();
    let used = covered(
        scene
            .access
            .decide(&query(BrowserFamily::Click, Impact::Routine), &moment()),
    );
    scene.access.confirm(&used, &moment()).expect("still valid");
    let used = covered(
        scene
            .access
            .decide(&query(BrowserFamily::Click, Impact::Routine), &moment()),
    );
    scene.set_view(Ok(Some(view_of(Vec::new()))));
    let refused = scene.access.confirm(&used, &moment()).expect_err("revoked");
    assert!(
        refused.message.starts_with(LEASE_INVALID),
        "{}",
        refused.message
    );
    assert!(refused.message.contains("revoked"));
    // Re-adding the same lease does not bring it back for this session.
    scene.set_view(Ok(Some(view_of(vec![scene.lease.clone()]))));
    assert!(is_ask(&scene.access.decide(
        &query(BrowserFamily::Click, Impact::Routine),
        &moment()
    )));
}

/// An authority epoch move (emergency stop, desktop grant), an approval
/// epoch move, a changed record, an unreadable store or expiry, found
/// right before dispatch, refuse that action.
#[test]
fn ob08_every_change_found_right_before_dispatch_refuses() {
    type Case = (&'static str, Box<dyn Fn(&Scene)>, LeaseMoment);
    let cases: Vec<Case> = vec![
        (
            "authority epoch",
            Box::new(|scene: &Scene| {
                let mut view = view_of(vec![scene.lease.clone()]);
                view.authority_epoch = 6;
                scene.set_view(Ok(Some(view)));
            }),
            moment(),
        ),
        (
            "store unreadable",
            Box::new(|scene: &Scene| scene.set_view(Err(()))),
            moment(),
        ),
        (
            "store key gone",
            Box::new(|scene: &Scene| scene.set_view(Ok(None))),
            moment(),
        ),
        (
            "record changed",
            Box::new(|scene: &Scene| {
                let mut changed = scene.lease.clone();
                changed.expires_at_ms -= 1;
                scene.set_view(Ok(Some(view_of(vec![changed]))));
            }),
            moment(),
        ),
        (
            "approval epoch",
            Box::new(|_: &Scene| {}),
            LeaseMoment {
                approval_epoch: Some(9),
                ..moment()
            },
        ),
        (
            "expired",
            Box::new(|_: &Scene| {}),
            LeaseMoment {
                now_ms: NOW + 60 * 60 * 1_000,
                ..moment()
            },
        ),
    ];
    for (name, change, at) in cases {
        let mut scene = Scene::new();
        let used = covered(
            scene
                .access
                .decide(&query(BrowserFamily::Type, Impact::Routine), &moment()),
        );
        change(&scene);
        let refused = scene.access.confirm(&used, &at).expect_err(name);
        assert!(
            refused.message.starts_with(LEASE_INVALID),
            "{name}: {}",
            refused.message
        );
        scene.set_view(Ok(Some(view_of(vec![scene.lease.clone()]))));
        assert!(
            is_ask(
                &scene
                    .access
                    .decide(&query(BrowserFamily::Type, Impact::Routine), &moment())
            ),
            "{name}"
        );
    }
}

/// FX-4 / Full Access test 2: a human interruption (the takeover gate's
/// intervention epoch moved, or the gate refused as paused) stops lease
/// use at once.
#[test]
fn ob08_human_interruption_ends_lease_use() {
    let mut scene = Scene::new();
    let at = LeaseMoment {
        intervention: Some(0),
        ..moment()
    };
    let used = covered(
        scene
            .access
            .decide(&query(BrowserFamily::Click, Impact::Routine), &at),
    );
    scene.access.confirm(&used, &at).expect("no person yet");
    let used = covered(
        scene
            .access
            .decide(&query(BrowserFamily::Click, Impact::Routine), &at),
    );
    let person = LeaseMoment {
        intervention: Some(1),
        ..moment()
    };
    assert!(
        scene.access.confirm(&used, &person).is_err(),
        "a person acted while it was pending"
    );
    assert!(is_ask(
        &scene
            .access
            .decide(&query(BrowserFamily::Click, Impact::Routine), &person)
    ));

    let mut scene = Scene::new();
    covered(
        scene
            .access
            .decide(&query(BrowserFamily::Click, Impact::Routine), &at),
    );
    assert!(is_lease_invalid(
        &scene
            .access
            .decide(&query(BrowserFamily::Click, Impact::Routine), &person)
    ));

    let mut scene = Scene::new();
    covered(
        scene
            .access
            .decide(&query(BrowserFamily::Click, Impact::Routine), &moment()),
    );
    scene
        .access
        .invalidate("a person interrupted this browser session");
    assert!(is_lease_invalid(&scene.access.decide(
        &query(BrowserFamily::Click, Impact::Routine),
        &moment()
    )));
    assert!(is_ask(&scene.access.decide(
        &query(BrowserFamily::Click, Impact::Routine),
        &moment()
    )));
}

/// Session end: the cache goes and the store forgets the session's lease.
#[test]
fn ob08_session_end_forgets_the_lease() {
    let mut scene = Scene::new();
    covered(
        scene
            .access
            .decide(&query(BrowserFamily::Click, Impact::Routine), &moment()),
    );
    scene.access.session_ended();
    assert_eq!(scene.store.ended.borrow().as_slice(), [SESSION.to_owned()]);
}

/// MCP tools may only read: the status names the scope and expiry, and
/// nothing an agent could use (no Windows user, logon session or device).
#[test]
fn ob08_status_is_read_only_scope_and_expiry() {
    let scene = Scene::new();
    let status = scene.access.status(NOW + 1);
    assert_eq!(status["lease_id"], json!(scene.lease.lease_id));
    assert_eq!(status["origins"], json!([ORIGIN]));
    assert_eq!(status["expires_at_ms"], json!(scene.lease.expires_at_ms));
    assert_eq!(status["active"], json!(true));
    let text = status.to_string();
    for secret in [SID, DEVICE] {
        assert!(!text.contains(secret), "{secret}");
    }
    scene.set_view(Ok(None));
    assert_eq!(scene.access.status(NOW + 1)["active"], json!(false));
}

// ---------------------------------------------------------------------
// The owner's management path.
// ---------------------------------------------------------------------

fn scratch(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!(
        "orcel-ob08-{label}-{}-{nanos}-{}",
        std::process::id(),
        crate::tests::next_temp_sequence()
    ));
    std::fs::create_dir_all(&dir).expect("scratch");
    dir
}

fn env(dir: &std::path::Path) -> ManagementEnv {
    ManagementEnv {
        store_path: dir.join("full_control.json"),
        key: Ok(KEY),
        identity: Ok((SID.into(), LOGON)),
        now_ms: orcel_approval::now_ms,
    }
}

fn management(capability: &str, operation: &str, arguments: Value) -> RequestEnvelope {
    RequestEnvelope {
        version: INTERNAL_PROTOCOL_VERSION,
        request_id: "ob08".into(),
        client_session_id: "owner".into(),
        workspace_id: "default".into(),
        capability: capability.into(),
        operation: operation.into(),
        target: None,
        arguments,
    }
}

fn issue_arguments() -> Value {
    json!({
        "session_id": SESSION,
        "client_ref": client_ref(CLIENT),
        "origins": ["HTTPS://Fixture.test/"],
        "families": ["navigate", "click", "type", "select", "read", "tabs"],
        "minutes": 30,
    })
}

/// A broker that records the STRONG prompts it was asked and delegates.
struct Recording<'a> {
    inner: &'a LocalApprovalBroker,
    prompts: RefCell<Vec<ApprovalPrompt>>,
    on_prompt: Box<dyn Fn()>,
    epoch_after: Cell<Option<u64>>,
}

impl<'a> Recording<'a> {
    fn new(inner: &'a LocalApprovalBroker) -> Self {
        Self {
            inner,
            prompts: RefCell::new(Vec::new()),
            on_prompt: Box::new(|| {}),
            epoch_after: Cell::new(None),
        }
    }
}

impl ApprovalBroker for Recording<'_> {
    fn request_token(&self, prompt: &ApprovalPrompt) -> Result<ApprovedToken, ApprovalError> {
        self.prompts.borrow_mut().push(prompt.clone());
        let token = self.inner.request_token(prompt);
        (self.on_prompt)();
        token
    }

    fn consume(
        &self,
        token: &ApprovedToken,
        expected: &ConsumeExpectation,
        now_ms: u64,
    ) -> Result<(), ApprovalError> {
        self.inner.consume(token, expected, now_ms)
    }

    fn verified_revoke_epoch(&self) -> Option<u64> {
        if !self.prompts.borrow().is_empty() {
            if let Some(epoch) = self.epoch_after.get() {
                return Some(epoch);
            }
        }
        self.inner.verified_revoke_epoch()
    }
}

/// The owner issues a lease with STRONG presence: one STRONG prompt naming
/// the session, the canonical scope and the duration; the lease lands in
/// the protected store bound to everything; list and revoke work.
#[test]
fn ob08_the_owner_issues_lists_and_revokes_with_strong_presence() {
    let dir = scratch("issue");
    let broker = broker_with_presence(dir.join("approvals.json"), TestPresenceVerifier::verified());
    let recording = Recording::new(&broker);
    let env = env(&dir);
    let issued = dispatch_management(
        &env,
        &recording,
        &management("browser.lease.issue", "issue", issue_arguments()),
    )
    .expect("issued");
    let prompts = recording.prompts.borrow().clone();
    assert_eq!(prompts.len(), 1);
    assert_eq!(prompts[0].action, LEASE_ISSUE_ACTION);
    assert_eq!(
        prompts[0].approval_class,
        orcel_approval::ApprovalClass::Strong
    );
    assert_eq!(prompts[0].target, SESSION);
    assert!(prompts[0].summary.contains("https://fixture.test"));
    assert!(prompts[0].summary.contains("30 minutes"));
    assert!(prompts[0].summary.contains("still ask"));
    assert_eq!(issued["origins"], json!(["https://fixture.test"]));
    assert_eq!(
        issued["families"],
        json!(["navigate", "click", "type", "select", "read", "tabs"])
    );
    assert_eq!(issued["active"], json!(true));
    let lease_id = issued["lease_id"].as_str().expect("id").to_owned();
    let store = full_control_store::load_store(&env.store_path, &KEY).expect("store");
    let lease = store.browser_leases.first().cloned().expect("stored");
    assert_eq!(lease.lease_id, lease_id);
    assert_eq!(lease.windows_user_sid, SID);
    assert_eq!(lease.logon_session_id, LOGON);
    assert_eq!(lease.device_id, full_control_store::derive_device_id(&KEY));
    assert_eq!(lease.authority_epoch, store.authority_epoch);
    assert_eq!(Some(lease.approval_epoch), broker.verified_revoke_epoch());
    assert_eq!(lease.expires_at_ms - lease.issued_at_ms, 30 * 60_000);

    let listed = dispatch_management(
        &env,
        &recording,
        &management("browser.lease.list", "list", json!({})),
    )
    .expect("list");
    assert_eq!(listed["leases"][0]["lease_id"], json!(lease_id));
    assert!(!listed.to_string().contains(SID));
    let revoked = dispatch_management(
        &env,
        &recording,
        &management(
            "browser.lease.revoke",
            "revoke",
            json!({ "lease_id": lease_id }),
        ),
    )
    .expect("revoke");
    assert_eq!(revoked["revoked"], json!(1));
    assert!(full_control_store::load_store(&env.store_path, &KEY)
        .expect("store")
        .browser_leases
        .is_empty());
    assert_eq!(
        recording.prompts.borrow().len(),
        1,
        "list and revoke ask nothing"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// Issuance never happens without STRONG presence: denied, unavailable, or
/// a SOFT-only broker leave the store without a lease.
#[test]
fn ob08_issuance_without_strong_presence_grants_nothing() {
    let dir = scratch("presence");
    let env = env(&dir);
    for verifier in [
        TestPresenceVerifier::denied(),
        TestPresenceVerifier::unavailable(),
    ] {
        let broker = broker_with_presence(dir.join("approvals.json"), verifier);
        assert!(dispatch_management(
            &env,
            &broker,
            &management("browser.lease.issue", "issue", issue_arguments())
        )
        .is_err());
    }
    let soft = FixedApprovalBroker(ApprovalDecision::Approved);
    assert!(dispatch_management(
        &env,
        &soft,
        &management("browser.lease.issue", "issue", issue_arguments())
    )
    .is_err());
    let leases = full_control_store::load_store(&env.store_path, &KEY)
        .map(|status| status.browser_leases)
        .unwrap_or_default();
    assert!(leases.is_empty());
    let _ = std::fs::remove_dir_all(dir);
}

/// A revoke, emergency stop or desktop grant (authority epoch) or an
/// emergency revoke (approval epoch) while the STRONG prompt was open
/// refuses the grant afterwards.
#[test]
fn ob08_an_epoch_moved_during_the_prompt_refuses_the_grant() {
    let dir = scratch("race");
    let env = env(&dir);
    let broker = broker_with_presence(dir.join("approvals.json"), TestPresenceVerifier::verified());
    let mut recording = Recording::new(&broker);
    let store_path = env.store_path.clone();
    recording.on_prompt = Box::new(move || {
        let _ = full_control_store::invalidate(&store_path, &KEY);
    });
    assert!(dispatch_management(
        &env,
        &recording,
        &management("browser.lease.issue", "issue", issue_arguments())
    )
    .is_err());
    let recording = Recording::new(&broker);
    recording.epoch_after.set(Some(77));
    let refused = dispatch_management(
        &env,
        &recording,
        &management("browser.lease.issue", "issue", issue_arguments()),
    )
    .expect_err("approval epoch moved");
    assert_eq!(refused.code, FailureCode::TargetStale);
    assert!(full_control_store::load_store(&env.store_path, &KEY)
        .expect("store")
        .browser_leases
        .is_empty());
    let _ = std::fs::remove_dir_all(dir);
}

/// A malformed scope is refused before anything is asked.
#[test]
fn ob08_a_malformed_issuance_is_refused_before_any_prompt() {
    let dir = scratch("malformed");
    let env = env(&dir);
    let broker = broker_with_presence(dir.join("approvals.json"), TestPresenceVerifier::verified());
    let recording = Recording::new(&broker);
    let with = |field: &str, value: Value| {
        let mut arguments = issue_arguments();
        arguments[field] = value;
        arguments
    };
    let mut extra = issue_arguments();
    extra["profile"] = json!("Default");
    let mut missing = issue_arguments();
    if let Some(map) = missing.as_object_mut() {
        map.remove("minutes");
    }
    for (name, arguments) in [
        (
            "wildcard",
            with("origins", json!(["https://*.fixture.test"])),
        ),
        ("path", with("origins", json!(["https://fixture.test/a"]))),
        ("http", with("origins", json!(["http://fixture.test"]))),
        ("no origin", with("origins", json!([]))),
        (
            "too many",
            with(
                "origins",
                json!((0..65)
                    .map(|n| format!("https://h{n}.test"))
                    .collect::<Vec<_>>()),
            ),
        ),
        // Within the 64-origin bound, but more than its STRONG prompt can
        // show in full: the owner would not see every origin, so no prompt.
        (
            "too long to show",
            with(
                "origins",
                json!((0..60)
                    .map(|n| format!("https://host-{n}.fixture.test"))
                    .collect::<Vec<_>>()),
            ),
        ),
        ("unknown family", with("families", json!(["submit"]))),
        ("no family", with("families", json!([]))),
        ("zero minutes", with("minutes", json!(0))),
        ("over twelve hours", with("minutes", json!(721))),
        ("session", with("session_id", json!("bs-nope"))),
        ("client", with("client_ref", json!(CLIENT))),
        ("extra field", extra),
        ("missing field", missing),
    ] {
        let refused = dispatch_management(
            &env,
            &recording,
            &management("browser.lease.issue", "issue", arguments),
        )
        .expect_err(name);
        assert_eq!(
            refused.code,
            FailureCode::InvalidRequest,
            "{name}: {}",
            refused.message
        );
    }
    assert!(recording.prompts.borrow().is_empty());
    let unknown = dispatch_management(
        &env,
        &recording,
        &management("browser.lease.widen", "widen", json!({})),
    )
    .expect_err("unknown");
    assert_eq!(unknown.code, FailureCode::CapabilityDenied);
    let _ = std::fs::remove_dir_all(dir);
}

/// FX-4: an agent (any request naming a tool surface profile, as an MCP
/// edge always does) and a remote caller can never manage leases; the
/// refusal is the authority self-grant refusal.
#[test]
fn ob08_agents_mcp_and_remote_callers_can_never_manage_leases() {
    assert!(refuse_untrusted(false, None).is_ok());
    for (remote, profile) in [
        (true, None),
        (true, Some("browser_full")),
        (false, Some("browser_full")),
        (false, Some("browser_structured")),
        (false, Some("desktop_structured")),
    ] {
        let refused = refuse_untrusted(remote, profile).expect_err("refused");
        assert_eq!(refused.code, FailureCode::CapabilityDenied);
        assert!(
            refused.message.contains("self-grant is denied"),
            "{}",
            refused.message
        );
    }
}

/// Through orceld's entry: every browser lease shape from a remote caller
/// or under a profile is refused before anything is read or asked, and the
/// remote lease gate also treats the prefix as local-only.
#[test]
fn ob08_the_entry_refuses_lease_management_from_agents_and_remote() {
    let (policy, audit, root) = entry_fixture();
    let workspaces = crate::remote_lease::WorkspaceSet::from_pairs(&[]);
    let never = FixedApprovalBroker(ApprovalDecision::Denied);
    for (capability, operation) in [
        ("browser.lease.issue", "issue"),
        ("browser.lease.list", "list"),
        ("browser.lease.revoke", "revoke"),
    ] {
        assert!(crate::remote_lease::is_lease_management(capability));
        assert!(orcel_policy::remote_session::is_local_only_capability(
            capability
        ));
        for (remote, profile) in [
            (Some(remote()), None),
            (None, Some("browser_full".to_owned())),
            (None, Some("desktop_structured".to_owned())),
        ] {
            let response = crate::handle_envelope(
                &policy,
                &audit,
                &never,
                &workspaces,
                orcel_contracts::RemoteRequestEnvelope {
                    request: management(capability, operation, issue_arguments()),
                    remote,
                    profile,
                },
            );
            assert!(!response.ok);
            let error = response.error.expect("refused");
            assert_eq!(
                error.code,
                FailureCode::CapabilityDenied,
                "{capability}: {}",
                error.message
            );
            assert!(
                error.message.contains("managed only by the owner"),
                "{}",
                error.message
            );
        }
    }
    let _ = std::fs::remove_dir_all(root);
}

fn entry_fixture() -> (
    orcel_policy::PolicyEngine,
    orcel_audit::AuditLogger,
    PathBuf,
) {
    let root = scratch("entry");
    std::fs::create_dir_all(root.join("workspace")).expect("workspace");
    let workspace = orcel_policy::Workspace {
        id: "default".into(),
        root: std::fs::canonicalize(root.join("workspace")).expect("canonical"),
    };
    let policy = orcel_policy::PolicyEngine::new(vec![workspace]).expect("policy");
    let audit = orcel_audit::AuditLogger::new(root.join("audit.jsonl")).expect("audit");
    (policy, audit, root)
}

fn remote() -> orcel_contracts::RemoteContext {
    orcel_contracts::RemoteContext {
        principal: format!("rp-{}", "1".repeat(32)),
        remote_connection_id: format!("rc-{}", "2".repeat(32)),
        connection_id: "conn-ob08-test".into(),
        device_id: format!("dev-{}", "3".repeat(32)),
        device_epoch: 1,
        provider_kind: "generic".into(),
        client_profile_id: "profile-test".into(),
        client_profile_revision: 1,
        tool_surface_profile: "core".into(),
        scopes: vec!["orcel.read".into()],
    }
}
