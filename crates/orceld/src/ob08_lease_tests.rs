//! SG-000135 OB-08 tests, against service-signed leases (SG-000132 slice 2):
//! the lease cache's scope matching and every invalidation, the service's
//! `Authorize` before each covered action, the owner's management path
//! (list and revoke through the service; orceld issues nothing) and its
//! refusal for agent, MCP and remote callers.
//!
//! Every lease here is a service lease body signed with a test key and
//! admitted through `authority_link::admit_browser_lease`, the same check
//! orceld runs on what the service returns; the scripted source stands in
//! for the service's pipe. No SOFT or STRONG prompt is ever shown.

use crate::authority_link::admit_browser_lease;
use crate::browser_lease::{
    dispatch_management, refuse_untrusted, AuthorityView, CoveredAction, FillValue, FullAccess,
    LeaseDecision, LeaseManager, LeaseMoment, LeaseQuery, LeaseSource, SecretMatcher,
    LEASE_INVALID,
};
use orcel_approval::test_support::FixedApprovalBroker;
use orcel_approval::ApprovalDecision;
use orcel_authority::lease::{
    signing_input, BrowserFamily as ServiceFamily, GrantEvidence, LeaseBody, LeaseScope,
    ObservedRequester, SignatureVerifier, SignedLease, LEASE_CONTRACT,
};
use orcel_authority::AuthorityError;
use orcel_contracts::browser_impact::Impact;
use orcel_contracts::{FailureCode, RequestEnvelope, INTERNAL_PROTOCOL_VERSION};
use orcel_policy::browser_lease::{client_ref, BrowserFamily, BrowserLease};
use orcel_provider_fs::ProviderError;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::rc::Rc;

const SESSION: &str = "bs-0123456789abcdef-1-0001020304050607";
const OTHER_SESSION: &str = "bs-0123456789abcdef-2-0001020304050607";
const CLIENT: &str = "mcp-client-a";
const SID: &str = "S-1-5-21-1-2-3-1001";
const LOGON: u64 = 42;
const ORIGIN: &str = "https://fixture.test";
const PAGE: &str = "pg-0123456789abcdef0123456789abcdef";
const NOW: u64 = 1_800_000_000_000;
const TASK: &str = "Book a table";
const OTHER_PAGE: &str = "pg-fedcba9876543210fedcba9876543210";
const EPOCH: u64 = 5;

// ---------------------------------------------------------------------
// Service-signed leases.
// ---------------------------------------------------------------------

/// A test signing key standing in for the service's ECDSA key (a keyed
/// SHA-256): `admit_browser_lease` checks it like the real verifier.
struct TestKey(&'static [u8]);

impl TestKey {
    fn sign(&self, message: &[u8]) -> Vec<u8> {
        let mut input = self.0.to_vec();
        input.extend_from_slice(message);
        Sha256::digest(&input).to_vec()
    }
}

impl SignatureVerifier for TestKey {
    fn key_id(&self) -> String {
        orcel_authority::lease::key_id_of(self.0)
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), AuthorityError> {
        if self.sign(message) == signature {
            Ok(())
        } else {
            Err(AuthorityError::lease_invalid("test signature mismatch"))
        }
    }
}

const SERVICE: TestKey = TestKey(b"the authority service's test key");
const STRANGER: TestKey = TestKey(b"a key the service does not hold");

/// What a test lease names.
struct Spec {
    session_id: String,
    client_ref: String,
    task: Option<String>,
    origins: Vec<String>,
    families: Vec<ServiceFamily>,
    sid: String,
    logon: u64,
    epoch: u64,
    revocations: u64,
    issued: u64,
    minutes: u64,
}

fn service_family(family: BrowserFamily) -> ServiceFamily {
    match family {
        BrowserFamily::Navigate => ServiceFamily::Navigate,
        BrowserFamily::Click => ServiceFamily::Click,
        BrowserFamily::Type => ServiceFamily::Type,
        BrowserFamily::Select => ServiceFamily::Select,
        BrowserFamily::Scroll => ServiceFamily::Scroll,
        BrowserFamily::Read => ServiceFamily::Read,
        BrowserFamily::Tabs => ServiceFamily::Tabs,
        BrowserFamily::Download => ServiceFamily::Download,
    }
}

fn signed_with(
    key: &TestKey,
    families: &[BrowserFamily],
    change: impl FnOnce(&mut Spec),
) -> SignedLease {
    let mut spec = Spec {
        session_id: SESSION.into(),
        client_ref: client_ref(CLIENT),
        task: Some(TASK.into()),
        origins: vec![ORIGIN.into()],
        families: families.iter().map(|f| service_family(*f)).collect(),
        sid: SID.into(),
        logon: LOGON,
        epoch: EPOCH,
        revocations: 2,
        issued: NOW,
        minutes: 60,
    };
    change(&mut spec);
    let body = LeaseBody {
        contract: LEASE_CONTRACT.to_owned(),
        lease_id: format!("al-{}", "7".repeat(32)),
        scope: LeaseScope::BrowserFullAccess {
            client_ref: spec.client_ref.clone(),
            session_id: spec.session_id,
            origins: spec.origins,
            families: spec.families,
            task: spec.task.clone(),
        },
        windows_user_sid: spec.sid,
        logon_session_id: spec.logon,
        ts_session_id: 1,
        principal_id: spec.client_ref,
        task: spec.task.unwrap_or_else(|| "browser Full Access".into()),
        requester: ObservedRequester {
            pid: 7,
            image: "C:\\Program Files\\Orcel\\orcel.exe".into(),
        },
        authority_epoch: spec.epoch,
        revocations_at_issue: spec.revocations,
        issued_at_ms: spec.issued,
        expires_at_ms: spec.issued + spec.minutes * 60_000,
        key_id: key.key_id(),
        grant: GrantEvidence {
            intent_digest: "0".repeat(64),
            confirmation_text_digest: "1".repeat(64),
            confirmation: "service_rendered".into(),
            confirmation_input_protected: false,
            presence: "windows_hello_key_credential".into(),
            presence_key_digest: "2".repeat(64),
        },
    };
    let signature = signing_input(&body)
        .map(|input| key.sign(&input))
        .unwrap_or_default();
    SignedLease {
        body,
        signature: orcel_authority::hex(&signature),
    }
}

/// A service lease, signed and admitted the way orceld admits one.
fn proof_lease(families: &[BrowserFamily], change: impl FnOnce(&mut Spec)) -> BrowserLease {
    let signed = signed_with(&SERVICE, families, change);
    match admit_browser_lease(&signed, &SERVICE) {
        Ok(Some(lease)) => lease,
        other => BrowserLease {
            requester: format!("not admitted: {other:?}"),
            ..placeholder()
        },
    }
}

/// A lease shape no check accepts (used only when admission failed, so the
/// test that expected it fails on its own assertion).
fn placeholder() -> BrowserLease {
    BrowserLease {
        lease_id: "not admitted".into(),
        client_ref: String::new(),
        session_id: String::new(),
        windows_user_sid: String::new(),
        logon_session_id: 0,
        authority_epoch: 0,
        revocations_at_issue: 0,
        origins: Vec::new(),
        families: Vec::new(),
        issued_at_ms: 0,
        expires_at_ms: 0,
        task: None,
        principal_id: String::new(),
        requester: String::new(),
    }
}

fn routine_families() -> Vec<BrowserFamily> {
    vec![
        BrowserFamily::Navigate,
        BrowserFamily::Click,
        BrowserFamily::Type,
        BrowserFamily::Select,
        BrowserFamily::Tabs,
    ]
}

fn view_of(leases: Vec<BrowserLease>) -> AuthorityView {
    AuthorityView {
        epoch: EPOCH,
        revocations: 2,
        leases,
    }
}

// ---------------------------------------------------------------------
// The scripted service.
// ---------------------------------------------------------------------

/// A scripted service: what the next read returns, how many reads there
/// were, which actions it authorized, and which sessions ended.
#[derive(Default)]
struct Scripted {
    view: RefCell<Option<Result<Option<AuthorityView>, ()>>>,
    reads: Cell<usize>,
    authorized: RefCell<Vec<CoveredAction>>,
    refuse_authorize: Cell<bool>,
    ended: RefCell<Vec<String>>,
}

#[derive(Clone)]
struct Source(Rc<Scripted>);

impl LeaseSource for Source {
    fn read(&self) -> Result<Option<AuthorityView>, ProviderError> {
        self.0.reads.set(self.0.reads.get() + 1);
        match self.0.view.borrow().clone() {
            Some(Ok(view)) => Ok(view),
            Some(Err(())) | None => Err(ProviderError::new(
                FailureCode::AuthorityUnavailable,
                "scripted service unreachable",
            )),
        }
    }

    fn authorize(&self, action: &CoveredAction) -> Result<(), ProviderError> {
        if self.0.refuse_authorize.get() {
            return Err(ProviderError::new(
                FailureCode::LeaseInvalid,
                "the scripted service refused Authorize",
            ));
        }
        self.0.authorized.borrow_mut().push(action.clone());
        Ok(())
    }

    fn end_session(&self, session_id: &str) {
        self.0.ended.borrow_mut().push(session_id.to_owned());
    }
}

struct Scene {
    service: Rc<Scripted>,
    access: FullAccess,
    lease: BrowserLease,
}

impl Scene {
    fn new() -> Self {
        Self::with(proof_lease(&routine_families(), |_| {}))
    }

    fn with(lease: BrowserLease) -> Self {
        let service = Rc::new(Scripted::default());
        *service.view.borrow_mut() = Some(Ok(Some(view_of(vec![lease.clone()]))));
        let access = FullAccess::new(
            SESSION,
            &client_ref(CLIENT),
            Some(TASK),
            Box::new(Source(Rc::clone(&service))),
            Box::new(NoSecrets),
            Some((SID.into(), LOGON)),
        );
        Self {
            service,
            access,
            lease,
        }
    }

    fn set_view(&self, view: Result<Option<AuthorityView>, ()>) {
        *self.service.view.borrow_mut() = Some(view);
    }
}

fn moment() -> LeaseMoment {
    LeaseMoment {
        approval_epoch: Some(2),
        now_ms: NOW + 1_000,
        interventions: gate(0),
    }
}

/// The takeover gate's view: both pages at intervention epoch `epoch`.
fn gate(epoch: u64) -> Option<BTreeMap<String, u64>> {
    Some(BTreeMap::from([
        (PAGE.to_owned(), epoch),
        (OTHER_PAGE.to_owned(), 0),
    ]))
}

/// A secret store holding nothing.
struct NoSecrets;

impl SecretMatcher for NoSecrets {
    fn matches(&self, _value: &str) -> Result<bool, ()> {
        Ok(false)
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

// ---------------------------------------------------------------------
// Admission of service-signed leases.
// ---------------------------------------------------------------------

/// Only a lease signed by the service's key is admitted; a desktop lease is
/// not a browser lease; a body changed after signing does not verify.
#[test]
fn ob08_only_service_signed_browser_leases_are_admitted() {
    let good = signed_with(&SERVICE, &routine_families(), |_| {});
    let admitted = admit_browser_lease(&good, &SERVICE);
    assert!(
        matches!(&admitted, Ok(Some(lease)) if lease.origins == [ORIGIN]),
        "{admitted:?}"
    );
    let foreign = signed_with(&STRANGER, &routine_families(), |_| {});
    assert_eq!(
        admit_browser_lease(&foreign, &SERVICE)
            .err()
            .map(|e| e.code),
        Some(FailureCode::AuthorityUnavailable)
    );
    let mut widened = good.clone();
    if let LeaseScope::BrowserFullAccess { origins, .. } = &mut widened.body.scope {
        origins.push("https://other.test".into());
    }
    assert!(
        admit_browser_lease(&widened, &SERVICE).is_err(),
        "a changed body"
    );
    let mut desktop = good.clone();
    desktop.body.scope = LeaseScope::narrow_default();
    let resigned = signing_input(&desktop.body)
        .map(|input| SERVICE.sign(&input))
        .unwrap_or_default();
    desktop.signature = orcel_authority::hex(&resigned);
    assert!(matches!(admit_browser_lease(&desktop, &SERVICE), Ok(None)));
    // A family orceld does not enforce (the service refuses it too) is out
    // of shape even when signed.
    let scroll = signed_with(&SERVICE, &[BrowserFamily::Scroll], |_| {});
    assert!(admit_browser_lease(&scroll, &SERVICE).is_err());
    let listed = json!({
        "epoch": EPOCH,
        "revocations": 2,
        "leases": [
            { "lease": good, "state": "active" },
            { "lease": signed_with(&SERVICE, &routine_families(), |s| s.session_id = OTHER_SESSION.into()), "state": "revoked" },
        ],
    });
    let leases = crate::authority_link::admit_listed(&listed, &SERVICE);
    assert!(matches!(&leases, Ok(list) if list.len() == 1), "{leases:?}");
}

// ---------------------------------------------------------------------
// The lease cache.
// ---------------------------------------------------------------------

/// FA-E: routine actions of every leased family on the leased origin are
/// covered, each with its own one-shot record id, each confirmed against
/// exactly one fresh service read and admitted by one service Authorize.
#[test]
fn ob08_routine_actions_in_scope_are_covered_confirmed_and_authorized() {
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
            let before = scene.service.reads.get();
            scene.access.confirm(&used, &moment()).expect("confirmed");
            assert_eq!(
                scene.service.reads.get(),
                before + 1,
                "one read right before dispatch"
            );
            let authorized = scene.service.authorized.borrow().last().cloned();
            let authorized = authorized.expect("authorized");
            assert_eq!(authorized.lease_id, scene.lease.lease_id);
            assert_eq!(authorized.family, family);
            assert_eq!(authorized.origin, ORIGIN);
            assert_eq!(authorized.principal_id, client_ref(CLIENT));
            assert_eq!(authorized.record_id, used.record_id);
            assert!(
                records.insert(used.record_id.clone()),
                "record ids are one-shot"
            );
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
    assert_eq!(scene.service.authorized.borrow().len(), 28);
    assert_eq!(scene.service.reads.get(), 28 + 1);
    let mut tab = query(BrowserFamily::Navigate, Impact::Routine);
    tab.also = Some(BrowserFamily::Tabs);
    covered(scene.access.decide(&tab, &moment()));
}

/// The service refusing Authorize (revoked there, epoch moved, orceld not
/// trusted) refuses that action, nothing sent; later actions ask.
#[test]
fn ob08_a_refused_authorize_refuses_the_action_and_ends_the_lease() {
    let mut scene = Scene::new();
    let used = covered(
        scene
            .access
            .decide(&query(BrowserFamily::Click, Impact::Routine), &moment()),
    );
    scene.service.refuse_authorize.set(true);
    let refused = scene.access.confirm(&used, &moment()).expect_err("refused");
    assert!(
        refused.message.starts_with(LEASE_INVALID),
        "{}",
        refused.message
    );
    assert!(refused.message.contains("Authorize"), "{}", refused.message);
    scene.service.refuse_authorize.set(false);
    assert!(is_ask(&scene.access.decide(
        &query(BrowserFamily::Click, Impact::Routine),
        &moment()
    )));
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

/// No lease, another session's lease, an unreachable or absent service, or
/// no native identity: nothing is covered.
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
    let other = proof_lease(&routine_families(), |spec| {
        spec.session_id = OTHER_SESSION.into();
    });
    scene.set_view(Ok(Some(view_of(vec![other]))));
    assert!(is_ask(&scene.access.decide(
        &query(BrowserFamily::Click, Impact::Routine),
        &moment()
    )));

    let lease = proof_lease(&routine_families(), |_| {});
    let service = Rc::new(Scripted::default());
    *service.view.borrow_mut() = Some(Ok(Some(view_of(vec![lease]))));
    let mut nobody = FullAccess::new(
        SESSION,
        &client_ref(CLIENT),
        Some(TASK),
        Box::new(Source(service)),
        Box::new(NoSecrets),
        None,
    );
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
    let service = Rc::new(Scripted::default());
    *service.view.borrow_mut() = Some(Ok(Some(view_of(vec![lease.clone()]))));
    let mut stranger = FullAccess::new(
        SESSION,
        &client_ref("mcp-client-b"),
        Some(TASK),
        Box::new(Source(Rc::clone(&service))),
        Box::new(NoSecrets),
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
        AuthorityView,
        LeaseMoment,
        Option<(String, u64)>,
    );
    let mut moved_epoch = view_of(vec![lease.clone()]);
    moved_epoch.epoch = EPOCH + 1;
    let mut counter_back = view_of(vec![lease.clone()]);
    counter_back.revocations = 1;
    let drifts: Vec<Drift> = vec![
        (
            "service epoch moved",
            moved_epoch,
            moment(),
            Some((SID.into(), LOGON)),
        ),
        (
            "service revocation counter went back",
            counter_back,
            moment(),
            Some((SID.into(), LOGON)),
        ),
        (
            "unverified approval epoch",
            view_of(vec![lease.clone()]),
            LeaseMoment {
                approval_epoch: None,
                ..moment()
            },
            Some((SID.into(), LOGON)),
        ),
        (
            "expired",
            view_of(vec![lease.clone()]),
            LeaseMoment {
                now_ms: lease.expires_at_ms,
                ..moment()
            },
            Some((SID.into(), LOGON)),
        ),
        (
            "windows user",
            view_of(vec![lease.clone()]),
            moment(),
            Some(("S-1-5-21-9".into(), LOGON)),
        ),
        (
            "logon session",
            view_of(vec![lease.clone()]),
            moment(),
            Some((SID.into(), LOGON + 1)),
        ),
    ];
    for (name, view, at, identity) in drifts {
        let service = Rc::new(Scripted::default());
        *service.view.borrow_mut() = Some(Ok(Some(view)));
        let mut access = FullAccess::new(
            SESSION,
            &client_ref(CLIENT),
            Some(TASK),
            Box::new(Source(service)),
            Box::new(NoSecrets),
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

/// An emergency revoke (the approval epoch moved since the lease was
/// cached) ends the lease's use at the next decision or confirmation.
#[test]
fn ob08_an_emergency_revoke_after_caching_ends_the_lease() {
    let mut scene = Scene::new();
    covered(
        scene
            .access
            .decide(&query(BrowserFamily::Click, Impact::Routine), &moment()),
    );
    let revoked = LeaseMoment {
        approval_epoch: Some(3),
        ..moment()
    };
    assert!(is_lease_invalid(&scene.access.decide(
        &query(BrowserFamily::Click, Impact::Routine),
        &revoked
    )));
    let mut scene = Scene::new();
    let used = covered(
        scene
            .access
            .decide(&query(BrowserFamily::Click, Impact::Routine), &moment()),
    );
    assert!(scene.access.confirm(&used, &revoked).is_err());
    assert!(
        scene.service.authorized.borrow().is_empty(),
        "nothing authorized"
    );
}

/// FX-4: a revoke stops the very next action, even with the lease cached:
/// the check right before dispatch reads the service once more and refuses
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
    let mut after_revoke = view_of(Vec::new());
    after_revoke.revocations = 3;
    scene.set_view(Ok(Some(after_revoke)));
    let refused = scene.access.confirm(&used, &moment()).expect_err("revoked");
    assert!(
        refused.message.starts_with(LEASE_INVALID),
        "{}",
        refused.message
    );
    assert!(refused.message.contains("revoked"));
    assert_eq!(scene.service.authorized.borrow().len(), 1, "only the first");
    // The same lease listed again does not come back for this session.
    scene.set_view(Ok(Some(view_of(vec![scene.lease.clone()]))));
    assert!(is_ask(&scene.access.decide(
        &query(BrowserFamily::Click, Impact::Routine),
        &moment()
    )));
}

/// A service epoch move (Stop, lock, sign-out, expiry, re-enrollment), a
/// changed record, an unreachable or absent service or expiry, found right
/// before dispatch, refuse that action.
#[test]
fn ob08_every_change_found_right_before_dispatch_refuses() {
    type Case = (&'static str, Box<dyn Fn(&Scene)>, LeaseMoment);
    let cases: Vec<Case> = vec![
        (
            "authority epoch",
            Box::new(|scene: &Scene| {
                let mut view = view_of(vec![scene.lease.clone()]);
                view.epoch = EPOCH + 1;
                scene.set_view(Ok(Some(view)));
            }),
            moment(),
        ),
        (
            "service unreachable",
            Box::new(|scene: &Scene| scene.set_view(Err(()))),
            moment(),
        ),
        (
            "service gone",
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
        assert!(scene.service.authorized.borrow().is_empty(), "{name}");
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
    let at = moment();
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
        interventions: gate(1),
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

/// Session end: the cache goes and the service revokes the session's lease.
#[test]
fn ob08_session_end_revokes_the_lease_at_the_service() {
    let mut scene = Scene::new();
    covered(
        scene
            .access
            .decide(&query(BrowserFamily::Click, Impact::Routine), &moment()),
    );
    scene.access.session_ended();
    assert_eq!(
        scene.service.ended.borrow().as_slice(),
        [SESSION.to_owned()]
    );
}

/// MCP tools may only read: the status names the scope and expiry, and
/// nothing an agent could use (no Windows user or logon session).
#[test]
fn ob08_status_is_read_only_scope_and_expiry() {
    let scene = Scene::new();
    let status = scene.access.status(NOW + 1);
    assert_eq!(status["lease_id"], json!(scene.lease.lease_id));
    assert_eq!(status["origins"], json!([ORIGIN]));
    assert_eq!(status["expires_at_ms"], json!(scene.lease.expires_at_ms));
    assert_eq!(status["active"], json!(true));
    assert_eq!(status["issued_by"], json!("orcel_authority_service"));
    let text = status.to_string();
    assert!(!text.contains(SID));
    scene.set_view(Ok(None));
    assert_eq!(scene.access.status(NOW + 1)["active"], json!(false));
}

// ---------------------------------------------------------------------
// The owner's management path.
// ---------------------------------------------------------------------

/// A scripted service for list and revoke.
#[derive(Default)]
struct Manager {
    leases: RefCell<Vec<BrowserLease>>,
}

impl LeaseManager for Manager {
    fn list(&self) -> Result<Vec<BrowserLease>, ProviderError> {
        Ok(self.leases.borrow().clone())
    }

    fn revoke(&self, lease_id: Option<&str>) -> Result<usize, ProviderError> {
        let mut leases = self.leases.borrow_mut();
        let before = leases.len();
        leases.retain(|lease| lease_id.is_some_and(|id| id != lease.lease_id));
        Ok(before - leases.len())
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
        "origins": ["https://fixture.test"],
        "families": ["navigate", "click", "type", "select", "tabs"],
        "task": TASK,
        "minutes": 30,
    })
}

/// orceld issues nothing: `browser.lease.issue` is refused whatever it
/// names; list and revoke go to the service and ask nothing.
#[test]
fn ob08_orceld_issues_no_lease_and_lists_and_revokes_through_the_service() {
    let manager = Manager::default();
    let refused = dispatch_management(
        &manager,
        &management("browser.lease.issue", "issue", issue_arguments()),
        NOW,
    )
    .expect_err("issue refused");
    assert_eq!(refused.code, FailureCode::CapabilityDenied);
    assert!(
        refused.message.contains("authority service"),
        "{}",
        refused.message
    );
    assert!(manager.leases.borrow().is_empty());

    let lease = proof_lease(&routine_families(), |_| {});
    manager.leases.borrow_mut().push(lease.clone());
    let listed = dispatch_management(
        &manager,
        &management("browser.lease.list", "list", json!({})),
        NOW + 1,
    )
    .expect("list");
    assert_eq!(listed["leases"][0]["lease_id"], json!(lease.lease_id));
    assert!(!listed.to_string().contains(SID));
    let revoked = dispatch_management(
        &manager,
        &management(
            "browser.lease.revoke",
            "revoke",
            json!({ "lease_id": lease.lease_id }),
        ),
        NOW,
    )
    .expect("revoke");
    assert_eq!(revoked["revoked"], json!(1));
    assert!(manager.leases.borrow().is_empty());
    for (capability, operation, arguments) in [
        ("browser.lease.list", "list", json!({ "extra": 1 })),
        ("browser.lease.revoke", "revoke", json!({})),
        ("browser.lease.revoke", "revoke", json!({ "lease_id": 7 })),
    ] {
        assert_eq!(
            dispatch_management(&manager, &management(capability, operation, arguments), NOW)
                .err()
                .map(|e| e.code),
            Some(FailureCode::InvalidRequest),
            "{capability}"
        );
    }
    let unknown = dispatch_management(
        &manager,
        &management("browser.lease.widen", "widen", json!({})),
        NOW,
    )
    .expect_err("unknown");
    assert_eq!(unknown.code, FailureCode::CapabilityDenied);
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

// ---------------------------------------------------------------------
// OB-08 review.
// ---------------------------------------------------------------------

/// Finding 3: without the takeover gate (feature off) no person's input can
/// be seen, so nothing is ever covered; a page the gate does not track asks.
#[test]
fn ob08_review_without_the_takeover_gate_nothing_is_covered() {
    let mut scene = Scene::new();
    let no_gate = LeaseMoment {
        interventions: None,
        ..moment()
    };
    for family in [
        BrowserFamily::Navigate,
        BrowserFamily::Click,
        BrowserFamily::Type,
    ] {
        assert!(is_ask(
            &scene
                .access
                .decide(&query(family, Impact::Routine), &no_gate)
        ));
    }
    let untracked = LeaseMoment {
        interventions: Some(BTreeMap::from([(OTHER_PAGE.to_owned(), 0)])),
        ..moment()
    };
    assert!(is_ask(&scene.access.decide(
        &query(BrowserFamily::Click, Impact::Routine),
        &untracked
    )));
    let used = covered(
        scene
            .access
            .decide(&query(BrowserFamily::Click, Impact::Routine), &moment()),
    );
    assert!(scene.access.confirm(&used, &no_gate).is_err());
}

/// Finding 3: the intervention marks are taken when the lease is cached
/// (every tracked page) and when a page opens, not at a page's first use.
#[test]
fn ob08_review_marks_are_taken_when_cached_not_at_first_use() {
    let mut scene = Scene::new();
    covered(
        scene
            .access
            .decide(&query(BrowserFamily::Click, Impact::Routine), &moment()),
    );
    let mut person_elsewhere = gate(0);
    if let Some(map) = person_elsewhere.as_mut() {
        map.insert(OTHER_PAGE.to_owned(), 1);
    }
    let moved = LeaseMoment {
        interventions: person_elsewhere,
        ..moment()
    };
    let mut other = query(BrowserFamily::Click, Impact::Routine);
    other.page_id = OTHER_PAGE;
    assert!(is_lease_invalid(&scene.access.decide(&other, &moved)));

    let mut scene = Scene::new();
    covered(
        scene
            .access
            .decide(&query(BrowserFamily::Click, Impact::Routine), &moment()),
    );
    let new_page = "pg-00000000000000000000000000000001";
    scene.access.page_opened(new_page, Some(0));
    let mut later = gate(0);
    if let Some(map) = later.as_mut() {
        map.insert(new_page.to_owned(), 2);
    }
    let mut on_new = query(BrowserFamily::Click, Impact::Routine);
    on_new.page_id = new_page;
    assert!(is_lease_invalid(&scene.access.decide(
        &on_new,
        &LeaseMoment {
            interventions: later,
            ..moment()
        }
    )));
}

/// Finding 7: a clock that went backwards behind what this session already
/// saw refuses.
#[test]
fn ob08_review_a_clock_that_went_backwards_refuses() {
    let mut scene = Scene::new();
    let later = LeaseMoment {
        now_ms: NOW + 9_000,
        ..moment()
    };
    covered(
        scene
            .access
            .decide(&query(BrowserFamily::Click, Impact::Routine), &later),
    );
    assert!(is_lease_invalid(&scene.access.decide(
        &query(BrowserFamily::Click, Impact::Routine),
        &moment()
    )));
}

/// A service whose revocation counter went back behind one this session saw
/// (restored from an older state) refuses.
#[test]
fn ob08_review_a_service_that_went_back_refuses() {
    let mut scene = Scene::new();
    let mut ahead = view_of(vec![scene.lease.clone()]);
    ahead.revocations = 4;
    scene.set_view(Ok(Some(ahead)));
    let used = covered(
        scene
            .access
            .decide(&query(BrowserFamily::Click, Impact::Routine), &moment()),
    );
    scene.access.confirm(&used, &moment()).expect("counter 4");
    let used = covered(
        scene
            .access
            .decide(&query(BrowserFamily::Click, Impact::Routine), &moment()),
    );
    scene.set_view(Ok(Some(view_of(vec![scene.lease.clone()]))));
    let refused = scene
        .access
        .confirm(&used, &moment())
        .expect_err("went back");
    assert!(refused.message.contains("went back"), "{}", refused.message);
}

/// The lease names the session's task label: another label, or none,
/// never covers.
#[test]
fn ob08_review_the_task_label_is_bound() {
    let lease = proof_lease(&routine_families(), |spec| {
        spec.task = Some("Another task".into())
    });
    let mut scene = Scene::with(lease);
    assert!(is_lease_invalid(&scene.access.decide(
        &query(BrowserFamily::Click, Impact::Routine),
        &moment()
    )));
}

/// A stored secret.
struct OneSecret(&'static str);

impl SecretMatcher for OneSecret {
    fn matches(&self, value: &str) -> Result<bool, ()> {
        Ok(value.contains(self.0))
    }
}

struct UnreadableSecrets;

impl SecretMatcher for UnreadableSecrets {
    fn matches(&self, _value: &str) -> Result<bool, ()> {
        Err(())
    }
}

/// Finding 8: a value that looks secret, or holds a stored secret, is
/// never typed under a lease; an unreadable secret store leaves it to the
/// person.
#[test]
fn ob08_review_secret_values_are_never_typed_under_a_lease() {
    let access = |secrets: Box<dyn SecretMatcher>| {
        FullAccess::new(
            SESSION,
            &client_ref(CLIENT),
            Some(TASK),
            Box::new(Source(Rc::new(Scripted::default()))),
            secrets,
            Some((SID.into(), LOGON)),
        )
    };
    let plain = access(Box::new(NoSecrets));
    assert_eq!(plain.fill_value("Ada Lovelace"), FillValue::Ordinary);
    for value in [
        "4111 1111 1111 1111",
        "123456",
        "sk-live-0123",
        "my password",
    ] {
        assert_eq!(plain.fill_value(value), FillValue::Secret, "{value}");
    }
    let stored = access(Box::new(OneSecret("correct-horse-battery")));
    assert_eq!(
        stored.fill_value("note correct-horse-battery staple"),
        FillValue::Secret
    );
    assert_eq!(stored.fill_value("Ada Lovelace"), FillValue::Ordinary);
    let unreadable = access(Box::new(UnreadableSecrets));
    assert_eq!(unreadable.fill_value("Ada Lovelace"), FillValue::Unverified);
}

/// Finding 5: families orceld does not enforce are never admitted, even in
/// a lease the service signed.
#[test]
fn ob08_review_unimplemented_families_are_never_admitted() {
    for family in [
        BrowserFamily::Read,
        BrowserFamily::Scroll,
        BrowserFamily::Download,
    ] {
        let signed = signed_with(&SERVICE, &[BrowserFamily::Navigate, family], |_| {});
        assert!(
            admit_browser_lease(&signed, &SERVICE).is_err(),
            "{family:?}"
        );
    }
}
