//! Contracts v1 (WP1-02, spec revision 8 section 4): golden fixture round
//! trips, unknown-field refusal on inbound authority-bearing types, frozen
//! spellings, the job state machine, the FailureCode to HTTP mapping,
//! authority and standing-approval shape checks, web bounds and canonical
//! JSON vectors.

use orcel_contracts::capability::{CapabilityReport, CapabilityStatus};
use orcel_contracts::event::{AnchorRef, AuditEvent, AuditEventKind, GENESIS_PREV_DIGEST};
use orcel_contracts::identity::{Device, OsFamily, OsIdentityBinding, Principal, PrincipalKind};
use orcel_contracts::job::{Job, JobBudget, JobKind, JobOutcome};
use orcel_contracts::lease::{
    ApprovalClass, AuthorityShapeError, DispatchAuthority, GrantRef, LeaseRef, LeaseView,
    StandingApproval,
};
use orcel_contracts::session::Session;
use orcel_contracts::sidecar::{
    HostToSidecar, SidecarLimits, SidecarToHost, MAX_CONTROL_FRAME_BYTES, MAX_DATA_FRAME_BYTES,
};
use orcel_contracts::tool::{RemoteExposure, ToolEntry};
use orcel_contracts::web::{
    CrawlBudget, HeaderSpec, HeaderValue, Ids, PrivacyProfileRef, SensitiveFeature,
    WebBatchScrapeRequest, WebContractError, WebCrawlRequest, WebScope, WebScrapeRequest,
};
use orcel_contracts::{
    canonical_json, canonical_json_value, AuthorityMode, CanonicalJsonError, Contract,
    ExecutionState, ExecutorClass, FailureCode,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeSet;

fn fixture(name: &str) -> Value {
    let path = format!("{}/tests/fixtures/{name}.json", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn parse<T: DeserializeOwned>(name: &str) -> T {
    serde_json::from_value(fixture(name)).unwrap_or_else(|e| panic!("fixture {name}: {e}"))
}

/// Parses the fixture as `T`, serializes it back and requires the exact
/// same JSON value: nothing dropped, renamed or defaulted differently.
fn round_trip<T: DeserializeOwned + Serialize>(name: &str) -> T {
    let golden = fixture(name);
    let parsed: T = serde_json::from_value(golden.clone())
        .unwrap_or_else(|e| panic!("fixture {name} does not parse: {e}"));
    let again = serde_json::to_value(&parsed).unwrap();
    assert_eq!(again, golden, "fixture {name} does not round-trip");
    parsed
}

fn round_trip_contract<T: DeserializeOwned + Serialize + Contract>(name: &str) -> T {
    let golden = fixture(name);
    assert_eq!(
        golden["contract"],
        T::CONTRACT,
        "fixture {name} names the wrong contract"
    );
    round_trip(name)
}

fn with_unknown_field(mut value: Value) -> Value {
    value
        .as_object_mut()
        .expect("object fixture")
        .insert("unexpected_field".to_owned(), json!(true));
    value
}

/// Inbound authority-bearing types refuse an unknown field.
fn refuses_unknown<T: DeserializeOwned>(name: &str) {
    let items = match fixture(name) {
        Value::Array(items) => items,
        other => vec![other],
    };
    for item in items {
        let tampered = with_unknown_field(item);
        assert!(
            serde_json::from_value::<T>(tampered.clone()).is_err(),
            "fixture {name} accepted an unknown field: {tampered}"
        );
    }
}

/// Outbound reports may gain optional fields within their major.
fn tolerates_unknown<T: DeserializeOwned>(name: &str) {
    let tampered = with_unknown_field(fixture(name));
    assert!(
        serde_json::from_value::<T>(tampered).is_ok(),
        "outbound fixture {name} refused an additive field"
    );
}

// ---------------------------------------------------------------- fixtures

const FIXTURES: &[&str] = &[
    "anchor_ref",
    "audit_event",
    "capability_report",
    "crawl_budget",
    "device",
    "dispatch_authority",
    "grant_ref",
    "host_to_sidecar",
    "ids",
    "job",
    "lease_view",
    "os_identity_binding",
    "principal",
    "session",
    "sidecar_to_host",
    "standing_approval",
    "tool_entry",
    "web_batch_scrape_request",
    "web_crawl_request",
    "web_scrape_request",
];

#[test]
fn fixture_set_matches_the_fixture_directory() {
    let dir = format!("{}/tests/fixtures", env!("CARGO_MANIFEST_DIR"));
    let on_disk: BTreeSet<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    let listed: BTreeSet<String> = FIXTURES.iter().map(|name| format!("{name}.json")).collect();
    assert_eq!(
        on_disk, listed,
        "every golden fixture is covered exactly once"
    );
}

#[test]
fn identity_fixtures_round_trip() {
    let principal: Principal = round_trip_contract("principal");
    assert_eq!(principal.kind, PrincipalKind::McpClient);
    let device: Device = round_trip_contract("device");
    assert_eq!(device.os, OsFamily::Windows);
    let bindings: Vec<OsIdentityBinding> = round_trip("os_identity_binding");
    let oses: Vec<OsFamily> = bindings.iter().map(OsIdentityBinding::os).collect();
    assert_eq!(oses, [OsFamily::Windows, OsFamily::Macos, OsFamily::Linux]);
}

#[test]
fn lease_and_grant_fixtures_round_trip() {
    let view: LeaseView = round_trip_contract("lease_view");
    assert_eq!(view.mode, AuthorityMode::FullUser);
    let grant: GrantRef = round_trip_contract("grant_ref");
    assert_eq!(grant.approval_class, ApprovalClass::Soft);
    assert_eq!(grant.principal_id, "mcp-client-7f3a");
    let authority: DispatchAuthority = round_trip("dispatch_authority");
    assert_eq!(authority.standing.as_deref(), Some("sa-01"));
    assert_eq!(authority.check(), Ok(()));
    let standing: StandingApproval = round_trip_contract("standing_approval");
    assert_eq!(standing.check_against_lease(&view), Ok(()));
}

#[test]
fn session_tool_and_capability_fixtures_round_trip() {
    let session: Session = round_trip_contract("session");
    assert!(session.remote.is_none());
    let tools: Vec<ToolEntry> = round_trip("tool_entry");
    assert_eq!(tools[0].remote, RemoteExposure::LocalOnly);
    assert!(!tools[0].standing_approvable);
    assert_eq!(
        tools[1].remote,
        RemoteExposure::Scopes(vec!["orcel.read".to_owned()])
    );
    for tool in &tools {
        assert_eq!(tool.contract, ToolEntry::CONTRACT);
    }
    let report: CapabilityReport = round_trip_contract("capability_report");
    let statuses: Vec<Option<FailureCode>> = report
        .entries
        .iter()
        .map(|entry| entry.status.failure_code())
        .collect();
    assert_eq!(
        statuses,
        [
            None,
            Some(FailureCode::ProviderUnavailable),
            Some(FailureCode::Unsupported),
            Some(FailureCode::PolicyBlocked),
            Some(FailureCode::PermissionRequired),
        ]
    );
}

#[test]
fn remote_exposure_refuses_other_strings() {
    assert!(serde_json::from_value::<RemoteExposure>(json!("everywhere")).is_err());
    assert!(serde_json::from_value::<RemoteExposure>(json!(7)).is_err());
}

#[test]
fn job_audit_and_anchor_fixtures_round_trip() {
    let job: Job = round_trip_contract("job");
    assert_eq!(job.kind, JobKind::WebCrawl);
    assert_eq!(
        job.outcome,
        Some(JobOutcome::Failed {
            code: FailureCode::TargetStale
        })
    );
    assert!(job.outcome_matches_state());
    assert_eq!(job.budget, JobBudget::from(CrawlBudget::DEFAULT));
    assert_eq!(job.authority.check(), Ok(()));
    let event: AuditEvent = round_trip_contract("audit_event");
    assert_eq!(event.kind, AuditEventKind::Dispatch);
    assert_eq!(event.prev_digest, GENESIS_PREV_DIGEST);
    assert!(event.asserted_by_session);
    let anchor: AnchorRef = round_trip("anchor_ref");
    assert_eq!(
        anchor.event_log_insertion().unwrap(),
        format!("orcel-anchor/1|authority|audit-0001|31|{}", "a".repeat(64))
    );
}

#[test]
fn ipc_fixtures_round_trip() {
    let host: Vec<HostToSidecar> = round_trip("host_to_sidecar");
    assert_eq!(host.len(), 5);
    let sidecar: Vec<SidecarToHost> = round_trip("sidecar_to_host");
    assert_eq!(sidecar.len(), 6);
}

#[test]
fn web_fixtures_round_trip() {
    let none: &[String] = &[];
    let crawl: WebCrawlRequest = round_trip_contract("web_crawl_request");
    assert_eq!(crawl.check(&CrawlBudget::DEFAULT, none), Ok(()));
    let scrape: WebScrapeRequest = round_trip_contract("web_scrape_request");
    assert_eq!(scrape.privacy, PrivacyProfileRef::default());
    assert_eq!(scrape.check(none), Ok(()));
    let batch: WebBatchScrapeRequest = round_trip_contract("web_batch_scrape_request");
    assert_eq!(batch.check(&CrawlBudget::DEFAULT, none), Ok(()));
    let budget: CrawlBudget = round_trip("crawl_budget");
    assert_eq!(budget, CrawlBudget::DEFAULT);
    assert_eq!(budget.check(), Ok(()));
    let ids: Ids = round_trip("ids");
    assert_eq!(ids.check(), Ok(()));
}

// ---------------------------------------------------------- unknown fields

#[test]
fn inbound_authority_bearing_types_refuse_unknown_fields() {
    refuses_unknown::<Principal>("principal");
    refuses_unknown::<OsIdentityBinding>("os_identity_binding");
    refuses_unknown::<GrantRef>("grant_ref");
    refuses_unknown::<DispatchAuthority>("dispatch_authority");
    refuses_unknown::<StandingApproval>("standing_approval");
    refuses_unknown::<Session>("session");
    refuses_unknown::<ToolEntry>("tool_entry");
    refuses_unknown::<AuditEvent>("audit_event");
    refuses_unknown::<AnchorRef>("anchor_ref");
    refuses_unknown::<HostToSidecar>("host_to_sidecar");
    refuses_unknown::<SidecarToHost>("sidecar_to_host");
    refuses_unknown::<Ids>("ids");
    refuses_unknown::<WebCrawlRequest>("web_crawl_request");
    refuses_unknown::<WebScrapeRequest>("web_scrape_request");
    refuses_unknown::<WebBatchScrapeRequest>("web_batch_scrape_request");
    refuses_unknown::<CrawlBudget>("crawl_budget");
}

#[test]
fn revision_8_required_fields_are_required() {
    refuses_missing::<GrantRef>("grant_ref", "principal_id");
    refuses_missing::<StandingApproval>("standing_approval", "lease_id");
    refuses_missing::<StandingApproval>("standing_approval", "granted_with");
    refuses_missing::<AuditEvent>("audit_event", "asserted_by_session");
    refuses_missing::<ToolEntry>("tool_entry", "standing_approvable");
    refuses_missing::<WebCrawlRequest>("web_crawl_request", "scope");
    refuses_missing::<WebCrawlRequest>("web_crawl_request", "task");
    refuses_missing::<WebBatchScrapeRequest>("web_batch_scrape_request", "scope");
    refuses_missing::<Ids>("ids", "principal_id");
    refuses_missing::<Job>("job", "scope_digest");
    refuses_missing::<Job>("job", "budget");
}

/// Inbound types refuse a missing required field (no silent default).
fn refuses_missing<T: DeserializeOwned>(name: &str, field: &str) {
    let mut value = fixture(name);
    let object = match &mut value {
        Value::Array(items) => items[0].as_object_mut().unwrap(),
        other => other.as_object_mut().unwrap(),
    };
    object.remove(field);
    let parsed = match value {
        Value::Array(mut items) => serde_json::from_value::<T>(items.remove(0)),
        other => serde_json::from_value::<T>(other),
    };
    assert!(parsed.is_err(), "fixture {name} accepted a missing {field}");
}

#[test]
fn nested_authority_objects_refuse_unknown_fields() {
    let mut value = fixture("dispatch_authority");
    value["lease"]["trusted"] = json!(true);
    assert!(serde_json::from_value::<DispatchAuthority>(value).is_err());
    let mut value = fixture("web_crawl_request");
    value["scope"]["subdomains"] = json!(true);
    assert!(serde_json::from_value::<WebCrawlRequest>(value).is_err());
    let mut value = fixture("web_crawl_request");
    value["privacy"]["captcha"] = json!(true);
    assert!(serde_json::from_value::<WebCrawlRequest>(value).is_err());
    let mut value = fixture("web_crawl_request");
    value["headers"][1]["value"] = json!({"secret": "x", "value": "inline"});
    assert!(serde_json::from_value::<WebCrawlRequest>(value).is_err());
    let mut value = fixture("host_to_sidecar");
    value[0]["limits"]["unbounded"] = json!(true);
    assert!(serde_json::from_value::<Vec<HostToSidecar>>(value).is_err());
}

#[test]
fn unknown_frames_and_variants_are_refused() {
    assert!(serde_json::from_value::<HostToSidecar>(json!({"frame": "grant"})).is_err());
    assert!(serde_json::from_value::<SidecarToHost>(json!({"frame": "elevate"})).is_err());
    let freebsd = json!({"os": "freebsd", "uid": 1});
    assert!(serde_json::from_value::<OsIdentityBinding>(freebsd).is_err());
    assert!(serde_json::from_value::<SensitiveFeature>(json!("captcha_solving")).is_err());
    assert!(serde_json::from_value::<HeaderValue>(json!({"inline": "x"})).is_err());
}

#[test]
fn outbound_reports_tolerate_additive_fields() {
    tolerates_unknown::<Device>("device");
    tolerates_unknown::<LeaseView>("lease_view");
    tolerates_unknown::<CapabilityReport>("capability_report");
    tolerates_unknown::<Job>("job");
}

// ------------------------------------------------------- frozen spellings

#[test]
fn moved_sg000093_vocabularies_keep_their_spellings() {
    let modes: Vec<Value> = AuthorityMode::ALL
        .iter()
        .map(|m| serde_json::to_value(m).unwrap())
        .collect();
    assert_eq!(
        modes,
        [
            "safe",
            "full_user",
            "full_admin",
            "persistent_admin",
            "remote_full_control"
        ]
    );
    let classes: Vec<Value> = ExecutorClass::ALL
        .iter()
        .map(|c| serde_json::to_value(c).unwrap())
        .collect();
    assert_eq!(
        classes,
        [
            "desktop_observation",
            "desktop_input",
            "shell_process",
            "filesystem",
            "browser",
            "web",
            "visual_agent",
            "admin",
            "remote"
        ]
    );
    let states: Vec<Value> = ExecutionState::ALL
        .iter()
        .map(|s| serde_json::to_value(s).unwrap())
        .collect();
    assert_eq!(
        states,
        [
            "not_started",
            "dispatched",
            "completed",
            "cancelled",
            "outcome_unknown"
        ]
    );
}

#[test]
fn approval_class_keeps_the_catalog_spellings() {
    let classes: Vec<Value> = [
        ApprovalClass::None,
        ApprovalClass::Soft,
        ApprovalClass::Strong,
    ]
    .iter()
    .map(|c| serde_json::to_value(c).unwrap())
    .collect();
    assert_eq!(classes, ["none", "SOFT", "STRONG"]);
}

#[test]
fn audit_event_kinds_include_standing() {
    assert_eq!(
        serde_json::to_value(AuditEventKind::Standing).unwrap(),
        "standing"
    );
}

#[test]
fn sensitive_features_map_to_their_permissions() {
    for feature in SensitiveFeature::ALL {
        assert_eq!(
            serde_json::to_value(feature).unwrap(),
            feature.wire_name(),
            "{feature:?}"
        );
        assert_eq!(
            feature.permission(),
            format!("web.privacy.sensitive:{}", feature.wire_name())
        );
    }
    let crawl: WebCrawlRequest = parse("web_crawl_request");
    assert_eq!(
        crawl.privacy.required_permissions(),
        ["web.privacy.sensitive:locale_override"]
    );
}

fn spelling(code: &FailureCode) -> String {
    serde_json::to_value(code)
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn existing_failure_codes_keep_their_frozen_spellings() {
    let existing = [
        "INVALID_REQUEST",
        "CAPABILITY_DENIED",
        "WORKSPACE_DENIED",
        "PATH_ESCAPE",
        "PATH_RACE_DETECTED",
        "APPROVAL_REQUIRED",
        "APPROVAL_DENIED",
        "APPROVAL_UNAVAILABLE",
        "TARGET_STALE",
        "PROVIDER_UNAVAILABLE",
        "PROCESS_TIMEOUT",
        "PROCESS_TERMINATION_UNVERIFIED",
        "OUTPUT_LIMIT",
        "POSTCONDITION_FAILED",
        "INTERNAL_ERROR",
        "REMOTE_SESSION_INACTIVE",
    ];
    let actual: Vec<String> = FailureCode::ALL[..existing.len()]
        .iter()
        .map(spelling)
        .collect();
    assert_eq!(actual, existing);
}

#[test]
fn lease_required_has_the_frozen_wire_spelling() {
    assert_eq!(spelling(&FailureCode::LeaseRequired), "LEASE_REQUIRED");
}

#[test]
fn lease_invalid_has_the_frozen_wire_spelling() {
    assert_eq!(spelling(&FailureCode::LeaseInvalid), "LEASE_INVALID");
}

#[test]
fn lease_unsupported_platform_has_the_frozen_wire_spelling() {
    assert_eq!(
        spelling(&FailureCode::LeaseUnsupportedPlatform),
        "LEASE_UNSUPPORTED_PLATFORM"
    );
}

#[test]
fn indicator_unavailable_has_the_frozen_wire_spelling() {
    assert_eq!(
        spelling(&FailureCode::IndicatorUnavailable),
        "INDICATOR_UNAVAILABLE"
    );
}

#[test]
fn unsupported_has_the_frozen_wire_spelling() {
    assert_eq!(spelling(&FailureCode::Unsupported), "UNSUPPORTED");
}

#[test]
fn policy_blocked_has_the_frozen_wire_spelling() {
    assert_eq!(spelling(&FailureCode::PolicyBlocked), "POLICY_BLOCKED");
}

#[test]
fn job_not_found_has_the_frozen_wire_spelling() {
    assert_eq!(spelling(&FailureCode::JobNotFound), "JOB_NOT_FOUND");
}

#[test]
fn queue_full_has_the_frozen_wire_spelling() {
    assert_eq!(spelling(&FailureCode::QueueFull), "QUEUE_FULL");
}

#[test]
fn rate_limited_has_the_frozen_wire_spelling() {
    assert_eq!(spelling(&FailureCode::RateLimited), "RATE_LIMITED");
}

#[test]
fn outcome_unknown_has_the_frozen_wire_spelling() {
    assert_eq!(spelling(&FailureCode::OutcomeUnknown), "OUTCOME_UNKNOWN");
}

#[test]
fn authority_unavailable_has_the_frozen_wire_spelling() {
    assert_eq!(
        spelling(&FailureCode::AuthorityUnavailable),
        "AUTHORITY_UNAVAILABLE"
    );
}

#[test]
fn human_verification_required_has_the_frozen_wire_spelling() {
    assert_eq!(
        spelling(&FailureCode::HumanVerificationRequired),
        "HUMAN_VERIFICATION_REQUIRED"
    );
}

#[test]
fn permission_required_has_the_frozen_wire_spelling() {
    assert_eq!(
        spelling(&FailureCode::PermissionRequired),
        "PERMISSION_REQUIRED"
    );
}

// ------------------------------------------------------------ HTTP mapping

/// Compile-time completeness: adding a variant without listing it here
/// fails to build, and `ALL` must then be extended to match.
fn declared_index(code: &FailureCode) -> usize {
    match code {
        FailureCode::InvalidRequest => 0,
        FailureCode::CapabilityDenied => 1,
        FailureCode::WorkspaceDenied => 2,
        FailureCode::PathEscape => 3,
        FailureCode::PathRaceDetected => 4,
        FailureCode::ApprovalRequired => 5,
        FailureCode::ApprovalDenied => 6,
        FailureCode::ApprovalUnavailable => 7,
        FailureCode::TargetStale => 8,
        FailureCode::ProviderUnavailable => 9,
        FailureCode::ProcessTimeout => 10,
        FailureCode::ProcessTerminationUnverified => 11,
        FailureCode::OutputLimit => 12,
        FailureCode::PostconditionFailed => 13,
        FailureCode::InternalError => 14,
        FailureCode::RemoteSessionInactive => 15,
        FailureCode::LeaseRequired => 16,
        FailureCode::LeaseInvalid => 17,
        FailureCode::LeaseUnsupportedPlatform => 18,
        FailureCode::IndicatorUnavailable => 19,
        FailureCode::Unsupported => 20,
        FailureCode::PolicyBlocked => 21,
        FailureCode::JobNotFound => 22,
        FailureCode::QueueFull => 23,
        FailureCode::RateLimited => 24,
        FailureCode::OutcomeUnknown => 25,
        FailureCode::AuthorityUnavailable => 26,
        FailureCode::PermissionRequired => 27,
        FailureCode::HumanVerificationRequired => 28,
    }
}

#[test]
fn failure_code_all_lists_every_variant_once_in_order() {
    for (index, code) in FailureCode::ALL.iter().enumerate() {
        assert_eq!(declared_index(code), index, "{code:?}");
    }
    let unique: BTreeSet<String> = FailureCode::ALL.iter().map(spelling).collect();
    assert_eq!(unique.len(), FailureCode::ALL.len());
}

#[test]
fn every_failure_code_maps_to_the_spec_http_status() {
    let table: &[(&str, u16)] = &[
        ("INVALID_REQUEST", 400),
        ("CAPABILITY_DENIED", 403),
        ("WORKSPACE_DENIED", 403),
        ("PATH_ESCAPE", 403),
        ("PATH_RACE_DETECTED", 409),
        ("APPROVAL_REQUIRED", 403),
        ("APPROVAL_DENIED", 403),
        ("APPROVAL_UNAVAILABLE", 503),
        ("TARGET_STALE", 409),
        ("PROVIDER_UNAVAILABLE", 503),
        ("PROCESS_TIMEOUT", 408),
        ("PROCESS_TERMINATION_UNVERIFIED", 500),
        ("OUTPUT_LIMIT", 413),
        ("POSTCONDITION_FAILED", 500),
        ("INTERNAL_ERROR", 500),
        ("REMOTE_SESSION_INACTIVE", 403),
        ("LEASE_REQUIRED", 403),
        ("LEASE_INVALID", 403),
        ("LEASE_UNSUPPORTED_PLATFORM", 501),
        ("INDICATOR_UNAVAILABLE", 503),
        ("UNSUPPORTED", 501),
        ("POLICY_BLOCKED", 403),
        ("JOB_NOT_FOUND", 404),
        ("QUEUE_FULL", 429),
        ("RATE_LIMITED", 429),
        ("OUTCOME_UNKNOWN", 500),
        ("AUTHORITY_UNAVAILABLE", 503),
        ("PERMISSION_REQUIRED", 403),
        ("HUMAN_VERIFICATION_REQUIRED", 409),
    ];
    assert_eq!(
        table.len(),
        FailureCode::ALL.len(),
        "table covers every variant"
    );
    for code in FailureCode::ALL {
        let name = spelling(&code);
        let expected = table
            .iter()
            .find(|(spelled, _)| *spelled == name)
            .unwrap_or_else(|| panic!("{name} has no spec mapping"))
            .1;
        assert_eq!(code.http_status(), expected, "{name}");
    }
}

// --------------------------------------------------------- state machine

#[test]
fn job_state_machine_allows_exactly_the_spec_transitions() {
    use ExecutionState::*;
    let allowed = [
        (NotStarted, Cancelled),
        (NotStarted, Dispatched),
        (Dispatched, Completed),
        (Dispatched, Cancelled),
        (Dispatched, OutcomeUnknown),
    ];
    for from in ExecutionState::ALL {
        for to in ExecutionState::ALL {
            assert_eq!(
                from.job_may_transition_to(to),
                allowed.contains(&(from, to)),
                "{from:?} -> {to:?}"
            );
        }
    }
    assert_eq!(ExecutionState::INITIAL, NotStarted);
}

#[test]
fn terminal_states_have_no_exit_and_outcome_unknown_is_never_retried() {
    for state in ExecutionState::ALL {
        let has_exit = ExecutionState::ALL
            .iter()
            .any(|to| state.job_may_transition_to(*to));
        assert_eq!(state.is_terminal(), !has_exit, "{state:?}");
    }
    assert!(!ExecutionState::OutcomeUnknown.job_may_transition_to(ExecutionState::Dispatched));
    assert!(!ExecutionState::OutcomeUnknown.job_may_transition_to(ExecutionState::NotStarted));
}

#[test]
fn restart_cancels_pending_jobs_and_marks_running_jobs_unknown() {
    use ExecutionState::*;
    assert_eq!(NotStarted.after_restart(), Cancelled);
    assert_eq!(Dispatched.after_restart(), OutcomeUnknown);
    for state in ExecutionState::ALL {
        let after = state.after_restart();
        assert!(after.is_terminal(), "{state:?} resumes after restart");
        assert!(after == state || state.job_may_transition_to(after));
    }
}

#[test]
fn job_outcome_is_present_exactly_when_completed() {
    let mut job: Job = parse("job");
    assert!(job.outcome_matches_state());
    job.state = ExecutionState::Dispatched;
    assert!(!job.outcome_matches_state());
    job.outcome = None;
    assert!(job.outcome_matches_state());
    let text = serde_json::to_string(&job).unwrap();
    assert!(!text.contains("\"outcome\""), "{text}");
}

// ----------------------------------------------------- authority shapes

#[test]
fn full_control_dispatch_needs_a_lease_and_an_authorization_id() {
    let base: DispatchAuthority = parse("dispatch_authority");
    for mode in [
        AuthorityMode::FullUser,
        AuthorityMode::FullAdmin,
        AuthorityMode::PersistentAdmin,
        AuthorityMode::RemoteFullControl,
    ] {
        let mut no_lease = base.clone();
        no_lease.mode = mode;
        no_lease.lease = None;
        assert_eq!(
            no_lease.check(),
            Err(AuthorityShapeError::LeaseMissing),
            "{mode:?}"
        );
        let mut no_authz = base.clone();
        no_authz.mode = mode;
        no_authz.authorization_id = None;
        assert_eq!(
            no_authz.check(),
            Err(AuthorityShapeError::AuthorizationMissing),
            "{mode:?}"
        );
    }
}

#[test]
fn safe_dispatch_carries_no_full_control_fields() {
    let base: DispatchAuthority = parse("dispatch_authority");
    let safe = DispatchAuthority {
        mode: AuthorityMode::Safe,
        lease: None,
        grant: Some(parse("grant_ref")),
        standing: None,
        authorization_id: None,
    };
    assert_eq!(safe.check(), Ok(()));
    let lease: LeaseRef = base.lease.clone().unwrap();
    for tampered in [
        DispatchAuthority {
            lease: Some(lease),
            ..safe.clone()
        },
        DispatchAuthority {
            standing: Some("sa-01".to_owned()),
            ..safe.clone()
        },
        DispatchAuthority {
            authorization_id: Some("authz".to_owned()),
            ..safe.clone()
        },
    ] {
        assert_eq!(
            tampered.check(),
            Err(AuthorityShapeError::FullControlFieldInSafeMode)
        );
    }
}

#[test]
fn standing_approvals_are_strong_and_never_cover_admin_or_remote() {
    let base: StandingApproval = parse("standing_approval");
    for class in [ApprovalClass::None, ApprovalClass::Soft] {
        let weak = StandingApproval {
            granted_with: class,
            ..base.clone()
        };
        assert_eq!(weak.check(), Err(AuthorityShapeError::StandingNotStrong));
    }
    for executor in [ExecutorClass::Admin, ExecutorClass::Remote] {
        let mut wide = base.clone();
        wide.executors.push(executor);
        assert_eq!(
            wide.check(),
            Err(AuthorityShapeError::StandingExecutorRefused)
        );
    }
    let empty = StandingApproval {
        executors: Vec::new(),
        ..base.clone()
    };
    assert_eq!(
        empty.check(),
        Err(AuthorityShapeError::StandingScopeInvalid)
    );
    let long_task = StandingApproval {
        task: "x".repeat(513),
        ..base.clone()
    };
    assert!(long_task.check().is_err());
}

#[test]
fn job_budget_tolerates_additive_fields_unlike_the_inbound_budget() {
    let mut job = fixture("job");
    job["budget"]["max_concurrent_fetches"] = json!(4);
    let parsed: Job = serde_json::from_value(job.clone()).expect("older reader accepts");
    assert_eq!(parsed.budget, JobBudget::from(CrawlBudget::DEFAULT));
    assert!(serde_json::from_value::<CrawlBudget>(job["budget"].clone()).is_err());
}

#[test]
fn empty_standing_scope_lists_cover_nothing() {
    let base: StandingApproval = parse("standing_approval");
    assert!(base.covers_command("git"));
    assert!(!base.covers_command("cmd"));
    assert!(base.covers_root("C:\\Users\\me\\src\\repo"));
    assert!(!base.covers_origin("https://example.com"));
    let none = StandingApproval {
        commands: None,
        ..base.clone()
    };
    assert_eq!(none.check(), Ok(()));
    assert!(!none.covers_command("git"));
    let empty = StandingApproval {
        commands: Some(Vec::new()),
        roots: Vec::new(),
        ..base
    };
    assert!(!empty.covers_command("git"));
    assert!(!empty.covers_root("C:\\"));
}

#[test]
fn standing_filesystem_needs_roots_and_origins_and_task_are_validated() {
    let base: StandingApproval = parse("standing_approval");
    let mut no_roots = base.clone();
    no_roots.executors.push(ExecutorClass::Filesystem);
    no_roots.roots.clear();
    assert_eq!(
        no_roots.check(),
        Err(AuthorityShapeError::StandingScopeInvalid)
    );
    let mut with_roots = base.clone();
    with_roots.executors.push(ExecutorClass::Filesystem);
    assert_eq!(with_roots.check(), Ok(()));
    for bad in [
        "http://example.com",
        "https://example.com/",
        "https://Example.com",
        "x",
    ] {
        let origin = StandingApproval {
            origins: vec![bad.to_owned()],
            ..base.clone()
        };
        assert!(origin.check().is_err(), "{bad}");
    }
    let good_origin = StandingApproval {
        origins: vec!["https://docs.example.com".to_owned()],
        ..base.clone()
    };
    assert_eq!(good_origin.check(), Ok(()));
    for bad in ["", "line\nbreak"] {
        let task = StandingApproval {
            task: bad.to_owned(),
            ..base.clone()
        };
        assert!(task.check().is_err(), "{bad:?}");
    }
    let control_root = StandingApproval {
        roots: vec!["C:\\a\u{0}".to_owned()],
        ..base
    };
    assert!(control_root.check().is_err());
}

#[test]
fn standing_approval_is_bound_to_its_lease_and_its_expiry() {
    let base: StandingApproval = parse("standing_approval");
    let lease: LeaseView = parse("lease_view");
    let other = StandingApproval {
        lease_id: "b".repeat(64),
        ..base.clone()
    };
    assert!(other.check_against_lease(&lease).is_err());
    let outlives = StandingApproval {
        expires_at_ms: lease.expires_at_ms + 1,
        ..base
    };
    assert!(outlives.check_against_lease(&lease).is_err());
}

#[test]
fn anchor_insertion_refuses_separator_and_control_characters() {
    let anchor: AnchorRef = parse("anchor_ref");
    for bad in ["a|b", "", "a\nb"] {
        let tampered = AnchorRef {
            file_id: bad.to_owned(),
            ..anchor.clone()
        };
        assert!(tampered.event_log_insertion().is_none(), "{bad:?}");
    }
}

// ------------------------------------------------------------- web shapes

#[test]
fn crawl_requests_are_checked_against_the_user_budget() {
    let none: &[String] = &[];
    let base: WebCrawlRequest = parse("web_crawl_request");
    let budget = CrawlBudget::DEFAULT;
    let cases: Vec<(WebCrawlRequest, WebContractError)> = vec![
        (
            WebCrawlRequest {
                max_pages: 51,
                ..base.clone()
            },
            WebContractError::OverBudget("max_pages"),
        ),
        (
            WebCrawlRequest {
                max_depth: 6,
                ..base.clone()
            },
            WebContractError::OverBudget("max_depth"),
        ),
        (
            WebCrawlRequest {
                deadline_s: 601,
                ..base.clone()
            },
            WebContractError::OverBudget("deadline_s"),
        ),
        (
            WebCrawlRequest {
                delay_ms: 249,
                ..base.clone()
            },
            WebContractError::OverBudget("delay_ms"),
        ),
        (
            WebCrawlRequest {
                include_paths: vec!["^/a".to_owned(); 17],
                ..base.clone()
            },
            WebContractError::OverBudget("include_paths"),
        ),
        (
            WebCrawlRequest {
                task: String::new(),
                ..base.clone()
            },
            WebContractError::InvalidField("task"),
        ),
        (
            WebCrawlRequest {
                start_url: "https://evil.example.com/".to_owned(),
                ..base.clone()
            },
            WebContractError::OutOfScope("start_url"),
        ),
    ];
    for (request, expected) in cases {
        assert_eq!(request.check(&budget, none), Err(expected));
    }

    // A user-raised budget admits what the default refuses.
    let raised = CrawlBudget {
        max_pages: 500,
        ..CrawlBudget::DEFAULT
    };
    assert_eq!(raised.check(), Ok(()));
    let big = WebCrawlRequest {
        max_pages: 500,
        ..base.clone()
    };
    assert_eq!(big.check(&raised, none), Ok(()));
    assert!(big.check(&budget, none).is_err());

    // The delay floor holds even when the user configures less.
    let low = CrawlBudget {
        min_delay_ms: 50,
        ..CrawlBudget::DEFAULT
    };
    assert!(low.check().is_err());
    let fast = WebCrawlRequest {
        delay_ms: 99,
        ..base
    };
    assert!(fast.check(&low, none).is_err());
}

#[test]
fn budget_ceilings_are_enforced() {
    let over_store = CrawlBudget {
        max_job_result_bytes: CrawlBudget::MAX_JOB_RESULT_BYTES_CEILING + 1,
        ..CrawlBudget::DEFAULT
    };
    assert!(over_store.check().is_err());
    let zero = CrawlBudget {
        max_pages: 0,
        ..CrawlBudget::DEFAULT
    };
    assert!(zero.check().is_err());
}

#[test]
fn batch_requests_bound_url_count_and_scope() {
    let none: &[String] = &[];
    let mut batch: WebBatchScrapeRequest = parse("web_batch_scrape_request");
    batch.urls = vec!["https://example.com/".to_owned(); 51];
    assert_eq!(
        batch.check(&CrawlBudget::DEFAULT, none),
        Err(WebContractError::OverBudget("urls"))
    );
    batch.urls = vec!["https://example.com.evil.test/".to_owned()];
    assert_eq!(
        batch.check(&CrawlBudget::DEFAULT, none),
        Err(WebContractError::OutOfScope("urls"))
    );
    batch.urls.clear();
    assert!(batch.check(&CrawlBudget::DEFAULT, none).is_err());
}

#[test]
fn scope_origins_are_canonical_https_origins() {
    for bad in [
        "http://example.com",
        "https://example.com/",
        "https://Example.com",
        "https://example.com:443",
        "https://user@example.com",
        "https://",
    ] {
        let scope = WebScope {
            origins: vec![bad.to_owned()],
        };
        assert!(scope.check().is_err(), "{bad}");
    }
    let scope = WebScope {
        origins: vec!["https://example.com:8443".to_owned()],
    };
    assert_eq!(scope.check(), Ok(()));
    assert!(scope.contains_url("https://example.com:8443/x"));
    assert!(!scope.contains_url("https://example.com:84430/x"));
    assert!(WebScope { origins: vec![] }.check().is_err());
}

fn header(name: &str, value: HeaderValue) -> HeaderSpec {
    HeaderSpec {
        name: name.to_owned(),
        value,
    }
}

fn literal(value: &str) -> HeaderValue {
    HeaderValue::Literal(value.to_owned())
}

fn secret(name: &str) -> HeaderValue {
    HeaderValue::Secret(name.to_owned())
}

#[test]
fn credential_like_headers_must_name_a_secret() {
    let none: &[String] = &[];
    for name in [
        "Authorization",
        "COOKIE",
        "proxy-authorization",
        "X-Api-Key",
    ] {
        assert_eq!(
            header(name, literal("value")).check(none),
            Err(WebContractError::ProtectedHeaderLiteral),
            "{name}"
        );
        assert_eq!(
            header(name, secret("docs-token")).check(none),
            Ok(()),
            "{name}"
        );
    }
    assert_eq!(header("Accept-Language", literal("en")).check(none), Ok(()));
}

#[test]
fn protected_header_names_are_configurable() {
    let configured = vec!["X-Session-Token".to_owned()];
    assert_eq!(
        header("x-session-token", literal("v")).check(&configured),
        Err(WebContractError::ProtectedHeaderLiteral)
    );
    assert_eq!(header("x-session-token", literal("v")).check(&[]), Ok(()));
}

#[test]
fn literal_values_allow_only_visible_ascii_space_and_tab() {
    let none: &[String] = &[];
    assert_eq!(header("X-Note", literal("a b\tc~")).check(none), Ok(()));
    for bad in [
        "a\r\nInjected: 1",
        "a\u{0}",
        "a\u{7f}",
        "caf\u{e9}",
        "a\u{b}",
    ] {
        assert_eq!(
            header("X-Note", literal(bad)).check(none),
            Err(WebContractError::InvalidField("headers.value")),
            "{bad:?}"
        );
    }
}

#[test]
fn transport_owned_and_malformed_headers_are_refused() {
    let none: &[String] = &[];
    for name in [
        "Host",
        "content-length",
        "Transfer-Encoding",
        "Connection",
        "TE",
        "Upgrade",
        "Expect",
    ] {
        assert_eq!(
            header(name, literal("x")).check(none),
            Err(WebContractError::ForbiddenHeader),
            "{name}"
        );
    }
    assert!(header("Bad Name", literal("x")).check(none).is_err());
    assert!(header("", literal("x")).check(none).is_err());
    assert!(header("Authorization", secret("")).check(none).is_err());
    assert!(header("Authorization", secret("a b")).check(none).is_err());
}

#[test]
fn firecrawl_secret_references_map_to_secret_values() {
    assert_eq!(
        HeaderValue::from_firecrawl("secret:docs-token"),
        secret("docs-token")
    );
    assert_eq!(
        HeaderValue::from_firecrawl("Bearer abc"),
        literal("Bearer abc")
    );
    assert_eq!(
        serde_json::to_value(secret("docs-token")).unwrap(),
        json!({"secret": "docs-token"})
    );
}

#[test]
fn duplicate_and_excess_headers_are_refused() {
    let none: &[String] = &[];
    let mut scrape: WebScrapeRequest = parse("web_scrape_request");
    scrape.headers = vec![header("X-A", literal("1")), header("x-a", literal("2"))];
    assert!(scrape.check(none).is_err());
    scrape.headers = (0..33)
        .map(|i| header(&format!("X-H{i}"), literal("1")))
        .collect();
    assert_eq!(
        scrape.check(none),
        Err(WebContractError::OverBudget("headers"))
    );
}

#[test]
fn privacy_and_headers_default_when_absent() {
    let mut value = fixture("web_scrape_request");
    value.as_object_mut().unwrap().remove("privacy");
    value.as_object_mut().unwrap().remove("headers");
    let parsed: WebScrapeRequest = serde_json::from_value(value).unwrap();
    assert_eq!(parsed.privacy, PrivacyProfileRef::default());
    assert!(parsed.privacy.required_permissions().is_empty());
    assert!(parsed.headers.is_empty());
}

// ---------------------------------------------------------------- sidecar

#[test]
fn sidecar_limits_respect_protocol_ceilings() {
    let ok = SidecarLimits {
        max_data_frame_bytes: MAX_DATA_FRAME_BYTES as u32,
        heartbeat_interval_ms: 2_000,
        cancel_grace_ms: 2_000,
    };
    assert!(ok.within_ceilings());
    assert!(!SidecarLimits {
        max_data_frame_bytes: MAX_DATA_FRAME_BYTES as u32 + 1,
        ..ok
    }
    .within_ceilings());
    assert!(!SidecarLimits {
        heartbeat_interval_ms: 0,
        ..ok
    }
    .within_ceilings());
    assert_eq!(MAX_CONTROL_FRAME_BYTES, 64 * 1024);
}

#[test]
fn indicator_heartbeat_goes_stale_after_five_seconds() {
    assert_eq!(
        orcel_contracts::indicator::INDICATOR_HEARTBEAT_STALE_MS,
        5_000
    );
}

#[test]
fn only_a_local_user_may_issue_a_lease() {
    for kind in [
        PrincipalKind::McpClient,
        PrincipalKind::RestClient,
        PrincipalKind::RemotePrincipal,
        PrincipalKind::AgentRuntime,
        PrincipalKind::Sidecar,
    ] {
        assert!(!kind.may_issue_lease(), "{kind:?}");
    }
    assert!(PrincipalKind::LocalUser.may_issue_lease());
}

#[test]
fn capability_status_is_flattened_into_the_entry() {
    let report = fixture("capability_report");
    assert_eq!(report["entries"][4]["status"], "permission_required");
    let status: CapabilityStatus =
        serde_json::from_value(json!({"status": "blocked", "policy": "cloud-only"})).unwrap();
    assert_eq!(status.failure_code(), Some(FailureCode::PolicyBlocked));
}

// ---------------------------------------------------------- canonical JSON

#[test]
fn canonical_json_sorts_keys_by_utf16_code_units() {
    // U+1F600 encodes as D83D DE00, which sorts before U+E000 in UTF-16
    // (RFC 8785) although its code point is larger.
    let value =
        json!({"\u{e000}": 1, "\u{1f600}": 2, "b": [1, {"z": true, "a": null}], "a": "x", "B": -5});
    assert_eq!(
        canonical_json_value(&value).unwrap(),
        "{\"B\":-5,\"a\":\"x\",\"b\":[1,{\"a\":null,\"z\":true}],\"\u{1f600}\":2,\"\u{e000}\":1}"
    );
}

#[test]
fn canonical_json_uses_minimal_string_escapes() {
    let value = json!("q\"b\\n\nt\tc\u{1}u\u{7f}/\u{e9}\u{1f600}");
    assert_eq!(
        canonical_json_value(&value).unwrap(),
        "\"q\\\"b\\\\n\\nt\\tc\\u0001u\u{7f}/\u{e9}\u{1f600}\""
    );
    assert_eq!(
        canonical_json_value(&json!("\u{8}\u{c}\r")).unwrap(),
        "\"\\b\\f\\r\""
    );
}

#[test]
fn canonical_json_refuses_floats_and_integers_beyond_2_pow_53() {
    let max = (1u64 << 53) - 1;
    assert_eq!(
        canonical_json_value(&json!({"x": 1.5})),
        Err(CanonicalJsonError::NonIntegerNumber)
    );
    assert_eq!(
        canonical_json_value(&json!(max + 1)),
        Err(CanonicalJsonError::IntegerOutOfRange)
    );
    assert_eq!(
        canonical_json_value(&json!(-(max as i64) - 1)),
        Err(CanonicalJsonError::IntegerOutOfRange)
    );
    assert_eq!(
        canonical_json_value(&json!([max, -(max as i64), 0])).unwrap(),
        format!("[{max},-{max},0]")
    );
}

#[test]
fn canonical_json_is_independent_of_input_key_order() {
    let a: Value = serde_json::from_str(r#"{"x":1,"y":{"q":2,"p":3}}"#).unwrap();
    let b: Value = serde_json::from_str(r#"{"y":{"p":3,"q":2},"x":1}"#).unwrap();
    assert_eq!(canonical_json_value(&a), canonical_json_value(&b));
    let crawl: WebCrawlRequest = parse("web_crawl_request");
    let text = canonical_json(&crawl).unwrap();
    assert_eq!(
        canonical_json_value(&serde_json::from_str(&text).unwrap()).unwrap(),
        text
    );
}

#[test]
fn audit_digest_input_excludes_the_digest_field() {
    let event: AuditEvent = parse("audit_event");
    let input = event.digest_input().unwrap();
    assert!(!input.contains("\"digest\""), "{input}");
    assert!(input.contains("\"prev_digest\""), "{input}");
    assert!(input.contains("\"asserted_by_session\":true"), "{input}");
    let mut changed = event.clone();
    changed.digest = "f".repeat(64);
    assert_eq!(changed.digest_input().unwrap(), input);
    changed.caller_pid = Some(1);
    assert_ne!(changed.digest_input().unwrap(), input);
}
