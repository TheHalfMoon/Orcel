//! Contracts v1 (WP1-02): golden fixture round trips, unknown-field
//! refusal on inbound authority-bearing types, frozen spellings, the job
//! state machine, the FailureCode to HTTP mapping and canonical JSON.

use orcel_contracts::capability::{CapabilityReport, CapabilityStatus};
use orcel_contracts::event::{AuditEvent, AuditEventKind, GENESIS_PREV_DIGEST};
use orcel_contracts::identity::{Device, OsFamily, OsIdentityBinding, Principal, PrincipalKind};
use orcel_contracts::indicator::{IndicatorToOrceld, OrceldToIndicator, RevokeRequest, Visibility};
use orcel_contracts::job::{Job, JobKind, JobOutcome};
use orcel_contracts::lease::{
    ApprovalClass, DispatchAuthority, GrantRef, LeaseView, StandingApproval,
};
use orcel_contracts::session::Session;
use orcel_contracts::sidecar::{
    HostToSidecar, SidecarLimits, SidecarToHost, MAX_CONTROL_FRAME_BYTES, MAX_DATA_FRAME_BYTES,
};
use orcel_contracts::tool::{RemoteExposure, ToolEntry};
use orcel_contracts::web::{
    CrawlBudget, HeaderValue, RequestHeader, StealthMode, WebBatchScrapeRequest, WebContractError,
    WebCrawlRequest, WebScrapeRequest,
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
    let golden = fixture(name);
    let items = match golden {
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
    "audit_event",
    "capability_report",
    "crawl_budget",
    "device",
    "dispatch_authority",
    "grant_ref",
    "host_to_sidecar",
    "indicator_to_orceld",
    "job",
    "lease_view",
    "orceld_to_indicator",
    "os_identity_binding",
    "principal",
    "revoke_request",
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
    let authority: DispatchAuthority = round_trip("dispatch_authority");
    assert!(authority.lease.is_some() && authority.grant.is_some());
    assert!(authority.standing_approval.is_some());
    let standing: StandingApproval = round_trip_contract("standing_approval");
    assert_eq!(standing.granted_with, ApprovalClass::Strong);
    assert_eq!(standing.scope.executors, [ExecutorClass::Web]);
    assert!(standing.lease.is_some());
}

#[test]
fn dispatch_authority_omits_an_absent_standing_approval() {
    let mut value = fixture("dispatch_authority");
    value.as_object_mut().unwrap().remove("standing_approval");
    let parsed: DispatchAuthority = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(&parsed).unwrap(), value);
}

#[test]
fn session_tool_and_capability_fixtures_round_trip() {
    let session: Session = round_trip_contract("session");
    assert!(session.remote.is_none());
    let tools: Vec<ToolEntry> = round_trip("tool_entry");
    assert_eq!(tools[0].remote, RemoteExposure::LocalOnly);
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
            Some(FailureCode::Unsupported),
        ]
    );
}

#[test]
fn remote_exposure_refuses_other_strings() {
    assert!(serde_json::from_value::<RemoteExposure>(json!("everywhere")).is_err());
    assert!(serde_json::from_value::<RemoteExposure>(json!(7)).is_err());
}

#[test]
fn job_and_audit_fixtures_round_trip() {
    let job: Job = round_trip_contract("job");
    assert_eq!(job.kind, JobKind::WebCrawl);
    assert_eq!(
        job.outcome,
        Some(JobOutcome::Failed {
            code: FailureCode::TargetStale
        })
    );
    assert!(job.outcome_matches_state());
    let event: AuditEvent = round_trip_contract("audit_event");
    assert_eq!(event.kind, AuditEventKind::Dispatch);
    assert_eq!(event.prev_digest, GENESIS_PREV_DIGEST);
}

#[test]
fn ipc_fixtures_round_trip() {
    let host: Vec<HostToSidecar> = round_trip("host_to_sidecar");
    assert_eq!(host.len(), 5);
    let sidecar: Vec<SidecarToHost> = round_trip("sidecar_to_host");
    assert_eq!(sidecar.len(), 6);
    let to_indicator: Vec<OrceldToIndicator> = round_trip("orceld_to_indicator");
    assert_eq!(to_indicator.len(), 5);
    let from_indicator: Vec<IndicatorToOrceld> = round_trip("indicator_to_orceld");
    assert_eq!(from_indicator.len(), 5);
    let _: RevokeRequest = round_trip_contract("revoke_request");
}

#[test]
fn web_fixtures_round_trip() {
    let crawl: WebCrawlRequest = round_trip_contract("web_crawl_request");
    assert_eq!(crawl.stealth, StealthMode::OptIn);
    assert_eq!(CrawlBudget::WAVE1.admits(&crawl), Ok(()));
    let scrape: WebScrapeRequest = round_trip_contract("web_scrape_request");
    assert_eq!(scrape.stealth, StealthMode::Off);
    assert_eq!(scrape.check(), Ok(()));
    let batch: WebBatchScrapeRequest = round_trip_contract("web_batch_scrape_request");
    assert_eq!(CrawlBudget::WAVE1.admits_batch(&batch), Ok(()));
    let budget: CrawlBudget = round_trip("crawl_budget");
    assert_eq!(budget, CrawlBudget::WAVE1);
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
    refuses_unknown::<HostToSidecar>("host_to_sidecar");
    refuses_unknown::<SidecarToHost>("sidecar_to_host");
    refuses_unknown::<OrceldToIndicator>("orceld_to_indicator");
    refuses_unknown::<IndicatorToOrceld>("indicator_to_orceld");
    refuses_unknown::<RevokeRequest>("revoke_request");
    refuses_unknown::<WebCrawlRequest>("web_crawl_request");
    refuses_unknown::<WebScrapeRequest>("web_scrape_request");
    refuses_unknown::<WebBatchScrapeRequest>("web_batch_scrape_request");
    refuses_unknown::<CrawlBudget>("crawl_budget");
}

#[test]
fn nested_authority_objects_refuse_unknown_fields() {
    let mut value = fixture("dispatch_authority");
    value["lease"]["trusted"] = json!(true);
    assert!(serde_json::from_value::<DispatchAuthority>(value).is_err());
    let mut value = fixture("standing_approval");
    value["scope"]["everything"] = json!(true);
    assert!(serde_json::from_value::<StandingApproval>(value).is_err());
    let mut value = fixture("web_crawl_request");
    value["headers"][1]["value"]["secret"] = json!("x");
    assert!(serde_json::from_value::<WebCrawlRequest>(value).is_err());
    let mut value = fixture("host_to_sidecar");
    value[0]["limits"]["unbounded"] = json!(true);
    assert!(serde_json::from_value::<Vec<HostToSidecar>>(value).is_err());
}

#[test]
fn unknown_frames_and_variants_are_refused() {
    assert!(serde_json::from_value::<HostToSidecar>(json!({"frame": "grant"})).is_err());
    assert!(serde_json::from_value::<SidecarToHost>(json!({"frame": "elevate"})).is_err());
    assert!(serde_json::from_value::<IndicatorToOrceld>(json!({"frame": "grant"})).is_err());
    assert!(serde_json::from_value::<OrceldToIndicator>(json!({"frame": "exec"})).is_err());
    let freebsd = json!({"os": "freebsd", "uid": 1});
    assert!(serde_json::from_value::<OsIdentityBinding>(freebsd).is_err());
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
        assert!(
            (400..600).contains(&code.http_status()),
            "{name} is an error status"
        );
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
    let mut job: Job = serde_json::from_value(fixture("job")).unwrap();
    assert!(job.outcome_matches_state());
    job.state = ExecutionState::Dispatched;
    assert!(!job.outcome_matches_state());
    job.outcome = None;
    assert!(job.outcome_matches_state());
    job.state = ExecutionState::OutcomeUnknown;
    assert!(job.outcome_matches_state());
    let text = serde_json::to_string(&job).unwrap();
    assert!(!text.contains("\"outcome\""), "{text}");
}

// ------------------------------------------------------------- web shapes

#[test]
fn crawl_budget_bounds_requests() {
    let base: WebCrawlRequest = serde_json::from_value(fixture("web_crawl_request")).unwrap();
    let budget = CrawlBudget::WAVE1;
    let mut over = base.clone();
    over.max_pages = 51;
    assert_eq!(
        budget.admits(&over),
        Err(WebContractError::OverBudget("max_pages"))
    );
    let mut over = base.clone();
    over.max_depth = 6;
    assert_eq!(
        budget.admits(&over),
        Err(WebContractError::OverBudget("max_depth"))
    );
    let mut over = base.clone();
    over.deadline_s = 601;
    assert_eq!(
        budget.admits(&over),
        Err(WebContractError::OverBudget("deadline_s"))
    );
    let mut over = base.clone();
    over.delay_ms = 249;
    assert_eq!(
        budget.admits(&over),
        Err(WebContractError::OverBudget("delay_ms"))
    );
    let mut over = base.clone();
    over.include_paths = vec!["^/a".to_owned(); 17];
    assert_eq!(
        budget.admits(&over),
        Err(WebContractError::OverBudget("include_paths"))
    );
    let mut over = base.clone();
    over.robots = false;
    assert_eq!(budget.admits(&over), Err(WebContractError::RobotsRequired));

    // A configured (decided) larger budget admits what WAVE1 refuses.
    let raised = CrawlBudget {
        max_pages: 500,
        ..CrawlBudget::WAVE1
    };
    let mut big = base;
    big.max_pages = 500;
    assert_eq!(raised.admits(&big), Ok(()));
    assert!(budget.admits(&big).is_err());
}

#[test]
fn batch_budget_bounds_url_count() {
    let mut batch: WebBatchScrapeRequest =
        serde_json::from_value(fixture("web_batch_scrape_request")).unwrap();
    batch.urls = vec!["https://example.com/".to_owned(); 51];
    assert_eq!(
        CrawlBudget::WAVE1.admits_batch(&batch),
        Err(WebContractError::OverBudget("urls"))
    );
    batch.urls.clear();
    assert!(CrawlBudget::WAVE1.admits_batch(&batch).is_err());
}

fn header(name: &str, value: HeaderValue) -> RequestHeader {
    RequestHeader {
        name: name.to_owned(),
        value,
    }
}

fn literal(value: &str) -> HeaderValue {
    HeaderValue::Literal {
        value: value.to_owned(),
    }
}

fn credential(id: &str) -> HeaderValue {
    HeaderValue::Credential {
        credential_ref: id.to_owned(),
    }
}

#[test]
fn credential_bearing_headers_must_reference_a_protected_credential() {
    for name in [
        "Authorization",
        "COOKIE",
        "proxy-authorization",
        "X-Api-Key",
    ] {
        assert_eq!(
            header(name, literal("secret")).check(),
            Err(WebContractError::ProtectedHeaderLiteral),
            "{name}"
        );
        assert_eq!(header(name, credential("cred-1")).check(), Ok(()), "{name}");
    }
    assert_eq!(header("Accept-Language", literal("en")).check(), Ok(()));
}

#[test]
fn transport_owned_and_malformed_headers_are_refused() {
    for name in [
        "Host",
        "content-length",
        "Transfer-Encoding",
        "Proxy-Connection",
        "proxy-foo",
    ] {
        assert_eq!(
            header(name, literal("x")).check(),
            Err(WebContractError::ForbiddenHeader),
            "{name}"
        );
    }
    assert!(header("Bad Name", literal("x")).check().is_err());
    assert!(header("", literal("x")).check().is_err());
    assert!(header("X-Note", literal("a\r\nInjected: 1"))
        .check()
        .is_err());
    assert!(header("Authorization", credential("")).check().is_err());
    assert!(!RequestHeader::is_forbidden_name("proxi\u{e9}-a"));
}

#[test]
fn duplicate_and_excess_headers_are_refused() {
    let mut scrape: WebScrapeRequest =
        serde_json::from_value(fixture("web_scrape_request")).unwrap();
    scrape.headers = vec![header("X-A", literal("1")), header("x-a", literal("2"))];
    assert!(scrape.check().is_err());
    scrape.headers = (0..33)
        .map(|i| header(&format!("X-H{i}"), literal("1")))
        .collect();
    assert_eq!(scrape.check(), Err(WebContractError::OverBudget("headers")));
}

#[test]
fn stealth_defaults_off_and_is_omitted_when_off() {
    let mut value = fixture("web_crawl_request");
    value.as_object_mut().unwrap().remove("stealth");
    value.as_object_mut().unwrap().remove("headers");
    let parsed: WebCrawlRequest = serde_json::from_value(value).unwrap();
    assert_eq!(parsed.stealth, StealthMode::Off);
    assert!(parsed.headers.is_empty());
    let text = serde_json::to_string(&parsed).unwrap();
    assert!(
        !text.contains("stealth") && !text.contains("headers"),
        "{text}"
    );
}

// ---------------------------------------------------- sidecar and indicator

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
fn visibility_requires_all_five_checks() {
    let all = Visibility {
        topmost: true,
        not_minimised: true,
        not_cloaked: true,
        on_monitor: true,
        on_input_desktop: true,
    };
    assert!(all.all_pass());
    assert!(!Visibility {
        on_input_desktop: false,
        ..all
    }
    .all_pass());
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
    assert_eq!(report["entries"][2]["status"], "unsupported");
    assert_eq!(report["entries"][2]["reason"], "Wave 2 engine");
    let status: CapabilityStatus =
        serde_json::from_value(json!({"status": "blocked", "policy": "cloud-only"})).unwrap();
    assert_eq!(status.failure_code(), Some(FailureCode::PolicyBlocked));
}

// ---------------------------------------------------------- canonical JSON

#[test]
fn canonical_json_sorts_keys_and_strips_whitespace() {
    let value = json!({"b": [1, {"z": true, "a": null}], "a": "x", "\u{e9}": 0, "B": -5});
    assert_eq!(
        canonical_json_value(&value).unwrap(),
        r#"{"B":-5,"a":"x","b":[1,{"a":null,"z":true}],"é":0}"#
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
fn canonical_json_refuses_non_integers_and_keeps_large_integers_exact() {
    assert_eq!(
        canonical_json_value(&json!({"x": 1.5})),
        Err(CanonicalJsonError::NonIntegerNumber)
    );
    assert_eq!(
        canonical_json_value(&json!([u64::MAX, i64::MIN])).unwrap(),
        format!("[{},{}]", u64::MAX, i64::MIN)
    );
}

#[test]
fn canonical_json_is_independent_of_input_key_order() {
    let a: Value = serde_json::from_str(r#"{"x":1,"y":{"q":2,"p":3}}"#).unwrap();
    let b: Value = serde_json::from_str(r#"{"y":{"p":3,"q":2},"x":1}"#).unwrap();
    assert_eq!(canonical_json_value(&a), canonical_json_value(&b));
    let crawl: WebCrawlRequest = serde_json::from_value(fixture("web_crawl_request")).unwrap();
    let text = canonical_json(&crawl).unwrap();
    assert_eq!(
        canonical_json_value(&serde_json::from_str(&text).unwrap()).unwrap(),
        text
    );
}

#[test]
fn audit_digest_input_excludes_the_digest_field() {
    let event: AuditEvent = serde_json::from_value(fixture("audit_event")).unwrap();
    let input = event.digest_input().unwrap();
    assert!(!input.contains("\"digest\""), "{input}");
    assert!(input.contains("\"prev_digest\""), "{input}");
    let mut changed = event.clone();
    changed.digest = "f".repeat(64);
    assert_eq!(changed.digest_input().unwrap(), input);
    changed.seq = 1;
    assert_ne!(changed.digest_input().unwrap(), input);
}
