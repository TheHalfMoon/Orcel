//! SG-000074 public surface: discovery, profile, argv, protocol,
//! supervision, and errors. No MCP tools, no network, no execution.

mod actuation;
#[cfg(windows)]
mod approved_folder;
mod argv;
mod capture;
mod change_tracking;
mod confinement;
mod coordinates;
mod crawl;
mod crawl_scope;
mod discovery;
mod error;
mod exposure;
mod extraction;
mod host;
#[cfg(windows)]
mod leftovers;
mod map_rank;
mod navigation;
mod observation;
mod profile;
mod proposal;
mod proto;
mod remote_leases;
mod robots;
mod runtime_pin;
mod sink;
mod supervise;
mod transfers;
mod uia;
// SG-000115 slice 1, inert until activation: compiled into test builds only.
#[cfg(test)]
mod unix_policy;
// The worker session that uses the probe machinery exists only on Windows.
#[cfg_attr(not(windows), allow(dead_code))]
mod verify;
mod webmcp;
#[cfg(all(
    windows,
    any(feature = "live-browser-test", feature = "live-browser-dev")
))]
pub mod worker_host;
mod worker_launch;
mod worker_navigation;
#[cfg(windows)]
mod worker_process;

pub use actuation::{
    coordinate_fallback, dispatch, name_looks_secret, retry_after_dispatch, role_supports_action,
    target_digest, verify_postcondition, verify_target, ActuationTarget, ApprovalToken,
    DispatchOutcome, FormInput, SupportedAction, MAX_FORM_OPTIONS, MAX_FORM_VALUE_BYTES,
    PRESS_KEYS,
};
pub use argv::{assert_argv_clean, build_argv};
pub use capture::{
    capture_binding_digest, invalidate_on, is_protected_surface, validate_capture_target,
    CaptureGeometry, CaptureLease, CaptureProcess, CaptureScope, CaptureTarget, CaptureWindow,
    InvalidationEvent, MAX_CAPTURE_BYTES, MAX_CAPTURE_DPI, MAX_CAPTURE_FRAMES, MAX_CAPTURE_HEIGHT,
    MAX_CAPTURE_LEASE_MS, MAX_CAPTURE_RATE_PER_MINUTE, MAX_CAPTURE_WIDTH, MIN_CAPTURE_DPI,
};
pub use change_tracking::{
    markdown_change_diff, Change, ChangeDiff, ChangeStore, Hunk, LineChange, LineKind,
    MAX_TRACKED_BYTES, MAX_TRACKED_PAGES,
};
pub use confinement::{
    assert_no_managed_policy, assert_worker_argv_exact, build_worker_argv, policy_keys,
    proxy_bypass_list, resolver_rules, validate_admitted_host, AdmittedDestination, PolicyHive,
    PolicyKeyState, PolicySource, RegistryPolicySource, MAX_ADMITTED_DESTINATIONS,
};
pub use coordinates::{
    arbitrary_drag, clipboard_typing, execute_one, hotkey_press, input_stream, proposal_digest,
    validate_proposal, CoordinateAction, CoordinateProposal, InputLease, InterruptionTracker,
    INPUT_LEASE_TTL_MS, MAX_INPUT_TEXT_CHARS, MAX_SCROLL_DELTA,
};
pub use crawl::{
    crawl, CrawlDriver, CrawlReport, CrawlSpec, CrawlStop, CrawledPage, SkipReason, SkippedLink,
    TextDocument, Visit, MAX_CRAWL_DEPTH, MAX_CRAWL_DURATION, MAX_CRAWL_PAGES, MAX_CRAWL_URLS,
    MAX_PATH_PATTERNS, MAX_PATH_PATTERN_BYTES, MAX_SITEMAPS, MAX_SKIPPED_REPORTED,
};
pub use crawl_scope::PatternKind;
pub use discovery::{discover_engine, Engine, EngineKind, SearchConfig};
pub use error::{DownloadFailure, HostError, UnavailableReason};
pub use exposure::{
    is_denied_shape, is_live_exposed, is_qualified_shape, profile_tools,
    remote_browser_mapping_enabled, BROWSER_STRUCTURED_PROFILE, DENIED_BROWSER_SHAPES,
    LIVE_BROWSER_MCP_TOOLS, LIVE_BROWSER_TOOL_SHAPES, PREEXISTING_PROFILES,
    QUALIFIED_BROWSER_SHAPES,
};
pub use extraction::{
    ExtractOptions, PageExtraction, MAX_EXTRACT_CHARS, MAX_EXTRACT_PIECES, MAX_PIECE_CHARS,
};
pub use host::{engine_launch_admitted, HostIdentity, LiveHost, Supervisor, HANDSHAKE_TIMEOUT};
#[cfg(all(
    windows,
    any(feature = "live-browser-test", feature = "live-browser-dev")
))]
pub use host::{LiveWorkerHost, WorkerHostLaunch, WORKER_HOST_REPLY_TIMEOUT};
pub use map_rank::MAX_SEARCH_BYTES;
pub use navigation::{
    check_rebinding_consistent, download_trigger_allowed, external_handler_allowed, mediate_frame,
    mediate_popup, mediate_service_worker, mediate_subresource, mediate_worker,
    parse_navigation_url, permission_allowed, validate_navigation, validate_redirect, DnsResolver,
    NavigationTarget, RedirectChain, SubresourceKind, MAX_REDIRECT_HOPS, MAX_URL_BYTES,
};
pub use observation::{
    cdp_command, check_freshness, devtools_open, evaluate_javascript, observe_snapshot,
    read_credentials, redact_value, select_by_caller_selector, short_digest,
    validate_identity_field, DocumentIdentity, InputNode, NodeIdentity, Observation,
    ObservationGate, ObservationScope, ObservedNode, PageIdentity, MAX_CONCURRENT_OBSERVATIONS,
    MAX_IDENTITY_BYTES, MAX_OBSERVATION_DEPTH, MAX_OBSERVATION_MS, MAX_OBSERVED_NODES,
    MAX_SNAPSHOT_BYTES, MAX_VALUE_BYTES,
};
pub use profile::{adopt_profile, setup_ephemeral_profile, AutomationProfile};
pub use proposal::{
    adapt_provider_record, invoke_backend_directly, mint_target_identity, parse_proposal,
    ComputerActionProposal, ProposalValue, ProviderRecord, FORBIDDEN_PROPOSAL_FIELDS,
    MAX_PROPOSAL_BYTES, MAX_TARGET_FIELD_BYTES, PROPOSAL_ACTION_VERBS, PROPOSAL_ENVELOPE_FIELDS,
    PROPOSAL_TARGET_FIELDS,
};
pub use proto::{
    decode_frame, encode_frame, write_frame, HostReply, HostRequest, MAX_FRAME_BYTES,
    PROTOCOL_GENERATION,
};
pub use remote_leases::{
    background_stream, check_lease, delayed_execution, issue_local, issue_remote, offline_queue,
    remote_execution_allowed, renew_silently, resurrect, self_approve, validate_route, widen_lease,
    LeaseScope, RemoteLease, LEASE_CAPABILITIES, MAX_LEASE_CAPABILITIES, MAX_LEASE_FIELD_BYTES,
    MAX_LEASE_TARGETS, MAX_REMOTE_LEASE_MS,
};
pub use robots::{
    sitemap_locations, Robots, MAX_ROBOTS_PATTERN_BYTES, MAX_ROBOTS_RULES, MAX_ROBOTS_SITEMAPS,
    MAX_SITEMAP_LOCS, ROBOTS_PRODUCT_TOKEN,
};
#[cfg(windows)]
pub use runtime_pin::node_folder_writable;
pub use runtime_pin::{
    compiled_runtime, runtime_files, tree_digest, worker_root, CompiledRuntime, HeldRuntime,
    RuntimePin,
};
pub use supervise::{
    spawn_engine_null, spawn_host_piped, HostPipes, SupervisedChild, JOB_ACTIVE_PROCESS_LIMIT,
    LAUNCH_GRACE, SHUTDOWN_TIMEOUT,
};
pub use transfers::{
    execute_automatically, extract_automatically, open_automatically, reparse_safe_contained,
    sniff_denied_class, validate_download_type, validate_inert_pdf, validate_relative_destination,
    validate_transfer_size, validate_upload_source, DeniedContentClass, DownloadSource,
    PresentedUpload, RecordedUpload, DOWNLOAD_SOURCE_TTL_MS, MAX_DESTINATION_BYTES,
    MAX_TRANSFER_BYTES, PDF_MEDIA,
};
pub use uia::{
    invoke, is_protected_uia_surface, keyboard_synthesis, mouse_synthesis, scroll, select,
    set_value, toggle, uia_coordinate_fallback, uia_target_digest, verify_pattern_support,
    verify_uia_target, ScrollDirection, SupportedPattern, UiaApproval, UiaElement, UiaLive,
    UiaProcess, UiaTarget, UiaWindow, MAX_SCROLL_AMOUNT, MAX_UIA_VALUE_CHARS, MIN_SCROLL_AMOUNT,
};
pub use verify::{
    check_postconditions, CheckResult, Postcondition, Verification, MAX_POSTCONDITIONS,
    MAX_VERIFY_COUNT, MAX_VERIFY_TEXT_BYTES,
};
pub use webmcp::{
    canonical_arguments, ensure_executable, resolve_action, validate_arguments,
    validate_result_blocks, validate_tools, ControlKind, DiscoveredTool, DiscoveredTools,
    ExecField, FormMethod, HostTool, PageText, ParamType, ToolParam, WireParam, WireTool,
    MAX_ACTION, MAX_ARGUMENT_CHARS, MAX_CHOICE, MAX_CHOICES, MAX_PARAM_DESCRIPTION, MAX_PATTERN,
    MAX_RESULT_BLOCK, MAX_RESULT_BLOCKS, MAX_TOOLS, MAX_TOOL_DESCRIPTION, MAX_TOOL_NAME,
    MAX_TOOL_PARAMS, MAX_TOOL_TITLE,
};
#[cfg(windows)]
pub use worker_launch::ephemeral_profile_dir;
pub use worker_launch::{
    classify_job, launch_worker, worker_environment, worker_node_args, BrowserWorker, CancelHandle,
    CommittedDownload, ExecutionOutcome, FetchedText, FormOutcome, HostNode, JobProcess,
    LiveObservation, NavigationOutcome, ShutdownReport, SnapshotNode, StagedUpload, WorkerLaunch,
    FETCH_TEXT_MEDIA, MAX_FETCH_TEXT_CHARS, MAX_WAIT_MS, WORKER_ACTIVATION_TIMEOUT,
    WORKER_EXECUTION_TIMEOUT, WORKER_EXTRACTION_TIMEOUT, WORKER_HANDSHAKE_TIMEOUT, WORKER_IDENTITY,
    WORKER_LAUNCH_TIMEOUT, WORKER_NAVIGATION_TIMEOUT, WORKER_NODE_OPTION,
    WORKER_OBSERVATION_TIMEOUT, WORKER_PROTOCOL_GENERATION, WORKER_REPLY_TIMEOUT,
    WORKER_SHUTDOWN_TIMEOUT,
};
pub use worker_launch::{
    DialogKind, DismissedDialog, DismissedDialogs, MAX_DIALOGS, MAX_DIALOG_MESSAGE_BYTES,
    MAX_DIALOG_URL_BYTES,
};
pub use worker_navigation::{
    decode_form, NavigationPolicy, RequestDetail, RouteKind, Submission, Submitted,
};
