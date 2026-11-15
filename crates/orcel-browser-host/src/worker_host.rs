//! SG-000108 product caller, slices 1a–3b: the host binary's worker mode.
//!
//! `orcel-browser-host --worker` never spawns the engine itself: it serves
//! a closed capability vocabulary over one `launch_worker` lifetime at a
//! time, for exactly one admitted destination. Orcel supervision is the
//! only peer (the pipe's other end). The module exists only in two
//! non-default builds, which the release-blocker sweep keeps out of every
//! release (docs/security/SG-000108_PRODUCT_CALLER.md):
//! - `live-browser-test` (test builds): `open` admits only the loopback
//!   fixture origin, trusting exactly its certificate, and Node and the
//!   worker come from the test harness;
//! - `live-browser-dev` (development builds, slice 3b-ii): `open_public`
//!   admits one SG-000075 public HTTPS destination, pinned from the host's
//!   own resolution, and the worker runtime is only the one the build
//!   pinned (decision 7), verified and held at every launch.
//!
//! Every consequential frame (navigate, activate, download) carries a
//! broker record id and the host binding the host itself computed for that
//! action (`bind`). The host re-derives the binding from its current state
//! and refuses a changed one (another lifetime, document, node, target,
//! folder or file name) or a record id already used in this lifetime. The
//! host never mints an approval: Orcel consumed it with the broker before
//! sending the frame (decision 3 of the design).
//!
//! SG-000122 slice A1 (inert: no orceld dispatch, policy or tool yet) adds
//! the BR-02 form actions and the BR-07 verifier to the vocabulary, narrowed
//! to the grain: fill and Enter only in a single-line text field, one option
//! of a native select, a checkbox or radio set, each bound and approved like
//! a click; read-only text waits and verifications of the main frame's
//! committed document, with at most `verify::MAX_AWAITED_TEXTS` distinct
//! texts per lifetime. Every rule the host can decide from its own state is
//! checked before any worker frame; the worker checks the element again.

use crate::actuation::{target_digest, ActuationTarget, ApprovalToken, FormInput, SupportedAction};
use crate::confinement::AdmittedDestination;
use crate::discovery::{discover_engine, SearchConfig};
use crate::error::{HostError, UnavailableReason};
use crate::observation::{DocumentIdentity, ObservationScope, ObservedNode, PageIdentity};
use crate::proto::{decode_frame, write_frame};
use crate::worker_launch::{launch_worker, BrowserWorker, WorkerLaunch};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::{BufRead, Write};
use std::net::IpAddr;
#[cfg(feature = "live-browser-test")]
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

/// Worker-mode protocol generation. 1 is SG-000074's hello/ping/shutdown;
/// 2 was slice 1a; 3 adds binding (`bind`), the typed selector, activation
/// and download, and binds navigation; 4 adds `open_public` (slice 3b-ii);
/// 5 adds SG-000122 slice A1's form actions, text waits and verification;
/// 6 is observation contract 2 (SG-000122 slice A5): an observed node may
/// carry `untrusted_name`; 7 (SG-000122 slice A6): `form_done` says whether
/// an Enter's submission committed a new document (`navigation`).
pub const WORKER_HOST_GENERATION: u32 = 7;

/// The observation contract an `observed` reply follows. 1 (SG-000108 slice
/// 1a): node identities, roles and keyed digests only; no name, value or
/// page text crosses. 2 (SG-000122 slice A5): the same, plus the accessible
/// name of each main-frame form control (roles in
/// `worker_launch::NAMED_ROLES`, on an input or a native select) whose name
/// no embedded or referenced control contributes to, as `untrusted_name`:
/// the page's own text, at most `prompt_display::MAX_FIELD_NAME_BYTES`, cut
/// on a character boundary and marked `cut`, control characters replaced.
/// It is untrusted and grants nothing. Values, page text, option labels and
/// every other node's name keep contract 1's rule.
pub const OBSERVATION_CONTRACT: u32 = 2;

/// Domain separation for host bindings.
const BINDING_DOMAIN: &str = "orcel-sg108-host-binding/1";

/// What an approval is for, as Orcel describes it to `bind` and the host
/// re-derives at dispatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BindAction {
    Navigate {
        url: String,
    },
    /// Click one observed link (the only live click in slices 1–3).
    Click {
        node_id: String,
        role: String,
    },
    /// Download the document behind one observed link, create-only, to
    /// `relative` inside `folder`.
    Download {
        node_id: String,
        role: String,
        folder: String,
        relative: String,
    },
    /// SG-000122: type `value` into one observed single-line text field,
    /// replacing its content. The value must be one the approval prompt
    /// shows exactly and in full.
    Fill {
        node_id: String,
        role: String,
        value: String,
    },
    /// SG-000122: choose the one option labelled exactly `label` of one
    /// observed native select.
    Select {
        node_id: String,
        role: String,
        label: String,
    },
    /// SG-000122: set one observed checkbox or radio to `checked`.
    Check {
        node_id: String,
        role: String,
        checked: bool,
    },
    /// SG-000122: press Enter, and no other key, in one observed
    /// single-line text field. It may submit or send what the page holds.
    PressEnter {
        node_id: String,
        role: String,
    },
}

/// SG-000122: the form action `action` describes, with its node and role,
/// or `None` for a navigation, click or download.
pub(crate) fn form_input(action: &BindAction) -> Option<(&str, &str, FormInput)> {
    match action {
        BindAction::Fill {
            node_id,
            role,
            value,
        } => Some((
            node_id,
            role,
            FormInput::Fill {
                value: value.clone(),
            },
        )),
        BindAction::Select {
            node_id,
            role,
            label,
        } => Some((
            node_id,
            role,
            FormInput::Select {
                labels: vec![label.clone()],
            },
        )),
        BindAction::Check {
            node_id,
            role,
            checked,
        } => Some((node_id, role, FormInput::Check { checked: *checked })),
        BindAction::PressEnter { node_id, role } => Some((node_id, role, FormInput::Enter)),
        BindAction::Navigate { .. } | BindAction::Click { .. } | BindAction::Download { .. } => {
            None
        }
    }
}

/// Closed worker-mode request vocabulary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "frame", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerHostRequest {
    Hello {
        generation: u32,
    },
    /// Start a lifetime for the loopback fixture, trusting exactly its
    /// certificate. Test builds only.
    #[cfg(feature = "live-browser-test")]
    Open {
        workspace: String,
        policy_revision: u64,
        host: String,
        fixture_spki: String,
    },
    /// Start a lifetime for one public HTTPS destination: the host resolves
    /// it and admits it under SG-000075 (`AdmittedDestination::admit`), and
    /// the pin is the host's own. Development builds only.
    #[cfg(feature = "live-browser-dev")]
    OpenPublic {
        workspace: String,
        policy_revision: u64,
        url: String,
    },
    /// The host's half of an approval for `action`, computed from its own
    /// state. Nothing is done.
    Bind {
        action: BindAction,
    },
    Navigate {
        url: String,
        record_id: String,
        binding: String,
    },
    Observe {},
    /// The host's typed selection: the observed link whose accessible name
    /// carries the latest ISO date. Raw names never leave the host.
    SelectLatestDatedLink {},
    Activate {
        node_id: String,
        role: String,
        record_id: String,
        binding: String,
    },
    Download {
        node_id: String,
        role: String,
        folder: String,
        relative: String,
        record_id: String,
        binding: String,
    },
    /// SG-000122: one approved form action; `action` is a form kind of
    /// [`BindAction`] (fill, select, check, press_enter), bound with `bind`.
    FormAction {
        action: BindAction,
        record_id: String,
        binding: String,
    },
    /// SG-000122: wait, read-only and without approval, until a visible copy
    /// of `text` appears (`appear`) or none is left, in the main frame's
    /// committed document, for at most `timeout_ms` (1 to `MAX_WAIT_MS`).
    WaitText {
        text: String,
        appear: bool,
        timeout_ms: u64,
    },
    /// SG-000122: the BR-07 postcondition verifier, read-only and without
    /// approval; text checks look at the main frame's committed document
    /// only and share the waits' cap on distinct texts.
    Verify {
        checks: Vec<crate::verify::Postcondition>,
    },
    /// End the current lifetime (profile removed); the host keeps serving.
    Close {},
    Shutdown {},
}

/// SG-000122: one checked postcondition as it crosses (fixed evidence
/// vocabulary and counts, never page text, a name or a value).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireCheck {
    pub index: usize,
    pub kind: String,
    pub passed: bool,
    pub evidence: String,
}

/// SG-000122 slice A2: what a form action's approval prompt shows about its
/// field, from the host's own record of the observation: the role and the
/// accessible name as the observation returned it (slice A5's
/// `untrusted_name`, or the empty name when it returned none), both
/// page-supplied (the name at most
/// `prompt_display::MAX_FIELD_NAME_BYTES`, cut on a character boundary) and,
/// when another observed node of that role would have the same name line
/// drawn in the prompt, the target's ordinal among them in page order. It
/// crosses only to orceld, for the prompt, never to a caller. The host
/// binding covers each part and is derived again at dispatch from the host's
/// record of its latest observation (the page is not observed again for
/// it): a caller that observed again in between, with a changed name or
/// ordinal, is refused. In the page, the worker then acts on the exact
/// observed reference and falls back to role and name only when exactly one
/// element has them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundForm {
    pub role: String,
    pub name: String,
    pub name_cut: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ordinal: Option<FieldOrdinal>,
}

/// SG-000122 slice A2: "position of count" among the observed nodes of one
/// role that show the same name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldOrdinal {
    pub position: usize,
    pub count: usize,
}

impl BoundForm {
    /// The facts for `role`, the full observed `name` and its ordinal.
    pub(crate) fn new(role: &str, name: &str, ordinal: Option<(usize, usize)>) -> Self {
        let (bounded, name_cut) = orcel_contracts::prompt_display::bounded_field_name(name);
        Self {
            role: role.to_owned(),
            name: bounded.to_owned(),
            name_cut,
            ordinal: ordinal.map(|(position, count)| FieldOrdinal { position, count }),
        }
    }

    /// The host binding's material for these facts: the full name's digest
    /// and the ordinal (`-` when there is none).
    fn material(&self, full_name: &str) -> String {
        let ordinal = self
            .ordinal
            .map(|ordinal| format!("{}/{}", ordinal.position, ordinal.count))
            .unwrap_or_else(|| "-".to_owned());
        format!("{}\n{ordinal}", sha256_hex(full_name))
    }
}

/// One observed node as it crosses to Orcel: identities and digests and,
/// for a main-frame form control only (observation contract 2), its
/// untrusted accessible name. Values, page text, option labels and every
/// other raw name never leave the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireNode {
    pub node_id: String,
    pub role: String,
    pub name_digest: String,
    pub value_digest: String,
    pub redacted: bool,
    pub children: Vec<WireNode>,
    /// Absent under contract 1 and for every node it does not name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub untrusted_name: Option<UntrustedName>,
}

/// SG-000122 slice A5: a form control's accessible name as the page
/// supplies it: untrusted text that grants nothing, at most
/// `prompt_display::MAX_FIELD_NAME_BYTES` and cut on a character boundary
/// (`cut`), with control characters already replaced. The host is the
/// authority on the cut.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UntrustedName {
    pub text: String,
    pub cut: bool,
}

impl UntrustedName {
    /// The bounded name for `full`, the host's record of the name.
    pub fn new(full: &str) -> Self {
        let (bounded, cut) = orcel_contracts::prompt_display::bounded_field_name(full);
        Self {
            text: bounded.to_owned(),
            cut,
        }
    }
}

impl From<&ObservedNode> for WireNode {
    fn from(node: &ObservedNode) -> Self {
        Self {
            node_id: node.node_id.clone(),
            role: node.role.clone(),
            name_digest: node.name_digest.clone(),
            value_digest: node.value_digest.clone(),
            redacted: node.redacted,
            children: node.children.iter().map(WireNode::from).collect(),
            untrusted_name: None,
        }
    }
}

/// Closed worker-mode reply vocabulary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "frame", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerHostReply {
    Hello {
        generation: u32,
        host: String,
    },
    /// A lifetime started: its nonce (bound into every host binding) and
    /// the address the host pinned.
    Opened {
        lifetime: String,
        pinned: String,
    },
    /// The host binding for the action, and where it goes (the URL a
    /// navigation or click opens, or the link a download reads), for the
    /// approval prompt.
    Bound {
        binding: String,
        target: String,
        /// SG-000122 slice A2: for a form action only, what the approval
        /// prompt names about the field (all of it bound into `binding`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        form: Option<BoundForm>,
    },
    /// The committed URL: on the lifetime's single origin (the policy
    /// refuses anything else), which Orcel's page store records.
    Navigated {
        url: String,
        status: u16,
    },
    Observed {
        page_id: String,
        origin: String,
        page_generation: u64,
        document_generation: u64,
        nodes: Vec<WireNode>,
        node_count: usize,
        truncated: bool,
    },
    Selected {
        node_id: String,
    },
    Activated {
        url: String,
        status: u16,
    },
    /// A committed download: where inside the approved folder, and what.
    Downloaded {
        relative: String,
        sha256: String,
        bytes: u64,
        source_url: String,
    },
    /// SG-000122: an approved form action ran. With `navigation: none` the
    /// page is still this committed document (its observation stays
    /// valid); with `document_committed` (slice A6, Enter only) its
    /// submission committed exactly one new document on the lifetime's
    /// origin, `url`: every earlier observation is stale.
    FormDone {
        url: String,
        navigation: FormNavigation,
    },
    /// SG-000122: whether the awaited text appeared (or went) in time.
    Waited {
        met: bool,
    },
    /// SG-000122: the verifier's report.
    Verified {
        url: String,
        document_generation: u64,
        results: Vec<WireCheck>,
        verified: bool,
        evidence_sha256: String,
    },
    Closed {
        job_empty: bool,
        profile_removed: bool,
    },
    Bye {},
    /// A typed refusal: a bounded, closed code, never page text.
    Error {
        code: String,
    },
}

/// SG-000122 slice A6: what an approved form action did to the page's
/// document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FormNavigation {
    /// The page stayed on its committed document.
    None,
    /// An Enter's submission committed one new same-origin document.
    DocumentCommitted,
}

/// What Orcel supervision passes the host in worker mode. Never caller
/// input: these come from Orcel's own state.
#[derive(Debug, Clone)]
pub struct WorkerHostArgs {
    pub host_id: String,
    /// The worker runtime, or `None` when the build has none it may run
    /// (every `open` is then refused, typed).
    pub runtime: Option<WorkerRuntime>,
    pub profile_root: PathBuf,
    pub temp_dir: PathBuf,
}

/// Node and the worker entry point a lifetime launches. In a test build
/// they come from the test harness, unpinned; in a `live-browser-dev`
/// build only from the build's own pin, which every launch verifies and
/// holds (decision 7).
#[derive(Debug, Clone)]
pub struct WorkerRuntime {
    pub node: PathBuf,
    pub worker_main: PathBuf,
    pub pin: Option<crate::runtime_pin::RuntimePin>,
}

/// The closed error code for a host error. No message text crosses: a
/// message could carry a URL or page text.
pub fn error_code(error: &HostError) -> String {
    match error {
        HostError::Unavailable(reason) => format!("unavailable:{reason:?}").to_ascii_lowercase(),
        HostError::Invalid(_) => "invalid".into(),
        HostError::Download(_) => "download".into(),
        _ => "failed".into(),
    }
}

struct Lifetime {
    worker: BrowserWorker,
    workspace: String,
    policy_revision: u64,
    profile_identity: String,
    nonce: String,
    pin: String,
    /// The page and document of the latest observation; node ids belong to
    /// it. Cleared whenever the page moves.
    observed: Option<(PageIdentity, DocumentIdentity)>,
    /// Broker record ids already presented in this lifetime.
    used_records: HashSet<String>,
}

/// Serve the worker-mode vocabulary until shutdown, end of input or a
/// protocol violation. At most one lifetime exists at a time; ending the
/// host ends it (the job is kill-on-close either way).
pub fn serve_worker_mode(
    args: &WorkerHostArgs,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<(), String> {
    let mut lifetime: Option<Lifetime> = None;
    let mut said_hello = false;
    let result = loop {
        let request: WorkerHostRequest = match decode_frame(input) {
            Ok(request) => request,
            Err(_) => break Err("protocol violation".to_string()),
        };
        if !said_hello && !matches!(request, WorkerHostRequest::Hello { .. }) {
            break Err("frame before hello".to_string());
        }
        let reply = match request {
            WorkerHostRequest::Hello { generation } => {
                if generation != WORKER_HOST_GENERATION {
                    break Err("protocol generation mismatch".to_string());
                }
                said_hello = true;
                WorkerHostReply::Hello {
                    generation: WORKER_HOST_GENERATION,
                    host: args.host_id.clone(),
                }
            }
            #[cfg(feature = "live-browser-test")]
            WorkerHostRequest::Open {
                workspace,
                policy_revision,
                host,
                fixture_spki,
            } => {
                if lifetime.is_some() {
                    error("lifetime_open")
                } else {
                    match open_fixture(args, &workspace, policy_revision, &host, &fixture_spki) {
                        Ok((opened, reply)) => {
                            lifetime = Some(opened);
                            reply
                        }
                        Err(err) => refusal(&err),
                    }
                }
            }
            #[cfg(feature = "live-browser-dev")]
            WorkerHostRequest::OpenPublic {
                workspace,
                policy_revision,
                url,
            } => {
                if lifetime.is_some() {
                    error("lifetime_open")
                } else {
                    match open_public(args, &workspace, policy_revision, &url, &HostResolver) {
                        Ok((opened, reply)) => {
                            lifetime = Some(opened);
                            reply
                        }
                        Err(err) => refusal(&err),
                    }
                }
            }
            WorkerHostRequest::Shutdown {} => {
                if let Some(live) = lifetime.take() {
                    let _ = live.worker.shutdown();
                }
                let _ = send(output, &WorkerHostReply::Bye {});
                break Ok(());
            }
            WorkerHostRequest::Close {} => match lifetime.take() {
                None => error("no_lifetime"),
                Some(live) => {
                    let report = live.worker.shutdown();
                    WorkerHostReply::Closed {
                        job_empty: report.job_empty,
                        profile_removed: report.profile_removed,
                    }
                }
            },
            // Everything decidable from the request alone is refused first,
            // with or without a lifetime, and never reaches the worker.
            other => match precheck(&other) {
                Err(refused) => refused,
                Ok(()) => match lifetime.as_mut() {
                    None => error("no_lifetime"),
                    Some(live) => in_lifetime(live, other),
                },
            },
        };
        if send(output, &reply).is_err() {
            break Err("reply failed".to_string());
        }
    };
    if let Some(live) = lifetime.take() {
        let _ = live.worker.kill();
    }
    result
}

/// SG-000122: the checks a form action, wait or verification needs before
/// anything else: a form kind with input the host would accept (a fill value
/// the prompt shows exactly and in full, one bounded option label), a
/// bounded single-line awaited text and timeout, well-formed postconditions.
fn precheck(request: &WorkerHostRequest) -> Result<(), WorkerHostReply> {
    let form = |action: &BindAction| -> Result<(), WorkerHostReply> {
        let Some((_, _, input)) = form_input(action) else {
            return Ok(());
        };
        input.check().map_err(|err| refusal(&err))?;
        if let FormInput::Fill { value } = &input {
            crate::actuation::live_fill_value(value).map_err(|err| refusal(&err))?;
        }
        Ok(())
    };
    match request {
        WorkerHostRequest::Bind { action } => form(action),
        WorkerHostRequest::FormAction { action, .. } => {
            if form_input(action).is_none() {
                return Err(error("invalid"));
            }
            form(action)
        }
        WorkerHostRequest::WaitText {
            text, timeout_ms, ..
        } => {
            if text.is_empty()
                || text.len() > crate::verify::MAX_VERIFY_TEXT_BYTES
                || text.chars().any(char::is_control)
                || *timeout_ms == 0
                || *timeout_ms > crate::worker_launch::MAX_WAIT_MS
            {
                return Err(error("invalid"));
            }
            Ok(())
        }
        WorkerHostRequest::Verify { checks } => {
            crate::verify::check_postconditions(checks).map_err(|err| refusal(&err))
        }
        _ => Ok(()),
    }
}

/// Frames that need a live lifetime.
fn in_lifetime(live: &mut Lifetime, request: WorkerHostRequest) -> WorkerHostReply {
    match request {
        WorkerHostRequest::Bind { action } => match host_binding(live, &action) {
            Ok(derived) => WorkerHostReply::Bound {
                binding: derived.binding,
                target: derived.target,
                form: derived.form,
            },
            Err(err) => refusal(&err),
        },
        WorkerHostRequest::Observe {} => observe(live),
        WorkerHostRequest::SelectLatestDatedLink {} => {
            if live.observed.is_none() {
                return error("no_observation");
            }
            match live.worker.select_latest_dated_link() {
                Ok(node_id) => WorkerHostReply::Selected { node_id },
                Err(err) => refusal(&err),
            }
        }
        WorkerHostRequest::Navigate {
            url,
            record_id,
            binding,
        } => {
            let action = BindAction::Navigate { url: url.clone() };
            if let Err(refused) = verify(live, &action, &record_id, &binding) {
                return refused;
            }
            live.observed = None;
            match live.worker.navigate(&url) {
                Ok(outcome) => WorkerHostReply::Navigated {
                    url: outcome.url,
                    status: outcome.status,
                },
                Err(err) => refusal(&err),
            }
        }
        WorkerHostRequest::Activate {
            node_id,
            role,
            record_id,
            binding,
        } => {
            let action = BindAction::Click {
                node_id: node_id.clone(),
                role: role.clone(),
            };
            let state = match verify(live, &action, &record_id, &binding) {
                Ok(state) => state,
                Err(refused) => return refused,
            };
            let (target, mut approval) = match approved_target(live, &action, &record_id, state) {
                Ok(pair) => pair,
                Err(err) => return refusal(&err),
            };
            live.observed = None;
            let (revision, workspace) = (live.policy_revision, live.workspace.clone());
            match live
                .worker
                .activate(&target, &mut approval, revision, &workspace)
            {
                Ok(outcome) => WorkerHostReply::Activated {
                    url: outcome.url,
                    status: outcome.status,
                },
                Err(err) => refusal(&err),
            }
        }
        WorkerHostRequest::Download {
            node_id,
            role,
            folder,
            relative,
            record_id,
            binding,
        } => {
            let action = BindAction::Download {
                node_id: node_id.clone(),
                role: role.clone(),
                folder: folder.clone(),
                relative: relative.clone(),
            };
            let state = match verify(live, &action, &record_id, &binding) {
                Ok(state) => state,
                Err(refused) => return refused,
            };
            let (target, mut approval) = match approved_target(live, &action, &record_id, state) {
                Ok(pair) => pair,
                Err(err) => return refusal(&err),
            };
            live.observed = None;
            let (revision, workspace) = (live.policy_revision, live.workspace.clone());
            match live.worker.download(
                &target,
                &mut approval,
                revision,
                &workspace,
                Path::new(&folder),
                &relative,
            ) {
                Ok(committed) => WorkerHostReply::Downloaded {
                    relative,
                    sha256: committed.sha256,
                    bytes: committed.bytes,
                    source_url: committed.source_url,
                },
                Err(err) => refusal(&err),
            }
        }
        WorkerHostRequest::FormAction {
            action,
            record_id,
            binding,
        } => {
            let Some((_, _, input)) = form_input(&action) else {
                return error("invalid");
            };
            let state = match verify(live, &action, &record_id, &binding) {
                Ok(state) => state,
                Err(refused) => return refused,
            };
            let (target, mut approval) = match approved_target(live, &action, &record_id, state) {
                Ok(pair) => pair,
                Err(err) => return refusal(&err),
            };
            let (revision, workspace) = (live.policy_revision, live.workspace.clone());
            match live
                .worker
                .live_form_action(&target, &mut approval, &input, revision, &workspace)
            {
                // The same document: its node identities stay valid.
                Ok(outcome) if outcome.committed.is_none() => WorkerHostReply::FormDone {
                    url: outcome.url,
                    navigation: FormNavigation::None,
                },
                // SG-000122 slice A6: an Enter's submission committed a new
                // document; nothing observed before is valid.
                Ok(outcome) => {
                    live.observed = None;
                    WorkerHostReply::FormDone {
                        url: outcome.url,
                        navigation: FormNavigation::DocumentCommitted,
                    }
                }
                Err(err) => {
                    // Nothing observed is trusted until the page is observed
                    // again.
                    live.observed = None;
                    refusal(&err)
                }
            }
        }
        WorkerHostRequest::WaitText {
            text,
            appear,
            timeout_ms,
        } => match live.worker.wait_for_text(
            &text,
            appear,
            std::time::Duration::from_millis(timeout_ms),
        ) {
            Ok(met) => WorkerHostReply::Waited { met },
            Err(err) => refusal(&err),
        },
        WorkerHostRequest::Verify { checks } => match live.worker.verify_postconditions(&checks) {
            Ok(report) => WorkerHostReply::Verified {
                url: report.url,
                document_generation: report.document_generation,
                results: report
                    .results
                    .into_iter()
                    .map(|result| WireCheck {
                        index: result.index,
                        kind: result.kind.to_owned(),
                        passed: result.passed,
                        evidence: result.evidence,
                    })
                    .collect(),
                verified: report.verified,
                evidence_sha256: report.evidence_sha256,
            },
            Err(err) => refusal(&err),
        },
        // Handled by the caller; unreachable here by construction.
        #[cfg(feature = "live-browser-test")]
        WorkerHostRequest::Open { .. } => error("invalid"),
        #[cfg(feature = "live-browser-dev")]
        WorkerHostRequest::OpenPublic { .. } => error("invalid"),
        WorkerHostRequest::Hello { .. }
        | WorkerHostRequest::Close {}
        | WorkerHostRequest::Shutdown {} => error("invalid"),
    }
}

fn error(code: &str) -> WorkerHostReply {
    WorkerHostReply::Error { code: code.into() }
}

fn refusal(err: &HostError) -> WorkerHostReply {
    WorkerHostReply::Error {
        code: error_code(err),
    }
}

fn send(output: &mut impl Write, value: &WorkerHostReply) -> Result<(), HostError> {
    write_frame(output, value)?;
    output.flush().map_err(HostError::from)
}

fn sha256_hex(text: &str) -> String {
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The binding digest: SHA-256 over the domain tag, the lifetime nonce,
/// the workspace and policy revision of the lifetime, and the action's
/// material. Pure, so every part it binds is tested directly.
pub(crate) fn binding_digest(
    nonce: &str,
    workspace: &str,
    policy_revision: u64,
    material: &str,
) -> String {
    sha256_hex(&format!(
        "{BINDING_DOMAIN}\n{nonce}\n{workspace}\n{policy_revision}\n{material}"
    ))
}

/// What a binding was derived from: the digest, the action's target (for
/// the prompt) and the state the host's own actuation path is bound to
/// (the link's destination for a click, the host's `download_binding` for a
/// download, the URL for a navigation). Dispatch uses the state verified
/// here, never a fresh derivation, so what runs is what was approved.
struct Derived {
    binding: String,
    target: String,
    state: String,
    /// SG-000122: a form action's prompt facts.
    form: Option<BoundForm>,
}

/// The host's half of an approval, from its own state now.
fn host_binding(live: &Lifetime, action: &BindAction) -> Result<Derived, HostError> {
    let mut form_facts = None;
    let (material, target, state) = match action {
        BindAction::Navigate { url } => {
            crate::navigation::parse_navigation_url(url)?;
            (
                format!("navigate\n{url}\n{}", live.pin),
                url.clone(),
                url.clone(),
            )
        }
        BindAction::Click { node_id, role } => {
            let (page, document) = observed(live)?;
            let destination = live.worker.link_destination(node_id)?;
            (
                format!(
                    "click\n{}\n{}\n{}\n{node_id}\n{role}\n{destination}",
                    page.page_id, page.origin, document.document_generation
                ),
                destination.clone(),
                destination,
            )
        }
        BindAction::Download {
            node_id,
            role,
            folder,
            relative,
        } => {
            let (page, document) = observed(live)?;
            let destination = live.worker.link_destination(node_id)?;
            let download = live
                .worker
                .download_binding(node_id, Path::new(folder), relative)?;
            (
                format!(
                    "download\n{}\n{}\n{}\n{node_id}\n{role}\n{download}\n{}",
                    page.page_id,
                    page.origin,
                    document.document_generation,
                    crate::transfers::MAX_TRANSFER_BYTES
                ),
                destination,
                download,
            )
        }
        form => {
            let (node_id, role, input) =
                form_input(form).ok_or_else(|| HostError::Invalid("not a form action".into()))?;
            let (page, document) = observed(live)?;
            // The host's own checks of the observed target, before any
            // worker frame; the binding names the name the host observed.
            let crate::actuation::LiveFormBinding {
                state,
                name,
                ordinal,
            } = live.worker.live_form_binding(node_id, role, &input)?;
            // SG-000122 slice A2: the role, the name and the ordinal the
            // prompt shows are bound too (the name by its full digest).
            let facts = BoundForm::new(role, &name, ordinal);
            let material = format!(
                "form\n{}\n{}\n{}\n{node_id}\n{role}\n{}\n{state}",
                page.page_id,
                page.origin,
                document.document_generation,
                facts.material(&name)
            );
            form_facts = Some(facts);
            (material, page.origin.clone(), state)
        }
    };
    Ok(Derived {
        binding: binding_digest(
            &live.nonce,
            &live.workspace,
            live.policy_revision,
            &material,
        ),
        target,
        state,
        form: form_facts,
    })
}

fn observed(live: &Lifetime) -> Result<(&PageIdentity, &DocumentIdentity), HostError> {
    live.observed
        .as_ref()
        .map(|(page, document)| (page, document))
        .ok_or_else(|| HostError::Invalid("no current observation".into()))
}

/// Check a consequential frame: a well-formed record id not used before in
/// this lifetime, and a binding equal to the one the host derives now. A
/// record id is spent once presented, whatever happens next (the broker
/// already consumed the approval). Returns the verified state.
fn verify(
    live: &mut Lifetime,
    action: &BindAction,
    record_id: &str,
    binding: &str,
) -> Result<String, WorkerHostReply> {
    if crate::observation::validate_identity_field(record_id).is_err() {
        return Err(error("invalid"));
    }
    if !live.used_records.insert(record_id.to_owned()) {
        return Err(error("approval_replay"));
    }
    match host_binding(live, action) {
        Ok(derived) if derived.binding == binding => Ok(derived.state),
        Ok(_) => Err(error("binding_mismatch")),
        // The material cannot be derived any more (the page moved, the node
        // is gone): the approved action no longer exists.
        Err(_) => Err(error("binding_mismatch")),
    }
}

/// The SG-000077 target and one-shot token the host's own actuation path
/// takes, built from the verified `state`. The token is the host's internal
/// mechanism, not an approval of its own; the actuation path then checks
/// the target against its current state, so anything that changed between
/// verification and dispatch (a folder junction swapped) is refused.
fn approved_target(
    live: &Lifetime,
    action: &BindAction,
    record_id: &str,
    state: String,
) -> Result<(ActuationTarget, ApprovalToken), HostError> {
    let (page, document) = observed(live)?;
    let (node_id, role, kind) = match action {
        BindAction::Click { node_id, role } => {
            (node_id.as_str(), role.as_str(), SupportedAction::Click)
        }
        BindAction::Download { node_id, role, .. } => {
            (node_id.as_str(), role.as_str(), SupportedAction::Download)
        }
        BindAction::Navigate { .. } => {
            return Err(HostError::Invalid(
                "navigation takes no actuation target".into(),
            ))
        }
        form => match form_input(form) {
            Some((node_id, role, input)) => (node_id, role, input.action()),
            None => return Err(HostError::Invalid("not a form action".into())),
        },
    };
    let target = ActuationTarget {
        page_id: page.page_id.clone(),
        origin: page.origin.clone(),
        document_generation: document.document_generation,
        node_id: node_id.to_owned(),
        role: role.to_owned(),
        state,
        action: kind,
        workspace: live.workspace.clone(),
        policy_revision: live.policy_revision,
    };
    let approval = ApprovalToken {
        approval_id: record_id.to_owned(),
        target_digest: target_digest(&target),
        workspace: live.workspace.clone(),
        policy_revision: live.policy_revision,
        consumed: false,
    };
    Ok((target, approval))
}

/// Start a fixture lifetime (test builds): the loopback fixture origin,
/// trusting exactly its certificate.
#[cfg(feature = "live-browser-test")]
fn open_fixture(
    args: &WorkerHostArgs,
    workspace: &str,
    policy_revision: u64,
    host: &str,
    fixture_spki: &str,
) -> Result<(Lifetime, WorkerHostReply), HostError> {
    crate::observation::validate_identity_field(workspace)?;
    if fixture_spki.len() != 44
        || !fixture_spki
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
    {
        return Err(HostError::Invalid(
            "fixture certificate hash is malformed".into(),
        ));
    }
    let destination = AdmittedDestination::fixture(host, IpAddr::V4(Ipv4Addr::LOCALHOST))?;
    open(
        args,
        workspace,
        policy_revision,
        destination,
        Some(fixture_spki),
    )
}

/// Start a public lifetime (development builds): one HTTPS destination,
/// admitted from the host's own resolution under SG-000075 (public
/// addresses only, port 443, no IP literal), so the pin every later
/// binding names is the host's.
#[cfg(feature = "live-browser-dev")]
fn open_public(
    args: &WorkerHostArgs,
    workspace: &str,
    policy_revision: u64,
    url: &str,
    resolver: &impl crate::navigation::DnsResolver,
) -> Result<(Lifetime, WorkerHostReply), HostError> {
    crate::observation::validate_identity_field(workspace)?;
    // A public lifetime runs only a pinned runtime, in every build (a test
    // build's unpinned harness runtime serves only the fixture).
    if !args
        .runtime
        .as_ref()
        .is_some_and(|runtime| runtime.pin.is_some())
    {
        return Err(HostError::Unavailable(
            UnavailableReason::UnsupportedRuntime,
        ));
    }
    let destination = AdmittedDestination::admit(url, resolver)?;
    open(args, workspace, policy_revision, destination, None)
}

/// Start a lifetime: the host's own engine discovery (A10 re-verifies it at
/// launch), its own pid-named ephemeral profile (#298) carrying the A9
/// marker, and the admitted destination. Everything that can be refused
/// without a profile is refused first.
fn open(
    args: &WorkerHostArgs,
    workspace: &str,
    policy_revision: u64,
    destination: AdmittedDestination,
    fixture_spki: Option<&str>,
) -> Result<(Lifetime, WorkerHostReply), HostError> {
    let runtime = args.runtime.as_ref().ok_or(HostError::Unavailable(
        UnavailableReason::UnsupportedRuntime,
    ))?;
    // A development build runs only a pinned runtime (judge, PR #428): the
    // type allows `None` for test builds' harness runtime, never here.
    #[cfg(not(feature = "live-browser-test"))]
    if runtime.pin.is_none() {
        return Err(HostError::Unavailable(
            UnavailableReason::UnsupportedRuntime,
        ));
    }
    // A runtime that is not the pinned one is refused before the engine is
    // probed or a profile exists (judge, PR #428). The files stay held
    // until the worker holds them itself (`launch_worker` verifies again).
    #[cfg(windows)]
    let _held = match &runtime.pin {
        Some(pin) => Some(pin.verify_and_hold(&runtime.node, &runtime.worker_main)?),
        None => None,
    };
    let pin = destination.pin();
    let engine = discover_engine(&SearchConfig::production())?;
    let profile_dir = crate::worker_launch::ephemeral_profile_dir(&args.profile_root)?;
    // From here until the worker owns the profile, any failure removes it:
    // the #298 sweep never collects this host's own profiles while it runs.
    let launched = launch_in(
        args,
        runtime,
        &profile_dir,
        engine,
        destination,
        fixture_spki,
    );
    let (worker, profile_identity) = match launched {
        Ok(launched) => launched,
        Err(err) => {
            let _ = std::fs::remove_dir_all(&profile_dir);
            return Err(err);
        }
    };
    let nonce = match crate::worker_launch::lifetime_key() {
        Ok(nonce) => nonce,
        Err(err) => {
            let _ = worker.kill();
            return Err(err);
        }
    };
    let nonce = nonce[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok((
        Lifetime {
            worker,
            workspace: workspace.to_owned(),
            policy_revision,
            profile_identity,
            nonce: nonce.clone(),
            pin: pin.to_string(),
            observed: None,
            used_records: HashSet::new(),
        },
        WorkerHostReply::Opened {
            lifetime: nonce,
            pinned: pin.to_string(),
        },
    ))
}

/// Mark the fresh profile (A9: adopt-back proves the marker round-trips),
/// then launch the worker in it. A pinned runtime is verified and held by
/// `launch_worker` before anything is swept or spawned.
fn launch_in(
    args: &WorkerHostArgs,
    runtime: &WorkerRuntime,
    profile_dir: &Path,
    engine: crate::discovery::Engine,
    destination: AdmittedDestination,
    fixture_spki: Option<&str>,
) -> Result<(BrowserWorker, String), HostError> {
    #[cfg(not(feature = "live-browser-test"))]
    if fixture_spki.is_some() {
        return Err(HostError::Invalid(
            "fixture trust exists only in test builds".into(),
        ));
    }
    let profile = crate::profile::mark_profile(profile_dir, &engine.fingerprint())?;
    let profile = crate::profile::adopt_profile(profile.dir(), &engine.fingerprint())?;
    let spec = WorkerLaunch {
        node: runtime.node.clone(),
        worker_main: runtime.worker_main.clone(),
        engine,
        profile_dir: profile.dir().to_path_buf(),
        ephemeral_profile: true,
        temp_dir: args.temp_dir.clone(),
        destinations: vec![destination],
        #[cfg(any(test, feature = "live-browser-test"))]
        test_trusted_spki: fixture_spki.map(str::to_owned),
        runtime_pin: runtime.pin.clone(),
    };
    let worker = launch_worker(&spec, &crate::confinement::RegistryPolicySource)?;
    Ok((worker, profile.identity().to_owned()))
}

/// The host's own name resolution for `open_public`: the system resolver,
/// bounded in time (a resolver that never answers is a typed timeout).
#[cfg(feature = "live-browser-dev")]
struct HostResolver;

#[cfg(feature = "live-browser-dev")]
const RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

#[cfg(feature = "live-browser-dev")]
static RESOLUTIONS_IN_FLIGHT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// At most this many resolutions may be outstanding: one that timed out
/// keeps its thread until the system resolver returns.
#[cfg(feature = "live-browser-dev")]
const MAX_RESOLUTIONS_IN_FLIGHT: usize = 4;

#[cfg(feature = "live-browser-dev")]
impl crate::navigation::DnsResolver for HostResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, HostError> {
        use std::net::ToSocketAddrs;
        use std::sync::atomic::Ordering;
        if RESOLUTIONS_IN_FLIGHT.fetch_add(1, Ordering::SeqCst) >= MAX_RESOLUTIONS_IN_FLIGHT {
            RESOLUTIONS_IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
            return Err(HostError::Unavailable(UnavailableReason::TimedOut));
        }
        let (sender, answer) = std::sync::mpsc::channel();
        let name = host.to_owned();
        let spawned = std::thread::Builder::new()
            .name("orcel-host-resolve".into())
            .spawn(move || {
                // The slot is released however the resolution ends, a panic
                // included.
                struct Slot;
                impl Drop for Slot {
                    fn drop(&mut self) {
                        RESOLUTIONS_IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
                    }
                }
                let _slot = Slot;
                let resolved = (name.as_str(), port)
                    .to_socket_addrs()
                    .map(|addresses| addresses.map(|address| address.ip()).collect::<Vec<_>>());
                let _ = sender.send(resolved);
            });
        if spawned.is_err() {
            RESOLUTIONS_IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
            return Err(HostError::Unavailable(UnavailableReason::LaunchFailed));
        }
        let mut addresses = match answer.recv_timeout(RESOLVE_TIMEOUT) {
            Ok(Ok(addresses)) => addresses,
            Ok(Err(_)) => {
                return Err(HostError::Invalid(
                    "the destination name did not resolve".into(),
                ))
            }
            Err(_) => return Err(HostError::Unavailable(UnavailableReason::TimedOut)),
        };
        addresses.sort();
        addresses.dedup();
        if addresses.is_empty() {
            return Err(HostError::Invalid(
                "the destination name resolved to no address".into(),
            ));
        }
        Ok(addresses)
    }
}

/// Observe the committed document; nodes are dropped from the end until the
/// reply fits one frame, and the reply then says it was truncated.
fn observe(live: &mut Lifetime) -> WorkerHostReply {
    let scope = ObservationScope {
        workspace: live.workspace.clone(),
        profile_identity: live.profile_identity.clone(),
    };
    let observed = match live.worker.observe(&scope) {
        Ok(observed) => observed,
        Err(err) => {
            live.observed = None;
            return refusal(&err);
        }
    };
    live.observed = Some((observed.page.clone(), observed.document.clone()));
    let mut nodes: Vec<WireNode> = observed
        .observation
        .nodes
        .iter()
        .map(WireNode::from)
        .collect();
    attach_names(&mut nodes, &|id| live.worker.form_name(id));
    let mut truncated = observed.observation.truncated;
    loop {
        let reply = WorkerHostReply::Observed {
            page_id: observed.page.page_id.clone(),
            origin: observed.page.origin.clone(),
            page_generation: observed.page.page_generation,
            document_generation: observed.document.document_generation,
            nodes: nodes.clone(),
            node_count: observed.observation.node_count,
            truncated,
        };
        if crate::proto::encode_frame(&reply).is_ok() || nodes.is_empty() {
            if truncated {
                // Only nodes Orcel actually received can be acted on.
                let mut sent = HashSet::new();
                collect_ids(&nodes, &mut sent);
                live.worker.retain_host_nodes(&sent);
            }
            return reply;
        }
        pop_last_leaf(&mut nodes);
        truncated = true;
    }
}

/// SG-000122 slice A5: each node `name_of` names (the host's record of a
/// main-frame form control's name) carries it, bounded.
fn attach_names<'a>(nodes: &mut [WireNode], name_of: &dyn Fn(&str) -> Option<&'a str>) {
    for node in nodes {
        node.untrusted_name = name_of(&node.node_id).map(UntrustedName::new);
        attach_names(&mut node.children, name_of);
    }
}

/// Drop the last node in depth-first order that has no children, so a
/// trimmed reply keeps the largest prefix of the tree (dropping a whole
/// top-level subtree could empty a page whose content sits under one root).
fn pop_last_leaf(nodes: &mut Vec<WireNode>) {
    if let Some(last) = nodes.last_mut() {
        if last.children.is_empty() {
            nodes.pop();
        } else {
            pop_last_leaf(&mut last.children);
        }
    }
}

fn collect_ids(nodes: &[WireNode], into: &mut HashSet<String>) {
    for node in nodes {
        into.insert(node.node_id.clone());
        collect_ids(&node.children, into);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_vocabulary_is_closed_and_round_trips() {
        for frame in [
            r#"{"frame":"navigate","url":"https://fixture.test/","extra":1}"#,
            r#"{"frame":"navigate","url":"https://fixture.test/"}"#,
            r#"{"frame":"evaluate","script":"1"}"#,
            r#"{"frame":"shutdown","now":true}"#,
            r#"{"frame":"bind","action":{"kind":"fill","node_id":"d1-e2","role":"textbox"}}"#,
            r#"{"frame":"bind","action":{"kind":"click","node_id":"d1-e2","role":"link","selector":"a"}}"#,
        ] {
            assert!(
                serde_json::from_str::<WorkerHostRequest>(frame).is_err(),
                "{frame}"
            );
        }
        #[allow(unused_mut)] // extended per build
        let mut requests = vec![WorkerHostRequest::Bind {
            action: BindAction::Download {
                node_id: "d1-e2".into(),
                role: "link".into(),
                folder: "C:\\approved".into(),
                relative: "r.pdf".into(),
            },
        }];
        #[cfg(feature = "live-browser-test")]
        requests.push(WorkerHostRequest::Open {
            workspace: "w".into(),
            policy_revision: 7,
            host: "fixture.test".into(),
            fixture_spki: "A".repeat(43) + "=",
        });
        #[cfg(feature = "live-browser-dev")]
        requests.push(WorkerHostRequest::OpenPublic {
            workspace: "w".into(),
            policy_revision: 7,
            url: "https://example.org/reports".into(),
        });
        for request in requests {
            let text = serde_json::to_string(&request).unwrap();
            assert_eq!(
                serde_json::from_str::<WorkerHostRequest>(&text).unwrap(),
                request
            );
        }
    }

    /// SG-000122: the form, wait and verify frames are closed: only the four
    /// form kinds, Enter without a key, one select label, no hover and no
    /// other key; each round-trips.
    #[test]
    fn sg122_the_form_vocabulary_is_closed_and_round_trips() {
        assert_eq!(WORKER_HOST_GENERATION, 7);
        assert_eq!(OBSERVATION_CONTRACT, 2);
        // SG-000122 slice A6: the reply names what happened to the document,
        // from a closed vocabulary.
        for (text, navigation) in [
            (
                r#"{"frame":"form_done","url":"https://fixture.test/form","navigation":"none"}"#,
                FormNavigation::None,
            ),
            (
                r#"{"frame":"form_done","url":"https://fixture.test/order","navigation":"document_committed"}"#,
                FormNavigation::DocumentCommitted,
            ),
        ] {
            let reply: WorkerHostReply = serde_json::from_str(text).expect(text);
            assert!(
                matches!(reply, WorkerHostReply::FormDone { navigation: n, .. } if n == navigation),
                "{text}"
            );
            assert_eq!(serde_json::to_string(&reply).expect("json"), text);
        }
        for text in [
            r#"{"frame":"form_done","url":"u"}"#,
            r#"{"frame":"form_done","url":"u","navigation":"elsewhere"}"#,
        ] {
            assert!(
                serde_json::from_str::<WorkerHostReply>(text).is_err(),
                "{text}"
            );
        }
        for frame in [
            r#"{"frame":"form_action","action":{"kind":"press_enter","node_id":"d1-e2","role":"textbox","key":"Tab"},"record_id":"r","binding":"b"}"#,
            r#"{"frame":"form_action","action":{"kind":"press","node_id":"d1-e2","role":"textbox","key":"Enter"},"record_id":"r","binding":"b"}"#,
            r#"{"frame":"form_action","action":{"kind":"hover","node_id":"d1-e2","role":"link"},"record_id":"r","binding":"b"}"#,
            r#"{"frame":"form_action","action":{"kind":"select","node_id":"d1-e2","role":"combobox","labels":["a","b"]},"record_id":"r","binding":"b"}"#,
            r#"{"frame":"form_action","action":{"kind":"fill","node_id":"d1-e2","role":"textbox","value":"x"},"record_id":"r"}"#,
            r#"{"frame":"form_action","action":{"kind":"check","node_id":"d1-e2","role":"checkbox","checked":"true"},"record_id":"r","binding":"b"}"#,
            r#"{"frame":"bind","action":{"kind":"fill","node_id":"d1-e2","role":"textbox","value":"x","accept_confirm":"ok"}}"#,
            r#"{"frame":"wait_text","text":"Saved","appear":true}"#,
            r#"{"frame":"wait_text","text":"Saved","appear":true,"timeout_ms":100,"frame_id":1}"#,
            r#"{"frame":"verify","checks":[{"kind":"text_visible","text":"x","frame":"f1"}]}"#,
            r#"{"frame":"verify","checks":[{"kind":"script","source":"1"}]}"#,
        ] {
            assert!(
                serde_json::from_str::<WorkerHostRequest>(frame).is_err(),
                "{frame}"
            );
        }
        let actions = [
            BindAction::Fill {
                node_id: "d1-e2".into(),
                role: "textbox".into(),
                value: "Ada".into(),
            },
            BindAction::Select {
                node_id: "d1-e3".into(),
                role: "combobox".into(),
                label: "Porto".into(),
            },
            BindAction::Check {
                node_id: "d1-e4".into(),
                role: "checkbox".into(),
                checked: true,
            },
            BindAction::PressEnter {
                node_id: "d1-e5".into(),
                role: "searchbox".into(),
            },
        ];
        let mut requests: Vec<WorkerHostRequest> = actions
            .iter()
            .map(|action| WorkerHostRequest::FormAction {
                action: action.clone(),
                record_id: "r1".into(),
                binding: "b".into(),
            })
            .collect();
        requests.push(WorkerHostRequest::WaitText {
            text: "Saved".into(),
            appear: true,
            timeout_ms: 500,
        });
        requests.push(WorkerHostRequest::Verify {
            checks: vec![crate::verify::Postcondition::TextVisible {
                text: "Saved".into(),
            }],
        });
        for request in requests {
            let text = serde_json::to_string(&request).unwrap();
            assert_eq!(
                serde_json::from_str::<WorkerHostRequest>(&text).unwrap(),
                request
            );
        }
        assert_eq!(
            serde_json::to_string(&actions[3]).unwrap(),
            r#"{"kind":"press_enter","node_id":"d1-e5","role":"searchbox"}"#
        );
        // Each form kind maps to exactly its live input.
        assert_eq!(
            form_input(&actions[1]).map(|(_, _, input)| input),
            Some(FormInput::Select {
                labels: vec!["Porto".into()]
            })
        );
        assert_eq!(
            form_input(&actions[3]).map(|(_, _, input)| input),
            Some(FormInput::Enter)
        );
        assert!(form_input(&BindAction::Navigate {
            url: "https://fixture.test/".into()
        })
        .is_none());
        let reply = WorkerHostReply::Verified {
            url: "https://fixture.test/form-page".into(),
            document_generation: 3,
            results: vec![WireCheck {
                index: 0,
                kind: "text_visible".into(),
                passed: false,
                evidence: "visible matches: 0".into(),
            }],
            verified: false,
            evidence_sha256: "0".repeat(64),
        };
        let text = serde_json::to_string(&reply).unwrap();
        assert_eq!(
            serde_json::from_str::<WorkerHostReply>(&text).unwrap(),
            reply
        );
    }

    /// SG-000122: what the host can refuse from the request alone is refused
    /// before a lifetime is even looked at, so never reaches a worker: an
    /// escaped or too long fill value, a non-form action in a form frame, an
    /// empty or multi-line awaited text, a timeout out of range, malformed
    /// postconditions. Well-formed frames go on (here: no lifetime).
    #[test]
    fn sg122_requests_the_host_can_refuse_alone_never_reach_a_worker() {
        let args = WorkerHostArgs {
            host_id: "h".into(),
            runtime: None,
            profile_root: std::env::temp_dir(),
            temp_dir: std::env::temp_dir(),
        };
        let fill = |value: &str| BindAction::Fill {
            node_id: "d1-e2".into(),
            role: "textbox".into(),
            value: value.into(),
        };
        let form = |action: BindAction| WorkerHostRequest::FormAction {
            action,
            record_id: "r1".into(),
            binding: "b".into(),
        };
        let wait = |text: &str, timeout_ms: u64| WorkerHostRequest::WaitText {
            text: text.into(),
            appear: true,
            timeout_ms,
        };
        let refused = vec![
            form(fill("a\u{202e}b")),
            form(fill("a\u{200b}b")),
            form(fill("tab\there")),
            form(fill(&"a".repeat(1025))),
            form(fill(&("\\".repeat(512) + "a"))),
            form(BindAction::Select {
                node_id: "d1-e3".into(),
                role: "combobox".into(),
                label: String::new(),
            }),
            form(BindAction::Click {
                node_id: "d1-e2".into(),
                role: "link".into(),
            }),
            form(BindAction::Navigate {
                url: "https://fixture.test/".into(),
            }),
            WorkerHostRequest::Bind {
                action: fill("line\nbreak"),
            },
            wait("", 100),
            wait("two\nlines", 100),
            wait(&"x".repeat(crate::verify::MAX_VERIFY_TEXT_BYTES + 1), 100),
            wait("Saved", 0),
            wait("Saved", crate::worker_launch::MAX_WAIT_MS + 1),
            WorkerHostRequest::Verify { checks: Vec::new() },
            WorkerHostRequest::Verify {
                checks: vec![crate::verify::Postcondition::TextVisible {
                    text: String::new(),
                }],
            },
        ];
        let accepted = vec![
            form(fill("C:\\temp\\notes")),
            form(fill(&"a".repeat(1024))),
            form(BindAction::PressEnter {
                node_id: "d1-e5".into(),
                role: "searchbox".into(),
            }),
            wait("Saved", crate::worker_launch::MAX_WAIT_MS),
            WorkerHostRequest::Verify {
                checks: vec![crate::verify::Postcondition::TextVisible {
                    text: "Saved".into(),
                }],
            },
        ];
        let mut bytes = crate::proto::encode_frame(&WorkerHostRequest::Hello {
            generation: WORKER_HOST_GENERATION,
        })
        .unwrap();
        for request in refused.iter().chain(accepted.iter()) {
            bytes.extend(crate::proto::encode_frame(request).unwrap());
        }
        bytes.extend(crate::proto::encode_frame(&WorkerHostRequest::Shutdown {}).unwrap());
        let mut out = Vec::new();
        assert!(serve_worker_mode(&args, &mut bytes.as_slice(), &mut out).is_ok());
        let mut replies = out.as_slice();
        assert!(matches!(
            decode_frame::<WorkerHostReply, _>(&mut replies).unwrap(),
            WorkerHostReply::Hello { .. }
        ));
        for request in &refused {
            assert_eq!(
                decode_frame::<WorkerHostReply, _>(&mut replies).unwrap(),
                WorkerHostReply::Error {
                    code: "invalid".into()
                },
                "{request:?}"
            );
        }
        for request in &accepted {
            assert_eq!(
                decode_frame::<WorkerHostReply, _>(&mut replies).unwrap(),
                WorkerHostReply::Error {
                    code: "no_lifetime".into()
                },
                "{request:?}"
            );
        }
        assert_eq!(
            decode_frame::<WorkerHostReply, _>(&mut replies).unwrap(),
            WorkerHostReply::Bye {}
        );
    }

    /// SG-000122 slice A2: a form bind reply carries the prompt's facts
    /// (role, bounded name, ordinal) and the binding material covers the full
    /// name and the ordinal; other binds carry none, unchanged on the wire.
    #[test]
    fn sg122_form_binds_carry_bound_prompt_facts() {
        let plain = WorkerHostReply::Bound {
            binding: "b".into(),
            target: "https://fixture.test/".into(),
            form: None,
        };
        assert_eq!(
            serde_json::to_string(&plain).unwrap(),
            r#"{"frame":"bound","binding":"b","target":"https://fixture.test/"}"#
        );
        let long = "n".repeat(300);
        let facts = BoundForm::new("textbox", &long, Some((2, 3)));
        assert_eq!(facts.name.len(), 256);
        assert!(facts.name_cut);
        let reply = WorkerHostReply::Bound {
            binding: "b".into(),
            target: "https://fixture.test/".into(),
            form: Some(facts.clone()),
        };
        let text = serde_json::to_string(&reply).unwrap();
        assert_eq!(
            serde_json::from_str::<WorkerHostReply>(&text).unwrap(),
            reply
        );
        // The material moves with the full name and with the ordinal.
        let other_name = format!("{long}x");
        assert_ne!(facts.material(&long), facts.material(&other_name));
        let moved = BoundForm::new("textbox", &long, Some((3, 3)));
        assert_ne!(facts.material(&long), moved.material(&long));
        let alone = BoundForm::new("textbox", &long, None);
        assert_ne!(facts.material(&long), alone.material(&long));
        assert!(alone.material(&long).ends_with("\n-"));
        assert!(serde_json::from_str::<BoundForm>(
            r#"{"role":"textbox","name":"x","name_cut":false,"value":"y"}"#
        )
        .is_err());
    }

    #[test]
    fn errors_cross_as_closed_codes_without_text() {
        assert_eq!(
            error_code(&HostError::Invalid(
                "https://secret.example/?q=page text".into()
            )),
            "invalid"
        );
        assert!(error_code(&HostError::Unavailable(
            UnavailableReason::UnsupportedEngine
        ))
        .starts_with("unavailable:"));
        // SG-000122: the text cap has its own closed code.
        assert_eq!(
            error_code(&HostError::Unavailable(UnavailableReason::TextLimitReached)),
            "unavailable:textlimitreached"
        );
        // SG-000122 slice A6: and so does a refused Enter submission.
        assert_eq!(
            error_code(&HostError::Unavailable(
                UnavailableReason::SubmissionRefused
            )),
            "unavailable:submissionrefused"
        );
    }

    #[test]
    fn frames_before_hello_or_of_another_generation_end_the_host() {
        let args = WorkerHostArgs {
            host_id: "h".into(),
            runtime: Some(WorkerRuntime {
                node: PathBuf::from("node.exe"),
                worker_main: PathBuf::from("main.js"),
                pin: None,
            }),
            profile_root: std::env::temp_dir(),
            temp_dir: std::env::temp_dir(),
        };
        let frames = |requests: &[WorkerHostRequest]| {
            let mut bytes = Vec::new();
            for request in requests {
                bytes.extend(crate::proto::encode_frame(request).unwrap());
            }
            bytes
        };
        let mut out = Vec::new();
        let early = frames(&[WorkerHostRequest::Observe {}]);
        assert!(serve_worker_mode(&args, &mut early.as_slice(), &mut out).is_err());
        for old in [1, 2, 3, 4] {
            let wrong = frames(&[WorkerHostRequest::Hello { generation: old }]);
            assert!(serve_worker_mode(&args, &mut wrong.as_slice(), &mut out).is_err());
        }
        // Before a lifetime: typed refusals, then a clean shutdown.
        let mut out = Vec::new();
        let ok = frames(&[
            WorkerHostRequest::Hello {
                generation: WORKER_HOST_GENERATION,
            },
            WorkerHostRequest::Navigate {
                url: "https://fixture.test/".into(),
                record_id: "r1".into(),
                binding: "b".into(),
            },
            WorkerHostRequest::Bind {
                action: BindAction::Navigate {
                    url: "https://fixture.test/".into(),
                },
            },
            WorkerHostRequest::Shutdown {},
        ]);
        assert!(serve_worker_mode(&args, &mut ok.as_slice(), &mut out).is_ok());
        let mut replies = out.as_slice();
        assert!(matches!(
            decode_frame::<WorkerHostReply, _>(&mut replies).unwrap(),
            WorkerHostReply::Hello {
                generation: WORKER_HOST_GENERATION,
                ..
            }
        ));
        for _ in 0..2 {
            assert_eq!(
                decode_frame::<WorkerHostReply, _>(&mut replies).unwrap(),
                WorkerHostReply::Error {
                    code: "no_lifetime".into()
                }
            );
        }
        assert_eq!(
            decode_frame::<WorkerHostReply, _>(&mut replies).unwrap(),
            WorkerHostReply::Bye {}
        );
    }

    #[test]
    fn a_binding_changes_with_every_part_it_binds() {
        let material = "navigate\nhttps://fixture.test/\n127.0.0.1";
        let reference = binding_digest("n1", "w", 1, material);
        for other in [
            binding_digest("n2", "w", 1, material),
            binding_digest("n1", "v", 1, material),
            binding_digest("n1", "w", 2, material),
            binding_digest("n1", "w", 1, "navigate\nhttps://fixture.test/x\n127.0.0.1"),
        ] {
            assert_ne!(reference, other);
        }
        assert_eq!(reference, binding_digest("n1", "w", 1, material));
        assert_eq!(reference.len(), 64);
    }

    #[test]
    fn trimming_drops_the_last_leaf_first() {
        let node = |id: &str, children: Vec<WireNode>| WireNode {
            node_id: id.into(),
            role: "list".into(),
            name_digest: String::new(),
            value_digest: String::new(),
            redacted: false,
            children,
            untrusted_name: None,
        };
        let mut nodes = vec![node(
            "root",
            vec![node("a", Vec::new()), node("b", Vec::new())],
        )];
        pop_last_leaf(&mut nodes);
        let mut ids = HashSet::new();
        collect_ids(&nodes, &mut ids);
        assert_eq!(ids, HashSet::from(["root".to_string(), "a".to_string()]));
        pop_last_leaf(&mut nodes);
        pop_last_leaf(&mut nodes);
        assert!(nodes.is_empty());
    }

    #[test]
    fn only_sent_node_ids_are_collected() {
        let leaf = |id: &str| WireNode {
            node_id: id.into(),
            role: "link".into(),
            name_digest: String::new(),
            value_digest: String::new(),
            redacted: false,
            children: Vec::new(),
            untrusted_name: None,
        };
        let mut parent = leaf("a");
        parent.children.push(leaf("b"));
        let mut ids = HashSet::new();
        collect_ids(&[parent, leaf("c")], &mut ids);
        assert_eq!(ids.len(), 3);
        assert!(ids.contains("b"));
    }

    /// SG-000122 slice A5: observation contract 2. A node carries the name
    /// the host recorded for it, cut by the host to 256 bytes on a character
    /// boundary and marked; every other node carries none, and a contract 1
    /// node (no `untrusted_name`) still decodes, unchanged on the wire.
    #[test]
    fn sg122_a5_names_cross_bounded_and_only_where_the_host_recorded_one() {
        let leaf = |id: &str| WireNode {
            node_id: id.into(),
            role: "textbox".into(),
            name_digest: "d".into(),
            value_digest: "v".into(),
            redacted: false,
            children: Vec::new(),
            untrusted_name: None,
        };
        let long = format!("a{}", "é".repeat(200));
        let mut parent = leaf("d1-e1");
        parent.children.push(leaf("d1-e2"));
        let mut nodes = vec![parent, leaf("d1-e3")];
        let names = |id: &str| match id {
            "d1-e2" => Some("City"),
            "d1-e3" => Some(long.as_str()),
            _ => None,
        };
        attach_names(&mut nodes, &names);
        assert_eq!(nodes[0].untrusted_name, None);
        assert_eq!(
            nodes[0].children[0].untrusted_name,
            Some(UntrustedName {
                text: "City".into(),
                cut: false
            })
        );
        let cut = nodes[1].untrusted_name.clone().expect("a cut name");
        assert!(cut.cut && cut.text.len() == 255 && long.starts_with(&cut.text));
        let at_bound = "x".repeat(256);
        assert_eq!(
            UntrustedName::new(&at_bound),
            UntrustedName {
                text: at_bound.clone(),
                cut: false
            }
        );
        assert!(UntrustedName::new(&format!("{at_bound}y")).cut);
        // Contract 1 and 2 agree on every node without a name.
        let old = r#"{"node_id":"d1-e3","role":"link","name_digest":"d","value_digest":"v","redacted":false,"children":[]}"#;
        let decoded: WireNode = serde_json::from_str(old).expect("a contract 1 node");
        assert_eq!(decoded.untrusted_name, None);
        assert_eq!(serde_json::to_string(&decoded).unwrap(), old);
        let named = serde_json::to_value(&nodes[0].children[0]).unwrap();
        assert_eq!(
            named["untrusted_name"],
            serde_json::json!({"text": "City", "cut": false})
        );
        // The name is closed: no other field rides along.
        let extra = r#"{"node_id":"d1-e3","role":"textbox","name_digest":"d","value_digest":"v","redacted":false,"children":[],"untrusted_name":{"text":"x","cut":false,"value":"y"}}"#;
        assert!(serde_json::from_str::<WireNode>(extra).is_err());
    }

    /// A development build's vocabulary: the fixture `open` does not exist
    /// unless the build is also a test build.
    #[cfg(all(feature = "live-browser-dev", not(feature = "live-browser-test")))]
    #[test]
    fn a_development_build_has_no_fixture_open() {
        let frame = format!(
            r#"{{"frame":"open","workspace":"w","policy_revision":1,"host":"fixture.test","fixture_spki":"{}="}}"#,
            "A".repeat(43)
        );
        assert!(serde_json::from_str::<WorkerHostRequest>(&frame).is_err());
    }

    #[cfg(feature = "live-browser-dev")]
    struct FixedResolver(Vec<IpAddr>);

    #[cfg(feature = "live-browser-dev")]
    impl crate::navigation::DnsResolver for FixedResolver {
        fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>, HostError> {
            Ok(self.0.clone())
        }
    }

    /// Slice 3b-ii: a public open admits only an SG-000075 destination, and
    /// every refusal comes before any profile exists.
    #[cfg(feature = "live-browser-dev")]
    #[test]
    fn a_public_open_admits_only_public_https_and_refuses_before_any_profile() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let root =
            std::env::temp_dir().join(format!("orcel-open-public-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let with_runtime = |pin: Option<crate::runtime_pin::RuntimePin>| WorkerHostArgs {
            host_id: "h".into(),
            runtime: Some(WorkerRuntime {
                node: PathBuf::from("C:\\none\\node.exe"),
                worker_main: PathBuf::from("C:\\none\\dist\\main.js"),
                pin,
            }),
            profile_root: root.clone(),
            temp_dir: root.clone(),
        };
        let pinned = crate::runtime_pin::RuntimePin {
            node_sha256: "0".repeat(64),
            tree_sha256: "0".repeat(64),
        };
        let args = |runtime: bool| {
            if runtime {
                with_runtime(Some(pinned.clone()))
            } else {
                WorkerHostArgs {
                    runtime: None,
                    ..with_runtime(None)
                }
            }
        };
        // An unpinned runtime never serves a public lifetime, in any build.
        assert_eq!(
            match open_public(
                &with_runtime(None),
                "w",
                1,
                "https://example.org/",
                &FixedResolver(Vec::new())
            ) {
                Ok(_) => "opened".to_string(),
                Err(err) => error_code(&err),
            },
            "unavailable:unsupportedruntime"
        );
        let public = FixedResolver(vec!["93.184.215.14".parse().unwrap()]);
        let code = |result: Result<(Lifetime, WorkerHostReply), HostError>| match result {
            Ok(_) => "opened".to_string(),
            Err(err) => error_code(&err),
        };
        // No runtime the build may run: typed, before resolution.
        assert_eq!(
            code(open_public(
                &args(false),
                "w",
                1,
                "https://example.org/",
                &public
            )),
            "unavailable:unsupportedruntime"
        );
        for url in [
            "http://example.org/",
            "https://example.org:8443/",
            "https://93.184.215.14/",
            "https://localhost/",
            "https://user@example.org/",
            "file:///C:/Windows/win.ini",
            "javascript:alert(1)",
            "https://metadata.google.internal/",
        ] {
            assert_eq!(
                code(open_public(&args(true), "w", 1, url, &public)),
                "invalid",
                "{url}"
            );
        }
        for private in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "192.168.1.1",
            "::1",
            "fd00::1",
        ] {
            let resolver = FixedResolver(vec![private.parse().unwrap()]);
            assert_eq!(
                code(open_public(
                    &args(true),
                    "w",
                    1,
                    "https://example.org/",
                    &resolver
                )),
                "invalid",
                "{private}"
            );
        }
        // A malformed workspace is refused before anything else.
        assert_eq!(
            code(open_public(
                &args(true),
                "",
                1,
                "https://example.org/",
                &public
            )),
            "invalid"
        );
        assert_eq!(
            std::fs::read_dir(&root).unwrap().count(),
            0,
            "a refused open left something behind"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
