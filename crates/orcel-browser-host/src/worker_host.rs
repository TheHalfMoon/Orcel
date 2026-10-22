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

use crate::actuation::{target_digest, ActuationTarget, ApprovalToken, SupportedAction};
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
/// and download, and binds navigation; 4 adds `open_public` (slice 3b-ii).
pub const WORKER_HOST_GENERATION: u32 = 4;

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
    /// End the current lifetime (profile removed); the host keeps serving.
    Close {},
    Shutdown {},
}

/// One observed node as it crosses to Orcel: identities and digests only.
/// Raw names and values never leave the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireNode {
    pub node_id: String,
    pub role: String,
    pub name_digest: String,
    pub value_digest: String,
    pub redacted: bool,
    pub children: Vec<WireNode>,
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
            other => match lifetime.as_mut() {
                None => error("no_lifetime"),
                Some(live) => in_lifetime(live, other),
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

/// Frames that need a live lifetime.
fn in_lifetime(live: &mut Lifetime, request: WorkerHostRequest) -> WorkerHostReply {
    match request {
        WorkerHostRequest::Bind { action } => match host_binding(live, &action) {
            Ok(derived) => WorkerHostReply::Bound {
                binding: derived.binding,
                target: derived.target,
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
}

/// The host's half of an approval, from its own state now.
fn host_binding(live: &Lifetime, action: &BindAction) -> Result<Derived, HostError> {
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
        BindAction::Click { node_id, role } => (node_id, role, SupportedAction::Click),
        BindAction::Download { node_id, role, .. } => (node_id, role, SupportedAction::Download),
        BindAction::Navigate { .. } => {
            return Err(HostError::Invalid(
                "navigation takes no actuation target".into(),
            ))
        }
    };
    let target = ActuationTarget {
        page_id: page.page_id.clone(),
        origin: page.origin.clone(),
        document_generation: document.document_generation,
        node_id: node_id.clone(),
        role: role.clone(),
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
    if args.runtime.is_none() {
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
impl crate::navigation::DnsResolver for HostResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, HostError> {
        use std::net::ToSocketAddrs;
        let (sender, answer) = std::sync::mpsc::channel();
        let name = host.to_owned();
        std::thread::spawn(move || {
            let resolved = (name.as_str(), port)
                .to_socket_addrs()
                .map(|addresses| addresses.map(|address| address.ip()).collect::<Vec<_>>());
            let _ = sender.send(resolved);
        });
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
        for old in [1, 2] {
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
        };
        let mut parent = leaf("a");
        parent.children.push(leaf("b"));
        let mut ids = HashSet::new();
        collect_ids(&[parent, leaf("c")], &mut ids);
        assert_eq!(ids.len(), 3);
        assert!(ids.contains("b"));
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
        let args = |runtime: bool| WorkerHostArgs {
            host_id: "h".into(),
            runtime: runtime.then(|| WorkerRuntime {
                node: PathBuf::from("C:\\none\\node.exe"),
                worker_main: PathBuf::from("C:\\none\\dist\\main.js"),
                pin: None,
            }),
            profile_root: root.clone(),
            temp_dir: root.clone(),
        };
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
