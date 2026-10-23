//! SG-000108 host launcher for the private browser worker.
//!
//! The host owns everything that grants authority: it checks the managed
//! policy precondition, builds the worker's environment from an allowlist
//! (never inherited), builds the engine argv (`build_worker_argv`), starts
//! Node with exactly `--disable-sigusr1` and the worker entry point inside a
//! kill-on-close Job Object with restricted handle inheritance, drives the
//! closed worker protocol with bounded waits, and then verifies the job: the
//! only members are the worker and the verified engine, exactly one browser
//! process exists, and its OS command line equals the host-built argv.
//! Every failure is typed; supervision ending always terminates the job and
//! removes an ephemeral profile.

use crate::argv::FORBIDDEN_FLAGS;
#[cfg(windows)]
use crate::confinement::build_worker_argv;
use crate::confinement::{assert_no_managed_policy, AdmittedDestination, PolicySource};
use crate::discovery::Engine;
use crate::error::{HostError, UnavailableReason};
use crate::supervise::{CleanEnv, JOB_ACTIVE_PROCESS_LIMIT};
#[cfg(any(windows, test))]
use serde::{Deserialize, Serialize};
#[cfg(any(windows, test))]
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// One process inside the worker's job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobProcess {
    pub pid: u32,
    pub image: PathBuf,
    /// The OS-reported command line split with `CommandLineToArgvW`.
    pub argv: Vec<String>,
}

/// Worker protocol generation (apps/orcel-browser-worker/src/protocol.ts).
/// Generation 2 adds the slice-3a navigation frames, generation 3 slice-3b
/// observation, generation 4 slice-3c activation, generation 5 slice-3d
/// downloads.
pub const WORKER_PROTOCOL_GENERATION: u32 = 9;
/// Worker identity reported in its hello.
pub const WORKER_IDENTITY: &str = "orcel-browser-worker";
/// The only Node option the worker accepts (inspector activation refused).
pub const WORKER_NODE_OPTION: &str = "--disable-sigusr1";

/// Bounded waits owned by the launcher.
pub const WORKER_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
pub const WORKER_LAUNCH_TIMEOUT: Duration = Duration::from_secs(60);
pub const WORKER_REPLY_TIMEOUT: Duration = Duration::from_secs(10);
pub const WORKER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
/// Upper bound for one navigation, including every route decision.
pub const WORKER_NAVIGATION_TIMEOUT: Duration = Duration::from_secs(45);

/// Upper bound for one activation (above the worker's worst case: a 5 s
/// click, 30 s for the navigation and 30 s for its load).
pub const WORKER_ACTIVATION_TIMEOUT: Duration = Duration::from_secs(75);

/// Upper bound for one tool execution (above the worker's worst case: 10 s
/// filling, a 5 s click, 30 s for the navigation, 30 s for its load and a
/// 3 s result snapshot).
pub const WORKER_EXECUTION_TIMEOUT: Duration = Duration::from_secs(90);

/// Upper bound for one observation round trip.
pub const WORKER_OBSERVATION_TIMEOUT: Duration = Duration::from_secs(10);

/// Upper bound for an extraction's first piece (above the worker's worst
/// case: a 5 s layout snapshot and a 4 s extraction budget). Later pieces
/// are already computed and take `WORKER_REPLY_TIMEOUT` each.
pub const WORKER_EXTRACTION_TIMEOUT: Duration = Duration::from_secs(20);

/// One node of a worker snapshot: ref, role, accessible name and (links
/// only) the link URL. The worker never sends field values.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotNode {
    #[serde(rename = "ref")]
    pub reference: String,
    pub role: String,
    pub name: String,
    #[serde(default)]
    pub url: Option<String>,
    pub children: Vec<SnapshotNode>,
}

/// What the host keeps about an observed node for its own typed selection;
/// never returned to callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostNode {
    pub reference: String,
    pub role: String,
    pub name: String,
    pub url: Option<String>,
}

/// A live observation: SG-000076 identities and the redacted, digested
/// observation. Raw names stay inside the host.
#[derive(Debug, Clone)]
pub struct LiveObservation {
    pub page: crate::observation::PageIdentity,
    pub document: crate::observation::DocumentIdentity,
    pub observation: crate::observation::Observation,
}

/// A text document (#317: robots.txt, sitemaps) opened by a governed
/// navigation. Its text is untrusted page text, present only for
/// `text/plain` and XML and cut to one frame (`truncated`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedText {
    pub url: String,
    pub status: u16,
    pub media: String,
    pub text: crate::webmcp::PageText,
    pub truncated: bool,
}

/// The media types a text fetch returns content for (mirrors the worker):
/// text, XML, HTML and none at all.
pub const FETCH_TEXT_MEDIA: [&str; 5] =
    ["text/plain", "application/xml", "text/xml", "text/html", ""];
/// Characters of one fetched text (it fits one frame).
pub const MAX_FETCH_TEXT_CHARS: usize = 56 * 1024;

/// A download committed create-only into the approved folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedDownload {
    pub path: PathBuf,
    pub sha256: String,
    pub bytes: u64,
    pub source_url: String,
}

/// The outcome of an executed WebMCP declarative tool: the document the
/// submission opened, and the structured data (`application/ld+json`) it
/// carries, as untrusted page text.
#[derive(Debug, Clone, PartialEq)]
pub struct ExecutionOutcome {
    pub url: String,
    pub status: u16,
    pub document_generation: u64,
    pub structured: Vec<crate::webmcp::PageText>,
    /// Every structured block was read and kept (false when the snapshot
    /// failed or blocks were dropped to fit the reply).
    pub structured_complete: bool,
}

/// A completed top-level navigation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NavigationOutcome {
    pub url: String,
    pub status: u16,
}

/// Everything the launcher needs; every path must be absolute. `node` and
/// `worker_main` must come from Orcel's install records, never from a
/// caller; the engine can only be a [`Engine`] that discovery verified
/// (kind, version, publisher), so no unverified executable can be launched
/// under the confinement contract.
#[derive(Debug, Clone)]
pub struct WorkerLaunch {
    /// node.exe recorded at install (the worker itself refuses Node < 22.14).
    pub node: PathBuf,
    /// The worker entry point, `…/dist/main.js`.
    pub worker_main: PathBuf,
    /// The verified engine (from `discover_engine`).
    pub engine: Engine,
    /// The Orcel-owned profile directory.
    pub profile_dir: PathBuf,
    /// Remove the profile directory when supervision ends. Production uses
    /// a fresh ephemeral profile per lifetime; the launcher does not refuse
    /// `false` (the native crash test reuses a profile deliberately).
    pub ephemeral_profile: bool,
    /// TEMP/TMP for the worker and engine.
    pub temp_dir: PathBuf,
    /// Destinations admitted into this engine lifetime.
    pub destinations: Vec<AdmittedDestination>,
    /// SG-000108 decision 7: the runtime the build pinned. When set, launch
    /// verifies `node.exe` and the worker's runtime tree against it through
    /// handles that refuse writes and deletes, and holds them for the
    /// worker's lifetime; any difference refuses the launch.
    pub runtime_pin: Option<crate::runtime_pin::RuntimePin>,
    /// Test builds only: a fixture certificate's SPKI hash the engine
    /// trusts. The worker accepts it only with loopback fixture pins.
    #[cfg(any(test, feature = "live-browser-test"))]
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) test_trusted_spki: Option<String>,
}

/// How supervision ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShutdownReport {
    /// The worker answered `bye` and exited with code 0.
    pub graceful: bool,
    /// No process remained in the job afterwards.
    pub job_empty: bool,
    /// The ephemeral profile was removed. Always true for a non-ephemeral
    /// profile, which the launcher never removes (nothing was to be removed);
    /// for an ephemeral one, true only once the directory no longer exists.
    pub profile_removed: bool,
}

#[cfg(any(windows, test))]
#[derive(Debug, Serialize)]
#[serde(tag = "frame", rename_all = "snake_case")]
pub(crate) enum WorkerRequest<'a> {
    Hello {
        generation: u32,
    },
    Launch {
        engine: &'a str,
        profile_dir: &'a str,
        argv: &'a [String],
        env: BTreeMap<String, String>,
    },
    Ping {
        nonce: &'a str,
    },
    Navigate {
        nav_id: u64,
        url: &'a str,
    },
    FetchText {
        fetch_id: u64,
        url: &'a str,
    },
    RouteDecision {
        request_id: u64,
        allow: bool,
    },
    Observe {
        obs_id: u64,
    },
    Discover {
        disc_id: u64,
    },
    Extract {
        ext_id: u64,
        links: bool,
        images: bool,
    },
    ExtractMore {
        ext_id: u64,
        piece: u32,
    },
    Activate {
        act_id: u64,
        #[serde(rename = "ref")]
        reference: &'a str,
    },
    Download {
        dl_id: u64,
        #[serde(rename = "ref")]
        reference: &'a str,
        path: &'a str,
    },
    Execute {
        exec_id: u64,
        tool: &'a str,
        fields: &'a [crate::webmcp::ExecField],
    },
    Shutdown,
}

#[cfg(any(windows, test))]
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "frame", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum WorkerReply {
    Hello {
        generation: u32,
        worker: String,
    },
    // Empty struct variants: serde ignores unknown fields on unit
    // variants of an internally tagged enum even with deny_unknown_fields.
    Launched {},
    Pong {
        nonce: String,
    },
    Bye {},
    RouteRequest {
        request_id: u64,
        kind: String,
        url: String,
        origin: String,
        method: String,
        content_type: String,
        body: Option<String>,
        body_bytes: u64,
    },
    Navigated {
        nav_id: u64,
        url: String,
        status: u16,
    },
    NavigationFailed {
        nav_id: u64,
        reason: String,
    },
    FetchedText {
        fetch_id: u64,
        url: String,
        status: u16,
        media: String,
        text: String,
        truncated: bool,
    },
    FetchFailed {
        fetch_id: u64,
        reason: String,
    },
    Observed {
        obs_id: u64,
        url: String,
        truncated: bool,
        nodes: Vec<SnapshotNode>,
    },
    ObservationFailed {
        obs_id: u64,
    },
    Discovered {
        disc_id: u64,
        url: String,
        truncated: bool,
        tools: Vec<crate::webmcp::WireTool>,
    },
    DiscoveryFailed {
        disc_id: u64,
    },
    Extracted {
        ext_id: u64,
        url: String,
        truncated: bool,
        piece: u32,
        total: u32,
        chunk: u32,
        content: String,
    },
    ExtractionFailed {
        ext_id: u64,
    },
    Activated {
        act_id: u64,
        url: String,
        status: u16,
    },
    ActivationFailed {
        act_id: u64,
        reason: String,
    },
    Downloaded {
        dl_id: u64,
        url: String,
        name: String,
        media: String,
        bytes: u64,
    },
    DownloadFailed {
        dl_id: u64,
        reason: String,
    },
    Executed {
        exec_id: u64,
        url: String,
        status: u16,
        structured: Vec<String>,
        structured_complete: bool,
    },
    ExecutionFailed {
        exec_id: u64,
        reason: String,
    },
    Error {
        code: String,
    },
}

/// Map a worker error code onto the typed vocabulary.
#[cfg(any(windows, test))]
pub(crate) fn reply_error(code: &str) -> HostError {
    match code {
        "launch_refused" => HostError::Invalid("the worker refused the launch contract".into()),
        "launch_failed" | "engine_exited" => {
            HostError::Unavailable(UnavailableReason::LaunchFailed)
        }
        _ => HostError::Unavailable(UnavailableReason::ProtocolViolation),
    }
}

/// Largest profile preferences file the host will rewrite.
#[cfg(any(windows, test))]
const MAX_PREFERENCES_BYTES: u64 = 8 * 1024 * 1024;

/// Turn off preloading in the profile before the engine starts. Speculation
/// rules prefetch and prerender run in the browser process, outside every
/// route and redirect guard (measured: an undecided request to another
/// admitted name, and a prerender whose activation moved the page). No
/// engine switch tested disables them; the profile's "Preload pages: never"
/// preference (`net.network_prediction_options` = 2) does. Existing
/// preferences are kept; an unreadable or oversized file fails closed.
#[cfg(any(windows, test))]
pub(crate) fn seed_profile_preferences(profile_dir: &Path) -> Result<(), HostError> {
    let dir = profile_dir.join("Default");
    std::fs::create_dir_all(&dir)
        .map_err(|err| HostError::Platform(format!("profile preferences: {err}")))?;
    let path = dir.join("Preferences");
    let mut value = match std::fs::metadata(&path) {
        Ok(meta) if meta.len() > MAX_PREFERENCES_BYTES => {
            return Err(HostError::Invalid(
                "profile preferences are oversized".into(),
            ))
        }
        Ok(_) => {
            let text = std::fs::read_to_string(&path)
                .map_err(|err| HostError::Platform(format!("profile preferences: {err}")))?;
            serde_json::from_str::<serde_json::Value>(&text)
                .map_err(|_| HostError::Invalid("profile preferences are not JSON".into()))?
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => serde_json::json!({}),
        Err(err) => return Err(HostError::Platform(format!("profile preferences: {err}"))),
    };
    let root = value
        .as_object_mut()
        .ok_or_else(|| HostError::Invalid("profile preferences are not an object".into()))?;
    let net = root
        .entry("net")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .ok_or_else(|| HostError::Invalid("profile `net` preferences are not an object".into()))?;
    net.insert("network_prediction_options".into(), serde_json::json!(2));
    // PDFs are downloaded (never shown in the built-in viewer), so the host
    // can validate and commit them; a viewer would render page-supplied PDF.
    let plugins = root
        .entry("plugins")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .ok_or_else(|| {
            HostError::Invalid("profile `plugins` preferences are not an object".into())
        })?;
    plugins.insert("always_open_pdf_externally".into(), serde_json::json!(true));
    let text = serde_json::to_string(&value)
        .map_err(|err| HostError::Invalid(format!("profile preferences: {err}")))?;
    std::fs::write(&path, text)
        .map_err(|err| HostError::Platform(format!("profile preferences: {err}")))
}

/// Test builds only: the fixture certificate trust flag.
#[cfg(any(test, feature = "live-browser-test"))]
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn test_certificate_flag(spki: &str) -> String {
    format!("--ignore-certificate-errors-spki-list={spki}")
}

/// Map a worker snapshot node onto an SG-000076 input node with a
/// host-issued identity, recording the raw name host-side. The value is
/// always empty: the worker never sends field values. An accessible name can
/// still carry a field's text (for example a button labelled by a password
/// field through aria-labelledby), so the name entering SG-000076 is first
/// keyed with this lifetime's secret: the caller-visible digest cannot be
/// checked against guesses, and the raw name never leaves the host.
#[cfg(any(windows, test))]
pub(crate) fn input_node(
    node: &SnapshotNode,
    generation: u64,
    key: &[u8; 32],
    index: &mut std::collections::HashMap<String, HostNode>,
) -> crate::observation::InputNode {
    let node_id = format!("d{generation}-{}", node.reference);
    index.insert(
        node_id.clone(),
        HostNode {
            reference: node.reference.clone(),
            role: node.role.clone(),
            name: node.name.clone(),
            url: node.url.clone(),
        },
    );
    crate::observation::InputNode {
        identity: crate::observation::NodeIdentity {
            node_id,
            role: node.role.clone(),
            document_generation: generation,
        },
        role: node.role.clone(),
        name: keyed_name(key, &node.name),
        value: String::new(),
        children: node
            .children
            .iter()
            .map(|child| input_node(child, generation, key, index))
            .collect(),
    }
}

/// SHA-256 over this lifetime's key and the name (hex).
#[cfg(any(windows, test))]
pub(crate) fn keyed_name(key: &[u8; 32], name: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.update(name.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// #298: a new ephemeral profile directory under `root`, a directory the
/// caller owns: `orcel-sg108-profile-<this host's pid>-<random hex>`,
/// created here and new (an existing directory of that name is an error,
/// never reused). Launched with `ephemeral_profile: true`, it is removed
/// at the end of the lifetime and, if this host dies first, by the next
/// launch of a profile in the same root. Only names made here are swept;
/// any other profile under `root` is never touched. The host that launches
/// the profile must be the one that calls this: the name records the
/// caller's pid, so a profile handed to another process becomes sweepable
/// once its maker exits. `root` must be absolute.
#[cfg(windows)]
pub fn ephemeral_profile_dir(root: &Path) -> Result<PathBuf, HostError> {
    let random = lifetime_key()?;
    let profile = root.join(format!(
        "{}{}-{}",
        crate::leftovers::PROFILE_PREFIX,
        std::process::id(),
        random[..8]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ));
    std::fs::create_dir(&profile)
        .map_err(|err| HostError::Platform(format!("ephemeral profile: {err}")))?;
    Ok(profile)
}

/// A random per-lifetime key from the system RNG.
#[cfg(windows)]
pub(crate) fn lifetime_key() -> Result<[u8; 32], HostError> {
    use windows_sys::Win32::Security::Cryptography::{
        BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    };
    let mut key = [0u8; 32];
    // SAFETY: the buffer and length describe `key`; the system RNG needs no
    // algorithm handle with BCRYPT_USE_SYSTEM_PREFERRED_RNG.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            key.as_mut_ptr(),
            key.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status != 0 {
        return Err(HostError::Platform("system RNG unavailable".into()));
    }
    Ok(key)
}

/// Resolve an observed link URL against the committed document's origin:
/// absolute https URLs and root-relative paths only; anything else (relative
/// paths, other schemes, protocol-relative) is refused rather than guessed.
#[cfg(any(windows, test))]
pub(crate) fn resolve_link(committed_origin: &str, link: &str) -> Result<String, HostError> {
    let origin = crate::navigation::parse_navigation_url(committed_origin)?;
    let base = if origin.port == 443 {
        format!("https://{}", origin.host)
    } else {
        format!("https://{}:{}", origin.host, origin.port)
    };
    let resolved = if link.starts_with("https://") {
        link.to_owned()
    } else if link.starts_with('/') && !link.starts_with("//") {
        format!("{base}{link}")
    } else {
        return Err(HostError::Invalid("the link URL cannot be resolved".into()));
    };
    crate::navigation::parse_navigation_url(&resolved)?;
    Ok(resolved)
}

/// The observed link whose name carries the latest ISO date; ties and
/// pages without a dated link are refused.
#[cfg(any(windows, test))]
pub(crate) fn select_latest_dated_link(
    nodes: &std::collections::HashMap<String, HostNode>,
) -> Result<String, HostError> {
    // Bytes only: slicing the string at byte offsets would panic inside a
    // multi-byte character ("Café 2026-09-30").
    fn date_in(name: &str) -> Option<(u16, u8, u8)> {
        let bytes = name.as_bytes();
        if bytes.len() < 10 {
            return None;
        }
        let mut best = None;
        for window in bytes.windows(10) {
            let digits =
                |range: std::ops::Range<usize>| window[range].iter().all(u8::is_ascii_digit);
            if !(digits(0..4)
                && window[4] == b'-'
                && digits(5..7)
                && window[7] == b'-'
                && digits(8..10))
            {
                continue;
            }
            let number = |range: std::ops::Range<usize>| {
                window[range]
                    .iter()
                    .fold(0u32, |acc, digit| acc * 10 + u32::from(digit - b'0'))
            };
            let (year, month, day) = (number(0..4), number(5..7), number(8..10));
            if (1..=12).contains(&month) && (1..=31).contains(&day) {
                best = best.max(Some((year as u16, month as u8, day as u8)));
            }
        }
        best
    }
    let mut dated: Vec<((u16, u8, u8), &String)> = nodes
        .iter()
        .filter(|(_, node)| node.role == "link")
        .filter_map(|(id, node)| date_in(&node.name).map(|date| (date, id)))
        .collect();
    dated.sort();
    match dated.as_slice() {
        [] => Err(HostError::Invalid("no dated link on the page".into())),
        [.., (a, _), (b, _)] if a == b => {
            Err(HostError::Invalid("the latest date is ambiguous".into()))
        }
        [.., (_, id)] => Ok((*id).clone()),
    }
}

/// A per-lifetime suffix for host-owned directories.
#[cfg(any(windows, test))]
fn unique_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// Lowercase hex SHA-256.
#[cfg(any(windows, test))]
pub(crate) fn sha256_hex(content: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(content)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Write `content` create-only (an existing file is never replaced), then
/// verify through the real path that the file is inside `root`. A portable
/// model of the commit for unit tests off Windows; the product commit is
/// `approved_folder::commit`, which writes through held handles (#307).
#[cfg(all(test, not(windows)))]
pub(crate) fn commit_create_only(
    destination: &Path,
    root: &Path,
    content: &[u8],
) -> Result<(), HostError> {
    use std::io::Write;
    let parent = destination
        .parent()
        .ok_or_else(|| HostError::Invalid("destination has no folder".into()))?;
    let real_root = std::fs::canonicalize(root)
        .map_err(|err| HostError::Platform(format!("approved folder: {err}")))?;
    let relative_parent = parent
        .strip_prefix(root)
        .map_err(|_| HostError::Invalid("destination escapes the approved folder".into()))?;
    // Each folder is created only after its parent's real path is checked,
    // so a junction never gets anything created behind it.
    let mut folder = root.to_path_buf();
    for part in relative_parent.components() {
        folder.push(part);
        if !folder.exists() {
            let real_parent = folder
                .parent()
                .and_then(|p| std::fs::canonicalize(p).ok())
                .ok_or_else(|| HostError::Platform("destination folder".into()))?;
            if !real_parent.starts_with(&real_root) {
                return Err(HostError::Invalid(
                    "destination escapes the approved folder".into(),
                ));
            }
            std::fs::create_dir(&folder)
                .map_err(|err| HostError::Platform(format!("destination folder: {err}")))?;
        }
        match std::fs::canonicalize(&folder) {
            Ok(real) if real.starts_with(&real_root) => {}
            _ => {
                return Err(HostError::Invalid(
                    "destination escapes the approved folder".into(),
                ))
            }
        }
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|err| {
            if err.kind() == std::io::ErrorKind::AlreadyExists {
                HostError::Invalid("destination exists (create-only)".into())
            } else {
                HostError::Platform(format!("destination: {err}"))
            }
        })?;
    let written = file.write_all(content).and_then(|()| file.sync_all());
    drop(file);
    let contained = match (
        std::fs::canonicalize(destination),
        std::fs::canonicalize(root),
    ) {
        (Ok(real), Ok(real_root)) => real.starts_with(&real_root),
        _ => false,
    };
    if written.is_err() || !contained {
        let _ = std::fs::remove_file(destination);
        return Err(match written {
            Err(err) => HostError::Platform(format!("destination write: {err}")),
            Ok(()) => HostError::Invalid("destination escapes the approved folder".into()),
        });
    }
    Ok(())
}

/// What an approved submission of `tool` with `fields` may send.
#[cfg(any(windows, test))]
pub(crate) fn submission_of(
    tool: &crate::webmcp::DiscoveredTool,
    fields: &[crate::webmcp::ExecField],
    post: bool,
) -> crate::worker_navigation::Submission {
    use crate::webmcp::ControlKind;
    use crate::worker_navigation::Submitted;
    let submitted = fields
        .iter()
        .map(|field| {
            let expected = match field.control {
                ControlKind::Checkbox
                    if field.values.first().map(String::as_str) == Some("true") =>
                {
                    Submitted::Present
                }
                ControlKind::Checkbox => Submitted::Absent,
                _ => Submitted::Values(field.values.clone()),
            };
            (field.name.clone(), expected)
        })
        .collect();
    crate::worker_navigation::Submission {
        method: if post { "POST" } else { "GET" }.to_owned(),
        fields: submitted,
        unsupplied: tool
            .params
            .iter()
            .filter(|param| !fields.iter().any(|field| field.name == param.name))
            .map(|param| param.name.clone())
            .collect(),
        multiline: fields
            .iter()
            .filter(|field| field.control == ControlKind::Textarea)
            .map(|field| field.name.clone())
            .collect(),
        fixed: tool.fixed_names.clone(),
    }
}

/// Map a worker download failure onto the typed vocabulary (#307).
#[cfg(any(windows, test))]
pub(crate) fn download_failure(reason: &str) -> HostError {
    use crate::error::DownloadFailure;
    match reason {
        "http_status" => HostError::Download(DownloadFailure::HttpStatus),
        "oversized" => HostError::Download(DownloadFailure::Oversized),
        "timeout" => HostError::Download(DownloadFailure::TimedOut),
        "failed" => HostError::Download(DownloadFailure::EngineFailed),
        "busy" => HostError::Unavailable(UnavailableReason::ActionFailed),
        _ => HostError::Unavailable(UnavailableReason::ProtocolViolation),
    }
}

/// Map a worker navigation failure onto the typed vocabulary.
#[cfg(any(windows, test))]
pub(crate) fn navigation_failure(reason: &str) -> HostError {
    match reason {
        "denied" => HostError::Invalid("navigation denied by the browser policy".into()),
        "timeout" => HostError::Unavailable(UnavailableReason::TimedOut),
        "failed" | "busy" => HostError::Unavailable(UnavailableReason::ActionFailed),
        _ => HostError::Unavailable(UnavailableReason::ProtocolViolation),
    }
}

/// The worker's environment: an explicit allowlist, never inherited. Node
/// consumes variables such as NODE_OPTIONS before any worker code runs, so
/// nothing outside this list may reach it.
pub fn worker_environment(temp_dir: &Path) -> CleanEnv {
    let system_root =
        std::env::var_os("SystemRoot").unwrap_or_else(|| OsString::from("C:\\Windows"));
    let system_drive = std::env::var_os("SystemDrive").unwrap_or_else(|| OsString::from("C:"));
    let system32 = PathBuf::from(&system_root).join("System32");
    vec![
        (OsString::from("SystemRoot"), system_root),
        (OsString::from("SystemDrive"), system_drive),
        (OsString::from("PATH"), system32.into_os_string()),
        (OsString::from("TEMP"), temp_dir.as_os_str().to_owned()),
        (OsString::from("TMP"), temp_dir.as_os_str().to_owned()),
    ]
}

/// The worker's Node arguments: exactly the inspector guard and the entry.
pub fn worker_node_args(worker_main: &Path) -> Vec<String> {
    vec![
        WORKER_NODE_OPTION.to_string(),
        worker_main.to_string_lossy().into_owned(),
    ]
}

fn require_absolute(path: &Path, what: &str) -> Result<(), HostError> {
    if !path.is_absolute() {
        return Err(HostError::Invalid(format!(
            "{what} is not an absolute path"
        )));
    }
    Ok(())
}

fn file_name_is(path: &Path, expected: &str) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case(expected))
}

/// Validate the launch request before anything is spawned. A missing Node
/// or worker is a missing prerequisite (typed unavailable).
pub(crate) fn validate_launch(spec: &WorkerLaunch) -> Result<(), HostError> {
    // Exactly one destination per engine lifetime. The browser process
    // issues some requests outside every route and guard (measured:
    // fetchLater, Reporting/CSP reports, FedCM, audio worklet modules,
    // NoStatePrefetch). With a single admitted name, the pinned resolver and
    // the no-route proxy make every other host unreachable, so such requests
    // can reach only the page's own origin, which SG-000075 permits. The
    // policy is exact-origin anyway; another site is another lifetime.
    if spec.destinations.len() != 1 {
        return Err(HostError::Invalid(
            "a browser lifetime admits exactly one destination".into(),
        ));
    }
    for (path, what) in [
        (spec.node.as_path(), "node"),
        (&spec.worker_main, "worker entry point"),
        (spec.engine.path(), "engine"),
        (&spec.profile_dir, "profile directory"),
        (&spec.temp_dir, "temp directory"),
    ] {
        require_absolute(path, what)?;
    }
    if !file_name_is(&spec.node, "node.exe") || !spec.node.is_file() {
        return Err(HostError::Unavailable(
            UnavailableReason::UnsupportedRuntime,
        ));
    }
    if !file_name_is(&spec.worker_main, "main.js") || !spec.worker_main.is_file() {
        return Err(HostError::Unavailable(
            UnavailableReason::UnsupportedRuntime,
        ));
    }
    if !spec.engine.path().is_file() {
        return Err(HostError::Unavailable(UnavailableReason::NoEngine));
    }
    // A10: the file about to run is still the engine discovery verified
    // (an in-place update or replacement is refused), and its version is
    // one the worker is qualified on.
    spec.engine.reverify()?;
    if !spec.engine.worker_qualified() {
        return Err(HostError::Unavailable(UnavailableReason::UnsupportedEngine));
    }
    if !spec.profile_dir.is_dir() || !spec.temp_dir.is_dir() {
        return Err(HostError::Invalid(
            "profile or temp directory does not exist".into(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn path_text(path: &Path, what: &str) -> Result<String, HostError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| HostError::Invalid(format!("{what} is not UTF-8")))
}

/// The switch name of a command-line argument as Chromium on Windows reads
/// it: a `--`, `-` or `/` prefix, the name lowercased, any `=value` dropped.
fn switch_name(arg: &str) -> Option<String> {
    let name = arg
        .strip_prefix("--")
        .or_else(|| arg.strip_prefix('-'))
        .or_else(|| arg.strip_prefix('/'))?;
    let name = name.split('=').next().unwrap_or(name);
    Some(name.to_ascii_lowercase())
}

/// The process type Chromium derives from a command line: switches end at a
/// bare `--` or at `--single-argument` (after which Chromium on Windows reads
/// the rest as one plain argument; matched here in any spelling, which can
/// only turn a process into a browser and so fails closed), the last `type`
/// switch in any accepted spelling wins, and an absent or empty value means
/// the browser process (`None`).
fn chromium_process_type(argv: &[String]) -> Option<String> {
    let mut kind = None;
    for arg in argv.iter().skip(1) {
        if arg == "--" || switch_name(arg).as_deref() == Some("single-argument") {
            break;
        }
        if switch_name(arg).as_deref() == Some("type") {
            kind = arg
                .split_once('=')
                .map(|(_, value)| value.to_owned())
                .filter(|value| !value.is_empty());
        }
    }
    kind
}

/// Verify the job against the host-built launch: the worker runs with
/// exactly its host-built arguments, every other member is the verified
/// engine, no member carries a forbidden flag (in any spelling Chromium
/// accepts), exactly one browser process (an engine process without
/// `--type=`) exists, and its OS command line equals
/// `[engine, …expected_argv]`. Returns its pid.
pub fn classify_job(
    processes: &[JobProcess],
    worker_pid: u32,
    node: &Path,
    worker_args: &[String],
    engine: &Path,
    expected_argv: &[String],
) -> Result<u32, HostError> {
    if processes.len() > JOB_ACTIVE_PROCESS_LIMIT as usize {
        return Err(HostError::Invalid(
            "browser job exceeds its process limit".into(),
        ));
    }
    let same = |a: &Path, b: &Path| {
        a.to_string_lossy()
            .eq_ignore_ascii_case(&b.to_string_lossy())
    };
    let Some(worker) = processes
        .iter()
        .find(|process| process.pid == worker_pid && same(&process.image, node))
    else {
        return Err(HostError::Invalid(
            "the worker is not a member of its job".into(),
        ));
    };
    if worker.argv.get(1..) != Some(worker_args) {
        return Err(HostError::Invalid(
            "the worker command line differs from the host-built one".into(),
        ));
    }
    let forbidden: Vec<String> = FORBIDDEN_FLAGS
        .iter()
        .filter_map(|flag| switch_name(flag))
        .collect();
    let mut browsers = Vec::new();
    for process in processes {
        if process.pid == worker_pid {
            continue;
        }
        if !same(&process.image, engine) {
            return Err(HostError::Invalid(format!(
                "a foreign process ({}) is in the browser job",
                process
                    .image
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            )));
        }
        for arg in process.argv.iter().skip(1) {
            if let Some(name) = switch_name(arg).filter(|name| forbidden.contains(name)) {
                return Err(HostError::Invalid(format!(
                    "an engine process carries the forbidden flag --{name}"
                )));
            }
        }
        if chromium_process_type(&process.argv).is_none() {
            browsers.push(process);
        }
    }
    let [browser] = browsers.as_slice() else {
        return Err(HostError::Invalid(format!(
            "expected exactly one browser process in the job, found {}",
            browsers.len()
        )));
    };
    let (program, args) = browser
        .argv
        .split_first()
        .ok_or_else(|| HostError::Invalid("browser command line is empty".into()))?;
    if !same(Path::new(program), engine) || args != expected_argv {
        return Err(HostError::Invalid(
            "the browser command line differs from the host-built argv".into(),
        ));
    }
    Ok(browser.pid)
}

/// Remove a profile directory, retrying for up to 30 s. After every engine
/// process has exited, the kernel can still hold memory-mapped profile files
/// briefly (Restart Manager reports the holder as System, pid 4); under load
/// that release has been observed to exceed 10 s. A profile still held after
/// the budget is reported as not removed, never as removed.
#[cfg(windows)]
pub(crate) fn remove_profile(path: &Path) -> bool {
    let mut last = None;
    for _ in 0..120 {
        match std::fs::remove_dir_all(path) {
            Ok(()) => return true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return true,
            Err(error) => {
                last = Some(error);
                std::thread::sleep(Duration::from_millis(250));
            }
        }
    }
    #[cfg(test)]
    eprintln!("SG108-DIAG remove_profile failed: {last:?}");
    let _ = last;
    !path.exists()
}

#[cfg(windows)]
pub use platform::{launch_worker, BrowserWorker, CancelHandle};

#[cfg(not(windows))]
pub use fallback::{launch_worker, BrowserWorker, CancelHandle};

#[cfg(windows)]
mod platform {
    use super::*;
    use crate::proto::{decode_frame, write_frame};
    use crate::worker_navigation::{NavigationPolicy, RouteKind};
    use crate::worker_process::{spawn, WorkerProcess};
    use std::fs::File;
    use std::io::BufRead;
    use std::io::BufReader;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
    use std::sync::{Arc, Weak};
    use std::time::Instant;

    /// What the reader thread saw on the worker's output.
    enum ReaderEvent {
        Frame(WorkerReply),
        /// The output ended cleanly at a frame boundary.
        Eof,
        /// A frame was malformed or cut short.
        Malformed,
    }

    /// Cancels a worker's lifetime from any thread, including while an
    /// operation is running: it terminates the whole job, and the blocked
    /// call returns `Cancelled`. It never keeps the job alive (a dropped
    /// worker makes it a no-op) and grants nothing else.
    #[derive(Debug, Clone)]
    pub struct CancelHandle {
        job: Weak<crate::supervise::platform::Job>,
        cancelled: Arc<AtomicBool>,
    }

    /// A text fetch's (media, text, truncated), as the worker sent it.
    type TextBody = (String, String, bool);

    /// A crawl's view of the worker.
    struct WorkerCrawl<'a> {
        worker: &'a mut BrowserWorker,
        scope: &'a crate::observation::ObservationScope,
    }

    impl crate::crawl::CrawlDriver for WorkerCrawl<'_> {
        fn open(&mut self, url: &str) -> Result<crate::crawl::Visit, HostError> {
            let outcome = self.worker.navigate(url)?;
            Ok(crate::crawl::Visit {
                final_url: outcome.url,
                status: outcome.status,
            })
        }

        fn links(&mut self) -> Result<Vec<String>, HostError> {
            let live = self.worker.observe(self.scope)?;
            // Document order: a preorder walk of the observation.
            let mut links = Vec::new();
            let mut stack: Vec<&crate::observation::ObservedNode> =
                live.observation.nodes.iter().rev().collect();
            while let Some(node) = stack.pop() {
                if let Some(url) = self
                    .worker
                    .host_nodes
                    .get(&node.node_id)
                    .filter(|host| host.role == "link")
                    .and_then(|host| host.url.clone())
                {
                    links.push(url);
                }
                stack.extend(node.children.iter().rev());
            }
            Ok(links)
        }

        fn extract(
            &mut self,
            options: crate::extraction::ExtractOptions,
        ) -> Result<crate::extraction::PageExtraction, HostError> {
            self.worker.extract_page(options)
        }

        fn lost(&self) -> bool {
            self.worker.failed.is_some()
        }

        fn fetch_text(&mut self, url: &str) -> Result<crate::crawl::TextDocument, HostError> {
            let fetched = self.worker.fetch_text(url)?;
            Ok(crate::crawl::TextDocument {
                final_url: fetched.url,
                status: fetched.status,
                text: fetched.text.untrusted().to_owned(),
                truncated: fetched.truncated,
                media: fetched.media,
            })
        }
    }

    impl CancelHandle {
        /// Cancel; true if a live job was terminated.
        pub fn cancel(&self) -> bool {
            self.cancelled.store(true, Ordering::SeqCst);
            match self.job.upgrade() {
                Some(job) => {
                    job.terminate();
                    true
                }
                None => false,
            }
        }
    }

    /// A supervised browser worker. Dropping it terminates the job and
    /// removes an ephemeral profile.
    pub struct BrowserWorker {
        pub(super) process: WorkerProcess,
        stdin: File,
        replies: Receiver<ReaderEvent>,
        /// Set by a `CancelHandle`.
        cancelled: Arc<AtomicBool>,
        /// The handshake completed; failures after it end the lifetime.
        handshaken: bool,
        /// The reason the lifetime ended early; every later call returns it.
        failed: Option<UnavailableReason>,
        node: PathBuf,
        worker_args: Vec<String>,
        engine: PathBuf,
        argv: Vec<String>,
        profile: Option<PathBuf>,
        browser_pid: u32,
        finished: bool,
        policy: NavigationPolicy,
        next_nav: u64,
        last_request: u64,
        next_obs: u64,
        next_disc: u64,
        next_ext: u64,
        next_act: u64,
        next_dl: u64,
        next_exec: u64,
        /// Host-owned staging directory for downloads of this lifetime.
        staging: PathBuf,
        /// Staging folders of hosts that died, removed at this launch (#309).
        swept_staging: usize,
        /// Ephemeral profiles of hosts that died, removed at this launch
        /// (#298).
        swept_profiles: usize,
        /// The committed document: URL and document generation.
        committed: Option<(String, u64)>,
        /// Raw names of the last observation, by host-issued node id.
        host_nodes: std::collections::HashMap<String, HostNode>,
        /// This lifetime's secret for keyed names.
        name_key: [u8; 32],
        /// Tools of the last discovery, by host-issued tool id.
        host_tools: std::collections::HashMap<String, crate::webmcp::HostTool>,
        /// The pinned runtime's files, held for the worker's lifetime.
        runtime_hold: Option<crate::runtime_pin::HeldRuntime>,
    }

    /// Launch the worker and its engine, or fail closed with a typed error
    /// and nothing left running.
    pub fn launch_worker(
        spec: &WorkerLaunch,
        policy: &impl PolicySource,
    ) -> Result<BrowserWorker, HostError> {
        validate_launch(spec)?;
        assert_no_managed_policy(spec.engine.kind(), policy)
            .map_err(|_| HostError::Unavailable(UnavailableReason::ManagedPolicy))?;
        // Decision 7: the pinned runtime, held from this check until the
        // worker ends, before anything is swept or spawned.
        let runtime_hold = match &spec.runtime_pin {
            Some(pin) => Some(pin.verify_and_hold(&spec.node, &spec.worker_main)?),
            None => None,
        };
        // What a host that died left in the temp directory (#309).
        let swept_staging = crate::leftovers::sweep_stale_staging(&spec.temp_dir);
        // And its ephemeral profiles beside this one (#298): only when this
        // profile is itself one `ephemeral_profile_dir` made, so a root is
        // swept only once a caller has chosen it for such profiles.
        let swept_profiles = match (spec.profile_dir.parent(), spec.profile_dir.file_name()) {
            (Some(root), Some(name))
                if spec.ephemeral_profile
                    && root.is_absolute()
                    && crate::leftovers::owner(
                        crate::leftovers::PROFILE_PREFIX,
                        &name.to_string_lossy(),
                    ) == Some(std::process::id()) =>
            {
                crate::leftovers::sweep_stale_profiles(root)
            }
            _ => 0,
        };
        #[allow(unused_mut)] // mutated in test builds only
        let mut argv = build_worker_argv(&spec.profile_dir, &spec.destinations)?;
        #[cfg(any(test, feature = "live-browser-test"))]
        if let Some(spki) = &spec.test_trusted_spki {
            // Before the trailing blank page, where the worker expects it.
            argv.insert(argv.len() - 1, test_certificate_flag(spki));
        }
        seed_profile_preferences(&spec.profile_dir)?;
        let env = worker_environment(&spec.temp_dir);
        let worker_args = worker_node_args(&spec.worker_main);
        let (process, pipes) = spawn(&spec.node, &worker_args, &env)?;
        let (sender, replies) = mpsc::channel();
        let stdout = pipes.stdout;
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let event = match reader.fill_buf() {
                    Ok([]) => ReaderEvent::Eof,
                    Ok(_) => match decode_frame::<WorkerReply, _>(&mut reader) {
                        Ok(frame) => ReaderEvent::Frame(frame),
                        Err(_) => ReaderEvent::Malformed,
                    },
                    Err(_) => ReaderEvent::Malformed,
                };
                let stop = !matches!(event, ReaderEvent::Frame(_));
                if sender.send(event).is_err() || stop {
                    return;
                }
            }
        });
        let mut worker = BrowserWorker {
            process,
            stdin: pipes.stdin,
            replies,
            cancelled: Arc::new(AtomicBool::new(false)),
            handshaken: false,
            failed: None,
            node: spec.node.clone(),
            worker_args,
            engine: spec.engine.path().to_path_buf(),
            argv,
            profile: spec.ephemeral_profile.then(|| spec.profile_dir.clone()),
            browser_pid: 0,
            finished: false,
            policy: NavigationPolicy::new(&spec.destinations),
            next_obs: 0,
            next_disc: 0,
            next_ext: 0,
            next_act: 0,
            next_dl: 0,
            next_exec: 0,
            swept_staging,
            swept_profiles,
            staging: spec.temp_dir.join(format!(
                "{}{}-{:x}",
                crate::leftovers::STAGING_PREFIX,
                std::process::id(),
                unique_suffix()
            )),
            committed: None,
            host_nodes: std::collections::HashMap::new(),
            name_key: lifetime_key()?,
            host_tools: std::collections::HashMap::new(),
            next_nav: 0,
            last_request: 0,
            runtime_hold,
        };
        worker.handshake(spec)?;
        Ok(worker)
    }

    impl BrowserWorker {
        fn send(&mut self, request: &WorkerRequest<'_>) -> Result<(), HostError> {
            if let Some(reason) = self.failed {
                return Err(HostError::Unavailable(reason));
            }
            if write_frame(&mut self.stdin, request).is_err() {
                return Err(self.fail_closed(UnavailableReason::ProtocolViolation));
            }
            Ok(())
        }

        /// The stored reason of an ended (or cancelled) lifetime.
        fn ensure_alive(&mut self) -> Result<(), HostError> {
            if self.cancelled.load(Ordering::SeqCst) {
                return Err(self.fail_closed(UnavailableReason::Cancelled));
            }
            match self.failed {
                Some(reason) => Err(HostError::Unavailable(reason)),
                None => Ok(()),
            }
        }

        /// A handle that cancels this lifetime from another thread.
        pub fn cancel_handle(&self) -> CancelHandle {
            CancelHandle {
                job: self.process.job_weak(),
                cancelled: Arc::clone(&self.cancelled),
            }
        }

        /// After the handshake, a channel failure, a deadline or a
        /// cancellation ends the lifetime: the job is terminated now (nothing
        /// stays in flight) and every later call returns the same reason. A
        /// cancellation outranks whatever symptom it caused.
        fn fail_closed(&mut self, reason: UnavailableReason) -> HostError {
            let reason = if self.cancelled.load(Ordering::SeqCst) {
                UnavailableReason::Cancelled
            } else {
                reason
            };
            if !self.handshaken {
                return HostError::Unavailable(reason);
            }
            let reason = *self.failed.get_or_insert(reason);
            self.process.terminate_and_confirm(WORKER_SHUTDOWN_TIMEOUT);
            HostError::Unavailable(reason)
        }

        /// The next reply within `timeout`. A worker that exits with code 2
        /// before answering refused its runtime (typed unsupported runtime).
        fn reply(&mut self, timeout: Duration) -> Result<WorkerReply, HostError> {
            let deadline = Instant::now() + timeout;
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                // A worker that keeps sending route requests cannot hold the
                // host past the deadline.
                if remaining.is_zero() {
                    return Err(self.deadline_passed());
                }
                match self.next_frame(remaining)? {
                    WorkerReply::RouteRequest {
                        request_id,
                        kind,
                        url,
                        origin,
                        method,
                        content_type,
                        body,
                        body_bytes,
                    } => {
                        let detail = crate::worker_navigation::RequestDetail {
                            method,
                            content_type,
                            body,
                            body_bytes,
                        };
                        self.answer_route(request_id, &kind, &url, &origin, &detail)?
                    }
                    reply => return Ok(reply),
                }
            }
        }

        /// Decide one forwarded engine request with the SG-000075 policy.
        /// Request ids must increase strictly; an unknown kind is refused.
        fn answer_route(
            &mut self,
            request_id: u64,
            kind: &str,
            url: &str,
            origin: &str,
            detail: &crate::worker_navigation::RequestDetail,
        ) -> Result<(), HostError> {
            if request_id <= self.last_request {
                return Err(HostError::Unavailable(UnavailableReason::ProtocolViolation));
            }
            self.last_request = request_id;
            let allow = match RouteKind::parse(kind) {
                Some(kind) => self
                    .policy
                    .decide_request(kind, url, origin, detail)
                    .is_ok(),
                None => false,
            };
            self.send(&WorkerRequest::RouteDecision { request_id, allow })
        }

        /// The host's own deadline: during the handshake a launch failure,
        /// afterwards a typed timeout that ends the lifetime.
        fn deadline_passed(&mut self) -> HostError {
            if self.handshaken {
                self.fail_closed(UnavailableReason::TimedOut)
            } else {
                HostError::Unavailable(UnavailableReason::LaunchFailed)
            }
        }

        fn next_frame(&mut self, timeout: Duration) -> Result<WorkerReply, HostError> {
            if let Some(reason) = self.failed {
                return Err(HostError::Unavailable(reason));
            }
            match self.replies.recv_timeout(timeout) {
                Ok(ReaderEvent::Frame(WorkerReply::Error { code })) => {
                    let error = reply_error(&code);
                    Err(match error {
                        HostError::Unavailable(reason) if self.handshaken => {
                            self.fail_closed(reason)
                        }
                        other => other,
                    })
                }
                Ok(ReaderEvent::Frame(reply)) => Ok(reply),
                // Malformed output is a violation, whatever the worker does
                // next.
                Ok(ReaderEvent::Malformed) => {
                    Err(self.fail_closed(UnavailableReason::ProtocolViolation))
                }
                Ok(ReaderEvent::Eof) | Err(RecvTimeoutError::Disconnected) => {
                    let reason = match self.process.wait_exit(Duration::from_secs(2)) {
                        // Exit code 2 is the runtime refusal, before the
                        // handshake completes.
                        Some(2) if !self.handshaken => UnavailableReason::UnsupportedRuntime,
                        // The worker died: the lifetime is over.
                        Some(_) => UnavailableReason::WorkerExited,
                        // Output ended but the worker still runs.
                        None => UnavailableReason::ProtocolViolation,
                    };
                    Err(self.fail_closed(reason))
                }
                Err(RecvTimeoutError::Timeout) => Err(self.deadline_passed()),
            }
        }

        fn handshake(&mut self, spec: &WorkerLaunch) -> Result<(), HostError> {
            self.send(&WorkerRequest::Hello {
                generation: WORKER_PROTOCOL_GENERATION,
            })?;
            match self.reply(WORKER_HANDSHAKE_TIMEOUT)? {
                WorkerReply::Hello { generation, worker }
                    if generation == WORKER_PROTOCOL_GENERATION && worker == WORKER_IDENTITY => {}
                _ => return Err(HostError::Unavailable(UnavailableReason::ProtocolViolation)),
            }
            let env: BTreeMap<String, String> = worker_environment(&spec.temp_dir)
                .into_iter()
                .map(|(key, value)| {
                    (
                        key.to_string_lossy().into_owned(),
                        value.to_string_lossy().into_owned(),
                    )
                })
                .collect();
            let engine = path_text(spec.engine.path(), "engine")?;
            let profile_dir = path_text(&spec.profile_dir, "profile directory")?;
            let argv = self.argv.clone();
            self.send(&WorkerRequest::Launch {
                engine: &engine,
                profile_dir: &profile_dir,
                argv: &argv,
                env,
            })?;
            match self.reply(WORKER_LAUNCH_TIMEOUT)? {
                WorkerReply::Launched {} => {}
                _ => return Err(HostError::Unavailable(UnavailableReason::ProtocolViolation)),
            }
            self.browser_pid = self.verify()?;
            self.handshaken = true;
            Ok(())
        }

        /// Re-verify the job membership and the browser command line.
        pub fn verify(&self) -> Result<u32, HostError> {
            let processes = self.process.snapshot()?;
            classify_job(
                &processes,
                self.process.pid(),
                &self.node,
                &self.worker_args,
                &self.engine,
                &self.argv,
            )
        }

        /// The current job members.
        pub fn job_processes(&self) -> Result<Vec<JobProcess>, HostError> {
            self.process.snapshot()
        }

        pub fn worker_pid(&self) -> u32 {
            self.process.pid()
        }

        /// How many files of a pinned runtime this worker holds (0 when the
        /// launch carried no pin).
        pub fn runtime_files_held(&self) -> usize {
            self.runtime_hold.as_ref().map_or(0, |held| held.len())
        }

        pub fn browser_pid(&self) -> u32 {
            self.browser_pid
        }

        /// Liveness check over the closed protocol.
        pub fn ping(&mut self, nonce: &str) -> Result<(), HostError> {
            self.send(&WorkerRequest::Ping { nonce })?;
            match self.reply(WORKER_REPLY_TIMEOUT)? {
                WorkerReply::Pong { nonce: echoed } if echoed == nonce => Ok(()),
                _ => Err(HostError::Unavailable(UnavailableReason::ProtocolViolation)),
            }
        }

        /// Navigate the primary page to an admitted HTTPS URL. Every request
        /// the engine makes meanwhile is decided here by the SG-000075
        /// policy; the outcome is typed.
        pub fn navigate(&mut self, url: &str) -> Result<NavigationOutcome, HostError> {
            self.navigate_with(url, false).map(|(outcome, _)| outcome)
        }

        /// Open `url` like `navigate` (the same policy, redirects and
        /// commit; the document generation advances) and return its text
        /// when it is plain text or XML (#317: robots.txt and sitemaps).
        pub fn fetch_text(&mut self, url: &str) -> Result<FetchedText, HostError> {
            let (outcome, body) = self.navigate_with(url, true)?;
            let (media, text, truncated) =
                body.ok_or(HostError::Unavailable(UnavailableReason::ProtocolViolation))?;
            Ok(FetchedText {
                url: outcome.url,
                status: outcome.status,
                media,
                text: crate::webmcp::PageText::from_page(text),
                truncated,
            })
        }

        fn navigate_with(
            &mut self,
            url: &str,
            text: bool,
        ) -> Result<(NavigationOutcome, Option<TextBody>), HostError> {
            // Any navigation attempt, failed or not, invalidates every
            // identity issued for the previous document.
            self.host_nodes.clear();
            self.host_tools.clear();
            let outcome = self.navigate_inner(url, text);
            if outcome.is_err() {
                self.policy.abort();
            }
            outcome
        }

        fn navigate_inner(
            &mut self,
            url: &str,
            text: bool,
        ) -> Result<(NavigationOutcome, Option<TextBody>), HostError> {
            self.policy.begin(url)?;
            self.next_nav += 1;
            let id = self.next_nav;
            if text {
                self.send(&WorkerRequest::FetchText { fetch_id: id, url })?;
            } else {
                self.send(&WorkerRequest::Navigate { nav_id: id, url })?;
            }
            let (committed, status, body) = match self.reply(WORKER_NAVIGATION_TIMEOUT)? {
                WorkerReply::Navigated {
                    nav_id: done,
                    url: committed,
                    status,
                } if !text && done == id => (committed, status, None),
                WorkerReply::FetchedText {
                    fetch_id: done,
                    url: committed,
                    status,
                    media,
                    text: body,
                    truncated,
                } if text && done == id => {
                    let bad = |ch: char| {
                        (ch.is_control() && !matches!(ch, '\n' | '\t' | '\r'))
                            || crate::webmcp::is_bidi_or_format(ch)
                    };
                    let known = FETCH_TEXT_MEDIA.contains(&media.as_str());
                    if media.len() > 128
                        || !media.bytes().all(|b| b.is_ascii_graphic())
                        || (!known && !body.is_empty())
                        || body.chars().count() > MAX_FETCH_TEXT_CHARS
                        || body.chars().any(bad)
                    {
                        return Err(HostError::Unavailable(UnavailableReason::ProtocolViolation));
                    }
                    (committed, status, Some((media, body, truncated)))
                }
                WorkerReply::NavigationFailed {
                    nav_id: done,
                    reason,
                } if !text && done == id => {
                    #[cfg(test)]
                    eprintln!("SG108-DIAG navigation {url} failed: {reason}");
                    return Err(navigation_failure(&reason));
                }
                WorkerReply::FetchFailed {
                    fetch_id: done,
                    reason,
                } if text && done == id => {
                    #[cfg(test)]
                    eprintln!("SG108-DIAG fetch {url} failed: {reason}");
                    return Err(navigation_failure(&reason));
                }
                other => {
                    #[cfg(test)]
                    eprintln!("SG108-DIAG navigation {url} unexpected reply: {other:?}");
                    let _ = other;
                    return Err(HostError::Unavailable(UnavailableReason::ProtocolViolation));
                }
            };
            self.policy.commit(&committed)?;
            // A new document: earlier node identities are stale. The
            // document generation advances only on a commit.
            let next = self
                .committed
                .as_ref()
                .map_or(1, |(_, generation)| generation + 1);
            self.committed = Some((committed.clone(), next));
            self.host_nodes.clear();
            self.host_tools.clear();
            Ok((
                NavigationOutcome {
                    url: committed,
                    status,
                },
                body,
            ))
        }

        /// Observe the committed document (SG-000076). The snapshot must be
        /// of exactly the committed URL (a page that moved itself is stale
        /// and needs a new navigation). Node identities are issued here,
        /// bound to the document generation; callers get only the
        /// redacted, digested observation.
        pub fn observe(
            &mut self,
            scope: &crate::observation::ObservationScope,
        ) -> Result<LiveObservation, HostError> {
            let (url, generation) = self
                .committed
                .clone()
                .ok_or_else(|| HostError::Invalid("no committed document to observe".into()))?;
            let origin = self
                .policy
                .committed_origin()
                .ok_or_else(|| HostError::Invalid("no committed origin".into()))?
                .to_owned();
            self.next_obs += 1;
            let obs_id = self.next_obs;
            let started = Instant::now();
            self.send(&WorkerRequest::Observe { obs_id })?;
            let (observed_url, worker_truncated, nodes) =
                match self.reply(WORKER_OBSERVATION_TIMEOUT)? {
                    WorkerReply::Observed {
                        obs_id: done,
                        url: observed_url,
                        truncated,
                        nodes,
                    } if done == obs_id => (observed_url, truncated, nodes),
                    WorkerReply::ObservationFailed { obs_id: done } if done == obs_id => {
                        return Err(HostError::Unavailable(UnavailableReason::LaunchFailed))
                    }
                    _ => return Err(HostError::Unavailable(UnavailableReason::ProtocolViolation)),
                };
            if observed_url != url {
                return Err(HostError::Invalid(
                    "stale page: the document changed".into(),
                ));
            }
            let elapsed = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
            let page = crate::observation::PageIdentity {
                page_id: format!("p{generation}"),
                origin,
                page_generation: generation,
            };
            let document = crate::observation::DocumentIdentity {
                page_id: page.page_id.clone(),
                document_generation: generation,
            };
            let mut index = std::collections::HashMap::new();
            let roots: Vec<crate::observation::InputNode> = nodes
                .iter()
                .map(|node| input_node(node, generation, &self.name_key, &mut index))
                .collect();
            let mut observation =
                crate::observation::observe_snapshot(scope, &page, &document, &roots, elapsed)?;
            // The worker's own ceilings count as truncation too.
            observation.truncated |= worker_truncated;
            // Only nodes the caller actually received can be acted on.
            let mut kept = std::collections::HashSet::new();
            let mut stack: Vec<&crate::observation::ObservedNode> =
                observation.nodes.iter().collect();
            while let Some(node) = stack.pop() {
                kept.insert(node.node_id.clone());
                stack.extend(node.children.iter());
            }
            index.retain(|id, _| kept.contains(id));
            self.host_nodes = index;
            Ok(LiveObservation {
                page,
                document,
                observation,
            })
        }

        /// Discover the committed document's WebMCP declarative tools
        /// (SG-000108 slice 4, read only). The worker reads them from an
        /// engine DOM snapshot, so no page script runs; the host re-checks
        /// every bound, issues identities bound to the document generation,
        /// and returns names, titles and descriptions as untrusted page
        /// text. A page with no declared tools yields an empty list (the
        /// caller falls back to observation). Nothing here grants execution.
        pub fn discover_tools(&mut self) -> Result<crate::webmcp::DiscoveredTools, HostError> {
            // A failed discovery leaves no tools from an earlier one.
            self.host_tools.clear();
            let (url, generation) = self
                .committed
                .clone()
                .ok_or_else(|| HostError::Invalid("no committed document to discover".into()))?;
            self.next_disc += 1;
            let disc_id = self.next_disc;
            self.send(&WorkerRequest::Discover { disc_id })?;
            let (found_url, truncated, wire) = match self.reply(WORKER_OBSERVATION_TIMEOUT)? {
                WorkerReply::Discovered {
                    disc_id: done,
                    url,
                    truncated,
                    tools,
                } if done == disc_id => (url, truncated, tools),
                WorkerReply::DiscoveryFailed { disc_id: done } if done == disc_id => {
                    return Err(HostError::Unavailable(UnavailableReason::ActionFailed))
                }
                _ => return Err(HostError::Unavailable(UnavailableReason::ProtocolViolation)),
            };
            if found_url != url {
                return Err(HostError::Invalid(
                    "stale page: the document changed".into(),
                ));
            }
            let (tools, index) = crate::webmcp::validate_tools(wire, generation)?;
            self.host_tools = index;
            Ok(crate::webmcp::DiscoveredTools {
                url,
                document_generation: generation,
                truncated,
                tools,
            })
        }

        /// Map or crawl the admitted destination from `spec.start_url`
        /// (slice 7): every page is opened by the governed navigation, its
        /// links come from an observation under `scope`, and its content,
        /// if asked, from `extract_page`. `cancelled` and the deadline are
        /// checked between pages; a page's own timeouts still apply.
        pub fn crawl_site(
            &mut self,
            spec: &crate::crawl::CrawlSpec,
            scope: &crate::observation::ObservationScope,
            cancelled: &std::sync::atomic::AtomicBool,
        ) -> Result<crate::crawl::CrawlReport, HostError> {
            let mut driver = WorkerCrawl {
                worker: self,
                scope,
            };
            crate::crawl::crawl(&mut driver, spec, cancelled)
        }

        /// The committed page's rendered content as Markdown, read by the
        /// engine without running page script, as untrusted page text bound
        /// to the document generation. Every piece is checked; a document
        /// that changes during the transfer makes the result stale.
        pub fn extract_page(
            &mut self,
            options: crate::extraction::ExtractOptions,
        ) -> Result<crate::extraction::PageExtraction, HostError> {
            let committed = self
                .committed
                .clone()
                .ok_or_else(|| HostError::Invalid("no committed document to extract".into()))?;
            self.next_ext += 1;
            let ext_id = self.next_ext;
            self.send(&WorkerRequest::Extract {
                ext_id,
                links: options.links,
                images: options.images,
            })?;
            // The worker took its snapshot of the page it reports; that must
            // be the committed document (a page that moved itself, even by
            // pushState, is stale). Every piece is of that one snapshot.
            let first = self.extraction_piece(ext_id, WORKER_EXTRACTION_TIMEOUT)?;
            if first.url != committed.0 {
                return Err(HostError::Invalid(
                    "stale page: the document changed".into(),
                ));
            }
            let mut assembly = crate::extraction::Assembly::start(first)?;
            while let Some(piece) = assembly.next() {
                self.send(&WorkerRequest::ExtractMore { ext_id, piece })?;
                let next = self.extraction_piece(ext_id, WORKER_REPLY_TIMEOUT)?;
                assembly.push(next)?;
            }
            assembly.finish(committed.1)
        }

        /// One `extracted` reply for `ext_id`. A typed failure is
        /// `ActionFailed`; anything else is a protocol violation.
        fn extraction_piece(
            &mut self,
            ext_id: u64,
            timeout: Duration,
        ) -> Result<crate::extraction::WirePiece, HostError> {
            match self.reply(timeout)? {
                WorkerReply::Extracted {
                    ext_id: done,
                    url,
                    truncated,
                    piece,
                    total,
                    chunk,
                    content,
                } if done == ext_id => Ok(crate::extraction::WirePiece {
                    url,
                    truncated,
                    piece,
                    total,
                    chunk,
                    content,
                }),
                WorkerReply::ExtractionFailed { ext_id: done } if done == ext_id => {
                    Err(HostError::Unavailable(UnavailableReason::ActionFailed))
                }
                _ => Err(HostError::Unavailable(UnavailableReason::ProtocolViolation)),
            }
        }

        /// The state an execution approval must name: the tool, a digest of
        /// its discovered record, its method and resolved action, and the
        /// canonical arguments, so the one-shot approval covers exactly what
        /// is submitted where. Refuses tools that cannot execute and
        /// arguments outside the declared subset.
        pub fn execution_binding(
            &self,
            tool_id: &str,
            args: &serde_json::Map<String, serde_json::Value>,
        ) -> Result<String, HostError> {
            let (url, generation) = self
                .committed
                .clone()
                .ok_or_else(|| HostError::Invalid("no committed document".into()))?;
            let tool = self
                .host_tools
                .get(tool_id)
                .filter(|tool| tool.document_generation == generation)
                .ok_or_else(|| HostError::Invalid("stale or unknown tool".into()))?;
            crate::webmcp::ensure_executable(&tool.record)?;
            crate::webmcp::validate_arguments(&tool.record, args)?;
            let action = crate::webmcp::resolve_action(
                &url,
                tool.record.action.as_deref().unwrap_or_default(),
            )?;
            let method = match tool.record.method {
                crate::webmcp::FormMethod::Post => "post",
                _ => "get",
            };
            Ok(format!(
                "execute\n{}\n{}\n{method}\n{action}\n{}",
                tool.record.name,
                sha256_hex(format!("{:?}", tool.record).as_bytes()),
                crate::webmcp::canonical_arguments(args)
            ))
        }

        /// Execute a discovered WebMCP declarative tool (SG-000108 slice 5)
        /// under SG-000077: the tool is discovered again and must be
        /// unchanged; the arguments are validated host-side; the approval
        /// (bound to `execution_binding`) is consumed in `dispatch`; the
        /// worker fills the form through typed Playwright actions and clicks
        /// its default submit button; the host accepts exactly one
        /// page-initiated document, the form's action on the page's origin
        /// (any query for GET). The result is that document and its
        /// structured data as untrusted page text. A form whose page handles
        /// the submission without opening a document is not a verified
        /// execution.
        pub fn execute_tool(
            &mut self,
            target: &crate::actuation::ActuationTarget,
            approval: &mut crate::actuation::ApprovalToken,
            args: &serde_json::Map<String, serde_json::Value>,
            policy_revision: u64,
            workspace: &str,
        ) -> Result<ExecutionOutcome, HostError> {
            self.ensure_alive()?;
            if target.action != crate::actuation::SupportedAction::Execute {
                return Err(HostError::Invalid(
                    "an execution needs an execute approval".into(),
                ));
            }
            let (url, generation) = self
                .committed
                .clone()
                .ok_or_else(|| HostError::Invalid("no committed document".into()))?;
            let shown = self
                .host_tools
                .get(&target.node_id)
                .filter(|tool| tool.document_generation == generation)
                .map(|tool| tool.record.clone())
                .ok_or_else(|| HostError::Invalid("stale or unknown tool".into()))?;
            // The page may have changed the form since it was discovered.
            self.discover_tools()?;
            let fresh = self
                .host_tools
                .get(&target.node_id)
                .map(|tool| tool.record.clone());
            if fresh.as_ref() != Some(&shown) {
                self.host_tools.clear();
                return Err(HostError::Invalid(
                    "the tool changed since it was discovered".into(),
                ));
            }
            let binding = self.execution_binding(&target.node_id, args)?;
            let fields = crate::webmcp::validate_arguments(&shown, args)?;
            let action =
                crate::webmcp::resolve_action(&url, shown.action.as_deref().unwrap_or_default())?;
            let post = shown.method == crate::webmcp::FormMethod::Post;
            self.policy
                .expect_submission(&action, !post, submission_of(&shown, &fields, post))?;
            if let Err(error) = crate::actuation::dispatch(
                target,
                approval,
                generation,
                &binding,
                policy_revision,
                workspace,
            ) {
                self.policy.finish_activation();
                return Err(error);
            }
            self.next_exec += 1;
            let exec_id = self.next_exec;
            let sent = self.send(&WorkerRequest::Execute {
                exec_id,
                tool: &shown.name,
                fields: &fields,
            });
            let reply = sent.and_then(|()| self.reply(WORKER_EXECUTION_TIMEOUT));
            let opened_expected = self.policy.finish_activation();
            self.host_nodes.clear();
            self.host_tools.clear();
            let (done_url, status, structured, structured_complete) = match reply? {
                WorkerReply::Executed {
                    exec_id: done,
                    url,
                    status,
                    structured,
                    structured_complete,
                } if done == exec_id => (url, status, structured, structured_complete),
                WorkerReply::ExecutionFailed {
                    exec_id: done,
                    reason,
                } if done == exec_id => return Err(navigation_failure(&reason)),
                _ => return Err(HostError::Unavailable(UnavailableReason::ProtocolViolation)),
            };
            if !opened_expected {
                return Err(HostError::Invalid(
                    "postcondition unverified: the submission opened no document".into(),
                ));
            }
            let structured = crate::webmcp::validate_result_blocks(structured)?;
            self.policy.commit_page_initiated(&done_url)?;
            let next = generation + 1;
            self.committed = Some((done_url.clone(), next));
            Ok(ExecutionOutcome {
                url: done_url,
                status,
                document_generation: next,
                structured,
                structured_complete,
            })
        }

        /// Test-only view of a discovered tool.
        #[cfg(test)]
        pub(crate) fn host_tool(&self, tool_id: &str) -> Option<&crate::webmcp::HostTool> {
            self.host_tools.get(tool_id)
        }

        /// Host-side typed selection: the observed link whose accessible
        /// name carries the latest ISO date (YYYY-MM-DD). Ties and pages
        /// without a dated link are refused rather than guessed.
        pub fn select_latest_dated_link(&self) -> Result<String, HostError> {
            select_latest_dated_link(&self.host_nodes)
        }

        /// Forget every observed node but `keep` (the product caller's
        /// worker mode: only nodes Orcel actually received can be acted
        /// on, when a reply had to drop some to fit one frame).
        #[cfg(any(feature = "live-browser-test", feature = "live-browser-dev"))]
        pub(crate) fn retain_host_nodes(&mut self, keep: &std::collections::HashSet<String>) {
            self.host_nodes.retain(|id, _| keep.contains(id));
        }

        /// The destination an activation of this observed link would open
        /// (what an approval must name as the target's `state`).
        pub fn link_destination(&self, node_id: &str) -> Result<String, HostError> {
            let node = self
                .host_nodes
                .get(node_id)
                .filter(|node| node.role == "link")
                .ok_or_else(|| HostError::Invalid("stale or unknown link".into()))?;
            let origin = self
                .policy
                .committed_origin()
                .ok_or_else(|| HostError::Invalid("no committed origin".into()))?;
            resolve_link(
                origin,
                node.url
                    .as_deref()
                    .ok_or_else(|| HostError::Invalid("the link has no URL".into()))?,
            )
        }

        /// The state a download approval must name: the link's destination,
        /// the approved folder's real path and the normalized file path, so
        /// the one-shot approval covers what is fetched and where it lands.
        pub fn download_binding(
            &self,
            node_id: &str,
            destination_root: &Path,
            relative: &str,
        ) -> Result<String, HostError> {
            let link = self.link_destination(node_id)?;
            let normalized = crate::transfers::validate_relative_destination(relative)?;
            let root = std::fs::canonicalize(destination_root)
                .ok()
                .filter(|root| root.is_dir())
                .ok_or_else(|| HostError::Invalid("the approved folder does not exist".into()))?;
            let root = path_text(&root, "approved folder")?;
            Ok(format!("download\n{link}\n{root}\n{normalized}"))
        }

        /// Activate (click) one observed link under SG-000077. The host
        /// does not model element state; the target's `state` must instead
        /// name the link's resolved destination, so the one-shot approval
        /// (bound to the target digest) covers where the click goes.
        /// `dispatch` verifies the target against the committed document
        /// and the host's own destination, then consumes the approval.
        /// During the click the host accepts exactly one page-initiated
        /// document, that destination (a changed href or a script redirect
        /// is refused at the request), and a click that requests no document
        /// is not a verified activation. The result commits on the same
        /// origin as a new document generation.
        pub fn activate(
            &mut self,
            target: &crate::actuation::ActuationTarget,
            approval: &mut crate::actuation::ApprovalToken,
            policy_revision: u64,
            workspace: &str,
        ) -> Result<NavigationOutcome, HostError> {
            // An ended lifetime refuses before any approval is spent.
            self.ensure_alive()?;
            if target.action != crate::actuation::SupportedAction::Click {
                return Err(HostError::Invalid(
                    "activation needs a click approval".into(),
                ));
            }
            let (_, generation) = self
                .committed
                .clone()
                .ok_or_else(|| HostError::Invalid("no committed document".into()))?;
            let reference = self
                .host_nodes
                .get(&target.node_id)
                .filter(|node| node.role == target.role)
                .map(|node| node.reference.clone())
                .ok_or_else(|| HostError::Invalid("stale or unknown node".into()))?;
            let destination = self.link_destination(&target.node_id)?;
            // Checked before the approval is consumed: a destination off the
            // page's origin is refused without spending it.
            self.policy.expect_activation(&destination)?;
            if let Err(error) = crate::actuation::dispatch(
                target,
                approval,
                generation,
                &destination,
                policy_revision,
                workspace,
            ) {
                self.policy.finish_activation();
                return Err(error);
            }
            self.next_act += 1;
            let act_id = self.next_act;
            self.send(&WorkerRequest::Activate {
                act_id,
                reference: &reference,
            })?;
            let reply = self.reply(WORKER_ACTIVATION_TIMEOUT);
            let opened_expected = self.policy.finish_activation();
            let outcome = match reply? {
                WorkerReply::Activated {
                    act_id: done,
                    url,
                    status,
                } if done == act_id => NavigationOutcome { url, status },
                WorkerReply::ActivationFailed {
                    act_id: done,
                    reason,
                } if done == act_id => {
                    // The page may have moved; nothing from before is valid.
                    self.host_nodes.clear();
                    self.host_tools.clear();
                    return Err(navigation_failure(&reason));
                }
                _ => return Err(HostError::Unavailable(UnavailableReason::ProtocolViolation)),
            };
            self.host_nodes.clear();
            self.host_tools.clear();
            if !opened_expected {
                return Err(HostError::Invalid(
                    "postcondition unverified: the activation opened no document".into(),
                ));
            }
            self.policy.commit_page_initiated(&outcome.url)?;
            let next = generation + 1;
            self.committed = Some((outcome.url.clone(), next));
            Ok(outcome)
        }

        /// Download the document behind one observed element under SG-000077
        /// and SG-000078: `dispatch` consumes the one-shot approval, the
        /// worker saves the engine's download to a fresh host staging path,
        /// the host checks its origin, type, content and size, and commits
        /// it create-only to `relative` inside `destination_root`, re-checking
        /// containment through the real path. The staging file is always
        /// removed. Inert PDFs use the SG-000078 amendment; other types the
        /// general allowlist.
        #[allow(clippy::too_many_arguments)]
        pub fn download(
            &mut self,
            target: &crate::actuation::ActuationTarget,
            approval: &mut crate::actuation::ApprovalToken,
            policy_revision: u64,
            workspace: &str,
            destination_root: &Path,
            relative: &str,
        ) -> Result<CommittedDownload, HostError> {
            self.ensure_alive()?;
            if target.action != crate::actuation::SupportedAction::Download {
                return Err(HostError::Invalid(
                    "a download needs a download approval".into(),
                ));
            }
            let binding = self.download_binding(&target.node_id, destination_root, relative)?;
            // The approved folder's real path, as the approval names it: the
            // commit writes only into that folder.
            let bound_root = binding
                .split('\n')
                .nth(2)
                .map(str::to_owned)
                .ok_or(HostError::Unavailable(UnavailableReason::ProtocolViolation))?;
            let normalized = crate::transfers::validate_relative_destination(relative)?;
            let destination = destination_root.join(&normalized);
            if destination.exists() {
                return Err(HostError::Invalid(
                    "destination exists (create-only)".into(),
                ));
            }
            let (_, generation) = self
                .committed
                .clone()
                .ok_or_else(|| HostError::Invalid("no committed document".into()))?;
            let reference = self
                .host_nodes
                .get(&target.node_id)
                .filter(|node| node.role == target.role)
                .map(|node| node.reference.clone())
                .ok_or_else(|| HostError::Invalid("stale or unknown node".into()))?;
            // As for activation: the approval names the link's destination,
            // checked against the page's origin before it is consumed, and
            // the click may open exactly that document.
            let link = self.link_destination(&target.node_id)?;
            // A fragment never reaches the request, so the exact-link check
            // could not match: refused before the approval is spent.
            if link.contains('#') {
                return Err(HostError::Invalid(
                    "a link with a fragment cannot be downloaded".into(),
                ));
            }
            std::fs::create_dir_all(&self.staging)
                .map_err(|err| HostError::Platform(format!("staging: {err}")))?;
            self.policy.expect_activation(&link)?;
            if let Err(error) = crate::actuation::dispatch(
                target,
                approval,
                generation,
                &binding,
                policy_revision,
                workspace,
            ) {
                self.policy.finish_activation();
                return Err(error);
            }
            self.next_dl += 1;
            let dl_id = self.next_dl;
            let staged = self.staging.join(format!("dl-{dl_id}.part"));
            let result = self.download_staged(
                dl_id,
                &reference,
                &staged,
                &link,
                (destination_root, &bound_root, &normalized),
            );
            let opened_expected = self.policy.finish_activation();
            let _ = std::fs::remove_file(&staged);
            // The click navigated the page to the downloaded document, which
            // the guard replaced with an inert blank page: that is now the
            // committed document (one generation later).
            if let Ok(committed) = &result {
                if self
                    .policy
                    .commit_page_initiated(&committed.source_url)
                    .is_ok()
                {
                    self.committed = Some((committed.source_url.clone(), generation + 1));
                }
            }
            let result = match result {
                Ok(committed) if !opened_expected => {
                    // The bytes did not come from the approved document.
                    let _ = std::fs::remove_file(&committed.path);
                    Err(HostError::Invalid(
                        "postcondition unverified: the download opened another document".into(),
                    ))
                }
                other => other,
            };
            // The page may have changed; earlier node identities are stale.
            self.host_nodes.clear();
            self.host_tools.clear();
            result
        }

        fn download_staged(
            &mut self,
            dl_id: u64,
            reference: &str,
            staged: &Path,
            link: &str,
            (destination_root, bound_root, relative): (&Path, &str, &str),
        ) -> Result<CommittedDownload, HostError> {
            let destination = &destination_root.join(relative);
            let staged_text = path_text(staged, "staging path")?;
            self.send(&WorkerRequest::Download {
                dl_id,
                reference,
                path: &staged_text,
            })?;
            // The worker's suggested name is advisory and never decides the
            // type check; the approved destination's own name does.
            let (url, media, declared) = match self.reply(WORKER_NAVIGATION_TIMEOUT)? {
                WorkerReply::Downloaded {
                    dl_id: done,
                    url,
                    name: _,
                    media,
                    bytes,
                } if done == dl_id => (url, media, bytes),
                WorkerReply::DownloadFailed {
                    dl_id: done,
                    reason,
                } if done == dl_id => return Err(download_failure(&reason)),
                _ => return Err(HostError::Unavailable(UnavailableReason::ProtocolViolation)),
            };
            // Exactly the approved document: redirects are not followed.
            if url != link {
                return Err(HostError::Invalid(
                    "the download is not the approved document".into(),
                ));
            }
            let source = crate::navigation::parse_navigation_url(&url)?;
            if Some(source.origin.as_str()) != self.policy.committed_origin() {
                return Err(HostError::Invalid("download left the page's origin".into()));
            }
            // One bounded read: the file cannot grow past the bound between
            // a size check and the read.
            let mut content = Vec::new();
            {
                use std::io::Read;
                std::fs::File::open(staged)
                    .and_then(|file| {
                        file.take(crate::transfers::MAX_TRANSFER_BYTES + 1)
                            .read_to_end(&mut content)
                    })
                    .map_err(|err| HostError::Platform(format!("staged download: {err}")))?;
            }
            if content.len() as u64 > crate::transfers::MAX_TRANSFER_BYTES {
                return Err(HostError::Invalid("transfer size out of bounds".into()));
            }
            crate::transfers::validate_transfer_size(declared, content.len() as u64)?;
            let name = destination
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| HostError::Invalid("destination has no file name".into()))?;
            if name.to_ascii_lowercase().ends_with(".pdf") {
                crate::transfers::validate_inert_pdf(name, &media, &content)?;
            } else {
                crate::transfers::validate_download_type(name, &media, &content)?;
            }
            let sha256 = sha256_hex(&content);
            let mut source_record = crate::transfers::DownloadSource {
                source_id: format!("dl-{dl_id}"),
                origin: source.origin,
                content_digest: sha256.clone(),
                issued_ms: 0,
                consumed: false,
            };
            source_record.consume(0)?;
            // The bytes must come from the approved document: checked before
            // anything is written to the approved folder.
            if !self.policy.activation_opened() {
                return Err(HostError::Invalid(
                    "postcondition unverified: the download opened another document".into(),
                ));
            }
            // A cancellation that arrived after the reply still wins: nothing
            // is written to the approved folder.
            if self.cancelled.load(Ordering::SeqCst) {
                return Err(self.fail_closed(UnavailableReason::Cancelled));
            }
            let path =
                crate::approved_folder::commit(destination_root, bound_root, relative, &content)?;
            Ok(CommittedDownload {
                path,
                sha256,
                bytes: content.len() as u64,
                source_url: url,
            })
        }

        /// How many staging folders of hosts that died this launch removed.
        pub fn swept_staging(&self) -> usize {
            self.swept_staging
        }

        /// How many ephemeral profiles of hosts that died this launch
        /// removed (#298).
        pub fn swept_profiles(&self) -> usize {
            self.swept_profiles
        }

        /// Test-only: this lifetime's download staging directory.
        #[cfg(test)]
        pub(crate) fn staging_dir(&self) -> &Path {
            &self.staging
        }

        /// Test-only view of an observed node: raw names never leave the
        /// host in product builds (callers get typed results such as
        /// `link_destination`).
        #[cfg(test)]
        pub(crate) fn host_node(&self, node_id: &str) -> Option<&HostNode> {
            self.host_nodes.get(node_id)
        }

        /// Graceful shutdown with a forced fallback: ask the worker to stop,
        /// wait for `bye` and its exit, then terminate the job regardless and
        /// confirm it is empty, then remove an ephemeral profile.
        pub fn shutdown(mut self) -> ShutdownReport {
            let bye = self.send(&WorkerRequest::Shutdown).is_ok()
                && matches!(self.reply(WORKER_SHUTDOWN_TIMEOUT), Ok(WorkerReply::Bye {}));
            let exited = self.process.wait_exit(WORKER_SHUTDOWN_TIMEOUT);
            self.finish(bye && exited == Some(0))
        }

        /// Forced termination (cancellation): no protocol exchange.
        pub fn kill(mut self) -> ShutdownReport {
            self.finish(false)
        }

        fn finish(&mut self, graceful: bool) -> ShutdownReport {
            self.finished = true;
            let _ = std::fs::remove_dir_all(&self.staging);
            let job_empty = self.process.terminate_and_confirm(WORKER_SHUTDOWN_TIMEOUT);
            let profile_removed = match self.profile.take() {
                Some(profile) => job_empty && remove_profile(&profile),
                None => true,
            };
            ShutdownReport {
                graceful,
                job_empty,
                profile_removed,
            }
        }
    }

    impl Drop for BrowserWorker {
        fn drop(&mut self) {
            if !self.finished {
                self.finish(false);
            }
        }
    }
}

#[cfg(not(windows))]
mod fallback {
    use super::*;

    /// The confinement design is Windows-only (the no-route proxy relies on
    /// Windows refusing connections to 0.0.0.0); elsewhere nothing launches.
    pub struct BrowserWorker {
        _private: (),
    }

    /// API parity: there is never a lifetime to cancel off Windows.
    #[derive(Debug, Clone)]
    pub struct CancelHandle {
        _private: (),
    }

    impl CancelHandle {
        pub fn cancel(&self) -> bool {
            false
        }
    }

    impl BrowserWorker {
        /// API parity: no worker ever exists off Windows.
        pub fn cancel_handle(&self) -> CancelHandle {
            CancelHandle { _private: () }
        }

        pub fn shutdown(self) -> ShutdownReport {
            ShutdownReport {
                graceful: false,
                job_empty: true,
                profile_removed: true,
            }
        }

        /// API parity: no worker ever exists off Windows.
        pub fn navigate(&mut self, _url: &str) -> Result<NavigationOutcome, HostError> {
            Err(HostError::Unavailable(
                UnavailableReason::UnsupportedRuntime,
            ))
        }

        /// API parity: no worker ever exists off Windows.
        pub fn observe(
            &mut self,
            _scope: &crate::observation::ObservationScope,
        ) -> Result<LiveObservation, HostError> {
            Err(HostError::Unavailable(
                UnavailableReason::UnsupportedRuntime,
            ))
        }

        /// API parity: no worker ever exists off Windows.
        pub fn execution_binding(
            &self,
            _tool_id: &str,
            _args: &serde_json::Map<String, serde_json::Value>,
        ) -> Result<String, HostError> {
            Err(HostError::Unavailable(
                UnavailableReason::UnsupportedRuntime,
            ))
        }

        /// API parity: no worker ever exists off Windows.
        pub fn execute_tool(
            &mut self,
            _target: &crate::actuation::ActuationTarget,
            _approval: &mut crate::actuation::ApprovalToken,
            _args: &serde_json::Map<String, serde_json::Value>,
            _policy_revision: u64,
            _workspace: &str,
        ) -> Result<ExecutionOutcome, HostError> {
            Err(HostError::Unavailable(
                UnavailableReason::UnsupportedRuntime,
            ))
        }

        /// API parity: no worker ever exists off Windows.
        pub fn discover_tools(&mut self) -> Result<crate::webmcp::DiscoveredTools, HostError> {
            Err(HostError::Unavailable(
                UnavailableReason::UnsupportedRuntime,
            ))
        }

        /// API parity: no worker ever exists off Windows.
        pub fn fetch_text(&mut self, _url: &str) -> Result<FetchedText, HostError> {
            Err(HostError::Unavailable(
                UnavailableReason::UnsupportedRuntime,
            ))
        }

        /// API parity: no worker ever exists off Windows.
        pub fn crawl_site(
            &mut self,
            _spec: &crate::crawl::CrawlSpec,
            _scope: &crate::observation::ObservationScope,
            _cancelled: &std::sync::atomic::AtomicBool,
        ) -> Result<crate::crawl::CrawlReport, HostError> {
            Err(HostError::Unavailable(
                UnavailableReason::UnsupportedRuntime,
            ))
        }

        /// API parity: no worker ever exists off Windows.
        pub fn extract_page(
            &mut self,
            _options: crate::extraction::ExtractOptions,
        ) -> Result<crate::extraction::PageExtraction, HostError> {
            Err(HostError::Unavailable(
                UnavailableReason::UnsupportedRuntime,
            ))
        }

        /// API parity: no worker ever exists off Windows.
        pub fn link_destination(&self, _node_id: &str) -> Result<String, HostError> {
            Err(HostError::Unavailable(
                UnavailableReason::UnsupportedRuntime,
            ))
        }

        /// API parity: no worker ever exists off Windows.
        pub fn download_binding(
            &self,
            _node_id: &str,
            _destination_root: &Path,
            _relative: &str,
        ) -> Result<String, HostError> {
            Err(HostError::Unavailable(
                UnavailableReason::UnsupportedRuntime,
            ))
        }

        /// API parity: no worker ever exists off Windows.
        #[allow(clippy::too_many_arguments)]
        pub fn download(
            &mut self,
            _target: &crate::actuation::ActuationTarget,
            _approval: &mut crate::actuation::ApprovalToken,
            _policy_revision: u64,
            _workspace: &str,
            _destination_root: &Path,
            _relative: &str,
        ) -> Result<CommittedDownload, HostError> {
            Err(HostError::Unavailable(
                UnavailableReason::UnsupportedRuntime,
            ))
        }

        /// API parity: no worker ever exists off Windows.
        pub fn select_latest_dated_link(&self) -> Result<String, HostError> {
            Err(HostError::Unavailable(
                UnavailableReason::UnsupportedRuntime,
            ))
        }

        /// API parity: no worker ever exists off Windows.
        pub fn activate(
            &mut self,
            _target: &crate::actuation::ActuationTarget,
            _approval: &mut crate::actuation::ApprovalToken,
            _policy_revision: u64,
            _workspace: &str,
        ) -> Result<NavigationOutcome, HostError> {
            Err(HostError::Unavailable(
                UnavailableReason::UnsupportedRuntime,
            ))
        }
    }

    pub fn launch_worker(
        spec: &WorkerLaunch,
        policy: &impl PolicySource,
    ) -> Result<BrowserWorker, HostError> {
        validate_launch(spec)?;
        assert_no_managed_policy(spec.engine.kind(), policy)
            .map_err(|_| HostError::Unavailable(UnavailableReason::ManagedPolicy))?;
        Err(HostError::Unavailable(
            UnavailableReason::UnsupportedRuntime,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(pid: u32, image: &str, argv: &[&str]) -> JobProcess {
        JobProcess {
            pid,
            image: PathBuf::from(image),
            argv: argv.iter().map(|arg| arg.to_string()).collect(),
        }
    }

    const NODE: &str = "C:\\Program Files\\nodejs\\node.exe";
    const EDGE: &str = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";

    fn expected() -> Vec<String> {
        vec![
            "--headless".into(),
            "--user-data-dir=C:\\p".into(),
            "about:blank".into(),
        ]
    }

    fn worker_args() -> Vec<String> {
        vec!["--disable-sigusr1".into(), "C:\\w\\main.js".into()]
    }

    fn healthy() -> Vec<JobProcess> {
        vec![
            process(10, NODE, &[NODE, "--disable-sigusr1", "C:\\w\\main.js"]),
            process(
                11,
                EDGE,
                &[EDGE, "--headless", "--user-data-dir=C:\\p", "about:blank"],
            ),
            process(
                12,
                EDGE,
                &[EDGE, "--type=renderer", "--user-data-dir=C:\\p"],
            ),
            process(13, EDGE, &[EDGE, "--type=gpu-process"]),
        ]
    }

    fn classify(processes: &[JobProcess]) -> Result<u32, HostError> {
        classify_job(
            processes,
            10,
            Path::new(NODE),
            &worker_args(),
            Path::new(EDGE),
            &expected(),
        )
    }

    #[test]
    fn a_healthy_job_yields_the_browser_pid() {
        assert_eq!(classify(&healthy()).unwrap(), 11);
        // Image paths compare case-insensitively.
        let mut upper = healthy();
        upper[1].image = PathBuf::from(EDGE.to_uppercase());
        assert_eq!(classify(&upper).unwrap(), 11);
        // A helper whose last `type` switch is non-empty stays a helper,
        // whatever its spelling.
        let mut helpers = healthy();
        helpers.push(process(18, EDGE, &[EDGE, "/Type=utility"]));
        helpers.push(process(19, EDGE, &[EDGE, "--type=", "--type=gpu-process"]));
        assert_eq!(classify(&helpers).unwrap(), 11);
    }

    #[test]
    fn every_unexpected_job_shape_is_refused() {
        let mut cases: Vec<Vec<JobProcess>> = Vec::new();
        // A second browser process (no --type=).
        let mut second = healthy();
        second.push(process(14, EDGE, &[EDGE, "--headless", "about:blank"]));
        cases.push(second);
        // No browser process at all.
        cases.push(healthy().into_iter().filter(|p| p.pid != 11).collect());
        // A foreign process in the job.
        let mut foreign = healthy();
        foreign.push(process(
            15,
            "C:\\Windows\\System32\\PING.EXE",
            &["PING.EXE"],
        ));
        cases.push(foreign);
        // The worker is not a member, or another node is.
        cases.push(healthy().into_iter().filter(|p| p.pid != 10).collect());
        let mut other_node = healthy();
        other_node.push(process(16, NODE, &[NODE, "evil.js"]));
        cases.push(other_node);
        // Browser argv drift: an added, removed or changed argument.
        for argv in [
            vec![
                EDGE,
                "--headless",
                "--user-data-dir=C:\\p",
                "--enable-automation",
                "about:blank",
            ],
            vec![EDGE, "--headless", "about:blank"],
            vec![EDGE, "--headless", "--user-data-dir=C:\\q", "about:blank"],
            vec![
                "C:\\other\\msedge.exe",
                "--headless",
                "--user-data-dir=C:\\p",
                "about:blank",
            ],
        ] {
            let mut drift = healthy();
            drift[1] = process(11, EDGE, &argv);
            cases.push(drift);
        }
        // A forbidden flag on a child process.
        let mut child = healthy();
        child[2] = process(
            12,
            EDGE,
            &[EDGE, "--type=renderer", "--remote-debugging-port=9222"],
        );
        cases.push(child);
        // The same flag in every other spelling Chromium accepts on Windows.
        for flag in [
            "-remote-debugging-port=9222",
            "/remote-debugging-port=9222",
            "--Remote-Debugging-Port=9222",
            "--NO-SANDBOX",
        ] {
            let mut child = healthy();
            child[2] = process(12, EDGE, &[EDGE, "--type=renderer", flag]);
            cases.push(child);
        }
        // A second browser disguised as a helper: Chromium takes the last
        // `type` switch, treats an empty value as the browser, accepts any
        // switch spelling, and stops reading switches at a bare `--`.
        for argv in [
            vec![EDGE, "--type=renderer", "--type=", "--user-data-dir=C:\\q"],
            vec![EDGE, "--type=renderer", "--type", "--user-data-dir=C:\\q"],
            vec![EDGE, "--type=", "--user-data-dir=C:\\q"],
            vec![EDGE, "--", "--type=renderer", "--user-data-dir=C:\\q"],
            vec![EDGE, "-type=renderer", "-type=", "--user-data-dir=C:\\q"],
            vec![
                EDGE,
                "--single-argument",
                "--type=renderer",
                "--user-data-dir=C:\\q",
            ],
            vec![EDGE, "/Single-Argument", "--type=renderer"],
        ] {
            let mut disguised = healthy();
            disguised.push(process(17, EDGE, &argv));
            cases.push(disguised);
        }
        // The worker with any arguments other than the host-built ones.
        for argv in [
            vec![NODE, "--disable-sigusr1", "C:\\w\\main.js", "--inspect"],
            vec![NODE, "--inspect", "C:\\w\\main.js"],
            vec![NODE, "--disable-sigusr1", "C:\\w\\other.js"],
            vec![NODE],
        ] {
            let mut drift = healthy();
            drift[0] = process(10, NODE, &argv);
            cases.push(drift);
        }
        // Over the job limit.
        let mut many = healthy();
        for pid in 100..100 + JOB_ACTIVE_PROCESS_LIMIT {
            many.push(process(pid, EDGE, &[EDGE, "--type=utility"]));
        }
        cases.push(many);
        for (index, case) in cases.iter().enumerate() {
            assert!(classify(case).is_err(), "case {index} was accepted");
        }
    }

    #[test]
    fn the_worker_environment_is_exactly_the_allowlist() {
        let env = worker_environment(Path::new("C:\\orcel\\tmp"));
        let keys: Vec<String> = env
            .iter()
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect();
        assert_eq!(keys, ["SystemRoot", "SystemDrive", "PATH", "TEMP", "TMP"]);
        let value = |key: &str| {
            env.iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.to_string_lossy().into_owned())
                .unwrap_or_default()
        };
        assert!(value("PATH").to_ascii_lowercase().ends_with("system32"));
        assert_eq!(value("TEMP"), "C:\\orcel\\tmp");
        assert_eq!(
            worker_node_args(Path::new("C:\\w\\main.js")),
            ["--disable-sigusr1", "C:\\w\\main.js"]
        );
    }

    #[test]
    fn profile_preferences_turn_preloading_off_and_keep_the_rest() {
        let dir = std::env::temp_dir().join(format!(
            "orcel-sg108-prefs-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let read = |dir: &Path| -> serde_json::Value {
            serde_json::from_str(
                &std::fs::read_to_string(dir.join("Default").join("Preferences")).unwrap(),
            )
            .unwrap()
        };
        // A fresh profile gets the preference.
        seed_profile_preferences(&dir).unwrap();
        assert_eq!(read(&dir)["net"]["network_prediction_options"], 2);
        assert_eq!(read(&dir)["plugins"]["always_open_pdf_externally"], true);
        // Existing preferences are kept and the value is forced.
        std::fs::write(
            dir.join("Default").join("Preferences"),
            r#"{"keep":1,"net":{"network_prediction_options":0,"other":true}}"#,
        )
        .unwrap();
        seed_profile_preferences(&dir).unwrap();
        let value = read(&dir);
        assert_eq!(value["keep"], 1);
        assert_eq!(value["net"]["other"], true);
        assert_eq!(value["net"]["network_prediction_options"], 2);
        // Malformed preferences fail closed.
        for bad in ["not json", "[1]", r#"{"net":5}"#] {
            std::fs::write(dir.join("Default").join("Preferences"), bad).unwrap();
            assert!(seed_profile_preferences(&dir).is_err(), "{bad}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(not(windows))]
    #[test]
    fn downloads_commit_create_only_inside_the_approved_folder() {
        let root = std::env::temp_dir().join(format!(
            "orcel-sg108-commit-{}-{:x}",
            std::process::id(),
            unique_suffix()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join("reports").join("r.pdf");
        commit_create_only(&target, &root, b"%PDF-1.4").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"%PDF-1.4");
        // Never replaces an existing file.
        assert!(matches!(
            commit_create_only(&target, &root, b"other"),
            Err(HostError::Invalid(message)) if message.contains("create-only")
        ));
        assert_eq!(std::fs::read(&target).unwrap(), b"%PDF-1.4");
        // A path that escapes the root is refused and leaves nothing behind.
        let outside = root
            .parent()
            .unwrap()
            .join(format!("orcel-sg108-outside-{:x}.pdf", unique_suffix()));
        assert!(commit_create_only(&outside, &root, b"x").is_err());
        assert!(!outside.exists());
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let json = |request: &WorkerRequest<'_>| serde_json::to_string(request).unwrap();
        assert_eq!(
            json(&WorkerRequest::Download {
                dl_id: 1,
                reference: "e5",
                path: "C:\\s\\dl-1.part"
            }),
            r#"{"frame":"download","dl_id":1,"ref":"e5","path":"C:\\s\\dl-1.part"}"#
        );
        let reply = |text: &str| serde_json::from_str::<WorkerReply>(text);
        assert!(reply(r#"{"frame":"downloaded","dl_id":1,"url":"https://fixture.test/r.pdf","name":"r.pdf","media":"application/pdf","bytes":8}"#).is_ok());
        assert!(reply(r#"{"frame":"download_failed","dl_id":1,"reason":"denied"}"#).is_ok());
        assert!(reply(
            r#"{"frame":"downloaded","dl_id":1,"url":"u","name":"n","media":"m","bytes":1,"x":0}"#
        )
        .is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn links_resolve_only_to_absolute_or_root_relative_https() {
        let origin = "https://fixture.test:443";
        assert_eq!(
            resolve_link(origin, "/archive/2026-09-30").unwrap(),
            "https://fixture.test/archive/2026-09-30"
        );
        assert_eq!(
            resolve_link(origin, "https://fixture.test/x").unwrap(),
            "https://fixture.test/x"
        );
        for link in [
            "archive/x",
            "//evil.test/x",
            "http://fixture.test/x",
            "javascript:alert(1)",
            "",
        ] {
            assert!(resolve_link(origin, link).is_err(), "{link}");
        }
        // Names entering SG-000076 are keyed per lifetime: the same name
        // gives unrelated digests under different keys.
        assert_ne!(
            keyed_name(&[1u8; 32], "HUNTER2PW"),
            keyed_name(&[2u8; 32], "HUNTER2PW")
        );
        assert_eq!(keyed_name(&[1u8; 32], "x").len(), 64);
    }

    #[test]
    fn dates_in_non_ascii_names_never_panic() {
        let link = |name: &str| HostNode {
            reference: "e1".into(),
            role: "link".into(),
            name: name.into(),
            url: None,
        };
        let mut nodes = std::collections::HashMap::new();
        nodes.insert("d1-e1".to_string(), link("Rapport — 2026-09-30"));
        nodes.insert("d1-e2".to_string(), link("Café 2026-06-30 ☕"));
        nodes.insert("d1-e3".to_string(), link("日本語レポート"));
        assert_eq!(select_latest_dated_link(&nodes).unwrap(), "d1-e1");
    }

    #[test]
    fn the_latest_dated_link_is_selected_and_ambiguity_refused() {
        let link = |name: &str| HostNode {
            reference: "e1".into(),
            role: "link".into(),
            name: name.into(),
            url: None,
        };
        let mut nodes = std::collections::HashMap::new();
        nodes.insert("d1-e1".to_string(), link("Quarterly report 2026-06-30"));
        nodes.insert("d1-e2".to_string(), link("Quarterly report 2026-09-30"));
        nodes.insert("d1-e3".to_string(), link("Report 2025-12-31"));
        nodes.insert(
            "d1-e4".to_string(),
            HostNode {
                role: "button".into(),
                ..link("Delete 2099-01-01")
            },
        );
        nodes.insert("d1-e5".to_string(), link("Invalid 2026-13-40"));
        assert_eq!(select_latest_dated_link(&nodes).unwrap(), "d1-e2");
        nodes.insert("d1-e6".to_string(), link("Duplicate 2026-09-30"));
        assert!(
            select_latest_dated_link(&nodes).is_err(),
            "a tie was guessed"
        );
        assert!(select_latest_dated_link(&std::collections::HashMap::new()).is_err());
        let json = |request: &WorkerRequest<'_>| serde_json::to_string(request).unwrap();
        assert_eq!(
            json(&WorkerRequest::Activate {
                act_id: 2,
                reference: "e5"
            }),
            r#"{"frame":"activate","act_id":2,"ref":"e5"}"#
        );
        let reply = |text: &str| serde_json::from_str::<WorkerReply>(text);
        assert!(reply(
            r#"{"frame":"activated","act_id":2,"url":"https://fixture.test/x","status":200}"#
        )
        .is_ok());
        assert!(reply(r#"{"frame":"activation_failed","act_id":2,"reason":"denied"}"#).is_ok());
        assert!(reply(r#"{"frame":"activated","act_id":2,"url":"u","status":200,"x":1}"#).is_err());
    }

    #[test]
    fn a_submission_names_exactly_the_approved_fields() {
        use crate::webmcp::{ControlKind, ExecField};
        use crate::worker_navigation::Submitted;
        let wire: Vec<crate::webmcp::WireTool> = serde_json::from_str(
            r#"[{"name":"t","title":"","description":"d","autosubmit":true,"node":3,"has_password":false,"action":"/s","method":"post","self_contained":true,"fixed_names":["csrf"],"utf8":true,"params":[
                {"name":"note","required":false,"control":"textarea","has_default":false,"type":"string"},
                {"name":"ok","required":false,"control":"checkbox","has_default":false,"type":"boolean"},
                {"name":"off","required":false,"control":"checkbox","has_default":false,"type":"boolean"},
                {"name":"tags","required":false,"control":"checkboxes","has_default":false,"type":"array","items_enum":["a","b"]},
                {"name":"left","required":false,"control":"text","has_default":false,"type":"string"}]}]"#,
        )
        .unwrap();
        let tool = crate::webmcp::validate_tools(wire, 1).unwrap().0.remove(0);
        let field = |name: &str, control, values: &[&str]| ExecField {
            name: name.into(),
            control,
            values: values.iter().map(|v| (*v).to_owned()).collect(),
        };
        let fields = [
            field("note", ControlKind::Textarea, &["a\nb"]),
            field("ok", ControlKind::Checkbox, &["true"]),
            field("off", ControlKind::Checkbox, &["false"]),
            field("tags", ControlKind::Checkboxes, &["b"]),
        ];
        let submission = submission_of(&tool, &fields, true);
        assert_eq!(submission.method, "POST");
        assert_eq!(
            submission.fields,
            vec![
                ("note".to_owned(), Submitted::Values(vec!["a\nb".into()])),
                ("ok".to_owned(), Submitted::Present),
                ("off".to_owned(), Submitted::Absent),
                ("tags".to_owned(), Submitted::Values(vec!["b".into()])),
            ]
        );
        assert_eq!(submission.unsupplied, vec!["left".to_owned()]);
        assert_eq!(submission.multiline, vec!["note".to_owned()]);
        assert_eq!(submission.fixed, vec!["csrf".to_owned()]);
        assert_eq!(submission_of(&tool, &fields, false).method, "GET");
    }

    #[test]
    fn execution_frames_are_exact() {
        let json = |request: &WorkerRequest<'_>| serde_json::to_string(request).unwrap();
        let fields = [crate::webmcp::ExecField {
            name: "q".into(),
            control: crate::webmcp::ControlKind::Text,
            values: vec!["rust".into()],
        }];
        assert_eq!(
            json(&WorkerRequest::Execute {
                exec_id: 3,
                tool: "search",
                fields: &fields
            }),
            r#"{"frame":"execute","exec_id":3,"tool":"search","fields":[{"name":"q","control":"text","values":["rust"]}]}"#
        );
        let reply = |text: &str| serde_json::from_str::<WorkerReply>(text);
        assert!(matches!(
            reply(r#"{"frame":"executed","exec_id":3,"url":"https://fixture.test/search?q=rust","status":200,"structured":["{}"],"structured_complete":true}"#).unwrap(),
            WorkerReply::Executed { exec_id: 3, status: 200, .. }
        ));
        assert!(matches!(
            reply(r#"{"frame":"execution_failed","exec_id":3,"reason":"timeout"}"#).unwrap(),
            WorkerReply::ExecutionFailed { exec_id: 3, .. }
        ));
        assert!(reply(
            r#"{"frame":"executed","exec_id":3,"url":"u","status":200,"structured":[],"structured_complete":true,"extra":1}"#
        )
        .is_err());
    }

    #[test]
    fn download_failures_are_typed() {
        use crate::error::DownloadFailure;
        for (reason, expected) in [
            ("http_status", DownloadFailure::HttpStatus),
            ("oversized", DownloadFailure::Oversized),
            ("timeout", DownloadFailure::TimedOut),
            ("failed", DownloadFailure::EngineFailed),
        ] {
            assert!(
                matches!(download_failure(reason), HostError::Download(got) if got == expected),
                "{reason}"
            );
        }
        assert!(matches!(
            download_failure("busy"),
            HostError::Unavailable(UnavailableReason::ActionFailed)
        ));
        assert!(matches!(
            download_failure("denied-by-magic"),
            HostError::Unavailable(UnavailableReason::ProtocolViolation)
        ));
    }

    #[test]
    fn text_fetch_frames_are_exact() {
        let json = |request: &WorkerRequest<'_>| serde_json::to_string(request).unwrap();
        assert_eq!(
            json(&WorkerRequest::FetchText {
                fetch_id: 4,
                url: "https://fixture.test/robots.txt"
            }),
            r#"{"frame":"fetch_text","fetch_id":4,"url":"https://fixture.test/robots.txt"}"#
        );
        let reply = |text: &str| serde_json::from_str::<WorkerReply>(text);
        assert!(matches!(
            reply(r#"{"frame":"fetched_text","fetch_id":4,"url":"https://fixture.test/robots.txt","status":200,"media":"text/plain","text":"User-agent: *","truncated":false}"#).unwrap(),
            WorkerReply::FetchedText { fetch_id: 4, status: 200, .. }
        ));
        assert!(matches!(
            reply(r#"{"frame":"fetch_failed","fetch_id":4,"reason":"denied"}"#).unwrap(),
            WorkerReply::FetchFailed { fetch_id: 4, .. }
        ));
        assert!(reply(
            r#"{"frame":"fetched_text","fetch_id":4,"url":"u","status":200,"media":"text/plain","text":"","truncated":false,"body":"x"}"#
        )
        .is_err());
    }

    #[test]
    fn extraction_frames_are_exact() {
        let json = |request: &WorkerRequest<'_>| serde_json::to_string(request).unwrap();
        assert_eq!(
            json(&WorkerRequest::Extract {
                ext_id: 2,
                links: true,
                images: false
            }),
            r#"{"frame":"extract","ext_id":2,"links":true,"images":false}"#
        );
        assert_eq!(
            json(&WorkerRequest::ExtractMore {
                ext_id: 2,
                piece: 1
            }),
            r#"{"frame":"extract_more","ext_id":2,"piece":1}"#
        );
        let reply = |text: &str| serde_json::from_str::<WorkerReply>(text);
        assert!(matches!(
            reply(r##"{"frame":"extracted","ext_id":2,"url":"https://fixture.test/","truncated":false,"piece":0,"total":2,"chunk":0,"content":"# A"}"##).unwrap(),
            WorkerReply::Extracted { ext_id: 2, piece: 0, total: 2, .. }
        ));
        assert!(matches!(
            reply(r#"{"frame":"extraction_failed","ext_id":2}"#).unwrap(),
            WorkerReply::ExtractionFailed { ext_id: 2 }
        ));
        for bad in [
            r#"{"frame":"extracted","ext_id":2,"url":"u","truncated":false,"piece":0,"total":1,"chunk":0,"content":"","html":"<b>"}"#,
            r#"{"frame":"extracted","ext_id":2,"url":"u","truncated":false,"piece":-1,"total":1,"chunk":0,"content":""}"#,
            r#"{"frame":"extracted","ext_id":2,"url":"u","truncated":false,"piece":0,"chunk":0,"content":""}"#,
        ] {
            assert!(reply(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn discovery_frames_are_exact() {
        let json = |request: &WorkerRequest<'_>| serde_json::to_string(request).unwrap();
        assert_eq!(
            json(&WorkerRequest::Discover { disc_id: 2 }),
            r#"{"frame":"discover","disc_id":2}"#
        );
        let reply = |text: &str| serde_json::from_str::<WorkerReply>(text);
        let tools = match reply(
            r#"{"frame":"discovered","disc_id":2,"url":"https://fixture.test/t","truncated":false,"tools":[{"name":"t","title":"","description":"d","autosubmit":false,"node":3,"has_password":false,"action":null,"method":"get","self_contained":false,"fixed_names":[],"utf8":true,"params":[]}]}"#,
        )
        .unwrap()
        {
            WorkerReply::Discovered { tools, .. } => tools,
            _ => Vec::new(),
        };
        assert_eq!(tools.len(), 1, "not a discovery");
        assert!(matches!(
            reply(r#"{"frame":"discovery_failed","disc_id":2}"#).unwrap(),
            WorkerReply::DiscoveryFailed { disc_id: 2 }
        ));
        // Unknown fields anywhere in a tool are refused.
        assert!(reply(
            r#"{"frame":"discovered","disc_id":2,"url":"u","truncated":false,"tools":[{"name":"t","title":"","description":"d","autosubmit":false,"node":3,"has_password":false,"action":null,"method":"get","self_contained":false,"fixed_names":[],"utf8":true,"params":[],"run":"x"}]}"#
        )
        .is_err());
    }

    #[test]
    fn observation_frames_and_identities_are_exact() {
        let json = |request: &WorkerRequest<'_>| serde_json::to_string(request).unwrap();
        assert_eq!(
            json(&WorkerRequest::Observe { obs_id: 4 }),
            r#"{"frame":"observe","obs_id":4}"#
        );
        let reply = |text: &str| serde_json::from_str::<WorkerReply>(text);
        let observed = reply(
            r#"{"frame":"observed","obs_id":4,"url":"https://fixture.test/r","truncated":false,"nodes":[{"ref":"e1","role":"list","name":"","children":[{"ref":"e2","role":"link","name":"Report 2026-09-30","url":"/r.pdf","children":[]}]}]}"#,
        )
        .unwrap();
        let nodes = match observed {
            WorkerReply::Observed { nodes, .. } => nodes,
            _ => Vec::new(),
        };
        assert_eq!(nodes.len(), 1, "not an observation");
        // Unknown fields (for example a field value) are refused anywhere.
        assert!(reply(r#"{"frame":"observed","obs_id":4,"url":"u","truncated":false,"nodes":[{"ref":"e1","role":"textbox","name":"","value":"secret","children":[]}]}"#).is_err());
        assert!(reply(r#"{"frame":"observation_failed","obs_id":4,"x":1}"#).is_err());
        // Identities are host-issued and bound to the document generation;
        // the raw name stays in the host index; values are always empty.
        let mut index = std::collections::HashMap::new();
        let key = [7u8; 32];
        let roots: Vec<_> = nodes
            .iter()
            .map(|n| input_node(n, 7, &key, &mut index))
            .collect();
        assert_eq!(roots[0].identity.node_id, "d7-e1");
        assert_eq!(roots[0].children[0].identity.node_id, "d7-e2");
        assert_eq!(roots[0].children[0].identity.document_generation, 7);
        assert!(roots[0].children[0].value.is_empty());
        let link = &index["d7-e2"];
        assert_eq!(link.name, "Report 2026-09-30");
        assert_eq!(link.url.as_deref(), Some("/r.pdf"));
        assert_eq!(WORKER_OBSERVATION_TIMEOUT, Duration::from_secs(10));
        // The SG-000076 pipeline digests names and checks generations.
        let scope = crate::observation::ObservationScope {
            workspace: "ws".into(),
            profile_identity: "profile".into(),
        };
        let page = crate::observation::PageIdentity {
            page_id: "p7".into(),
            origin: "https://fixture.test".into(),
            page_generation: 7,
        };
        let document = crate::observation::DocumentIdentity {
            page_id: "p7".into(),
            document_generation: 7,
        };
        let observation =
            crate::observation::observe_snapshot(&scope, &page, &document, &roots, 5).unwrap();
        let text = format!("{observation:?}");
        assert!(
            !text.contains("Report 2026-09-30"),
            "a raw name reached the observation"
        );
        let stale = crate::observation::DocumentIdentity {
            page_id: "p7".into(),
            document_generation: 8,
        };
        assert!(crate::observation::observe_snapshot(&scope, &page, &stale, &roots, 5).is_err());
    }

    #[test]
    fn navigation_frames_match_the_typescript_vocabulary() {
        let json = |request: &WorkerRequest<'_>| serde_json::to_string(request).unwrap();
        assert_eq!(
            json(&WorkerRequest::Navigate {
                nav_id: 3,
                url: "https://fixture.test/a"
            }),
            r#"{"frame":"navigate","nav_id":3,"url":"https://fixture.test/a"}"#
        );
        assert_eq!(
            json(&WorkerRequest::RouteDecision {
                request_id: 9,
                allow: false
            }),
            r#"{"frame":"route_decision","request_id":9,"allow":false}"#
        );
        let reply = |text: &str| serde_json::from_str::<WorkerReply>(text);
        assert_eq!(
            reply(r#"{"frame":"route_request","request_id":1,"kind":"frame","url":"https://x.test/","origin":"https://fixture.test","method":"GET","content_type":"","body":null,"body_bytes":0}"#).unwrap(),
            WorkerReply::RouteRequest {
                request_id: 1,
                kind: "frame".into(),
                url: "https://x.test/".into(),
                origin: "https://fixture.test".into(),
                method: "GET".into(),
                content_type: String::new(),
                body: None,
                body_bytes: 0
            }
        );
        assert_eq!(
            reply(
                r#"{"frame":"navigated","nav_id":3,"url":"https://fixture.test/a","status":200}"#
            )
            .unwrap(),
            WorkerReply::Navigated {
                nav_id: 3,
                url: "https://fixture.test/a".into(),
                status: 200
            }
        );
        assert_eq!(
            reply(r#"{"frame":"navigation_failed","nav_id":3,"reason":"denied"}"#).unwrap(),
            WorkerReply::NavigationFailed {
                nav_id: 3,
                reason: "denied".into()
            }
        );
        // Unknown fields, negative ids and out-of-range statuses are refused.
        assert!(reply(r#"{"frame":"navigated","nav_id":3,"url":"u","status":200,"x":1}"#).is_err());
        assert!(reply(
            r#"{"frame":"route_request","request_id":-1,"kind":"frame","url":"u","origin":"","method":"GET","content_type":"","body":null,"body_bytes":0}"#
        )
        .is_err());
        assert!(reply(r#"{"frame":"navigated","nav_id":3,"url":"u","status":70000}"#).is_err());
        // Failure reasons map onto the typed vocabulary.
        assert!(matches!(
            navigation_failure("denied"),
            HostError::Invalid(_)
        ));
        assert!(matches!(
            navigation_failure("timeout"),
            HostError::Unavailable(UnavailableReason::TimedOut)
        ));
        for reason in ["failed", "busy"] {
            assert!(matches!(
                navigation_failure(reason),
                HostError::Unavailable(UnavailableReason::ActionFailed)
            ));
        }
        assert!(matches!(
            navigation_failure("other"),
            HostError::Unavailable(UnavailableReason::ProtocolViolation)
        ));
        assert_eq!(WORKER_NAVIGATION_TIMEOUT, Duration::from_secs(45));
    }

    #[test]
    fn worker_frames_match_the_typescript_vocabulary() {
        let json = |request: &WorkerRequest<'_>| serde_json::to_string(request).unwrap();
        assert_eq!(
            json(&WorkerRequest::Hello { generation: 2 }),
            r#"{"frame":"hello","generation":2}"#
        );
        assert_eq!(json(&WorkerRequest::Shutdown), r#"{"frame":"shutdown"}"#);
        assert_eq!(
            json(&WorkerRequest::Ping { nonce: "n1" }),
            r#"{"frame":"ping","nonce":"n1"}"#
        );
        let argv = vec!["--headless".to_string()];
        let mut env = BTreeMap::new();
        env.insert("PATH".to_string(), "C:\\Windows\\System32".to_string());
        assert_eq!(
            json(&WorkerRequest::Launch {
                engine: "C:\\e.exe",
                profile_dir: "C:\\p",
                argv: &argv,
                env
            }),
            r#"{"frame":"launch","engine":"C:\\e.exe","profile_dir":"C:\\p","argv":["--headless"],"env":{"PATH":"C:\\Windows\\System32"}}"#
        );
        let reply = |text: &str| serde_json::from_str::<WorkerReply>(text);
        assert_eq!(
            reply(r#"{"frame":"hello","generation":1,"worker":"orcel-browser-worker"}"#).unwrap(),
            WorkerReply::Hello {
                generation: 1,
                worker: WORKER_IDENTITY.into()
            }
        );
        assert_eq!(
            reply(r#"{"frame":"launched"}"#).unwrap(),
            WorkerReply::Launched {}
        );
        assert!(reply(r#"{"frame":"launched","extra":1}"#).is_err());
        assert!(reply(r#"{"frame":"bye","extra":1}"#).is_err());
        assert_eq!(reply(r#"{"frame":"bye"}"#).unwrap(), WorkerReply::Bye {});
        assert!(reply(r#"{"frame":"navigate","url":"x"}"#).is_err());
        assert!(matches!(
            reply_error("launch_failed"),
            HostError::Unavailable(UnavailableReason::LaunchFailed)
        ));
        assert!(matches!(
            reply_error("launch_refused"),
            HostError::Invalid(_)
        ));
        assert!(matches!(
            reply_error("anything"),
            HostError::Unavailable(UnavailableReason::ProtocolViolation)
        ));
    }

    struct NoPolicy;
    impl PolicySource for NoPolicy {
        fn key_state(
            &self,
            _: crate::confinement::PolicyHive,
            _: &str,
        ) -> crate::confinement::PolicyKeyState {
            crate::confinement::PolicyKeyState::Absent
        }
    }

    #[test]
    fn a_lifetime_admits_exactly_one_destination() {
        let base = std::env::temp_dir();
        let engine = Engine::for_tests(base.join("msedge.exe"), crate::discovery::EngineKind::Edge);
        let destination = |host: &str| {
            crate::confinement::AdmittedDestination::fixture(
                host,
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            )
            .unwrap()
        };
        let launch = |destinations| WorkerLaunch {
            test_trusted_spki: None,
            runtime_pin: None,
            node: base.join("node.exe"),
            worker_main: base.join("main.js"),
            engine: engine.clone(),
            profile_dir: base.clone(),
            ephemeral_profile: false,
            temp_dir: base.clone(),
            destinations,
        };
        for destinations in [
            Vec::new(),
            vec![destination("fixture.test"), destination("other.test")],
        ] {
            assert!(matches!(
                validate_launch(&launch(destinations)),
                Err(HostError::Invalid(message)) if message.contains("exactly one destination")
            ));
        }
        // One destination passes this rule (and then fails on the missing
        // runtime, as a typed prerequisite).
        assert!(matches!(
            validate_launch(&launch(vec![destination("fixture.test")])),
            Err(HostError::Unavailable(
                UnavailableReason::UnsupportedRuntime
            ))
        ));
    }

    #[test]
    fn an_unqualified_engine_version_is_refused_before_anything_runs() {
        // A10: every prerequisite present, only the engine version outside
        // the qualified window: a typed refusal, nothing spawned.
        let base = std::env::temp_dir().join(format!(
            "orcel-a10-{}-{:x}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        for name in ["msedge.exe", "chrome.exe", "node.exe", "main.js"] {
            std::fs::write(base.join(name), b"").unwrap();
        }
        let spec = |engine: Engine| WorkerLaunch {
            test_trusted_spki: None,
            runtime_pin: None,
            node: base.join("node.exe"),
            worker_main: base.join("main.js"),
            engine,
            profile_dir: base.clone(),
            ephemeral_profile: false,
            temp_dir: base.clone(),
            destinations: vec![crate::confinement::AdmittedDestination::fixture(
                "fixture.test",
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            )
            .unwrap()],
        };
        use crate::discovery::EngineKind::{Chromium, Edge};
        for (name, kind, version) in [
            ("msedge.exe", Edge, "154.0.1.2"),
            ("msedge.exe", Edge, "156.0.1.2"),
            ("chrome.exe", Chromium, "157.0.4283.45"),
            ("chrome.exe", Chromium, "153.0.1.2"),
        ] {
            let engine = Engine::for_tests_at(base.join(name), kind, version);
            assert!(
                matches!(
                    validate_launch(&spec(engine)),
                    Err(HostError::Unavailable(UnavailableReason::UnsupportedEngine))
                ),
                "{kind:?} {version}"
            );
        }
        // The qualified version passes this rule.
        let engine = Engine::for_tests_at(base.join("msedge.exe"), Edge, "155.0.4283.45");
        assert!(validate_launch(&spec(engine)).is_ok());
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn missing_prerequisites_are_typed_and_nothing_is_spawned() {
        let base = std::env::temp_dir();
        // Built from temp_dir so the path is absolute on every platform.
        let engine = Engine::for_tests(base.join("msedge.exe"), crate::discovery::EngineKind::Edge);
        let spec = |node: PathBuf, main: PathBuf| WorkerLaunch {
            test_trusted_spki: None,
            runtime_pin: None,
            node,
            worker_main: main,
            engine: engine.clone(),
            profile_dir: base.clone(),
            ephemeral_profile: false,
            temp_dir: base.clone(),
            destinations: vec![crate::confinement::AdmittedDestination::fixture(
                "fixture.test",
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            )
            .unwrap()],
        };
        let missing = base.join("orcel-sg108-missing");
        // A missing Node or worker is a missing prerequisite.
        assert!(matches!(
            launch_worker(
                &spec(missing.join("node.exe"), missing.join("main.js")),
                &NoPolicy
            ),
            Err(HostError::Unavailable(
                UnavailableReason::UnsupportedRuntime
            ))
        ));
        // A relative path is an invalid request.
        assert!(matches!(
            launch_worker(
                &spec(PathBuf::from("node.exe"), missing.join("main.js")),
                &NoPolicy
            ),
            Err(HostError::Invalid(_))
        ));
    }
}

#[cfg(all(test, windows))]
#[path = "worker_launch_tests.rs"]
mod native_tests;
