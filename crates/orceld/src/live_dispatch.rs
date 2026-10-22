//! SG-000108 slice 3c: orceld's dispatch of the live browser shapes.
//!
//! `handle_envelope` routes a shape here only after the profile gate
//! admitted it (a local request naming `browser_structured`) and policy
//! authorized its live form (`PolicyEngine::authorize_live_browser`). The
//! live browser exists only in `live-browser-dev` builds (decision 7); every
//! other build, release builds included, answers typed unavailable.
//!
//! The six shapes:
//! - `browser.page/open {}`: the live page, allocated in the page store; no
//!   lifetime and no network yet. A page already open ends.
//! - `browser.navigation/navigate {page_id, url, expected_generation}`: a
//!   broker-approved navigation. A page with no lifetime, or one on another
//!   origin, first gets a lifetime for the URL's origin, which the host
//!   admits and pins itself, and the approval binds that pin.
//! - `browser.snapshot/observe {page_id, expected_generation}`: identities
//!   and digests only, plus the host's typed selection of the latest dated
//!   link. No approval.
//! - `browser.dom/click {page_id, node_id, expected_generation}`: a
//!   broker-approved activation of one observed link.
//! - `browser.download/preview {page_id, node_id, file_name,
//!   expected_generation}`: what the download would read and where it
//!   would land. Writes and consumes nothing.
//! - `browser.download/download {...the same}`: a broker-approved,
//!   create-only download into the workspace's approved download root,
//!   verified by the host and journaled first.

use orcel_approval::ApprovalBroker;
use orcel_contracts::{FailureCode, RequestEnvelope};
use orcel_policy::Workspace;
use orcel_provider_fs::ProviderError;
use serde_json::Value;

/// Dispatch one live browser shape.
pub fn dispatch(
    workspace: &Workspace,
    approval: &impl ApprovalBroker,
    request: &RequestEnvelope,
) -> Result<Value, ProviderError> {
    #[cfg(all(windows, feature = "live-browser-dev"))]
    {
        live::dispatch(workspace, approval, request)
    }
    #[cfg(not(all(windows, feature = "live-browser-dev")))]
    {
        let _ = (workspace, approval, request);
        Err(unavailable())
    }
}

/// What every build without the live browser answers.
#[cfg_attr(all(windows, feature = "live-browser-dev"), allow(dead_code))]
pub fn unavailable() -> ProviderError {
    ProviderError::new(
        FailureCode::ProviderUnavailable,
        "the live browser exists only in live-browser-dev builds until SG-000106 ships a signed, pinned runtime",
    )
}

#[cfg(all(windows, feature = "live-browser-dev"))]
mod live {
    use super::*;
    use crate::live_browser::{LiveBrowser, LiveState};
    use orcel_browser_host::WorkerHostLaunch;
    use serde_json::json;
    use std::cell::RefCell;
    use std::path::PathBuf;

    thread_local! {
        /// orceld serves one request at a time on one thread: the browser
        /// (one host, at most one lifetime and one page) lives across them.
        static BROWSER: RefCell<Option<LiveBrowser>> = const { RefCell::new(None) };
    }

    fn string<'a>(request: &'a RequestEnvelope, name: &str) -> Result<&'a str, ProviderError> {
        request
            .arguments
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ProviderError::new(
                    FailureCode::InvalidRequest,
                    format!("live browser request requires arguments.{name}"),
                )
            })
    }

    fn generation(request: &RequestEnvelope) -> Result<u64, ProviderError> {
        request
            .arguments
            .get("expected_generation")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                ProviderError::new(
                    FailureCode::InvalidRequest,
                    "live browser request requires arguments.expected_generation",
                )
            })
    }

    /// The host binary beside orceld's own executable: never a caller's or
    /// a setting's. Test builds may name the one the test harness built.
    fn host_binary() -> Result<PathBuf, ProviderError> {
        #[cfg(test)]
        if let Some(path) = std::env::var_os("ORCEL_SG108_HOST_BINARY") {
            return Ok(PathBuf::from(path));
        }
        let exe = std::env::current_exe().map_err(|_| super::unavailable())?;
        Ok(exe.with_file_name("orcel-browser-host.exe"))
    }

    /// Supervise a host under orceld's protected browser state.
    fn start() -> Result<LiveBrowser, ProviderError> {
        let root = orcel_provider_browser::default_profile_root()
            .map_err(|error| crate::state_unavailable("browser profile", &error))?
            .join("live");
        let launch = WorkerHostLaunch {
            node: None,
            worker_main: None,
            profile_root: root.join("profiles"),
            temp_dir: root.join("staging"),
            state_root: root.join("host"),
        };
        for dir in [&launch.profile_root, &launch.temp_dir, &launch.state_root] {
            std::fs::create_dir_all(dir).map_err(|_| {
                ProviderError::new(
                    FailureCode::ProviderUnavailable,
                    "the live browser state could not be created",
                )
            })?;
        }
        LiveBrowser::start(
            &host_binary()?,
            &launch,
            &LiveState {
                pages: root.join("pages.jsonl"),
                intents: root.join("intents.jsonl"),
            },
        )
    }

    /// Run `action` on the live browser, starting one (or replacing one
    /// whose host is gone) first.
    fn with_browser<T>(
        action: impl FnOnce(&mut LiveBrowser) -> Result<T, ProviderError>,
    ) -> Result<T, ProviderError> {
        BROWSER.with(|cell| {
            let mut slot = cell.borrow_mut();
            if slot.as_mut().is_some_and(|browser| !browser.is_usable()) {
                if let Some(old) = slot.take() {
                    let _ = old.shutdown();
                }
            }
            if slot.is_none() {
                *slot = Some(start()?);
            }
            match slot.as_mut() {
                Some(browser) => action(browser),
                None => Err(super::unavailable()),
            }
        })
    }

    pub(super) fn dispatch(
        workspace: &Workspace,
        approval: &impl ApprovalBroker,
        request: &RequestEnvelope,
    ) -> Result<Value, ProviderError> {
        match (request.capability.as_str(), request.operation.as_str()) {
            ("browser.page", "open") => with_browser(|browser| {
                // What a restart reconciled from an earlier run's lost
                // downloads is reported once, here (judge, slice 3c): never
                // adopted as a committed download.
                let recovered: Vec<Value> = browser
                    .take_recovered()
                    .into_iter()
                    .map(|(intent, found)| {
                        let state = match found {
                            Ok(crate::live_browser::Reconciled::Absent) => json!({"state": "absent"}),
                            Ok(crate::live_browser::Reconciled::PresentUnverified { sha256, bytes }) => {
                                json!({"state": "present_unverified", "sha256": sha256, "bytes": bytes})
                            }
                            Err(error) => json!({"state": "unreadable", "code": error.code}),
                        };
                        json!({
                            "record_id": intent.record_id,
                            "file_name": intent.relative,
                            "destination": state,
                        })
                    })
                    .collect();
                let page = browser.open_page(workspace)?;
                Ok(json!({
                    "page_id": page.page_id,
                    "generation": page.generation,
                    "origin": page.current_origin,
                    "live": true,
                    "recovered_downloads": recovered,
                }))
            }),
            ("browser.navigation", "navigate") => {
                let (page_id, url, expected) = (
                    string(request, "page_id")?,
                    string(request, "url")?,
                    generation(request)?,
                );
                with_browser(|browser| {
                    let (committed, status) =
                        browser.navigate_live(workspace, approval, page_id, expected, url)?;
                    let page = browser.page().cloned().ok_or_else(stale)?;
                    Ok(json!({
                        "page_id": page.page_id,
                        "generation": page.generation,
                        "origin": page.current_origin,
                        "url": committed,
                        "status": status,
                    }))
                })
            }
            ("browser.snapshot", "observe") => {
                let (page_id, expected) = (string(request, "page_id")?, generation(request)?);
                with_browser(|browser| {
                    let (page, nodes, latest) =
                        browser.observe_live(workspace, page_id, expected)?;
                    Ok(json!({
                        "page_id": page.page_id,
                        "generation": page.generation,
                        "origin": page.current_origin,
                        "nodes": nodes,
                        "latest_dated_link": latest,
                        "untrusted": "names and values never leave the isolated browser; nodes carry identities and keyed digests only",
                    }))
                })
            }
            ("browser.dom", "click") => {
                let (page_id, node_id, expected) = (
                    string(request, "page_id")?,
                    string(request, "node_id")?,
                    generation(request)?,
                );
                with_browser(|browser| {
                    let (url, status) =
                        browser.click(workspace, approval, page_id, expected, node_id)?;
                    let page = browser.page().cloned().ok_or_else(stale)?;
                    Ok(json!({
                        "page_id": page.page_id,
                        "generation": page.generation,
                        "url": url,
                        "status": status,
                    }))
                })
            }
            ("browser.download", operation @ ("preview" | "download")) => {
                let (page_id, node_id, file_name, expected) = (
                    string(request, "page_id")?,
                    string(request, "node_id")?,
                    string(request, "file_name")?,
                    generation(request)?,
                );
                let folder = orcel_provider_browser::resolve_download_root(&workspace.root)
                    .map_err(|error| ProviderError::new(error.code, error.message))?;
                with_browser(|browser| {
                    if operation == "preview" {
                        let (_binding, source) = browser.preview_download(
                            workspace, page_id, expected, node_id, &folder, file_name,
                        )?;
                        // Only a same-origin document can be downloaded, and
                        // only its link crosses, bounded and marked as
                        // page-controlled (judge, slice 3c).
                        let origin = browser
                            .page()
                            .map(|page| page.current_origin.clone())
                            .unwrap_or_default();
                        let same_origin = source.len() <= MAX_SOURCE_BYTES
                            && orcel_provider_browser::parse_destination_url(&source)
                                .is_ok_and(|parsed| parsed.origin == origin);
                        if !same_origin {
                            return Err(ProviderError::new(
                                FailureCode::CapabilityDenied,
                                "the link leaves the live page's origin; only same-origin documents are downloaded",
                            ));
                        }
                        // Not the raw link: its path and query are the
                        // page's text. The origin is the page's own, the
                        // name is its last segment (bounded, plain), and the
                        // digest identifies the link (judge, slice 3c).
                        let name = source
                            .split(['?', '#'])
                            .next()
                            .and_then(|path| path.rsplit('/').next())
                            .unwrap_or("");
                        let name = if name.len() <= MAX_SOURCE_NAME_BYTES
                            && name
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
                        {
                            name
                        } else {
                            ""
                        };
                        return Ok(json!({
                            "page_id": page_id,
                            "generation": expected,
                            "node_id": node_id,
                            "source_origin": origin,
                            "source_name": name,
                            "source_sha256": crate::live_browser::sha256_hex(&source),
                            "source_is_page_controlled": true,
                            "destination_folder": folder.to_string_lossy(),
                            "file_name": file_name,
                            "approval": "SOFT",
                            "writes": false,
                        }));
                    }
                    browser.live_page(workspace, page_id, expected)?;
                    let committed =
                        browser.download(workspace, approval, node_id, &folder, file_name)?;
                    let record_id = committed.record_id.clone();
                    // The worker downloads by following the link and never
                    // renders the document it captured, so the page no
                    // longer shows what was observed: the page store moves
                    // to a new generation, and the caller navigates again
                    // before acting on it. If the store cannot follow, the
                    // lifetime ends (follow), and the committed file is
                    // still reported, with no generation.
                    let generation = browser
                        .follow(&committed.source_url)
                        .ok()
                        .map(|page| page.generation);
                    Ok(json!({
                        "page_id": page_id,
                        "generation": generation,
                        "relative": committed.relative,
                        "sha256": committed.sha256,
                        "bytes": committed.bytes,
                        "source_url": committed.source_url,
                        "record_id": record_id,
                        "create_only": true,
                    }))
                })
            }
            _ => Err(ProviderError::new(
                FailureCode::CapabilityDenied,
                "not a live browser shape",
            )),
        }
    }

    /// The longest link a preview accepts.
    const MAX_SOURCE_BYTES: usize = 2048;
    /// The longest file name of a link a preview hands out.
    const MAX_SOURCE_NAME_BYTES: usize = 128;

    fn stale() -> ProviderError {
        ProviderError::new(FailureCode::TargetStale, "no live browser page")
    }
}

/// SG-000108 `done_when`: the public journey through the real kernel caller.
/// `handle_envelope` (profile gate, live policy, live dispatch) drives the
/// supervised development host on a public HTTPS site, under the real
/// approval broker (its ledger, nonces, digests and single use; only the
/// SOFT consent dialog is scripted). Run by `npm run browser-launcher:native`
/// with the dev host binary it built with the runtime's real pin.
#[cfg(all(test, windows, feature = "live-browser-dev"))]
mod native {
    use crate::{handle_envelope, profile_gate, remote_lease};
    use orcel_approval::{ApprovalDecision, LocalApprovalBroker, NoPresenceVerifier};
    use orcel_audit::AuditLogger;
    use orcel_contracts::{
        FailureCode, RemoteRequestEnvelope, RequestEnvelope, ResponseEnvelope,
        INTERNAL_PROTOCOL_VERSION,
    };
    use orcel_policy::{PolicyEngine, Workspace};
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    /// The public document list: the Federal Reserve's FOMC meeting calendar,
    /// whose minutes are same-origin PDFs named by meeting date.
    const DEFAULT_PUBLIC_LIST: &str =
        "https://www.federalreserve.gov/monetarypolicy/fomccalendars.htm";

    struct Kernel {
        policy: PolicyEngine,
        audit: AuditLogger,
        workspaces: remote_lease::WorkspaceSet,
        root: PathBuf,
        workspace: PathBuf,
    }

    impl Kernel {
        fn new() -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            // orceld refuses state a different user could reach; a machine
            // whose temp folder grants more than that can name another
            // parent for this run (test-only).
            let parent = std::env::var_os("ORCEL_SG108_STATE_PARENT")
                .map(PathBuf::from)
                .unwrap_or_else(std::env::temp_dir);
            let root = parent.join(format!(
                "sg108-public-journey-{}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(root.join("workspace")).expect("workspace");
            std::fs::create_dir_all(root.join("state")).expect("state");
            // orceld's browser state for this run (profiles, staging, page
            // store, intent journal) under the test's own directory.
            std::env::set_var("ORCEL_BROWSER_STATE_DIR", root.join("state"));
            let workspace = std::fs::canonicalize(root.join("workspace")).expect("canonical");
            let policy = PolicyEngine::new(vec![Workspace {
                id: "default".into(),
                root: workspace.clone(),
            }])
            .expect("policy");
            let audit = AuditLogger::new(root.join("audit.jsonl")).expect("audit");
            let workspaces =
                remote_lease::WorkspaceSet::from_pairs(&[("default".into(), workspace.clone())]);
            Self {
                policy,
                audit,
                workspaces,
                root,
                workspace,
            }
        }

        fn call(
            &self,
            approval: &impl orcel_approval::ApprovalBroker,
            capability: &str,
            operation: &str,
            arguments: Value,
            profile: Option<&str>,
        ) -> ResponseEnvelope {
            handle_envelope(
                &self.policy,
                &self.audit,
                approval,
                &self.workspaces,
                RemoteRequestEnvelope {
                    request: RequestEnvelope {
                        version: INTERNAL_PROTOCOL_VERSION,
                        request_id: format!("sg108-{capability}-{operation}"),
                        client_session_id: "sg108-journey".into(),
                        workspace_id: "default".into(),
                        capability: capability.into(),
                        operation: operation.into(),
                        target: None,
                        arguments,
                    },
                    remote: None,
                    profile: profile.map(str::to_owned),
                },
            )
        }
    }

    fn ok(response: &ResponseEnvelope, what: &str) -> Value {
        assert!(
            response.ok,
            "{what} failed: {:?}",
            response.error.as_ref().map(|e| (&e.code, &e.message))
        );
        response.result.clone().unwrap_or(Value::Null)
    }

    fn code(response: &ResponseEnvelope) -> FailureCode {
        response.error.as_ref().expect("a failure").code.clone()
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// Every link node of an observation, depth-first.
    fn links(nodes: &Value, into: &mut Vec<String>) {
        for node in nodes.as_array().into_iter().flatten() {
            if node["role"] == "link" {
                if let Some(id) = node["node_id"].as_str() {
                    into.push(id.to_owned());
                }
            }
            links(&node["children"], into);
        }
    }

    /// The independent checker: fetch the document again outside Orcel
    /// (curl.exe, the system's own TLS stack) and return its bytes.
    fn independent_fetch(url: &str, into: &Path) -> Vec<u8> {
        let status = std::process::Command::new("curl.exe")
            .args([
                "--silent",
                "--show-error",
                "--fail",
                "--proto",
                "=https",
                "--max-time",
                "120",
                "-o",
            ])
            .arg(into)
            .arg(url)
            .status()
            .expect("curl.exe");
        assert!(status.success(), "the independent fetch failed: {status:?}");
        std::fs::read(into).expect("the independent copy")
    }

    #[test]
    #[ignore = "requires the built browser worker and Edge; run by npm run browser-launcher:native"]
    fn the_public_journey_downloads_and_verifies_the_latest_dated_pdf_through_the_kernel() {
        let kernel = Kernel::new();
        let list =
            std::env::var("ORCEL_SG108_PUBLIC_LIST").unwrap_or_else(|_| DEFAULT_PUBLIC_LIST.into());
        let approve = LocalApprovalBroker::with_path_and_soft_decider(
            kernel.root.join("approvals.json"),
            Arc::new(NoPresenceVerifier),
            Arc::new(|_| ApprovalDecision::Approved),
        );
        let deny = LocalApprovalBroker::with_path_and_soft_decider(
            kernel.root.join("denials.json"),
            Arc::new(NoPresenceVerifier),
            Arc::new(|_| ApprovalDecision::Denied),
        );
        let live = Some(profile_gate::BROWSER_STRUCTURED_PROFILE);

        // Without the profile, the gate refuses before anything starts.
        assert_eq!(
            code(&kernel.call(&approve, "browser.page", "open", json!({}), None)),
            FailureCode::CapabilityDenied
        );
        let opened = ok(
            &kernel.call(&approve, "browser.page", "open", json!({}), live),
            "open",
        );
        let page_id = opened["page_id"].as_str().expect("page id").to_owned();
        assert_eq!(opened["generation"], 0);

        // A denied navigation reaches no site and leaves the page where it
        // was: the same generation, no lifetime.
        let denied = kernel.call(
            &deny,
            "browser.navigation",
            "navigate",
            json!({"page_id": page_id, "url": list, "expected_generation": 0}),
            live,
        );
        // Where the lifetime cannot start (a managed browser policy, or a
        // node.exe folder the user can change, as on CI), it is refused
        // typed before any prompt.
        for (refusal, line) in [
            ("managedpolicy", "managed policy present"),
            ("unsupportedruntime", "runtime refused"),
        ] {
            if denied
                .error
                .as_ref()
                .is_some_and(|e| e.message.contains(refusal))
            {
                assert_eq!(code(&denied), FailureCode::ProviderUnavailable);
                println!(
                    "SG108-EVIDENCE public journey refused: {line}; the lifetime was refused typed"
                );
                let _ = std::fs::remove_dir_all(&kernel.root);
                return;
            }
        }
        assert_eq!(
            code(&denied),
            FailureCode::ApprovalDenied,
            "{:?}",
            denied.error
        );

        let navigated = ok(
            &kernel.call(
                &approve,
                "browser.navigation",
                "navigate",
                json!({"page_id": page_id, "url": list, "expected_generation": 0}),
                live,
            ),
            "navigate",
        );
        assert_eq!(navigated["status"], 200, "{navigated}");
        let generation = navigated["generation"].as_u64().expect("generation");
        assert_eq!(generation, 1);
        // A stale generation is refused before anything is asked.
        assert_eq!(
            code(&kernel.call(
                &approve,
                "browser.snapshot",
                "observe",
                json!({"page_id": page_id, "expected_generation": 0}),
                live
            )),
            FailureCode::TargetStale
        );
        let observed = ok(
            &kernel.call(
                &approve,
                "browser.snapshot",
                "observe",
                json!({"page_id": page_id, "expected_generation": generation}),
                live,
            ),
            "observe",
        );
        let text = observed.to_string();
        assert!(
            !text.contains("Federal Open Market Committee"),
            "page text crossed"
        );
        let mut nodes = Vec::new();
        links(&observed["nodes"], &mut nodes);
        assert!(!nodes.is_empty(), "no links observed");

        // Find the dated documents: preview each link (writes and asks
        // nothing) and keep the same-origin PDFs named by a date.
        let dated = regex_free_dated_pdfs(&kernel, &approve, &page_id, generation, &nodes);
        // The public list names its documents by date in their file names,
        // not in the links' accessible names, so the host's typed selection
        // (proven on the controlled fixture, A6) has nothing to select here;
        // the caller picks the latest minutes from the previews instead.
        if let Some(latest) = observed["latest_dated_link"].as_str() {
            println!("SG108-EVIDENCE public journey note: the host also selected {latest}");
        }
        let (date, node, identity) = dated
            .iter()
            .filter(|(_, _, identity)| identity.starts_with("fomcminutes"))
            .max()
            .cloned()
            .expect("dated minutes on the public list");
        // The independent checker reads the list itself and agrees that this
        // is the latest minutes document it names.
        let listed =
            String::from_utf8_lossy(&independent_fetch(&list, &kernel.root.join("list.html")))
                .into_owned();
        let latest_listed = listed
            .match_indices("fomcminutes")
            .filter_map(|(at, _)| {
                listed.get(at + "fomcminutes".len()..at + "fomcminutes".len() + 12)
            })
            .filter(|tail| tail.ends_with(".pdf") && tail[..8].bytes().all(|b| b.is_ascii_digit()))
            .map(|tail| tail[..8].to_owned())
            .max()
            .expect("the list page names dated minutes");
        assert_eq!(
            date, latest_listed,
            "the journey did not pick the latest minutes"
        );
        let file_name = format!("fomc-minutes-{date}.pdf");
        let preview = ok(
            &kernel.call(
                &approve,
                "browser.download",
                "preview",
                json!({"page_id": page_id, "node_id": node, "file_name": file_name, "expected_generation": generation}),
                live,
            ),
            "preview",
        );
        assert_eq!(preview["writes"], false);
        assert!(
            !kernel.workspace.join(&file_name).exists(),
            "the preview wrote"
        );

        let committed = ok(
            &kernel.call(
                &approve,
                "browser.download",
                "download",
                json!({"page_id": page_id, "node_id": node, "file_name": file_name, "expected_generation": generation}),
                live,
            ),
            "download",
        );
        let path = kernel.workspace.join(&file_name);
        let bytes = std::fs::read(&path).expect("the committed file");
        assert!(
            bytes.starts_with(b"%PDF-"),
            "the committed file is not a PDF"
        );
        assert_eq!(committed["sha256"], sha256_hex(&bytes));
        assert_eq!(committed["bytes"], bytes.len() as u64);
        // The link the preview identified is the one committed.
        let source = committed["source_url"].as_str().expect("source").to_owned();
        assert!(
            identity.ends_with(&format!(" {}", sha256_hex(source.as_bytes()))),
            "the committed link is not the previewed one"
        );
        // The independent checker: the same URL fetched outside Orcel.
        let independent = independent_fetch(&source, &kernel.root.join("independent.pdf"));
        assert_eq!(
            sha256_hex(&independent),
            sha256_hex(&bytes),
            "the bytes differ from the site's"
        );

        // The download followed the link, so the page moved on: the old
        // generation is stale, and the list is navigated again.
        let after = committed["generation"]
            .as_u64()
            .expect("generation after the download");
        assert_eq!(after, generation + 1);
        assert_eq!(
            code(&kernel.call(
                &approve,
                "browser.snapshot",
                "observe",
                json!({"page_id": page_id, "expected_generation": generation}),
                live
            )),
            FailureCode::TargetStale
        );
        let renavigated = ok(
            &kernel.call(
                &approve,
                "browser.navigation",
                "navigate",
                json!({"page_id": page_id, "url": list, "expected_generation": after}),
                live,
            ),
            "navigate again",
        );
        let generation = renavigated["generation"].as_u64().expect("generation");
        assert_eq!(generation, after + 1);

        // Create-only: the same document to the same name again, through a
        // fresh observation and a fresh approval, is refused at the commit
        // itself, and the file is unchanged (judge, slice 3c).
        let observed_again = ok(
            &kernel.call(
                &approve,
                "browser.snapshot",
                "observe",
                json!({"page_id": page_id, "expected_generation": generation}),
                live,
            ),
            "observe again",
        );
        let mut nodes_again = Vec::new();
        links(&observed_again["nodes"], &mut nodes_again);
        let node_again =
            regex_free_dated_pdfs(&kernel, &approve, &page_id, generation, &nodes_again)
                .into_iter()
                .find(|(_, _, again)| again == &identity)
                .map(|(_, node, _)| node)
                .expect("the same document observed again");
        let again = kernel.call(
            &approve,
            "browser.download",
            "download",
            json!({"page_id": page_id, "node_id": node_again, "file_name": file_name, "expected_generation": generation}),
            live,
        );
        assert!(!again.ok, "a second download replaced the file");
        assert_eq!(
            code(&again),
            FailureCode::InvalidRequest,
            "the second download was not refused by the create-only commit: {:?}",
            again.error
        );
        assert_eq!(std::fs::read(&path).expect("file"), bytes);
        // Nothing else landed in the workspace.
        let entries: Vec<_> = std::fs::read_dir(&kernel.workspace)
            .expect("workspace")
            .flatten()
            .map(|e| e.file_name())
            .collect();
        assert_eq!(entries.len(), 1, "{entries:?}");
        println!(
            "SG108-EVIDENCE public journey: {list} -> {source} committed create-only as {file_name}, {} bytes, sha256 {}, equal to the independent fetch",
            bytes.len(),
            sha256_hex(&bytes)
        );
        let _ = std::fs::remove_dir_all(&kernel.root);
    }

    /// (date, node, "name digest") for every previewed link that is a same-origin
    /// PDF whose file name carries a YYYYMMDD or YYYY-MM-DD date.
    fn regex_free_dated_pdfs(
        kernel: &Kernel,
        approve: &LocalApprovalBroker,
        page_id: &str,
        generation: u64,
        nodes: &[String],
    ) -> Vec<(String, String, String)> {
        let mut found = Vec::new();
        for node in nodes {
            let preview = kernel.call(
                approve,
                "browser.download",
                "preview",
                json!({"page_id": page_id, "node_id": node, "file_name": "probe.pdf", "expected_generation": generation}),
                Some(profile_gate::BROWSER_STRUCTURED_PROFILE),
            );
            let Some(result) = preview.result.as_ref() else {
                continue;
            };
            assert!(
                result.get("source").is_none(),
                "a preview handed out the raw link"
            );
            let (Some(name), Some(source)) = (
                result["source_name"].as_str().map(str::to_ascii_lowercase),
                result["source_sha256"].as_str().map(str::to_owned),
            ) else {
                continue;
            };
            if !name.ends_with(".pdf") {
                continue;
            }
            let digits: String = name.chars().filter(char::is_ascii_digit).collect();
            if let Some(date) = digits
                .as_bytes()
                .windows(8)
                .map(|w| String::from_utf8_lossy(w).into_owned())
                .find(|d| d.starts_with("20") && (&d[4..6] >= "01" && &d[4..6] <= "12"))
            {
                found.push((date, node.clone(), format!("{name} {source}")));
            }
        }
        found
    }
}
