//! BM-02 Tier C, slice C2b (tests/benchmarks/ORCEL_EXECUTION_PLAN.md): a
//! deterministic, scripted plan acting on a launched GUI task app through
//! orceld's own request entry (`handle_envelope`: policy, dispatch, audit)
//! and its approval-gated UIA shapes (`uia.element set_value`, `invoke`).
//!
//! The SOFT consent is scripted (every prompt this plan causes is approved
//! and recorded), as in Tier B, and the plan encodes the task's known
//! answer: the report labels both (`scripted-plan`, `scripted-consent`).
//! It is not agent performance. It never runs by itself: the Python harness
//! (`orcel_bench/tierc_gui.py`, `tierc-act`) launches the apps on a CI
//! runner and runs this test with the plan, workspace and result paths.
//! Windows only (UIA).

use super::*;
use orcel_approval::{ApprovalDecision, ApprovalPrompt, NoPresenceVerifier};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A plan step: set a named Edit's value, or invoke a named Button.
#[derive(serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum Step {
    SetValue { name: String, value: String },
    Invoke { name: String },
}

#[derive(serde::Deserialize)]
struct Plan {
    window_title: String,
    steps: Vec<Step>,
}

struct Kernel {
    policy: PolicyEngine,
    audit: AuditLogger,
    workspaces: remote_lease::WorkspaceSet,
    calls: Vec<Value>,
    /// The last refusal's message (test-internal; never in the report).
    last_refusal: String,
}

impl Kernel {
    fn call(
        &mut self,
        broker: &LocalApprovalBroker,
        capability: &str,
        operation: &str,
        arguments: Value,
    ) -> Result<Value, String> {
        let started = Instant::now();
        let scoped = arguments.get("root_element_id").is_some();
        let response = handle_envelope(
            &self.policy,
            &self.audit,
            broker,
            &self.workspaces,
            RemoteRequestEnvelope {
                request: RequestEnvelope {
                    version: INTERNAL_PROTOCOL_VERSION,
                    request_id: format!("tierc-{}", self.calls.len() + 1),
                    client_session_id: "bm02-tierc".into(),
                    workspace_id: "default".into(),
                    capability: capability.into(),
                    operation: operation.into(),
                    target: None,
                    arguments,
                },
                remote: None,
                profile: None,
            },
        );
        let code = response
            .error
            .as_ref()
            .and_then(|e| serde_json::to_value(&e.code).ok())
            .and_then(|v| v.as_str().map(str::to_owned));
        self.calls.push(json!({
            "shape": format!("{capability}/{operation}"),
            "scoped": scoped,
            "ok": response.ok,
            "code": code,
            "ms": (started.elapsed().as_secs_f64() * 1000.0 * 1000.0).round() / 1000.0,
        }));
        if !response.ok {
            // CI log only, never the report: which check refused, and why.
            if let Some(error) = response.error.as_ref() {
                eprintln!(
                    "TIERC-ACT-DIAG {capability}/{operation} refused {:?}: {}",
                    error.code, error.message
                );
                self.last_refusal = error.message.clone();
            }
        }
        if response.ok {
            Ok(response.result.unwrap_or(Value::Null))
        } else {
            Err(code.unwrap_or_else(|| "UNKNOWN".into()))
        }
    }
}

/// Successful scoped observations so far.
fn scoped_reads(kernel: &Kernel) -> usize {
    kernel
        .calls
        .iter()
        .filter(|c| c["scoped"] == true && c["ok"] == true)
        .count()
}

/// The window, then a fresh tree; the node named `name` with an eligible
/// control type.
fn find(
    kernel: &mut Kernel,
    broker: &LocalApprovalBroker,
    title: &str,
    name: &str,
    types: &[&str],
) -> Result<(Value, u64), String> {
    // The app's title changes while its page loads (its configured title,
    // then the page's <title>, then the app sets it back): wait for it.
    let deadline = Instant::now() + Duration::from_secs(30);
    let window = loop {
        let listing = kernel.call(broker, "uia.window", "list", json!({}))?;
        let windows = listing["windows"].as_array().cloned().unwrap_or_default();
        if let Some(found) = windows.iter().find(|w| w["title"] == title) {
            break found.clone();
        }
        if Instant::now() >= deadline {
            let titles: Vec<&str> = windows.iter().filter_map(|w| w["title"].as_str()).collect();
            eprintln!("TIERC-ACT-DIAG window {title:?} not listed; listed titles {titles:?}");
            return Err("WINDOW_NOT_FOUND".into());
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    let tree = kernel.call(
        broker,
        "uia.tree",
        "observe",
        json!({
            "window_id": window["window_id"],
            "expected_window_generation": window["window_generation"],
            "max_nodes": 2000,
        }),
    )?;
    let mut generation = tree["tree_generation"]
        .as_u64()
        .ok_or("NO_TREE_GENERATION")?;
    let pick = |tree: &Value| {
        tree["nodes"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|n| n["name"] == name && types.iter().any(|t| n["control_type"] == *t))
            .cloned()
    };
    let mut node = pick(&tree);
    let mut tree = tree;
    // SG-000128: a web page's controls sit below its Document, past the
    // window tree's depth cap. One scoped observation below the Document
    // orceld issued (same window, current tree generation) reaches them.
    if node.is_none() {
        if let Some(document) = tree["nodes"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|n| n["control_type"] == "Document")
            .cloned()
        {
            let scoped = kernel.call(
                broker,
                "uia.tree",
                "observe",
                json!({
                    "window_id": window["window_id"],
                    "expected_window_generation": window["window_generation"],
                    "root_element_id": document["element_id"],
                    "expected_tree_generation": generation,
                }),
            )?;
            generation = scoped["tree_generation"]
                .as_u64()
                .ok_or("NO_TREE_GENERATION")?;
            node = pick(&scoped);
            tree = scoped;
        }
    }
    let Some(node) = node else {
        // Diagnostics for the CI log only (never the report): what the
        // bounded tree did contain.
        let nodes = tree["nodes"].as_array().cloned().unwrap_or_default();
        let deepest = nodes.iter().filter_map(|n| n["depth"].as_u64()).max();
        let actionable: Vec<String> = nodes
            .iter()
            .filter(|n| {
                ["Edit", "Document", "Button"]
                    .iter()
                    .any(|t| n["control_type"] == *t)
            })
            .map(|n| {
                format!(
                    "{}:{}@{}",
                    n["control_type"].as_str().unwrap_or("?"),
                    n["name"].as_str().unwrap_or(""),
                    n["depth"]
                )
            })
            .take(40)
            .collect();
        eprintln!(
            "TIERC-ACT-DIAG element {name:?} not found: {} nodes, deepest {deepest:?}, truncated {}, actionable {actionable:?}",
            nodes.len(),
            tree["truncated"]
        );
        return Err("ELEMENT_NOT_FOUND".into());
    };
    Ok((node, generation))
}

#[test]
#[ignore = "run by the BM-02 Tier C harness (tierc-act) on a CI runner with the apps launched"]
fn bm02_tier_c_scripted_plan_acts_through_orceld() {
    let plan_path = std::env::var_os("ORCEL_TIERC_ACT_PLAN").expect("ORCEL_TIERC_ACT_PLAN");
    let workspace = PathBuf::from(
        std::env::var_os("ORCEL_TIERC_ACT_WORKSPACE").expect("ORCEL_TIERC_ACT_WORKSPACE"),
    );
    let result_path = std::env::var_os("ORCEL_TIERC_ACT_RESULT").expect("ORCEL_TIERC_ACT_RESULT");
    let state =
        PathBuf::from(std::env::var_os("ORCEL_TIERC_ACT_STATE").expect("ORCEL_TIERC_ACT_STATE"));
    let plan: Plan = serde_json::from_str(&std::fs::read_to_string(plan_path).expect("plan"))
        .expect("plan json");

    let root = std::fs::canonicalize(&workspace).expect("workspace");
    let mut kernel = Kernel {
        policy: PolicyEngine::new(vec![Workspace {
            id: "default".into(),
            root: root.clone(),
        }])
        .expect("policy"),
        audit: AuditLogger::new(state.join("audit.jsonl")).expect("audit"),
        workspaces: remote_lease::WorkspaceSet::from_pairs(&[("default".into(), root)]),
        calls: Vec::new(),
        last_refusal: String::new(),
    };
    // The real broker over its own ledger; only the SOFT answer is scripted:
    // every prompt this plan causes is approved and recorded.
    let prompts: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&prompts);
    let broker = LocalApprovalBroker::with_path_and_soft_decider(
        state.join("approvals.json"),
        Arc::new(NoPresenceVerifier),
        Arc::new(move |prompt: &ApprovalPrompt| {
            seen.lock()
                .unwrap()
                .push(json!({"action": prompt.action, "target_len": prompt.target.len()}));
            ApprovalDecision::Approved
        }),
    );

    let mut outcome = "completed".to_owned();
    // SG-000128 slice 3a ("reach"): every target element is reached through
    // the scoped read, then the first action must be refused because
    // DesktopInput needs a person-granted Full User lease (STRONG presence),
    // which a CI runner does not have and this test never manufactures.
    let reach_only = std::env::var("ORCEL_TIERC_ACT_MODE").as_deref() == Ok("reach");
    if reach_only {
        outcome = "reached-and-gated".to_owned();
        for step in &plan.steps {
            let (name, types): (&str, &[&str]) = match step {
                Step::SetValue { name, .. } => (name, &["Edit", "Document"]),
                Step::Invoke { name } => (name, &["Button"]),
            };
            let scoped_before = scoped_reads(&kernel);
            if let Err(code) = find(&mut kernel, &broker, &plan.window_title, name, types) {
                outcome = format!("reach-failed-{}", code.to_ascii_lowercase());
                break;
            }
            // Each element must be reached through exactly one successful
            // scoped read (the slice 3a evidence), not the unscoped tree.
            if scoped_reads(&kernel) != scoped_before + 1 {
                outcome = "reach-not-scoped".to_owned();
                break;
            }
        }
        if outcome == "reached-and-gated" {
            outcome = match plan.steps.first() {
                Some(Step::SetValue { name, value }) => {
                    match find(
                        &mut kernel,
                        &broker,
                        &plan.window_title,
                        name,
                        &["Edit", "Document"],
                    ) {
                        Err(code) => format!("reach-failed-{}", code.to_ascii_lowercase()),
                        Ok((node, generation)) => {
                            kernel.last_refusal.clear();
                            let attempted = kernel.call(
                                &broker,
                                "uia.element",
                                "set_value",
                                json!({
                                    "element_id": node["element_id"],
                                    "expected_tree_generation": generation,
                                    "expected_control_type": node["control_type"],
                                    "value": value,
                                }),
                            );
                            match attempted {
                                // The set_value call itself must be refused by
                                // the DesktopInput gate (check_current_desktop_input),
                                // not some other denial that shares the code.
                                Err(code)
                                    if code == "CAPABILITY_DENIED"
                                        && kernel.last_refusal.contains("DesktopInput") =>
                                {
                                    "reached-and-gated".to_owned()
                                }
                                Err(code) => {
                                    format!("gate-unexpected-{}", code.to_ascii_lowercase())
                                }
                                Ok(_) => "gate-missing-action-ran".to_owned(),
                            }
                        }
                    }
                }
                _ => "plan-does-not-start-with-set-value".to_owned(),
            };
        }
    }
    for step in plan.steps.iter().filter(|_| !reach_only) {
        let done = match step {
            Step::SetValue { name, value } => find(
                &mut kernel,
                &broker,
                &plan.window_title,
                name,
                &["Edit", "Document"],
            )
            .and_then(|(node, generation)| {
                kernel.call(
                    &broker,
                    "uia.element",
                    "set_value",
                    json!({
                        "element_id": node["element_id"],
                        "expected_tree_generation": generation,
                        "expected_control_type": node["control_type"],
                        "value": value,
                    }),
                )
            }),
            Step::Invoke { name } => {
                find(&mut kernel, &broker, &plan.window_title, name, &["Button"]).and_then(
                    |(node, generation)| {
                        kernel.call(
                            &broker,
                            "uia.element",
                            "invoke",
                            json!({
                                "element_id": node["element_id"],
                                "expected_tree_generation": generation,
                                "expected_control_type": node["control_type"],
                            }),
                        )
                    },
                )
            }
        };
        if let Err(code) = done {
            outcome = format!("step-failed-{}", code.to_ascii_lowercase());
            break;
        }
        // Let the app react before the next observation.
        std::thread::sleep(Duration::from_millis(300));
    }
    let audit_records = std::fs::read_to_string(state.join("audit.jsonl"))
        .map(|t| t.lines().count())
        .unwrap_or(0);
    let result = json!({
        "outcome": outcome,
        "calls": kernel.calls,
        "prompts": *prompts.lock().unwrap(),
        "audit_records": audit_records,
    });
    std::fs::write(result_path, serde_json::to_string_pretty(&result).unwrap()).expect("result");
}
