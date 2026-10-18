use orcel_approval::{
    now_ms, ApprovalBroker, ApprovalPrompt, ConsumeExpectation, LocalApprovalBroker,
};
use orcel_audit::{default_audit_path, AuditLogger};
use orcel_contracts::{FailureCode, RequestEnvelope, ResponseEnvelope, INTERNAL_PROTOCOL_VERSION};
use orcel_policy::{PolicyEngine, Workspace, POLICY_REVISION};
use orcel_provider_fs::{FsProvider, ProviderError};
use orcel_provider_git::{GitProvider, GitProviderError};
use orcel_provider_process::{
    build_execution_plan, execute_contained, ExecutionLimits, OutputStream, PrivateExecutionFailure,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Deserialize)]
struct WorkspaceConfig {
    id: String,
    root: PathBuf,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("orceld fatal: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let policy = load_policy()?;
    let audit_path =
        default_audit_path().map_err(|error| format!("resolve audit log: {error}"))?;
    let audit = AuditLogger::new(audit_path)
        .map_err(|error| format!("initialize audit log: {error}"))?;
    let approval = LocalApprovalBroker::new()
        .map_err(|error| format!("initialize approval broker: {}", error.message))?;

    eprintln!(
        "orceld ready: protocol={} audit={} mode=SG-000010_BOUNDED_PROCESS_SPAWN",
        INTERNAL_PROTOCOL_VERSION,
        audit.path().display()
    );

    let stdin = io::stdin();
    let mut stdout = io::BufWriter::new(io::stdout().lock());

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(line) => line,
            Err(error) => {
                eprintln!("orceld stdin error: {error}");
                break;
            }
        };
        if line.trim().is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<RequestEnvelope>(&line) {
            Ok(request) => handle_request(&policy, &audit, &approval, request),
            Err(error) => ResponseEnvelope::failure(
                "unknown",
                FailureCode::InvalidRequest,
                format!("invalid request JSON: {error}"),
            ),
        };

        serde_json::to_writer(&mut stdout, &response)
            .map_err(|error| format!("serialize response: {error}"))?;
        stdout
            .write_all(b"\n")
            .map_err(|error| format!("write response: {error}"))?;
        stdout
            .flush()
            .map_err(|error| format!("flush response: {error}"))?;
    }

    Ok(())
}

fn load_policy() -> Result<PolicyEngine, String> {
    let workspaces = if let Ok(raw) = std::env::var("ORCEL_WORKSPACES_JSON") {
        let configs: Vec<WorkspaceConfig> = serde_json::from_str(&raw)
            .map_err(|error| format!("parse ORCEL_WORKSPACES_JSON: {error}"))?;
        configs
            .into_iter()
            .map(|config| Workspace {
                id: config.id,
                root: config.root,
            })
            .collect()
    } else if let Some(root) = std::env::var_os("ORCEL_WORKSPACE_ROOT") {
        vec![Workspace {
            id: std::env::var("ORCEL_WORKSPACE_ID").unwrap_or_else(|_| "default".into()),
            root: PathBuf::from(root),
        }]
    } else {
        return Err(
            "configure ORCEL_WORKSPACES_JSON or ORCEL_WORKSPACE_ROOT before starting orceld".into(),
        );
    };

    PolicyEngine::new(workspaces).map_err(|error| error.message)
}

fn handle_request(
    policy: &PolicyEngine,
    audit: &AuditLogger,
    approval: &impl ApprovalBroker,
    request: RequestEnvelope,
) -> ResponseEnvelope {
    let decision = match policy.authorize(&request) {
        Ok(decision) => decision,
        Err(error) => {
            let _ = audit.record(&request, POLICY_REVISION, "DENIED");
            return ResponseEnvelope::failure(request.request_id, error.code, error.message);
        }
    };

    match dispatch(policy, &decision.workspace, approval, &request) {
        Ok(value) => {
            if let Err(error) = audit.record(&request, decision.policy_revision, "SUCCESS") {
                return ResponseEnvelope::failure(
                    request.request_id,
                    FailureCode::InternalError,
                    format!("audit write failed: {error}"),
                );
            }
            ResponseEnvelope::success(&request, value, decision.policy_revision)
        }
        Err(error) => {
            let state = match error.code {
                FailureCode::ApprovalDenied => "APPROVAL_DENIED",
                FailureCode::ApprovalUnavailable => "APPROVAL_UNAVAILABLE",
                FailureCode::TargetStale => "TARGET_STALE",
                FailureCode::ProcessTimeout => "PROCESS_TIMEOUT",
                FailureCode::ProcessTerminationUnverified => "PROCESS_TERMINATION_UNVERIFIED",
                FailureCode::OutputLimit => "OUTPUT_LIMIT",
                _ => "FAILED",
            };
            let _ = audit.record(&request, decision.policy_revision, state);
            ResponseEnvelope::failure(request.request_id, error.code, error.message)
        }
    }
}

fn dispatch(
    policy: &PolicyEngine,
    workspace: &Workspace,
    approval: &impl ApprovalBroker,
    request: &RequestEnvelope,
) -> Result<Value, ProviderError> {
    match (request.capability.as_str(), request.operation.as_str()) {
        ("system.status", "get") => Ok(json!({
            "name": "orceld",
            "version": env!("CARGO_PKG_VERSION"),
            "internal_protocol_version": INTERNAL_PROTOCOL_VERSION,
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "pid": std::process::id(),
            "mode": "SG-000010_BOUNDED_PROCESS_SPAWN",
            "registered_executables": crate::executable_admin::registered_summaries(
                &orcel_policy::executable_registry::default_registry_path()
            )
        })),
        ("workspace.get", "get") => {
            let configured = policy.workspace(&workspace.id).ok_or_else(|| {
                ProviderError::new(
                    FailureCode::WorkspaceDenied,
                    "workspace disappeared during request",
                )
            })?;
            Ok(json!({
                "id": configured.id,
                "root": configured.root,
                "policy_revision": POLICY_REVISION,
                "mode": "approved_write_bounded_process_read_only_git"
            }))
        }
        ("fs.stat", "stat") => fs_provider(workspace)?.stat(target(request)?),
        ("fs.list", "list") => fs_provider(workspace)?.list(target(request)?),
        ("fs.read", "read") => fs_provider(workspace)?.read_text(target(request)?),
        ("fs.search", "search") => {
            let query = request
                .arguments
                .get("query")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    ProviderError::new(
                        FailureCode::InvalidRequest,
                        "fs.search requires arguments.query",
                    )
                })?;
            let max_results = request
                .arguments
                .get("max_results")
                .and_then(Value::as_u64)
                .map(|value| value as usize);
            fs_provider(workspace)?.search_text(target(request)?, query, max_results)
        }
        ("fs.write", "preview") => {
            let content = content(request)?;
            Ok(fs_provider(workspace)?
                .preview_write(target(request)?, content)?
                .to_json())
        }
        ("fs.write", "write") => write_file(workspace, approval, request),
        ("process.spawn", "spawn") => process_spawn(workspace, approval, request),
        ("git.status", "status") => git_result(git_provider(workspace)?.status(target(request)?)),
        ("git.diff", "diff") => {
            let staged = request
                .arguments
                .get("staged")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            git_result(git_provider(workspace)?.diff(target(request)?, staged))
        }
        ("git.log", "log") => {
            let max_count = request
                .arguments
                .get("max_count")
                .and_then(Value::as_u64)
                .unwrap_or(20)
                .clamp(1, 100) as usize;
            git_result(git_provider(workspace)?.log(target(request)?, max_count))
        }
        _ => Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "dispatch reached an unauthorized capability",
        )),
    }
}

fn write_file(
    workspace: &Workspace,
    approval: &impl ApprovalBroker,
    request: &RequestEnvelope,
) -> Result<Value, ProviderError> {
    let content = content(request)?;
    let relative = target(request)?;
    let provider = fs_provider(workspace)?;
    let preview = provider.preview_write(relative, content)?;
    let expected = request
        .arguments
        .get("expected_current_sha256")
        .and_then(Value::as_str);
    let create_if_missing = request
        .arguments
        .get("create_if_missing")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    match (&preview.current_sha256, expected) {
        (Some(actual), Some(expected)) if actual == expected => {}
        (Some(_), Some(_)) => {
            return Err(ProviderError::new(
                FailureCode::TargetStale,
                "target changed since preview",
            ))
        }
        (Some(_), None) => {
            return Err(ProviderError::new(
                FailureCode::TargetStale,
                "existing file requires expected_current_sha256 from preview",
            ))
        }
        (None, Some(_)) => {
            return Err(ProviderError::new(
                FailureCode::TargetStale,
                "target disappeared since preview",
            ))
        }
        (None, None) if create_if_missing => {}
        (None, None) => {
            return Err(ProviderError::new(
                FailureCode::TargetStale,
                "missing target requires create_if_missing=true",
            ))
        }
    }

    let digest = preview.approval_digest(&workspace.id, POLICY_REVISION);
    let prompt = ApprovalPrompt::new(
        workspace.id.clone(),
        POLICY_REVISION,
        if preview.exists {
            "overwrite UTF-8 file"
        } else {
            "create UTF-8 file"
        },
        relative.to_owned(),
        format!(
            "{} bytes; new SHA-256 {}",
            preview.bytes, preview.new_sha256
        ),
        digest.clone(),
    );

    let token = require_approval(approval, &prompt, "file write")?;
    approval
        .consume(
            &token,
            &ConsumeExpectation::new(digest, workspace.id.clone(), POLICY_REVISION),
            now_ms(),
        )
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    provider.write_text(relative, content, expected, create_if_missing)
}

fn process_spawn(
    workspace: &Workspace,
    approval: &impl ApprovalBroker,
    request: &RequestEnvelope,
) -> Result<Value, ProviderError> {
    let executable = process_string(request, "executable")?;
    let cwd = process_string(request, "cwd")?;
    let argv = request
        .arguments
        .get("argv")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ProviderError::new(
                FailureCode::InvalidRequest,
                "process.spawn requires arguments.argv",
            )
        })?
        .iter()
        .map(|value| {
            value.as_str().map(str::to_owned).ok_or_else(|| {
                ProviderError::new(
                    FailureCode::InvalidRequest,
                    "process.spawn argv entries must be strings",
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let timeout_ms = process_u64(request, "timeout_ms")?;
    let stdout_bytes = usize::try_from(process_u64(request, "stdout_bytes")?).map_err(|_| {
        ProviderError::new(
            FailureCode::InvalidRequest,
            "process.spawn stdout_bytes does not fit this platform",
        )
    })?;
    let stderr_bytes = usize::try_from(process_u64(request, "stderr_bytes")?).map_err(|_| {
        ProviderError::new(
            FailureCode::InvalidRequest,
            "process.spawn stderr_bytes does not fit this platform",
        )
    })?;

    if process_string(request, "stdin_policy")? != "null" {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "process.spawn stdin_policy must be null",
        ));
    }
    if process_string(request, "network_class")? != "NONE" {
        return Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "process.spawn network_class must be NONE",
        ));
    }

    let source_env = std::env::vars().collect::<BTreeMap<_, _>>();
    let plan = build_execution_plan(
        &workspace.root,
        executable,
        &argv,
        cwd,
        &source_env,
        ExecutionLimits {
            timeout: Duration::from_millis(timeout_ms),
            stdout_bytes,
            stderr_bytes,
        },
    )
    .map_err(|error| ProviderError::new(FailureCode::InvalidRequest, error.message))?;

    let digest = process_approval_digest(workspace, &plan);
    let prompt = ApprovalPrompt::new(
        workspace.id.clone(),
        POLICY_REVISION,
        "execute argv process",
        plan.executable.display().to_string(),
        format!(
            "argv={:?} cwd={} timeout={}ms stdout_limit={} stderr_limit={} stdin=null network=NONE",
            plan.argv,
            plan.cwd.display(),
            plan.limits.timeout.as_millis(),
            plan.limits.stdout_bytes,
            plan.limits.stderr_bytes
        ),
        digest.clone(),
    );
    let token = require_approval(approval, &prompt, "process execution")?;
    approval
        .consume(
            &token,
            &ConsumeExpectation::new(digest, workspace.id.clone(), POLICY_REVISION),
            now_ms(),
        )
        .map_err(|error| ProviderError::new(error.code, error.message))?;

    verify_registered_identity(&plan)?;
    let profile = process_profile_name(&request.request_id);
    let result = execute_contained(plan, &profile).map_err(map_process_failure)?;
    Ok(json!({
        "exit_code": result.exit_code,
        "stdout": String::from_utf8_lossy(&result.stdout),
        "stderr": String::from_utf8_lossy(&result.stderr),
        "appcontainer_verified": result.appcontainer_verified,
        "assigned_to_job_before_resume": result.assigned_to_job_before_resume,
        "job_quiescent": result.job_quiescent,
        "stdin_policy": "null",
        "network_class": "NONE"
    }))
}

/// SG-000060: immediately before launch, a non-baseline executable must
/// still be registered, match its argv grammar, and keep its registered path,
/// size, and SHA-256. Any drift fails closed.
#[cfg(windows)]
fn verify_registered_identity(plan: &orcel_provider_process::ExecutionPlan) -> Result<(), ProviderError> {
    if let Some(system_root) = std::env::var_os("SystemRoot") {
        let baseline = std::fs::canonicalize(
            PathBuf::from(system_root).join("System32").join("whoami.exe"),
        );
        if baseline.as_ref().is_ok_and(|path| *path == plan.executable) {
            return Ok(());
        }
    }
    let entries = orcel_policy::executable_registry::load_registry(
        &orcel_policy::executable_registry::default_registry_path(),
    );
    let entry = orcel_policy::executable_registry::check_spawn(&entries, &plan.executable, &plan.argv)
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    orcel_policy::executable_registry::verify_identity(entry, &plan.executable)
        .map_err(|error| ProviderError::new(error.code, error.message))
}

#[cfg(not(windows))]
fn verify_registered_identity(_plan: &orcel_provider_process::ExecutionPlan) -> Result<(), ProviderError> {
    Ok(())
}

fn process_approval_digest(
    workspace: &Workspace,
    plan: &orcel_provider_process::ExecutionPlan,
) -> String {
    let mut hasher = Sha256::new();
    digest_field(&mut hasher, b"ORCEL_PROCESS_APPROVAL_V1");
    digest_field(&mut hasher, workspace.id.as_bytes());
    digest_field(&mut hasher, POLICY_REVISION.as_bytes());
    digest_field(&mut hasher, plan.executable.to_string_lossy().as_bytes());
    for argument in &plan.argv {
        digest_field(&mut hasher, argument.as_bytes());
    }
    digest_field(&mut hasher, plan.cwd.to_string_lossy().as_bytes());
    digest_field(
        &mut hasher,
        plan.limits.timeout.as_millis().to_string().as_bytes(),
    );
    digest_field(&mut hasher, plan.limits.stdout_bytes.to_string().as_bytes());
    digest_field(&mut hasher, plan.limits.stderr_bytes.to_string().as_bytes());
    digest_field(&mut hasher, b"stdin=null");
    digest_field(&mut hasher, b"network=NONE");
    for (name, value) in &plan.env {
        digest_field(&mut hasher, name.as_bytes());
        digest_field(&mut hasher, value.as_bytes());
    }
    hex_lower(&hasher.finalize())
}

fn digest_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn process_profile_name(request_id: &str) -> String {
    let digest = Sha256::digest(request_id.as_bytes());
    let short = hex_lower(&digest[..12]);
    format!("Orcel.Exec.{}.{}", std::process::id(), short)
}

fn map_process_failure(error: PrivateExecutionFailure) -> ProviderError {
    match error {
        PrivateExecutionFailure::InvalidPlan(message) => {
            ProviderError::new(FailureCode::InvalidRequest, message)
        }
        PrivateExecutionFailure::Provider(message) => {
            ProviderError::new(FailureCode::ProviderUnavailable, message)
        }
        PrivateExecutionFailure::ProcessTimeout => ProviderError::new(
            FailureCode::ProcessTimeout,
            "process exceeded the approved timeout and the Job was verified quiescent",
        ),
        PrivateExecutionFailure::OutputLimit(stream) => ProviderError::new(
            FailureCode::OutputLimit,
            match stream {
                OutputStream::Stdout => {
                    "process stdout exceeded the approved bound and the Job was verified quiescent"
                }
                OutputStream::Stderr => {
                    "process stderr exceeded the approved bound and the Job was verified quiescent"
                }
            },
        ),
        PrivateExecutionFailure::TerminationUnverified => ProviderError::new(
            FailureCode::ProcessTerminationUnverified,
            "Orcel could not verify zero active Job processes after termination",
        ),
    }
}

fn require_approval(
    approval: &impl ApprovalBroker,
    prompt: &ApprovalPrompt,
    _action: &str,
) -> Result<orcel_approval::ApprovedToken, ProviderError> {
    match approval.request_token(prompt) {
        Ok(token) => Ok(token),
        Err(error) => Err(ProviderError::new(error.code, error.message)),
    }
}

fn process_string<'a>(request: &'a RequestEnvelope, name: &str) -> Result<&'a str, ProviderError> {
    request
        .arguments
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ProviderError::new(
                FailureCode::InvalidRequest,
                format!("process.spawn requires arguments.{name}"),
            )
        })
}

fn process_u64(request: &RequestEnvelope, name: &str) -> Result<u64, ProviderError> {
    request
        .arguments
        .get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            ProviderError::new(
                FailureCode::InvalidRequest,
                format!("process.spawn requires arguments.{name}"),
            )
        })
}

fn fs_provider(workspace: &Workspace) -> Result<FsProvider, ProviderError> {
    FsProvider::new(&workspace.root)
}

fn git_provider(workspace: &Workspace) -> Result<GitProvider, ProviderError> {
    GitProvider::new(&workspace.root).map_err(map_git_error)
}

fn git_result(result: Result<Value, GitProviderError>) -> Result<Value, ProviderError> {
    result.map_err(map_git_error)
}

fn map_git_error(error: GitProviderError) -> ProviderError {
    ProviderError::new(error.code, error.message)
}

fn target(request: &RequestEnvelope) -> Result<&str, ProviderError> {
    request.target.as_deref().ok_or_else(|| {
        ProviderError::new(FailureCode::InvalidRequest, "filesystem target is required")
    })
}

fn content(request: &RequestEnvelope) -> Result<&str, ProviderError> {
    request
        .arguments
        .get("content")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ProviderError::new(
                FailureCode::InvalidRequest,
                "fs.write requires arguments.content",
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    use orcel_approval::test_support::FixedApprovalBroker;
    #[cfg(windows)]
    use orcel_approval::ApprovalDecision;
    use orcel_approval::{ApprovalError, ApprovalPrompt};
    use serde_json::json;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct DenyBroker;

    impl ApprovalBroker for DenyBroker {
        fn request_token(
            &self,
            _prompt: &ApprovalPrompt,
        ) -> Result<orcel_approval::ApprovedToken, ApprovalError> {
            Err(ApprovalError {
                code: FailureCode::ApprovalDenied,
                message: "local user denied the operation in test".into(),
            })
        }

        fn consume(
            &self,
            _token: &orcel_approval::ApprovedToken,
            _expected: &ConsumeExpectation,
            _now_ms: u64,
        ) -> Result<(), ApprovalError> {
            Err(ApprovalError {
                code: FailureCode::ApprovalDenied,
                message: "no approval was granted".into(),
            })
        }
    }

    struct UnavailableBroker;

    impl ApprovalBroker for UnavailableBroker {
        fn request_token(
            &self,
            _prompt: &ApprovalPrompt,
        ) -> Result<orcel_approval::ApprovedToken, ApprovalError> {
            Err(ApprovalError {
                code: FailureCode::ApprovalUnavailable,
                message: "approval unavailable in test".into(),
            })
        }

        fn consume(
            &self,
            _token: &orcel_approval::ApprovedToken,
            _expected: &ConsumeExpectation,
            _now_ms: u64,
        ) -> Result<(), ApprovalError> {
            Err(ApprovalError {
                code: FailureCode::ApprovalUnavailable,
                message: "approval unavailable in test".into(),
            })
        }
    }

    fn temp_root(label: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("orcel-daemon-{label}-{suffix}"));
        fs::create_dir_all(&root).expect("create temp workspace");
        root
    }

    fn process_request(workspace: &Workspace, executable: PathBuf) -> RequestEnvelope {
        RequestEnvelope {
            version: INTERNAL_PROTOCOL_VERSION,
            request_id: "process-test-request".into(),
            client_session_id: "s-test".into(),
            workspace_id: workspace.id.clone(),
            capability: "process.spawn".into(),
            operation: "spawn".into(),
            target: None,
            arguments: json!({
                "executable": executable,
                "argv": [],
                "cwd": ".",
                "timeout_ms": 30_000,
                "stdout_bytes": 2 * 1024 * 1024,
                "stderr_bytes": 256 * 1024,
                "stdin_policy": "null",
                "network_class": "NONE"
            }),
        }
    }

    #[test]
    fn denied_approval_does_not_mutate_existing_file() {
        let root = temp_root("write");
        fs::write(root.join("notes.txt"), "before").expect("seed file");
        let workspace = Workspace {
            id: "default".into(),
            root: fs::canonicalize(&root).expect("canonical workspace"),
        };
        let policy = PolicyEngine::new(vec![workspace.clone()]).expect("policy");
        let provider = FsProvider::new(&workspace.root).expect("provider");
        let preview = provider
            .preview_write("notes.txt", "after")
            .expect("preview");

        let request = RequestEnvelope {
            version: INTERNAL_PROTOCOL_VERSION,
            request_id: "r-deny".into(),
            client_session_id: "s-test".into(),
            workspace_id: workspace.id.clone(),
            capability: "fs.write".into(),
            operation: "write".into(),
            target: Some("notes.txt".into()),
            arguments: json!({
                "content": "after",
                "expected_current_sha256": preview.current_sha256,
                "create_if_missing": false
            }),
        };

        let error = dispatch(&policy, &workspace, &DenyBroker, &request)
            .expect_err("denied approval must fail");
        assert_eq!(error.code, FailureCode::ApprovalDenied);
        assert_eq!(
            fs::read_to_string(root.join("notes.txt")).expect("read result"),
            "before"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn process_spawn_denial_and_unavailable_approval_fail_before_execution() {
        let root = temp_root("process-approval");
        let workspace = Workspace {
            id: "default".into(),
            root: fs::canonicalize(&root).expect("canonical workspace"),
        };
        let policy = PolicyEngine::new(vec![workspace.clone()]).expect("policy");
        #[cfg(windows)]
        let executable = {
            let system_root = std::env::var_os("SystemRoot").expect("SystemRoot");
            PathBuf::from(system_root)
                .join("System32")
                .join("whoami.exe")
        };
        #[cfg(not(windows))]
        let executable = std::env::current_exe().expect("test executable");
        let request = process_request(&workspace, executable);
        policy
            .authorize(&request)
            .expect("policy accepts bounded request");

        let denied = dispatch(&policy, &workspace, &DenyBroker, &request)
            .expect_err("denied approval must prevent execution");
        assert_eq!(denied.code, FailureCode::ApprovalDenied);

        let unavailable = dispatch(&policy, &workspace, &UnavailableBroker, &request)
            .expect_err("unavailable approval must prevent execution");
        assert_eq!(unavailable.code, FailureCode::ApprovalUnavailable);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn process_approval_digest_changes_for_material_plan_drift() {
        let root = temp_root("process-digest");
        let workspace = Workspace {
            id: "default".into(),
            root: fs::canonicalize(&root).expect("canonical workspace"),
        };
        let executable = std::env::current_exe().expect("test executable");
        let source_env = std::env::vars().collect::<BTreeMap<_, _>>();
        let first = build_execution_plan(
            &workspace.root,
            &executable,
            &["first".into()],
            ".",
            &source_env,
            ExecutionLimits::default(),
        )
        .expect("first plan");
        let second = build_execution_plan(
            &workspace.root,
            &executable,
            &["second".into()],
            ".",
            &source_env,
            ExecutionLimits::default(),
        )
        .expect("second plan");
        assert_ne!(
            process_approval_digest(&workspace, &first),
            process_approval_digest(&workspace, &second)
        );
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn windows_public_process_spawn_executes_approved_system_argv_with_containment_evidence() {
        let root = temp_root("process-public");
        let workspace = Workspace {
            id: "default".into(),
            root: fs::canonicalize(&root).expect("canonical workspace"),
        };
        let policy = PolicyEngine::new(vec![workspace.clone()]).expect("policy");
        let system_root = std::env::var_os("SystemRoot").expect("SystemRoot");
        let executable = PathBuf::from(system_root)
            .join("System32")
            .join("whoami.exe");
        let request = process_request(&workspace, executable);
        policy
            .authorize(&request)
            .expect("policy accepts public fixture");

        let result = dispatch(
            &policy,
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Approved),
            &request,
        )
        .expect("approved public process.spawn");
        assert_eq!(result["exit_code"], 0);
        assert!(result["stdout"]
            .as_str()
            .is_some_and(|value| !value.is_empty()));
        assert_eq!(result["stderr"], "");
        assert_eq!(result["appcontainer_verified"], true);
        assert_eq!(result["assigned_to_job_before_resume"], true);
        assert_eq!(result["job_quiescent"], true);
        assert_eq!(result["network_class"], "NONE");
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn sg000060_registered_executables_run_contained_and_drift_fails_closed() {
        use orcel_policy::executable_registry::{build_entry, save_registry, RegisteredExecutable};
        let root = temp_root("process-registry");
        let workspace = Workspace {
            id: "default".into(),
            root: fs::canonicalize(&root).expect("canonical workspace"),
        };
        let registry = root.with_extension("registry.json");
        std::env::set_var("ORCEL_EXECUTABLE_REGISTRY_PATH", &registry);
        let policy = PolicyEngine::new(vec![workspace.clone()]).expect("policy");
        let system_root = std::env::var_os("SystemRoot").expect("SystemRoot");
        let hostname = PathBuf::from(&system_root).join("System32").join("hostname.exe");
        let mut request = process_request(&workspace, hostname.clone());
        // A distinct request id gives this test its own AppContainer profile,
        // so it never collides with the SG-000010 test running in parallel.
        request.request_id = "process-registry-test-request".into();

        // Unregistered: denied by policy before any approval.
        let error = policy.authorize(&request).expect_err("unregistered executable");
        assert_eq!(error.code, FailureCode::CapabilityDenied);

        // Registered with an empty grammar: argv must be empty.
        let entry = build_entry("hostname", &hostname, vec![], vec![], 0, std::slice::from_ref(&workspace.root), 1)
            .expect("registrable system executable");
        save_registry(&registry, std::slice::from_ref(&entry)).expect("save registry");
        policy.authorize(&request).expect("registered executable");
        let mut with_args = request.clone();
        with_args.arguments["argv"] = json!(["/?"]);
        assert_eq!(
            policy.authorize(&with_args).expect_err("grammar").code,
            FailureCode::CapabilityDenied
        );
        let mut shell = request.clone();
        shell.arguments["executable"] = json!(PathBuf::from(&system_root).join("System32").join("cmd.exe"));
        assert_eq!(
            policy.authorize(&shell).expect_err("shell").code,
            FailureCode::CapabilityDenied
        );

        // Drifted identity: approved, but refused before launch.
        let drifted = RegisteredExecutable {
            sha256: "0".repeat(64),
            ..entry.clone()
        };
        save_registry(&registry, &[drifted]).expect("save drifted registry");
        policy.authorize(&request).expect("policy does not hash");
        let stale = dispatch(
            &policy,
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Approved),
            &request,
        )
        .expect_err("hash drift fails closed before launch");
        assert_eq!(stale.code, FailureCode::TargetStale);

        // Intact identity: runs through the unchanged contained process path.
        save_registry(&registry, std::slice::from_ref(&entry)).expect("save registry");
        let result = dispatch(
            &policy,
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Approved),
            &request,
        )
        .expect("registered executable runs through the contained path");
        assert_eq!(result["exit_code"], 0);
        assert!(result["stdout"].as_str().is_some_and(|value| !value.trim().is_empty()));
        assert_eq!(result["appcontainer_verified"], true);
        assert_eq!(result["assigned_to_job_before_resume"], true);
        assert_eq!(result["job_quiescent"], true);
        assert_eq!(result["network_class"], "NONE");
        let _ = fs::remove_file(&registry);
        let _ = fs::remove_dir_all(root);
    }
}
