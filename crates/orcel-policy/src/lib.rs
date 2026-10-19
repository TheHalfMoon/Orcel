use orcel_contracts::{FailureCode, RequestEnvelope};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};

pub const POLICY_REVISION: &str = "sg-000010-v1";

const MAX_PROCESS_ARGV_ITEMS: usize = 64;
const MAX_PROCESS_ARG_UTF16: usize = 8_192;
const MAX_PROCESS_COMMAND_UTF16: usize = 30_000;
const MAX_PROCESS_TIMEOUT_MS: u64 = 30 * 60 * 1_000;
const MAX_PROCESS_STDOUT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_PROCESS_STDERR_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Workspace {
    pub id: String,
    pub root: PathBuf,
}

#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub workspace: Workspace,
    pub policy_revision: &'static str,
}

#[derive(Debug, Clone)]
pub struct PolicyError {
    pub code: FailureCode,
    pub message: String,
}

impl PolicyError {
    fn new(code: FailureCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PolicyEngine {
    workspaces: HashMap<String, Workspace>,
}

impl PolicyEngine {
    pub fn new(workspaces: Vec<Workspace>) -> Result<Self, PolicyError> {
        if workspaces.is_empty() {
            return Err(PolicyError::new(
                FailureCode::WorkspaceDenied,
                "at least one workspace must be configured",
            ));
        }

        Self::with_protected_state_roots(
            workspaces,
            crate::protected_state::protected_state_roots(),
        )
    }

    fn with_protected_state_roots(
        workspaces: Vec<Workspace>,
        protected_roots: Vec<PathBuf>,
    ) -> Result<Self, PolicyError> {
        let protected_roots = protected_roots
            .iter()
            .map(|root| crate::protected_state::resolve_protected_root(root))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                PolicyError::new(
                    FailureCode::WorkspaceDenied,
                    format!("Orcel protected state could not be resolved: {error}"),
                )
            })?;

        let mut map = HashMap::new();
        for mut workspace in workspaces {
            if workspace.id.trim().is_empty() {
                return Err(PolicyError::new(
                    FailureCode::InvalidRequest,
                    "workspace id cannot be empty",
                ));
            }
            workspace.root = std::fs::canonicalize(&workspace.root).map_err(|error| {
                PolicyError::new(
                    FailureCode::WorkspaceDenied,
                    format!(
                        "workspace root could not be resolved for {}: {error}",
                        workspace.id
                    ),
                )
            })?;
            if !workspace.root.is_dir() {
                return Err(PolicyError::new(
                    FailureCode::WorkspaceDenied,
                    format!("workspace root is not a directory: {}", workspace.id),
                ));
            }
            if protected_roots
                .iter()
                .any(|root| crate::protected_state::paths_overlap(&workspace.root, root))
            {
                return Err(PolicyError::new(
                    FailureCode::WorkspaceDenied,
                    format!(
                        "workspace {} overlaps Orcel protected state and is refused",
                        workspace.id
                    ),
                ));
            }
            if map.insert(workspace.id.clone(), workspace).is_some() {
                return Err(PolicyError::new(
                    FailureCode::InvalidRequest,
                    "duplicate workspace id",
                ));
            }
        }

        Ok(Self { workspaces: map })
    }

    pub fn workspace(&self, id: &str) -> Option<&Workspace> {
        self.workspaces.get(id)
    }

    pub fn authorize(&self, request: &RequestEnvelope) -> Result<PolicyDecision, PolicyError> {
        if request.version != orcel_contracts::INTERNAL_PROTOCOL_VERSION {
            return Err(PolicyError::new(
                FailureCode::InvalidRequest,
                "unsupported internal protocol version",
            ));
        }

        let workspace = self.workspaces.get(&request.workspace_id).ok_or_else(|| {
            PolicyError::new(
                FailureCode::WorkspaceDenied,
                "requested workspace is not configured",
            )
        })?;

        let allowed = matches!(
            (request.capability.as_str(), request.operation.as_str()),
            ("system.status", "get")
                | ("workspace.get", "get")
                | ("fs.stat", "stat")
                | ("fs.list", "list")
                | ("fs.read", "read")
                | ("fs.search", "search")
                | ("fs.write", "preview")
                | ("fs.write", "write")
                | ("git.status", "status")
                | ("git.diff", "diff")
                | ("git.log", "log")
                | ("process.spawn", "spawn")
        );

        if !allowed {
            return Err(PolicyError::new(
                FailureCode::CapabilityDenied,
                format!(
                    "capability/operation is not allowed by {POLICY_REVISION}: {}/{}",
                    request.capability, request.operation
                ),
            ));
        }

        if request.capability.starts_with("fs.") || request.capability.starts_with("git.") {
            let target = request.target.as_deref().ok_or_else(|| {
                PolicyError::new(
                    FailureCode::InvalidRequest,
                    "workspace-relative target is required",
                )
            })?;
            validate_relative_target(target)?;
        }

        if request.capability == "fs.write" {
            let content = request
                .arguments
                .get("content")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    PolicyError::new(
                        FailureCode::InvalidRequest,
                        "fs.write requires arguments.content as UTF-8 text",
                    )
                })?;
            if content.len() > 2 * 1024 * 1024 {
                return Err(PolicyError::new(
                    FailureCode::OutputLimit,
                    "fs.write content exceeds 2 MiB limit",
                ));
            }
        }

        if request.capability == "process.spawn" {
            validate_process_spawn(request)?;
        }

        Ok(PolicyDecision {
            workspace: workspace.clone(),
            policy_revision: POLICY_REVISION,
        })
    }
}

fn validate_process_spawn(request: &RequestEnvelope) -> Result<(), PolicyError> {
    if request.target.is_some() {
        return Err(PolicyError::new(
            FailureCode::InvalidRequest,
            "process.spawn does not accept a target field",
        ));
    }

    let arguments = request.arguments.as_object().ok_or_else(|| {
        PolicyError::new(
            FailureCode::InvalidRequest,
            "process.spawn arguments must be an object",
        )
    })?;
    reject_unknown_process_arguments(arguments)?;

    let executable = required_string(arguments, "executable")?;

    let argv = arguments
        .get("argv")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            PolicyError::new(
                FailureCode::InvalidRequest,
                "process.spawn requires arguments.argv as an array",
            )
        })?;
    if argv.len() > MAX_PROCESS_ARGV_ITEMS {
        return Err(PolicyError::new(
            FailureCode::InvalidRequest,
            format!("process.spawn argv exceeds {MAX_PROCESS_ARGV_ITEMS} items"),
        ));
    }

    let mut command_utf16 = executable.encode_utf16().count() + 3;
    for value in argv {
        let argument = value.as_str().ok_or_else(|| {
            PolicyError::new(
                FailureCode::InvalidRequest,
                "process.spawn argv entries must be strings",
            )
        })?;
        if argument.contains('\0') {
            return Err(PolicyError::new(
                FailureCode::InvalidRequest,
                "process.spawn argv contains a NUL byte",
            ));
        }
        let length = argument.encode_utf16().count();
        if length > MAX_PROCESS_ARG_UTF16 {
            return Err(PolicyError::new(
                FailureCode::InvalidRequest,
                "process.spawn argv entry is too large",
            ));
        }
        command_utf16 = command_utf16.saturating_add(length + 3);
    }
    if command_utf16 > MAX_PROCESS_COMMAND_UTF16 {
        return Err(PolicyError::new(
            FailureCode::InvalidRequest,
            "process.spawn command line exceeds the bounded UTF-16 limit",
        ));
    }
    let argv_strings: Vec<String> = argv
        .iter()
        .filter_map(|value| value.as_str().map(str::to_owned))
        .collect();
    validate_process_executable(executable, &argv_strings)?;

    let cwd = required_string(arguments, "cwd")?;
    if cwd.is_empty() {
        return Err(PolicyError::new(
            FailureCode::InvalidRequest,
            "process.spawn cwd cannot be empty",
        ));
    }
    validate_relative_target(cwd)?;

    bounded_u64(arguments, "timeout_ms", 1_000, MAX_PROCESS_TIMEOUT_MS)?;
    bounded_u64(arguments, "stdout_bytes", 1, MAX_PROCESS_STDOUT_BYTES)?;
    bounded_u64(arguments, "stderr_bytes", 1, MAX_PROCESS_STDERR_BYTES)?;

    if required_string(arguments, "stdin_policy")? != "null" {
        return Err(PolicyError::new(
            FailureCode::InvalidRequest,
            "process.spawn stdin_policy must be null",
        ));
    }
    if required_string(arguments, "network_class")? != "NONE" {
        return Err(PolicyError::new(
            FailureCode::CapabilityDenied,
            "process.spawn network_class must be NONE",
        ));
    }

    Ok(())
}

fn reject_unknown_process_arguments(arguments: &Map<String, Value>) -> Result<(), PolicyError> {
    const ALLOWED: &[&str] = &[
        "executable",
        "argv",
        "cwd",
        "timeout_ms",
        "stdout_bytes",
        "stderr_bytes",
        "stdin_policy",
        "network_class",
    ];
    if let Some(key) = arguments
        .keys()
        .find(|key| !ALLOWED.contains(&key.as_str()))
    {
        return Err(PolicyError::new(
            FailureCode::InvalidRequest,
            format!("process.spawn does not accept argument field: {key}"),
        ));
    }
    Ok(())
}

fn required_string<'a>(
    arguments: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a str, PolicyError> {
    arguments.get(key).and_then(Value::as_str).ok_or_else(|| {
        PolicyError::new(
            FailureCode::InvalidRequest,
            format!("process.spawn requires arguments.{key} as a string"),
        )
    })
}

fn bounded_u64(
    arguments: &Map<String, Value>,
    key: &str,
    minimum: u64,
    maximum: u64,
) -> Result<u64, PolicyError> {
    let value = arguments.get(key).and_then(Value::as_u64).ok_or_else(|| {
        PolicyError::new(
            FailureCode::InvalidRequest,
            format!("process.spawn requires arguments.{key} as an unsigned integer"),
        )
    })?;
    if !(minimum..=maximum).contains(&value) {
        return Err(PolicyError::new(
            FailureCode::InvalidRequest,
            format!("process.spawn {key} must be between {minimum} and {maximum}"),
        ));
    }
    Ok(value)
}

fn validate_process_executable(executable: &str, argv: &[String]) -> Result<(), PolicyError> {
    if executable.is_empty() || executable.contains('\0') {
        return Err(PolicyError::new(
            FailureCode::InvalidRequest,
            "process.spawn executable must be a non-empty absolute path without NUL bytes",
        ));
    }

    let portable = executable.replace('/', "\\");
    if portable.starts_with("\\\\") {
        return Err(PolicyError::new(
            FailureCode::CapabilityDenied,
            "process.spawn executable cannot use UNC or device namespaces",
        ));
    }

    let bytes = executable.as_bytes();
    let windows_absolute = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/');
    if !windows_absolute && !Path::new(executable).is_absolute() {
        return Err(PolicyError::new(
            FailureCode::InvalidRequest,
            "process.spawn executable must be an absolute local path",
        ));
    }

    enforce_sg000010_executable_policy(executable, argv)?;
    Ok(())
}

/// SG-000010 baseline (`whoami.exe`, Windows only) or, from SG-000060, a
/// locally registered, hash-pinned executable whose argv matches its
/// grammar. XP-13b: the registry applies on every OS, now that the Safe tier
/// runs on Linux and macOS too.
fn enforce_sg000010_executable_policy(
    executable: &str,
    argv: &[String],
) -> Result<(), PolicyError> {
    #[cfg(windows)]
    if is_sg000010_baseline(executable)? {
        return Ok(());
    }
    let registry_path = crate::executable_registry::default_registry_path().map_err(|error| {
        PolicyError::new(
            FailureCode::ProviderUnavailable,
            format!("SG-000060 executable registry is unavailable: {error}"),
        )
    })?;
    let entries = crate::executable_registry::load_registry(&registry_path);
    crate::executable_registry::check_spawn(&entries, Path::new(executable), argv)
        .map(|_| ())
        .map_err(|error| PolicyError::new(error.code, error.message))
}

#[cfg(windows)]
fn is_sg000010_baseline(executable: &str) -> Result<bool, PolicyError> {
    let requested = std::fs::canonicalize(executable).map_err(|error| {
        PolicyError::new(
            FailureCode::InvalidRequest,
            format!("process.spawn executable could not be resolved: {error}"),
        )
    })?;
    let system_root = std::env::var_os("SystemRoot").ok_or_else(|| {
        PolicyError::new(
            FailureCode::ProviderUnavailable,
            "SystemRoot is unavailable for SG-000010 executable policy",
        )
    })?;
    let allowed = std::fs::canonicalize(
        PathBuf::from(system_root)
            .join("System32")
            .join("whoami.exe"),
    )
    .map_err(|error| {
        PolicyError::new(
            FailureCode::ProviderUnavailable,
            format!("SG-000010 whoami.exe fixture could not be resolved: {error}"),
        )
    })?;
    Ok(requested == allowed)
}

pub fn validate_relative_target(target: &str) -> Result<(), PolicyError> {
    if target.contains('\0') {
        return Err(PolicyError::new(
            FailureCode::InvalidRequest,
            "path contains a NUL byte",
        ));
    }

    let portable = target.replace('/', "\\");
    let bytes = portable.as_bytes();
    let drive_prefixed = bytes.len() >= 2 && bytes[1] == b':';
    let root_prefixed = portable.starts_with('\\');
    let device_prefixed = portable.starts_with("\\\\?\\") || portable.starts_with("\\\\.\\");
    if drive_prefixed || root_prefixed || device_prefixed {
        return Err(PolicyError::new(
            FailureCode::PathEscape,
            "absolute, UNC, or device paths are not allowed",
        ));
    }

    let path = Path::new(target);
    if path.is_absolute() {
        return Err(PolicyError::new(
            FailureCode::PathEscape,
            "absolute paths are not allowed",
        ));
    }

    for component in path.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(PolicyError::new(
                    FailureCode::PathEscape,
                    "parent/root/prefix path components are not allowed",
                ));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use orcel_contracts::RequestEnvelope;
    use serde_json::json;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static TEMP_ROOT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn temp_root() -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let sequence = TEMP_ROOT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "orcel-policy-{}-{suffix}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).expect("create temp workspace");
        root
    }

    fn request(target: &str) -> RequestEnvelope {
        RequestEnvelope {
            version: 1,
            request_id: "r1".into(),
            client_session_id: "s1".into(),
            workspace_id: "default".into(),
            capability: "fs.read".into(),
            operation: "read".into(),
            target: Some(target.into()),
            arguments: json!({}),
        }
    }

    fn process_request(executable: &Path) -> RequestEnvelope {
        RequestEnvelope {
            version: 1,
            request_id: "process-r1".into(),
            client_session_id: "s1".into(),
            workspace_id: "default".into(),
            capability: "process.spawn".into(),
            operation: "spawn".into(),
            target: None,
            arguments: json!({
                "executable": executable.to_string_lossy(),
                "argv": ["--version"],
                "cwd": ".",
                "timeout_ms": 30_000,
                "stdout_bytes": 2 * 1024 * 1024,
                "stderr_bytes": 256 * 1024,
                "stdin_policy": "null",
                "network_class": "NONE"
            }),
        }
    }

    #[cfg(windows)]
    fn process_fixture_executable() -> PathBuf {
        PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot"))
            .join("System32")
            .join("whoami.exe")
    }

    /// Off Windows there is no baseline executable, so this test binary is
    /// registered (grammar: `--version` only) in a private test registry that
    /// `ORCEL_EXECUTABLE_REGISTRY_PATH` names for the whole test process.
    #[cfg(not(windows))]
    fn process_fixture_executable() -> PathBuf {
        static REGISTERED: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
        REGISTERED
            .get_or_init(|| {
                use std::os::unix::fs::PermissionsExt;
                let executable = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
                let dir = crate::test_support::unique_temp_dir("orcel-policy-registry");
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
                let registry = dir.join("executable_registry.json");
                let entry = crate::executable_registry::build_entry(
                    "fixture",
                    &executable,
                    vec!["--version".into()],
                    vec![],
                    1,
                    &[],
                    1,
                )
                .unwrap();
                crate::executable_registry::save_registry(&registry, &[entry]).unwrap();
                std::env::set_var("ORCEL_EXECUTABLE_REGISTRY_PATH", &registry);
                executable
            })
            .clone()
    }

    fn engine(root: &Path) -> PolicyEngine {
        PolicyEngine::new(vec![Workspace {
            id: "default".into(),
            root: root.to_path_buf(),
        }])
        .expect("policy")
    }

    fn workspace(id: &str, root: &Path) -> Workspace {
        Workspace {
            id: id.into(),
            root: root.to_path_buf(),
        }
    }

    fn sg41_refused(root: &Path, protected: &Path) -> bool {
        match PolicyEngine::with_protected_state_roots(
            vec![workspace("default", root)],
            vec![protected.to_path_buf()],
        ) {
            Ok(_) => false,
            Err(error) => {
                assert_eq!(error.code, FailureCode::WorkspaceDenied);
                assert!(error.message.contains("overlaps Orcel protected state"));
                true
            }
        }
    }

    #[test]
    fn sg000041_refuses_workspace_equal_to_above_or_below_protected_state() {
        let base = temp_root();
        let state = base.join("Orcel");
        std::fs::create_dir_all(state.join("state")).unwrap();
        assert!(sg41_refused(&state, &state));
        assert!(sg41_refused(&base, &state));
        assert!(sg41_refused(&state.join("state"), &state));
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn sg000041_refuses_ancestor_of_missing_protected_root() {
        let base = temp_root();
        assert!(sg41_refused(&base, &base.join("Orcel").join("audit.jsonl")));
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn sg000041_refuses_workspace_containing_each_override() {
        let base = temp_root();
        // The per-OS state root comes from LOCALAPPDATA on Windows and from
        // HOME elsewhere; both point under `lad` so it is one root per OS.
        let roots = crate::protected_state::protected_state_roots_from(&|name| match name {
            "LOCALAPPDATA" | "HOME" => Some(base.join("lad").into_os_string()),
            "ORCEL_AUDIT_PATH" => Some(base.join("audit").join("a.jsonl").into_os_string()),
            "ORCEL_TRUST_PATH" => Some(base.join("trust").join("t.jsonl").into_os_string()),
            "ORCEL_APPROVAL_HISTORY_PATH" => {
                Some(base.join("history").join("h.jsonl").into_os_string())
            }
            "ORCEL_BROWSER_STATE_DIR" => Some(base.join("browser").into_os_string()),
            _ => None,
        });
        assert_eq!(roots.len(), 5);
        for dir in ["lad", "audit", "trust", "history", "browser"] {
            let workspace_root = base.join(dir);
            std::fs::create_dir_all(&workspace_root).unwrap();
            let refused = PolicyEngine::with_protected_state_roots(
                vec![workspace("default", &workspace_root)],
                roots.clone(),
            );
            assert!(refused.is_err(), "{dir} must be refused");
        }
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn sg000041_accepts_sibling_and_prefix_sharing_roots() {
        let base = temp_root();
        let state = base.join("Orcel");
        std::fs::create_dir_all(&state).unwrap();
        for sibling in ["Orcel-work", "Cotr", "project"] {
            let root = base.join(sibling);
            std::fs::create_dir_all(&root).unwrap();
            assert!(!sg41_refused(&root, &state), "{sibling} must be accepted");
        }
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn sg000041_parent_relative_override_fails_closed() {
        let base = temp_root();
        let error = PolicyEngine::with_protected_state_roots(
            vec![workspace("default", &base)],
            vec![base.join("x").join("..").join("audit.jsonl")],
        )
        .unwrap_err();
        assert_eq!(error.code, FailureCode::WorkspaceDenied);
        let _ = std::fs::remove_dir_all(base);
    }

    #[cfg(windows)]
    #[test]
    fn sg000041_case_variant_workspace_is_refused_on_windows() {
        let base = temp_root();
        let state = base.join("Orcel");
        std::fs::create_dir_all(&state).unwrap();
        let upper = PathBuf::from(base.to_string_lossy().to_uppercase()).join("ORCEL");
        assert!(sg41_refused(&state, &upper));
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn rejects_parent_escape() {
        let root = temp_root();
        let error = engine(&root)
            .authorize(&request("../outside.txt"))
            .expect_err("escape must fail");
        assert_eq!(error.code, FailureCode::PathEscape);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn rejects_windows_root_and_device_paths_portably() {
        assert!(validate_relative_target(r"C:\Windows\System32").is_err());
        assert!(validate_relative_target(r"\Windows\System32").is_err());
        assert!(validate_relative_target(r"\\server\share\file").is_err());
        assert!(validate_relative_target(r"\\?\C:\Windows").is_err());
        assert!(validate_relative_target(r"\\.\PhysicalDrive0").is_err());
    }

    #[test]
    fn denies_unknown_capability() {
        let root = temp_root();
        let mut req = request("file.txt");
        req.capability = "process.kill".into();
        req.operation = "kill".into();
        let error = engine(&root).authorize(&req).expect_err("must be denied");
        assert_eq!(error.code, FailureCode::CapabilityDenied);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn write_requires_content() {
        let root = temp_root();
        let mut req = request("file.txt");
        req.capability = "fs.write".into();
        req.operation = "write".into();
        let error = engine(&root)
            .authorize(&req)
            .expect_err("missing content must fail");
        assert_eq!(error.code, FailureCode::InvalidRequest);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn authorizes_only_bounded_argv_process_spawn() {
        let root = temp_root();
        let executable = process_fixture_executable();
        let req = process_request(&executable);
        engine(&root)
            .authorize(&req)
            .expect("bounded process.spawn");

        let mut wrong_operation = req.clone();
        wrong_operation.operation = "run".into();
        assert_eq!(
            engine(&root).authorize(&wrong_operation).unwrap_err().code,
            FailureCode::CapabilityDenied
        );

        let mut powershell = req.clone();
        powershell.capability = "powershell.run".into();
        powershell.operation = "run".into();
        assert_eq!(
            engine(&root).authorize(&powershell).unwrap_err().code,
            FailureCode::CapabilityDenied
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn process_spawn_rejects_escape_shell_network_stdin_env_and_unbounded_inputs() {
        let root = temp_root();
        let executable = process_fixture_executable();
        let base = process_request(&executable);

        let mut relative_executable = base.clone();
        relative_executable.arguments["executable"] = json!("tool.exe");
        assert_eq!(
            engine(&root)
                .authorize(&relative_executable)
                .unwrap_err()
                .code,
            FailureCode::InvalidRequest
        );

        let mut cwd_escape = base.clone();
        cwd_escape.arguments["cwd"] = json!("..");
        assert_eq!(
            engine(&root).authorize(&cwd_escape).unwrap_err().code,
            FailureCode::PathEscape
        );

        let mut nul_argv = base.clone();
        nul_argv.arguments["argv"] = json!(["bad\0arg"]);
        assert_eq!(
            engine(&root).authorize(&nul_argv).unwrap_err().code,
            FailureCode::InvalidRequest
        );

        let mut network = base.clone();
        network.arguments["network_class"] = json!("DIRECT_DESTINATION");
        assert_eq!(
            engine(&root).authorize(&network).unwrap_err().code,
            FailureCode::CapabilityDenied
        );

        let mut stdin = base.clone();
        stdin.arguments["stdin_policy"] = json!("text");
        assert_eq!(
            engine(&root).authorize(&stdin).unwrap_err().code,
            FailureCode::InvalidRequest
        );

        let mut env = base.clone();
        env.arguments["env"] = json!({"PATH": "caller"});
        assert_eq!(
            engine(&root).authorize(&env).unwrap_err().code,
            FailureCode::InvalidRequest
        );

        let mut raw_command = base.clone();
        raw_command.arguments["command"] = json!("cmd /c whoami");
        assert_eq!(
            engine(&root).authorize(&raw_command).unwrap_err().code,
            FailureCode::InvalidRequest
        );

        let mut timeout = base.clone();
        timeout.arguments["timeout_ms"] = json!(MAX_PROCESS_TIMEOUT_MS + 1);
        assert_eq!(
            engine(&root).authorize(&timeout).unwrap_err().code,
            FailureCode::InvalidRequest
        );

        let mut stdout = base.clone();
        stdout.arguments["stdout_bytes"] = json!(MAX_PROCESS_STDOUT_BYTES + 1);
        assert_eq!(
            engine(&root).authorize(&stdout).unwrap_err().code,
            FailureCode::InvalidRequest
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn process_spawn_rejects_unqualified_shell_and_powershell_executables() {
        let root = temp_root();
        let system32 =
            PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot")).join("System32");
        for name in ["cmd.exe", "WindowsPowerShell\\v1.0\\powershell.exe"] {
            let request = process_request(&system32.join(name));
            let error = engine(&root)
                .authorize(&request)
                .expect_err("SG-000010 must not expose shell/interpreter authority");
            assert_eq!(error.code, FailureCode::CapabilityDenied);
        }
        let _ = std::fs::remove_dir_all(root);
    }
}
