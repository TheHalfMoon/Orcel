use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

const SECRETISH: &[&str] = &[
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
    "API_KEY",
    "TUNNEL_KEY",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelConfig {
    pub tunnel_client: PathBuf,
    pub tunnel_id: String,
    pub runtime_key_file: PathBuf,
    pub mcp_command: PathBuf,
    pub health_url_file: PathBuf,
    pub workspace_roots: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchPlan {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct WorkspaceConfig {
    root: PathBuf,
}

impl TunnelConfig {
    pub fn from_env() -> Result<Self, String> {
        let tunnel_client = required_path("ORCEL_TUNNEL_CLIENT")?;
        let tunnel_id = required("ORCEL_TUNNEL_ID")?;
        let runtime_key_file = required_path("ORCEL_TUNNEL_KEY_FILE")?;
        let mcp_command = required_path("ORCEL_MCP_COMMAND")?;
        let health_url_file = required_path("ORCEL_TUNNEL_HEALTH_URL_FILE")?;
        let workspace_roots = configured_workspace_roots()?;
        let config = Self {
            tunnel_client,
            tunnel_id,
            runtime_key_file,
            mcp_command,
            health_url_file,
            workspace_roots,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), String> {
        if !valid_tunnel_id(&self.tunnel_id) {
            return Err(
                "ORCEL_TUNNEL_ID must match tunnel_<32 lowercase alphanumeric characters>".into(),
            );
        }
        require_absolute_existing_file(&self.tunnel_client, "tunnel-client")?;
        require_absolute_existing_file(&self.mcp_command, "Orcel MCP command")?;
        require_absolute_existing_file(&self.runtime_key_file, "runtime key file")?;
        if !self.health_url_file.is_absolute() {
            return Err("health URL file path must be absolute".into());
        }
        let key_metadata = fs::metadata(&self.runtime_key_file)
            .map_err(|e| format!("inspect runtime key file: {e}"))?;
        if key_metadata.len() == 0 {
            return Err("runtime key file is empty".into());
        }

        let secret_path = canonical(&self.runtime_key_file, "runtime key file")?;
        for root in &self.workspace_roots {
            let root = canonical(root, "workspace root")?;
            if secret_path == root || secret_path.starts_with(&root) {
                return Err(
                    "runtime key file must be outside every trusted Orcel workspace".into(),
                );
            }
        }
        Ok(())
    }

    pub fn launch_plan(&self, source: &BTreeMap<String, String>) -> Result<LaunchPlan, String> {
        self.validate()?;
        let key_ref = format!("file:{}", self.runtime_key_file.display());
        let mcp_binding = format!(
            "channel=main,command={}",
            quote_stdio_command_path(&self.mcp_command)?
        );
        let args = vec![
            "run".into(),
            "--control-plane.tunnel-id".into(),
            self.tunnel_id.clone(),
            "--control-plane.api-key".into(),
            key_ref,
            "--mcp.command".into(),
            mcp_binding,
            "--health.listen-addr".into(),
            "127.0.0.1:0".into(),
            "--health.url-file".into(),
            self.health_url_file.to_string_lossy().into_owned(),
            "--log.http-raw-unsafe=false".into(),
        ];
        Ok(LaunchPlan {
            program: self.tunnel_client.clone(),
            args,
            env: tunnel_client_env(source),
        })
    }
}

/// #395: the tunnel client's environment carries OS execution variables
/// only. It runs `orcel-mcp-host`, which rebuilds its whole environment from
/// the local configuration, so no `ORCEL_*` variable (workspace overrides,
/// a daemon path, the runtime session binding, provider configuration) has
/// any reason to cross the remote transport, and none may widen it.
pub fn tunnel_client_env(source: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut env = sanitized_env(source);
    env.retain(|name, _| is_os_execution_env(name));
    env
}

pub fn sanitized_env(source: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (name, value) in source {
        let upper = name.to_ascii_uppercase();
        if SECRETISH.iter().any(|needle| upper.contains(needle)) {
            continue;
        }
        if is_os_execution_env(name) || is_safe_orcel_env(name) {
            out.insert(name.clone(), value.clone());
        }
    }
    out
}

pub fn current_env() -> BTreeMap<String, String> {
    env::vars().collect()
}

pub fn run(config: &TunnelConfig) -> Result<ExitStatus, String> {
    let plan = config.launch_plan(&current_env())?;
    let mut command = Command::new(&plan.program);
    command
        .args(&plan.args)
        .env_clear()
        .envs(&plan.env)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let mut child = command
        .spawn()
        .map_err(|e| format!("start tunnel-client: {e}"))?;
    child.wait().map_err(|e| format!("wait tunnel-client: {e}"))
}

pub fn status(config: &TunnelConfig) -> serde_json::Value {
    match fs::read_to_string(&config.health_url_file) {
        Ok(url) if !url.trim().is_empty() => json!({
            "configured": true,
            "health_url_present": true,
            "health_url": url.trim(),
            "credential_source": "file",
            "runtime_key_in_environment": false
        }),
        _ => json!({
            "configured": true,
            "health_url_present": false,
            "credential_source": "file",
            "runtime_key_in_environment": false
        }),
    }
}

fn valid_tunnel_id(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix("tunnel_") else {
        return false;
    };
    suffix.len() == 32
        && suffix
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

fn quote_stdio_command_path(path: &Path) -> Result<String, String> {
    let raw = path.to_string_lossy();
    if raw.contains(',') {
        return Err("Orcel MCP command path must not contain a comma".into());
    }
    let escaped = raw.replace('\\', "\\\\").replace('"', "\\\"");
    Ok(format!("\"{escaped}\""))
}

fn required(name: &str) -> Result<String, String> {
    env::var(name).map_err(|_| format!("{name} is required"))
}

fn required_path(name: &str) -> Result<PathBuf, String> {
    Ok(PathBuf::from(required(name)?))
}

fn require_absolute_existing_file(path: &Path, label: &str) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!("{label} path must be absolute"));
    }
    let metadata = fs::metadata(path).map_err(|e| format!("{label} is unavailable: {e}"))?;
    if !metadata.is_file() {
        return Err(format!("{label} must be a file"));
    }
    Ok(())
}

fn canonical(path: &Path, label: &str) -> Result<PathBuf, String> {
    fs::canonicalize(path).map_err(|e| format!("resolve {label}: {e}"))
}

fn configured_workspace_roots() -> Result<Vec<PathBuf>, String> {
    if let Ok(raw) = env::var("ORCEL_WORKSPACES_JSON") {
        let values: Vec<WorkspaceConfig> =
            serde_json::from_str(&raw).map_err(|e| format!("parse ORCEL_WORKSPACES_JSON: {e}"))?;
        return Ok(values.into_iter().map(|v| v.root).collect());
    }
    if let Some(root) = env::var_os("ORCEL_WORKSPACE_ROOT") {
        return Ok(vec![PathBuf::from(root)]);
    }
    Ok(Vec::new())
}

fn is_os_execution_env(name: &str) -> bool {
    matches!(
        name,
        "PATH"
            | "Path"
            | "PATHEXT"
            | "SystemRoot"
            | "WINDIR"
            | "TEMP"
            | "TMP"
            | "USERPROFILE"
            | "LOCALAPPDATA"
            | "APPDATA"
            | "PROGRAMDATA"
            | "ProgramFiles"
            | "ProgramFiles(x86)"
    )
}

/// Orcel variables passed to local Orcel children (`orceld`, the local stdio
/// MCP app). Never passed to the tunnel client (see [`tunnel_client_env`]).
fn is_safe_orcel_env(name: &str) -> bool {
    matches!(
        name,
        "ORCEL_WORKSPACES_JSON"
            | "ORCEL_WORKSPACE_ROOT"
            | "ORCEL_WORKSPACE_ID"
            | "ORCEL_DEFAULT_WORKSPACE"
            | "ORCEL_DAEMON"
            | "ORCEL_ORCEL_SESSION_ID"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> PathBuf {
        // Tests run in parallel and the clock can repeat, so a per-process
        // counter keeps every directory unique; otherwise one test's cleanup
        // can delete another test's files.
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let seq = NEXT.fetch_add(1, Ordering::Relaxed);
        let p = env::temp_dir().join(format!(
            "orcel-tunnel-{name}-{}-{n}-{seq}",
            std::process::id()
        ));
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn file(dir: &Path, name: &str, contents: &str) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, contents).unwrap();
        p
    }

    fn config() -> (TunnelConfig, PathBuf) {
        let dir = temp_dir("config");
        let workspace = dir.join("workspace");
        let secrets = dir.join("state");
        fs::create_dir_all(&workspace).unwrap();
        fs::create_dir_all(&secrets).unwrap();
        let tunnel = file(&dir, "tunnel-client", "binary");
        let mcp = file(&dir, "orcel-mcp", "binary");
        let key = file(&secrets, "runtime-key", "sk-proj-test");
        (
            TunnelConfig {
                tunnel_client: tunnel,
                tunnel_id: "tunnel_0123456789abcdefghijklmnopqrstuv".into(),
                runtime_key_file: key,
                mcp_command: mcp,
                health_url_file: dir.join("health.url"),
                workspace_roots: vec![workspace],
            },
            dir,
        )
    }

    #[test]
    fn launch_uses_file_reference_and_drops_secret_env() {
        let (cfg, dir) = config();
        let source = BTreeMap::from([
            ("PATH".into(), "bin".into()),
            ("ORCEL_WORKSPACE_ID".into(), "default".into()),
            ("CONTROL_PLANE_API_KEY".into(), "leak".into()),
            ("OPENAI_API_KEY".into(), "leak2".into()),
            ("ORCEL_TUNNEL_KEY".into(), "leak3".into()),
        ]);
        let plan = cfg.launch_plan(&source).unwrap();
        assert!(!plan.env.contains_key("CONTROL_PLANE_API_KEY"));
        assert!(!plan.env.contains_key("OPENAI_API_KEY"));
        assert!(!plan.env.contains_key("ORCEL_TUNNEL_KEY"));
        assert_eq!(plan.env.get("PATH").unwrap(), "bin");
        let rendered = plan.args.join(" ");
        assert!(rendered.contains("--control-plane.api-key file:"));
        assert!(!rendered.contains("sk-proj-test"));
        let _ = fs::remove_dir_all(dir);
    }

    /// WI-06: web search must never reach the tunnel, so its provider
    /// configuration never crosses into the tunnel client.
    #[test]
    fn wi06_tunnel_drops_search_configuration() {
        let (cfg, dir) = config();
        let source = BTreeMap::from([
            ("PATH".into(), "bin".into()),
            (
                "ORCEL_SEARCH_PROVIDERS_JSON".into(),
                r#"{"providers":{"brave":{}}}"#.into(),
            ),
        ]);
        let plan = cfg.launch_plan(&source).unwrap();
        assert!(!plan.env.contains_key("ORCEL_SEARCH_PROVIDERS_JSON"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn tunnel_client_env_carries_no_orcel_variable() {
        // #395: every Orcel variable the local children accept, and the ones
        // that would widen the tunnel host, stay out of the tunnel client.
        let (cfg, dir) = config();
        let source = BTreeMap::from([
            ("PATH".into(), "bin".into()),
            ("SystemRoot".into(), r"C:\Windows".into()),
            ("ORCEL_WORKSPACES_JSON".into(), "[]".into()),
            ("ORCEL_WORKSPACE_ROOT".into(), "/w".into()),
            ("ORCEL_WORKSPACE_ID".into(), "default".into()),
            ("ORCEL_DEFAULT_WORKSPACE".into(), "default".into()),
            ("ORCEL_DAEMON".into(), "/elsewhere/orceld".into()),
            ("ORCEL_ORCEL_SESSION_ID".into(), "session".into()),
            (
                "ORCEL_TOOL_SURFACE_PROFILE".into(),
                "desktop_structured".into(),
            ),
            ("ORCEL_SEARCH_PROVIDERS_JSON".into(), "{}".into()),
            ("ORCEL_MCP_TRANSPORT".into(), "stdio".into()),
        ]);
        let plan = cfg.launch_plan(&source).unwrap();
        assert_eq!(
            plan.env.keys().map(String::as_str).collect::<Vec<_>>(),
            ["PATH", "SystemRoot"]
        );
        // The local children keep their allowlist.
        assert!(sanitized_env(&source).contains_key("ORCEL_ORCEL_SESSION_ID"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn mcp_command_path_is_quoted_for_spaces_and_backslashes() {
        let (mut cfg, dir) = config();
        let spaced = dir.join("Program Files").join("Orcel");
        fs::create_dir_all(&spaced).unwrap();
        cfg.mcp_command = file(&spaced, "orcel-mcp.exe", "binary");
        let plan = cfg.launch_plan(&BTreeMap::new()).unwrap();
        let binding = plan
            .args
            .iter()
            .skip_while(|arg| arg.as_str() != "--mcp.command")
            .nth(1)
            .unwrap();
        assert!(binding.starts_with("channel=main,command=\""));
        assert!(binding.ends_with("orcel-mcp.exe\""));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn malformed_tunnel_ids_are_rejected_locally() {
        let (mut cfg, dir) = config();
        cfg.tunnel_id = "tunnel_TOO_SHORT".into();
        assert!(cfg.validate().unwrap_err().contains("must match"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn runtime_key_inside_workspace_is_rejected() {
        let (mut cfg, dir) = config();
        let key = file(&cfg.workspace_roots[0], "bad-key", "secret");
        cfg.runtime_key_file = key;
        assert!(cfg
            .validate()
            .unwrap_err()
            .contains("outside every trusted"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn health_listener_is_loopback_ephemeral_and_raw_http_logging_is_off() {
        let (cfg, dir) = config();
        let plan = cfg.launch_plan(&BTreeMap::new()).unwrap();
        let rendered = plan.args.join(" ");
        assert!(rendered.contains("--health.listen-addr 127.0.0.1:0"));
        assert!(rendered.contains("--log.http-raw-unsafe=false"));
        let _ = fs::remove_dir_all(dir);
    }
}
