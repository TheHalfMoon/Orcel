//! User configuration in `state\config.json`: workspaces and the tunnel
//! profile. The tunnel runtime key is never stored here; it lives in
//! `state\secrets\tunnel-runtime-key` and is passed to the tunnel client by
//! file reference only.

use crate::layout::{read_json, write_bytes_atomic, write_json_atomic, Layout};
use crate::LifecycleError;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const CONFIG_SCHEMA: &str = "orcel-config-v1";
/// Configuration schema version written by this build.
pub const CONFIG_SCHEMA_VERSION: u32 = 1;
const MAX_WORKSPACES: usize = 64;
const MAX_KEY_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceEntry {
    pub id: String,
    pub root: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelSettings {
    pub client: PathBuf,
    pub tunnel_id: String,
}

/// What approval prompts show of the content they approve: the person's saved choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalPreviews {
    /// A bounded preview, hidden when the content matches a credential pattern (the default).
    Content,
    /// Sizes only: prompts never show any of the content.
    Sizes,
}

impl ApprovalPreviews {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Content => "content",
            Self::Sizes => "sizes",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "content" => Some(Self::Content),
            "sizes" => Some(Self::Sizes),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema: String,
    pub config_schema: u32,
    pub workspaces: Vec<WorkspaceEntry>,
    pub tunnel: Option<TunnelSettings>,
    /// Absent until the person chooses; absent means content previews. Left out of the file
    /// while unset, so a configuration saved without a choice reads the same in older builds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_previews: Option<ApprovalPreviews>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema: CONFIG_SCHEMA.into(),
            config_schema: CONFIG_SCHEMA_VERSION,
            workspaces: Vec::new(),
            tunnel: None,
            approval_previews: None,
        }
    }
}

impl Config {
    /// Loads the configuration; an absent file is an empty configuration.
    pub fn load(layout: &Layout) -> Result<Self, LifecycleError> {
        let config: Config = read_json(&layout.config_file())?.unwrap_or_default();
        config.validate_shape()?;
        Ok(config)
    }

    pub fn save(&self, layout: &Layout) -> Result<(), LifecycleError> {
        self.validate_shape()?;
        std::fs::create_dir_all(layout.state_dir())
            .map_err(|error| LifecycleError::io("create state directory", error))?;
        write_json_atomic(&layout.config_file(), self)
    }

    fn validate_shape(&self) -> Result<(), LifecycleError> {
        if self.schema != CONFIG_SCHEMA {
            return Err(LifecycleError::state(
                "config.json has an unsupported schema",
            ));
        }
        if self.config_schema != CONFIG_SCHEMA_VERSION {
            return Err(LifecycleError::state(format!(
                "config.json schema version {} is not supported by this build (supports {CONFIG_SCHEMA_VERSION})",
                self.config_schema
            )));
        }
        if self.workspaces.len() > MAX_WORKSPACES {
            return Err(LifecycleError::state("too many workspaces configured"));
        }
        let mut ids = std::collections::BTreeSet::new();
        for workspace in &self.workspaces {
            validate_workspace_id(&workspace.id)?;
            if !ids.insert(workspace.id.to_ascii_lowercase()) {
                return Err(LifecycleError::state(format!(
                    "duplicate workspace id {}",
                    workspace.id
                )));
            }
            if !workspace.root.is_absolute() {
                return Err(LifecycleError::state(format!(
                    "workspace {} root is not absolute",
                    workspace.id
                )));
            }
        }
        if let Some(tunnel) = &self.tunnel {
            validate_tunnel_id(&tunnel.tunnel_id)?;
            if !tunnel.client.is_absolute() {
                return Err(LifecycleError::state("tunnel client path is not absolute"));
            }
        }
        Ok(())
    }

    /// Validates the workspace set exactly as the policy kernel will: every
    /// root must resolve to a directory that does not overlap Orcel
    /// protected state.
    pub fn check_workspaces_with_policy(&self) -> Result<(), LifecycleError> {
        if self.workspaces.is_empty() {
            return Err(LifecycleError::state(
                "no workspace is configured; run `orcel workspace add <id> <directory>`",
            ));
        }
        orcel_policy::PolicyEngine::new(
            self.workspaces
                .iter()
                .map(|workspace| orcel_policy::Workspace {
                    id: workspace.id.clone(),
                    root: workspace.root.clone(),
                })
                .collect(),
        )
        .map(|_| ())
        .map_err(|error| LifecycleError::state(error.message))
    }

    pub fn add_workspace(
        &mut self,
        id: &str,
        root: &Path,
    ) -> Result<WorkspaceEntry, LifecycleError> {
        validate_workspace_id(id)?;
        if self
            .workspaces
            .iter()
            .any(|workspace| workspace.id.eq_ignore_ascii_case(id))
        {
            return Err(LifecycleError::conflict(format!(
                "workspace {id} already exists"
            )));
        }
        let root = std::fs::canonicalize(root).map_err(|error| {
            LifecycleError::usage(format!("workspace directory cannot be resolved: {error}"))
        })?;
        let entry = WorkspaceEntry {
            id: id.to_string(),
            root: display_path(&root),
        };
        let mut candidate = self.clone();
        candidate.workspaces.push(entry.clone());
        candidate.check_workspaces_with_policy()?;
        *self = candidate;
        Ok(entry)
    }

    pub fn remove_workspace(&mut self, id: &str) -> Result<WorkspaceEntry, LifecycleError> {
        let index = self
            .workspaces
            .iter()
            .position(|workspace| workspace.id.eq_ignore_ascii_case(id))
            .ok_or_else(|| LifecycleError::usage(format!("workspace {id} is not configured")))?;
        Ok(self.workspaces.remove(index))
    }

    /// `ORCEL_WORKSPACES_JSON` for `orceld` and `orcel-mcp`.
    pub fn workspaces_json(&self) -> String {
        serde_json::to_string(
            &self
                .workspaces
                .iter()
                .map(|workspace| serde_json::json!({"id": workspace.id, "root": workspace.root}))
                .collect::<Vec<_>>(),
        )
        .unwrap_or_else(|_| "[]".into())
    }

    pub fn default_workspace(&self) -> Option<&str> {
        self.workspaces
            .first()
            .map(|workspace| workspace.id.as_str())
    }
}

/// Removes the Windows verbatim prefix for display and configuration while
/// keeping the same location.
pub fn display_path(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{rest}"))
    } else if let Some(rest) = text.strip_prefix(r"\\?\") {
        PathBuf::from(rest)
    } else {
        path.to_path_buf()
    }
}

pub fn validate_workspace_id(id: &str) -> Result<(), LifecycleError> {
    let valid = !id.is_empty()
        && id.len() <= 64
        && id.as_bytes()[0].is_ascii_alphanumeric()
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if valid {
        Ok(())
    } else {
        Err(LifecycleError::usage(
            "workspace id must be 1-64 characters of letters, digits, '-' or '_', starting with a letter or digit",
        ))
    }
}

pub fn validate_tunnel_id(id: &str) -> Result<(), LifecycleError> {
    let valid = id.strip_prefix("tunnel_").is_some_and(|suffix| {
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    });
    if valid {
        Ok(())
    } else {
        Err(LifecycleError::usage(
            "tunnel id must match tunnel_<32 lowercase letters or digits>",
        ))
    }
}

/// Validates runtime key material without echoing it: 1-4096 printable,
/// non-whitespace ASCII bytes.
pub fn validate_runtime_key(key: &str) -> Result<(), LifecycleError> {
    if key.is_empty() || key.len() > MAX_KEY_BYTES {
        return Err(LifecycleError::usage("runtime key is empty or too long"));
    }
    if !key.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(LifecycleError::usage(
            "runtime key must be printable ASCII without whitespace",
        ));
    }
    Ok(())
}

/// Stores the runtime key in the protected secrets directory.
pub fn store_runtime_key(layout: &Layout, key: &str) -> Result<(), LifecycleError> {
    validate_runtime_key(key)?;
    std::fs::create_dir_all(layout.secrets_dir())
        .map_err(|error| LifecycleError::io("create secrets directory", error))?;
    write_bytes_atomic(&layout.runtime_key_file(), key.as_bytes())
}

/// Builds the closed `orcel-tunnel` configuration for the active version.
pub fn tunnel_config(
    layout: &Layout,
    config: &Config,
    active_version: &str,
) -> Result<orcel_tunnel::TunnelConfig, LifecycleError> {
    let tunnel = config.tunnel.as_ref().ok_or_else(|| {
        LifecycleError::state("the tunnel is not configured; run `orcel tunnel setup`")
    })?;
    let tunnel_config = orcel_tunnel::TunnelConfig {
        tunnel_client: tunnel.client.clone(),
        tunnel_id: tunnel.tunnel_id.clone(),
        runtime_key_file: layout.runtime_key_file(),
        mcp_command: layout
            .version_dir(active_version)
            .join("orcel-mcp-host.exe"),
        health_url_file: layout.health_url_file(),
        workspace_roots: config
            .workspaces
            .iter()
            .map(|workspace| workspace.root.clone())
            .collect(),
    };
    tunnel_config
        .validate()
        .map_err(|message| LifecycleError::state(format!("tunnel configuration: {message}")))?;
    Ok(tunnel_config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_preview_choice_is_saved_only_once_made_and_unknown_values_refuse() {
        let unset = serde_json::to_string(&Config::default()).unwrap();
        assert!(!unset.contains("approval_previews"), "{unset}");
        let old: Config = serde_json::from_str(
            r#"{"schema":"orcel-config-v1","config_schema":1,"workspaces":[],"tunnel":null}"#,
        )
        .unwrap();
        assert_eq!(old.approval_previews, None);
        let sizes = Config {
            approval_previews: Some(ApprovalPreviews::Sizes),
            ..Config::default()
        };
        let saved = serde_json::to_string(&sizes).unwrap();
        assert!(saved.contains(r#""approval_previews":"sizes""#), "{saved}");
        assert_eq!(serde_json::from_str::<Config>(&saved).unwrap(), sizes);
        assert!(serde_json::from_str::<Config>(
            r#"{"schema":"orcel-config-v1","config_schema":1,"workspaces":[],"tunnel":null,"approval_previews":"all"}"#,
        )
        .is_err());
        assert_eq!(
            ApprovalPreviews::parse("sizes"),
            Some(ApprovalPreviews::Sizes)
        );
        assert_eq!(ApprovalPreviews::parse("Sizes"), None);
    }
    use crate::test_support::temp_dir;

    #[test]
    fn ids_are_validated() {
        for id in ["default", "repo-1", "A_b"] {
            validate_workspace_id(id).unwrap();
        }
        for id in ["", "-x", "a b", "a/b", "é", &"a".repeat(65)] {
            assert!(validate_workspace_id(id).is_err(), "{id:?}");
        }
        validate_tunnel_id("tunnel_0123456789abcdefghijklmnopqrstuv").unwrap();
        for id in [
            "tunnel_0123456789ABCDEFGHIJKLMNOPQRSTUV",
            "tunnel_short",
            "tunnel-0123456789abcdefghijklmnopqrstuv",
        ] {
            assert!(validate_tunnel_id(id).is_err(), "{id:?}");
        }
    }

    #[test]
    fn runtime_keys_are_validated_without_whitespace() {
        validate_runtime_key("sk-abc_DEF.123").unwrap();
        for key in ["", "has space", "tab\t", "new\nline", "caf\u{e9}"] {
            assert!(validate_runtime_key(key).is_err(), "{key:?}");
        }
        assert!(validate_runtime_key(&"k".repeat(4097)).is_err());
    }

    #[test]
    fn workspace_add_applies_policy_admission_and_round_trips() {
        let base = temp_dir("config");
        let layout = Layout::new(base.join("Orcel"));
        let project = base.join("project");
        std::fs::create_dir_all(&project).unwrap();
        let mut config = Config::default();
        config.add_workspace("default", &project).unwrap();
        assert!(config.add_workspace("DEFAULT", &project).is_err());
        assert!(config
            .add_workspace("missing", &base.join("missing"))
            .is_err());
        config.save(&layout).unwrap();
        let loaded = Config::load(&layout).unwrap();
        assert_eq!(loaded, config);
        let parsed: serde_json::Value = serde_json::from_str(&loaded.workspaces_json()).unwrap();
        assert_eq!(parsed[0]["id"], "default");
        assert_eq!(loaded.default_workspace(), Some("default"));
        let mut loaded = loaded;
        loaded.remove_workspace("default").unwrap();
        assert!(loaded.check_workspaces_with_policy().is_err());
    }

    #[test]
    fn unsupported_schema_version_fails_closed() {
        let base = temp_dir("config-schema");
        let layout = Layout::new(base.join("Orcel"));
        std::fs::create_dir_all(layout.state_dir()).unwrap();
        std::fs::write(
            layout.config_file(),
            br#"{"schema":"orcel-config-v1","config_schema":2,"workspaces":[],"tunnel":null}"#,
        )
        .unwrap();
        let error = Config::load(&layout).unwrap_err();
        assert!(error.message.contains("not supported"));
    }

    #[test]
    fn verbatim_prefix_is_removed_for_display() {
        assert_eq!(
            display_path(Path::new(r"\\?\C:\work")),
            PathBuf::from(r"C:\work")
        );
        assert_eq!(
            display_path(Path::new(r"\\?\UNC\server\share")),
            PathBuf::from(r"\\server\share")
        );
    }
}
