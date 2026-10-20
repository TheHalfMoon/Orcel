//! Orcel per-user installation and lifecycle management.
//!
//! This crate backs the human-invoked `orcel` CLI. It is never reachable from
//! the MCP surface and adds no agent capability.

pub mod config;
pub mod console;
pub mod doctor;
pub mod full_control;
pub mod health;
pub mod install;
pub mod ipc;
pub mod layout;
pub mod lifecycle;
pub mod linux;
pub mod logs;
pub mod manifest;
pub mod mcp;
pub mod mcp_host;
pub mod platform;
pub mod remote;
#[cfg(windows)]
pub mod runtime;
pub mod tunnel_route;
pub mod update;
pub mod version;

use serde::Serialize;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    Usage,
    Prerequisite,
    Manifest,
    NotInstalled,
    Conflict,
    State,
    Platform,
    Io,
    Internal,
}

impl ErrorKind {
    /// Process exit code for this failure class.
    pub fn exit_code(self) -> i32 {
        match self {
            Self::Usage => 2,
            Self::Prerequisite => 3,
            Self::Manifest => 4,
            Self::NotInstalled => 5,
            Self::Conflict => 6,
            Self::State => 7,
            Self::Platform => 8,
            Self::Io => 9,
            Self::Internal => 10,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LifecycleError {
    pub kind: ErrorKind,
    pub message: String,
}

impl LifecycleError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
    pub fn usage(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Usage, message)
    }
    pub fn prerequisite(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Prerequisite, message)
    }
    pub fn manifest(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Manifest, message)
    }
    pub fn not_installed(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::NotInstalled, message)
    }
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Conflict, message)
    }
    pub fn state(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::State, message)
    }
    pub fn platform(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Platform, message)
    }
    pub fn io(context: impl fmt::Display, error: std::io::Error) -> Self {
        Self::new(ErrorKind::Io, format!("{context}: {error}"))
    }
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Internal, message)
    }
}

impl fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for LifecycleError {}

/// A process-unique suffix for temporary and staging names.
pub fn nonce() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!(
        "{}-{nanos}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )
}

/// The host platform for the running build. Installation is supported on
/// Windows only; elsewhere every host query fails closed.
#[cfg(windows)]
pub fn host_platform() -> Box<dyn platform::Platform> {
    Box::new(platform::WindowsPlatform::default())
}

#[cfg(not(windows))]
pub fn host_platform() -> Box<dyn platform::Platform> {
    Box::new(UnsupportedPlatform)
}

#[cfg(not(windows))]
struct UnsupportedPlatform;

#[cfg(not(windows))]
impl platform::Platform for UnsupportedPlatform {
    fn windows_build(&self) -> Result<u32, LifecycleError> {
        Err(LifecycleError::prerequisite(
            "Orcel installation is supported on Windows only",
        ))
    }
    fn is_avoidably_elevated(&self) -> Result<bool, LifecycleError> {
        Err(LifecycleError::prerequisite(
            "Orcel installation is supported on Windows only",
        ))
    }
    fn protect_tree(&self, _root: &std::path::Path) -> Result<(), LifecycleError> {
        Err(LifecycleError::platform("owner-only ACLs require Windows"))
    }
    fn verify_tree_acl(&self, _root: &std::path::Path) -> Result<(), LifecycleError> {
        Err(LifecycleError::platform("owner-only ACLs require Windows"))
    }
    fn add_user_path(&self, _dir: &std::path::Path) -> Result<bool, LifecycleError> {
        Err(LifecycleError::platform(
            "the user PATH is managed on Windows only",
        ))
    }
    fn remove_user_path(&self, _dir: &std::path::Path) -> Result<bool, LifecycleError> {
        Err(LifecycleError::platform(
            "the user PATH is managed on Windows only",
        ))
    }
    fn node_version(&self, node: &std::path::Path) -> Result<version::Version, LifecycleError> {
        platform::run_node_version(node)
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use crate::manifest::{
        sha256_bytes, ConfigSchemaRange, Manifest, ManifestFile, MANIFEST_FILE, MANIFEST_SCHEMA,
        REQUIRED_FILES,
    };
    use crate::platform::Platform;
    use crate::version::Version;
    use crate::LifecycleError;
    use std::cell::RefCell;
    use std::fs;
    use std::path::{Path, PathBuf};

    pub fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("orcel-lifecycle-{label}-{}", crate::nonce()));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    /// Writes a synthetic release: every required file plus one nested
    /// dependency file, and a matching manifest.
    pub fn release_dir(version: &str) -> PathBuf {
        let dir = temp_dir(&format!("release-{version}"));
        let mut files = Vec::new();
        let mut paths = REQUIRED_FILES
            .iter()
            .map(|path| path.to_string())
            .collect::<Vec<_>>();
        paths.push("app/orcel-mcp/node_modules/zod/package.json".into());
        for path in paths {
            let contents = format!("{path} for {version}").into_bytes();
            let target = crate::manifest::join_relative(&dir, &path);
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            fs::write(&target, &contents).unwrap();
            files.push(ManifestFile {
                path,
                size: contents.len() as u64,
                sha256: sha256_bytes(&contents),
            });
        }
        let manifest = Manifest {
            schema: MANIFEST_SCHEMA.into(),
            version: version.into(),
            config_schema: ConfigSchemaRange { min: 1, max: 1 },
            files,
        };
        fs::write(
            dir.join(MANIFEST_FILE),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        dir
    }

    /// Deterministic platform double for logic tests. It records calls and
    /// reports configured outcomes; it never touches real ACLs or PATH.
    pub struct FakePlatform {
        pub build: u32,
        pub elevated: bool,
        pub node_major: u64,
        pub acl_ok: bool,
        pub path: RefCell<Vec<PathBuf>>,
        pub protected: RefCell<Vec<PathBuf>>,
    }

    impl Default for FakePlatform {
        fn default() -> Self {
            Self {
                build: 22_631,
                elevated: false,
                node_major: 24,
                acl_ok: true,
                path: RefCell::new(Vec::new()),
                protected: RefCell::new(Vec::new()),
            }
        }
    }

    impl FakePlatform {
        pub fn protected_roots(&self) -> Vec<PathBuf> {
            self.protected.borrow().clone()
        }
    }

    impl Platform for FakePlatform {
        fn windows_build(&self) -> Result<u32, LifecycleError> {
            Ok(self.build)
        }
        fn is_avoidably_elevated(&self) -> Result<bool, LifecycleError> {
            Ok(self.elevated)
        }
        fn protect_tree(&self, root: &Path) -> Result<(), LifecycleError> {
            self.protected.borrow_mut().push(root.to_path_buf());
            Ok(())
        }
        fn verify_tree_acl(&self, _root: &Path) -> Result<(), LifecycleError> {
            if self.acl_ok {
                Ok(())
            } else {
                Err(LifecycleError::platform("unexpected principal BU"))
            }
        }
        fn add_user_path(&self, dir: &Path) -> Result<bool, LifecycleError> {
            let mut path = self.path.borrow_mut();
            if path.iter().any(|entry| entry == dir) {
                return Ok(false);
            }
            path.push(dir.to_path_buf());
            Ok(true)
        }
        fn remove_user_path(&self, dir: &Path) -> Result<bool, LifecycleError> {
            let mut path = self.path.borrow_mut();
            let before = path.len();
            path.retain(|entry| entry != dir);
            Ok(path.len() != before)
        }
        fn node_version(&self, _node: &Path) -> Result<Version, LifecycleError> {
            Version::parse(&format!("{}.0.0", self.node_major))
        }
    }
}
