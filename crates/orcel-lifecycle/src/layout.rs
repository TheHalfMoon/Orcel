//! Per-user install layout under the Orcel state root and its records.

use crate::LifecycleError;
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const CURRENT_SCHEMA: &str = "orcel-current-v1";
pub const INSTALL_SCHEMA: &str = "orcel-install-v1";

/// Paths of the per-user install rooted at the XP-01 state root
/// (`%LOCALAPPDATA%\Orcel` on Windows).
///
/// On Linux and macOS the same root is the XDG or Application Support state
/// root, and only the state paths apply there (`state_dir`, `config_file`,
/// `logs_dir`, the ledgers). The payload paths (`bin_dir`, `versions_dir`,
/// `current.json`, `install.json`) are Windows-only: on other OSes the
/// host platform refuses `install`, `update`, `rollback` and `uninstall`
/// before any of them is created or removed, and `orceld` comes from the
/// package or tarball location instead (`commands::local_orceld`, XP-17).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub root: PathBuf,
}

impl Layout {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The layout for the current user, from the process environment.
    /// Installs never fall back to another location.
    pub fn for_current_user() -> Result<Self, LifecycleError> {
        Self::from_lookup(&|name| std::env::var_os(name))
    }

    /// The layout rooted where XP-01's single resolver,
    /// [`orcel_platform::paths::state_root_from`], puts the state root. It
    /// refuses missing, relative and `.`/`..`-bearing values.
    pub fn from_lookup(lookup: &dyn Fn(&str) -> Option<OsString>) -> Result<Self, LifecycleError> {
        orcel_platform::paths::state_root_from(lookup)
            .map(Self::new)
            .map_err(|error| {
                LifecycleError::prerequisite(format!(
                    "a per-user install root is unavailable: {error}"
                ))
            })
    }

    pub fn bin_dir(&self) -> PathBuf {
        self.root.join("bin")
    }
    pub fn bin_cli(&self) -> PathBuf {
        self.bin_dir().join("orcel.exe")
    }
    pub fn versions_dir(&self) -> PathBuf {
        self.root.join("versions")
    }
    pub fn version_dir(&self, version: &str) -> PathBuf {
        self.versions_dir().join(version)
    }
    pub fn current_file(&self) -> PathBuf {
        self.root.join("current.json")
    }
    pub fn install_file(&self) -> PathBuf {
        self.root.join("install.json")
    }
    pub fn state_dir(&self) -> PathBuf {
        self.root.join("state")
    }
    pub fn logs_dir(&self) -> PathBuf {
        self.root.join("logs")
    }
    pub fn run_dir(&self) -> PathBuf {
        self.root.join("run")
    }
    pub fn supervisor_record(&self) -> PathBuf {
        self.run_dir().join("supervisor.json")
    }
    pub fn stop_result(&self) -> PathBuf {
        self.run_dir().join("stop-result.json")
    }
    pub fn last_exit(&self) -> PathBuf {
        self.run_dir().join("last-exit.json")
    }
    pub fn health_url_file(&self) -> PathBuf {
        self.run_dir().join("tunnel-health.url")
    }
    pub fn config_file(&self) -> PathBuf {
        self.state_dir().join("config.json")
    }
    pub fn secrets_dir(&self) -> PathBuf {
        self.state_dir().join("secrets")
    }
    pub fn runtime_key_file(&self) -> PathBuf {
        self.secrets_dir().join("tunnel-runtime-key")
    }
    pub fn tunnel_log(&self) -> PathBuf {
        self.logs_dir().join("tunnel.log")
    }
    pub fn supervisor_log(&self) -> PathBuf {
        self.logs_dir().join("supervisor.log")
    }

    /// User-owned data that uninstall retains unless purging is requested.
    pub fn retained_data(&self) -> Vec<PathBuf> {
        let mut data = vec![
            self.state_dir(),
            self.logs_dir(),
            self.root.join("audit.jsonl"),
            self.root.join("approval-history.jsonl"),
            // Single-writer lock created beside the approval ledger (#278).
            self.root.join("approval-history.jsonl.lock"),
            self.root.join("trust.jsonl"),
            self.root.join("browser-profile"),
            // SG-000120 RJ-02: the report task journal, its single-writer
            // lock and a compaction rewrite left by a crash.
            self.root.join("report-tasks.jsonl"),
            self.root.join("report-tasks.jsonl.lock"),
            self.root.join("report-tasks.jsonl.rewrite"),
            // SG-000120 RJ-03: the resume fingerprint key.
            self.root.join("report-tasks.key"),
            self.root.join("mutations.jsonl"),
            self.root.join("mutations.jsonl.lock"),
            self.root.join("mutations.jsonl.rewrite"),
        ];
        // Approval ledgers quarantined by `orcel approvals recover` (#278),
        // and a new chain staged by a recovery that was interrupted.
        if let Ok(entries) = std::fs::read_dir(&self.root) {
            let mut quarantined: Vec<PathBuf> = entries
                .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                .filter(|path| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| {
                            name.starts_with("approval-history.jsonl.quarantine-")
                                || name.starts_with("approval-history.jsonl.recovering-")
                        })
                })
                .collect();
            quarantined.sort();
            data.extend(quarantined);
        }
        data
    }

    /// Executable state that uninstall removes.
    pub fn executable_state(&self) -> Vec<PathBuf> {
        vec![
            self.versions_dir(),
            self.bin_dir(),
            self.current_file(),
            self.install_file(),
            self.run_dir(),
        ]
    }

    /// Guards every destructive operation: the target must lie strictly
    /// beneath the install root.
    pub fn ensure_beneath_root(&self, path: &Path) -> Result<(), LifecycleError> {
        if path != self.root && orcel_policy::protected_state::path_within(path, &self.root) {
            Ok(())
        } else {
            Err(LifecycleError::internal(format!(
                "refusing to operate outside the install root: {}",
                path.display()
            )))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentRecord {
    pub schema: String,
    pub version: String,
    pub manifest_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallRecord {
    pub schema: String,
    pub active: String,
    pub previous: Option<String>,
    pub node_path: String,
    pub path_entry_added: bool,
}

impl CurrentRecord {
    /// Checks the schema, the version (which becomes a path component), and
    /// the manifest digest before the record is used.
    pub fn validate(&self) -> Result<(), LifecycleError> {
        if self.schema != CURRENT_SCHEMA {
            return Err(LifecycleError::state(
                "current.json has an unsupported schema",
            ));
        }
        crate::version::Version::parse(&self.version)
            .map_err(|_| LifecycleError::state("current.json names an invalid version"))?;
        if !crate::manifest::is_sha256_hex(&self.manifest_sha256) {
            return Err(LifecycleError::state(
                "current.json has an invalid manifest digest",
            ));
        }
        Ok(())
    }
}

impl InstallRecord {
    /// Checks the schema and every version, which become path components.
    pub fn validate(&self) -> Result<(), LifecycleError> {
        if self.schema != INSTALL_SCHEMA {
            return Err(LifecycleError::state(
                "install.json has an unsupported schema",
            ));
        }
        for version in std::iter::once(&self.active).chain(self.previous.iter()) {
            crate::version::Version::parse(version)
                .map_err(|_| LifecycleError::state("install.json names an invalid version"))?;
        }
        Ok(())
    }
}

/// Reads and validates `current.json`.
pub fn read_current(layout: &Layout) -> Result<Option<CurrentRecord>, LifecycleError> {
    let record: Option<CurrentRecord> = read_json(&layout.current_file())?;
    if let Some(record) = &record {
        record.validate()?;
    }
    Ok(record)
}

/// Reads and validates `install.json`.
pub fn read_install(layout: &Layout) -> Result<Option<InstallRecord>, LifecycleError> {
    let record: Option<InstallRecord> = read_json(&layout.install_file())?;
    if let Some(record) = &record {
        record.validate()?;
    }
    Ok(record)
}

pub fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>, LifecycleError> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|error| {
            LifecycleError::state(format!("{} is corrupt: {error}", path.display()))
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(LifecycleError::io(
            format!("read {}", path.display()),
            error,
        )),
    }
}

/// Writes JSON atomically: a sibling temporary file is written, flushed, and
/// renamed over the destination.
pub fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), LifecycleError> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| LifecycleError::internal(format!("serialize record: {error}")))?;
    write_bytes_atomic(path, &bytes)
}

pub fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<(), LifecycleError> {
    let file_name = path
        .file_name()
        .ok_or_else(|| LifecycleError::internal("atomic write target has no file name"))?;
    let temp = path.with_file_name(format!(
        ".{}.tmp-{}",
        file_name.to_string_lossy(),
        crate::nonce()
    ));
    let result = (|| {
        let mut file = fs::File::create(&temp)
            .map_err(|error| LifecycleError::io(format!("create {}", temp.display()), error))?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| LifecycleError::io(format!("write {}", temp.display()), error))?;
        drop(file);
        fs::rename(&temp, path)
            .map_err(|error| LifecycleError::io(format!("replace {}", path.display()), error))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::temp_dir;

    #[test]
    fn destructive_guard_accepts_only_strict_descendants() {
        let layout = Layout::new(PathBuf::from("/x/Orcel"));
        assert!(layout.ensure_beneath_root(&layout.versions_dir()).is_ok());
        assert!(layout.ensure_beneath_root(&layout.root).is_err());
        assert!(layout.ensure_beneath_root(Path::new("/x")).is_err());
        assert!(layout
            .ensure_beneath_root(Path::new("/x/Orcel-other/bin"))
            .is_err());
    }

    /// #358 item 1: the root comes from XP-01's resolver, so a `..` input
    /// is refused on every OS instead of escaping the per-user directory.
    #[test]
    fn current_user_root_refuses_parent_components() {
        let escaping = if cfg!(windows) {
            r"C:\Users\someone\AppData\Local\..\..\..\Public"
        } else {
            "/home/someone/../shared"
        };
        assert!(Layout::from_lookup(&|_| Some(OsString::from(escaping))).is_err());
        assert!(Layout::from_lookup(&|_| Some(OsString::from("relative"))).is_err());
        assert!(Layout::from_lookup(&|_| None).is_err());
    }

    /// Valid Windows input resolves exactly as the earlier
    /// `LOCALAPPDATA` + `Orcel` resolver did.
    #[cfg(windows)]
    #[test]
    fn current_user_root_on_windows_is_localappdata_orcel() {
        let local = r"C:\Users\someone\AppData\Local";
        let lookup = |name: &str| (name == "LOCALAPPDATA").then(|| OsString::from(local));
        assert_eq!(
            Layout::from_lookup(&lookup).unwrap().root,
            Path::new(local).join("Orcel")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn current_user_root_on_linux_is_the_xdg_state_root() {
        let lookup = |name: &str| (name == "HOME").then(|| OsString::from("/home/someone"));
        assert_eq!(
            Layout::from_lookup(&lookup).unwrap().root,
            Path::new("/home/someone/.local/state/orcel")
        );
    }

    #[test]
    fn retained_and_executable_state_are_disjoint() {
        let layout = Layout::new(PathBuf::from("/x/Orcel"));
        for kept in layout.retained_data() {
            for removed in layout.executable_state() {
                assert!(!orcel_policy::protected_state::paths_overlap(
                    &kept, &removed
                ));
            }
        }
    }

    #[test]
    fn quarantined_ledgers_are_retained_children_only() {
        let root = temp_dir("retained-quarantine").join("Orcel");
        fs::create_dir_all(root.join("approval-history.jsonl.quarantine-nested")).unwrap();
        let kept = root.join("approval-history.jsonl.quarantine-1-abcdef012345");
        fs::write(&kept, b"{}\n").unwrap();
        let staged = root.join("approval-history.jsonl.recovering-1");
        fs::write(&staged, b"{}\n").unwrap();
        fs::write(root.join("unrelated.jsonl.quarantine-1"), b"{}\n").unwrap();
        let layout = Layout::new(&root);
        let retained = layout.retained_data();
        assert!(retained.contains(&kept));
        assert!(retained.contains(&staged));
        assert!(!retained.contains(&root.join("unrelated.jsonl.quarantine-1")));
        for kept in &retained {
            assert_eq!(kept.parent(), Some(root.as_path()));
            layout.ensure_beneath_root(kept).unwrap();
            for removed in layout.executable_state() {
                assert!(!orcel_policy::protected_state::paths_overlap(
                    kept, &removed
                ));
            }
        }
        let _ = fs::remove_dir_all(root.parent().unwrap());
    }

    #[test]
    fn atomic_write_replaces_and_leaves_no_temp_files() {
        let dir = temp_dir("atomic");
        let path = dir.join("current.json");
        let record = CurrentRecord {
            schema: CURRENT_SCHEMA.into(),
            version: "0.1.0".into(),
            manifest_sha256: "0".repeat(64),
        };
        write_json_atomic(&path, &record).unwrap();
        write_json_atomic(&path, &record).unwrap();
        let back: CurrentRecord = read_json(&path).unwrap().unwrap();
        assert_eq!(back, record);
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn corrupt_record_is_reported_not_ignored() {
        let dir = temp_dir("corrupt");
        let path = dir.join("install.json");
        fs::write(&path, b"{not json").unwrap();
        assert!(read_json::<InstallRecord>(&path).is_err());
        assert!(read_json::<InstallRecord>(&dir.join("absent.json"))
            .unwrap()
            .is_none());
        let _ = fs::remove_dir_all(dir);
    }
}
