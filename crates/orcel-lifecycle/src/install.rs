//! Per-user install, uninstall, and install-state inspection.

use crate::layout::{
    write_json_atomic, CurrentRecord, InstallRecord, Layout, CURRENT_SCHEMA, INSTALL_SCHEMA,
};
use crate::manifest::{self, join_relative, Manifest, VerifiedRelease, MANIFEST_FILE};
use crate::platform::{self, Platform, MIN_NODE_MAJOR, MIN_WINDOWS_BUILD};
use crate::{nonce, LifecycleError};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default)]
pub struct InstallOptions {
    pub node: Option<PathBuf>,
    pub add_to_path: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct InstallReport {
    pub version: String,
    pub root: PathBuf,
    pub version_dir: PathBuf,
    pub cli: PathBuf,
    pub node_path: PathBuf,
    pub path_entry_added: bool,
    /// Why there's no Start Menu entry, if `add_to_path` asked for one. Install doesn't fail for it.
    pub start_menu_problem: Option<String>,
    pub start_menu_added: bool,
    pub repaired_existing: bool,
    pub retained_data: Vec<PathBuf>,
}

#[derive(Debug, Clone, Default)]
pub struct UninstallOptions {
    pub purge_data: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct UninstallReport {
    pub removed: Vec<PathBuf>,
    pub retained: Vec<PathBuf>,
    pub purged: Vec<PathBuf>,
    pub path_entry_removed: bool,
    pub start_menu_removed: bool,
    pub relocated_cli: Option<PathBuf>,
    pub residual: Vec<PathBuf>,
}

/// The verified state of an existing install.
#[derive(Debug, Clone, Serialize)]
pub struct InstallState {
    pub root: PathBuf,
    pub active: CurrentRecord,
    pub record: InstallRecord,
    pub manifest: Manifest,
}

pub struct Installer<'a> {
    layout: Layout,
    platform: &'a dyn Platform,
}

impl<'a> Installer<'a> {
    pub fn new(layout: Layout, platform: &'a dyn Platform) -> Self {
        Self { layout, platform }
    }

    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    /// Validates the Windows build and refuses avoidable elevation.
    pub fn check_prerequisites_without_node(&self) -> Result<(), LifecycleError> {
        let build = self.platform.windows_build()?;
        if build < MIN_WINDOWS_BUILD {
            return Err(LifecycleError::prerequisite(format!(
                "Windows build {build} is older than the supported minimum {MIN_WINDOWS_BUILD}"
            )));
        }
        if self.platform.is_avoidably_elevated()? {
            return Err(LifecycleError::prerequisite(
                "run Orcel lifecycle commands from a non-elevated prompt; administrator rights are not required",
            ));
        }
        Ok(())
    }

    /// Validates the platform and returns the verified Node.js runtime path.
    pub fn check_prerequisites(&self, node: Option<&Path>) -> Result<PathBuf, LifecycleError> {
        self.check_prerequisites_without_node()?;
        let node = match node {
            Some(path) => path.to_path_buf(),
            None => platform::find_node_on_path().ok_or_else(|| {
                LifecycleError::prerequisite(format!(
                    "Node.js {MIN_NODE_MAJOR} or later was not found on PATH; install it or pass --node <path>"
                ))
            })?,
        };
        let version = self.platform.node_version(&node)?;
        if version.major < MIN_NODE_MAJOR {
            return Err(LifecycleError::prerequisite(format!(
                "Node.js {version} is older than the required {MIN_NODE_MAJOR}"
            )));
        }
        Ok(node)
    }

    pub fn install(
        &self,
        source: &Path,
        options: &InstallOptions,
    ) -> Result<InstallReport, LifecycleError> {
        let node = self.check_prerequisites(options.node.as_deref())?;
        let release = manifest::verify_release(source)?;
        let version = release.manifest.version.clone();

        self.prepare_root()?;
        let existing: Option<CurrentRecord> = crate::layout::read_current(&self.layout)?;
        let previous_record: Option<InstallRecord> = crate::layout::read_install(&self.layout)?;
        let repaired_existing = match &existing {
            Some(current) if current.version != version => {
                return Err(LifecycleError::conflict(format!(
                    "Orcel {} is already installed; use `orcel update --source <release-dir>` to change versions",
                    current.version
                )));
            }
            Some(_) => true,
            None => false,
        };

        let version_dir = self.stage_version(&release)?;

        write_json_atomic(
            &self.layout.current_file(),
            &CurrentRecord {
                schema: CURRENT_SCHEMA.into(),
                version: version.clone(),
                manifest_sha256: release.manifest_sha256.clone(),
            },
        )?;
        self.replace_cli(&version_dir.join("orcel.exe"))?;

        let already_added = previous_record
            .as_ref()
            .is_some_and(|record| record.path_entry_added);
        let path_entry_added = if options.add_to_path {
            self.platform.add_user_path(&self.layout.bin_dir())? || already_added
        } else {
            already_added
        };
        // A convenience: `orcel app` works without it, so its failure doesn't fail the install.
        let (start_menu_added, start_menu_problem) = if options.add_to_path {
            match self.platform.add_start_menu_entry(&self.layout.bin_cli()) {
                Ok(()) => (true, None),
                Err(error) => (false, Some(error.message)),
            }
        } else {
            (false, None)
        };
        write_json_atomic(
            &self.layout.install_file(),
            &InstallRecord {
                schema: INSTALL_SCHEMA.into(),
                active: version.clone(),
                previous: previous_record.and_then(|record| record.previous),
                node_path: node.to_string_lossy().into_owned(),
                path_entry_added,
            },
        )?;

        self.protect_root()?;
        self.verify()?;
        crate::logs::transcript(
            &self.layout,
            &format!(
                "install {version} {}",
                if repaired_existing {
                    "repaired"
                } else {
                    "installed"
                }
            ),
        );

        Ok(InstallReport {
            version,
            root: self.layout.root.clone(),
            version_dir,
            cli: self.layout.bin_cli(),
            node_path: node,
            path_entry_added,
            start_menu_problem,
            start_menu_added,
            repaired_existing,
            retained_data: self.layout.retained_data(),
        })
    }

    pub(crate) fn prepare_root(&self) -> Result<(), LifecycleError> {
        if let Ok(metadata) = fs::symlink_metadata(&self.layout.root) {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(LifecycleError::state(
                    "the Orcel install root is not a plain directory",
                ));
            }
        }
        fs::create_dir_all(&self.layout.root)
            .map_err(|error| LifecycleError::io("create install root", error))?;
        self.protect_root()?;
        self.platform.verify_tree_acl(&self.layout.root)?;
        for dir in [
            self.layout.versions_dir(),
            self.layout.bin_dir(),
            self.layout.state_dir(),
            self.layout.logs_dir(),
            self.layout.run_dir(),
        ] {
            fs::create_dir_all(&dir)
                .map_err(|error| LifecycleError::io(format!("create {}", dir.display()), error))?;
        }
        Ok(())
    }

    /// Applies the owner-only DACL to the install tree. The tree is walked
    /// first and any link or reparse point fails closed, so the recursive ACL
    /// reset can never be redirected outside the install root.
    pub(crate) fn protect_root(&self) -> Result<(), LifecycleError> {
        reject_links(&self.layout.root)?;
        self.platform.protect_tree(&self.layout.root)
    }

    /// Copies the verified release into a staging directory, re-verifies the
    /// copy, and activates it as `versions\<version>`.
    pub(crate) fn stage_version(
        &self,
        release: &VerifiedRelease,
    ) -> Result<PathBuf, LifecycleError> {
        let version = &release.manifest.version;
        let target = self.layout.version_dir(version);
        let staging = self
            .layout
            .versions_dir()
            .join(format!("{version}.staging-{}", nonce()));
        self.layout.ensure_beneath_root(&staging)?;
        let result = (|| {
            fs::create_dir_all(&staging)
                .map_err(|error| LifecycleError::io("create staging directory", error))?;
            for file in &release.manifest.files {
                let from = join_relative(&release.dir, &file.path);
                let to = join_relative(&staging, &file.path);
                if let Some(parent) = to.parent() {
                    fs::create_dir_all(parent).map_err(|error| {
                        LifecycleError::io(format!("create {}", parent.display()), error)
                    })?;
                }
                fs::copy(&from, &to)
                    .map_err(|error| LifecycleError::io(format!("copy {}", file.path), error))?;
            }
            fs::copy(release.dir.join(MANIFEST_FILE), staging.join(MANIFEST_FILE))
                .map_err(|error| LifecycleError::io("copy manifest", error))?;
            manifest::verify_payload(&staging, &release.manifest)
        })();
        if let Err(error) = result {
            let _ = fs::remove_dir_all(&staging);
            return Err(error);
        }

        if target.exists() {
            if manifest::verify_payload(&target, &release.manifest).is_ok()
                && manifest::sha256_file(&target.join(MANIFEST_FILE))? == release.manifest_sha256
            {
                remove_path(&self.layout, &staging)?;
                return Ok(target);
            }
            let invalid = self
                .layout
                .versions_dir()
                .join(format!("{version}.invalid-{}", nonce()));
            fs::rename(&target, &invalid)
                .map_err(|error| LifecycleError::io("set aside invalid version", error))?;
            remove_path(&self.layout, &invalid)?;
        }
        fs::rename(&staging, &target)
            .map_err(|error| LifecycleError::io("activate staged version", error))?;
        Ok(target)
    }

    /// Replaces `bin\orcel.exe`, renaming a possibly running copy aside first.
    pub(crate) fn replace_cli(&self, source: &Path) -> Result<(), LifecycleError> {
        let bin = self.layout.bin_dir();
        let target = self.layout.bin_cli();
        let incoming = bin.join(format!("orcel.exe.new-{}", nonce()));
        fs::copy(source, &incoming)
            .map_err(|error| LifecycleError::io("copy lifecycle CLI", error))?;
        if target.exists() {
            let aside = bin.join(format!("orcel.exe.old-{}", nonce()));
            fs::rename(&target, &aside)
                .map_err(|error| LifecycleError::io("move previous lifecycle CLI aside", error))?;
        }
        fs::rename(&incoming, &target)
            .map_err(|error| LifecycleError::io("activate lifecycle CLI", error))?;
        if let Ok(entries) = fs::read_dir(&bin) {
            for entry in entries.flatten() {
                if entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("orcel.exe.old-")
                {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
        Ok(())
    }

    /// Verifies the pointer, the active payload, the CLI copy, and the ACLs.
    pub fn verify(&self) -> Result<InstallState, LifecycleError> {
        let active: CurrentRecord = crate::layout::read_current(&self.layout)?
            .ok_or_else(|| LifecycleError::not_installed("Orcel is not installed"))?;
        if active.schema != CURRENT_SCHEMA {
            return Err(LifecycleError::state(
                "current.json has an unsupported schema",
            ));
        }
        let record: InstallRecord = crate::layout::read_install(&self.layout)?
            .ok_or_else(|| LifecycleError::state("install.json is missing"))?;
        if record.schema != INSTALL_SCHEMA || record.active != active.version {
            return Err(LifecycleError::state(
                "install.json does not match the active version pointer",
            ));
        }
        let version_dir = self.layout.version_dir(&active.version);
        let manifest_path = version_dir.join(MANIFEST_FILE);
        let manifest_bytes = fs::read(&manifest_path).map_err(|error| {
            LifecycleError::state(format!("active manifest unreadable: {error}"))
        })?;
        if manifest::sha256_bytes(&manifest_bytes) != active.manifest_sha256 {
            return Err(LifecycleError::state(
                "active manifest does not match the version pointer",
            ));
        }
        let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|error| LifecycleError::state(format!("active manifest corrupt: {error}")))?;
        manifest.validate()?;
        if manifest.version != active.version {
            return Err(LifecycleError::state("active manifest version mismatch"));
        }
        manifest::verify_payload(&version_dir, &manifest)?;
        if manifest::sha256_file(&self.layout.bin_cli())?
            != manifest::sha256_file(&version_dir.join("orcel.exe"))?
        {
            return Err(LifecycleError::state(
                "bin\\orcel.exe does not match the active version",
            ));
        }
        self.platform.verify_tree_acl(&self.layout.root)?;
        Ok(InstallState {
            root: self.layout.root.clone(),
            active,
            record,
            manifest,
        })
    }

    pub fn uninstall(&self, options: &UninstallOptions) -> Result<UninstallReport, LifecycleError> {
        // #369 item 3: the payload layout exists on Windows only. On Linux
        // and macOS the layout root is the live XDG or Application Support
        // state root, so `--purge-data` must never walk it; the platform
        // refuses first, as it does for install, update and rollback.
        self.platform.windows_build()?;
        let root_exists = self.layout.root.is_dir();
        let record: Option<InstallRecord> = if root_exists {
            // Tolerant read: uninstall only consults `path_entry_added` and
            // builds no path from the record, so a malformed record must not
            // strand the user with an install the CLI refuses to remove.
            crate::layout::read_json::<InstallRecord>(&self.layout.install_file()).unwrap_or(None)
        } else {
            None
        };
        let installed = root_exists
            && (self.layout.current_file().exists() || self.layout.install_file().exists());
        if !installed && !options.purge_data {
            return Err(LifecycleError::not_installed("Orcel is not installed"));
        }
        if self.layout.supervisor_record().exists() {
            return Err(LifecycleError::conflict(
                "a Orcel supervisor record exists; stop Orcel before uninstalling",
            ));
        }

        if !options.purge_data {
            crate::logs::transcript(&self.layout, "uninstall started; user data retained");
        }
        let mut report = UninstallReport {
            removed: Vec::new(),
            retained: Vec::new(),
            purged: Vec::new(),
            path_entry_removed: false,
            // Before the CLI below moves. A failure here shouldn't stop an uninstall.
            start_menu_removed: self
                .platform
                .remove_start_menu_entry(&self.layout.bin_cli())
                .unwrap_or(false),
            relocated_cli: None,
            residual: Vec::new(),
        };

        if record
            .as_ref()
            .is_some_and(|record| record.path_entry_added)
        {
            report.path_entry_removed = self.platform.remove_user_path(&self.layout.bin_dir())?;
        }

        if let Ok(exe) = std::env::current_exe() {
            if orcel_policy::protected_state::path_within(&exe, &self.layout.root) {
                let relocated =
                    std::env::temp_dir().join(format!("orcel-uninstalled-{}.exe", nonce()));
                match fs::rename(&exe, &relocated) {
                    Ok(()) => report.relocated_cli = Some(relocated),
                    Err(_) => report.residual.push(exe),
                }
            }
        }

        for path in self.layout.executable_state() {
            if path.exists() {
                match remove_path(&self.layout, &path) {
                    Ok(()) => report.removed.push(path),
                    Err(_) => report.residual.push(path),
                }
            }
        }

        // Last, and only if the rest went: while part of an interrupted migration's copies remain,
        // the marker is what keeps orceld from starting on them.
        let marker = self
            .layout
            .root
            .join(orcel_platform::legacy::MIGRATION_IN_PROGRESS);
        for path in self.layout.retained_data() {
            if !path.exists() {
                continue;
            }
            if options.purge_data && path == marker {
                continue;
            }
            if options.purge_data {
                match remove_path(&self.layout, &path) {
                    Ok(()) => report.purged.push(path),
                    Err(_) => report.residual.push(path),
                }
            } else {
                report.retained.push(path);
            }
        }

        if options.purge_data && marker.exists() {
            if report.residual.is_empty() {
                match remove_path(&self.layout, &marker) {
                    Ok(()) => report.purged.push(marker),
                    Err(_) => report.residual.push(marker),
                }
            } else {
                report.residual.push(marker);
            }
        }

        if options.purge_data && root_exists && report.residual.is_empty() {
            match fs::remove_dir(&self.layout.root) {
                Ok(()) => report.purged.push(self.layout.root.clone()),
                Err(_) => {
                    // Name what's in the way: it isn't Orcel's, so a purge left it.
                    if let Ok(entries) = fs::read_dir(&self.layout.root) {
                        report.residual.extend(
                            entries.filter_map(|entry| entry.ok().map(|entry| entry.path())),
                        );
                    }
                    report.residual.push(self.layout.root.clone());
                }
            }
        }
        Ok(report)
    }
}

fn reject_links(dir: &Path) -> Result<(), LifecycleError> {
    let entries = fs::read_dir(dir)
        .map_err(|error| LifecycleError::io(format!("read {}", dir.display()), error))?;
    for entry in entries {
        let entry =
            entry.map_err(|error| LifecycleError::io(format!("read {}", dir.display()), error))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| LifecycleError::io(format!("inspect {}", path.display()), error))?;
        if metadata.file_type().is_symlink() || manifest::is_reparse_point(&metadata) {
            return Err(LifecycleError::state(format!(
                "the Orcel install tree contains a link or reparse point and will not be modified: {}",
                path.display()
            )));
        }
        if metadata.is_dir() {
            reject_links(&path)?;
        }
    }
    Ok(())
}

fn remove_path(layout: &Layout, path: &Path) -> Result<(), LifecycleError> {
    layout.ensure_beneath_root(path)?;
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(LifecycleError::io(
                format!("inspect {}", path.display()),
                error,
            ))
        }
    };
    let result = if metadata.is_dir() && !metadata.file_type().is_symlink() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    };
    result.map_err(|error| LifecycleError::io(format!("remove {}", path.display()), error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{release_dir, temp_dir, FakePlatform};

    fn options() -> InstallOptions {
        InstallOptions {
            node: Some(PathBuf::from("/fake/node")),
            add_to_path: true,
        }
    }

    #[test]
    fn install_verifies_stages_and_records_state() {
        let platform = FakePlatform::default();
        let root = temp_dir("install-root").join("Orcel");
        let source = release_dir("0.2.0");
        let installer = Installer::new(Layout::new(&root), &platform);
        let report = installer.install(&source, &options()).unwrap();
        assert_eq!(report.version, "0.2.0");
        assert!(report.path_entry_added);
        assert!(!report.repaired_existing);
        let state = installer.verify().unwrap();
        assert_eq!(state.active.version, "0.2.0");
        assert!(root.join("bin").join("orcel.exe").is_file());
        assert!(platform.protected_roots().contains(&root));
        let leftovers = fs::read_dir(root.join("versions"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(leftovers, vec!["0.2.0".to_string()]);
    }

    #[test]
    fn tampered_release_installs_nothing() {
        let platform = FakePlatform::default();
        let root = temp_dir("install-tamper").join("Orcel");
        let source = release_dir("0.2.0");
        fs::write(source.join("orcel.exe"), b"evil").unwrap();
        let installer = Installer::new(Layout::new(&root), &platform);
        assert!(installer.install(&source, &options()).is_err());
        assert!(!root.join("current.json").exists());
        assert!(!root.join("versions").join("0.2.0").exists());
    }

    #[test]
    fn elevated_old_windows_and_old_node_fail_closed() {
        let root = temp_dir("install-prereq").join("Orcel");
        let source = release_dir("0.2.0");
        for platform in [
            FakePlatform {
                elevated: true,
                ..FakePlatform::default()
            },
            FakePlatform {
                build: 17_134,
                ..FakePlatform::default()
            },
            FakePlatform {
                node_major: 18,
                ..FakePlatform::default()
            },
        ] {
            let installer = Installer::new(Layout::new(&root), &platform);
            let error = installer.install(&source, &options()).unwrap_err();
            assert_eq!(
                error.kind,
                crate::ErrorKind::Prerequisite,
                "{}",
                error.message
            );
            assert!(!root.exists());
        }
    }

    #[test]
    fn acl_verification_failure_aborts_install() {
        let platform = FakePlatform {
            acl_ok: false,
            ..FakePlatform::default()
        };
        let root = temp_dir("install-acl").join("Orcel");
        let installer = Installer::new(Layout::new(&root), &platform);
        assert!(installer
            .install(&release_dir("0.2.0"), &options())
            .is_err());
        assert!(!root.join("current.json").exists());
    }

    #[test]
    fn same_version_reinstall_repairs_and_other_version_is_refused() {
        let platform = FakePlatform::default();
        let root = temp_dir("install-repair").join("Orcel");
        let installer = Installer::new(Layout::new(&root), &platform);
        installer
            .install(&release_dir("0.2.0"), &options())
            .unwrap();
        fs::write(root.join("versions").join("0.2.0").join("orceld.exe"), b"x").unwrap();
        assert!(installer.verify().is_err());
        let report = installer
            .install(&release_dir("0.2.0"), &options())
            .unwrap();
        assert!(report.repaired_existing);
        installer.verify().unwrap();
        let error = installer
            .install(&release_dir("0.3.0"), &options())
            .unwrap_err();
        assert_eq!(error.kind, crate::ErrorKind::Conflict);
    }

    #[test]
    fn uninstall_retains_user_data_by_default() {
        let platform = FakePlatform::default();
        let root = temp_dir("uninstall").join("Orcel");
        let installer = Installer::new(Layout::new(&root), &platform);
        installer
            .install(&release_dir("0.2.0"), &options())
            .unwrap();
        fs::write(root.join("state").join("config.json"), b"{}").unwrap();
        fs::write(root.join("audit.jsonl"), b"{}\n").unwrap();
        fs::write(root.join("trust.jsonl"), b"{}\n").unwrap();

        let report = installer.uninstall(&UninstallOptions::default()).unwrap();
        assert!(report.path_entry_removed);
        assert!(!root.join("versions").exists());
        assert!(!root.join("bin").exists());
        assert!(!root.join("current.json").exists());
        assert!(root.join("state").join("config.json").is_file());
        assert!(root.join("audit.jsonl").is_file());
        assert!(root.join("trust.jsonl").is_file());
        assert!(report.retained.contains(&root.join("state")));
        assert!(report.purged.is_empty());
        assert_eq!(
            installer
                .uninstall(&UninstallOptions::default())
                .unwrap_err()
                .kind,
            crate::ErrorKind::NotInstalled
        );
    }

    #[test]
    fn purge_removes_data_only_when_requested() {
        let platform = FakePlatform::default();
        let root = temp_dir("purge").join("Orcel");
        let installer = Installer::new(Layout::new(&root), &platform);
        installer
            .install(&release_dir("0.2.0"), &options())
            .unwrap();
        fs::write(root.join("approval-history.jsonl"), b"{}\n").unwrap();
        fs::write(root.join("approval-history.jsonl.lock"), b"").unwrap();
        let quarantined = root.join("approval-history.jsonl.quarantine-1-abcdef012345");
        fs::write(&quarantined, b"{}\n").unwrap();
        let report = installer
            .uninstall(&UninstallOptions { purge_data: true })
            .unwrap();
        assert!(report.residual.is_empty(), "{:?}", report.residual);
        assert!(!root.exists());
        assert!(report.purged.contains(&root.join("approval-history.jsonl")));
        assert!(report
            .purged
            .contains(&root.join("approval-history.jsonl.lock")));
        assert!(report.purged.contains(&quarantined));
    }

    /// Every store Orcel keeps at the root: what uninstall says it kept, and what a purge removes.
    #[test]
    fn every_store_is_retained_and_then_purged() {
        let platform = FakePlatform::default();
        let root = temp_dir("purge-all").join("Orcel");
        let installer = Installer::new(Layout::new(&root), &platform);
        installer
            .install(&release_dir("0.2.0"), &options())
            .unwrap();
        let stores = [
            "secrets/service.name.dpapi",
            "state/secrets/tunnel-runtime-key",
            "state/authority/authority.key",
            "state/device/device_key.json",
            "state/remote/uplink.json",
            "state/search/usage.json",
            "state/legacy-state-decision.txt",
            "executable_registry.json",
            "remote_leases.json",
            "audit.jsonl",
            "trust.jsonl",
            "report-tasks.jsonl",
            "report-tasks.key",
            "mutations.jsonl",
            "browser-profile/live/pages.jsonl",
            "contained-runs/old/left",
            "document-parse/old/left",
            "sg-000012-qualification/old/sentinel",
            "legacy-migration-in-progress",
            "legacy-import-1/state/secrets/key",
            ".report-tasks.key.tmp-1-2",
            ".remote_leases.json.tmp-1-2",
            ".executable_registry.json.tmp-1-2",
            ".current.json.tmp-1-2",
            ".install.json.tmp-1-2",
            "report-tasks.jsonl.lock",
            "report-tasks.jsonl.rewrite",
            "mutations.jsonl.lock",
            "mutations.jsonl.rewrite",
            "approval-history.jsonl",
            "approval-history.jsonl.lock",
            "approval-history.jsonl.quarantine-1-abc",
            "approval-history.jsonl.recovering-1",
            "logs/supervisor.log",
        ];
        for store in stores {
            let path = root.join(store);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, b"x").unwrap();
        }
        let retained = Layout::new(&root).retained_data();
        for store in stores {
            let path = root.join(store);
            assert!(
                retained.iter().any(|kept| path.starts_with(kept)),
                "{store} isn't reported as kept"
            );
        }
        let report = installer
            .uninstall(&UninstallOptions { purge_data: true })
            .unwrap();
        assert!(report.residual.is_empty(), "{:?}", report.residual);
        assert!(!root.exists());
    }

    /// A purge removes what's known to be Orcel's. Anything else stays, and is reported.
    #[test]
    fn a_purge_leaves_and_reports_what_it_doesnt_recognise() {
        let platform = FakePlatform::default();
        let root = temp_dir("purge-unknown").join("Orcel");
        let installer = Installer::new(Layout::new(&root), &platform);
        installer
            .install(&release_dir("0.2.0"), &options())
            .unwrap();
        fs::write(root.join("somebody-elses.txt"), b"keep").unwrap();
        let report = installer
            .uninstall(&UninstallOptions { purge_data: true })
            .unwrap();
        assert!(report.residual.contains(&root), "{:?}", report.residual);
        assert!(
            report.residual.contains(&root.join("somebody-elses.txt")),
            "{:?}",
            report.residual
        );
        assert_eq!(fs::read(root.join("somebody-elses.txt")).unwrap(), b"keep");
    }

    /// A similar name isn't migration's staging.
    #[test]
    fn a_purge_only_takes_real_staging_folders() {
        let platform = FakePlatform::default();
        let root = temp_dir("purge-similar").join("Orcel");
        let installer = Installer::new(Layout::new(&root), &platform);
        installer
            .install(&release_dir("0.2.0"), &options())
            .unwrap();
        for name in [
            "legacy-import-my-notes.txt",
            "legacy-import-",
            "legacy-importer",
        ] {
            fs::write(root.join(name), b"keep").unwrap();
        }
        fs::create_dir_all(root.join("legacy-import-7")).unwrap();
        let report = installer
            .uninstall(&UninstallOptions { purge_data: true })
            .unwrap();
        for name in [
            "legacy-import-my-notes.txt",
            "legacy-import-",
            "legacy-importer",
        ] {
            assert_eq!(fs::read(root.join(name)).unwrap(), b"keep", "{name}");
        }
        assert!(!root.join("legacy-import-7").exists());
        assert!(report.residual.contains(&root));
    }

    /// While something couldn't be removed, the marker stays and keeps the gate closed.
    #[test]
    fn a_partial_purge_keeps_the_migration_marker() {
        let platform = FakePlatform::default();
        let root = temp_dir("purge-partial").join("Orcel");
        let installer = Installer::new(Layout::new(&root), &platform);
        installer
            .install(&release_dir("0.2.0"), &options())
            .unwrap();
        let marker = root.join("legacy-migration-in-progress");
        fs::write(&marker, b"").unwrap();
        // A store that can't be removed: a non-empty read-only folder on Unix, an open file on
        // Windows.
        fs::write(root.join("trust.jsonl"), b"x").unwrap();
        #[cfg(windows)]
        let _held = {
            use std::os::windows::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .read(true)
                .share_mode(0)
                .open(root.join("trust.jsonl"))
                .unwrap()
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let held = root.join("browser-profile");
            fs::create_dir_all(&held).unwrap();
            fs::write(held.join("file"), b"x").unwrap();
            fs::set_permissions(&held, fs::Permissions::from_mode(0o500)).unwrap();
        }
        let report = installer
            .uninstall(&UninstallOptions { purge_data: true })
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                root.join("browser-profile"),
                fs::Permissions::from_mode(0o700),
            )
            .unwrap();
        }
        assert!(!report.residual.is_empty());
        assert!(marker.exists());
        assert!(report.residual.contains(&marker));
    }

    /// Without `--purge-data`, nothing goes, and everything is reported.
    #[test]
    fn a_plain_uninstall_keeps_and_reports_every_store() {
        let platform = FakePlatform::default();
        let root = temp_dir("uninstall-plain").join("Orcel");
        let installer = Installer::new(Layout::new(&root), &platform);
        installer
            .install(&release_dir("0.2.0"), &options())
            .unwrap();
        let stores = [
            "secrets/service.name.dpapi",
            "executable_registry.json",
            "remote_leases.json",
            "contained-runs/old/left",
            "legacy-migration-in-progress",
            "legacy-import-1/key",
        ];
        for store in stores {
            let path = root.join(store);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, b"x").unwrap();
        }
        let report = installer
            .uninstall(&UninstallOptions { purge_data: false })
            .unwrap();
        for store in stores {
            let path = root.join(store);
            assert_eq!(fs::read(&path).unwrap(), b"x", "{store}");
            assert!(
                report.retained.iter().any(|kept| path.starts_with(kept)),
                "{store} isn't reported as kept"
            );
        }
    }

    #[test]
    fn the_start_menu_entry_follows_install_and_uninstall() {
        let platform = FakePlatform::default();
        let root = temp_dir("start-menu").join("Orcel");
        let layout = Layout::new(&root);
        let installer = Installer::new(layout.clone(), &platform);
        let report = installer
            .install(&release_dir("0.2.0"), &options())
            .unwrap();
        assert!(report.start_menu_added);
        assert_eq!(*platform.start_menu.borrow(), Some(layout.bin_cli()));
        let report = installer.uninstall(&UninstallOptions::default()).unwrap();
        assert!(report.start_menu_removed);
        assert_eq!(*platform.start_menu.borrow(), None);
    }

    #[test]
    fn a_start_menu_failure_doesnt_fail_the_install() {
        let platform = FakePlatform {
            start_menu_fails: true,
            ..FakePlatform::default()
        };
        let root = temp_dir("start-menu-fails").join("Orcel");
        let installer = Installer::new(Layout::new(&root), &platform);
        let report = installer
            .install(&release_dir("0.2.0"), &options())
            .unwrap();
        assert!(!report.start_menu_added);
        assert!(report.start_menu_problem.is_some());
    }

    #[test]
    fn no_path_leaves_the_start_menu_alone() {
        let platform = FakePlatform::default();
        let root = temp_dir("start-menu-none").join("Orcel");
        let installer = Installer::new(Layout::new(&root), &platform);
        let report = installer
            .install(
                &release_dir("0.2.0"),
                &InstallOptions {
                    add_to_path: false,
                    ..options()
                },
            )
            .unwrap();
        assert!(!report.start_menu_added);
        assert_eq!(*platform.start_menu.borrow(), None);
    }

    #[test]
    fn running_supervisor_blocks_uninstall() {
        let platform = FakePlatform::default();
        let root = temp_dir("uninstall-running").join("Orcel");
        let installer = Installer::new(Layout::new(&root), &platform);
        installer
            .install(&release_dir("0.2.0"), &options())
            .unwrap();
        fs::write(root.join("run").join("supervisor.json"), b"{}").unwrap();
        let error = installer
            .uninstall(&UninstallOptions::default())
            .unwrap_err();
        assert_eq!(error.kind, crate::ErrorKind::Conflict);
        assert!(root.join("versions").join("0.2.0").is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn link_inside_install_tree_blocks_acl_reset() {
        let platform = FakePlatform::default();
        let base = temp_dir("install-inner-link");
        let root = base.join("Orcel");
        let outside = base.join("outside");
        fs::create_dir_all(root.join("state")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("state").join("escape")).unwrap();
        let installer = Installer::new(Layout::new(&root), &platform);
        let error = installer
            .install(&release_dir("0.2.0"), &options())
            .unwrap_err();
        assert!(error.message.contains("reparse point"), "{}", error.message);
        assert!(platform.protected_roots().is_empty());
    }

    #[test]
    fn install_root_must_not_be_a_link() {
        #[cfg(unix)]
        {
            let platform = FakePlatform::default();
            let base = temp_dir("install-link");
            let real = base.join("real");
            fs::create_dir_all(&real).unwrap();
            std::os::unix::fs::symlink(&real, base.join("Orcel")).unwrap();
            let installer = Installer::new(Layout::new(base.join("Orcel")), &platform);
            assert!(installer
                .install(&release_dir("0.2.0"), &options())
                .is_err());
        }
    }
}
