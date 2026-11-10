//! Explicit, offline update and rollback with automatic recovery.
//!
//! Releases are discovered by the user (GitHub Releases) and applied from a
//! local release directory; Orcel performs no network update check. An
//! update verifies the candidate exactly like an install, refuses downgrades
//! unless explicitly allowed, checks configuration-schema compatibility,
//! stops a running instance with verified termination, activates the new
//! version atomically, and then asks the new version's own CLI to verify the
//! installation. If that fails, the previous version is restored and the
//! failure is recorded. Configuration, secrets, and history are never
//! modified by update or rollback.

use crate::config::CONFIG_SCHEMA_VERSION;
use crate::install::{Installer, StartMenuChange};
use crate::layout::{
    read_json, write_json_atomic, CurrentRecord, InstallRecord, Layout, CURRENT_SCHEMA,
    INSTALL_SCHEMA,
};
use crate::lifecycle::{self, RunState};
use crate::manifest::{self, Manifest, MANIFEST_FILE};
use crate::platform::Platform;
use crate::version::Version;
use crate::LifecycleError;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const UPDATE_SCHEMA: &str = "orcel-update-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateState {
    Pending,
    Failed,
}

/// `state\update.json`: present while an update is in flight (pending) or
/// after an update failed and was rolled back (failed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateMarker {
    pub schema: String,
    pub state: UpdateState,
    pub from: String,
    pub to: String,
    pub reason: Option<String>,
    pub at_ms: u64,
}

#[derive(Debug, Clone, Default)]
pub struct UpdateOptions {
    pub check_only: bool,
    pub allow_downgrade: bool,
    pub reinstall: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateOutcome {
    /// `--check`: nothing changed.
    Checked,
    AlreadyCurrent,
    Updated,
}

#[derive(Debug, Clone, Serialize)]
pub struct UpdateReport {
    pub outcome: UpdateOutcome,
    pub from: String,
    pub to: String,
    pub direction: String,
    pub restarted: bool,
    pub pruned: Vec<String>,
    /// Only when a version was activated.
    pub start_menu: Option<StartMenuChange>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RollbackReport {
    pub from: String,
    pub to: String,
    pub restarted: bool,
    pub start_menu: StartMenuChange,
}

pub fn update_marker_path(layout: &Layout) -> std::path::PathBuf {
    orcel_platform::stores::UPDATE_MARKER.path(&layout.root)
}

/// Reads and validates `state\update.json`; malformed markers are errors.
pub fn read_marker(layout: &Layout) -> Result<Option<UpdateMarker>, LifecycleError> {
    let marker: Option<UpdateMarker> = read_json(&update_marker_path(layout))?;
    if let Some(marker) = &marker {
        if marker.schema != UPDATE_SCHEMA
            || Version::parse(&marker.from).is_err()
            || Version::parse(&marker.to).is_err()
        {
            return Err(LifecycleError::state(format!(
                "{} is malformed; inspect and delete it, then run `orcel doctor` (or reinstall)",
                update_marker_path(layout).display()
            )));
        }
    }
    Ok(marker)
}

fn write_marker(
    layout: &Layout,
    state: UpdateState,
    from: &str,
    to: &str,
    reason: Option<String>,
) -> Result<(), LifecycleError> {
    write_json_atomic(
        &update_marker_path(layout),
        &UpdateMarker {
            schema: UPDATE_SCHEMA.into(),
            state,
            from: from.into(),
            to: to.into(),
            reason,
            at_ms: lifecycle::now_ms(),
        },
    )
}

/// Whether the candidate supports the configuration schema currently in use.
pub fn compatible(manifest: &Manifest, config_schema: u32) -> bool {
    manifest.config_schema.min <= config_schema && config_schema <= manifest.config_schema.max
}

fn current_config_schema(layout: &Layout) -> Result<u32, LifecycleError> {
    #[derive(Deserialize)]
    struct SchemaOnly {
        config_schema: u32,
    }
    Ok(read_json::<SchemaOnly>(&layout.config_file())?
        .map(|config| config.config_schema)
        .unwrap_or(CONFIG_SCHEMA_VERSION))
}

/// Runs the new version's own CLI integrity check.
fn self_check(cli: &Path) -> Result<(), String> {
    let mut child = Command::new(cli)
        .args(["self-check", "--json"])
        .env_clear()
        .envs(orcel_tunnel::sanitized_env(&crate::ipc::host_environment()))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("the new version's CLI could not run: {error}"))?;
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(status)) => {
                return Err(format!("the new version's self-check failed ({status})"))
            }
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("the new version's self-check did not finish".into());
            }
        }
    }
}

fn stop_if_running(layout: &Layout) -> Result<bool, LifecycleError> {
    if !layout.supervisor_record().exists() {
        return Ok(false);
    }
    let running = lifecycle::status(layout)?.supervisor_pid.is_some();
    lifecycle::stop(layout, Duration::from_secs(20)).map_err(|error| {
        LifecycleError::conflict(format!(
            "Orcel could not be stopped, so nothing was changed: {}",
            error.message
        ))
    })?;
    Ok(running)
}

fn restart(layout: &Layout, platform: &dyn Platform) -> Result<bool, LifecycleError> {
    let status = lifecycle::start(layout, platform, Duration::from_secs(20))?;
    Ok(status.state != RunState::NotRunning)
}

/// Removes version directories other than `keep`, plus staging leftovers.
fn prune(layout: &Layout, keep: &[&str]) -> Vec<String> {
    let mut pruned = Vec::new();
    let Ok(entries) = std::fs::read_dir(layout.versions_dir()) else {
        return pruned;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if keep.iter().any(|kept| kept == &name) {
            continue;
        }
        let path = entry.path();
        if layout.ensure_beneath_root(&path).is_ok() && std::fs::remove_dir_all(&path).is_ok() {
            pruned.push(name);
        }
    }
    pruned
}

pub struct Updater<'a> {
    layout: Layout,
    platform: &'a dyn Platform,
}

impl<'a> Updater<'a> {
    pub fn new(layout: Layout, platform: &'a dyn Platform) -> Self {
        Self { layout, platform }
    }

    fn installer(&self) -> Installer<'a> {
        Installer::new(self.layout.clone(), self.platform)
    }

    pub fn update(
        &self,
        source: &Path,
        options: &UpdateOptions,
    ) -> Result<UpdateReport, LifecycleError> {
        let installer = self.installer();
        installer.check_prerequisites_without_node()?;
        self.resolve_pending_for_update()?;
        let state = installer.verify()?;
        let release = manifest::verify_release(source)?;
        let from = state.active.version.clone();
        let to = release.manifest.version.clone();
        let direction = match Version::parse(&to)?.cmp(&Version::parse(&from)?) {
            Ordering::Greater => "upgrade",
            Ordering::Equal => "same",
            Ordering::Less => "downgrade",
        };
        if direction == "downgrade" && !options.allow_downgrade {
            return Err(LifecycleError::conflict(format!(
                "{to} is older than the installed {from}; pass --allow-downgrade to install an older version deliberately"
            )));
        }
        let config_schema = current_config_schema(&self.layout)?;
        if !compatible(&release.manifest, config_schema) {
            return Err(LifecycleError::conflict(format!(
                "Orcel {to} supports configuration schema {}-{} but this configuration uses schema {config_schema}; nothing was changed",
                release.manifest.config_schema.min, release.manifest.config_schema.max
            )));
        }
        let report = |outcome, restarted, pruned, start_menu| UpdateReport {
            outcome,
            from: from.clone(),
            to: to.clone(),
            direction: direction.into(),
            restarted,
            pruned,
            start_menu,
        };
        if options.check_only {
            return Ok(report(UpdateOutcome::Checked, false, Vec::new(), None));
        }
        if direction == "same" && !options.reinstall {
            // Also where an interrupted update was just completed, which didn't reconcile.
            let start_menu = installer.reconcile_start_menu(
                &self.layout.version_dir(&from),
                state.record.path_entry_added,
            );
            return Ok(report(
                UpdateOutcome::AlreadyCurrent,
                false,
                Vec::new(),
                Some(start_menu),
            ));
        }

        let was_running = stop_if_running(&self.layout)?;
        // Any failure before activation leaves the original version active;
        // restart it if it was running.
        let prepared = installer
            .prepare_root()
            .and_then(|()| installer.stage_version(&release))
            .and_then(|dir| {
                write_marker(&self.layout, UpdateState::Pending, &from, &to, None).map(|()| dir)
            });
        let version_dir = match prepared {
            Ok(dir) => dir,
            Err(error) => {
                let restarted =
                    was_running && restart(&self.layout, self.platform).unwrap_or(false);
                return Err(LifecycleError::new(
                    error.kind,
                    format!(
                        "{}; nothing was activated{}",
                        error.message,
                        if restarted {
                            " and Orcel was restarted"
                        } else {
                            ""
                        }
                    ),
                ));
            }
        };
        let previous_current = state.active.clone();
        let previous_record = state.record.clone();
        let activate = || -> Result<(), LifecycleError> {
            write_json_atomic(
                &self.layout.current_file(),
                &CurrentRecord {
                    schema: CURRENT_SCHEMA.into(),
                    version: to.clone(),
                    manifest_sha256: release.manifest_sha256.clone(),
                },
            )?;
            installer.replace_cli(&version_dir.join("orcel.exe"))?;
            write_json_atomic(
                &self.layout.install_file(),
                &InstallRecord {
                    schema: INSTALL_SCHEMA.into(),
                    active: to.clone(),
                    previous: if direction == "same" {
                        previous_record.previous.clone()
                    } else {
                        Some(from.clone())
                    },
                    node_path: previous_record.node_path.clone(),
                    path_entry_added: previous_record.path_entry_added,
                },
            )?;
            installer.protect_root()?;
            installer.verify()?;
            self_check(&version_dir.join("orcel.exe")).map_err(LifecycleError::state)
        };
        if let Err(error) = activate() {
            let restored = self.restore(&previous_current, &previous_record);
            let reason = error.message.clone();
            let _ = write_marker(
                &self.layout,
                UpdateState::Failed,
                &from,
                &to,
                Some(reason.clone()),
            );
            if direction != "same" {
                let _ = std::fs::remove_dir_all(&version_dir);
            }
            crate::logs::transcript(
                &self.layout,
                &format!("update {from} -> {to} failed and was rolled back: {reason}"),
            );
            let restarted = was_running && restart(&self.layout, self.platform).unwrap_or(false);
            return Err(match restored {
                Ok(()) => LifecycleError::state(format!(
                    "the update to {to} failed and Orcel {from} was restored{}: {reason}",
                    if restarted { " and restarted" } else { "" }
                )),
                Err(restore) => LifecycleError::state(format!(
                    "the update to {to} failed ({reason}) and restoring {from} also failed: {}; \
                     run `orcel doctor`, which names the version to repair with",
                    restore.message
                )),
            });
        }
        let _ = std::fs::remove_file(update_marker_path(&self.layout));
        let keep_previous = if direction == "same" {
            previous_record.previous.clone()
        } else {
            Some(from.clone())
        };
        let mut keep = vec![to.as_str()];
        if let Some(previous) = keep_previous.as_deref() {
            keep.push(previous);
        }
        let pruned = prune(&self.layout, &keep);
        let start_menu =
            installer.reconcile_start_menu(&version_dir, previous_record.path_entry_added);
        crate::logs::transcript(
            &self.layout,
            &format!("update {from} -> {to} ({direction}) succeeded"),
        );
        let restarted = was_running && restart(&self.layout, self.platform)?;
        Ok(report(
            UpdateOutcome::Updated,
            restarted,
            pruned,
            Some(start_menu),
        ))
    }

    fn restore(
        &self,
        current: &CurrentRecord,
        record: &InstallRecord,
    ) -> Result<(), LifecycleError> {
        let installer = self.installer();
        write_json_atomic(&self.layout.current_file(), current)?;
        installer.replace_cli(&self.layout.version_dir(&current.version).join("orcel.exe"))?;
        write_json_atomic(&self.layout.install_file(), record)?;
        installer.verify().map(|_| ())
    }

    /// Reads a retained version's manifest and verifies its payload.
    fn verified_version(&self, version: &str) -> Result<(Manifest, Vec<u8>), LifecycleError> {
        let dir = self.layout.version_dir(version);
        let bytes = std::fs::read(dir.join(MANIFEST_FILE)).map_err(|error| {
            LifecycleError::state(format!("version {version} is unavailable: {error}"))
        })?;
        let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|error| {
            LifecycleError::state(format!("manifest of {version} is corrupt: {error}"))
        })?;
        manifest.validate()?;
        if manifest.version != version {
            return Err(LifecycleError::state(format!(
                "manifest version mismatch for {version}"
            )));
        }
        manifest::verify_payload(&dir, &manifest)?;
        Ok((manifest, bytes))
    }

    /// Before a new update: an interrupted update whose target is active,
    /// verified, and passes its own self-check is completed; any other
    /// pending state must be resolved with `orcel rollback`.
    fn resolve_pending_for_update(&self) -> Result<(), LifecycleError> {
        let Some(marker) = read_marker(&self.layout)? else {
            return Ok(());
        };
        if marker.state != UpdateState::Pending {
            return Ok(());
        }
        let completed = self
            .installer()
            .verify()
            .ok()
            .filter(|state| state.active.version == marker.to);
        if completed.is_some()
            && self_check(&self.layout.version_dir(&marker.to).join("orcel.exe")).is_ok()
        {
            let _ = std::fs::remove_file(update_marker_path(&self.layout));
            crate::logs::transcript(
                &self.layout,
                &format!(
                    "interrupted update {} -> {} completed after self-check",
                    marker.from, marker.to
                ),
            );
            return Ok(());
        }
        Err(LifecycleError::conflict(format!(
            "an interrupted update from {} to {} was not completed; run `orcel rollback` to restore {}",
            marker.from, marker.to, marker.from
        )))
    }

    /// Recovers from an interrupted update: restores the marker's `from`
    /// version even if the pointer and install record disagree.
    fn recover_pending(&self, marker: &UpdateMarker) -> Result<RollbackReport, LifecycleError> {
        let installer = self.installer();
        // Refuse links and reparse points anywhere in the install tree before
        // reading or copying from a retained version directory.
        installer.protect_root()?;
        let (manifest, bytes) = self.verified_version(&marker.from)?;
        if !compatible(&manifest, current_config_schema(&self.layout)?) {
            return Err(LifecycleError::conflict(format!(
                "Orcel {} does not support the current configuration schema; nothing was changed",
                marker.from
            )));
        }
        let record: Option<InstallRecord> = read_json(&self.layout.install_file()).unwrap_or(None);
        let record = record.ok_or_else(|| {
            LifecycleError::state(
                "install.json is unreadable; reinstall from the release directory",
            )
        })?;
        let candidate_ok = self.verified_version(&marker.to).is_ok();
        write_json_atomic(
            &self.layout.current_file(),
            &CurrentRecord {
                schema: CURRENT_SCHEMA.into(),
                version: marker.from.clone(),
                manifest_sha256: manifest::sha256_bytes(&bytes),
            },
        )?;
        installer.replace_cli(&self.layout.version_dir(&marker.from).join("orcel.exe"))?;
        write_json_atomic(
            &self.layout.install_file(),
            &InstallRecord {
                schema: INSTALL_SCHEMA.into(),
                active: marker.from.clone(),
                // Keep an existing rollback target when the candidate is invalid.
                previous: if candidate_ok {
                    Some(marker.to.clone())
                } else {
                    record.previous.clone()
                },
                node_path: record.node_path,
                path_entry_added: record.path_entry_added,
            },
        )?;
        if !candidate_ok && marker.to != marker.from {
            let _ = std::fs::remove_dir_all(self.layout.version_dir(&marker.to));
        }
        installer.protect_root()?;
        installer.verify()?;
        let _ = std::fs::remove_file(update_marker_path(&self.layout));
        let start_menu = installer.reconcile_start_menu(
            &self.layout.version_dir(&marker.from),
            record.path_entry_added,
        );
        crate::logs::transcript(
            &self.layout,
            &format!(
                "interrupted update {} -> {} rolled back",
                marker.from, marker.to
            ),
        );
        Ok(RollbackReport {
            from: marker.to.clone(),
            to: marker.from.clone(),
            restarted: false,
            start_menu,
        })
    }

    /// Activates the retained previous version, or recovers an interrupted
    /// update when a pending marker exists.
    pub fn rollback(&self) -> Result<RollbackReport, LifecycleError> {
        let installer = self.installer();
        installer.check_prerequisites_without_node()?;
        if !self.layout.root.is_dir() {
            return Err(LifecycleError::not_installed("Orcel is not installed"));
        }
        if let Some(marker) = read_marker(&self.layout)? {
            if marker.state == UpdateState::Pending {
                return self.recover_pending(&marker);
            }
        }
        installer.protect_root()?;
        let current: CurrentRecord = crate::layout::read_current(&self.layout)?
            .ok_or_else(|| LifecycleError::not_installed("Orcel is not installed"))?;
        let record: InstallRecord = crate::layout::read_install(&self.layout)?
            .ok_or_else(|| LifecycleError::state("install.json is missing"))?;
        let previous = record.previous.clone().ok_or_else(|| {
            LifecycleError::conflict("no previous version is retained for rollback")
        })?;
        let previous_dir = self.layout.version_dir(&previous);
        let manifest_bytes = std::fs::read(previous_dir.join(MANIFEST_FILE)).map_err(|error| {
            LifecycleError::state(format!(
                "previous version {previous} is unavailable: {error}"
            ))
        })?;
        let manifest: Manifest = serde_json::from_slice(&manifest_bytes).map_err(|error| {
            LifecycleError::state(format!("previous manifest corrupt: {error}"))
        })?;
        manifest.validate()?;
        if manifest.version != previous {
            return Err(LifecycleError::state("previous manifest version mismatch"));
        }
        manifest::verify_payload(&previous_dir, &manifest)?;
        if !compatible(&manifest, current_config_schema(&self.layout)?) {
            return Err(LifecycleError::conflict(format!(
                "Orcel {previous} does not support the current configuration schema; nothing was changed"
            )));
        }
        // A saved approval preview choice is a field that versions before it refuse to load,
        // which would leave the rolled-back Orcel unable to start. Clearing it first is the
        // person's choice, since it shows content previews again.
        if crate::config::Config::load(&self.layout)?
            .approval_previews
            .is_some()
        {
            return Err(LifecycleError::conflict(format!(
                "Orcel {previous} may not read the saved approval preview choice; nothing was changed. \
                 Run `orcel approvals previews content` to clear it, then roll back. After that, \
                 prompts show content previews, except that a version which reads \
                 ORCEL_APPROVAL_PREVIEWS shows sizes only for CLI and `orcel mcp stdio` sessions \
                 whose environment sets it to `sizes` (never for tunnel sessions)"
            )));
        }
        let was_running = stop_if_running(&self.layout)?;
        let from = current.version.clone();
        let result = (|| {
            write_json_atomic(
                &self.layout.current_file(),
                &CurrentRecord {
                    schema: CURRENT_SCHEMA.into(),
                    version: previous.clone(),
                    manifest_sha256: manifest::sha256_bytes(&manifest_bytes),
                },
            )?;
            installer.replace_cli(&previous_dir.join("orcel.exe"))?;
            write_json_atomic(
                &self.layout.install_file(),
                &InstallRecord {
                    schema: INSTALL_SCHEMA.into(),
                    active: previous.clone(),
                    previous: Some(from.clone()),
                    node_path: record.node_path.clone(),
                    path_entry_added: record.path_entry_added,
                },
            )?;
            installer.protect_root()?;
            installer.verify().map(|_| ())
        })();
        if let Err(error) = result {
            let restored = self.restore(&current, &record);
            crate::logs::transcript(
                &self.layout,
                &format!("rollback {from} -> {previous} failed: {}", error.message),
            );
            let restarted = restored.is_ok()
                && was_running
                && restart(&self.layout, self.platform).unwrap_or(false);
            return Err(match restored {
                Ok(()) => LifecycleError::state(format!(
                    "rollback to {previous} failed and {from} remains active{}: {}",
                    if restarted { " and was restarted" } else { "" },
                    error.message
                )),
                Err(restore) => LifecycleError::state(format!(
                    "rollback to {previous} failed ({}) and restoring {from} also failed: {}; \
                     run `orcel doctor`, which names the version to repair with",
                    error.message, restore.message
                )),
            });
        }
        let _ = std::fs::remove_file(update_marker_path(&self.layout));
        let start_menu = installer.reconcile_start_menu(&previous_dir, record.path_entry_added);
        crate::logs::transcript(
            &self.layout,
            &format!("rollback {from} -> {previous} succeeded"),
        );
        let restarted = was_running && restart(&self.layout, self.platform)?;
        Ok(RollbackReport {
            from,
            to: previous,
            restarted,
            start_menu,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install::InstallOptions;
    use crate::test_support::{release_dir, temp_dir, FakePlatform};
    use std::path::PathBuf;

    fn setup(version: &str) -> (Layout, FakePlatform) {
        let layout = Layout::new(temp_dir("update").join("Orcel"));
        let platform = FakePlatform::default();
        Installer::new(layout.clone(), &platform)
            .install(
                &release_dir(version),
                &InstallOptions {
                    node: Some(PathBuf::from("/fake/node")),
                    add_to_path: false,
                },
            )
            .unwrap();
        (layout, platform)
    }

    #[test]
    fn a_saved_preview_choice_refuses_rollback_until_it_is_cleared() {
        let (layout, platform) = setup("0.2.0");
        // 0.3.0 active with 0.2.0 retained, written directly: a real update would run the
        // fixture's CLI, which isn't an executable.
        let installer = Installer::new(layout.clone(), &platform);
        let release = manifest::verify_release(&release_dir("0.3.0")).unwrap();
        installer.stage_version(&release).unwrap();
        let record: InstallRecord = crate::layout::read_install(&layout).unwrap().unwrap();
        write_json_atomic(
            &layout.current_file(),
            &CurrentRecord {
                schema: CURRENT_SCHEMA.into(),
                version: "0.3.0".into(),
                manifest_sha256: release.manifest_sha256.clone(),
            },
        )
        .unwrap();
        write_json_atomic(
            &layout.install_file(),
            &InstallRecord {
                schema: INSTALL_SCHEMA.into(),
                active: "0.3.0".into(),
                previous: Some("0.2.0".into()),
                node_path: record.node_path.clone(),
                path_entry_added: record.path_entry_added,
            },
        )
        .unwrap();
        installer.verify().unwrap();
        let mut config = crate::config::Config::load(&layout).unwrap();
        config.approval_previews = Some(crate::config::ApprovalPreviews::Sizes);
        config.save(&layout).unwrap();
        let error = Updater::new(layout.clone(), &platform)
            .rollback()
            .unwrap_err();
        assert!(
            error.message.contains("orcel approvals previews content"),
            "{}",
            error.message
        );
        let current: CurrentRecord = read_json(&layout.current_file()).unwrap().unwrap();
        assert_eq!(current.version, "0.3.0", "nothing was changed");
        config.approval_previews = None;
        config.save(&layout).unwrap();
        Updater::new(layout.clone(), &platform).rollback().unwrap();
        let current: CurrentRecord = read_json(&layout.current_file()).unwrap().unwrap();
        assert_eq!(current.version, "0.2.0");
    }

    #[test]
    fn check_reports_direction_without_changes() {
        let (layout, platform) = setup("0.2.0");
        let report = Updater::new(layout.clone(), &platform)
            .update(
                &release_dir("0.3.0"),
                &UpdateOptions {
                    check_only: true,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(report.direction, "upgrade");
        assert!(matches!(report.outcome, UpdateOutcome::Checked));
        let current: CurrentRecord = read_json(&layout.current_file()).unwrap().unwrap();
        assert_eq!(current.version, "0.2.0");
    }

    #[test]
    fn downgrade_requires_explicit_flag() {
        let (layout, platform) = setup("0.3.0");
        let error = Updater::new(layout.clone(), &platform)
            .update(&release_dir("0.2.0"), &UpdateOptions::default())
            .unwrap_err();
        assert_eq!(error.kind, crate::ErrorKind::Conflict);
        let current: CurrentRecord = read_json(&layout.current_file()).unwrap().unwrap();
        assert_eq!(current.version, "0.3.0");
    }

    #[test]
    fn incompatible_configuration_schema_is_refused_before_any_change() {
        let (layout, platform) = setup("0.2.0");
        let candidate = release_dir("0.3.0");
        let mut manifest: Manifest =
            serde_json::from_slice(&std::fs::read(candidate.join(MANIFEST_FILE)).unwrap()).unwrap();
        manifest.config_schema = crate::manifest::ConfigSchemaRange { min: 2, max: 2 };
        std::fs::write(
            candidate.join(MANIFEST_FILE),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let error = Updater::new(layout.clone(), &platform)
            .update(&candidate, &UpdateOptions::default())
            .unwrap_err();
        assert!(
            error.message.contains("configuration schema"),
            "{}",
            error.message
        );
        assert!(!layout.version_dir("0.3.0").exists());
    }

    #[test]
    fn failed_self_check_restores_the_previous_version() {
        // Synthetic payload binaries cannot run, so the new version's
        // self-check fails and the update must roll back.
        let (layout, platform) = setup("0.2.0");
        let error = Updater::new(layout.clone(), &platform)
            .update(&release_dir("0.3.0"), &UpdateOptions::default())
            .unwrap_err();
        assert!(
            error.message.contains("0.2.0 was restored"),
            "{}",
            error.message
        );
        let current: CurrentRecord = read_json(&layout.current_file()).unwrap().unwrap();
        assert_eq!(current.version, "0.2.0");
        Installer::new(layout.clone(), &platform).verify().unwrap();
        let marker = read_marker(&layout).unwrap().unwrap();
        assert_eq!(marker.state, UpdateState::Failed);
        assert_eq!(marker.to, "0.3.0");
        assert!(!layout.version_dir("0.3.0").exists());
    }

    #[test]
    fn a_failed_update_leaves_the_start_menu_entry_alone() {
        let (layout, platform) = setup("0.2.0");
        *platform.start_menu.borrow_mut() = Some(layout.bin_cli());
        Updater::new(layout.clone(), &platform)
            .update(&release_dir("0.3.0"), &UpdateOptions::default())
            .unwrap_err();
        assert_eq!(*platform.start_menu.borrow(), Some(layout.bin_cli()));
    }

    #[test]
    fn start_is_refused_while_an_update_is_pending() {
        let (layout, platform) = setup("0.2.0");
        write_marker(&layout, UpdateState::Pending, "0.2.0", "0.3.0", None).unwrap();
        let error = crate::lifecycle::start(&layout, &platform, std::time::Duration::from_secs(1))
            .unwrap_err();
        if cfg!(windows) {
            assert_eq!(error.kind, crate::ErrorKind::Conflict, "{}", error.message);
            assert!(error.message.contains("in progress"), "{}", error.message);
        }
        write_marker(
            &layout,
            UpdateState::Failed,
            "0.2.0",
            "0.3.0",
            Some("x".into()),
        )
        .unwrap();
        let error = crate::lifecycle::start(&layout, &platform, std::time::Duration::from_secs(1))
            .unwrap_err();
        assert!(!error.message.contains("in progress"), "{}", error.message);
    }

    #[test]
    fn rollback_recovers_a_crash_between_pointer_and_install_record() {
        let (layout, platform) = setup("0.2.0");
        let installer = Installer::new(layout.clone(), &platform);
        let release = manifest::verify_release(&release_dir("0.3.0")).unwrap();
        installer.stage_version(&release).unwrap();
        write_marker(&layout, UpdateState::Pending, "0.2.0", "0.3.0", None).unwrap();
        // Simulate a crash after the pointer flip but before install.json.
        write_json_atomic(
            &layout.current_file(),
            &CurrentRecord {
                schema: CURRENT_SCHEMA.into(),
                version: "0.3.0".into(),
                manifest_sha256: release.manifest_sha256.clone(),
            },
        )
        .unwrap();
        assert!(installer.verify().is_err());
        let error = Updater::new(layout.clone(), &platform)
            .update(&release_dir("0.3.0"), &UpdateOptions::default())
            .unwrap_err();
        assert!(
            error.message.contains("orcel rollback"),
            "{}",
            error.message
        );

        let report = Updater::new(layout.clone(), &platform).rollback().unwrap();
        assert_eq!(report.to, "0.2.0");
        assert_eq!(report.start_menu, StartMenuChange::Unchanged);
        let state = installer.verify().unwrap();
        assert_eq!(state.active.version, "0.2.0");
        assert_eq!(state.record.previous.as_deref(), Some("0.3.0"));
        assert!(read_marker(&layout).unwrap().is_none());
    }

    #[test]
    fn malformed_markers_are_errors_not_warnings() {
        let (layout, platform) = setup("0.2.0");
        std::fs::write(
            update_marker_path(&layout),
            br#"{"schema":"other","state":"failed","from":"0.2.0","to":"0.3.0","reason":null,"at_ms":1}"#,
        )
        .unwrap();
        assert!(read_marker(&layout).is_err());
        let report = crate::doctor::run(&layout, &platform);
        let check = report
            .checks
            .iter()
            .find(|check| check.name == "update_state")
            .unwrap();
        assert_eq!(check.status, crate::doctor::CheckStatus::Fail);
    }

    #[test]
    fn rollback_without_an_install_reports_not_installed() {
        let platform = FakePlatform::default();
        let layout = Layout::new(temp_dir("rollback-none").join("Orcel"));
        let error = Updater::new(layout, &platform).rollback().unwrap_err();
        assert_eq!(error.kind, crate::ErrorKind::NotInstalled);
    }

    #[test]
    fn rollback_without_previous_is_refused() {
        let (layout, platform) = setup("0.2.0");
        let error = Updater::new(layout, &platform).rollback().unwrap_err();
        assert_eq!(error.kind, crate::ErrorKind::Conflict);
    }

    #[test]
    fn schema_compatibility_is_inclusive() {
        let mut manifest: Manifest = serde_json::from_slice(
            &std::fs::read(release_dir("0.2.0").join(MANIFEST_FILE)).unwrap(),
        )
        .unwrap();
        manifest.config_schema = crate::manifest::ConfigSchemaRange { min: 1, max: 3 };
        assert!(compatible(&manifest, 1));
        assert!(compatible(&manifest, 3));
        assert!(!compatible(&manifest, 4));
    }
}
