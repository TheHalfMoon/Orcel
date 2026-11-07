//! `orcel state`: what happens to state left at the earlier Windows root.
//!
//! Migration copies user data only, and only from a root and files that pass the same rules as
//! the current ones: another account that could have changed them could have forged approvals,
//! trust or keys, and copying them would launder that. That's what their permissions show now:
//! it can't show what they allowed before. It never deletes or changes the source, and never
//! overwrites. It stages everything first and verifies it, so a crash leaves nothing half-trusted,
//! and running it again finishes the job. Payload is reinstalled, not copied.
//!
//! Live authority and identity aren't copied, since a copy would stay valid beside the original
//! and a revocation or rotation would reach only one: full-control authority, remote leases, and
//! the device's key and pairing are granted again. Workspace trust and the executable registry
//! are copied: they're the person's own choices, and Orcel rechecks a registered executable when
//! it runs one.

use crate::LifecycleError;
use orcel_platform::legacy::{self, DECISION_KEPT_SEPARATE, DECISION_MIGRATED, DECISION_SCHEMA};
use orcel_platform::paths;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

/// Single files of user data at the root.
const DATA_FILES: [&str; 7] = [
    "audit.jsonl",
    "approval-history.jsonl",
    "trust.jsonl",
    "executable_registry.json",
    "report-tasks.jsonl",
    "report-tasks.key",
    "mutations.jsonl",
];
/// Directories of user data, whole.
const DATA_DIRS: [&str; 2] = ["state", "secrets"];
/// Under `state`, with the payload it describes: not user data.
const SKIPPED_IN_STATE: [&str; 1] = ["update.json"];
/// Live authority and identity, relative to the root: granted again, not copied.
const NOT_COPIED: [&str; 4] = [
    "state/authority",
    "state/remote/uplink.json",
    "state/device/device_key.json",
    "secrets/device.key.dpapi",
];
const QUARANTINE_PREFIX: &str = "approval-history.jsonl.quarantine-";
/// Left by a crash or a live writer: the data isn't at rest.
const UNCLEAN_SUFFIXES: [&str; 1] = [".rewrite"];
const UNCLEAN_MARKER: &str = ".recovering-";
const LOCKS: [&str; 3] = [
    "approval-history.jsonl.lock",
    "report-tasks.jsonl.lock",
    "mutations.jsonl.lock",
];
pub(crate) const STAGING_PREFIX: &str = "legacy-import-";
/// Whether `name` is a staging folder migration made: its prefix and a process id, and nothing
/// else, so a person's own file with a similar name is never taken for one.
pub(crate) fn is_staging_name(name: &str) -> bool {
    name.strip_prefix(STAGING_PREFIX)
        .is_some_and(|id| !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_digit()))
}

/// Only this tells an interrupted migration's copies from state in normal use.
const IN_PROGRESS: &str = legacy::MIGRATION_IN_PROGRESS;

/// What an earlier root holds, sorted by what migration would do with it.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Inventory {
    /// Relative paths of the files migration copies.
    pub data: Vec<PathBuf>,
    /// Top-level names it leaves where they are.
    pub left: Vec<String>,
    /// Why the data isn't at rest, if it isn't.
    pub unclean: Vec<String>,
    /// Whether an earlier install's program files are there.
    pub payload: bool,
}

fn refuse(message: impl Into<String>) -> LifecycleError {
    LifecycleError::conflict(message)
}

fn read_err(path: &Path, error: impl std::fmt::Display) -> LifecycleError {
    LifecycleError::state(format!("{} can't be read: {error}", path.display()))
}

fn collect(root: &Path, relative: &Path, out: &mut Vec<PathBuf>) -> Result<(), LifecycleError> {
    let path = root.join(relative);
    let metadata = fs::symlink_metadata(&path).map_err(|error| read_err(&path, error))?;
    if metadata.file_type().is_symlink() {
        return Err(refuse(format!(
            "{} is a link, which migration doesn't follow",
            path.display()
        )));
    }
    if metadata.is_dir() {
        for entry in fs::read_dir(&path).map_err(|error| read_err(&path, error))? {
            let entry = entry.map_err(|error| read_err(&path, error))?;
            collect(root, &relative.join(entry.file_name()), out)?;
        }
    } else if metadata.is_file() {
        out.push(relative.to_owned());
    } else {
        return Err(refuse(format!(
            "{} isn't a regular file or folder",
            path.display()
        )));
    }
    Ok(())
}

/// Reads what is at `legacy`. Changes nothing.
pub fn inventory(legacy: &Path) -> Result<Inventory, LifecycleError> {
    let mut found = Inventory::default();
    for entry in fs::read_dir(legacy).map_err(|error| read_err(legacy, error))? {
        let entry = entry.map_err(|error| read_err(legacy, error))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let relative = PathBuf::from(&name);
        if name == "run" {
            if legacy.join("run").join("supervisor.json").exists() {
                found.unclean.push(
                    "an earlier supervisor record exists; stop the earlier Orcel first".into(),
                );
            }
            found.left.push(name);
        } else if UNCLEAN_SUFFIXES.iter().any(|suffix| name.ends_with(suffix))
            || name.contains(UNCLEAN_MARKER)
        {
            found
                .unclean
                .push(format!("{name} was left by an interrupted write"));
        } else if DATA_DIRS.contains(&name.as_str())
            || DATA_FILES.contains(&name.as_str())
            || name.starts_with(QUARANTINE_PREFIX)
        {
            collect(legacy, &relative, &mut found.data)?;
        } else {
            found.payload |=
                ["bin", "versions", "current.json", "install.json"].contains(&name.as_str());
            found.left.push(name);
        }
    }
    for name in NOT_COPIED {
        let matched = |path: &PathBuf| path.starts_with(Path::new(name));
        if found.data.iter().any(matched) {
            found.left.push(name.to_owned());
        }
        found.data.retain(|path| !matched(path));
    }
    found.data.retain(|path| {
        !(path.starts_with("state")
            && SKIPPED_IN_STATE
                .iter()
                .any(|name| path.file_name().is_some_and(|file| file == *name)))
    });
    found.data.sort();
    found.left.sort();
    found.unclean.sort();
    Ok(found)
}

/// Whether a live process holds one of the journals' locks.
fn check_locks(legacy: &Path) -> Result<(), LifecycleError> {
    for name in LOCKS {
        let path = legacy.join(name);
        match fs::File::open(&path) {
            // The lock the journals themselves take, released when this handle closes.
            Ok(file) => match fs4::FileExt::try_lock(&file) {
                Ok(()) => {}
                Err(fs4::TryLockError::WouldBlock) => {
                    return Err(refuse(format!(
                        "{} is locked: an earlier Orcel is running. Stop it first",
                        path.display()
                    )))
                }
                Err(fs4::TryLockError::Error(error)) => return Err(read_err(&path, error)),
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(read_err(&path, error)),
        }
    }
    Ok(())
}

fn digest(path: &Path) -> Result<[u8; 32], LifecycleError> {
    let bytes = fs::read(path).map_err(|error| read_err(path, error))?;
    Ok(Sha256::digest(&bytes).into())
}

fn io(path: &Path, error: impl std::fmt::Display) -> LifecycleError {
    LifecycleError::state(format!("{}: {error}", path.display()))
}

/// Records `decision`. Written last, whole, so a crash before it leaves the gate closed.
fn record(root: &Path, decision: &str) -> Result<(), LifecycleError> {
    let file = legacy::decision_file(root);
    let parent = file.parent().expect("the decision file has a folder");
    paths::ensure_private_dir(parent).map_err(|error| io(parent, error))?;
    let temporary = file.with_extension(format!("tmp-{}", std::process::id()));
    fs::write(&temporary, format!("{DECISION_SCHEMA}\n{decision}\n"))
        .map_err(|error| io(&temporary, error))?;
    fs::rename(&temporary, &file).map_err(|error| io(&file, error))
}

fn refuse_if_decided(root: &Path) -> Result<(), LifecycleError> {
    match legacy::read_decision(root) {
        Some(decision) => Err(refuse(format!(
            "this was already decided ({decision}), in {}",
            legacy::decision_file(root).display()
        ))),
        None => Ok(()),
    }
}

/// Removes what an earlier attempt staged, which only ever holds copies. A link or file planted
/// under that name is removed itself, and never followed.
fn clear_staging(root: &Path) -> Result<(), LifecycleError> {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(read_err(root, error)),
    };
    for entry in entries {
        let entry = entry.map_err(|error| read_err(root, error))?;
        if !entry
            .file_name()
            .to_string_lossy()
            .starts_with(STAGING_PREFIX)
        {
            continue;
        }
        let planted = entry.path();
        let metadata = fs::symlink_metadata(&planted).map_err(|error| read_err(&planted, error))?;
        let removed = if metadata.is_dir() && !metadata.file_type().is_symlink() {
            fs::remove_dir_all(&planted)
        } else if metadata.is_dir() {
            fs::remove_dir(&planted)
        } else {
            fs::remove_file(&planted)
        };
        removed.map_err(|error| io(&planted, error))?;
    }
    Ok(())
}

/// Copied files and what stayed, for the person to read.
#[derive(Debug, PartialEq, Eq)]
pub struct MigrateReport {
    pub copied: usize,
    pub already_there: usize,
    pub left: Vec<String>,
    pub payload: bool,
}

/// Copies the user data at `legacy` into `root`. `check_source` decides whether the earlier root
/// could have been changed by anyone else: if it could, its contents can't be trusted, so
/// nothing is copied.
pub fn migrate(
    legacy: &Path,
    root: &Path,
    check_source: &dyn Fn(&Path) -> Result<(), String>,
    check_entry: &dyn Fn(&Path) -> Result<(), String>,
) -> Result<MigrateReport, LifecycleError> {
    refuse_if_decided(root)?;
    check_source(legacy).map_err(|reason| {
        refuse(format!(
            "{} can't be migrated: {reason}. Another account could have changed those files, so \
             they can't be trusted as approvals, trust records or keys. Nothing was copied. They \
             stay where they are; `orcel state keep-separate` records that",
            legacy.display()
        ))
    })?;
    check_locks(legacy)?;
    let found = inventory(legacy)?;
    if let Some(reason) = found.unclean.first() {
        return Err(refuse(format!(
            "{} isn't at rest: {reason}. Nothing was copied",
            legacy.display()
        )));
    }
    // Every file, and every folder between it and the root: each could carry a grant of its own.
    let mut checked = std::collections::BTreeSet::new();
    for relative in &found.data {
        for entry in relative
            .ancestors()
            .filter(|entry| !entry.as_os_str().is_empty())
        {
            if checked.insert(entry.to_owned()) {
                check_entry(&legacy.join(entry)).map_err(|reason| {
                    refuse(format!(
                        "{reason}. It can't be trusted, so nothing was copied. It stays where it \
                         is; `orcel state keep-separate` records that"
                    ))
                })?;
            }
        }
    }
    paths::ensure_private_dir(root).map_err(|error| io(root, error))?;

    clear_staging(root)?;
    let staging = root.join(format!("{STAGING_PREFIX}{}", std::process::id()));
    paths::ensure_private_dir(&staging).map_err(|error| io(&staging, error))?;

    let mut to_place = Vec::new();
    let mut already_there = 0;
    for relative in &found.data {
        let source = legacy.join(relative);
        let target = root.join(relative);
        let before = digest(&source)?;
        match fs::symlink_metadata(&target) {
            Ok(metadata) if !metadata.is_file() => {
                fs::remove_dir_all(&staging).ok();
                return Err(refuse(format!(
                    "{} is already there and isn't a regular file. Nothing was overwritten",
                    target.display()
                )));
            }
            Ok(_) => {
                // A rerun after a crash finds its own earlier copies. Anything else isn't ours.
                if digest(&target)? != before {
                    fs::remove_dir_all(&staging).ok();
                    return Err(refuse(format!(
                        "{} already exists and differs from {}. Nothing was overwritten",
                        target.display(),
                        source.display()
                    )));
                }
                already_there += 1;
                continue;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(read_err(&target, error)),
        }
        let staged = staging.join(relative);
        let parent = staged.parent().expect("a staged file has a folder");
        paths::ensure_private_dir(parent).map_err(|error| io(parent, error))?;
        fs::copy(&source, &staged).map_err(|error| io(&staged, error))?;
        if digest(&staged)? != before || digest(&source)? != before {
            fs::remove_dir_all(&staging).ok();
            return Err(refuse(format!(
                "{} changed while it was copied. Nothing was placed",
                source.display()
            )));
        }
        to_place.push(relative.clone());
    }
    let in_progress = root.join(IN_PROGRESS);
    // A real marker stays, so a crash here never leaves copies without one. Anything else under
    // that name, such as a link, is removed and never followed.
    let marked = match fs::symlink_metadata(&in_progress) {
        Ok(metadata) if metadata.is_file() => true,
        Ok(_) => {
            fs::remove_file(&in_progress).map_err(|error| io(&in_progress, error))?;
            false
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(read_err(&in_progress, error)),
    };
    if !marked {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&in_progress)
            .map_err(|error| io(&in_progress, error))?;
    }
    for relative in &to_place {
        let target = root.join(relative);
        let parent = target.parent().expect("a target has a folder");
        paths::ensure_private_dir(parent).map_err(|error| io(parent, error))?;
        // A new name, which fails if anything took it since the check: a rename would replace it.
        fs::hard_link(staging.join(relative), &target).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                refuse(format!(
                    "{} appeared during migration. Nothing was overwritten",
                    target.display()
                ))
            } else {
                io(&target, error)
            }
        })?;
    }
    fs::remove_dir_all(&staging).map_err(|error| io(&staging, error))?;
    record(root, DECISION_MIGRATED)?;
    fs::remove_file(&in_progress).map_err(|error| io(&in_progress, error))?;
    Ok(MigrateReport {
        copied: to_place.len(),
        already_there,
        left: found.left,
        payload: found.payload,
    })
}

/// Records that the earlier state stays where it is, unused. Deletes nothing. Refused while a
/// migration is unfinished: a decision would start Orcel on part of what it copied.
pub fn keep_separate(legacy: &Path, root: &Path) -> Result<(), LifecycleError> {
    refuse_if_decided(root)?;
    let in_progress = root.join(IN_PROGRESS);
    if fs::symlink_metadata(&in_progress).is_ok() {
        let copied: Vec<String> = inventory(legacy)
            .map(|found| found.data)
            .unwrap_or_default()
            .iter()
            .map(|relative| root.join(relative))
            .filter(|target| fs::symlink_metadata(target).is_ok())
            .map(|target| target.display().to_string())
            .collect();
        let listed = if copied.is_empty() {
            format!(
                "The earlier state can't be read, so what it copied can't be listed: look in {}",
                root.display()
            )
        } else {
            format!("Those it may have copied: {}", copied.join(", "))
        };
        return Err(refuse(format!(
            "a migration was interrupted, so a decision would start Orcel on part of what it \
             copied. Run `orcel state migrate` to finish it. If that's refused, remove what it \
             copied, then {}, and try again. {listed}",
            in_progress.display()
        )));
    }
    paths::ensure_private_dir(root).map_err(|error| io(root, error))?;
    clear_staging(root)?;
    record(root, DECISION_KEPT_SEPARATE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use orcel_platform::legacy::{examine, LegacyState};

    fn trusted(_: &Path) -> Result<(), String> {
        Ok(())
    }

    fn run(legacy: &Path, root: &Path) -> Result<MigrateReport, LifecycleError> {
        migrate(legacy, root, &trusted, &trusted)
    }

    fn scratch(label: &str) -> (PathBuf, PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!(
            "legacy-state-{label}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let legacy = base.join("Orcel");
        fs::create_dir_all(legacy.join("state").join("secrets")).unwrap();
        fs::create_dir_all(legacy.join("secrets")).unwrap();
        fs::create_dir_all(legacy.join("bin")).unwrap();
        fs::create_dir_all(legacy.join("browser-profile")).unwrap();
        fs::write(legacy.join("trust.jsonl"), "trust").unwrap();
        fs::write(legacy.join("approval-history.jsonl"), "approvals").unwrap();
        fs::write(
            legacy.join("approval-history.jsonl.quarantine-1"),
            "quarantined",
        )
        .unwrap();
        fs::write(legacy.join("state").join("config.json"), "{}").unwrap();
        fs::write(legacy.join("state").join("update.json"), "{}").unwrap();
        fs::write(legacy.join("state").join("secrets").join("key"), "k").unwrap();
        fs::write(legacy.join("secrets").join("a.dpapi"), "blob").unwrap();
        fs::write(legacy.join("bin").join("orcel.exe"), "exe").unwrap();
        fs::write(legacy.join("current.json"), "{}").unwrap();
        fs::write(legacy.join("browser-profile").join("x"), "x").unwrap();
        let root = base.join(".orcel");
        (base, legacy, root)
    }

    fn tree(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        let mut files = Vec::new();
        collect(root, Path::new(""), &mut files).unwrap();
        files.sort();
        files
            .into_iter()
            .map(|file| {
                let bytes = fs::read(root.join(&file)).unwrap();
                (file, bytes)
            })
            .collect()
    }

    #[test]
    fn inventory_sorts_data_from_what_stays() {
        let (base, legacy, _) = scratch("inventory");
        let found = inventory(&legacy).unwrap();
        assert_eq!(
            found.data,
            [
                "approval-history.jsonl",
                "approval-history.jsonl.quarantine-1",
                "secrets/a.dpapi",
                "state/config.json",
                "state/secrets/key",
                "trust.jsonl",
            ]
            .map(PathBuf::from)
        );
        assert_eq!(found.left, ["bin", "browser-profile", "current.json"]);
        assert!(found.payload);
        assert!(found.unclean.is_empty());
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn migrate_copies_data_leaves_the_source_alone_and_opens_the_gate() {
        let (base, legacy, root) = scratch("copy");
        let before = tree(&legacy);
        assert!(matches!(examine(&legacy, &root), LegacyState::Undecided(_)));
        let report = run(&legacy, &root).unwrap();
        assert_eq!(report.copied, 6);
        assert_eq!(report.already_there, 0);
        assert!(report.payload);
        assert_eq!(tree(&legacy), before);
        assert_eq!(fs::read(root.join("trust.jsonl")).unwrap(), b"trust");
        assert_eq!(
            fs::read(root.join("state").join("secrets").join("key")).unwrap(),
            b"k"
        );
        assert!(!root.join("bin").exists());
        assert!(!root.join("browser-profile").exists());
        assert!(!root.join("state").join("update.json").exists());
        assert_eq!(
            examine(&legacy, &root),
            LegacyState::Decided(DECISION_MIGRATED.into())
        );
        assert!(run(&legacy, &root).is_err());
        assert_eq!(tree(&legacy), before);
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn an_untrusted_source_copies_nothing_and_stays_undecided() {
        let (base, legacy, root) = scratch("untrusted");
        let before = tree(&legacy);
        let error = migrate(
            &legacy,
            &root,
            &|_| Err("grants S-1-5-21-9 access".into()),
            &trusted,
        )
        .unwrap_err()
        .message;
        assert!(error.contains("grants S-1-5-21-9 access"), "{error}");
        assert!(error.contains("keep-separate"), "{error}");
        assert!(!root.exists());
        assert_eq!(tree(&legacy), before);
        assert!(matches!(examine(&legacy, &root), LegacyState::Undecided(_)));
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn nothing_is_overwritten_and_a_refusal_leaves_the_gate_closed() {
        let (base, legacy, root) = scratch("overwrite");
        paths::ensure_private_dir(&root).unwrap();
        fs::write(root.join("trust.jsonl"), "newer").unwrap();
        let error = run(&legacy, &root).unwrap_err().message;
        assert!(error.contains("differs"), "{error}");
        assert_eq!(fs::read(root.join("trust.jsonl")).unwrap(), b"newer");
        assert!(!root.join("approval-history.jsonl").exists());
        assert!(matches!(examine(&legacy, &root), LegacyState::Undecided(_)));
        fs::remove_dir_all(&base).unwrap();
    }

    /// A crash after some files were placed and before the decision: the next run finishes.
    #[test]
    fn a_rerun_after_a_crash_finishes_the_job() {
        let (base, legacy, root) = scratch("rerun");
        paths::ensure_private_dir(&root).unwrap();
        fs::create_dir_all(root.join(format!("{STAGING_PREFIX}1").as_str())).unwrap();
        fs::write(root.join(format!("{STAGING_PREFIX}1")).join("half"), "half").unwrap();
        fs::write(root.join("trust.jsonl"), "trust").unwrap();
        let report = run(&legacy, &root).unwrap();
        assert_eq!(report.already_there, 1);
        assert_eq!(report.copied, 5);
        assert!(!root.join(format!("{STAGING_PREFIX}1")).exists());
        assert_eq!(
            examine(&legacy, &root),
            LegacyState::Decided(DECISION_MIGRATED.into())
        );
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn data_not_at_rest_is_refused_before_anything_is_copied() {
        for (label, prepare) in [
            ("rewrite", "mutations.jsonl.rewrite"),
            ("recovering", "approval-history.jsonl.recovering-1"),
        ] {
            let (base, legacy, root) = scratch(label);
            fs::write(legacy.join(prepare), "x").unwrap();
            assert!(run(&legacy, &root).is_err(), "{label}");
            assert!(!root.exists(), "{label}");
            fs::remove_dir_all(&base).unwrap();
        }
        let (base, legacy, root) = scratch("supervisor");
        fs::create_dir_all(legacy.join("run")).unwrap();
        fs::write(legacy.join("run").join("supervisor.json"), "{}").unwrap();
        assert!(run(&legacy, &root).is_err());
        assert!(!root.exists());
        fs::remove_dir_all(&base).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_link_is_refused_before_anything_is_copied() {
        let (base, legacy, root) = scratch("symlink");
        std::os::unix::fs::symlink(&base, legacy.join("state").join("elsewhere")).unwrap();
        assert!(run(&legacy, &root).is_err());
        assert!(!root.exists());
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn a_file_or_folder_that_fails_its_own_check_copies_nothing() {
        for bad in ["trust.jsonl", "state", "secrets/a.dpapi"] {
            let (base, legacy, root) = scratch("entry");
            let refused = legacy.join(bad);
            let error = migrate(&legacy, &root, &trusted, &|path| {
                if path == refused {
                    Err(format!("{} grants someone access", path.display()))
                } else {
                    Ok(())
                }
            })
            .unwrap_err()
            .message;
            assert!(error.contains("grants someone access"), "{error}");
            assert!(!root.exists(), "{bad}");
            assert!(matches!(examine(&legacy, &root), LegacyState::Undecided(_)));
            fs::remove_dir_all(&base).unwrap();
        }
    }

    #[test]
    fn live_authority_is_not_copied() {
        let (base, legacy, root) = scratch("authority");
        let authority = legacy.join("state").join("authority");
        fs::create_dir_all(&authority).unwrap();
        fs::write(authority.join("authority.key"), "key").unwrap();
        fs::write(legacy.join("remote_leases.json"), "{}").unwrap();
        for (folder, file) in [
            ("remote", "uplink.json"),
            ("device", "device_key.json"),
            ("device", "revocations.json"),
        ] {
            fs::create_dir_all(legacy.join("state").join(folder)).unwrap();
            fs::write(legacy.join("state").join(folder).join(file), "{}").unwrap();
        }
        fs::write(legacy.join("secrets").join("device.key.dpapi"), "key").unwrap();
        fs::write(legacy.join("executable_registry.json"), "{}").unwrap();
        let report = run(&legacy, &root).unwrap();
        assert!(!root.join("state").join("authority").exists());
        assert!(!root.join("remote_leases.json").exists());
        assert!(!root
            .join("state")
            .join("remote")
            .join("uplink.json")
            .exists());
        assert!(!root
            .join("state")
            .join("device")
            .join("device_key.json")
            .exists());
        assert!(!root.join("secrets").join("device.key.dpapi").exists());
        for left in [
            "remote_leases.json",
            "state/authority",
            "state/remote/uplink.json",
            "state/device/device_key.json",
            "secrets/device.key.dpapi",
        ] {
            assert!(report.left.contains(&left.to_owned()), "{left}");
        }
        // Dropping these would lose a revocation, or the person's own choices.
        assert!(root
            .join("state")
            .join("device")
            .join("revocations.json")
            .exists());
        assert!(root.join("executable_registry.json").exists());
        assert!(root.join("secrets").join("a.dpapi").exists());
        assert!(authority.join("authority.key").exists());
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn keep_separate_is_refused_while_a_migration_is_unfinished() {
        let (base, legacy, root) = scratch("half");
        paths::ensure_private_dir(&root).unwrap();
        fs::write(root.join(IN_PROGRESS), b"").unwrap();
        fs::write(root.join("trust.jsonl"), "trust").unwrap();
        let error = keep_separate(&legacy, &root).unwrap_err().message;
        assert!(error.contains("interrupted"), "{error}");
        assert!(error.contains("trust.jsonl"), "{error}");
        assert!(error.contains(IN_PROGRESS), "{error}");
        assert!(matches!(examine(&legacy, &root), LegacyState::Undecided(_)));
        // The source moving on doesn't make the copy any less partial.
        fs::write(legacy.join("trust.jsonl"), "newer").unwrap();
        assert!(keep_separate(&legacy, &root).is_err());
        fs::write(legacy.join("trust.jsonl"), "trust").unwrap();
        run(&legacy, &root).unwrap();
        assert!(!root.join(IN_PROGRESS).exists());
        fs::remove_dir_all(&base).unwrap();
    }

    /// An older build wrote to the earlier root after the current one was in use. Those files are
    /// the person's real state, not leftovers, and nothing should tell them to delete it.
    #[test]
    fn keep_separate_works_over_state_in_normal_use() {
        let (base, legacy, root) = scratch("in-use");
        paths::ensure_private_dir(&root).unwrap();
        fs::write(root.join("trust.jsonl"), "current").unwrap();
        fs::write(root.join("approval-history.jsonl"), "current").unwrap();
        assert!(run(&legacy, &root).unwrap_err().message.contains("differs"));
        keep_separate(&legacy, &root).unwrap();
        assert_eq!(fs::read(root.join("trust.jsonl")).unwrap(), b"current");
        assert_eq!(
            examine(&legacy, &root),
            LegacyState::Decided(DECISION_KEPT_SEPARATE.into())
        );
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn a_rerun_keeps_the_marker_it_finds() {
        let (base, legacy, root) = scratch("marker-kept");
        paths::ensure_private_dir(&root).unwrap();
        fs::write(root.join(IN_PROGRESS), b"").unwrap();
        // Differing, so the rerun stops after the marker's turn would have come: it stays.
        fs::write(root.join("trust.jsonl"), "newer").unwrap();
        assert!(run(&legacy, &root).is_err());
        assert!(root.join(IN_PROGRESS).is_file());
        assert!(keep_separate(&legacy, &root).is_err());
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn keep_separate_clears_what_a_crash_staged() {
        let (base, legacy, root) = scratch("staged");
        paths::ensure_private_dir(&root).unwrap();
        let staged = root.join(format!("{STAGING_PREFIX}1"));
        fs::create_dir_all(&staged).unwrap();
        fs::write(staged.join("key"), "secret").unwrap();
        keep_separate(&legacy, &root).unwrap();
        assert!(!staged.exists());
        fs::remove_dir_all(&base).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_link_planted_as_the_marker_is_replaced_not_followed() {
        let (base, legacy, root) = scratch("marker-link");
        paths::ensure_private_dir(&root).unwrap();
        let victim = base.join("victim");
        fs::write(&victim, "keep me").unwrap();
        std::os::unix::fs::symlink(&victim, root.join(IN_PROGRESS)).unwrap();
        run(&legacy, &root).unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"keep me");
        assert!(fs::symlink_metadata(root.join(IN_PROGRESS)).is_err());
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn a_planted_staging_file_doesnt_stop_it() {
        let (base, legacy, root) = scratch("planted");
        paths::ensure_private_dir(&root).unwrap();
        fs::write(root.join(format!("{STAGING_PREFIX}file")), "x").unwrap();
        run(&legacy, &root).unwrap();
        assert!(!root.join(format!("{STAGING_PREFIX}file")).exists());
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn keep_separate_deletes_nothing_and_opens_the_gate() {
        let (base, legacy, root) = scratch("separate");
        let before = tree(&legacy);
        keep_separate(&legacy, &root).unwrap();
        assert_eq!(tree(&legacy), before);
        assert_eq!(
            examine(&legacy, &root),
            LegacyState::Decided(DECISION_KEPT_SEPARATE.into())
        );
        assert!(keep_separate(&legacy, &root).is_err());
        assert!(run(&legacy, &root).is_err());
        fs::remove_dir_all(&base).unwrap();
    }
}
