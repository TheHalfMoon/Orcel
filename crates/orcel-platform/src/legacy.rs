//! The gate on state left at the earlier Windows root, `%LOCALAPPDATA%\Orcel`.
//!
//! Earlier builds kept their state there. Starting fresh under the current root would silently
//! abandon it: approvals, trust, audit history, secrets. So until a person has decided what
//! happens to it, `orceld` refuses to start. `orcel state` shows what is there and records the
//! decision. Nothing here reads that state as state, changes it or deletes it.

use crate::paths::{absolute_var, StateLayout};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Written before a migration places its first file, removed once the decision is recorded.
pub const MIGRATION_IN_PROGRESS: &str = "legacy-migration-in-progress";
/// First line of the decision file.
pub const DECISION_SCHEMA: &str = "orcel-legacy-state-decision-v1";
pub const DECISION_MIGRATED: &str = "migrated";
pub const DECISION_KEPT_SEPARATE: &str = "kept-separate";

/// Directories of short-lived runs, whose contents are nobody's data. Empty ones from an old
/// test run are all some machines have at the earlier root.
const TRANSIENT: [&str; 4] = [
    "contained-runs",
    "document-parse",
    "sg-000012-qualification",
    "run",
];

/// What the earlier root holds, as far as starting is concerned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegacyState {
    /// No earlier root on this layout, or nothing in it but transient runs.
    None,
    /// A person decided, by [`DECISION_MIGRATED`] or [`DECISION_KEPT_SEPARATE`].
    Decided(String),
    /// Data is there, and nobody has decided. Holds the first file found.
    Undecided(PathBuf),
    /// It could not be read, so it can't be shown to be empty.
    Unreadable(PathBuf, String),
}

/// The earlier root of `layout`. Only Windows moved.
pub fn legacy_root_for(
    layout: StateLayout,
    lookup: &dyn Fn(&str) -> Option<OsString>,
) -> Option<PathBuf> {
    match layout {
        StateLayout::Windows => {
            absolute_var(layout, lookup, "LOCALAPPDATA").map(|local| local.join("Orcel"))
        }
        StateLayout::MacOs | StateLayout::Xdg => None,
    }
}

/// The earlier root of the running OS's layout. On Windows a hidden or unusable `LOCALAPPDATA`
/// falls back to the known folder: a parent that doesn't pass the variable must not make state
/// there invisible.
pub fn legacy_root_from(lookup: &dyn Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    let layout = StateLayout::current()?;
    legacy_root_for(layout, lookup).or_else(|| match layout {
        StateLayout::Windows => known_local_app_data().map(|local| local.join("Orcel")),
        StateLayout::MacOs | StateLayout::Xdg => None,
    })
}

#[cfg(windows)]
fn known_local_app_data() -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::UI::Shell::{FOLDERID_LocalAppData, SHGetKnownFolderPath, KF_FLAG_DEFAULT};
    // SAFETY: the folder id is a valid constant, and no token means the current user. On success
    // the result is a NUL-terminated string this function frees, once, after copying it.
    unsafe {
        let text = SHGetKnownFolderPath(&FOLDERID_LocalAppData, KF_FLAG_DEFAULT, None).ok()?;
        let path = PathBuf::from(OsString::from_wide(text.as_wide()));
        CoTaskMemFree(Some(text.0.cast()));
        Some(path)
    }
}

#[cfg(not(windows))]
fn known_local_app_data() -> Option<PathBuf> {
    None
}

/// Where the decision is recorded, in the private current root.
pub fn decision_file(state_root: &Path) -> PathBuf {
    state_root.join("state").join("legacy-state-decision.txt")
}

/// The recorded decision. A file that isn't exactly a decision is no decision.
pub fn read_decision(state_root: &Path) -> Option<String> {
    let text = std::fs::read_to_string(decision_file(state_root)).ok()?;
    let mut lines = text.lines();
    if lines.next() != Some(DECISION_SCHEMA) {
        return None;
    }
    lines
        .next()
        .filter(|decision| [DECISION_MIGRATED, DECISION_KEPT_SEPARATE].contains(decision))
        .map(str::to_owned)
}

/// The first file under `dir` outside the transient directories. A link is reported as data,
/// not followed: it could point anywhere.
fn first_file(dir: &Path, top: bool) -> Result<Option<PathBuf>, (PathBuf, String)> {
    let entries = std::fs::read_dir(dir).map_err(|error| (dir.to_owned(), error.to_string()))?;
    for entry in entries {
        let entry = entry.map_err(|error| (dir.to_owned(), error.to_string()))?;
        let path = entry.path();
        if top && TRANSIENT.iter().any(|name| entry.file_name() == *name) {
            continue;
        }
        let metadata =
            std::fs::symlink_metadata(&path).map_err(|error| (path.clone(), error.to_string()))?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            if let Some(found) = first_file(&path, false)? {
                return Ok(Some(found));
            }
        } else {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

/// What `legacy` holds, given the decision recorded under `state_root`. A decision comes first,
/// so a person who has decided is never held up by what can't be read there. Next, an unfinished
/// migration: even with the earlier root gone, what it placed is only part of the state.
pub fn examine(legacy: &Path, state_root: &Path) -> LegacyState {
    if let Some(decision) = read_decision(state_root) {
        return LegacyState::Decided(decision);
    }
    let in_progress = state_root.join(MIGRATION_IN_PROGRESS);
    if std::fs::symlink_metadata(&in_progress).is_ok() {
        return LegacyState::Undecided(in_progress);
    }
    match std::fs::symlink_metadata(legacy) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return LegacyState::None,
        Err(error) => return LegacyState::Unreadable(legacy.to_owned(), error.to_string()),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return LegacyState::Undecided(legacy.to_owned());
        }
        Ok(_) => {}
    }
    match first_file(legacy, true) {
        Ok(None) => LegacyState::None,
        Ok(Some(file)) => LegacyState::Undecided(file),
        Err((path, error)) => LegacyState::Unreadable(path, error),
    }
}

/// `Ok` when starting abandons nothing. `state_root` is the current root.
pub fn gate(lookup: &dyn Fn(&str) -> Option<OsString>, state_root: &Path) -> Result<(), String> {
    if StateLayout::current() != Some(StateLayout::Windows) {
        return Ok(());
    }
    if read_decision(state_root).is_some() {
        return Ok(());
    }
    let Some(legacy) = legacy_root_from(lookup) else {
        return Err(
            "the earlier Orcel state location can't be found, so nothing there can be shown to be \
             decided. Nothing was changed"
                .into(),
        );
    };
    match examine(&legacy, state_root) {
        LegacyState::None | LegacyState::Decided(_) => Ok(()),
        LegacyState::Undecided(file) if file.ends_with(MIGRATION_IN_PROGRESS) => Err(format!(
            "a migration of earlier Orcel state was interrupted, so {} holds only part of it. \
             Nothing was changed. Run `orcel state migrate` to finish it, or `orcel state \
             keep-separate`, which says what to remove if that can't be done",
            state_root.display()
        )),
        LegacyState::Undecided(file) => Err(format!(
            "earlier Orcel state is at {} (for example {}), and nobody has decided what happens \
             to it. Nothing was changed. Run `orcel state status`, then `orcel state migrate` or \
             `orcel state keep-separate`",
            legacy.display(),
            file.display()
        )),
        LegacyState::Unreadable(path, error) => Err(format!(
            "earlier Orcel state at {} can't be read ({error}), so it can't be shown to be empty. \
             Nothing was changed. Run `orcel state status`",
            path.display()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn scratch(label: &str) -> (PathBuf, PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!(
            "orcel-legacy-{label}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
        ));
        let legacy = base.join("Orcel");
        let root = base.join(".orcel");
        fs::create_dir_all(&legacy).unwrap();
        fs::create_dir_all(root.join("state")).unwrap();
        (base, legacy, root)
    }

    #[test]
    fn only_windows_has_an_earlier_root() {
        let local = if cfg!(windows) {
            r"C:\Users\u\AppData\Local"
        } else {
            "/home/u/local"
        };
        let lookup = |name: &str| (name == "LOCALAPPDATA").then(|| OsString::from(local));
        assert_eq!(
            legacy_root_for(StateLayout::Windows, &lookup),
            Some(PathBuf::from(local).join("Orcel"))
        );
        assert_eq!(legacy_root_for(StateLayout::Xdg, &lookup), None);
        assert_eq!(legacy_root_for(StateLayout::MacOs, &lookup), None);
        assert_eq!(legacy_root_for(StateLayout::Windows, &|_| None), None);
    }

    #[test]
    fn nothing_there_passes_and_so_do_empty_folders_and_transient_runs() {
        let (base, legacy, root) = scratch("empty");
        assert_eq!(examine(&base.join("absent"), &root), LegacyState::None);
        assert_eq!(examine(&legacy, &root), LegacyState::None);
        fs::create_dir_all(legacy.join("secrets")).unwrap();
        fs::create_dir_all(legacy.join("contained-runs").join("old")).unwrap();
        fs::write(legacy.join("contained-runs").join("old").join("x"), "x").unwrap();
        fs::create_dir_all(legacy.join("run")).unwrap();
        fs::write(legacy.join("run").join("last-exit.json"), "{}").unwrap();
        assert_eq!(examine(&legacy, &root), LegacyState::None);
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn data_is_undecided_however_deep_it_is() {
        let (base, legacy, root) = scratch("data");
        let deep = legacy.join("state").join("secrets");
        fs::create_dir_all(&deep).unwrap();
        fs::write(deep.join("key"), "secret").unwrap();
        assert_eq!(
            examine(&legacy, &root),
            LegacyState::Undecided(deep.join("key"))
        );
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn a_decision_opens_the_gate_and_junk_does_not() {
        let (base, legacy, root) = scratch("decision");
        fs::write(legacy.join("trust.jsonl"), "{}").unwrap();
        for junk in [
            "",
            "kept-separate\n",
            "orcel-legacy-state-decision-v1\n",
            "orcel-legacy-state-decision-v1\nwhatever\n",
            "orcel-legacy-state-decision-v2\nkept-separate\n",
        ] {
            fs::write(decision_file(&root), junk).unwrap();
            assert!(
                matches!(examine(&legacy, &root), LegacyState::Undecided(_)),
                "{junk:?}"
            );
        }
        fs::write(
            decision_file(&root),
            format!("{DECISION_SCHEMA}\n{DECISION_KEPT_SEPARATE}\n"),
        )
        .unwrap();
        assert_eq!(
            examine(&legacy, &root),
            LegacyState::Decided(DECISION_KEPT_SEPARATE.into())
        );
        fs::remove_dir_all(&base).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_link_is_data_and_is_not_followed() {
        let (base, legacy, root) = scratch("link");
        let elsewhere = base.join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, legacy.join("state")).unwrap();
        assert_eq!(
            examine(&legacy, &root),
            LegacyState::Undecided(legacy.join("state"))
        );
        let moved = base.join("Orcel-link");
        std::os::unix::fs::symlink(&elsewhere, &moved).unwrap();
        assert!(matches!(examine(&moved, &root), LegacyState::Undecided(_)));
        fs::remove_dir_all(&base).unwrap();
    }
}
