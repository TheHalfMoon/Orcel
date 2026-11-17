//! SG-000135 OB-04: persistent Orcel-managed browser profiles (FA-H, SH-8).
//!
//! A named profile is a folder under orceld's own protected browser state
//! (`<browser-profile>/live/named-profiles/<name>`), never a person's Chrome,
//! Edge or Chromium profile and never its user-data-dir:
//!
//! - `<name>/profile.json` records the name and when it was created;
//! - `<name>/data` is the engine's user-data-dir for every session that uses
//!   the profile, so its cookies and site storage persist across sessions
//!   and orceld restarts until the profile is deleted;
//! - `locks/<name>.lock` is held (an OS file lock, device-wide, across every
//!   orceld) by the one live session that uses the profile; a second
//!   session, here or in another orceld, is refused while it is held, and a
//!   crashed orceld's lock frees itself.
//!
//! Every path is built here from a checked name (lowercase letters, digits
//! and inner hyphens, at most 32), so nothing a caller says becomes a path;
//! the store root and every profile folder must be real directories (never
//! a junction, symbolic link or other reparse point), and every data folder
//! must lie inside the store root. Removal never follows a reparse point.
//!
//! Profiles are created and deleted only through owner-approved writes
//! (a fresh SOFT approval each, asked by `live_dispatch`); listing and using
//! an existing profile ask nothing. Sessions without a profile stay
//! ephemeral, the default. The store grants nothing: profile gate, policy,
//! takeover gate and approval broker still decide every action.

use crate::browser_broker::{is_reparse, real_dir, remove_tree, try_lock_file};
use orcel_contracts::FailureCode;
use orcel_provider_fs::ProviderError;
use serde_json::{json, Value};
use std::fs::File;
use std::path::{Path, PathBuf};

/// The longest profile name.
pub(crate) const MAX_NAME_CHARS: usize = 32;
/// The most named profiles one store holds.
pub(crate) const MAX_PROFILES: usize = 16;
/// The metadata file of each profile.
const METADATA_FILE: &str = "profile.json";
/// The metadata schema.
const METADATA_SCHEMA: &str = "orcel-ob04-profile/1";
/// The engine user-data-dir inside each profile (the host checks the leaf).
const DATA_DIR: &str = "data";
/// The folder of per-profile lock files.
const LOCKS_DIR: &str = "locks";
/// The largest metadata file read back.
const MAX_METADATA_BYTES: u64 = 4096;

fn invalid(message: impl Into<String>) -> ProviderError {
    ProviderError::new(FailureCode::InvalidRequest, message)
}

fn unavailable(message: impl Into<String>) -> ProviderError {
    ProviderError::new(FailureCode::ProviderUnavailable, message)
}

/// Check a profile name: 1 to 32 lowercase ASCII letters, digits and inner
/// hyphens, starting with a letter or digit and not ending with a hyphen.
pub(crate) fn check_name(name: &str) -> Result<(), ProviderError> {
    let bytes = name.as_bytes();
    let well_formed = !bytes.is_empty()
        && bytes.len() <= MAX_NAME_CHARS
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        && bytes.first().is_some_and(|b| *b != b'-')
        && bytes.last().is_some_and(|b| *b != b'-');
    if !well_formed {
        return Err(invalid(format!(
            "profile is 1 to {MAX_NAME_CHARS} lowercase letters, digits and inner hyphens"
        )));
    }
    Ok(())
}

/// Whether `path` is a real directory (not a reparse point), without
/// creating anything.
fn is_real_dir(path: &Path) -> bool {
    matches!(
        std::fs::symlink_metadata(path),
        Ok(metadata) if metadata.is_dir() && !is_reparse(&metadata)
    )
}

/// One profile as `browser_profiles` lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProfileInfo {
    pub name: String,
    pub created_at_ms: u64,
    /// A live session (in any orceld on the device) holds it now.
    pub in_use: bool,
}

impl ProfileInfo {
    pub(crate) fn to_json(&self) -> Value {
        json!({
            "name": self.name,
            "created_at_ms": self.created_at_ms,
            "in_use": self.in_use,
        })
    }
}

/// A live session's hold on one profile: its data folder and its lock,
/// released when the session ends (the lease is dropped).
#[derive(Debug)]
pub(crate) struct ProfileLease {
    pub name: String,
    pub data_dir: PathBuf,
    _lock: File,
}

/// The named profiles under one root in orceld's protected browser state.
#[derive(Debug, Clone)]
pub(crate) struct ProfileStore {
    root: PathBuf,
}

impl ProfileStore {
    /// Open (creating if needed) the store at `root`, orceld's own state.
    /// A root or lock folder that is a link or junction is refused.
    pub(crate) fn open(root: PathBuf) -> Result<Self, ProviderError> {
        real_dir(&root)?;
        real_dir(&root.join(LOCKS_DIR))?;
        Ok(Self { root })
    }

    #[cfg(test)]
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    fn profile_dir(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    fn lock_path(&self, name: &str) -> PathBuf {
        self.root.join(LOCKS_DIR).join(format!("{name}.lock"))
    }

    /// The created time of profile `name`, when its folder, data folder and
    /// metadata are all whole and real; `None` for anything else.
    fn created_at(&self, name: &str) -> Option<u64> {
        let dir = self.profile_dir(name);
        let data = dir.join(DATA_DIR);
        if !is_real_dir(&self.root) || !is_real_dir(&dir) || !is_real_dir(&data) {
            return None;
        }
        if !data.starts_with(&self.root) {
            return None;
        }
        let metadata_path = dir.join(METADATA_FILE);
        match std::fs::symlink_metadata(&metadata_path) {
            Ok(meta)
                if meta.is_file() && !is_reparse(&meta) && meta.len() <= MAX_METADATA_BYTES => {}
            _ => return None,
        }
        let raw = std::fs::read(&metadata_path).ok()?;
        let value: Value = serde_json::from_slice(&raw).ok()?;
        if value.get("schema").and_then(Value::as_str) != Some(METADATA_SCHEMA)
            || value.get("name").and_then(Value::as_str) != Some(name)
        {
            return None;
        }
        value.get("created_at_ms").and_then(Value::as_u64)
    }

    /// Whether a live session holds profile `name` now.
    fn in_use(&self, name: &str) -> bool {
        // Probing takes the lock for a moment and releases it at once.
        !matches!(try_lock_file(&self.lock_path(name)), Ok(Some(_)))
    }

    /// Every whole profile, by name. Folders that are not a well-formed,
    /// real, whole profile are left out (and left alone).
    pub(crate) fn list(&self) -> Vec<ProfileInfo> {
        let Ok(entries) = std::fs::read_dir(&self.root) else {
            return Vec::new();
        };
        let mut names: Vec<String> = entries
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name != LOCKS_DIR && check_name(name).is_ok())
            .collect();
        names.sort();
        names
            .into_iter()
            .filter_map(|name| {
                let created_at_ms = self.created_at(&name)?;
                let in_use = self.in_use(&name);
                Some(ProfileInfo {
                    name,
                    created_at_ms,
                    in_use,
                })
            })
            .collect()
    }

    /// Whether profile `name` exists, whole.
    pub(crate) fn exists(&self, name: &str) -> bool {
        check_name(name).is_ok() && self.created_at(name).is_some()
    }

    /// Check that profile `name` could be created now (the name, the count,
    /// no folder by that name), before any approval is asked for.
    pub(crate) fn check_create(&self, name: &str) -> Result<(), ProviderError> {
        check_name(name)?;
        if std::fs::symlink_metadata(self.profile_dir(name)).is_ok() {
            return Err(invalid(format!(
                "a browser profile named {name} already exists"
            )));
        }
        if self.list().len() >= MAX_PROFILES {
            return Err(ProviderError::new(
                FailureCode::OutputLimit,
                format!("Orcel keeps at most {MAX_PROFILES} browser profiles; delete one first"),
            ));
        }
        Ok(())
    }

    /// Create profile `name`: an empty data folder and its metadata. The
    /// caller asked the owner first.
    pub(crate) fn create(&self, name: &str, now_ms: u64) -> Result<ProfileInfo, ProviderError> {
        self.check_create(name)?;
        let dir = self.profile_dir(name);
        std::fs::create_dir(&dir)
            .map_err(|_| invalid(format!("the browser profile {name} could not be created")))?;
        let made = (|| {
            real_dir(&dir)?;
            real_dir(&dir.join(DATA_DIR))?;
            let metadata = json!({
                "schema": METADATA_SCHEMA,
                "name": name,
                "created_at_ms": now_ms,
            });
            std::fs::write(dir.join(METADATA_FILE), metadata.to_string())
                .map_err(|_| unavailable("the browser profile's metadata could not be written"))
        })();
        if let Err(error) = made {
            remove_tree(&dir);
            return Err(error);
        }
        Ok(ProfileInfo {
            name: name.to_owned(),
            created_at_ms: now_ms,
            in_use: false,
        })
    }

    /// Hold profile `name` for one live session: refused when it does not
    /// exist whole, or when another session (in any orceld) holds it.
    pub(crate) fn acquire(&self, name: &str) -> Result<ProfileLease, ProviderError> {
        check_name(name)?;
        if self.created_at(name).is_none() {
            return Err(ProviderError::new(
                FailureCode::TargetStale,
                format!("no browser profile named {name}; create it with browser_profile_create"),
            ));
        }
        let lock = try_lock_file(&self.lock_path(name))?.ok_or_else(|| {
            ProviderError::new(
                FailureCode::TargetStale,
                format!("the browser profile {name} is in use by another session; one session per profile at a time"),
            )
        })?;
        let data_dir = self.profile_dir(name).join(DATA_DIR);
        // Checked again under the lock: still whole, still real, still inside.
        if self.created_at(name).is_none() || !data_dir.starts_with(&self.root) {
            return Err(unavailable(format!(
                "the browser profile {name} is not a whole Orcel profile"
            )));
        }
        Ok(ProfileLease {
            name: name.to_owned(),
            data_dir,
            _lock: lock,
        })
    }

    /// Check that profile `name` could be deleted now (it exists and no
    /// session holds it), before any approval is asked for.
    pub(crate) fn check_delete(&self, name: &str) -> Result<(), ProviderError> {
        check_name(name)?;
        if !self.exists(name) {
            return Err(ProviderError::new(
                FailureCode::TargetStale,
                format!("no browser profile named {name}"),
            ));
        }
        if self.in_use(name) {
            return Err(ProviderError::new(
                FailureCode::TargetStale,
                format!("the browser profile {name} is in use by a session; close it first"),
            ));
        }
        Ok(())
    }

    /// Delete profile `name` and everything in it, never following a link.
    /// The caller asked the owner first. Refused while a session holds it.
    pub(crate) fn delete(&self, name: &str) -> Result<(), ProviderError> {
        self.check_delete(name)?;
        let lock_path = self.lock_path(name);
        let lock = try_lock_file(&lock_path)?.ok_or_else(|| {
            ProviderError::new(
                FailureCode::TargetStale,
                format!("the browser profile {name} is in use by a session; close it first"),
            )
        })?;
        if !remove_tree(&self.profile_dir(name)) {
            return Err(unavailable(format!(
                "the browser profile {name} could not be removed completely; retry"
            )));
        }
        drop(lock);
        let _ = std::fs::remove_file(&lock_path);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Outcome = Result<(), Box<dyn std::error::Error>>;

    struct Root(PathBuf);

    impl Root {
        fn new(label: &str) -> Result<Self, std::io::Error> {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|since| since.as_nanos())
                .unwrap_or(0);
            let root = std::env::temp_dir().join(format!(
                "orcel-ob04-profiles-{label}-{}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(&root)?;
            Ok(Self(root))
        }

        fn store(&self) -> Result<ProfileStore, ProviderError> {
            ProfileStore::open(self.0.join("named-profiles"))
        }
    }

    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn boxed(error: ProviderError) -> Box<dyn std::error::Error> {
        format!("{:?}: {}", error.code, error.message).into()
    }

    #[test]
    fn ob04_profile_names_are_short_lowercase_words() {
        for good in ["work", "a", "shop-2", "0x", "a-b-c", &"a".repeat(32)] {
            assert!(check_name(good).is_ok(), "{good}");
        }
        for bad in [
            "",
            "-a",
            "a-",
            "Work",
            "a b",
            "a/b",
            "a\\b",
            "..",
            ".",
            "a.b",
            "con:",
            "café",
            "locks!",
            &"a".repeat(33),
        ] {
            assert!(check_name(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn ob04_a_profile_is_created_listed_held_by_one_session_and_kept_after() -> Outcome {
        let root = Root::new("cycle")?;
        let store = root.store().map_err(boxed)?;
        assert!(store.list().is_empty());
        let info = store.create("work", 42).map_err(boxed)?;
        assert_eq!(info.created_at_ms, 42);
        assert!(
            store.create("work", 43).is_err(),
            "no second profile of one name"
        );
        let listed = store.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed.first().map(|p| p.name.as_str()), Some("work"));
        assert_eq!(listed.first().map(|p| p.in_use), Some(false));

        let lease = store.acquire("work").map_err(boxed)?;
        assert!(lease.data_dir.starts_with(store.root()));
        assert!(lease.data_dir.ends_with("work\\data") || lease.data_dir.ends_with("work/data"));
        std::fs::write(lease.data_dir.join("Cookies"), b"session=kept")?;
        // One live session per profile; deleting it is refused meanwhile.
        assert_eq!(
            store.acquire("work").map(|_| ()).map_err(|e| e.code),
            Err(FailureCode::TargetStale)
        );
        assert!(store.check_delete("work").is_err());
        assert!(store.delete("work").is_err());
        assert_eq!(store.list().first().map(|p| p.in_use), Some(true));
        drop(lease);

        // The next session sees what the last one left.
        let again = store.acquire("work").map_err(boxed)?;
        assert_eq!(
            std::fs::read(again.data_dir.join("Cookies"))?,
            b"session=kept"
        );
        drop(again);
        assert!(store.acquire("missing").is_err());
        Ok(())
    }

    #[test]
    fn ob04_two_profiles_share_nothing() -> Outcome {
        let root = Root::new("isolate")?;
        let store = root.store().map_err(boxed)?;
        store.create("alpha", 1).map_err(boxed)?;
        store.create("beta", 2).map_err(boxed)?;
        let alpha = store.acquire("alpha").map_err(boxed)?;
        let beta = store.acquire("beta").map_err(boxed)?;
        assert_ne!(alpha.data_dir, beta.data_dir);
        assert!(!alpha.data_dir.starts_with(&beta.data_dir));
        assert!(!beta.data_dir.starts_with(&alpha.data_dir));
        std::fs::write(alpha.data_dir.join("Cookies"), b"alpha")?;
        assert!(!beta.data_dir.join("Cookies").exists());
        Ok(())
    }

    #[test]
    fn ob04_deleting_removes_the_profile_and_its_data() -> Outcome {
        let root = Root::new("delete")?;
        let store = root.store().map_err(boxed)?;
        store.create("gone", 1).map_err(boxed)?;
        let lease = store.acquire("gone").map_err(boxed)?;
        std::fs::create_dir_all(lease.data_dir.join("Default"))?;
        std::fs::write(lease.data_dir.join("Default").join("Cookies"), b"x")?;
        drop(lease);
        store.delete("gone").map_err(boxed)?;
        assert!(!store.root().join("gone").exists());
        assert!(store.list().is_empty());
        assert!(store.delete("gone").is_err(), "already gone");
        // The name can be used again, from empty.
        store.create("gone", 2).map_err(boxed)?;
        let lease = store.acquire("gone").map_err(boxed)?;
        assert!(!lease.data_dir.join("Default").exists());
        Ok(())
    }

    #[test]
    fn ob04_the_profile_count_is_bounded() -> Outcome {
        let root = Root::new("count")?;
        let store = root.store().map_err(boxed)?;
        for index in 0..MAX_PROFILES {
            store.create(&format!("p{index}"), 1).map_err(boxed)?;
        }
        assert_eq!(
            store.create("one-more", 1).map(|_| ()).map_err(|e| e.code),
            Err(FailureCode::OutputLimit)
        );
        Ok(())
    }

    #[test]
    fn ob04_folders_that_are_not_whole_profiles_are_ignored_and_never_used() -> Outcome {
        let root = Root::new("foreign")?;
        let store = root.store().map_err(boxed)?;
        // A folder with no metadata, one with another name's metadata, and
        // one whose data folder is missing.
        std::fs::create_dir_all(store.root().join("bare").join("data"))?;
        std::fs::create_dir_all(store.root().join("other").join("data"))?;
        std::fs::write(
            store.root().join("other").join(METADATA_FILE),
            json!({"schema": METADATA_SCHEMA, "name": "elsewhere", "created_at_ms": 1}).to_string(),
        )?;
        std::fs::create_dir_all(store.root().join("nodata"))?;
        std::fs::write(
            store.root().join("nodata").join(METADATA_FILE),
            json!({"schema": METADATA_SCHEMA, "name": "nodata", "created_at_ms": 1}).to_string(),
        )?;
        assert!(store.list().is_empty());
        for name in ["bare", "other", "nodata"] {
            assert!(store.acquire(name).is_err(), "{name}");
            assert!(store.delete(name).is_err(), "{name}");
            assert!(store.root().join(name).exists(), "left alone: {name}");
        }
        Ok(())
    }

    #[cfg(windows)]
    fn junction(link: &Path, target: &Path) -> bool {
        std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    #[cfg(windows)]
    #[test]
    fn ob04_a_linked_profile_or_store_is_refused_and_never_followed() -> Outcome {
        let root = Root::new("links")?;
        let store = root.store().map_err(boxed)?;
        // A personal folder the link points at, with a file to protect.
        let outside = root.0.join("personal");
        std::fs::create_dir_all(outside.join("data"))?;
        std::fs::write(outside.join("data").join("Cookies"), b"personal")?;
        std::fs::write(
            outside.join(METADATA_FILE),
            json!({"schema": METADATA_SCHEMA, "name": "linked", "created_at_ms": 1}).to_string(),
        )?;
        if !junction(&store.root().join("linked"), &outside) {
            return Ok(());
        }
        assert!(store.list().iter().all(|p| p.name != "linked"));
        assert!(store.acquire("linked").is_err());
        assert!(store.delete("linked").is_err());
        assert_eq!(
            std::fs::read(outside.join("data").join("Cookies"))?,
            b"personal"
        );
        // A data folder that is a junction is refused too.
        store.create("inner", 1).map_err(boxed)?;
        let data = store.root().join("inner").join("data");
        std::fs::remove_dir(&data)?;
        if junction(&data, &outside.join("data")) {
            assert!(store.acquire("inner").is_err());
            assert!(store.list().iter().all(|p| p.name != "inner"));
        }
        // A store root that is a junction is refused at open.
        let linked_root = root.0.join("linked-root");
        if junction(&linked_root, &outside) {
            assert!(ProfileStore::open(linked_root).is_err());
        }
        assert_eq!(
            std::fs::read(outside.join("data").join("Cookies"))?,
            b"personal"
        );
        Ok(())
    }
}
