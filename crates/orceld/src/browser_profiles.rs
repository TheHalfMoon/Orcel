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
    /// The MCP session (client principal) whose owner-approved write
    /// created it, for display only; it grants nothing.
    pub created_by_client: Option<String>,
    /// A live session (in any orceld on the device) holds it now.
    pub in_use: bool,
}

impl ProfileInfo {
    pub(crate) fn to_json(&self) -> Value {
        json!({
            "name": self.name,
            "created_at_ms": self.created_at_ms,
            "created_by_client": self.created_by_client,
            "in_use": self.in_use,
        })
    }
}

/// A live session's hold on one profile: its data folder, its lock and
/// open handles on the store root, the profile folder and the data folder
/// that refuse deletion and renaming (so neither can be swapped for a
/// junction while the session runs), all released when the session ends
/// (the lease is dropped).
#[derive(Debug)]
pub(crate) struct ProfileLease {
    pub name: String,
    pub data_dir: PathBuf,
    _lock: File,
    _holds: Vec<File>,
}

/// Hold `path` open as a directory that cannot be deleted or renamed while
/// the handle lives, refusing it if it is not a real directory (the handle
/// is opened on the path itself, never through a reparse point).
#[cfg(windows)]
fn hold_dir(path: &Path) -> Result<File, ProviderError> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    // Data access (list), so the handle takes part in sharing checks; an
    // attributes-only handle would not block a rename.
    const FILE_LIST_DIRECTORY_AND_ATTRIBUTES: u32 = 0x0001 | 0x0080;
    const FILE_SHARE_READ: u32 = 0x0001;
    const FILE_SHARE_WRITE: u32 = 0x0002;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    let refused = || unavailable("a browser profile folder could not be held as a real directory");
    let file = std::fs::OpenOptions::new()
        .access_mode(FILE_LIST_DIRECTORY_AND_ATTRIBUTES)
        // No FILE_SHARE_DELETE: nothing can delete or rename it meanwhile.
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| refused())?;
    let metadata = file.metadata().map_err(|_| refused())?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(refused());
    }
    Ok(file)
}

/// Other systems: a handle and the same real-directory check (no
/// rename protection; persistent profiles run on Windows only).
#[cfg(not(windows))]
fn hold_dir(path: &Path) -> Result<File, ProviderError> {
    if !is_real_dir(path) {
        return Err(unavailable(
            "a browser profile folder could not be held as a real directory",
        ));
    }
    File::open(path).map_err(|_| unavailable("a browser profile folder could not be held"))
}

/// Whether a running browser engine holds the data folder: the engine's
/// own single-instance lock is present and held (on Windows `lockfile`,
/// opened by the running engine without write sharing; elsewhere the
/// `SingletonLock` link). A stale lock left by an engine that is gone is
/// not held, and the engine reuses it.
fn live_engine_holds(data: &Path) -> bool {
    if std::fs::symlink_metadata(data.join("SingletonLock")).is_ok() {
        return true;
    }
    let lockfile = data.join("lockfile");
    match std::fs::symlink_metadata(&lockfile) {
        Err(_) => false,
        Ok(_) => std::fs::OpenOptions::new()
            .write(true)
            .open(&lockfile)
            .is_err(),
    }
}

/// The store-wide lock (its name is never a profile name), held around a
/// create or delete so the profile count and names hold across processes.
const STORE_LOCK: &str = ".store";
/// How long a create or delete waits for another process's.
const STORE_LOCK_ATTEMPTS: u32 = 100;

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

    /// Take the store-wide lock, waiting a little for another process.
    fn store_lock(&self) -> Result<File, ProviderError> {
        let path = self.root.join(LOCKS_DIR).join(STORE_LOCK);
        for _ in 0..STORE_LOCK_ATTEMPTS {
            if let Some(lock) = try_lock_file(&path)? {
                return Ok(lock);
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        Err(unavailable(
            "another Orcel process is changing the browser profiles; retry",
        ))
    }

    /// The created time and creating client of profile `name`, when its
    /// folder, data folder and metadata are all whole and real; `None` for
    /// anything else.
    fn metadata(&self, name: &str) -> Option<(u64, Option<String>)> {
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
        let created = value.get("created_at_ms").and_then(Value::as_u64)?;
        let client = value
            .get("created_by_client")
            .and_then(Value::as_str)
            .map(str::to_owned);
        Some((created, client))
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
                let (created_at_ms, created_by_client) = self.metadata(&name)?;
                let in_use = self.in_use(&name);
                Some(ProfileInfo {
                    name,
                    created_at_ms,
                    created_by_client,
                    in_use,
                })
            })
            .collect()
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

    /// Create profile `name` for `client` (recorded for display): an empty
    /// data folder and its metadata, under the store-wide lock so the name
    /// and the count hold across processes. The caller asked the owner
    /// first.
    pub(crate) fn create(
        &self,
        name: &str,
        client: &str,
        now_ms: u64,
    ) -> Result<ProfileInfo, ProviderError> {
        let _store = self.store_lock()?;
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
                "created_by_client": client,
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
            created_by_client: Some(client.to_owned()),
            in_use: false,
        })
    }

    /// Check that profile `name` could be held now (it exists whole, no
    /// session holds it and no running engine holds its data folder),
    /// before any approval is asked for.
    pub(crate) fn check_acquire(&self, name: &str) -> Result<(), ProviderError> {
        check_name(name)?;
        if self.metadata(name).is_none() {
            return Err(ProviderError::new(
                FailureCode::TargetStale,
                format!("no browser profile named {name}; create it with browser_profile_create"),
            ));
        }
        if self.in_use(name) {
            return Err(in_use(name));
        }
        if live_engine_holds(&self.profile_dir(name).join(DATA_DIR)) {
            return Err(engine_running(name));
        }
        Ok(())
    }

    /// Hold profile `name` for one live session: refused when it does not
    /// exist whole, when another session (in any orceld) holds it, or when a
    /// running engine still holds its data folder.
    pub(crate) fn acquire(&self, name: &str) -> Result<ProfileLease, ProviderError> {
        check_name(name)?;
        if self.metadata(name).is_none() {
            return Err(ProviderError::new(
                FailureCode::TargetStale,
                format!("no browser profile named {name}; create it with browser_profile_create"),
            ));
        }
        let lock = try_lock_file(&self.lock_path(name))?.ok_or_else(|| in_use(name))?;
        let dir = self.profile_dir(name);
        let data_dir = dir.join(DATA_DIR);
        // Held first, then checked again: from here on neither folder can be
        // renamed or deleted, so the checks stay true for the session.
        let holds = vec![hold_dir(&self.root)?, hold_dir(&dir)?, hold_dir(&data_dir)?];
        if self.metadata(name).is_none() || !data_dir.starts_with(&self.root) {
            return Err(unavailable(format!(
                "the browser profile {name} is not a whole Orcel profile"
            )));
        }
        if live_engine_holds(&data_dir) {
            return Err(engine_running(name));
        }
        Ok(ProfileLease {
            name: name.to_owned(),
            data_dir,
            _lock: lock,
            _holds: holds,
        })
    }

    /// Check that profile `name` could be deleted now (a real folder of
    /// that name inside the store, whole or left incomplete, that no session
    /// holds), before any approval is asked for.
    pub(crate) fn check_delete(&self, name: &str) -> Result<(), ProviderError> {
        check_name(name)?;
        let dir = self.profile_dir(name);
        if !is_real_dir(&self.root) || !is_real_dir(&dir) || !dir.starts_with(&self.root) {
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

    /// Delete profile `name` and everything in it (also a folder an
    /// interrupted create left incomplete), never following a link, under
    /// its lock and the store-wide lock. The caller asked the owner first.
    /// Refused while a session holds it.
    pub(crate) fn delete(&self, name: &str) -> Result<(), ProviderError> {
        let _store = self.store_lock()?;
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

fn in_use(name: &str) -> ProviderError {
    ProviderError::new(
        FailureCode::TargetStale,
        format!(
            "the browser profile {name} is in use by another session; one session per profile at a time"
        ),
    )
}

fn engine_running(name: &str) -> ProviderError {
    ProviderError::new(
        FailureCode::TargetStale,
        format!("a browser engine still runs in the browser profile {name}; wait for it to end"),
    )
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
        let info = store.create("work", "client-a", 42).map_err(boxed)?;
        assert_eq!(info.created_at_ms, 42);
        assert!(
            store.create("work", "client-a", 43).is_err(),
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
        store.create("alpha", "client-a", 1).map_err(boxed)?;
        store.create("beta", "client-a", 2).map_err(boxed)?;
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
        store.create("gone", "client-a", 1).map_err(boxed)?;
        let lease = store.acquire("gone").map_err(boxed)?;
        std::fs::create_dir_all(lease.data_dir.join("Default"))?;
        std::fs::write(lease.data_dir.join("Default").join("Cookies"), b"x")?;
        drop(lease);
        store.delete("gone").map_err(boxed)?;
        assert!(!store.root().join("gone").exists());
        assert!(store.list().is_empty());
        assert!(store.delete("gone").is_err(), "already gone");
        // The name can be used again, from empty.
        store.create("gone", "client-a", 2).map_err(boxed)?;
        let lease = store.acquire("gone").map_err(boxed)?;
        assert!(!lease.data_dir.join("Default").exists());
        Ok(())
    }

    #[test]
    fn ob04_the_profile_count_is_bounded() -> Outcome {
        let root = Root::new("count")?;
        let store = root.store().map_err(boxed)?;
        for index in 0..MAX_PROFILES {
            store
                .create(&format!("p{index}"), "client-a", 1)
                .map_err(boxed)?;
        }
        assert_eq!(
            store
                .create("one-more", "client-a", 1)
                .map(|_| ())
                .map_err(|e| e.code),
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
            assert!(store.check_acquire(name).is_err(), "{name}");
            assert!(store.root().join(name).exists(), "left alone: {name}");
        }
        // An incomplete real folder of a valid name can be deleted (under
        // its lock), so a name an interrupted create left can be reused.
        for name in ["bare", "other", "nodata"] {
            store.delete(name).map_err(boxed)?;
            assert!(!store.root().join(name).exists(), "removed: {name}");
        }
        store.create("bare", "client-a", 1).map_err(boxed)?;
        Ok(())
    }

    /// The creating client is recorded for display, and listed.
    #[test]
    fn ob04_the_creating_client_is_recorded_for_display() -> Outcome {
        let root = Root::new("creator")?;
        let store = root.store().map_err(boxed)?;
        store.create("work", "mcp-session-7", 5).map_err(boxed)?;
        let listed = store.list();
        assert_eq!(
            listed.first().and_then(|p| p.created_by_client.as_deref()),
            Some("mcp-session-7")
        );
        assert_eq!(
            listed
                .first()
                .map(|p| p.to_json()["created_by_client"].clone()),
            Some(json!("mcp-session-7"))
        );
        Ok(())
    }

    /// Creates and deletes wait for the store-wide lock, so the count and
    /// names hold across processes.
    #[test]
    fn ob04_create_and_delete_take_the_store_wide_lock() -> Outcome {
        let root = Root::new("storelock")?;
        let store = root.store().map_err(boxed)?;
        store.create("kept", "client-a", 1).map_err(boxed)?;
        let held = try_lock_file(&store.root().join(LOCKS_DIR).join(STORE_LOCK))
            .map_err(boxed)?
            .ok_or("the store lock is free")?;
        assert_eq!(
            store
                .create("work", "client-a", 1)
                .map(|_| ())
                .map_err(|e| e.code),
            Err(FailureCode::ProviderUnavailable)
        );
        assert!(store.delete("kept").is_err());
        assert!(!store.root().join("work").exists());
        drop(held);
        store.create("work", "client-a", 1).map_err(boxed)?;
        store.delete("kept").map_err(boxed)?;
        Ok(())
    }

    /// A data folder a running engine still holds is refused, before any
    /// approval and at acquire; a stale engine lock is not.
    #[cfg(windows)]
    #[test]
    fn ob04_a_profile_a_running_engine_holds_is_refused() -> Outcome {
        use std::os::windows::fs::OpenOptionsExt;
        let root = Root::new("engine")?;
        let store = root.store().map_err(boxed)?;
        store.create("work", "client-a", 1).map_err(boxed)?;
        let lockfile = store.root().join("work").join(DATA_DIR).join("lockfile");
        // As the engine opens it: written, shared for reading only.
        let engine = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .share_mode(0x0001)
            .open(&lockfile)?;
        assert!(store.check_acquire("work").is_err());
        assert!(store.acquire("work").is_err());
        drop(engine);
        // The stale lock is left behind; it is not held, so the profile
        // is usable again.
        assert!(lockfile.exists());
        store.check_acquire("work").map_err(boxed)?;
        drop(store.acquire("work").map_err(boxed)?);
        Ok(())
    }

    /// While a session holds a profile, neither its folder nor its data
    /// folder can be renamed or deleted (no junction can be swapped in).
    #[cfg(windows)]
    #[test]
    fn ob04_held_profile_folders_cannot_be_swapped() -> Outcome {
        let root = Root::new("swap")?;
        let store = root.store().map_err(boxed)?;
        store.create("work", "client-a", 1).map_err(boxed)?;
        let dir = store.root().join("work");
        let lease = store.acquire("work").map_err(boxed)?;
        assert!(std::fs::rename(&dir, store.root().join("moved")).is_err());
        assert!(std::fs::rename(&lease.data_dir, dir.join("moved-data")).is_err());
        assert!(std::fs::remove_dir(&lease.data_dir).is_err());
        // Files inside stay writable for the engine.
        std::fs::write(lease.data_dir.join("Cookies"), b"x")?;
        std::fs::remove_file(lease.data_dir.join("Cookies"))?;
        drop(lease);
        std::fs::rename(&dir, store.root().join("moved"))?;
        std::fs::rename(store.root().join("moved"), &dir)?;
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
        store.create("inner", "client-a", 1).map_err(boxed)?;
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
