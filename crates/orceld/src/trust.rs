use orcel_contracts::FailureCode;
use orcel_platform::{files, paths, PlatformError};
use orcel_provider_fs::ProviderError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const TRUST_SCHEMA: &str = "orcel-trust-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredTrust {
    schema: String,
    workspace_id: String,
    trusted: bool,
    revision: u64,
    provenance_method: String,
    updated_at_ms: u64,
    policy_revision: String,
    prev_checksum: String,
    checksum: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustStatus {
    pub workspace_id: String,
    pub trusted: bool,
    pub revision: u64,
    pub provenance_method: String,
    pub updated_at_ms: u64,
    pub policy_revision: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustHistoryEntry {
    pub workspace_id: String,
    pub trusted: bool,
    pub revision: u64,
    pub provenance_method: String,
    pub updated_at_ms: u64,
    pub policy_revision: String,
}

#[derive(Debug)]
pub struct TrustStore {
    path: std::path::PathBuf,
    records: BTreeMap<String, StoredTrust>,
    history: Vec<StoredTrust>,
    tip: String,
}

impl TrustStore {
    pub fn load_or_create(path: std::path::PathBuf) -> Self {
        let mut store = Self {
            path,
            records: BTreeMap::new(),
            history: Vec::new(),
            tip: String::from("GENESIS"),
        };
        if store.path.is_file() {
            if let Ok(text) = std::fs::read_to_string(&store.path) {
                let mut tip = String::from("GENESIS");
                for line in text.lines() {
                    if line.trim().is_empty() {
                        continue;
                    }
                    let Ok(record) = serde_json::from_str::<StoredTrust>(line) else {
                        break;
                    };
                    if record.schema != TRUST_SCHEMA || !verify_checksum(&record, &tip) {
                        break;
                    }
                    tip = record.checksum.clone();
                    store
                        .records
                        .insert(record.workspace_id.clone(), record.clone());
                    store.history.push(record);
                }
                store.tip = tip;
            }
        } else if let Some(parent) = store.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        store
    }

    pub fn get(&self, workspace_id: &str) -> TrustStatus {
        if let Some(record) = self.records.get(workspace_id) {
            TrustStatus {
                workspace_id: record.workspace_id.clone(),
                trusted: record.trusted,
                revision: record.revision,
                provenance_method: record.provenance_method.clone(),
                updated_at_ms: record.updated_at_ms,
                policy_revision: record.policy_revision.clone(),
            }
        } else {
            TrustStatus {
                workspace_id: workspace_id.to_owned(),
                trusted: false,
                revision: 0,
                provenance_method: String::from("none"),
                updated_at_ms: 0,
                policy_revision: String::from("none"),
            }
        }
    }

    pub fn grant(
        &mut self,
        workspace_id: &str,
        policy_revision: &str,
        provenance_method: &str,
        now_ms: u64,
    ) -> Result<TrustStatus, ProviderError> {
        self.apply(
            workspace_id,
            true,
            policy_revision,
            provenance_method,
            now_ms,
        )
    }

    pub fn revoke_workspace(
        &mut self,
        workspace_id: &str,
        policy_revision: &str,
        provenance_method: &str,
        now_ms: u64,
    ) -> Result<TrustStatus, ProviderError> {
        self.apply(
            workspace_id,
            false,
            policy_revision,
            provenance_method,
            now_ms,
        )
    }

    fn apply(
        &mut self,
        workspace_id: &str,
        trusted: bool,
        policy_revision: &str,
        provenance_method: &str,
        now_ms: u64,
    ) -> Result<TrustStatus, ProviderError> {
        if workspace_id.trim().is_empty() {
            return Err(ProviderError::new(
                FailureCode::InvalidRequest,
                "trust workspace id is empty",
            ));
        }
        if policy_revision.trim().is_empty() {
            return Err(ProviderError::new(
                FailureCode::InvalidRequest,
                "trust policy revision is empty",
            ));
        }
        if provenance_method.trim().is_empty() {
            return Err(ProviderError::new(
                FailureCode::InvalidRequest,
                "trust provenance method is empty",
            ));
        }
        let revision = self
            .records
            .get(workspace_id)
            .map(|record| record.revision.saturating_add(1))
            .unwrap_or(1);
        let mut record = StoredTrust {
            schema: TRUST_SCHEMA.to_owned(),
            workspace_id: workspace_id.to_owned(),
            trusted,
            revision,
            provenance_method: provenance_method.to_owned(),
            updated_at_ms: now_ms,
            policy_revision: policy_revision.to_owned(),
            prev_checksum: self.tip.clone(),
            checksum: String::new(),
        };
        record.checksum = record_checksum(&record);
        self.tip = record.checksum.clone();
        self.append_to_file(&record)?;
        self.records.insert(workspace_id.to_owned(), record.clone());
        self.history.push(record.clone());
        Ok(TrustStatus {
            workspace_id: record.workspace_id,
            trusted: record.trusted,
            revision: record.revision,
            provenance_method: record.provenance_method,
            updated_at_ms: record.updated_at_ms,
            policy_revision: record.policy_revision,
        })
    }

    fn append_to_file(&self, record: &StoredTrust) -> Result<(), ProviderError> {
        use std::io::Write as _;
        let mut file = files::open_private_append(&self.path).map_err(|error| {
            ProviderError::new(
                FailureCode::ApprovalUnavailable,
                format!("persist trust record: {error}"),
            )
        })?;
        serde_json::to_writer(&mut file, record).map_err(|error| {
            ProviderError::new(
                FailureCode::ApprovalUnavailable,
                format!("serialize trust record: {error}"),
            )
        })?;
        file.write_all(b"\n").map_err(|error| {
            ProviderError::new(
                FailureCode::ApprovalUnavailable,
                format!("persist trust record: {error}"),
            )
        })?;
        file.flush().map_err(|error| {
            ProviderError::new(
                FailureCode::ApprovalUnavailable,
                format!("persist trust record: {error}"),
            )
        })?;
        Ok(())
    }

    pub fn history(&self, limit: usize) -> Vec<TrustHistoryEntry> {
        let bound = limit.clamp(1, 200);
        self.history
            .iter()
            .rev()
            .take(bound)
            .map(|record| TrustHistoryEntry {
                workspace_id: record.workspace_id.clone(),
                trusted: record.trusted,
                revision: record.revision,
                provenance_method: record.provenance_method.clone(),
                updated_at_ms: record.updated_at_ms,
                policy_revision: record.policy_revision.clone(),
            })
            .collect()
    }
}

/// `ORCEL_TRUST_PATH`, else `trust.jsonl` in the private per-user Orcel state
/// root (XP-01B). Fails closed when the override is empty, relative or not in a
/// private directory, or when the root cannot be resolved or is not private; it
/// never falls back to the shared temp directory.
pub fn default_trust_path() -> Result<std::path::PathBuf, PlatformError> {
    default_trust_path_from(&|name| std::env::var_os(name))
}

/// [`default_trust_path`] with the environment read through `lookup`.
pub fn default_trust_path_from(
    lookup: &dyn Fn(&str) -> Option<std::ffi::OsString>,
) -> Result<std::path::PathBuf, PlatformError> {
    if let Some(path) = lookup("ORCEL_TRUST_PATH") {
        return paths::private_file_override(path);
    }
    let root = paths::state_root_from(lookup)?;
    paths::ensure_private_dir(&root)?;
    Ok(root.join("trust.jsonl"))
}

fn record_checksum(record: &StoredTrust) -> String {
    let mut hasher = Sha256::new();
    checksum_field(&mut hasher, TRUST_SCHEMA.as_bytes());
    checksum_field(&mut hasher, record.workspace_id.as_bytes());
    checksum_field(
        &mut hasher,
        (if record.trusted { "1" } else { "0" }).as_bytes(),
    );
    checksum_field(&mut hasher, record.revision.to_string().as_bytes());
    checksum_field(&mut hasher, record.provenance_method.as_bytes());
    checksum_field(&mut hasher, record.updated_at_ms.to_string().as_bytes());
    checksum_field(&mut hasher, record.policy_revision.as_bytes());
    checksum_field(&mut hasher, record.prev_checksum.as_bytes());
    hex_lower(&hasher.finalize())
}

fn verify_checksum(record: &StoredTrust, tip: &str) -> bool {
    if record.prev_checksum != tip {
        return false;
    }
    record.checksum == record_checksum(record)
}

fn checksum_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(name: &str) -> std::path::PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("orcel-trust-{name}-{suffix}.jsonl"))
    }

    #[test]
    fn unknown_workspace_is_untrusted_fail_closed() {
        let path = temp_path("unknown");
        let store = TrustStore::load_or_create(path.clone());
        let status = store.get("missing");
        assert!(!status.trusted);
        assert_eq!(status.revision, 0);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn grant_and_revoke_advance_revision() {
        let path = temp_path("grant");
        let mut store = TrustStore::load_or_create(path.clone());
        let granted = store
            .grant("default", "sg-000020-v1", "test-hello", 1_000)
            .expect("grant");
        assert!(granted.trusted);
        assert_eq!(granted.revision, 1);
        let revoked = store
            .revoke_workspace("default", "sg-000020-v1", "test-hello", 2_000)
            .expect("revoke");
        assert!(!revoked.trusted);
        assert_eq!(revoked.revision, 2);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn history_is_redacted_bounded_and_tamper_evident() {
        let path = temp_path("history");
        let mut store = TrustStore::load_or_create(path.clone());
        store
            .grant("default", "sg-000020-v1", "test-hello", 1_000)
            .expect("grant");
        store
            .revoke_workspace("default", "sg-000020-v1", "test-hello", 2_000)
            .expect("revoke");
        let full = store.history(200);
        assert_eq!(full.len(), 2);
        let rendered = format!("{full:?}");
        assert!(!rendered.contains("secret"));
        assert!(!rendered.contains("biometric"));
        let bounded = store.history(1);
        assert_eq!(bounded.len(), 1);
        drop(store);
        let mut text = std::fs::read_to_string(&path).expect("read");
        text = text.replace("test-hello", "tampered");
        std::fs::write(&path, text).expect("tamper");
        let reloaded = TrustStore::load_or_create(path.clone());
        assert!(reloaded.history.len() < 2);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn corrupt_state_fails_closed_as_untrusted() {
        let path = temp_path("corrupt");
        std::fs::write(&path, "not json\n").expect("corrupt");
        let store = TrustStore::load_or_create(path.clone());
        assert!(!store.get("default").trusted);
        assert!(store.history.is_empty());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn sg000041_state_defaults_lie_within_protected_state_roots() {
        // The audit and approval defaults create their state root, so HOME
        // and XDG_STATE_HOME point at a sandbox instead of the real home.
        // The Windows layout reads neither.
        let home = temp_path("home");
        std::fs::create_dir_all(&home).expect("sandbox home");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700))
                .expect("chmod sandbox home");
        }
        let lookup = |name: &str| match name {
            "HOME" => Some(home.clone().into_os_string()),
            "XDG_STATE_HOME" => None,
            _ => std::env::var_os(name),
        };
        let roots = orcel_policy::protected_state::protected_state_roots_from(&lookup);
        for path in [
            default_trust_path_from(&lookup).expect("trust path"),
            orcel_audit::default_audit_path_from(&lookup).expect("audit path"),
            orcel_approval::default_approval_history_path_from(&lookup)
                .expect("approval history path"),
            orcel_provider_browser::default_profile_root_from(&lookup)
                .expect("browser profile root"),
            orcel_policy::remote_session::default_lease_store_path_from(&lookup)
                .expect("lease store path"),
            orcel_policy::executable_registry::default_registry_path_from(&lookup)
                .expect("registry path"),
            orcel_policy::full_control_store::default_authority_dir_from(&lookup)
                .expect("authority dir"),
        ] {
            assert!(
                roots
                    .iter()
                    .any(|root| orcel_policy::protected_state::path_within(&path, root)),
                "{} must be protected state",
                path.display()
            );
        }
        let _ = std::fs::remove_dir_all(home);
    }

    /// XP-01B: the trust record default resolves under the private per-user Orcel
    /// state root, fails closed without one, and never falls back to the
    /// shared temp directory. State earlier builds left under the shared temp
    /// directory is not migrated and is never read.
    mod xp01b {
        use super::*;
        use std::ffi::OsString;
        use std::path::{Path, PathBuf};

        fn resolve(lookup: &dyn Fn(&str) -> Option<OsString>) -> Result<PathBuf, String> {
            default_trust_path_from(lookup).map_err(|error| error.to_string())
        }

        fn lookup(vars: Vec<(&'static str, OsString)>) -> impl Fn(&str) -> Option<OsString> {
            move |name| {
                vars.iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| value.clone())
            }
        }

        fn sandbox(label: &str) -> PathBuf {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0);
            let dir = std::env::temp_dir().join(format!(
                "orcel-trust-xp01b-{label}-{}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(&dir).expect("sandbox");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                    .expect("chmod sandbox");
            }
            dir
        }

        fn user_root_env(base: &Path) -> Vec<(&'static str, OsString)> {
            #[cfg(windows)]
            let name = "LOCALAPPDATA";
            #[cfg(not(windows))]
            let name = "HOME";
            vec![(name, base.as_os_str().to_owned())]
        }

        #[test]
        fn default_resolves_under_the_private_root() {
            let base = sandbox("resolve");
            let lookup = lookup(user_root_env(&base));
            let root = orcel_platform::paths::state_root_from(&lookup).expect("root");
            let path = resolve(&lookup).expect("default");
            assert_eq!(path, root.join("trust.jsonl"));
            assert!(path.starts_with(&base));
            assert!(!path.starts_with(std::env::temp_dir().join("orcel")));
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&root).expect("root").permissions().mode();
                assert_eq!(mode & 0o777, 0o700);
            }
            let _ = std::fs::remove_dir_all(base);
        }

        #[test]
        fn missing_state_root_is_an_error_never_temp() {
            let error = resolve(&lookup(Vec::new())).expect_err("no root");
            assert!(error.contains("state root is unavailable"), "{error}");
        }

        #[test]
        fn relative_override_is_refused() {
            for value in ["", "trust.jsonl", "state/trust.jsonl"] {
                let error = resolve(&lookup(vec![("ORCEL_TRUST_PATH", OsString::from(value))]))
                    .expect_err("relative override");
                assert!(error.contains("is not absolute"), "{value:?}: {error}");
            }
        }

        #[cfg(windows)]
        #[test]
        fn windows_path_is_byte_identical_to_the_previous_default() {
            // A real directory: resolving creates the private state root
            // with an owner-only DACL (#358 item 2).
            let local = sandbox("windows-bytes");
            let path = resolve(&lookup(vec![(
                "LOCALAPPDATA",
                local.clone().into_os_string(),
            )]))
            .expect("default");
            assert_eq!(
                path.as_os_str(),
                format!(r"{}\Orcel\trust.jsonl", local.display()).as_str()
            );
            let _ = std::fs::remove_dir_all(local);
        }

        /// Recovery: trust records already at the default location are read
        /// in place with no migration step.
        #[test]
        fn existing_trust_records_are_read_in_place_without_migration() {
            let base = sandbox("recover");
            let lookup = lookup(user_root_env(&base));
            let path = resolve(&lookup).expect("default");
            let mut store = TrustStore::load_or_create(path.clone());
            store
                .grant("default", "sg-000020-v1", "test-hello", 1_000)
                .expect("grant");
            drop(store);
            let before = std::fs::read(&path).expect("read");
            let again = resolve(&lookup).expect("default");
            assert_eq!(again, path);
            assert!(
                TrustStore::load_or_create(again.clone())
                    .get("default")
                    .trusted
            );
            assert_eq!(std::fs::read(&again).expect("read"), before);
            let _ = std::fs::remove_dir_all(base);
        }

        /// Recovery: trust records an earlier build left in the legacy
        /// shared-temp `orcel` directory are not migrated and never read, so
        /// every workspace starts untrusted under the private root. Only what
        /// the test seeds is removed; an earlier build's file is kept and
        /// serves as the seed.
        #[test]
        fn legacy_shared_temp_trust_records_are_ignored() {
            let legacy_dir = std::env::temp_dir().join("orcel");
            let legacy = legacy_dir.join("trust.jsonl");
            let created_dir = !legacy_dir.exists();
            let created_file = !legacy.exists();
            if created_file && std::fs::create_dir_all(&legacy_dir).is_ok() {
                TrustStore::load_or_create(legacy.clone())
                    .grant("default", "sg-000020-v1", "legacy-seed", 1_000)
                    .expect("seed legacy trust");
                assert!(
                    TrustStore::load_or_create(legacy.clone())
                        .get("default")
                        .trusted
                );
            }
            let base = sandbox("legacy");
            let lookup = lookup(user_root_env(&base));
            let path = resolve(&lookup).expect("default");
            assert_ne!(path, legacy);
            let store = TrustStore::load_or_create(path.clone());
            assert!(!store.get("default").trusted);
            assert!(store.history(200).is_empty());
            assert!(!path.exists(), "nothing is copied from the legacy store");
            if created_file {
                let _ = std::fs::remove_file(&legacy);
            }
            if created_dir {
                let _ = std::fs::remove_dir(&legacy_dir);
            }
            let _ = std::fs::remove_dir_all(base);
        }

        #[cfg(unix)]
        mod unix {
            use super::*;
            use std::os::unix::fs::PermissionsExt;

            fn chmod(path: &Path, mode: u32) {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
                    .expect("chmod");
            }

            /// The state root this OS's layout derives from `HOME=base`, with every
            /// directory between `base` and the root's parent created 0700.
            fn root_under(base: &Path) -> PathBuf {
                let root = orcel_platform::paths::state_root_from(&home_only(base)).expect("root");
                let parent = root.parent().expect("root parent");
                std::fs::create_dir_all(parent).expect("root parent");
                let mut dir = parent;
                while dir != base {
                    chmod(dir, 0o700);
                    dir = dir.parent().expect("below base");
                }
                root
            }

            fn home_only(base: &Path) -> impl Fn(&str) -> Option<OsString> {
                lookup(vec![("HOME", base.as_os_str().to_owned())])
            }

            #[test]
            fn symlinked_root_is_refused() {
                let base = sandbox("symlink");
                let target = base.join("elsewhere");
                std::fs::create_dir(&target).expect("target");
                chmod(&target, 0o700);
                std::os::unix::fs::symlink(&target, root_under(&base)).expect("symlink");
                let error = resolve(&home_only(&base)).expect_err("symlinked root");
                assert!(error.contains("is a symbolic link"), "{error}");
                assert_eq!(std::fs::read_dir(&target).expect("target").count(), 0);
                let _ = std::fs::remove_dir_all(base);
            }

            #[test]
            fn world_writable_root_is_refused_and_left_unrepaired() {
                let base = sandbox("writable-root");
                let root = root_under(&base);
                std::fs::create_dir(&root).expect("root");
                chmod(&root, 0o777);
                let error = resolve(&home_only(&base)).expect_err("writable root");
                assert!(error.contains("grants group or other access"), "{error}");
                let mode = std::fs::metadata(&root).expect("root").permissions().mode();
                assert_eq!(mode & 0o777, 0o777);
                let _ = std::fs::remove_dir_all(base);
            }

            /// An override gets the default location's guarantees: a parent other
            /// users can reach is refused.
            #[test]
            fn override_in_a_shared_directory_is_refused() {
                let base = sandbox("shared-override");
                chmod(&base, 0o755);
                let override_path = base.join("trust.jsonl");
                let error = resolve(&lookup(vec![(
                    "ORCEL_TRUST_PATH",
                    override_path.into_os_string(),
                )]))
                .expect_err("shared parent");
                assert!(error.contains("grants group or other access"), "{error}");
                let _ = std::fs::remove_dir_all(base);
            }

            #[test]
            fn world_writable_home_is_refused_before_anything_is_created() {
                let base = sandbox("writable-home");
                chmod(&base, 0o777);
                let error = resolve(&home_only(&base)).expect_err("writable home");
                assert!(error.contains("is writable by other users"), "{error}");
                assert_eq!(std::fs::read_dir(&base).expect("base").count(), 0);
                chmod(&base, 0o700);
                let _ = std::fs::remove_dir_all(base);
            }
        }
    }
}
