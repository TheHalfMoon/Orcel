use orcel_contracts::FailureCode;
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
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|error| {
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

pub fn default_trust_path() -> std::path::PathBuf {
    if let Some(path) = std::env::var_os("ORCEL_TRUST_PATH") {
        return std::path::PathBuf::from(path);
    }
    if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
        return std::path::PathBuf::from(local_app_data)
            .join("Orcel")
            .join("trust.jsonl");
    }
    std::env::temp_dir().join("orcel").join("trust.jsonl")
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
            default_trust_path(),
            orcel_audit::default_audit_path_from(&lookup).expect("audit path"),
            orcel_approval::default_approval_history_path_from(&lookup)
                .expect("approval history path"),
            orcel_provider_browser::default_profile_root(),
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
}
