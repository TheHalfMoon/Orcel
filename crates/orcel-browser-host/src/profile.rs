//! SG-000074 dedicated ephemeral automation profile.
//!
//! Every host launch owns a fresh profile directory under Orcel state. The
//! directory carries a marker binding the engine fingerprint, so a foreign
//! or personal directory is never adopted. Profiles are deleted on clean
//! shutdown; there is no persistent profile mode in this grain.

use crate::error::{HostError, UnavailableReason};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

const MARKER_FILE: &str = "orcel-browser-profile.json";
const MARKER_SCHEMA: &str = "orcel-browser-profile/1";

/// A Orcel-owned ephemeral automation profile directory.
pub struct AutomationProfile {
    dir: PathBuf,
    identity: String,
}

impl AutomationProfile {
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// Delete the profile directory. Best-effort removal failure is
    /// reported so cleanup gaps are visible, never silent.
    pub fn destroy(self) -> Result<(), HostError> {
        fs::remove_dir_all(&self.dir).map_err(HostError::from)
    }
}

/// Create a fresh ephemeral profile under `state_root`. The caller owns
/// `state_root`; personal and foreign directories are never adopted.
pub fn setup_ephemeral_profile(
    state_root: &Path,
    engine_fingerprint: &str,
) -> Result<AutomationProfile, HostError> {
    if !state_root.is_absolute() {
        return Err(HostError::Invalid(
            "profile state root must be absolute".into(),
        ));
    }
    let nonce: u64 = random_nonce();
    let dir = state_root.join(format!("browser-profile-{nonce:016x}"));
    if dir.exists() {
        return Err(HostError::Invalid(
            "profile directory already exists".into(),
        ));
    }
    fs::create_dir_all(&dir)?;
    let identity = profile_identity(engine_fingerprint, &dir);
    let marker = serde_json::json!({
        "schema": MARKER_SCHEMA,
        "engine_fingerprint": engine_fingerprint,
        "identity": identity,
    });
    fs::write(dir.join(MARKER_FILE), serde_json::to_vec(&marker).unwrap())?;
    Ok(AutomationProfile { dir, identity })
}

/// Mark a fresh, empty profile directory (SG-000108 product caller: the
/// host's own `ephemeral_profile_dir`) with this engine's marker, so
/// `adopt_profile` can re-check it before the launch (A9). A directory with
/// anything in it is refused.
#[cfg(any(
    test,
    all(
        windows,
        any(feature = "live-browser-test", feature = "live-browser-dev")
    )
))]
pub fn mark_profile(dir: &Path, engine_fingerprint: &str) -> Result<AutomationProfile, HostError> {
    if !dir.is_absolute() || fs::read_dir(dir)?.next().is_some() {
        return Err(HostError::Invalid(
            "only a fresh, empty profile directory is marked".into(),
        ));
    }
    let identity = profile_identity(engine_fingerprint, dir);
    let marker = serde_json::json!({
        "schema": MARKER_SCHEMA,
        "engine_fingerprint": engine_fingerprint,
        "identity": identity,
    });
    fs::write(dir.join(MARKER_FILE), serde_json::to_vec(&marker).unwrap())?;
    Ok(AutomationProfile {
        dir: dir.to_path_buf(),
        identity,
    })
}

/// Adopt an existing directory only if it carries our marker for this
/// engine. Anything else is refused, never repaired.
pub fn adopt_profile(dir: &Path, engine_fingerprint: &str) -> Result<AutomationProfile, HostError> {
    let raw = fs::read(dir.join(MARKER_FILE))
        .map_err(|_| HostError::Unavailable(UnavailableReason::LaunchFailed))?;
    let marker: serde_json::Value = serde_json::from_slice(&raw)
        .map_err(|_| HostError::Unavailable(UnavailableReason::LaunchFailed))?;
    if marker.get("schema").and_then(|v| v.as_str()) != Some(MARKER_SCHEMA) {
        return Err(HostError::Unavailable(UnavailableReason::LaunchFailed));
    }
    if marker.get("engine_fingerprint").and_then(|v| v.as_str()) != Some(engine_fingerprint) {
        return Err(HostError::Unavailable(UnavailableReason::LaunchFailed));
    }
    let identity = marker
        .get("identity")
        .and_then(|v| v.as_str())
        .ok_or(HostError::Unavailable(UnavailableReason::LaunchFailed))?;
    if identity != profile_identity(engine_fingerprint, dir) {
        return Err(HostError::Unavailable(UnavailableReason::LaunchFailed));
    }
    Ok(AutomationProfile {
        dir: dir.to_path_buf(),
        identity: identity.to_owned(),
    })
}

fn profile_identity(engine_fingerprint: &str, dir: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"orcel-browser-profile/1");
    hasher.update(engine_fingerprint.as_bytes());
    hasher.update(dir.to_string_lossy().as_bytes());
    hex(&hasher.finalize())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn random_nonce() -> u64 {
    // No randomness authority is needed: uniqueness across launches comes
    // from time plus process identity. Collisions fail closed at creation.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    now.wrapping_add((std::process::id() as u128) << 64) as u64
}

#[cfg(test)]
mod tests {

    #[test]
    fn only_a_fresh_empty_directory_is_marked_and_then_adopted() {
        let dir = std::env::temp_dir().join(format!("orcel-mark-{:016x}", random_nonce()));
        fs::create_dir_all(&dir).unwrap();
        let marked = mark_profile(&dir, "Edge:1:x").unwrap();
        let adopted = adopt_profile(&dir, "Edge:1:x").unwrap();
        assert_eq!(marked.identity(), adopted.identity());
        assert!(
            adopt_profile(&dir, "Edge:2:x").is_err(),
            "another engine's marker"
        );
        assert!(
            mark_profile(&dir, "Edge:1:x").is_err(),
            "not empty any more"
        );
        assert!(mark_profile(Path::new("relative"), "Edge:1:x").is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    use super::*;

    fn temp_root(label: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("orcel-host-profile-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn ephemeral_profile_round_trip_and_destroy() {
        let root = temp_root("roundtrip");
        let profile = setup_ephemeral_profile(&root, "engine-fp").unwrap();
        assert!(profile.dir().join(MARKER_FILE).is_file());
        let adopted = adopt_profile(profile.dir(), "engine-fp").unwrap();
        assert_eq!(adopted.identity(), profile.identity());
        let dir = profile.dir().to_path_buf();
        profile.destroy().unwrap();
        assert!(!dir.exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn foreign_directory_is_never_adopted() {
        let root = temp_root("foreign");
        assert!(adopt_profile(&root, "engine-fp").is_err());
        fs::write(root.join(MARKER_FILE), b"{}").unwrap();
        assert!(adopt_profile(&root, "engine-fp").is_err());
        let profile = setup_ephemeral_profile(&root, "engine-a").unwrap();
        assert!(adopt_profile(profile.dir(), "engine-b").is_err());
        let dir = profile.dir().to_path_buf();
        profile.destroy().unwrap();
        assert!(!dir.exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn relative_state_root_is_refused() {
        assert!(setup_ephemeral_profile(Path::new("relative"), "fp").is_err());
    }
}
