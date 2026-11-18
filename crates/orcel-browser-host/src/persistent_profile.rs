//! SG-000135 OB-04: persistent Orcel-managed profiles, host side.
//!
//! orceld keeps named profiles under its own protected browser state and
//! passes one profile's data directory to a host it supervises
//! (`--profile-dir`). The host never trusts that path blindly. Before any
//! lifetime uses it, the host requires:
//!
//! - an absolute path whose leaf is `data`, with no `User Data` component
//!   anywhere (the folder name every Chromium-family browser gives a
//!   person's own profile root; Orcel's layout never uses it), so a person's
//!   own Chrome, Edge or Chromium profile is refused even if it were named;
//! - a real directory: neither it nor its parent is a junction, symbolic
//!   link or other reparse point;
//! - the Orcel profile marker: an empty directory is marked on first use,
//!   any other directory must already carry Orcel's marker for this engine
//!   family at this exact path, or it is refused, never repaired.
//!
//! The marker binds the engine family and path, not its version
//! (`Engine::profile_family`), so an engine update keeps the profile usable.
//! A persistent profile is never removed by the host: it is launched with
//! `ephemeral_profile: false`, and the #298 sweep never runs for it.
//!
//! The idea of refusing a browser's default profile folder outright comes
//! from browser-use (`browser_use/browser/local.py`,
//! `is_default_user_data_dir`, MIT); no code is copied.

use crate::error::HostError;
use std::path::{Component, Path, PathBuf};

/// The leaf every persistent profile data directory has.
const DATA_LEAF: &str = "data";

/// Whether `metadata` (from `symlink_metadata`) is a reparse point.
fn is_reparse(metadata: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    metadata.file_type().is_symlink()
}

fn real_dir(path: &Path) -> bool {
    matches!(
        std::fs::symlink_metadata(path),
        Ok(metadata) if metadata.is_dir() && !is_reparse(&metadata)
    )
}

fn refused(message: &str) -> HostError {
    HostError::Invalid(format!("persistent profile refused: {message}"))
}

/// Check a persistent profile data directory before any lifetime uses it.
pub fn checked_dir(dir: &Path) -> Result<PathBuf, HostError> {
    if !dir.is_absolute() {
        return Err(refused("the directory is not absolute"));
    }
    let mut leaf = None;
    for component in dir.components() {
        match component {
            Component::Normal(name) => {
                let name = name.to_string_lossy();
                if name.eq_ignore_ascii_case("User Data") {
                    return Err(refused("a browser's own user-data folder is never used"));
                }
                leaf = Some(name.into_owned());
            }
            Component::ParentDir | Component::CurDir => {
                return Err(refused("the directory has a relative component"));
            }
            Component::Prefix(_) | Component::RootDir => {}
        }
    }
    if leaf.as_deref() != Some(DATA_LEAF) {
        return Err(refused("the directory is not an Orcel profile data folder"));
    }
    let parent = dir
        .parent()
        .ok_or_else(|| refused("the directory has no parent"))?;
    if !real_dir(parent) || !real_dir(dir) {
        return Err(refused(
            "the directory or its parent is missing or is a link or junction",
        ));
    }
    Ok(dir.to_path_buf())
}

/// Mark an empty persistent profile directory for `family`, or adopt one
/// that already carries Orcel's marker for `family` at this path.
#[cfg(any(
    test,
    all(
        windows,
        any(feature = "live-browser-test", feature = "live-browser-dev")
    )
))]
pub fn mark_or_adopt(
    dir: &Path,
    family: &str,
) -> Result<crate::profile::AutomationProfile, HostError> {
    let dir = checked_dir(dir)?;
    let empty = std::fs::read_dir(&dir)
        .map_err(|_| refused("the directory cannot be read"))?
        .next()
        .is_none();
    if empty {
        crate::profile::mark_profile(&dir, family)?;
    }
    crate::profile::adopt_profile(&dir, family)
}

// SG-000135 OB-04: the junction tests spawn `cmd /C mklink /J`, so they
// live in a test-only file the qualification scan admits only under this
// exact declaration (sg000085_qualification.rs).
#[cfg(all(test, windows))]
#[path = "persistent_profile_tests.rs"]
mod junction_tests;

#[cfg(test)]
mod tests {
    use super::*;

    struct Root(PathBuf);

    impl Root {
        fn new(label: &str) -> Result<Self, HostError> {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|since| since.as_nanos())
                .unwrap_or(0);
            let root = std::env::temp_dir().join(format!(
                "orcel-ob04-host-{label}-{}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(&root)?;
            Ok(Self(root))
        }
    }

    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn ob04_a_persistent_profile_is_marked_once_then_adopted_and_kept() -> Result<(), HostError> {
        let root = Root::new("mark")?;
        let data = root.0.join("work").join("data");
        std::fs::create_dir_all(&data)?;
        let first = mark_or_adopt(&data, "Edge:C:\\edge\\msedge.exe")?;
        std::fs::write(data.join("Cookies"), b"kept")?;
        let again = mark_or_adopt(&data, "Edge:C:\\edge\\msedge.exe")?;
        assert_eq!(first.identity(), again.identity());
        assert_eq!(std::fs::read(data.join("Cookies"))?, b"kept");
        // Another engine family or path is refused, never re-marked.
        assert!(mark_or_adopt(&data, "Chromium:C:\\edge\\msedge.exe").is_err());
        assert!(mark_or_adopt(&data, "Edge:D:\\other\\msedge.exe").is_err());
        Ok(())
    }

    #[test]
    fn ob04_a_foreign_or_personal_directory_is_refused() -> Result<(), HostError> {
        let root = Root::new("foreign")?;
        // Something that is not Orcel's: files and no marker.
        let foreign = root.0.join("someone").join("data");
        std::fs::create_dir_all(&foreign)?;
        std::fs::write(foreign.join("Local State"), b"{}")?;
        assert!(mark_or_adopt(&foreign, "Edge:x").is_err());
        // A browser's own user-data root, by name, however it is reached.
        let personal = root.0.join("Edge").join("User Data").join("data");
        std::fs::create_dir_all(&personal)?;
        assert!(checked_dir(&personal).is_err());
        let personal_case = root.0.join("user data").join("data");
        std::fs::create_dir_all(&personal_case)?;
        assert!(checked_dir(&personal_case).is_err());
        // Not a data folder, relative, missing, or with `..`.
        assert!(checked_dir(&root.0).is_err());
        assert!(checked_dir(Path::new("relative\\data")).is_err());
        assert!(checked_dir(&root.0.join("missing").join("data")).is_err());
        assert!(checked_dir(&root.0.join("someone").join("..").join("data")).is_err());
        Ok(())
    }
}
