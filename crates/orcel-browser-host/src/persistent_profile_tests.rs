//! SG-000135 OB-04: the persistent-profile junction tests (Windows test
//! builds only). They make junctions with `cmd /C mklink /J`, a fixed
//! command line with no caller input, so they live in this file, which
//! persistent_profile.rs declares under `#[cfg(all(test, windows))]` and
//! the qualification scan admits only under that exact declaration.

use super::checked_dir;
use crate::error::HostError;
use std::path::PathBuf;

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
fn ob04_a_junction_is_never_followed() -> Result<(), HostError> {
    let root = Root::new("junction")?;
    let target = root.0.join("target");
    std::fs::create_dir_all(target.join("data"))?;
    let link = root.0.join("link");
    let made = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&link)
        .arg(&target)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);
    if !made {
        // No junction could be made here; nothing to check.
        return Ok(());
    }
    assert!(
        checked_dir(&link.join("data")).is_err(),
        "parent is a junction"
    );
    let leaf_link = root.0.join("p").join("data");
    std::fs::create_dir_all(root.0.join("p"))?;
    let made = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&leaf_link)
        .arg(target.join("data"))
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);
    if made {
        assert!(
            checked_dir(&leaf_link).is_err(),
            "the data folder is a junction"
        );
    }
    Ok(())
}
