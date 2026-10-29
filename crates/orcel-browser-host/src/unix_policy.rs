//! SG-000115 slice 1, inert pre-activation engineering (category A1 in
//! `docs/orcel/implementation-readiness/prep/SG-000115.md`): the macOS and
//! Linux managed-policy inspection that the browser launch precondition will
//! use once SG-000115 is activated.
//!
//! The module is compiled only into test builds (`#[cfg(test)]` in
//! `lib.rs`), so no release build contains it. On macOS and Linux the launch
//! precondition still reads `RegistryPolicySource`, whose non-Windows stub
//! answers `Unreadable`, so launch stays refused; `worker_launch.rs` starts
//! nothing there either. Wiring this reader in is activation work
//! (category B). A source scan in the tests below pins that only this module
//! names its entry points.
//!
//! Every location is inspected read-only, below an explicit root (`/` once
//! activation wires it in; a scratch directory in tests). Anything present, populated,
//! unexpected or unreadable fails closed, as the Windows registry check
//! does: managed policy outranks the confinement flags.

use std::path::{Path, PathBuf};

use crate::confinement::PolicyKeyState;
use crate::discovery::EngineKind;
use crate::error::HostError;

/// The Unix platform whose policy locations are inspected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnixPlatform {
    Linux,
    MacOs,
}

/// How a policy location is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LocationKind {
    /// A Chromium policy directory: any entry in it is a policy.
    Directory,
    /// A managed-preferences property list: its presence is a policy.
    File,
}

/// One place a managed browser policy can live, relative to the root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyLocation {
    pub(crate) relative: PathBuf,
    pub(crate) kind: LocationKind,
}

/// Linux policy directories per engine family. Chrome builds on some
/// distributions also read Chromium's directory; refusing on it only fails
/// safe. Both `managed` and `recommended` are refused, as on Windows.
fn linux_roots(kind: EngineKind) -> &'static [&'static str] {
    match kind {
        EngineKind::Edge => &["etc/opt/edge/policies"],
        EngineKind::Chromium => &["etc/opt/chrome/policies", "etc/chromium/policies"],
    }
}

/// macOS managed-preference domains per engine family.
fn macos_domains(kind: EngineKind) -> &'static [&'static str] {
    match kind {
        EngineKind::Edge => &["com.microsoft.Edge"],
        EngineKind::Chromium => &["com.google.Chrome", "org.chromium.Chromium"],
    }
}

/// A user name usable as one path component under Managed Preferences.
fn valid_user(user: &str) -> bool {
    !user.is_empty()
        && user.len() <= 255
        && user != "."
        && user != ".."
        && !user.contains(['/', '\\', '\0'])
}

/// Every location to inspect. On macOS the per-user domain needs the user
/// the engine would run as; without a usable name the check cannot be
/// established and fails closed (`Err`).
pub(crate) fn policy_locations(
    platform: UnixPlatform,
    kind: EngineKind,
    user: Option<&str>,
) -> Result<Vec<PolicyLocation>, HostError> {
    match platform {
        UnixPlatform::Linux => Ok(linux_roots(kind)
            .iter()
            .flat_map(|root| {
                ["managed", "recommended"]
                    .into_iter()
                    .map(move |leaf| PolicyLocation {
                        relative: Path::new(root).join(leaf),
                        kind: LocationKind::Directory,
                    })
            })
            .collect()),
        UnixPlatform::MacOs => {
            let user = user.filter(|user| valid_user(user)).ok_or_else(|| {
                HostError::Platform(
                    "managed browser policy cannot be read: no usable user for the per-user domain; launch refused"
                        .into(),
                )
            })?;
            let base = Path::new("Library").join("Managed Preferences");
            Ok(macos_domains(kind)
                .iter()
                .flat_map(|domain| {
                    let file = format!("{domain}.plist");
                    [base.join(&file), base.join(user).join(&file)]
                })
                .map(|relative| PolicyLocation {
                    relative,
                    kind: LocationKind::File,
                })
                .collect())
        }
    }
}

/// A deliberately conservative, read-only, test-only walk. Reject symbolic
/// links and unexpected files at *every* ancestor below the trusted root,
/// not only at the final policy location. A dangling parent symlink must
/// never masquerade as an absent policy. Checking separately is NOT atomic
/// against a concurrently swapped directory; activation requires its own
/// descriptor-relative and race-resistant qualification before any wiring.
fn check_policy_ancestors(root: &Path, relative: &Path) -> Result<(), PolicyKeyState> {
    use std::path::Component;

    match std::fs::symlink_metadata(root) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => return Err(PolicyKeyState::Populated),
        Err(_) => return Err(PolicyKeyState::Unreadable),
    }

    let components = relative.components().collect::<Vec<_>>();
    if components.is_empty()
        || components
            .iter()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(PolicyKeyState::Unreadable);
    }

    let mut current = root.to_path_buf();
    for component in &components[..components.len() - 1] {
        current.push(component.as_os_str());
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => return Err(PolicyKeyState::Populated),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(PolicyKeyState::Absent);
            }
            Err(_) => return Err(PolicyKeyState::Unreadable),
        }
    }
    Ok(())
}

/// The state of one location below `root`. An ancestor symlink, including
/// one pointing to a nonexistent target, cannot be mistaken for absence.
pub(crate) fn location_state(root: &Path, location: &PolicyLocation) -> PolicyKeyState {
    if let Err(state) = check_policy_ancestors(root, &location.relative) {
        return state;
    }
    let path = root.join(&location.relative);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return PolicyKeyState::Absent
        }
        Err(_) => return PolicyKeyState::Unreadable,
    };
    match location.kind {
        // A property list, or anything else standing in its place.
        LocationKind::File => PolicyKeyState::Populated,
        LocationKind::Directory => {
            if !metadata.is_dir() {
                // A link or a file where the engine expects a directory.
                return PolicyKeyState::Populated;
            }
            match std::fs::read_dir(&path) {
                Ok(mut entries) => match entries.next() {
                    None => PolicyKeyState::Empty,
                    Some(Ok(_)) => PolicyKeyState::Populated,
                    Some(Err(_)) => PolicyKeyState::Unreadable,
                },
                Err(_) => PolicyKeyState::Unreadable,
            }
        }
    }
}

/// The Unix launch precondition, for use after activation: refuse when any
/// managed policy location is present or populated, or cannot be read.
pub(crate) fn assert_no_unix_managed_policy(
    platform: UnixPlatform,
    kind: EngineKind,
    root: &Path,
    user: Option<&str>,
) -> Result<(), HostError> {
    for location in policy_locations(platform, kind, user)? {
        match location_state(root, &location) {
            PolicyKeyState::Absent | PolicyKeyState::Empty => {}
            PolicyKeyState::Populated => {
                return Err(HostError::Invalid(format!(
                    "managed browser policy is present ({}); launch refused",
                    location.relative.display()
                )))
            }
            PolicyKeyState::Unreadable => {
                return Err(HostError::Platform(format!(
                    "managed browser policy cannot be read ({}); launch refused",
                    location.relative.display()
                )))
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!(
            "orcel-sg115-policy-{label}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    const KINDS: [EngineKind; 2] = [EngineKind::Edge, EngineKind::Chromium];

    #[test]
    fn linux_locations_cover_managed_and_recommended_per_family() {
        let names = |kind| {
            policy_locations(UnixPlatform::Linux, kind, None)
                .unwrap()
                .into_iter()
                .map(|location| {
                    assert_eq!(location.kind, LocationKind::Directory);
                    location.relative.to_string_lossy().replace('\\', "/")
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            names(EngineKind::Edge),
            [
                "etc/opt/edge/policies/managed",
                "etc/opt/edge/policies/recommended"
            ]
        );
        assert_eq!(
            names(EngineKind::Chromium),
            [
                "etc/opt/chrome/policies/managed",
                "etc/opt/chrome/policies/recommended",
                "etc/chromium/policies/managed",
                "etc/chromium/policies/recommended"
            ]
        );
    }

    #[test]
    fn macos_locations_cover_the_machine_and_user_domains() {
        let names = policy_locations(UnixPlatform::MacOs, EngineKind::Chromium, Some("ana"))
            .unwrap()
            .into_iter()
            .map(|location| location.relative.to_string_lossy().replace('\\', "/"))
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            [
                "Library/Managed Preferences/com.google.Chrome.plist",
                "Library/Managed Preferences/ana/com.google.Chrome.plist",
                "Library/Managed Preferences/org.chromium.Chromium.plist",
                "Library/Managed Preferences/ana/org.chromium.Chromium.plist"
            ]
        );
    }

    #[test]
    fn a_clean_root_and_empty_directories_pass() {
        let root = scratch("clean");
        for kind in KINDS {
            assert!(assert_no_unix_managed_policy(UnixPlatform::Linux, kind, &root, None).is_ok());
            assert!(
                assert_no_unix_managed_policy(UnixPlatform::MacOs, kind, &root, Some("ana"))
                    .is_ok()
            );
        }
        std::fs::create_dir_all(root.join("etc/opt/chrome/policies/managed")).unwrap();
        assert!(assert_no_unix_managed_policy(
            UnixPlatform::Linux,
            EngineKind::Chromium,
            &root,
            None
        )
        .is_ok());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn any_linux_policy_entry_refuses_launch() {
        for dir in [
            "etc/opt/chrome/policies/managed",
            "etc/opt/chrome/policies/recommended",
            "etc/chromium/policies/managed",
            "etc/chromium/policies/recommended",
        ] {
            let root = scratch("linux");
            std::fs::create_dir_all(root.join(dir)).unwrap();
            // Any entry counts, not only *.json: refusing extra names fails safe.
            std::fs::write(root.join(dir).join("policy.txt"), "{}").unwrap();
            let error = assert_no_unix_managed_policy(
                UnixPlatform::Linux,
                EngineKind::Chromium,
                &root,
                None,
            )
            .unwrap_err();
            assert!(matches!(error, HostError::Invalid(_)), "{dir}: {error:?}");
            // Edge reads its own directories only.
            assert!(assert_no_unix_managed_policy(
                UnixPlatform::Linux,
                EngineKind::Edge,
                &root,
                None
            )
            .is_ok());
            std::fs::remove_dir_all(&root).ok();
        }
    }

    #[test]
    fn a_file_where_a_policy_directory_belongs_refuses_launch() {
        let root = scratch("file");
        std::fs::create_dir_all(root.join("etc/opt/edge/policies")).unwrap();
        std::fs::write(root.join("etc/opt/edge/policies/managed"), "x").unwrap();
        assert!(matches!(
            assert_no_unix_managed_policy(UnixPlatform::Linux, EngineKind::Edge, &root, None),
            Err(HostError::Invalid(_))
        ));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn any_macos_managed_preference_refuses_launch() {
        for relative in [
            "Library/Managed Preferences/com.microsoft.Edge.plist",
            "Library/Managed Preferences/ana/com.microsoft.Edge.plist",
        ] {
            let root = scratch("macos");
            let path = root.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, "<plist/>").unwrap();
            assert!(matches!(
                assert_no_unix_managed_policy(
                    UnixPlatform::MacOs,
                    EngineKind::Edge,
                    &root,
                    Some("ana")
                ),
                Err(HostError::Invalid(_))
            ));
            // Edge's domain is not Chrome's policy.
            assert!(assert_no_unix_managed_policy(
                UnixPlatform::MacOs,
                EngineKind::Chromium,
                &root,
                Some("ana")
            )
            .is_ok());
            std::fs::remove_dir_all(&root).ok();
        }
    }

    #[test]
    fn macos_without_a_usable_user_fails_closed() {
        let root = scratch("user");
        for user in [
            None,
            Some(""),
            Some("."),
            Some(".."),
            Some("a/b"),
            Some("a\\b"),
            Some("a\0b"),
        ] {
            assert!(
                matches!(
                    assert_no_unix_managed_policy(
                        UnixPlatform::MacOs,
                        EngineKind::Edge,
                        &root,
                        user
                    ),
                    Err(HostError::Platform(_))
                ),
                "{user:?}"
            );
        }
        std::fs::remove_dir_all(&root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn a_symbolic_link_at_a_policy_location_refuses_launch() {
        let root = scratch("link");
        let target = root.join("elsewhere");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::create_dir_all(root.join("etc/opt/edge/policies")).unwrap();
        std::os::unix::fs::symlink(&target, root.join("etc/opt/edge/policies/managed")).unwrap();
        assert!(matches!(
            assert_no_unix_managed_policy(UnixPlatform::Linux, EngineKind::Edge, &root, None),
            Err(HostError::Invalid(_))
        ));
        std::fs::remove_dir_all(&root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn a_dangling_symlink_in_the_policy_ancestor_fails_closed() {
        let root = scratch("dangling-ancestor");
        let parent = root.join("etc/opt/edge");
        std::fs::create_dir_all(&parent).unwrap();
        // The original final-only symlink_metadata check returned NotFound
        // here, incorrectly interpreting this redirect as absent policy.
        std::os::unix::fs::symlink(root.join("missing"), parent.join("policies")).unwrap();
        assert!(matches!(
            assert_no_unix_managed_policy(UnixPlatform::Linux, EngineKind::Edge, &root, None),
            Err(HostError::Invalid(_))
        ));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_to_an_empty_directory_in_a_policy_ancestor_fails_closed() {
        let root = scratch("existing-ancestor");
        let base = root.join("Library/Managed Preferences");
        std::fs::create_dir_all(&base).unwrap();
        std::fs::create_dir_all(root.join("empty")).unwrap();
        std::os::unix::fs::symlink(root.join("empty"), base.join("ana")).unwrap();
        assert!(matches!(
            assert_no_unix_managed_policy(UnixPlatform::MacOs, EngineKind::Edge, &root, Some("ana")),
            Err(HostError::Invalid(_))
        ));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_policy_inspection_root_fails_closed() {
        let actual = scratch("real-root");
        let holder = scratch("root-holder");
        let link = holder.join("linked-root");
        std::os::unix::fs::symlink(&actual, &link).unwrap();
        assert!(matches!(
            assert_no_unix_managed_policy(UnixPlatform::Linux, EngineKind::Edge, &link, None),
            Err(HostError::Invalid(_))
        ));
        std::fs::remove_dir_all(&holder).unwrap();
        std::fs::remove_dir_all(&actual).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_policy_directory_fails_closed() {
        use std::os::unix::fs::PermissionsExt;
        let root = scratch("unreadable");
        let dir = root.join("etc/opt/edge/policies/managed");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();
        // Root can read a 0o000 directory; the check is meaningful only
        // when the permission bites.
        if std::fs::read_dir(&dir).is_err() {
            assert!(matches!(
                assert_no_unix_managed_policy(UnixPlatform::Linux, EngineKind::Edge, &root, None),
                Err(HostError::Platform(_))
            ));
        }
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir_all(&root).ok();
    }

    /// Pre-activation boundary: off Windows the production launch
    /// precondition still reads the registry stub, which answers
    /// `Unreadable` for every key, so launch stays refused.
    #[cfg(not(windows))]
    #[test]
    fn production_policy_check_still_fails_closed_off_windows() {
        use crate::confinement::{
            assert_no_managed_policy, PolicyHive, PolicySource, RegistryPolicySource,
        };
        for kind in KINDS {
            for hive in [PolicyHive::LocalMachine, PolicyHive::CurrentUser] {
                for key in crate::confinement::policy_keys(kind) {
                    assert_eq!(
                        RegistryPolicySource.key_state(hive, key),
                        PolicyKeyState::Unreadable
                    );
                }
            }
            assert!(matches!(
                assert_no_managed_policy(kind, &RegistryPolicySource),
                Err(HostError::Platform(_))
            ));
        }
    }

    /// Pre-activation boundary: no file outside this module names the Unix
    /// reader, and the non-Windows registry stub is unchanged.
    #[test]
    fn the_unix_reader_is_unreachable_from_production() {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut named = Vec::new();
        for entry in std::fs::read_dir(&src).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if !name.ends_with(".rs") || name == "unix_policy.rs" {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            for needle in [
                "assert_no_unix_managed_policy",
                "unix_policy::",
                "UnixPlatform",
                "policy_locations(",
            ] {
                if text.contains(needle) {
                    named.push(format!("{name}: {needle}"));
                }
            }
        }
        assert!(named.is_empty(), "{named:?}");
        let lib = std::fs::read_to_string(src.join("lib.rs")).unwrap();
        assert!(
            lib.contains(
                "#[cfg(test)]
mod unix_policy;"
            ) && !lib.contains("pub mod unix_policy")
        );
        let confinement = std::fs::read_to_string(src.join("confinement.rs")).unwrap();
        let stub = confinement
            .split("#[cfg(not(windows))]\nmod registry {")
            .nth(1)
            .unwrap();
        assert!(stub.contains("PolicyKeyState::Unreadable"));
        assert!(!stub.contains("unix_policy"));
    }
}
