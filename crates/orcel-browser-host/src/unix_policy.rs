//! SG-000115 slice A1, inert pre-activation engineering (category A1 in
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
//! Everything is inspected read-only, below an explicit root (`/` once
//! activation wires it in; a scratch directory in tests), and fails closed:
//!
//! - Linux: each engine family's `policies` root may hold nothing but empty
//!   `managed` and `recommended` directories. Any other entry (a policy
//!   file, Chrome Browser Cloud Management's `enrollment`, a link, a file in
//!   a directory's place) refuses, as the Windows check refuses the whole
//!   policy key.
//! - macOS: a target-domain property list directly in `Library/Managed
//!   Preferences` (machine) or in any subdirectory of it (per user) refuses.
//!   Every subdirectory is inspected, so no caller-supplied user name can
//!   steer the check past another account's domain. A link where a
//!   subdirectory or a target plist could be also refuses.
//! - Anything that cannot be read, or more entries than the bound, refuses.
//!
//! The walk checks each component separately, so it is not atomic against
//! a concurrently swapped directory. Activation needs its own
//! descriptor-relative, race-resistant qualification before any wiring.
//!
//! Open for the activation spec (not decided here): macOS non-forced
//! preferences (`/Library/Preferences`, `~/Library/Preferences`), which
//! Chrome can apply as recommended policy; per-channel domains (beta, dev,
//! canary) if discovery ever admits those channels; and whether to re-check
//! policy at teardown (policy written by root after the check is the same
//! trust boundary as on Windows).

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

/// At most this many entries are read from one directory; more fails
/// closed, so a hostile directory cannot make the check unbounded.
const MAX_ENTRIES: usize = 4096;

/// Linux policy roots per engine family. Chrome builds on some
/// distributions read Chromium's roots too (Debian's `chromium`, Ubuntu's
/// `chromium-browser`); refusing on them only fails safe.
fn linux_roots(kind: EngineKind) -> &'static [&'static str] {
    match kind {
        EngineKind::Edge => &["etc/opt/edge/policies"],
        EngineKind::Chromium => &[
            "etc/opt/chrome/policies",
            "etc/chromium/policies",
            "etc/chromium-browser/policies",
        ],
    }
}

/// macOS managed-preference domains per engine family.
fn macos_domains(kind: EngineKind) -> &'static [&'static str] {
    match kind {
        EngineKind::Edge => &["com.microsoft.Edge"],
        EngineKind::Chromium => &["com.google.Chrome", "org.chromium.Chromium"],
    }
}

/// The entries of a directory, bounded; `Err` carries the fail-closed state.
fn bounded_entries(dir: &Path) -> Result<Vec<std::fs::DirEntry>, PolicyKeyState> {
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|_| PolicyKeyState::Unreadable)? {
        if entries.len() == MAX_ENTRIES {
            return Err(PolicyKeyState::Unreadable);
        }
        entries.push(entry.map_err(|_| PolicyKeyState::Unreadable)?);
    }
    Ok(entries)
}

/// The metadata of `root/relative`, walking one component at a time
/// without following a link at the location itself. `Ok(None)` only when a
/// component is missing below a chain of real directories; a file or link
/// standing in for an intermediate directory refuses (`Populated`), and any
/// other error fails closed (`Unreadable`). The walk is explicit so the
/// answer does not depend on how a platform reports a blocked path.
fn locate(root: &Path, relative: &str) -> Result<Option<std::fs::Metadata>, PolicyKeyState> {
    // The inspection root itself must be a real directory (not a link).
    match std::fs::symlink_metadata(root) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => return Err(PolicyKeyState::Populated),
        Err(_) => return Err(PolicyKeyState::Unreadable),
    }
    let components: Vec<&str> = relative.split('/').collect();
    // Only plain names: never `.`, `..`, an empty or a rooted component.
    if components.iter().any(|component| {
        component.is_empty() || *component == "." || *component == ".." || component.contains('\\')
    }) {
        return Err(PolicyKeyState::Unreadable);
    }
    let mut path = root.to_path_buf();
    for (index, component) in components.iter().enumerate() {
        path.push(component);
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(PolicyKeyState::Unreadable),
        };
        if index + 1 == components.len() {
            return Ok(Some(metadata));
        }
        if !metadata.file_type().is_dir() {
            return Err(PolicyKeyState::Populated);
        }
    }
    Ok(None)
}

/// One Linux `policies` root: only empty `managed` / `recommended`
/// directories may be present.
fn linux_root_state(base: &Path, relative: &str) -> PolicyKeyState {
    let metadata = match locate(base, relative) {
        Ok(None) => return PolicyKeyState::Absent,
        Ok(Some(metadata)) => metadata,
        Err(state) => return state,
    };
    if !metadata.file_type().is_dir() {
        return PolicyKeyState::Populated;
    }
    let entries = match bounded_entries(&base.join(relative)) {
        Ok(entries) => entries,
        Err(state) => return state,
    };
    for entry in entries {
        let name = entry.file_name();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => return PolicyKeyState::Unreadable,
        };
        if !(name == "managed" || name == "recommended") || !file_type.is_dir() {
            return PolicyKeyState::Populated;
        }
        match bounded_entries(&entry.path()) {
            Ok(inner) if inner.is_empty() => {}
            Ok(_) => return PolicyKeyState::Populated,
            Err(state) => return state,
        }
    }
    PolicyKeyState::Empty
}

/// One directory of managed preferences (`top` is `Library/Managed
/// Preferences` itself): is a target-domain plist, or a link standing in
/// for one or for a per-user directory, present?
fn macos_dir_state(dir: &Path, targets: &[String], top: bool) -> PolicyKeyState {
    let entries = match bounded_entries(dir) {
        Ok(entries) => entries,
        Err(state) => return state,
    };
    for entry in entries {
        let name = entry.file_name();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => return PolicyKeyState::Unreadable,
        };
        // macOS volumes are case-insensitive by default, so a plist named in
        // any case applies to the domain; a name that is not UTF-8 cannot be
        // compared and refuses.
        let Some(name) = name.to_str() else {
            return PolicyKeyState::Populated;
        };
        if targets
            .iter()
            .any(|target| name.eq_ignore_ascii_case(target))
        {
            return PolicyKeyState::Populated;
        }
        // APFS folds case beyond ASCII (for example U+017F to `s`), so any
        // non-ASCII name (in the domain or the suffix) could still reach a
        // target domain: refuse every one.
        if !name.is_ascii() {
            return PolicyKeyState::Populated;
        }
        if file_type.is_symlink() && (top || name.to_ascii_lowercase().ends_with(".plist")) {
            // A link where a per-user directory or a plist could be: refuse
            // rather than follow it anywhere.
            return PolicyKeyState::Populated;
        }
        if top && file_type.is_dir() {
            match macos_dir_state(&entry.path(), targets, false) {
                PolicyKeyState::Absent | PolicyKeyState::Empty => {}
                decisive => return decisive,
            }
        }
    }
    PolicyKeyState::Empty
}

/// The managed-policy state of one engine family below `root`.
pub(crate) fn unix_policy_state(
    platform: UnixPlatform,
    kind: EngineKind,
    root: &Path,
) -> PolicyKeyState {
    match platform {
        UnixPlatform::Linux => {
            let mut state = PolicyKeyState::Absent;
            for relative in linux_roots(kind) {
                match linux_root_state(root, relative) {
                    PolicyKeyState::Absent => {}
                    PolicyKeyState::Empty => state = PolicyKeyState::Empty,
                    decisive => return decisive,
                }
            }
            state
        }
        UnixPlatform::MacOs => {
            let base = root.join("Library").join("Managed Preferences");
            let targets: Vec<String> = macos_domains(kind)
                .iter()
                .map(|domain| format!("{domain}.plist"))
                .collect();
            match locate(root, "Library/Managed Preferences") {
                Ok(None) => PolicyKeyState::Absent,
                Ok(Some(metadata)) if !metadata.file_type().is_dir() => PolicyKeyState::Populated,
                Ok(Some(_)) => macos_dir_state(&base, &targets, true),
                Err(state) => state,
            }
        }
    }
}

/// The Unix launch precondition, for use after activation: refuse when any
/// managed policy is present or populated, or cannot be read.
pub(crate) fn assert_no_unix_managed_policy(
    platform: UnixPlatform,
    kind: EngineKind,
    root: &Path,
) -> Result<(), HostError> {
    match unix_policy_state(platform, kind, root) {
        PolicyKeyState::Absent | PolicyKeyState::Empty => Ok(()),
        PolicyKeyState::Populated => Err(HostError::Invalid(format!(
            "managed browser policy is present ({platform:?}, {kind:?}); launch refused"
        ))),
        PolicyKeyState::Unreadable => Err(HostError::Platform(format!(
            "managed browser policy cannot be read ({platform:?}, {kind:?}); launch refused"
        ))),
    }
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

    fn write(root: &Path, relative: &str) {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "x").unwrap();
    }

    fn check(platform: UnixPlatform, kind: EngineKind, root: &Path) -> Result<(), HostError> {
        assert_no_unix_managed_policy(platform, kind, root)
    }

    fn other(kind: EngineKind) -> EngineKind {
        match kind {
            EngineKind::Edge => EngineKind::Chromium,
            EngineKind::Chromium => EngineKind::Edge,
        }
    }

    const KINDS: [EngineKind; 2] = [EngineKind::Edge, EngineKind::Chromium];
    const PLATFORMS: [UnixPlatform; 2] = [UnixPlatform::Linux, UnixPlatform::MacOs];

    #[test]
    fn a_clean_root_and_empty_policy_directories_pass() {
        let root = scratch("clean");
        for platform in PLATFORMS {
            for kind in KINDS {
                assert!(
                    check(platform, kind, &root).is_ok(),
                    "{platform:?} {kind:?}"
                );
            }
        }
        for dir in [
            "etc/opt/chrome/policies/managed",
            "etc/opt/chrome/policies/recommended",
            "etc/chromium-browser/policies/managed",
            "Library/Managed Preferences/ana",
        ] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        // Other domains' managed preferences are not this engine's policy.
        write(&root, "Library/Managed Preferences/com.apple.Safari.plist");
        write(
            &root,
            "Library/Managed Preferences/ana/com.apple.dock.plist",
        );
        assert!(check(UnixPlatform::Linux, EngineKind::Chromium, &root).is_ok());
        for kind in KINDS {
            assert!(check(UnixPlatform::MacOs, kind, &root).is_ok());
        }
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn any_linux_policy_content_refuses_launch() {
        for (kind, relative) in [
            (
                EngineKind::Chromium,
                "etc/opt/chrome/policies/managed/p.json",
            ),
            (
                EngineKind::Chromium,
                "etc/opt/chrome/policies/recommended/p.json",
            ),
            (EngineKind::Chromium, "etc/chromium/policies/managed/p.txt"),
            (
                EngineKind::Chromium,
                "etc/chromium-browser/policies/recommended/p.json",
            ),
            // Cloud management enrollment, and any other name in the root.
            (
                EngineKind::Chromium,
                "etc/opt/chrome/policies/enrollment/CloudManagementEnrollmentToken",
            ),
            (EngineKind::Chromium, "etc/opt/chrome/policies/other"),
            (EngineKind::Edge, "etc/opt/edge/policies/managed/p.json"),
            (EngineKind::Edge, "etc/opt/edge/policies/recommended/p.json"),
            // A file where `managed` should be a directory.
            (EngineKind::Edge, "etc/opt/edge/policies/managed"),
        ] {
            let root = scratch("linux");
            write(&root, relative);
            assert!(
                matches!(
                    check(UnixPlatform::Linux, kind, &root),
                    Err(HostError::Invalid(_))
                ),
                "{relative}"
            );
            assert!(
                check(UnixPlatform::Linux, other(kind), &root).is_ok(),
                "{relative} is not another family's policy"
            );
            std::fs::remove_dir_all(&root).ok();
        }
    }

    #[test]
    fn a_file_where_a_policy_root_or_its_parent_belongs_fails_closed() {
        let root = scratch("file-root");
        write(&root, "etc/opt/edge/policies");
        assert!(matches!(
            check(UnixPlatform::Linux, EngineKind::Edge, &root),
            Err(HostError::Invalid(_))
        ));
        std::fs::remove_dir_all(&root).ok();

        // A file standing in for an intermediate directory (`etc/opt`).
        let root = scratch("file-parent");
        write(&root, "etc/opt");
        assert!(matches!(
            check(UnixPlatform::Linux, EngineKind::Edge, &root),
            Err(HostError::Invalid(_))
        ));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn any_macos_managed_preference_for_the_domain_refuses_launch() {
        for (kind, relative) in [
            (
                EngineKind::Edge,
                "Library/Managed Preferences/com.microsoft.Edge.plist",
            ),
            (
                EngineKind::Edge,
                "Library/Managed Preferences/ana/com.microsoft.Edge.plist",
            ),
            (
                EngineKind::Chromium,
                "Library/Managed Preferences/com.google.Chrome.plist",
            ),
            (
                EngineKind::Chromium,
                "Library/Managed Preferences/bo/com.google.Chrome.plist",
            ),
            (
                EngineKind::Chromium,
                "Library/Managed Preferences/org.chromium.Chromium.plist",
            ),
            (
                EngineKind::Chromium,
                "Library/Managed Preferences/bo/org.chromium.Chromium.plist",
            ),
        ] {
            let root = scratch("macos");
            std::fs::create_dir_all(root.join("Library/Managed Preferences/ana")).unwrap();
            write(&root, relative);
            assert!(
                matches!(
                    check(UnixPlatform::MacOs, kind, &root),
                    Err(HostError::Invalid(_))
                ),
                "{relative}"
            );
            assert!(
                check(UnixPlatform::MacOs, other(kind), &root).is_ok(),
                "{relative} is not another family's policy"
            );
            std::fs::remove_dir_all(&root).ok();
        }
    }

    #[test]
    fn a_managed_preference_named_in_another_case_refuses_launch() {
        for relative in [
            "Library/Managed Preferences/com.google.chrome.plist",
            "Library/Managed Preferences/ana/COM.GOOGLE.CHROME.PLIST",
            // A non-ASCII lookalike (U+017F for `s`) that APFS may fold.
            "Library/Managed Preferences/com.microſoft.Edge.plist",
            "Library/Managed Preferences/ana/com.microsoft.Edge.pliſt",
        ] {
            let root = scratch("macos-case");
            std::fs::create_dir_all(root.join("Library/Managed Preferences/ana")).unwrap();
            write(&root, relative);
            assert!(
                matches!(
                    check(UnixPlatform::MacOs, EngineKind::Chromium, &root),
                    Err(HostError::Invalid(_))
                ) || relative.contains("Edge"),
                "{relative}"
            );
            assert!(
                matches!(
                    check(UnixPlatform::MacOs, EngineKind::Edge, &root),
                    Err(HostError::Invalid(_))
                ) || !relative.contains("Edge"),
                "{relative}"
            );
            std::fs::remove_dir_all(&root).ok();
        }
    }

    #[test]
    fn a_file_where_managed_preferences_belongs_refuses_launch() {
        let root = scratch("macos-file");
        write(&root, "Library/Managed Preferences");
        assert!(matches!(
            check(UnixPlatform::MacOs, EngineKind::Edge, &root),
            Err(HostError::Invalid(_))
        ));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn an_oversized_directory_fails_closed() {
        let root = scratch("bound");
        let dir = root.join("Library/Managed Preferences");
        std::fs::create_dir_all(&dir).unwrap();
        for index in 0..=MAX_ENTRIES {
            std::fs::write(dir.join(format!("com.example.{index}.plist")), "").unwrap();
        }
        assert!(matches!(
            check(UnixPlatform::MacOs, EngineKind::Edge, &root),
            Err(HostError::Platform(_))
        ));
        std::fs::remove_dir_all(&root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn symbolic_links_at_policy_locations_refuse_launch() {
        use std::os::unix::fs::symlink;
        for (platform, link) in [
            (UnixPlatform::Linux, "etc/opt/edge/policies/managed"),
            (UnixPlatform::Linux, "etc/opt/edge/policies"),
            (UnixPlatform::MacOs, "Library/Managed Preferences/ana"),
            (
                UnixPlatform::MacOs,
                "Library/Managed Preferences/com.microsoft.Edge.plist",
            ),
            // Any link at the top level, even one named like a plist.
            (UnixPlatform::MacOs, "Library/Managed Preferences/x.plist"),
            // A link named like a plist inside a user directory.
            (
                UnixPlatform::MacOs,
                "Library/Managed Preferences/ana/x.plist",
            ),
        ] {
            for dangling in [false, true] {
                let root = scratch("link");
                let target = root.join("elsewhere");
                if !dangling {
                    std::fs::create_dir_all(&target).unwrap();
                }
                let path = root.join(link);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                symlink(&target, &path).unwrap();
                assert!(
                    check(platform, EngineKind::Edge, &root).is_err(),
                    "{link} dangling={dangling}"
                );
                std::fs::remove_dir_all(&root).ok();
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_policy_directories_fail_closed() {
        use std::os::unix::fs::PermissionsExt;
        for (platform, dir) in [
            (UnixPlatform::Linux, "etc/opt/edge/policies/managed"),
            (UnixPlatform::Linux, "etc/opt/edge/policies"),
            (UnixPlatform::MacOs, "Library/Managed Preferences/ana"),
        ] {
            let root = scratch("unreadable");
            let path = root.join(dir);
            std::fs::create_dir_all(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
            if std::fs::read_dir(&path).is_ok() {
                // Running with privileges that ignore 0o000: the case proves
                // nothing here, so say so instead of passing silently.
                eprintln!("skipped {dir}: privileges ignore 0o000");
            } else {
                assert!(
                    matches!(
                        check(platform, EngineKind::Edge, &root),
                        Err(HostError::Platform(_))
                    ),
                    "{dir}"
                );
            }
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::remove_dir_all(&root).ok();
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_dangling_symlink_in_the_policy_ancestor_fails_closed() {
        let root = scratch("dangling-ancestor");
        let parent = root.join("etc/opt/edge");
        std::fs::create_dir_all(&parent).unwrap();
        // A final-only symlink_metadata check returned NotFound here,
        // reading the redirect as absent policy.
        std::os::unix::fs::symlink(root.join("missing"), parent.join("policies")).unwrap();
        assert!(matches!(
            check(UnixPlatform::Linux, EngineKind::Edge, &root),
            Err(HostError::Invalid(_))
        ));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_ancestor_of_a_policy_root_fails_closed() {
        let root = scratch("existing-ancestor");
        std::fs::create_dir_all(root.join("elsewhere/opt")).unwrap();
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::os::unix::fs::symlink(root.join("elsewhere/opt"), root.join("etc/opt")).unwrap();
        assert!(matches!(
            check(UnixPlatform::Linux, EngineKind::Edge, &root),
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
        for platform in PLATFORMS {
            assert!(matches!(
                check(platform, EngineKind::Edge, &link),
                Err(HostError::Invalid(_))
            ));
        }
        std::fs::remove_dir_all(&holder).unwrap();
        std::fs::remove_dir_all(&actual).unwrap();
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

    fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                rust_sources(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }

    fn normalized(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap().replace("\r\n", "\n")
    }

    /// Pre-activation boundary: the module is declared exactly once, private
    /// and test-only; no other source names it; the non-Windows registry
    /// stub still answers `Unreadable` and nothing else.
    #[test]
    fn the_unix_reader_is_unreachable_from_production() {
        let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        rust_sources(&crate_dir.join("src"), &mut files);
        rust_sources(&crate_dir.join("tests"), &mut files);
        assert!(files.len() > 10, "the scan found the crate's sources");
        let mut named = Vec::new();
        for path in &files {
            if *path == crate_dir.join("src").join("unix_policy.rs")
                || *path == crate_dir.join("src").join("unix_rehearsal.rs")
                || *path == crate_dir.join("src").join("lib.rs")
            {
                continue;
            }
            let text = normalized(path);
            for needle in [
                "unix_policy",
                "assert_no_unix_managed_policy",
                "unix_policy_state",
                "UnixPlatform",
            ] {
                if text.contains(needle) {
                    named.push(format!("{}: {needle}", path.display()));
                }
            }
        }
        assert!(named.is_empty(), "{named:?}");

        let lib = normalized(&crate_dir.join("src/lib.rs"));
        let lines: Vec<&str> = lib.lines().collect();
        let mentions: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, line)| line.contains("unix_policy"))
            .map(|(index, _)| index)
            .collect();
        let code: Vec<usize> = mentions
            .iter()
            .copied()
            .filter(|index| !lines[*index].trim_start().starts_with("//"))
            .collect();
        assert_eq!(code.len(), 1, "lib.rs names the module once: {mentions:?}");
        assert_eq!(lines[code[0]], "mod unix_policy;");
        assert_eq!(lines[code[0] - 1], "#[cfg(test)]");
        // A6's rehearsal (recorded rule change, prep/SG-000115.md) composes
        // this module; it is admitted only while declared once, private,
        // under the Unix test cfg.
        assert_eq!(lib.matches("mod unix_rehearsal;").count(), 1);
        assert!(!lib.contains("pub mod unix_rehearsal"));
        assert!(lib.contains("#[cfg(all(test, unix))]\nmod unix_rehearsal;\n"));

        let confinement = normalized(&crate_dir.join("src/confinement.rs"));
        let (_, after) = confinement
            .split_once("#[cfg(not(windows))]\nmod registry {")
            .expect("the non-Windows registry stub exists");
        let (stub, _) = after.split_once("\n}\n").expect("the stub module ends");
        let body: Vec<&str> = stub
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with("//"))
            .collect();
        assert_eq!(
            body,
            [
                "use super::{PolicyHive, PolicyKeyState};",
                "pub(super) fn key_state(_hive: PolicyHive, _subkey: &str) -> PolicyKeyState {",
                "PolicyKeyState::Unreadable",
                "}"
            ]
        );
    }
}
