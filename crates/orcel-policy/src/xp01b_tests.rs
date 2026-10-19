//! XP-01B: the full-control authority, executable registry and remote lease
//! defaults resolve under the private per-user Orcel state root, fail closed
//! when no private root can be established, and never fall back to the
//! shared temp directory. State that earlier builds left under the shared
//! temp directory is not migrated and is never read.

use crate::{executable_registry, full_control_store, remote_session};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

type Lookup<'a> = &'a dyn Fn(&str) -> Option<OsString>;

struct Store {
    name: &'static str,
    resolve: fn(Lookup<'_>) -> Result<PathBuf, String>,
    /// The default location relative to the state root.
    relative: &'static [&'static str],
}

const STORES: &[Store] = &[
    Store {
        name: "full-control authority",
        resolve: |lookup| {
            full_control_store::default_authority_dir_from(lookup).map_err(|error| error.message)
        },
        relative: &["state", "authority"],
    },
    Store {
        name: "executable registry",
        resolve: |lookup| {
            executable_registry::default_registry_path_from(lookup)
                .map_err(|error| error.to_string())
        },
        relative: &["executable_registry.json"],
    },
    Store {
        name: "remote lease store",
        resolve: |lookup| {
            remote_session::default_lease_store_path_from(lookup).map_err(|error| error.to_string())
        },
        relative: &["remote_leases.json"],
    },
];

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
        "orcel-policy-xp01b-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("sandbox");
    // Independent of the umask, so the ancestor checks see a private base.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("chmod sandbox");
    }
    dir
}

/// The per-user variable the running OS's layout reads, pointed at `base`.
fn user_root_env(base: &Path) -> Vec<(&'static str, OsString)> {
    #[cfg(windows)]
    let name = "LOCALAPPDATA";
    #[cfg(not(windows))]
    let name = "HOME";
    vec![(name, base.as_os_str().to_owned())]
}

fn under(root: &Path, relative: &[&str]) -> PathBuf {
    relative
        .iter()
        .fold(root.to_path_buf(), |path, part| path.join(part))
}

#[test]
fn each_store_resolves_under_the_private_root() {
    for store in STORES {
        let base = sandbox("resolve");
        let lookup = lookup(user_root_env(&base));
        let root = orcel_platform::paths::state_root_from(&lookup).expect("root");
        let path = (store.resolve)(&lookup).expect(store.name);
        assert_eq!(path, under(&root, store.relative), "{}", store.name);
        assert!(path.starts_with(&base), "{}", store.name);
        assert!(
            !path.starts_with(std::env::temp_dir().join("orcel")),
            "{}",
            store.name
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let metadata = std::fs::metadata(&root).expect("root");
            assert_eq!(
                metadata.permissions().mode() & 0o777,
                0o700,
                "{}",
                store.name
            );
            assert_eq!(
                metadata.uid(),
                std::fs::metadata(&base).expect("base").uid(),
                "{}",
                store.name
            );
        }
        let _ = std::fs::remove_dir_all(base);
    }
}

#[test]
fn missing_state_root_is_an_error_never_temp() {
    for store in STORES {
        let error = (store.resolve)(&lookup(Vec::new())).expect_err(store.name);
        assert!(
            error.contains("state root is unavailable"),
            "{}: {error}",
            store.name
        );
    }
}

#[cfg(windows)]
#[test]
fn windows_paths_are_byte_identical_to_the_previous_defaults() {
    let lookup = lookup(vec![(
        "LOCALAPPDATA",
        OsString::from(r"C:\Users\u\AppData\Local"),
    )]);
    let expected = [
        r"C:\Users\u\AppData\Local\Orcel\state\authority",
        r"C:\Users\u\AppData\Local\Orcel\executable_registry.json",
        r"C:\Users\u\AppData\Local\Orcel\remote_leases.json",
    ];
    for (store, expected) in STORES.iter().zip(expected) {
        let path = (store.resolve)(&lookup).expect(store.name);
        assert_eq!(path.as_os_str(), expected, "{}", store.name);
    }
}

#[test]
fn absolute_overrides_are_kept_and_relative_ones_refused() {
    let base = sandbox("override");
    let custom = base.join("custom-xp01b.json");
    for (name, resolve) in [
        (
            "ORCEL_EXECUTABLE_REGISTRY_PATH",
            STORES[1].resolve as fn(Lookup<'_>) -> Result<PathBuf, String>,
        ),
        ("ORCEL_REMOTE_LEASE_PATH", STORES[2].resolve),
    ] {
        let path = resolve(&lookup(vec![(name, custom.clone().into_os_string())]));
        assert_eq!(path, Ok(custom.clone()), "{name}");
        for value in ["", "leases.json", "state/leases.json"] {
            let error = resolve(&lookup(vec![(name, OsString::from(value))]))
                .expect_err("relative override");
            assert!(
                error.contains("is not absolute"),
                "{name} {value:?}: {error}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(base);
}

/// Recovery: a store already written at the default location is read in
/// place, byte for byte, with no migration step.
#[test]
fn existing_lease_store_is_read_in_place_without_migration() {
    let base = sandbox("recover");
    let lookup = lookup(user_root_env(&base));
    let path = remote_session::default_lease_store_path_from(&lookup).expect("lease path");
    remote_session::save_leases(&path, &[]).expect("save");
    let before = std::fs::read(&path).expect("read");
    assert!(remote_session::load_leases(&path).is_empty());
    let again = remote_session::default_lease_store_path_from(&lookup).expect("lease path");
    assert_eq!(again, path);
    assert_eq!(std::fs::read(&again).expect("read"), before);
    let _ = std::fs::remove_dir_all(base);
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn chmod(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
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
    fn symlinked_root_is_refused_for_each_store() {
        for store in STORES {
            let base = sandbox("symlink");
            let target = base.join("elsewhere");
            std::fs::create_dir(&target).expect("target");
            chmod(&target, 0o700);
            let root = root_under(&base);
            std::os::unix::fs::symlink(&target, &root).expect("symlink");
            let error = (store.resolve)(&home_only(&base)).expect_err(store.name);
            assert!(
                error.contains("is a symbolic link"),
                "{}: {error}",
                store.name
            );
            assert_eq!(
                std::fs::read_dir(&target).expect("target").count(),
                0,
                "{}",
                store.name
            );
            let _ = std::fs::remove_dir_all(base);
        }
    }

    #[test]
    fn world_writable_root_is_refused_and_left_unrepaired() {
        for store in STORES {
            let base = sandbox("writable-root");
            let root = root_under(&base);
            std::fs::create_dir(&root).expect("root");
            chmod(&root, 0o777);
            let error = (store.resolve)(&home_only(&base)).expect_err(store.name);
            assert!(
                error.contains("grants group or other access"),
                "{}: {error}",
                store.name
            );
            let mode = std::fs::metadata(&root).expect("root").permissions().mode();
            assert_eq!(mode & 0o777, 0o777, "{}", store.name);
            let _ = std::fs::remove_dir_all(base);
        }
    }

    /// An override gets the default location's guarantees: a parent other
    /// users can reach is refused.
    #[test]
    fn override_in_a_shared_directory_is_refused() {
        for (name, resolve) in [
            (
                "ORCEL_EXECUTABLE_REGISTRY_PATH",
                STORES[1].resolve as fn(Lookup<'_>) -> Result<PathBuf, String>,
            ),
            ("ORCEL_REMOTE_LEASE_PATH", STORES[2].resolve),
        ] {
            let base = sandbox("shared-override");
            chmod(&base, 0o755);
            let error = resolve(&lookup(vec![(name, base.join("s.json").into_os_string())]))
                .expect_err("shared parent");
            assert!(
                error.contains("grants group or other access"),
                "{name}: {error}"
            );
            let _ = std::fs::remove_dir_all(base);
        }
    }

    #[test]
    fn world_writable_home_is_refused_before_anything_is_created() {
        for store in STORES {
            let base = sandbox("writable-home");
            chmod(&base, 0o777);
            let error = (store.resolve)(&home_only(&base)).expect_err(store.name);
            assert!(
                error.contains("is writable by other users"),
                "{}: {error}",
                store.name
            );
            assert_eq!(
                std::fs::read_dir(&base).expect("base").count(),
                0,
                "{}",
                store.name
            );
            chmod(&base, 0o700);
            let _ = std::fs::remove_dir_all(base);
        }
    }
}

/// A file in the legacy shared-temp `orcel` directory that earlier builds
/// defaulted to. Only what the test created is removed again; state an
/// earlier build already left there is kept, and serves as the seed.
struct LegacySeed {
    file: PathBuf,
    created_dir: bool,
    created_file: bool,
}

impl LegacySeed {
    /// Seeds `name` with `write` unless it already exists. `None` when the
    /// legacy directory belongs to someone else and cannot be written.
    fn plant(name: &str, write: impl FnOnce(&Path)) -> Option<Self> {
        let dir = std::env::temp_dir().join("orcel");
        let created_dir = !dir.exists();
        if std::fs::create_dir_all(&dir).is_err() {
            return None;
        }
        let file = dir.join(name);
        let created_file = !file.exists();
        if created_file {
            write(&file);
        }
        Some(Self {
            file,
            created_dir,
            created_file,
        })
    }
}

impl Drop for LegacySeed {
    fn drop(&mut self) {
        if self.created_file {
            let _ = std::fs::remove_file(&self.file);
        }
        if self.created_dir {
            if let Some(dir) = self.file.parent() {
                let _ = std::fs::remove_dir(dir);
            }
        }
    }
}

/// Recovery: a lease store an earlier build left under the shared temp
/// directory is not migrated and never read; the private default starts
/// empty, so every remote request stays fail-closed until a new lease.
#[test]
fn legacy_shared_temp_lease_store_is_ignored() {
    let seed = LegacySeed::plant("remote_leases.json", |path| {
        remote_session::save_leases(path, &[remote_session::tests::lease()]).expect("seed");
    });
    if let Some(seed) = &seed {
        if seed.created_file {
            assert_eq!(remote_session::load_leases(&seed.file).len(), 1);
        }
    }
    let base = sandbox("legacy");
    let lookup = lookup(user_root_env(&base));
    let path = remote_session::default_lease_store_path_from(&lookup).expect("lease path");
    assert_ne!(
        path,
        std::env::temp_dir()
            .join("orcel")
            .join("remote_leases.json")
    );
    assert!(remote_session::load_leases(&path).is_empty());
    assert!(!path.exists(), "nothing is copied from the legacy store");
    let roots = crate::protected_state::protected_state_roots_from(&lookup);
    assert!(!roots.contains(&std::env::temp_dir().join("orcel")));
    drop(seed);
    let _ = std::fs::remove_dir_all(base);
}
