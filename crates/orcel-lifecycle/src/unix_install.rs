//! MAC-M1-03: the per-user install tree on macOS (and its owner and mode
//! rules on every Unix).
//!
//! The install lives under the XP-01 state root, which on macOS is
//! `~/Library/Application Support/Orcel` ([`crate::layout::Layout`]):
//! `versions/<version>/` holds the hash-checked payload, `current.json`
//! points at the active version, `install.json` records it, and `bin/orcel`
//! is a copy of the active CLI. The same layout and the same
//! [`crate::install::Installer`] as on Windows; only the host operations
//! differ, and they take the place of the Windows owner-only DACL:
//!
//! - [`protect_tree`]: the root is made 0700 and must then pass XP-01's
//!   private-directory rule ([`orcel_platform::paths::verify_existing_private_dir`]:
//!   owned by the user, 0700, no extended ACL grant, and every ancestor owned
//!   by the user or root and not writable by group or others, so a root under
//!   an admin-writable folder such as `/Applications` is refused). Every
//!   entry beneath loses its group and other bits. A link, an entry of
//!   another owner, or anything but a file or a folder fails closed and
//!   nothing further is changed.
//! - [`verify_tree`]: the same root rule, then every entry beneath must be
//!   this user's, not a link, not writable by group or others, and a file
//!   must have no other hard link
//!   ([`orcel_platform::paths::check_migration_entry`]).
//!
//! The tree is in use while it is walked: an `orceld` that a client starts
//! writes state files, and its start script moves its log. An entry that is
//! gone, or is no longer the same entry, when it is looked at does not fail
//! the walk and is not skipped either: the whole tree is walked again until
//! one walk saw nothing change, so what it was renamed to is checked as well.
//! A tree that keeps changing is refused. Every other error is returned as it
//! is. A mode is changed without following a link. The walk reads names, so
//! another program of the same user that moves entries around while it runs
//! can still hide one or lead it into another folder; the 0700 root keeps
//! other users out, and nothing here defends against the user's own programs.
//!
//! Hashes and unlisted files are the manifest's job
//! ([`crate::manifest::verify_payload`]), which also refuses a hard-linked
//! payload file on Unix.
//!
//! [`MacosPlatform`] exists on macOS only. It also writes, loads, unloads
//! and removes the per-user launchd agent that starts `orceld` on demand
//! (MAC-M1-07, [`crate::launchd`]) whenever the active version changes and
//! on uninstall. `host_platform()` does not return it yet: the `orcel`
//! lifecycle commands on macOS wait for the founder's activation of the macOS
//! M1 grain (approval 1 in `MACOS_M0_READINESS.md`). Until then it is reached
//! from tests on the hosted macOS runner only.

use crate::LifecycleError;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

/// The macOS release the install supports at least (MAC-M1-01's deployment
/// target).
pub const MIN_MACOS_MAJOR: u32 = 15;

fn effective_uid() -> Result<u32, LifecycleError> {
    orcel_platform::session::effective_uid()
        .ok_or_else(|| LifecycleError::platform("the effective user id is unavailable"))
}

fn refuse(path: &Path, why: &str) -> LifecycleError {
    LifecycleError::state(format!(
        "the Orcel install tree is not private to you and was not changed further: {} {why}",
        path.display()
    ))
}

/// Makes `root` and everything beneath it private to the user (see the
/// module documentation).
pub fn protect_tree(root: &Path) -> Result<(), LifecycleError> {
    let uid = effective_uid()?;
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| LifecycleError::io(format!("inspect {}", root.display()), error))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(refuse(root, "is not a plain folder"));
    }
    if metadata.uid() != uid {
        return Err(refuse(root, "is owned by another user"));
    }
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))
        .map_err(|error| LifecycleError::io(format!("protect {}", root.display()), error))?;
    orcel_platform::paths::verify_existing_private_dir(root)
        .map_err(|error| LifecycleError::state(format!("the Orcel install root: {error}")))?;
    walk_until_still(root, &mut |walk| walk.protect(root, uid), &mut |_| {})
}

/// How often a tree that changes while it is walked is walked again.
const WALKS: u32 = 16;

/// One walk of the tree.
struct Walk<'a> {
    /// An entry was gone, or was another one, when it was looked at.
    changed: bool,
    /// Called between the first look at an entry and its check; tests change
    /// the tree there.
    between: &'a mut dyn FnMut(&Path),
}

/// Walks until one walk saw no entry change; a tree that keeps changing is
/// refused.
fn walk_until_still(
    root: &Path,
    walk: &mut dyn FnMut(&mut Walk) -> Result<(), LifecycleError>,
    between: &mut dyn FnMut(&Path),
) -> Result<(), LifecycleError> {
    for _ in 0..WALKS {
        let mut one = Walk {
            changed: false,
            between: &mut *between,
        };
        walk(&mut one)?;
        if !one.changed {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    Err(refuse(root, "keeps changing while it is checked"))
}

fn is_gone(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::NotFound
}

/// The entry under a name now, a link not followed; `None` when it is gone.
fn look(path: &Path) -> Result<Option<fs::Metadata>, LifecycleError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if is_gone(&error) => Ok(None),
        Err(error) => Err(LifecycleError::io(
            format!("inspect {}", path.display()),
            error,
        )),
    }
}

fn same_entry(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.file_type() == after.file_type()
}

/// Sets the mode of the entry itself: a link is never followed.
fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // SAFETY: `name` is a NUL-terminated string that outlives the call;
    // fchmodat keeps no pointer to it and touches no other memory.
    let result = unsafe {
        libc::fchmodat(
            libc::AT_FDCWD,
            name.as_ptr(),
            mode as libc::mode_t,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

impl Walk<'_> {
    /// The paths in `dir`.
    fn names(dir: &Path) -> std::io::Result<Vec<std::path::PathBuf>> {
        fs::read_dir(dir)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect()
    }

    /// The paths in the folder `path`, which `before` described; `None`, and
    /// noted, when it is gone or another entry by now.
    fn enter(
        &mut self,
        path: &Path,
        before: &fs::Metadata,
    ) -> Result<Option<Vec<std::path::PathBuf>>, LifecycleError> {
        let names = match Self::names(path) {
            Ok(names) => names,
            Err(error) if is_gone(&error) => {
                self.changed = true;
                return Ok(None);
            }
            Err(error) => {
                return Err(LifecycleError::io(
                    format!("read {}", path.display()),
                    error,
                ))
            }
        };
        if self.unchanged(path, before)? {
            Ok(Some(names))
        } else {
            Ok(None)
        }
    }

    /// Whether `path` is still the entry `before` described; noted when not.
    fn unchanged(&mut self, path: &Path, before: &fs::Metadata) -> Result<bool, LifecycleError> {
        let same = look(path)?.is_some_and(|after| same_entry(before, &after));
        self.changed |= !same;
        Ok(same)
    }

    fn protect(&mut self, root: &Path, uid: u32) -> Result<(), LifecycleError> {
        let names = Self::names(root)
            .map_err(|error| LifecycleError::io(format!("read {}", root.display()), error))?;
        for path in names {
            self.protect_entry(&path, uid)?;
        }
        Ok(())
    }

    fn protect_entry(&mut self, path: &Path, uid: u32) -> Result<(), LifecycleError> {
        let Some(before) = look(path)? else {
            self.changed = true;
            return Ok(());
        };
        (self.between)(path);
        let file_type = before.file_type();
        if file_type.is_symlink() {
            return Err(refuse(path, "is a link"));
        }
        if before.uid() != uid {
            return Err(refuse(path, "is owned by another user"));
        }
        let mode = if file_type.is_dir() {
            0o700
        } else if file_type.is_file() {
            before.mode() & 0o700
        } else {
            return Err(refuse(path, "is neither a file nor a folder"));
        };
        if !self.unchanged(path, &before)? {
            return Ok(());
        }
        match set_mode(path, mode) {
            Ok(()) => {}
            Err(error) if is_gone(&error) => {
                self.changed = true;
                return Ok(());
            }
            Err(error) => {
                return Err(LifecycleError::io(
                    format!("protect {}", path.display()),
                    error,
                ))
            }
        }
        if file_type.is_dir() {
            for child in self.enter(path, &before)?.unwrap_or_default() {
                self.protect_entry(&child, uid)?;
            }
            Ok(())
        } else {
            self.unchanged(path, &before).map(|_| ())
        }
    }

    fn verify(&mut self, root: &Path) -> Result<(), LifecycleError> {
        let names = Self::names(root)
            .map_err(|error| LifecycleError::io(format!("read {}", root.display()), error))?;
        for path in names {
            self.verify_entry(&path)?;
        }
        Ok(())
    }

    fn verify_entry(&mut self, path: &Path) -> Result<(), LifecycleError> {
        let Some(before) = look(path)? else {
            self.changed = true;
            return Ok(());
        };
        (self.between)(path);
        let checked = orcel_platform::paths::check_migration_entry(path);
        // The check is of the entry there now; another one than before, or
        // none, says nothing about this one.
        if !self.unchanged(path, &before)? {
            return Ok(());
        }
        checked
            .map_err(|reason| LifecycleError::state(format!("the Orcel install tree: {reason}")))?;
        if before.is_dir() {
            for child in self.enter(path, &before)?.unwrap_or_default() {
                self.verify_entry(&child)?;
            }
            Ok(())
        } else if before.is_file() {
            Ok(())
        } else {
            Err(refuse(path, "is neither a file nor a folder"))
        }
    }
}

/// Verifies that `root` and everything beneath it are private to the user
/// (see the module documentation). Changes nothing.
pub fn verify_tree(root: &Path) -> Result<(), LifecycleError> {
    orcel_platform::paths::verify_existing_private_dir(root)
        .map_err(|error| LifecycleError::state(format!("the Orcel install root: {error}")))?;
    walk_until_still(root, &mut |walk| walk.verify(root), &mut |_| {})
}

/// Moves an oversized agent log aside (MAC-M1-07), best effort: the start
/// script checks the log every time, so a log that cannot be moved aside is
/// noted in the lifecycle log and never fails an install, update, rollback,
/// restore or recovery. Links and foreign owners in the install are still
/// refused by [`protect_tree`] and [`verify_tree`].
#[cfg(any(target_os = "macos", test))]
pub(crate) fn move_agent_log_aside(layout: &crate::layout::Layout) -> std::path::PathBuf {
    let log = layout.logs_dir().join(crate::launchd::STDERR_LOG);
    if let Err(error) = crate::launchd::rotate_log(&log, crate::launchd::MAX_STDERR_LOG) {
        crate::logs::transcript(
            layout,
            &format!("agent log not moved aside: {}", error.message),
        );
    }
    log
}

/// Parses `sw_vers -productVersion` output such as `15.8.2` into its major
/// version.
pub fn parse_macos_major(output: &str) -> Result<u32, LifecycleError> {
    let text = output.trim();
    text.split('.')
        .next()
        .filter(|major| !major.is_empty() && major.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|major| major.parse().ok())
        .ok_or_else(|| LifecycleError::prerequisite(format!("unexpected macOS version {text:?}")))
}

#[cfg(target_os = "macos")]
pub use macos::{AgentTarget, MacosPlatform};

#[cfg(target_os = "macos")]
mod macos {
    use super::{parse_macos_major, MIN_MACOS_MAJOR};
    use crate::launchd::{self, AgentSpec};
    use crate::layout::Layout;
    use crate::platform::Platform;
    use crate::version::Version;
    use crate::LifecycleError;
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output, Stdio};

    /// `launchctl` by absolute path, never from `PATH`.
    const LAUNCHCTL: &str = "/bin/launchctl";

    /// Where the per-user launchd agent goes (MAC-M1-07).
    #[derive(Debug, Clone, Default)]
    pub enum AgentTarget {
        /// `~/Library/LaunchAgents/ai.orcel.orceld.plist`, its socket in
        /// the per-user runtime directory, loaded in `gui/<uid>`.
        #[default]
        CurrentUser,
        /// Its own folder, label, socket and extra environment (the hosted
        /// runner tests, so they never touch the runner user's agents).
        Custom {
            plist_dir: PathBuf,
            label: String,
            socket: PathBuf,
            extra_environment: BTreeMap<String, String>,
        },
        /// No agent: the install tests that do not exercise launchd.
        None,
    }

    /// A resolved agent: its plist folder, label, socket and extra
    /// environment.
    type ResolvedAgent = (PathBuf, String, PathBuf, BTreeMap<String, String>);

    /// The macOS host operations of the per-user install (MAC-M1-03) and
    /// its launchd agent (MAC-M1-07).
    #[derive(Debug, Default)]
    pub struct MacosPlatform {
        pub agent: AgentTarget,
    }

    impl MacosPlatform {
        /// The host operations without a launchd agent.
        pub fn without_agent() -> Self {
            Self {
                agent: AgentTarget::None,
            }
        }

        /// The agent's folder, label, socket and extra environment, or
        /// `None` when this platform has no agent.
        fn agent(&self) -> Result<Option<ResolvedAgent>, LifecycleError> {
            match &self.agent {
                AgentTarget::None => Ok(None),
                AgentTarget::Custom {
                    plist_dir,
                    label,
                    socket,
                    extra_environment,
                } => Ok(Some((
                    plist_dir.clone(),
                    label.clone(),
                    socket.clone(),
                    extra_environment.clone(),
                ))),
                AgentTarget::CurrentUser => {
                    let home = std::env::var_os("HOME")
                        .map(PathBuf::from)
                        .filter(|home| home.is_absolute())
                        .ok_or_else(|| {
                            LifecycleError::prerequisite(
                                "HOME is not an absolute path; the launchd agent has no folder",
                            )
                        })?;
                    let runtime =
                        orcel_platform::paths::macos_per_user_runtime_dir().ok_or_else(|| {
                            LifecycleError::prerequisite(
                                "macOS gave no per-user runtime directory for the orceld socket",
                            )
                        })?;
                    Ok(Some((
                        launchd::launch_agents_dir(&home),
                        launchd::LABEL.to_owned(),
                        launchd::socket_path(&runtime),
                        BTreeMap::new(),
                    )))
                }
            }
        }
    }

    fn launchctl(args: &[&str]) -> Result<Output, LifecycleError> {
        Command::new(LAUNCHCTL)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .map_err(|error| LifecycleError::platform(format!("run launchctl: {error}")))
    }

    /// `gui/<uid>`, the logged-in user's domain.
    fn domain() -> Result<String, LifecycleError> {
        Ok(format!("gui/{}", super::effective_uid()?))
    }

    fn loaded(label: &str) -> Result<bool, LifecycleError> {
        Ok(launchctl(&["print", &format!("{}/{label}", domain()?)])?
            .status
            .success())
    }

    /// How long an agent may take to unload.
    const UNLOAD: std::time::Duration = std::time::Duration::from_secs(10);

    /// Unloads the agent and waits until it is: `launchctl bootout` can
    /// answer before launchd is done, and a new agent of the same label
    /// cannot be loaded until then.
    fn bootout(label: &str) -> Result<(), LifecycleError> {
        if !loaded(label)? {
            return Ok(());
        }
        let output = launchctl(&["bootout", &format!("{}/{label}", domain()?)])?;
        let deadline = std::time::Instant::now() + UNLOAD;
        while loaded(label)? {
            if std::time::Instant::now() > deadline {
                return Err(LifecycleError::platform(format!(
                    "launchctl could not unload {label}: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                )));
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        Ok(())
    }

    /// Removes a leftover socket of this user; anything else there is an
    /// error, never removed.
    fn remove_socket(socket: &Path) -> Result<bool, LifecycleError> {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let Ok(metadata) = std::fs::symlink_metadata(socket) else {
            return Ok(false);
        };
        if !metadata.file_type().is_socket() || metadata.uid() != super::effective_uid()? {
            return Err(LifecycleError::state(format!(
                "{} is not this user's orceld socket and was left in place",
                socket.display()
            )));
        }
        std::fs::remove_file(socket)
            .map_err(|error| LifecycleError::io(format!("remove {}", socket.display()), error))?;
        Ok(true)
    }

    impl Platform for MacosPlatform {
        /// Writes the agent for the `orceld` of the active version, with the
        /// configured workspaces, and loads it in place of an earlier one.
        fn refresh_service(&self, layout: &Layout, orceld: &Path) -> Result<(), LifecycleError> {
            let Some((plist_dir, label, socket, extra)) = self.agent()? else {
                return Ok(());
            };
            let config = crate::config::Config::load(layout)?;
            let stderr_log = super::move_agent_log_aside(layout);
            let mut environment = launchd::agent_environment(&config);
            environment.extend(extra);
            let spec = AgentSpec {
                label: label.clone(),
                program: orceld.to_path_buf(),
                stderr_log: stderr_log.clone(),
                socket: socket.clone(),
                environment,
            };
            let text = launchd::plist(&spec)?;
            let socket_dir = socket.parent().ok_or_else(|| {
                LifecycleError::state("the orceld socket path has no parent folder")
            })?;
            orcel_platform::paths::ensure_private_dir(socket_dir).map_err(|error| {
                LifecycleError::state(format!("the orceld socket folder: {error}"))
            })?;
            std::fs::create_dir_all(&plist_dir).map_err(|error| {
                LifecycleError::io(format!("create {}", plist_dir.display()), error)
            })?;
            let plist_path = plist_dir.join(spec.plist_file_name());
            bootout(&label)?;
            remove_socket(&socket)?;
            orcel_platform::files::write_private_atomic(&plist_path, text.as_bytes()).map_err(
                |error| LifecycleError::io(format!("write {}", plist_path.display()), error),
            )?;
            let plist_text = plist_path.to_str().ok_or_else(|| {
                LifecycleError::state("the launchd agent's folder is not valid UTF-8")
            })?;
            let output = launchctl(&["bootstrap", &domain()?, plist_text])?;
            if !output.status.success() {
                return Err(LifecycleError::platform(format!(
                    "launchctl could not load {label}: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                )));
            }
            Ok(())
        }

        /// Unloads the agent, then removes its plist and socket.
        fn remove_service(&self) -> Result<Vec<PathBuf>, LifecycleError> {
            let Some((plist_dir, label, socket, _)) = self.agent()? else {
                return Ok(Vec::new());
            };
            bootout(&label)?;
            let mut removed = Vec::new();
            let plist_path = plist_dir.join(format!("{label}.plist"));
            if std::fs::symlink_metadata(&plist_path).is_ok() {
                std::fs::remove_file(&plist_path).map_err(|error| {
                    LifecycleError::io(format!("remove {}", plist_path.display()), error)
                })?;
                removed.push(plist_path);
            }
            if remove_socket(&socket)? {
                removed.push(socket);
            }
            Ok(removed)
        }

        fn windows_build(&self) -> Result<u32, LifecycleError> {
            Err(LifecycleError::prerequisite("this is macOS, not Windows"))
        }
        /// Running as root is the avoidable elevation on macOS: the
        /// install is per user and needs no administrator rights.
        fn is_avoidably_elevated(&self) -> Result<bool, LifecycleError> {
            Ok(super::effective_uid()? == 0)
        }
        fn protect_tree(&self, root: &Path) -> Result<(), LifecycleError> {
            super::protect_tree(root)
        }
        fn verify_tree_acl(&self, root: &Path) -> Result<(), LifecycleError> {
            super::verify_tree(root)
        }
        /// The user's shell `PATH` is not managed on macOS; nothing is
        /// added (`bin/orcel` is used by its full path).
        fn add_user_path(&self, _dir: &Path) -> Result<bool, LifecycleError> {
            Ok(false)
        }
        fn remove_user_path(&self, _dir: &Path) -> Result<bool, LifecycleError> {
            Ok(false)
        }
        fn add_start_menu_entry(&self, _cli: &Path) -> Result<(), LifecycleError> {
            Err(LifecycleError::platform("macOS has no Start Menu"))
        }
        fn remove_start_menu_entry(&self, _cli: &Path) -> Result<bool, LifecycleError> {
            Ok(false)
        }
        fn has_start_menu_entry(&self, _cli: &Path) -> Result<bool, LifecycleError> {
            Ok(false)
        }
        fn node_version(&self, node: &Path) -> Result<Version, LifecycleError> {
            crate::platform::run_node_version(node)
        }
        /// macOS 15 or later, read from `/usr/bin/sw_vers` by absolute path.
        fn check_os_version(&self) -> Result<(), LifecycleError> {
            let output = std::process::Command::new("/usr/bin/sw_vers")
                .arg("-productVersion")
                .stdin(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .output()
                .map_err(|error| {
                    LifecycleError::prerequisite(format!("read the macOS version: {error}"))
                })?;
            if !output.status.success() {
                return Err(LifecycleError::prerequisite(
                    "sw_vers could not read the macOS version",
                ));
            }
            let major = parse_macos_major(&String::from_utf8_lossy(&output.stdout))?;
            if major < MIN_MACOS_MAJOR {
                return Err(LifecycleError::prerequisite(format!(
                    "macOS {major} is older than the supported minimum macOS {MIN_MACOS_MAJOR}"
                )));
            }
            Ok(())
        }
        fn check_lifecycle_supported(&self) -> Result<(), LifecycleError> {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::temp_dir;

    /// A parent folder 0755 whatever the umask, so only what a test changes
    /// is insecure.
    fn parent(label: &str) -> std::path::PathBuf {
        let dir = temp_dir(label);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        dir
    }

    fn private_root(label: &str) -> std::path::PathBuf {
        let root = parent(label).join("Orcel");
        fs::create_dir_all(root.join("versions/0.2.0")).unwrap();
        fs::write(root.join("versions/0.2.0/orceld"), b"x").unwrap();
        fs::set_permissions(
            root.join("versions/0.2.0/orceld"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        root
    }

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().mode() & 0o777
    }

    #[test]
    fn protect_strips_group_and_other_bits_and_verify_then_passes() {
        let root = private_root("unix-protect");
        protect_tree(&root).unwrap();
        assert_eq!(mode(&root), 0o700);
        assert_eq!(mode(&root.join("versions")), 0o700);
        assert_eq!(mode(&root.join("versions/0.2.0/orceld")), 0o700);
        verify_tree(&root).unwrap();
    }

    #[test]
    fn a_group_writable_entry_fails_verification() {
        let root = private_root("unix-group-write");
        protect_tree(&root).unwrap();
        let file = root.join("versions/0.2.0/orceld");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o720)).unwrap();
        assert!(verify_tree(&root).is_err());
        fs::set_permissions(&file, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(root.join("versions"), fs::Permissions::from_mode(0o702)).unwrap();
        assert!(verify_tree(&root).is_err());
    }

    #[test]
    fn a_readable_root_fails_verification() {
        let root = private_root("unix-root-mode");
        protect_tree(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(verify_tree(&root).is_err());
    }

    #[test]
    fn links_fail_closed_in_protect_and_verify() {
        let root = private_root("unix-link");
        protect_tree(&root).unwrap();
        let outside = parent("unix-link-target");
        std::os::unix::fs::symlink(&outside, root.join("versions/escape")).unwrap();
        assert!(verify_tree(&root).is_err());
        assert!(protect_tree(&root).is_err());
        // The link target was never touched.
        assert_ne!(mode(&outside), 0o700);
    }

    #[test]
    fn a_hard_linked_file_fails_verification() {
        let root = private_root("unix-hardlink");
        protect_tree(&root).unwrap();
        let alias = temp_dir("unix-hardlink-alias").join("alias");
        fs::hard_link(root.join("versions/0.2.0/orceld"), alias).unwrap();
        assert!(verify_tree(&root).is_err());
    }

    #[test]
    fn a_root_under_a_group_writable_folder_is_refused() {
        // The shape of /Applications (root:admin 0775): writable by a group.
        let shared = temp_dir("unix-shared-parent");
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o775)).unwrap();
        let root = shared.join("Orcel");
        fs::create_dir_all(&root).unwrap();
        assert!(protect_tree(&root).is_err());
        assert!(verify_tree(&root).is_err());
    }

    fn walk_both(
        root: &Path,
        protect: bool,
        between: &mut dyn FnMut(&Path),
    ) -> Result<(), LifecycleError> {
        let uid = effective_uid().unwrap();
        walk_until_still(
            root,
            &mut |walk| {
                if protect {
                    walk.protect(root, uid)
                } else {
                    walk.verify(root)
                }
            },
            between,
        )
    }

    fn write(path: &Path, mode: u32) {
        fs::write(path, b"x").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    /// A root with one private log, and the log's path.
    fn with_log(label: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let root = private_root(label);
        fs::create_dir_all(root.join("logs")).unwrap();
        protect_tree(&root).unwrap();
        let log = root.join("logs/agent.log");
        write(&log, 0o600);
        (root, log)
    }

    #[test]
    fn an_entry_that_vanishes_while_walked_does_not_fail_the_walk() {
        for protect in [true, false] {
            let (root, log) = with_log("unix-vanish");
            walk_both(&root, protect, &mut |path| {
                if path == log {
                    let _ = fs::remove_file(&log);
                }
            })
            .unwrap();
            // A folder too, with what is in it.
            let folder = root.join("logs/folder");
            fs::create_dir(&folder).unwrap();
            fs::set_permissions(&folder, fs::Permissions::from_mode(0o700)).unwrap();
            write(&folder.join("inside"), 0o600);
            walk_both(&root, protect, &mut |path| {
                if path == folder {
                    let _ = fs::remove_dir_all(&folder);
                }
            })
            .unwrap();
        }
    }

    #[test]
    fn what_an_entry_is_renamed_to_is_still_checked() {
        let (root, log) = with_log("unix-rename");
        let aside = root.join("logs/agent.log.1");
        // Renamed while walked, and writable by the group under its new name.
        let mut rename = |path: &Path| {
            if path == log {
                fs::rename(&log, &aside).unwrap();
                fs::set_permissions(&aside, fs::Permissions::from_mode(0o620)).unwrap();
            }
        };
        assert!(walk_both(&root, false, &mut rename).is_err());
        fs::rename(&aside, &log).unwrap();
        walk_both(&root, true, &mut rename).unwrap();
        assert_eq!(mode(&aside), 0o600, "protected under its new name");
    }

    #[test]
    fn an_entry_swapped_for_a_link_is_refused_and_never_followed() {
        for protect in [true, false] {
            for dangling in [true, false] {
                let (root, log) = with_log("unix-swap");
                let outside = parent("unix-swap-target").join("outside");
                if !dangling {
                    write(&outside, 0o644);
                }
                let mut swapped = false;
                let result = walk_both(&root, protect, &mut |path| {
                    if path == log && !swapped {
                        swapped = true;
                        fs::remove_file(&log).unwrap();
                        std::os::unix::fs::symlink(&outside, &log).unwrap();
                    }
                });
                assert!(result.is_err(), "protect {protect} dangling {dangling}");
                if !dangling {
                    assert_eq!(mode(&outside), 0o644, "the target was not touched");
                }
            }
        }
        // The mode change itself does not follow a link.
        let dir = parent("unix-no-follow");
        write(&dir.join("target"), 0o644);
        std::os::unix::fs::symlink(dir.join("target"), dir.join("link")).unwrap();
        let _ = set_mode(&dir.join("link"), 0o600);
        assert_eq!(mode(&dir.join("target")), 0o644);
    }

    #[test]
    fn an_entry_swapped_for_an_insecure_one_is_refused() {
        let (root, log) = with_log("unix-swap-file");
        let other = root.join("logs/other");
        let mut swapped = false;
        let result = walk_both(&root, false, &mut |path| {
            if path == log && !swapped {
                swapped = true;
                write(&other, 0o620);
                fs::rename(&other, &log).unwrap();
            }
        });
        assert!(result.is_err());
    }

    #[test]
    fn a_tree_that_keeps_changing_is_refused() {
        for protect in [true, false] {
            let (root, log) = with_log("unix-busy");
            let other = root.parent().unwrap().join("other");
            let error = walk_both(&root, protect, &mut |path| {
                if path == log {
                    write(&other, 0o600);
                    fs::rename(&other, &log).unwrap();
                }
            })
            .unwrap_err();
            assert!(
                error.message.contains("keeps changing"),
                "{}",
                error.message
            );
        }
    }

    #[test]
    fn only_a_missing_entry_is_tolerated() {
        let root = private_root("unix-missing-root");
        fs::remove_dir_all(&root).unwrap();
        assert!(walk_both(&root, true, &mut |_| {}).is_err(), "no root");
        assert!(walk_both(&root, false, &mut |_| {}).is_err(), "no root");
        // Root reads any folder, so this says nothing for it.
        if effective_uid().unwrap() != 0 {
            let root = private_root("unix-unreadable");
            protect_tree(&root).unwrap();
            let closed = root.join("versions");
            fs::set_permissions(&closed, fs::Permissions::from_mode(0o000)).unwrap();
            assert!(verify_tree(&root).is_err(), "a folder that cannot be read");
            fs::set_permissions(&closed, fs::Permissions::from_mode(0o700)).unwrap();
            verify_tree(&root).unwrap();
        }
    }

    /// As a running agent and `orceld` use it: a log moved aside and made
    /// again, and records that come and go, while the tree is walked.
    #[test]
    fn a_tree_in_use_passes() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let (root, log) = with_log("unix-in-use");
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let worker = {
            let (stop, root, log) = (stop.clone(), root.clone(), log.clone());
            std::thread::spawn(move || {
                let mut round = 0u32;
                while !stop.load(Ordering::Acquire) {
                    let record = root.join(format!("logs/record-{round}"));
                    orcel_platform::files::write_private_atomic(&record, b"x").unwrap();
                    fs::rename(&log, root.join("logs/agent.log.1")).unwrap();
                    orcel_platform::files::write_private_atomic(&log, b"x").unwrap();
                    std::thread::sleep(std::time::Duration::from_millis(5));
                    fs::remove_file(&record).unwrap();
                    round += 1;
                }
                round
            })
        };
        let mut result = Ok(());
        for _ in 0..100 {
            result = protect_tree(&root).and_then(|()| verify_tree(&root));
            if result.is_err() {
                break;
            }
        }
        stop.store(true, Ordering::Release);
        assert!(worker.join().unwrap() > 0);
        result.unwrap();
    }

    #[test]
    fn macos_versions_parse_strictly() {
        assert_eq!(parse_macos_major("15.8.2\n").unwrap(), 15);
        assert_eq!(parse_macos_major("26.7.2").unwrap(), 26);
        assert_eq!(parse_macos_major("15").unwrap(), 15);
        for bad in ["", "x.1", "-15.0", " .1"] {
            assert!(parse_macos_major(bad).is_err(), "{bad:?}");
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn this_runner_is_a_supported_macos_and_not_root() {
        use crate::platform::Platform;
        let platform = MacosPlatform::without_agent();
        platform.check_os_version().unwrap();
        assert!(!platform.is_avoidably_elevated().unwrap());
        platform.check_lifecycle_supported().unwrap();
        assert!(platform.windows_build().is_err());
    }
}
