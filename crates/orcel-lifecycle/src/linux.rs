//! XP-17 Linux per-user layout under the XDG Base Directory specification.
//!
//! | Purpose | Path |
//! | --- | --- |
//! | state (audit, approvals, trust, leases) | the XP-01 state root, `$XDG_STATE_HOME/orcel`, else `$HOME/.local/state/orcel`, mode 0700 |
//! | per-user payload (tarball install) | `$XDG_DATA_HOME/orcel`, else `$HOME/.local/share/orcel` |
//! | `orceld` environment (`orceld.env`) | `$XDG_CONFIG_HOME/orcel`, else `$HOME/.config/orcel` |
//! | per-user systemd units | `$XDG_CONFIG_HOME/systemd/user`, else `$HOME/.config/systemd/user` |
//! | `orceld` socket | `$XDG_RUNTIME_DIR/orcel/orceld.sock`, only when `XDG_RUNTIME_DIR` is set |
//!
//! The deb and rpm packages install read-only, root-owned binaries in
//! [`PACKAGE_LIB_DIR`] and the user units in [`PACKAGE_USER_UNIT_DIR`];
//! every location the user writes stays per-user. Nothing resolves under
//! `/tmp`.
//!
//! Every variable goes through XP-01's rules
//! ([`orcel_platform::paths::absolute_var`]): a relative or `.`/`..`-bearing
//! `XDG_*` value is ignored as the XDG specification requires, and a
//! missing or unusable `HOME` is an error, never a fallback elsewhere.
//!
//! The functions are pure over `lookup`, so the layout is tested on every
//! OS; only [`XdgLayout::for_current_user`] is Linux-only.

use orcel_platform::paths::{self, PlatformError, StateLayout};
use std::ffi::OsString;
use std::path::PathBuf;

/// Where the deb and rpm packages install `orceld` and `orcel`.
pub const PACKAGE_LIB_DIR: &str = "/usr/lib/orcel";
/// Where the deb and rpm packages install the systemd user units.
pub const PACKAGE_USER_UNIT_DIR: &str = "/usr/lib/systemd/user";
/// The socket unit that starts one `orceld` per connection.
pub const SOCKET_UNIT: &str = "orceld.socket";
/// The per-connection service template the socket unit instantiates.
pub const SERVICE_UNIT: &str = "orceld@.service";
/// The `orceld` environment file inside [`XdgLayout::config_dir`].
pub const ENV_FILE: &str = "orceld.env";

/// The per-user Linux locations of one user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XdgLayout {
    /// XP-01 private state root.
    pub state_root: PathBuf,
    /// Per-user payload of a tarball install.
    pub data_root: PathBuf,
    /// User configuration, including [`ENV_FILE`].
    pub config_dir: PathBuf,
    /// The user's systemd unit directory.
    pub user_unit_dir: PathBuf,
    /// `$XDG_RUNTIME_DIR/orcel`; `None` when the session has no runtime
    /// directory.
    pub runtime_dir: Option<PathBuf>,
}

impl XdgLayout {
    /// The layout `lookup` describes.
    pub fn from_lookup(lookup: &dyn Fn(&str) -> Option<OsString>) -> Result<Self, PlatformError> {
        let state_root = paths::state_root_for(StateLayout::Xdg, lookup)?;
        let data_home = base_dir(lookup, "XDG_DATA_HOME", &[".local", "share"])?;
        let config_home = base_dir(lookup, "XDG_CONFIG_HOME", &[".config"])?;
        Ok(Self {
            state_root,
            data_root: data_home.join("orcel"),
            config_dir: config_home.join("orcel"),
            user_unit_dir: config_home.join("systemd").join("user"),
            runtime_dir: paths::absolute_var(StateLayout::Xdg, lookup, "XDG_RUNTIME_DIR")
                .map(|runtime| runtime.join("orcel")),
        })
    }

    /// The layout of the current user, from the process environment.
    #[cfg(target_os = "linux")]
    pub fn for_current_user() -> Result<Self, PlatformError> {
        Self::from_lookup(&|name| std::env::var_os(name))
    }

    /// `orceld` of a tarball install.
    pub fn tarball_orceld(&self) -> PathBuf {
        self.data_root.join("bin").join("orceld")
    }

    /// The environment file both unit files read.
    pub fn env_file(&self) -> PathBuf {
        self.config_dir.join(ENV_FILE)
    }

    /// The socket [`SOCKET_UNIT`] listens on.
    pub fn socket(&self) -> Option<PathBuf> {
        self.runtime_dir
            .as_ref()
            .map(|runtime| runtime.join("orceld.sock"))
    }
}

/// `$name` when usable, else `$HOME` joined with `fallback`.
fn base_dir(
    lookup: &dyn Fn(&str) -> Option<OsString>,
    name: &str,
    fallback: &[&str],
) -> Result<PathBuf, PlatformError> {
    if let Some(dir) = paths::absolute_var(StateLayout::Xdg, lookup, name) {
        return Ok(dir);
    }
    let home = paths::absolute_var(StateLayout::Xdg, lookup, "HOME").ok_or_else(|| {
        PlatformError::StateRootUnavailable(format!(
            "{name} or HOME is not set to an absolute path"
        ))
    })?;
    Ok(fallback.iter().fold(home, |dir, part| dir.join(part)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::{Component, Path};

    const SOCKET: &str = include_str!("../../../distribution/linux/orceld.socket");
    const SERVICE: &str = include_str!("../../../distribution/linux/orceld@.service");
    const NFPM: &str = include_str!("../../../distribution/linux/nfpm.yaml");

    fn layout(vars: &[(&str, &str)]) -> Result<XdgLayout, PlatformError> {
        let vars: BTreeMap<String, OsString> = vars
            .iter()
            .map(|(name, value)| (name.to_string(), OsString::from(value)))
            .collect();
        XdgLayout::from_lookup(&|name| vars.get(name).cloned())
    }

    /// Unix paths compared component-wise, so the test also holds on
    /// Windows, where `Path::join` inserts `\`.
    fn unix(path: &Path) -> String {
        path.components()
            .map(|part| match part {
                Component::RootDir => String::new(),
                other => other.as_os_str().to_string_lossy().into_owned(),
            })
            .collect::<Vec<_>>()
            .join("/")
    }

    #[test]
    fn home_only_uses_the_xdg_defaults() {
        let layout = layout(&[("HOME", "/home/ana")]).unwrap();
        assert_eq!(unix(&layout.state_root), "/home/ana/.local/state/orcel");
        assert_eq!(unix(&layout.data_root), "/home/ana/.local/share/orcel");
        assert_eq!(unix(&layout.config_dir), "/home/ana/.config/orcel");
        assert_eq!(
            unix(&layout.user_unit_dir),
            "/home/ana/.config/systemd/user"
        );
        assert_eq!(
            unix(&layout.tarball_orceld()),
            "/home/ana/.local/share/orcel/bin/orceld"
        );
        assert_eq!(
            unix(&layout.env_file()),
            "/home/ana/.config/orcel/orceld.env"
        );
        assert_eq!(layout.runtime_dir, None);
        assert_eq!(layout.socket(), None);
    }

    #[test]
    fn absolute_xdg_variables_win() {
        let layout = layout(&[
            ("HOME", "/home/ana"),
            ("XDG_STATE_HOME", "/srv/ana/state"),
            ("XDG_DATA_HOME", "/srv/ana/data"),
            ("XDG_CONFIG_HOME", "/srv/ana/config"),
            ("XDG_RUNTIME_DIR", "/run/user/1000"),
        ])
        .unwrap();
        assert_eq!(unix(&layout.state_root), "/srv/ana/state/orcel");
        assert_eq!(unix(&layout.data_root), "/srv/ana/data/orcel");
        assert_eq!(unix(&layout.config_dir), "/srv/ana/config/orcel");
        assert_eq!(unix(&layout.user_unit_dir), "/srv/ana/config/systemd/user");
        assert_eq!(
            unix(&layout.socket().unwrap()),
            "/run/user/1000/orcel/orceld.sock"
        );
    }

    #[test]
    fn relative_or_dotted_xdg_variables_are_ignored() {
        for bad in ["relative/dir", "/home/ana/../bob", "/home/./ana", ""] {
            let layout = layout(&[
                ("HOME", "/home/ana"),
                ("XDG_STATE_HOME", bad),
                ("XDG_DATA_HOME", bad),
                ("XDG_CONFIG_HOME", bad),
                ("XDG_RUNTIME_DIR", bad),
            ])
            .unwrap();
            assert_eq!(unix(&layout.state_root), "/home/ana/.local/state/orcel");
            assert_eq!(unix(&layout.data_root), "/home/ana/.local/share/orcel");
            assert_eq!(unix(&layout.config_dir), "/home/ana/.config/orcel");
            assert_eq!(layout.runtime_dir, None, "{bad}");
        }
    }

    #[test]
    fn unusable_home_is_refused_not_replaced() {
        for vars in [
            &[][..],
            &[("HOME", "relative")][..],
            &[("HOME", "/home/../tmp")][..],
            // XDG values alone are not enough: every base needs a home.
            &[
                ("XDG_STATE_HOME", "/s"),
                ("XDG_DATA_HOME", "/d"),
                ("XDG_RUNTIME_DIR", "/run/user/1"),
            ][..],
        ] {
            assert!(layout(vars).is_err(), "{vars:?}");
        }
    }

    #[test]
    fn nothing_resolves_under_tmp() {
        let layout = layout(&[("HOME", "/home/ana")]).unwrap();
        for path in [
            &layout.state_root,
            &layout.data_root,
            &layout.config_dir,
            &layout.user_unit_dir,
        ] {
            assert!(!unix(path).starts_with("/tmp"), "{}", path.display());
        }
    }

    fn directive<'a>(unit: &'a str, name: &str) -> Vec<&'a str> {
        unit.lines()
            .filter_map(|line| line.trim().strip_prefix(name)?.strip_prefix('='))
            .collect()
    }

    /// The shipped units agree with this layout.
    #[test]
    fn units_use_the_packaged_paths_and_per_user_state() {
        assert_eq!(
            directive(SERVICE, "ExecStart"),
            [format!("{PACKAGE_LIB_DIR}/orceld")]
        );
        assert_eq!(
            directive(SERVICE, "EnvironmentFile"),
            [format!("-%E/orcel/{ENV_FILE}")]
        );
        assert_eq!(directive(SOCKET, "ListenStream"), ["%t/orcel/orceld.sock"]);
        assert_eq!(directive(SOCKET, "SocketMode"), ["0600"]);
        assert_eq!(directive(SOCKET, "DirectoryMode"), ["0700"]);
        assert_eq!(directive(SOCKET, "Accept"), ["yes"]);
        for unit in [SOCKET, SERVICE] {
            for forbidden in ["User", "Group", "ListenDatagram", "ListenNetlink"] {
                assert!(directive(unit, forbidden).is_empty(), "{forbidden}");
            }
            assert!(!unit.contains("/tmp"));
        }
    }

    /// The hardening the PR justifies stays in the service unit.
    #[test]
    fn service_unit_keeps_its_hardening() {
        for (name, value) in [
            ("NoNewPrivileges", "yes"),
            ("RestrictSUIDSGID", "yes"),
            ("RestrictAddressFamilies", "AF_UNIX AF_INET AF_INET6"),
            ("RestrictNamespaces", "yes"),
            ("RestrictRealtime", "yes"),
            ("LockPersonality", "yes"),
            ("SystemCallArchitectures", "native"),
            ("UMask", "0077"),
            ("KillMode", "control-group"),
            ("Delegate", "yes"),
        ] {
            assert_eq!(directive(SERVICE, name), [value], "{name}");
        }
    }

    /// The packages install no maintainer scripts, nothing setuid, and the
    /// units in the user (not system) unit directory.
    #[test]
    fn nfpm_config_ships_no_scripts_or_system_units() {
        for forbidden in [
            "scripts:",
            "preinstall",
            "postinstall",
            "preremove",
            "postremove",
            "/lib/systemd/system",
            "/etc/systemd/system",
        ] {
            assert!(!NFPM.contains(forbidden), "{forbidden}");
        }
        let modes: Vec<u32> = NFPM
            .lines()
            .filter_map(|line| line.trim().strip_prefix("mode:"))
            .map(|mode| u32::from_str_radix(mode.trim(), 8).unwrap())
            .collect();
        assert_eq!(
            modes,
            [0o755, 0o755, 0o755, 0o755, 0o644, 0o644, 0o644, 0o644, 0o644, 0o644]
        );
        assert!(modes.iter().all(|mode| mode & 0o7022 == 0));
        let owners: Vec<&str> = NFPM
            .lines()
            .filter_map(|line| line.trim().strip_prefix("owner:"))
            .map(str::trim)
            .collect();
        assert_eq!(owners, ["root"; 10]);
        assert!(NFPM.contains(&format!("dst: {PACKAGE_LIB_DIR}/orceld")));
        // XP-13b: the contained-tier helper and its pin sit beside orceld.
        for helper in ["orcel-contain", "orcel-contain.sha256"] {
            let dst = format!("dst: {PACKAGE_LIB_DIR}/{helper}");
            assert!(NFPM.lines().any(|line| line.trim() == dst), "{dst}");
        }
        assert!(NFPM.contains(&format!("dst: {PACKAGE_USER_UNIT_DIR}/{SOCKET_UNIT}")));
        assert!(NFPM.contains(&format!("dst: {PACKAGE_USER_UNIT_DIR}/{SERVICE_UNIT}")));
    }
}
