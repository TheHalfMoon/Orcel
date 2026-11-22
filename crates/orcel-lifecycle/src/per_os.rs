//! Per-OS executable names and presence wording for the `orcel` CLI
//! (MAC-M1-02).
//!
//! Every value is a function of [`Os`], so each OS's value is tested on
//! every host; [`Os::CURRENT`] picks this build's. The Windows values are
//! the exact strings the CLI used before this module existed (`orceld.exe`,
//! "Windows Hello"), pinned by tests.
//!
//! This module only names things. It grants nothing and makes no command
//! reachable on another OS: a command that needs the verified per-user
//! install still fails closed off Windows, where `host_platform()` is
//! unsupported.

/// The OS family whose names and wording the CLI uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Windows,
    MacOs,
    Linux,
    /// Any other OS; Orcel ships nothing there.
    Other,
}

impl Os {
    /// The OS this binary was built for.
    pub const CURRENT: Os = if cfg!(windows) {
        Os::Windows
    } else if cfg!(target_os = "macos") {
        Os::MacOs
    } else if cfg!(target_os = "linux") {
        Os::Linux
    } else {
        Os::Other
    };

    /// The suffix of an executable file name: `.exe` on Windows, none on
    /// macOS and Linux.
    pub fn executable_suffix(self) -> &'static str {
        match self {
            Os::Windows => ".exe",
            Os::MacOs | Os::Linux | Os::Other => "",
        }
    }

    /// The file name of the executable `stem` on this OS.
    pub fn executable_name(self, stem: &str) -> String {
        format!("{stem}{}", self.executable_suffix())
    }

    /// What the person uses to prove presence for a STRONG approval, as
    /// shown in "Confirm with ... when prompted".
    pub fn presence_method(self) -> &'static str {
        match self {
            Os::Windows => "Windows Hello",
            Os::MacOs => "Touch ID or your password (LocalAuthentication)",
            Os::Linux => "your password (polkit)",
            Os::Other => "your operating system's authentication",
        }
    }

    /// The line printed before a request that needs STRONG presence:
    /// "Confirm with <presence method> when prompted. <then>".
    pub fn confirm_when_prompted(self, then: &str) -> String {
        format!(
            "Confirm with {} when prompted. {then}",
            self.presence_method()
        )
    }
}

/// `orceld`'s file name on this OS (`orceld.exe` on Windows).
pub fn orceld_file_name() -> String {
    Os::CURRENT.executable_name("orceld")
}

/// [`Os::confirm_when_prompted`] for this OS.
pub fn confirm_when_prompted(then: &str) -> String {
    Os::CURRENT.confirm_when_prompted(then)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_names_and_wording_are_the_exact_earlier_strings() {
        assert_eq!(Os::Windows.executable_name("orceld"), "orceld.exe");
        assert_eq!(Os::Windows.presence_method(), "Windows Hello");
        assert_eq!(
            Os::Windows.confirm_when_prompted("Every pending approval will be invalidated."),
            "Confirm with Windows Hello when prompted. Every pending approval will be invalidated."
        );
    }

    #[test]
    fn macos_names_orceld_without_a_suffix_and_says_touch_id_or_password() {
        assert_eq!(Os::MacOs.executable_name("orceld"), "orceld");
        assert_eq!(
            Os::MacOs.confirm_when_prompted("Every pending approval will be invalidated."),
            "Confirm with Touch ID or your password (LocalAuthentication) when prompted. Every pending approval will be invalidated."
        );
        assert!(!Os::MacOs.presence_method().contains("Windows"));
    }

    #[test]
    fn linux_names_orceld_without_a_suffix_and_says_polkit() {
        assert_eq!(Os::Linux.executable_name("orceld"), "orceld");
        assert_eq!(Os::Linux.presence_method(), "your password (polkit)");
        assert!(!Os::Linux.presence_method().contains("Windows"));
    }

    #[test]
    fn the_current_os_matches_the_build_target() {
        if cfg!(any(windows, target_os = "macos", target_os = "linux")) {
            assert_eq!(
                Os::CURRENT.executable_suffix(),
                std::env::consts::EXE_SUFFIX
            );
            assert_eq!(
                orceld_file_name(),
                format!("orceld{}", std::env::consts::EXE_SUFFIX)
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn this_windows_build_keeps_orceld_exe_and_windows_hello() {
        assert_eq!(Os::CURRENT, Os::Windows);
        assert_eq!(orceld_file_name(), "orceld.exe");
        assert_eq!(
            confirm_when_prompted("x"),
            "Confirm with Windows Hello when prompted. x"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn this_macos_build_names_orceld_and_local_authentication() {
        assert_eq!(Os::CURRENT, Os::MacOs);
        assert_eq!(orceld_file_name(), "orceld");
        assert_eq!(
            confirm_when_prompted("x"),
            "Confirm with Touch ID or your password (LocalAuthentication) when prompted. x"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn this_linux_build_names_orceld_and_polkit() {
        assert_eq!(Os::CURRENT, Os::Linux);
        assert_eq!(orceld_file_name(), "orceld");
        assert_eq!(
            confirm_when_prompted("x"),
            "Confirm with your password (polkit) when prompted. x"
        );
    }

    /// The launched `orceld` must be a file the install manifest requires,
    /// so a launch never reaches an unverified binary. Windows only until
    /// MAC-M1-03 gives macOS its own payload names.
    #[cfg(windows)]
    #[test]
    fn the_launched_orceld_is_a_required_payload_file() {
        assert!(crate::manifest::REQUIRED_FILES.contains(&orceld_file_name().as_str()));
    }
}
