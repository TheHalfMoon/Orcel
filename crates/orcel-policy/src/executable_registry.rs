//! SG-000060 protected executable registry.
//!
//! Replaces the single-executable process ceiling with a local registry of
//! executables the human registered with STRONG presence. Identity is never
//! path-only: every entry pins the canonical path, SHA-256, and size, and the
//! identity is re-verified immediately before every launch. Each entry
//! carries an argv grammar (allowed first arguments, denied arguments, and a
//! bound). Shells, script hosts, interpreters, and script or shortcut files
//! are denied whether or not they are registered. Registered executables
//! still run only through the existing argv-only, AppContainer-contained,
//! network-less, bounded, per-run-approved process path.

use orcel_contracts::FailureCode;
use orcel_platform::{files, paths, PlatformError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::PolicyError;

pub const REGISTRY_SCHEMA: &str = "orcel-executable-registry/1";
pub const MAX_ENTRIES: usize = 64;
pub const MAX_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_SUBCOMMANDS: usize = 32;
pub const MAX_DENIED_ARGS: usize = 64;
pub const MAX_ARGS_CEILING: usize = 64;

/// File stems that are general-purpose shells, script hosts, interpreters,
/// or system administration tools. They are denied even if registered.
pub const DENIED_EXECUTABLE_STEMS: &[&str] = &[
    "cmd",
    "command",
    "powershell",
    "pwsh",
    "powershell_ise",
    "bash",
    "sh",
    "zsh",
    "fish",
    "dash",
    "wsl",
    "wslhost",
    "wslg",
    "python",
    "python3",
    "pythonw",
    "py",
    "pyw",
    "node",
    "nodejs",
    "deno",
    "bun",
    "ruby",
    "irb",
    "perl",
    "php",
    "lua",
    "tclsh",
    "wish",
    "java",
    "javaw",
    "jshell",
    "dotnet-script",
    "csi",
    "fsi",
    "wscript",
    "cscript",
    "mshta",
    "rundll32",
    "regsvr32",
    "msiexec",
    "installutil",
    "regasm",
    "regsvcs",
    "cmstp",
    "certutil",
    "bitsadmin",
    "schtasks",
    "at",
    "sc",
    "reg",
    "regedit",
    "netsh",
    "conhost",
    "explorer",
    "runas",
    "curl",
    "wget",
    "ftp",
    "tftp",
    "ssh",
    "scp",
    "sftp",
    "telnet",
    "nc",
    "ncat",
    "socat",
    "psexec",
    "wmic",
    "forfiles",
    "pcalua",
    "msbuild",
    "hh",
    "control",
    "mmc",
    "taskkill",
    "tskill",
    "shutdown",
    "format",
    "diskpart",
    "bcdedit",
    "vssadmin",
    "wevtutil",
    "icacls",
    "takeown",
    "cacls",
    "attrib",
    "robocopy",
    "xcopy",
    "where",
];

/// XP-13b: Unix shells, command runners, privilege tools and interpreters,
/// denied on Linux and macOS in addition to the list above. A command runner
/// (`env`, `xargs`, `nohup`, ...) would let a registered argv start anything.
pub const DENIED_UNIX_EXECUTABLE_STEMS: &[&str] = &[
    "ksh",
    "mksh",
    "csh",
    "tcsh",
    "ash",
    "busybox",
    "toybox",
    "env",
    "xargs",
    "nohup",
    "setsid",
    "nice",
    "timeout",
    "stdbuf",
    "chroot",
    "flock",
    "script",
    "expect",
    "watch",
    "time",
    "sudo",
    "su",
    "doas",
    "pkexec",
    "runuser",
    "systemd-run",
    "systemctl",
    "launchctl",
    "osascript",
    "open",
    "awk",
    "gawk",
    "mawk",
    "nawk",
    "sed",
    "find",
    "vi",
    "vim",
    "nvim",
    "ex",
    "ed",
    "emacs",
    "nano",
    "less",
    "more",
    "man",
    "gdb",
    "lldb",
    "strace",
    "ltrace",
    "dtrace",
    "tmux",
    "screen",
    "make",
    "rlwrap",
    "parallel",
    "ssh-agent",
];

/// Only native `.exe` images are admissible on Windows.
pub const ALLOWED_EXTENSION: &str = "exe";

/// XP-13b: on Linux and macOS there is no extension rule, so these script
/// and archive extensions are denied by name, and the file itself must start
/// with the native image magic (ELF, or Mach-O) when it is registered; a
/// `#!` script never qualifies.
pub const DENIED_UNIX_EXTENSIONS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "ksh",
    "csh",
    "fish",
    "py",
    "pyc",
    "pyw",
    "pl",
    "pm",
    "rb",
    "js",
    "mjs",
    "cjs",
    "ts",
    "php",
    "lua",
    "tcl",
    "r",
    "jar",
    "command",
    "tool",
    "scpt",
    "applescript",
    "workflow",
    "app",
    "pkg",
    "dmg",
    "deb",
    "rpm",
    "appimage",
    "desktop",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegisteredExecutable {
    pub id: String,
    pub path: String,
    pub sha256: String,
    pub size: u64,
    /// Allowed values for argv[0]; an empty list means argv must be empty.
    pub subcommands: Vec<String>,
    /// Arguments that are always denied (exact match, or `name=` prefix).
    pub denied_args: Vec<String>,
    pub max_args: usize,
    pub registered_at_ms: u64,
    /// XP-13b: the execution tier, chosen at registration under the same
    /// STRONG approval. Absent in older registries, which stay `Safe`; it is
    /// stored only when `Contained`, so existing checksums are unchanged.
    #[serde(default, skip_serializing_if = "ExecutionTier::is_safe")]
    pub tier: ExecutionTier,
}

/// XP-13b: how a registered executable runs.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ExecutionTier {
    /// The Safe tier: argv only, bounded output, owned process tree
    /// (Windows Job Object and AppContainer; Linux and macOS process group).
    #[default]
    Safe,
    /// Opt-in: the pinned `orcel-contain` helper. No network, no process
    /// creation, the requested cwd read-only and nothing else of the user's
    /// writable. A contained entry never falls back to the Safe tier.
    Contained,
}

impl ExecutionTier {
    pub fn is_safe(&self) -> bool {
        *self == Self::Safe
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Safe => "safe",
            Self::Contained => "contained",
        }
    }

    /// `None`, `"safe"` or `"contained"`; anything else is refused.
    pub fn parse(value: Option<&str>) -> Result<Self, PolicyError> {
        match value {
            None | Some("safe") => Ok(Self::Safe),
            Some("contained") => Ok(Self::Contained),
            Some(_) => Err(invalid("tier must be \"safe\" or \"contained\"")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct StoredRegistry {
    schema: String,
    entries: Vec<RegisteredExecutable>,
    checksum: String,
}

fn denied(message: impl Into<String>) -> PolicyError {
    PolicyError {
        code: FailureCode::CapabilityDenied,
        message: message.into(),
    }
}

fn invalid(message: impl Into<String>) -> PolicyError {
    PolicyError {
        code: FailureCode::InvalidRequest,
        message: message.into(),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn checksum(entries: &[RegisteredExecutable]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(REGISTRY_SCHEMA.as_bytes());
    hasher.update(serde_json::to_vec(entries).unwrap_or_default());
    hex_lower(&hasher.finalize())
}

/// Protected registry location: `ORCEL_EXECUTABLE_REGISTRY_PATH`, else
/// `executable_registry.json` in the private per-user Orcel state root (XP-01B).
/// Fails closed when the override is empty, relative or not in a private
/// directory, or when the root cannot be resolved or is not private; it never
/// falls back to the shared temp directory. The override must stay listed in
/// `protected_state::PROTECTED_STATE_OVERRIDES`.
pub fn default_registry_path() -> Result<PathBuf, PlatformError> {
    default_registry_path_from(&|name| std::env::var_os(name))
}

/// [`default_registry_path`] with the environment read through `lookup`.
pub fn default_registry_path_from(
    lookup: &dyn Fn(&str) -> Option<OsString>,
) -> Result<PathBuf, PlatformError> {
    if let Some(path) = lookup("ORCEL_EXECUTABLE_REGISTRY_PATH") {
        return paths::private_file_override(path);
    }
    let root = paths::state_root_from(lookup)?;
    paths::ensure_private_dir(&root)?;
    Ok(root.join("executable_registry.json"))
}

/// Load the registry. A missing, corrupt, tampered, or oversized registry
/// yields no entries, so only the built-in baseline remains.
pub fn load_registry(path: &Path) -> Vec<RegisteredExecutable> {
    let Ok(bytes) = std::fs::read(path) else {
        return Vec::new();
    };
    let Ok(stored) = serde_json::from_slice::<StoredRegistry>(&bytes) else {
        return Vec::new();
    };
    if stored.schema != REGISTRY_SCHEMA
        || stored.checksum != checksum(&stored.entries)
        || stored.entries.len() > MAX_ENTRIES
    {
        return Vec::new();
    }
    stored.entries
}

pub fn save_registry(path: &Path, entries: &[RegisteredExecutable]) -> Result<(), PolicyError> {
    if entries.len() > MAX_ENTRIES {
        return Err(invalid("too many registered executables"));
    }
    let stored = StoredRegistry {
        schema: REGISTRY_SCHEMA.into(),
        entries: entries.to_vec(),
        checksum: checksum(entries),
    };
    let bytes = serde_json::to_vec_pretty(&stored)
        .map_err(|error| invalid(format!("serialize registry: {error}")))?;
    let internal = |message: String| PolicyError {
        code: FailureCode::InternalError,
        message,
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| internal(format!("create registry directory: {error}")))?;
    }
    files::write_private_atomic(path, &bytes)
        .map_err(|error| internal(format!("write registry: {error}")))
}

/// Deny shells, interpreters, script hosts, non-`.exe` images, UNC and
/// device paths, and relative paths.
pub fn check_admissible_path(path: &Path) -> Result<(), PolicyError> {
    let text = path.to_string_lossy().replace('/', "\\");
    let trimmed = text.strip_prefix("\\\\?\\").unwrap_or(&text);
    if trimmed.starts_with("\\\\") || trimmed.starts_with("UNC\\") {
        return Err(denied(
            "registered executables cannot use UNC or device paths",
        ));
    }
    if !path.is_absolute() {
        return Err(invalid("registered executables need an absolute path"));
    }
    let extension = path
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    #[cfg(windows)]
    if extension != ALLOWED_EXTENSION {
        return Err(denied(
            "only native .exe images can be registered; scripts, batch files, shortcuts, and installers are denied",
        ));
    }
    #[cfg(not(windows))]
    if DENIED_UNIX_EXTENSIONS.contains(&extension.as_str()) {
        return Err(denied(
            "only native executable images can be registered; scripts, archives, bundles, and installers are denied",
        ));
    }
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let base =
        stem.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.' || c == '-' || c == '_');
    let denied_stem = |name: &str| {
        DENIED_EXECUTABLE_STEMS.contains(&name)
            || (cfg!(not(windows)) && DENIED_UNIX_EXECUTABLE_STEMS.contains(&name))
    };
    if denied_stem(&stem) || denied_stem(base) {
        return Err(denied(
            "shells, interpreters, script hosts, and system administration tools are never registrable",
        ));
    }
    Ok(())
}

/// XP-13b: on Linux and macOS, a registrable file starts with the native
/// image magic: ELF on Linux; thin or universal Mach-O on macOS. Scripts
/// (`#!`) and anything else are refused. The registered digest then pins the
/// bytes, so this is checked once, at registration. Windows keeps its
/// extension rule.
pub fn check_native_image(path: &Path) -> Result<(), PolicyError> {
    if cfg!(windows) {
        return Ok(());
    }
    let mut magic = [0_u8; 4];
    std::fs::File::open(path)
        .and_then(|mut file| file.read_exact(&mut magic))
        .map_err(|error| invalid(format!("executable cannot be read: {error}")))?;
    let native: &[[u8; 4]] = if cfg!(target_os = "macos") {
        &[
            [0xfe, 0xed, 0xfa, 0xcf],
            [0xcf, 0xfa, 0xed, 0xfe],
            [0xfe, 0xed, 0xfa, 0xce],
            [0xce, 0xfa, 0xed, 0xfe],
            [0xca, 0xfe, 0xba, 0xbe],
        ]
    } else {
        &[[0x7f, b'E', b'L', b'F']]
    };
    if !native.contains(&magic) {
        return Err(denied(
            "only native executable images can be registered; this file is a script or not an executable",
        ));
    }
    Ok(())
}

/// Hash a file with a size bound.
pub fn file_identity(path: &Path) -> Result<(String, u64), PolicyError> {
    let metadata = std::fs::metadata(path)
        .map_err(|error| invalid(format!("executable cannot be inspected: {error}")))?;
    if !metadata.is_file() {
        return Err(invalid("executable must be a regular file"));
    }
    if metadata.len() > MAX_EXECUTABLE_BYTES {
        return Err(invalid("executable exceeds the registry size bound"));
    }
    let mut file = std::fs::File::open(path)
        .map_err(|error| invalid(format!("executable cannot be read: {error}")))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| invalid(format!("executable cannot be read: {error}")))?;
        if read == 0 {
            break;
        }
        total += read as u64;
        hasher.update(&buffer[..read]);
    }
    Ok((hex_lower(&hasher.finalize()), total))
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || b == b'-'
                || b == b'_'
                || b == b'.'
                || b == b'='
                || b == b'/'
        })
}

/// Build a registry entry for a STRONG-approved registration request.
/// Executables inside any configured workspace are refused because the agent
/// can write there.
pub fn build_entry(
    id: &str,
    path: &Path,
    subcommands: Vec<String>,
    denied_args: Vec<String>,
    max_args: usize,
    workspace_roots: &[PathBuf],
    now_ms: u64,
) -> Result<RegisteredExecutable, PolicyError> {
    if id.is_empty()
        || id.len() > 32
        || !id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(invalid(
            "executable id must be 1-32 lowercase letters, digits, or dashes",
        ));
    }
    check_admissible_path(path)?;
    let canonical = std::fs::canonicalize(path)
        .map_err(|error| invalid(format!("executable cannot be resolved: {error}")))?;
    check_admissible_path(&canonical)?;
    for root in workspace_roots {
        let root = std::fs::canonicalize(root).unwrap_or_else(|_| root.clone());
        if canonical.starts_with(&root) {
            return Err(denied(
                "executables inside a workspace are agent-writable and cannot be registered",
            ));
        }
    }
    if subcommands.len() > MAX_SUBCOMMANDS || !subcommands.iter().all(|s| valid_token(s)) {
        return Err(invalid("subcommands must be at most 32 simple tokens"));
    }
    if denied_args.len() > MAX_DENIED_ARGS || !denied_args.iter().all(|s| valid_token(s)) {
        return Err(invalid("denied arguments must be at most 64 simple tokens"));
    }
    if max_args > MAX_ARGS_CEILING {
        return Err(invalid("max_args must be at most 64"));
    }
    check_native_image(&canonical)?;
    let (sha256, size) = file_identity(&canonical)?;
    Ok(RegisteredExecutable {
        id: id.to_owned(),
        path: canonical.to_string_lossy().into_owned(),
        sha256,
        size,
        subcommands,
        denied_args,
        max_args,
        registered_at_ms: now_ms,
        tier: ExecutionTier::Safe,
    })
}

/// Find the registered entry for an executable path and check the argv
/// grammar. Content identity is verified separately right before launch.
pub fn check_spawn<'a>(
    entries: &'a [RegisteredExecutable],
    executable: &Path,
    argv: &[String],
) -> Result<&'a RegisteredExecutable, PolicyError> {
    check_admissible_path(executable)?;
    let canonical = std::fs::canonicalize(executable).map_err(|error| {
        invalid(format!(
            "process.spawn executable could not be resolved: {error}"
        ))
    })?;
    check_admissible_path(&canonical)?;
    let canonical = canonical.to_string_lossy().into_owned();
    let entry = entries
        .iter()
        .find(|entry| entry.path.eq_ignore_ascii_case(&canonical))
        .ok_or_else(|| {
            denied("process.spawn executable is not in the protected executable registry")
        })?;
    if argv.len() > entry.max_args {
        return Err(denied("argv exceeds this executable's registered bound"));
    }
    match argv.first() {
        None if entry.subcommands.is_empty() => {}
        None => return Err(denied("this executable requires a registered subcommand")),
        Some(_) if entry.subcommands.is_empty() => {
            return Err(denied("this executable is registered without arguments"))
        }
        Some(first) => {
            if !entry.subcommands.iter().any(|allowed| allowed == first) {
                return Err(denied("argv[0] is not a registered subcommand"));
            }
        }
    }
    for argument in argv {
        for blocked in &entry.denied_args {
            let prefixed = format!("{blocked}=");
            if argument == blocked || argument.starts_with(&prefixed) {
                return Err(denied(
                    "argv contains a denied argument for this executable",
                ));
            }
        }
    }
    Ok(entry)
}

/// Re-verify an entry's path, size, and content hash immediately before
/// launch. Any drift fails closed.
pub fn verify_identity(
    entry: &RegisteredExecutable,
    launch_path: &Path,
) -> Result<(), PolicyError> {
    let canonical = std::fs::canonicalize(launch_path).map_err(|error| {
        denied(format!(
            "registered executable is no longer resolvable: {error}"
        ))
    })?;
    if !canonical
        .to_string_lossy()
        .eq_ignore_ascii_case(&entry.path)
    {
        return Err(denied("registered executable path changed"));
    }
    let (sha256, size) = file_identity(&canonical)?;
    if size != entry.size || sha256 != entry.sha256 {
        return Err(PolicyError {
            code: FailureCode::TargetStale,
            message:
                "registered executable content changed since registration; re-register it locally"
                    .into(),
        });
    }
    Ok(())
}

/// Insert or replace an entry by id and by path.
pub fn upsert(
    entries: &[RegisteredExecutable],
    entry: RegisteredExecutable,
) -> Result<Vec<RegisteredExecutable>, PolicyError> {
    let mut next: Vec<RegisteredExecutable> = entries
        .iter()
        .filter(|existing| {
            existing.id != entry.id && !existing.path.eq_ignore_ascii_case(&entry.path)
        })
        .cloned()
        .collect();
    if next.len() >= MAX_ENTRIES {
        return Err(invalid("too many registered executables"));
    }
    next.push(entry);
    Ok(next)
}

/// Digest bound into the STRONG approval for a registration.
pub fn registration_digest(entry: &RegisteredExecutable, policy_revision: &str) -> String {
    let mut hasher = Sha256::new();
    for field in [
        "ORCEL_EXECUTABLE_REGISTRATION_V1",
        policy_revision,
        &entry.id,
        &entry.path,
        &entry.sha256,
        &entry.size.to_string(),
        &entry.subcommands.join("\n"),
        &entry.denied_args.join("\n"),
        &entry.max_args.to_string(),
    ] {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field.as_bytes());
    }
    // XP-13b: a contained registration binds its tier; a Safe one hashes as
    // before.
    if !entry.tier.is_safe() {
        for field in ["tier", entry.tier.as_str()] {
            hasher.update((field.len() as u64).to_be_bytes());
            hasher.update(field.as_bytes());
        }
    }
    hex_lower(&hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(label: &str) -> PathBuf {
        crate::test_support::unique_temp_dir(&format!("orcel-registry-{label}"))
    }

    /// The native image magic `check_native_image` wants on this OS.
    fn native_magic() -> &'static [u8] {
        if cfg!(windows) {
            b""
        } else if cfg!(target_os = "macos") {
            &[0xcf, 0xfa, 0xed, 0xfe]
        } else {
            b"\x7fELF"
        }
    }

    fn fake_exe(dir: &Path, name: &str, body: &[u8]) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, [native_magic(), body].concat()).unwrap();
        path
    }

    #[test]
    fn shells_interpreters_scripts_and_unc_paths_are_never_registrable() {
        let dir = temp("deny");
        for name in [
            "cmd.exe",
            "powershell.exe",
            "pwsh.exe",
            "bash.exe",
            "python.exe",
            "python3.12.exe",
            "node.exe",
            "wscript.exe",
            "mshta.exe",
            "rundll32.exe",
            "curl.exe",
            "PowerShell.EXE",
        ] {
            let path = fake_exe(&dir, name, b"MZ");
            assert!(
                build_entry("x", &path, vec![], vec![], 0, &[], 1).is_err(),
                "{name}"
            );
        }
        #[cfg(windows)]
        let refused_names = [
            "build.cmd",
            "build.bat",
            "run.ps1",
            "a.vbs",
            "a.js",
            "a.lnk",
            "a.com",
            "a.msi",
            "noext",
        ];
        #[cfg(not(windows))]
        let refused_names = [
            "build.sh",
            "run.py",
            "a.pl",
            "a.rb",
            "a.js",
            "a.command",
            "x.jar",
            "bash",
            "sh",
            "env",
            "sudo",
            "busybox",
            "xargs",
            "awk",
            "osascript",
            "python3.12",
        ];
        for name in refused_names {
            let path = fake_exe(&dir, name, b"MZ");
            assert!(
                build_entry("x", &path, vec![], vec![], 0, &[], 1).is_err(),
                "{name}"
            );
        }
        assert!(check_admissible_path(Path::new(r"\\server\share\tool.exe")).is_err());
        assert!(check_admissible_path(Path::new("relative\\tool.exe")).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// XP-13b: on Linux and macOS a registrable file must be a native image,
    /// whatever its name; a `#!` script with an innocent name is refused.
    #[cfg(not(windows))]
    #[test]
    fn xp13b_only_native_images_are_registrable_off_windows() {
        let dir = temp("native");
        let script = dir.join("tool");
        std::fs::write(&script, b"#!/bin/sh\nexit 0\n").unwrap();
        assert!(build_entry("tool", &script, vec![], vec![], 0, &[], 1).is_err());
        let empty = dir.join("empty");
        std::fs::write(&empty, b"").unwrap();
        assert!(build_entry("empty", &empty, vec![], vec![], 0, &[], 1).is_err());
        let native = fake_exe(&dir, "tool-native", b" body");
        assert!(build_entry("tool", &native, vec![], vec![], 0, &[], 1).is_ok());
        // The real test binary is a native image.
        let current = std::env::current_exe().unwrap();
        assert!(check_native_image(&current).is_ok());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// XP-13b: the tier is stored only when contained, so a Safe registry
    /// keeps its bytes and checksum; the contained tier changes the
    /// registration digest the STRONG approval binds.
    #[test]
    fn xp13b_the_tier_round_trips_and_binds_the_registration_digest() {
        let dir = temp("tier");
        let registry = dir.join("executable_registry.json");
        let path = fake_exe(&dir, "tool.exe", b"MZ tool");
        let safe = build_entry("tool", &path, vec![], vec![], 0, &[], 1).unwrap();
        assert_eq!(safe.tier, ExecutionTier::Safe);
        assert!(!serde_json::to_string(&safe).unwrap().contains("\"tier\":"));
        let contained = RegisteredExecutable {
            tier: ExecutionTier::Contained,
            ..safe.clone()
        };
        assert!(serde_json::to_string(&contained)
            .unwrap()
            .contains("\"tier\":\"contained\""));
        assert_ne!(
            registration_digest(&safe, "p"),
            registration_digest(&contained, "p")
        );
        save_registry(&registry, std::slice::from_ref(&contained)).unwrap();
        assert_eq!(load_registry(&registry), vec![contained]);
        assert_eq!(ExecutionTier::parse(None).unwrap(), ExecutionTier::Safe);
        assert_eq!(
            ExecutionTier::parse(Some("contained")).unwrap(),
            ExecutionTier::Contained
        );
        assert!(ExecutionTier::parse(Some("sandboxed")).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn workspace_executables_are_refused_and_ids_are_strict() {
        let dir = temp("workspace");
        let path = fake_exe(&dir, "tool.exe", b"MZ tool");
        assert!(build_entry(
            "tool",
            &path,
            vec![],
            vec![],
            0,
            std::slice::from_ref(&dir),
            1
        )
        .is_err());
        assert!(build_entry("Tool!", &path, vec![], vec![], 0, &[], 1).is_err());
        assert!(build_entry("tool", &path, vec!["a b".into()], vec![], 0, &[], 1).is_err());
        assert!(build_entry("tool", &path, vec![], vec![], 65, &[], 1).is_err());
        let ok = build_entry(
            "tool",
            &path,
            vec!["test".into()],
            vec!["--config".into()],
            8,
            &[],
            1,
        )
        .unwrap();
        assert_eq!(ok.size, 7 + native_magic().len() as u64);
        assert_eq!(ok.sha256.len(), 64);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn argv_grammar_is_enforced() {
        let dir = temp("grammar");
        let path = fake_exe(&dir, "cargo-like.exe", b"MZ cargo");
        let entry = build_entry(
            "cargo",
            &path,
            vec!["test".into(), "build".into()],
            vec!["--config".into(), "-Z".into()],
            6,
            &[],
            1,
        )
        .unwrap();
        let entries = vec![entry];
        let args = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(check_spawn(&entries, &path, &args(&["test", "--release"])).is_ok());
        assert!(check_spawn(&entries, &path, &args(&["install"])).is_err());
        assert!(check_spawn(&entries, &path, &args(&[])).is_err());
        assert!(check_spawn(&entries, &path, &args(&["test", "--config", "x"])).is_err());
        assert!(check_spawn(
            &entries,
            &path,
            &args(&["test", "--config=build.rustflags"])
        )
        .is_err());
        assert!(check_spawn(&entries, &path, &args(&["test", "-Z"])).is_err());
        assert!(check_spawn(
            &entries,
            &path,
            &args(&["test", "1", "2", "3", "4", "5", "6"])
        )
        .is_err());
        let other = fake_exe(&dir, "other.exe", b"MZ other");
        assert!(
            check_spawn(&entries, &other, &args(&["test"])).is_err(),
            "unregistered executables are denied"
        );
        let bare = build_entry("bare", &other, vec![], vec![], 0, &[], 1).unwrap();
        assert!(check_spawn(std::slice::from_ref(&bare), &other, &args(&[])).is_ok());
        assert!(check_spawn(&[bare], &other, &args(&["anything"])).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn modified_or_moved_executables_fail_closed_before_launch() {
        let dir = temp("identity");
        let path = fake_exe(&dir, "tool.exe", b"MZ original");
        let entry = build_entry("tool", &path, vec![], vec![], 0, &[], 1).unwrap();
        assert!(verify_identity(&entry, &path).is_ok());
        std::fs::write(&path, b"MZ modified").unwrap();
        let error = verify_identity(&entry, &path).unwrap_err();
        assert_eq!(error.code, FailureCode::TargetStale);
        std::fs::remove_file(&path).unwrap();
        assert!(verify_identity(&entry, &path).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn registry_store_is_checksummed_and_fails_closed_when_tampered() {
        let dir = temp("store");
        let registry = dir.join("executable_registry.json");
        assert!(load_registry(&registry).is_empty());
        let path = fake_exe(&dir, "tool.exe", b"MZ tool");
        let entry = build_entry("tool", &path, vec!["run".into()], vec![], 4, &[], 1).unwrap();
        let entries = upsert(&[], entry.clone()).unwrap();
        save_registry(&registry, &entries).unwrap();
        assert_eq!(load_registry(&registry), entries);
        let text = std::fs::read_to_string(&registry).unwrap();
        std::fs::write(&registry, text.replace("\"run\"", "\"install\"")).unwrap();
        assert!(load_registry(&registry).is_empty());
        let replaced = upsert(
            &entries,
            RegisteredExecutable {
                subcommands: vec!["test".into()],
                ..entry.clone()
            },
        )
        .unwrap();
        assert_eq!(replaced.len(), 1);
        assert_ne!(
            registration_digest(&replaced[0], "p"),
            registration_digest(&entry, "p")
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
