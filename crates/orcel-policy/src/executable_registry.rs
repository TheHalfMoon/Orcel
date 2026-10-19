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
use orcel_platform::{paths, PlatformError};
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

/// Only native `.exe` images are admissible.
pub const ALLOWED_EXTENSION: &str = "exe";

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
/// `executable_registry.json` in the private per-user Orcel state root
/// (XP-01B). Fails closed when the override is empty or relative, or when
/// the root cannot be resolved or is not private; it never falls back to the
/// shared temp directory. The override must stay listed in
/// `protected_state::PROTECTED_STATE_OVERRIDES`.
pub fn default_registry_path() -> Result<PathBuf, PlatformError> {
    default_registry_path_from(&|name| std::env::var_os(name))
}

/// [`default_registry_path`] with the environment read through `lookup`.
pub fn default_registry_path_from(
    lookup: &dyn Fn(&str) -> Option<OsString>,
) -> Result<PathBuf, PlatformError> {
    if let Some(path) = lookup("ORCEL_EXECUTABLE_REGISTRY_PATH") {
        return paths::absolute_override(path);
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
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let temp = path.with_extension(format!("tmp-{}-{nanos}", std::process::id()));
    let result = std::fs::write(&temp, &bytes)
        .and_then(|()| std::fs::rename(&temp, path))
        .map_err(|error| internal(format!("write registry: {error}")));
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
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
    if extension != ALLOWED_EXTENSION {
        return Err(denied(
            "only native .exe images can be registered; scripts, batch files, shortcuts, and installers are denied",
        ));
    }
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let base =
        stem.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.' || c == '-' || c == '_');
    if DENIED_EXECUTABLE_STEMS.contains(&stem.as_str()) || DENIED_EXECUTABLE_STEMS.contains(&base) {
        return Err(denied(
            "shells, interpreters, script hosts, and system administration tools are never registrable",
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
    hex_lower(&hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "orcel-registry-{label}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn fake_exe(dir: &Path, name: &str, body: &[u8]) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, body).unwrap();
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
        for name in [
            "build.cmd",
            "build.bat",
            "run.ps1",
            "a.vbs",
            "a.js",
            "a.lnk",
            "a.com",
            "a.msi",
            "noext",
        ] {
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
        assert_eq!(ok.size, 7);
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
