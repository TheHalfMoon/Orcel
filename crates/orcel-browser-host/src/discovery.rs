//! SG-000074 engine discovery and verification.
//!
//! Orcel never bundles a browser and never downloads one. Discovery finds
//! an installed Chromium-family engine, verifies its kind, version, and
//! (on Windows) Authenticode signature, and refuses everything else with
//! typed unavailable. There is no personal-browser fallback.

use crate::error::{HostError, UnavailableReason};
#[cfg(not(windows))]
use std::ffi::OsString;
use std::path::{Path, PathBuf};
#[cfg(not(windows))]
use std::time::{Duration, Instant};

/// Supported engine kinds. Anything else is unsupported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineKind {
    Edge,
    Chromium,
}

impl EngineKind {
    fn executable_names(&self) -> &'static [&'static str] {
        match self {
            Self::Edge => &["msedge.exe", "msedge"],
            Self::Chromium => &["chrome.exe", "chrome", "chromium", "chromium-browser"],
        }
    }
}

/// SG-000108 A10: the engine major versions the live worker
/// (playwright-core 1.63.0) is qualified on. Qualified means that the full
/// native suite (`npm run browser-launcher:native`) passed on that engine:
/// every confinement, policy and network-endpoint probe re-runs per
/// version, because a new engine can change how it honours a flag.
/// - Edge 155: the evidence host, with the #324 leak control required.
/// - Edge 156: the evidence host after its update to 156.0.4314.42: a full
///   native-suite pass with the #324 leak control required (runs recorded
///   in the engine-attachment decision, A10).
/// - Chrome 154: qualified by earlier CI evidence.
/// - Chrome 155: qualified by earlier CI evidence.
/// - Chrome 156: windows-latest image 20261021 (Chromium 156.0.8078.48):
///   four full native-suite passes with the endpoint probes on #431's head
///   (runs recorded in the engine-attachment decision, A10).
///
/// A new major is added only by a PR whose own native-suite run passes on
/// it. Any other kind or major is refused at launch with a typed error.
pub const QUALIFIED_WORKER_ENGINES: &[(EngineKind, u32)] = &[
    (EngineKind::Edge, 155),
    (EngineKind::Edge, 156),
    (EngineKind::Chromium, 154),
    (EngineKind::Chromium, 155),
    (EngineKind::Chromium, 156),
];

/// A verified engine executable.
#[derive(Debug, Clone)]
pub struct Engine {
    path: PathBuf,
    kind: EngineKind,
    version: String,
    publisher_verified: bool,
    /// A unit-test stand-in, which `reverify` does not re-read.
    #[cfg(test)]
    stand_in: bool,
}

impl Engine {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn kind(&self) -> EngineKind {
        self.kind
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    /// The major version, if the version starts with one.
    pub fn major(&self) -> Option<u32> {
        self.version.split('.').next()?.parse().ok()
    }

    /// A10: verify the engine file again, now, exactly as discovery did
    /// (name, presence, version resource and, on Windows, Authenticode), and
    /// require the same kind and version. An engine updated or replaced in
    /// place since discovery is refused, so the window and the signature
    /// are checked against the file that is about to run.
    pub fn reverify(&self) -> Result<(), HostError> {
        #[cfg(test)]
        if self.stand_in {
            return Ok(());
        }
        let fresh = verify_candidate(&self.path)?;
        if fresh.kind != self.kind || fresh.version != self.version {
            return Err(HostError::Unavailable(UnavailableReason::UnsupportedEngine));
        }
        Ok(())
    }

    /// Whether the live worker is qualified on this engine (A10): its kind
    /// and major are in `QUALIFIED_WORKER_ENGINES`.
    pub fn worker_qualified(&self) -> bool {
        self.major().is_some_and(|major| {
            QUALIFIED_WORKER_ENGINES
                .iter()
                .any(|&(kind, qualified)| kind == self.kind && qualified == major)
        })
    }

    /// Whether the OS publisher check passed. Always true on Windows
    /// (WinVerifyTrust is mandatory there); elsewhere the path and
    /// version checks apply and this reports false.
    pub fn publisher_verified(&self) -> bool {
        self.publisher_verified
    }

    /// Unit-test stand-in for a verified engine (never constructed in
    /// production code).
    #[cfg(test)]
    pub(crate) fn for_tests(path: PathBuf, kind: EngineKind) -> Self {
        Self::for_tests_at(path, kind, "0.0.0.0")
    }

    /// As `for_tests`, with a given version.
    #[cfg(test)]
    pub(crate) fn for_tests_at(path: PathBuf, kind: EngineKind, version: &str) -> Self {
        Self {
            path,
            kind,
            version: version.into(),
            publisher_verified: false,
            stand_in: true,
        }
    }

    /// Short fingerprint binding kind, version, and path for identities.
    pub fn fingerprint(&self) -> String {
        format!(
            "{:?}:{}:{}",
            self.kind,
            self.version,
            self.path.to_string_lossy()
        )
    }
}

/// Where to look. Production scans isolated extra roots (none) plus the
/// machine. Tests disable the machine scan for deterministic unavailability.
pub struct SearchConfig {
    extra_roots: Vec<PathBuf>,
    system: bool,
}

impl SearchConfig {
    pub fn production() -> Self {
        Self {
            extra_roots: Vec::new(),
            system: true,
        }
    }

    pub fn with_extra_roots(roots: Vec<PathBuf>) -> Self {
        Self {
            extra_roots: roots,
            system: true,
        }
    }

    /// Test-only scope: extra roots alone, never the machine.
    pub fn isolated(roots: Vec<PathBuf>) -> Self {
        Self {
            extra_roots: roots,
            system: false,
        }
    }
}

/// Discover, probe, and verify one engine. Fails closed with
/// [`UnavailableReason`] when nothing suitable exists.
pub fn discover_engine(search: &SearchConfig) -> Result<Engine, HostError> {
    let mut candidates = Vec::new();
    candidates.extend(
        search
            .extra_roots
            .iter()
            .flat_map(|root| candidate_executables(root)),
    );
    if search.system {
        candidates.extend(platform_candidates());
    }
    for path in candidates {
        match verify_candidate(&path) {
            Ok(engine) => return Ok(engine),
            Err(HostError::Unavailable(_)) => continue,
            Err(other) => return Err(other),
        }
    }
    Err(HostError::Unavailable(UnavailableReason::NoEngine))
}

fn candidate_executables(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for kind in [EngineKind::Edge, EngineKind::Chromium] {
        for name in kind.executable_names() {
            out.push(root.join(name));
        }
    }
    out.sort();
    out
}

fn verify_candidate(path: &Path) -> Result<Engine, HostError> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let kind = if file_name == "msedge.exe" || file_name == "msedge" {
        EngineKind::Edge
    } else if ["chrome.exe", "chrome", "chromium", "chromium-browser"].contains(&file_name.as_str())
    {
        EngineKind::Chromium
    } else {
        return Err(HostError::Unavailable(UnavailableReason::UnsupportedEngine));
    };
    if !path.is_file() {
        return Err(HostError::Unavailable(UnavailableReason::NoEngine));
    }
    let version = probe_version(path)?;
    let publisher_verified = verify_publisher(path)?;
    Ok(Engine {
        path: path.to_path_buf(),
        kind,
        version,
        publisher_verified,
        #[cfg(test)]
        stand_in: false,
    })
}

/// The engine's version. On Windows it is read from the executable's
/// version resource without running anything: Chromium-family engines print
/// no version for `--version` on Windows and instead hand the command to an
/// already-running browser session, which would touch the user's personal
/// profile. Elsewhere `<engine> --version` runs with a bounded wait and a
/// scrubbed environment.
#[cfg(windows)]
pub fn probe_version(engine: &Path) -> Result<String, HostError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW, VS_FIXEDFILEINFO,
    };
    let path: Vec<u16> = engine.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut ignored = 0u32;
    // SAFETY: NUL-terminated path; the out-parameter is valid.
    let size = unsafe { GetFileVersionInfoSizeW(path.as_ptr(), &mut ignored) };
    if size == 0 || size > 1 << 20 {
        return Err(HostError::Unavailable(UnavailableReason::UnsupportedEngine));
    }
    let mut block = vec![0u8; size as usize];
    // SAFETY: the buffer holds `size` bytes.
    if unsafe { GetFileVersionInfoW(path.as_ptr(), 0, size, block.as_mut_ptr().cast()) } == 0 {
        return Err(HostError::Unavailable(UnavailableReason::UnsupportedEngine));
    }
    let root: Vec<u16> = "\\".encode_utf16().chain(Some(0)).collect();
    let mut info: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut len = 0u32;
    // SAFETY: `block` is a version resource; the result points into it.
    if unsafe { VerQueryValueW(block.as_ptr().cast(), root.as_ptr(), &mut info, &mut len) } == 0
        || info.is_null()
        || (len as usize) < std::mem::size_of::<VS_FIXEDFILEINFO>()
    {
        return Err(HostError::Unavailable(UnavailableReason::UnsupportedEngine));
    }
    // SAFETY: VerQueryValueW returned a VS_FIXEDFILEINFO inside `block`.
    let fixed = unsafe { std::ptr::read_unaligned(info as *const VS_FIXEDFILEINFO) };
    if fixed.dwSignature != 0xFEEF_04BD {
        return Err(HostError::Unavailable(UnavailableReason::UnsupportedEngine));
    }
    let version = format!(
        "{}.{}.{}.{}",
        fixed.dwProductVersionMS >> 16,
        fixed.dwProductVersionMS & 0xFFFF,
        fixed.dwProductVersionLS >> 16,
        fixed.dwProductVersionLS & 0xFFFF
    );
    parse_version(&version).ok_or(HostError::Unavailable(UnavailableReason::UnsupportedEngine))
}

/// Run `<engine> --version` with a bounded wait and parse the version.
/// The probe inherits only a scrubbed environment.
#[cfg(not(windows))]
pub fn probe_version(engine: &Path) -> Result<String, HostError> {
    let mut child = std::process::Command::new(engine)
        .arg("--version")
        .env_clear()
        .envs(probe_env())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|_| HostError::Unavailable(UnavailableReason::NoEngine))?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return Err(HostError::Unavailable(UnavailableReason::UnsupportedEngine));
                }
                let output = child
                    .wait_with_output()
                    .map_err(|_| HostError::Unavailable(UnavailableReason::LaunchFailed))?;
                let text = String::from_utf8_lossy(&output.stdout);
                return parse_version(&text)
                    .ok_or(HostError::Unavailable(UnavailableReason::UnsupportedEngine));
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    return Err(HostError::Unavailable(UnavailableReason::LaunchFailed));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => return Err(HostError::Unavailable(UnavailableReason::LaunchFailed)),
        }
    }
}

fn parse_version(text: &str) -> Option<String> {
    let mut run = String::new();
    let mut runs = Vec::new();
    for ch in text.chars().chain(std::iter::once(' ')) {
        if ch.is_ascii_digit() || (ch == '.' && !run.is_empty()) {
            run.push(ch);
        } else if !run.is_empty() {
            runs.push(std::mem::take(&mut run));
        }
    }
    runs.into_iter().find(|run| run.matches('.').count() >= 2)
}

/// Minimal scrubbed environment for the non-Windows version probe. No
/// caller, user, or Orcel secret variable is inherited.
#[cfg(not(windows))]
fn probe_env() -> Vec<(OsString, OsString)> {
    platform_probe_env()
}

#[cfg(not(windows))]
fn platform_probe_env() -> Vec<(OsString, OsString)> {
    vec![
        (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
        (OsString::from("LANG"), OsString::from("C")),
    ]
}

#[cfg(windows)]
fn platform_candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    for name in ["msedge.exe", "chrome.exe"] {
        if let Some(path) = app_paths_executable(name) {
            out.push(path);
        }
    }
    if let Some(program_files) = std::env::var_os("ProgramFiles") {
        out.push(Path::new(&program_files).join("Microsoft/Edge/Application/msedge.exe"));
        out.push(Path::new(&program_files).join("Google/Chrome/Application/chrome.exe"));
    }
    if let Some(program_files_x86) = std::env::var_os("ProgramFiles(x86)") {
        out.push(Path::new(&program_files_x86).join("Microsoft/Edge/Application/msedge.exe"));
        out.push(Path::new(&program_files_x86).join("Google/Chrome/Application/chrome.exe"));
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(not(windows))]
fn platform_candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    for dir in [
        "/usr/bin",
        "/usr/local/bin",
        "/opt/google/chrome",
        "/snap/bin",
    ] {
        out.extend(candidate_executables(Path::new(dir)));
    }
    // PATH lookup for the known names.
    if let Some(path_var) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_var) {
            for kind in [EngineKind::Edge, EngineKind::Chromium] {
                for name in kind.executable_names() {
                    let candidate = dir.join(name);
                    if candidate.is_file() {
                        out.push(candidate);
                    }
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::ffi::c_void;
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
    use windows_sys::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO,
        WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    };
    use windows_sys::Win32::System::Registry::{
        RegGetValueW, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ,
    };

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(Some(0)).collect()
    }

    pub(super) fn app_paths_executable(file_name: &str) -> Option<PathBuf> {
        let subkey =
            format!("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\{file_name}");
        for hive in [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER] {
            let mut size: u32 = 0;
            // SAFETY: query the size first with a null buffer.
            let status = unsafe {
                RegGetValueW(
                    hive,
                    wide(&subkey).as_ptr(),
                    std::ptr::null(),
                    RRF_RT_REG_SZ,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut size,
                )
            };
            if status != ERROR_SUCCESS || size == 0 || size > 32_768 {
                continue;
            }
            let mut buffer = vec![0u16; (size as usize).div_ceil(2)];
            let mut actual = (buffer.len() * 2) as u32;
            // SAFETY: buffer length is passed in `actual`.
            let status = unsafe {
                RegGetValueW(
                    hive,
                    wide(&subkey).as_ptr(),
                    std::ptr::null(),
                    RRF_RT_REG_SZ,
                    std::ptr::null_mut(),
                    buffer.as_mut_ptr() as *mut _,
                    &mut actual,
                )
            };
            if status != ERROR_SUCCESS {
                continue;
            }
            let path = String::from_utf16_lossy(&buffer)
                .trim_matches('\0')
                .trim()
                .trim_matches('"')
                .to_owned();
            if !path.is_empty() {
                return Some(PathBuf::from(path));
            }
        }
        None
    }

    pub(super) fn verify_publisher(path: &Path) -> Result<bool, HostError> {
        let wide_path = wide(&path.to_string_lossy());
        // SAFETY: all structures are zeroed then fully initialized below;
        // `data.u.pFile` matches `dwUnionChoice`, and every borrow outlives
        // the verification call, which performs no mutation.
        unsafe {
            let mut file_info: WINTRUST_FILE_INFO = std::mem::zeroed();
            file_info.cbStruct = std::mem::size_of::<WINTRUST_FILE_INFO>() as u32;
            file_info.pcwszFilePath = wide_path.as_ptr();
            let mut data: WINTRUST_DATA = std::mem::zeroed();
            data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
            data.dwUIChoice = WTD_UI_NONE;
            data.fdwRevocationChecks = WTD_REVOKE_NONE;
            data.dwUnionChoice = WTD_CHOICE_FILE;
            data.dwStateAction = WTD_STATEACTION_VERIFY;
            data.hWVTStateData = 0 as HANDLE;
            data.Anonymous.pFile = &mut file_info;
            let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            Ok(WinVerifyTrust(0 as HANDLE, &mut action, &mut data as *mut _ as *mut c_void) == 0)
        }
    }
}

#[cfg(windows)]
fn verify_publisher(path: &Path) -> Result<bool, HostError> {
    if !windows::verify_publisher(path)? {
        return Err(HostError::Unavailable(UnavailableReason::UnsupportedEngine));
    }
    Ok(true)
}

#[cfg(not(windows))]
fn verify_publisher(_path: &Path) -> Result<bool, HostError> {
    // No OS publisher check is implemented off Windows: path, kind, and
    // version checks apply and the engine reports unverified. Recorded as
    // a platform boundary in the SG-000074 note.
    Ok(false)
}

#[cfg(windows)]
fn app_paths_executable(name: &str) -> Option<PathBuf> {
    windows::app_paths_executable(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn only_qualified_engine_versions_run_the_worker() {
        let engine = |kind, version| Engine::for_tests_at(PathBuf::from("x"), kind, version);
        assert!(engine(EngineKind::Edge, "155.0.4283.45").worker_qualified());
        assert_eq!(engine(EngineKind::Edge, "155.0.4283.45").major(), Some(155));
        assert!(engine(EngineKind::Chromium, "154.0.8037.58").worker_qualified());
        assert!(engine(EngineKind::Chromium, "155.0.8059.40").worker_qualified());
        assert!(engine(EngineKind::Chromium, "156.0.8078.48").worker_qualified());
        assert!(engine(EngineKind::Edge, "156.0.4314.42").worker_qualified());
        for (kind, version) in [
            (EngineKind::Edge, "154.0.1.2"),
            // Each kind has its own qualified majors: Chromium 154 is
            // qualified, Edge 154 is not.
            (EngineKind::Edge, "157.0.1.2"),
            (EngineKind::Edge, "1550.0.1.2"),
            (EngineKind::Edge, "0.0.0.0"),
            (EngineKind::Edge, ""),
            (EngineKind::Edge, "x155.0"),
            // The next Chromium major is not qualified.
            (EngineKind::Chromium, "157.0.4283.45"),
            (EngineKind::Chromium, "153.0.1.2"),
            (EngineKind::Edge, "154.0.8037.58"),
        ] {
            assert!(
                !engine(kind, version).worker_qualified(),
                "{kind:?} {version}"
            );
        }
    }

    #[test]
    fn version_parsing_accepts_dotted_runs() {
        assert_eq!(
            parse_version("Microsoft Edge 120.0.2210.61").as_deref(),
            Some("120.0.2210.61")
        );
        assert_eq!(
            parse_version("Chromium 131.0.6778.0").as_deref(),
            Some("131.0.6778.0")
        );
        assert!(parse_version("no version here").is_none());
        assert!(parse_version("v2").is_none());
    }

    #[test]
    fn unknown_executables_are_unsupported() {
        let dir = std::env::temp_dir().join(format!("orcel-host-disc-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("firefox.exe"), b"fake").unwrap();
        // Isolated scope: the machine may ship a real engine, which must
        // not satisfy this test either way.
        let search = SearchConfig::isolated(vec![dir.clone()]);
        assert!(matches!(
            discover_engine(&search),
            Err(HostError::Unavailable(
                UnavailableReason::NoEngine | UnavailableReason::UnsupportedEngine
            ))
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_roots_report_no_engine_without_touching_the_machine() {
        // Extra roots only: a scratch empty directory proves the typed
        // unavailable path without depending on installed software.
        let dir = std::env::temp_dir().join(format!("orcel-host-empty-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        // Point PATH-less discovery at the empty root by direct candidate
        // verification of a missing file.
        assert!(matches!(
            verify_candidate(&dir.join("chrome.exe")),
            Err(HostError::Unavailable(_))
        ));
        let _ = fs::remove_dir_all(&dir);
    }
}
