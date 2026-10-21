//! XP-13 kernel-side client of the contained tier's helper,
//! `apps/orcel-contain` (std only; tokio stays out of the kernel, AD-16).
//!
//! The contained tier is opt-in for a registered executable and is what
//! parsers and helpers (WI-05) run under: no network, an exact read/write
//! allowlist, no process creation, resource limits and owned cleanup. The
//! helper installs those boundaries; this module only
//!
//! 1. pins the helper: an absolute, symlink-free path that is not writable by
//!    group or others (nor is its directory, on Unix), whose SHA-256 must equal
//!    the pinned digest. The helper is hashed from the same open file that is
//!    then executed on Linux (`/proc/self/fd/N`); elsewhere the hashed handle
//!    stays open across the spawn, and on Windows it denies writers, renames
//!    and deletes while it is open;
//! 2. writes the closed, bounded spec (refusing one larger than
//!    [`MAX_SPEC_BYTES`] before anything starts) and keeps the helper's stdin
//!    open, so the helper sees end of file if orceld dies. The spec carries
//!    the executable's SHA-256; the helper hashes the executable through the
//!    descriptor it then runs and refuses a mismatch
//!    ([`RefusalKind::ExecutableChanged`], #384 item 2);
//! 3. reads one bounded result: a header line and exactly the byte counts it
//!    names, never more than the run's own output bounds;
//! 4. enforces its own deadline (the run's timeout plus a grace period) and
//!    kills the helper past it, which takes the child down with it.
//!
//! The format is documented in `apps/orcel-contain/src/spec.rs`; both sides'
//! tests pin it. [`run_contained`] blocks the calling thread for the whole
//! run. That matters on Linux: the helper arms `PR_SET_PDEATHSIG`, which fires
//! when the spawning *thread* exits.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const SPEC_MAGIC: &str = "orcel-contain-spec 2";
const RESULT_MAGIC: &str = "orcel-contain-result 1";

/// The helper's own bound on the spec, `end` line included.
pub const MAX_SPEC_BYTES: usize = 64 * 1024;
const MAX_ARGS: usize = 256;
const MAX_ROOTS: usize = 32;
const MAX_VALUE_BYTES: usize = 4096;
const MAX_HEADER_BYTES: usize = 2048;
/// A helper larger than this is not the helper.
const MAX_HELPER_BYTES: u64 = 64 * 1024 * 1024;
/// Past the run's own timeout, the helper gets this long to kill, reap and
/// report before it is killed itself.
const HELPER_GRACE: Duration = Duration::from_secs(15);
/// The helper's refusal exit status (`EXIT_REFUSED` in its main.rs).
const HELPER_REFUSED_STATUS: i32 = 3;

/// Limits of one contained run. Every value is checked against the helper's
/// own ranges before anything starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainedLimits {
    pub timeout: Duration,
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
    pub memory_bytes: u64,
    pub cpu_seconds: u64,
    pub open_files: u32,
}

impl Default for ContainedLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            stdout_bytes: 2 * 1024 * 1024,
            stderr_bytes: 256 * 1024,
            memory_bytes: 2 * 1024 * 1024 * 1024,
            cpu_seconds: 60,
            open_files: 256,
        }
    }
}

impl ContainedLimits {
    pub fn validate(&self) -> Result<(), ContainedError> {
        let invalid = |message: &str| Err(ContainedError::InvalidSpec(message.to_owned()));
        let timeout_ms = self.timeout.as_millis();
        if timeout_ms == 0 || timeout_ms > 30 * 60 * 1000 {
            return invalid("timeout must be between 1 ms and 30 minutes");
        }
        if self.stdout_bytes == 0 || self.stdout_bytes > 16 * 1024 * 1024 {
            return invalid("stdout limit must be between 1 byte and 16 MiB");
        }
        if self.stderr_bytes == 0 || self.stderr_bytes > 4 * 1024 * 1024 {
            return invalid("stderr limit must be between 1 byte and 4 MiB");
        }
        if self.memory_bytes < 16 * 1024 * 1024 || self.memory_bytes > 64 * 1024 * 1024 * 1024 {
            return invalid("memory limit must be between 16 MiB and 64 GiB");
        }
        if self.cpu_seconds == 0 || self.cpu_seconds > 60 * 60 {
            return invalid("CPU limit must be between 1 second and 1 hour");
        }
        if !(16..=4096).contains(&self.open_files) {
            return invalid("open-file limit must be between 16 and 4096");
        }
        Ok(())
    }
}

/// One contained run: an exact executable, its arguments, a private working
/// directory (readable and writable) and the exact extra roots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainedSpec {
    pub executable: PathBuf,
    /// The executable's 64-digit lower-case SHA-256 (#384 item 2): the
    /// registered digest for a contained-tier entry, the pinned digest for
    /// WI-05's parser. The helper hashes the file through the descriptor it
    /// then executes and refuses a mismatch, so a file swapped in after
    /// orceld's own check never runs.
    pub executable_sha256: String,
    pub argv: Vec<String>,
    pub workdir: PathBuf,
    pub readable: Vec<PathBuf>,
    pub writable: Vec<PathBuf>,
    pub limits: ContainedLimits,
}

/// The helper binary orceld may launch: an exact path and its SHA-256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperPin {
    path: PathBuf,
    sha256: [u8; 32],
}

impl HelperPin {
    /// `sha256_hex` is the 64-digit lower-case digest from the signed install
    /// manifest. No PATH lookup is ever made: the path must be absolute.
    pub fn new(path: impl Into<PathBuf>, sha256_hex: &str) -> Result<Self, ContainedError> {
        let path = path.into();
        if !path.is_absolute() {
            return Err(ContainedError::HelperNotPinned(
                "the helper path must be absolute".into(),
            ));
        }
        let digest = decode_hex(sha256_hex)
            .filter(|digest| digest.len() == 32)
            .ok_or_else(|| {
                ContainedError::HelperNotPinned("the helper digest must be 64 hex digits".into())
            })?;
        let mut sha256 = [0_u8; 32];
        sha256.copy_from_slice(&digest);
        Ok(Self { path, sha256 })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainedStream {
    Stdout,
    Stderr,
}

/// How a contained run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainedOutcome {
    Exited(i64),
    /// Unix only: the terminating signal.
    Signaled(i64),
    /// A CPU or memory ceiling ended the child.
    ResourceLimit,
    /// The run's own timeout passed; the helper killed the tree.
    TimedOut,
    /// One stream passed its bound; the tree was killed and the first
    /// `bound` bytes are kept.
    OutputLimit(ContainedStream),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainedRun {
    pub outcome: ContainedOutcome,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Why the helper refused to launch anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalKind {
    /// A boundary cannot be installed on this host (for example no Landlock,
    /// no seccomp, no `sandbox-exec`).
    UnsupportedPlatform,
    /// A boundary could not be configured or the child could not start.
    LaunchFailed,
    ResourceLimitExceeded,
    Crashed,
    SpecTooLarge,
    InvalidSpec,
    /// The executable did not match `executable_sha256` when the helper
    /// opened it (#384 item 2).
    ExecutableChanged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainedError {
    /// The spec was refused here, before the helper started.
    InvalidSpec(String),
    /// The encoded spec exceeds [`MAX_SPEC_BYTES`]; the helper never started.
    SpecTooLarge,
    /// The helper path is not a pinnable file.
    HelperNotPinned(String),
    /// The helper's bytes do not match the pinned digest.
    HelperTampered,
    /// The helper refused; nothing was launched.
    Refused { kind: RefusalKind, message: String },
    /// The helper broke the result protocol, crashed or could not start.
    Helper(String),
    /// The helper outlived the run's timeout plus its grace and was killed.
    HelperTimedOut,
}

/// Encode a spec exactly as the helper parses it. The parent pid is the
/// process that will start the helper.
pub fn encode_spec(spec: &ContainedSpec, parent: u32) -> Result<Vec<u8>, ContainedError> {
    spec.limits.validate()?;
    if spec.argv.len() > MAX_ARGS {
        return Err(ContainedError::InvalidSpec("too many arguments".into()));
    }
    if spec.readable.len() > MAX_ROOTS || spec.writable.len() > MAX_ROOTS {
        return Err(ContainedError::InvalidSpec("too many roots".into()));
    }
    if parent == 0 {
        return Err(ContainedError::InvalidSpec(
            "parent pid must be non-zero".into(),
        ));
    }
    let mut out = String::new();
    out.push_str(SPEC_MAGIC);
    out.push('\n');
    out.push_str(&format!("parent {parent}\n"));
    push_path(&mut out, "exe", &spec.executable)?;
    if spec.executable_sha256.len() != 64
        || !spec
            .executable_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ContainedError::InvalidSpec(
            "executable_sha256 must be 64 lower-case hex digits".into(),
        ));
    }
    out.push_str(&format!("sha256 {}\n", spec.executable_sha256));
    for arg in &spec.argv {
        push_text(&mut out, "arg", arg)?;
    }
    push_path(&mut out, "workdir", &spec.workdir)?;
    for root in &spec.readable {
        push_path(&mut out, "read", root)?;
    }
    for root in &spec.writable {
        push_path(&mut out, "write", root)?;
    }
    let limits = &spec.limits;
    out.push_str(&format!(
        "memory {}\ncpu {}\ntimeout_ms {}\nstdout {}\nstderr {}\nfiles {}\nend\n",
        limits.memory_bytes,
        limits.cpu_seconds,
        limits.timeout.as_millis(),
        limits.stdout_bytes,
        limits.stderr_bytes,
        limits.open_files,
    ));
    if out.len() > MAX_SPEC_BYTES {
        return Err(ContainedError::SpecTooLarge);
    }
    Ok(out.into_bytes())
}

fn push_path(out: &mut String, key: &str, path: &Path) -> Result<(), ContainedError> {
    if !path.is_absolute() {
        return Err(ContainedError::InvalidSpec(format!(
            "{key} must be an absolute path"
        )));
    }
    let text = path
        .to_str()
        .ok_or_else(|| ContainedError::InvalidSpec(format!("{key} is not valid Unicode")))?;
    push_text(out, key, text)
}

fn push_text(out: &mut String, key: &str, text: &str) -> Result<(), ContainedError> {
    if text.is_empty() || text.len() > MAX_VALUE_BYTES || text.contains('\0') {
        return Err(ContainedError::InvalidSpec(format!(
            "{key} is empty, too long or contains NUL"
        )));
    }
    out.push_str(key);
    out.push(' ');
    out.push_str(&encode_hex(text.as_bytes()));
    out.push('\n');
    Ok(())
}

/// Run `spec` under the pinned helper. Blocks until the run ends.
pub fn run_contained(
    pin: &HelperPin,
    spec: &ContainedSpec,
) -> Result<ContainedRun, ContainedError> {
    let encoded = encode_spec(spec, std::process::id())?;
    let verified = verify_helper(pin)?;
    check_exact_paths(spec)?;
    let mut child = spawn_helper(&verified, &spec.workdir)?;
    drop(verified);

    let Some(mut stdin) = child.stdin.take() else {
        kill(&mut child);
        return Err(ContainedError::Helper("the helper has no stdin".into()));
    };
    let Some(stdout) = child.stdout.take() else {
        kill(&mut child);
        return Err(ContainedError::Helper("the helper has no stdout".into()));
    };
    let limit = MAX_HEADER_BYTES + spec.limits.stdout_bytes + spec.limits.stderr_bytes;
    let (sender, receiver) = mpsc::channel();
    let reader = std::thread::Builder::new()
        .name("orcel-contained-result".into())
        .spawn(move || {
            let mut bytes = Vec::new();
            let read = stdout
                .take(u64::try_from(limit + 1).unwrap_or(u64::MAX))
                .read_to_end(&mut bytes);
            let _ = sender.send(read.map(|_| bytes));
        });
    if reader.is_err() {
        kill(&mut child);
        return Err(ContainedError::Helper(
            "failed to start the result reader".into(),
        ));
    }
    if stdin
        .write_all(&encoded)
        .and_then(|()| stdin.flush())
        .is_err()
    {
        // The helper may have refused already; its result says why.
    }

    let deadline = Instant::now() + spec.limits.timeout + HELPER_GRACE;
    let received = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            kill(&mut child);
            return Err(ContainedError::HelperTimedOut);
        }
        match receiver.recv_timeout(remaining.min(Duration::from_millis(100))) {
            Ok(received) => break received,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                kill(&mut child);
                return Err(ContainedError::Helper("the result reader stopped".into()));
            }
        }
    };
    // The result is complete (or broken); the helper may exit now.
    drop(stdin);
    let bytes = match received {
        Ok(bytes) => bytes,
        Err(_) => {
            kill(&mut child);
            return Err(ContainedError::Helper(
                "failed to read the helper result".into(),
            ));
        }
    };
    let status = wait_until(&mut child, deadline);
    let parsed = parse_result(&bytes, &spec.limits);
    match (parsed, status) {
        (Err(error), _) => Err(error),
        (Ok(Parsed::Refused { kind, message }), Some(HELPER_REFUSED_STATUS)) => {
            Err(ContainedError::Refused { kind, message })
        }
        (Ok(Parsed::Run(run)), Some(0)) => Ok(run),
        (Ok(_), _) => Err(ContainedError::Helper(
            "the helper's exit status does not match its result".into(),
        )),
    }
}

fn wait_until(child: &mut Child, deadline: Instant) -> Option<i32> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.code(),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            _ => {
                kill(child);
                return None;
            }
        }
    }
}

fn kill(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

enum Parsed {
    Run(ContainedRun),
    Refused { kind: RefusalKind, message: String },
}

/// Decode one helper result, bounded by `limits`, without the exit-status
/// cross-check [`run_contained`] adds. For callers (and tests) that start the
/// helper themselves.
pub fn decode_result(
    bytes: &[u8],
    limits: &ContainedLimits,
) -> Result<ContainedRun, ContainedError> {
    match parse_result(bytes, limits)? {
        Parsed::Run(run) => Ok(run),
        Parsed::Refused { kind, message } => Err(ContainedError::Refused { kind, message }),
    }
}

fn parse_result(bytes: &[u8], limits: &ContainedLimits) -> Result<Parsed, ContainedError> {
    let broken = |message: &str| ContainedError::Helper(format!("malformed result: {message}"));
    let newline = bytes
        .iter()
        .take(MAX_HEADER_BYTES)
        .position(|byte| *byte == b'\n')
        .ok_or_else(|| broken("no header line"))?;
    let header =
        std::str::from_utf8(&bytes[..newline]).map_err(|_| broken("header is not UTF-8"))?;
    let rest = header
        .strip_prefix(RESULT_MAGIC)
        .and_then(|rest| rest.strip_prefix(' '))
        .ok_or_else(|| broken("wrong magic"))?;
    let fields: Vec<&str> = rest.split(' ').collect();
    let [outcome, code, stdout_len, stderr_len, detail] = fields[..] else {
        return Err(broken("wrong field count"));
    };
    let number = |text: &str| text.parse::<usize>().map_err(|_| broken("bad length"));
    let code: i64 = code.parse().map_err(|_| broken("bad code"))?;
    let stdout_len = number(stdout_len)?;
    let stderr_len = number(stderr_len)?;
    if stdout_len > limits.stdout_bytes || stderr_len > limits.stderr_bytes {
        return Err(broken("output exceeds the requested bounds"));
    }
    let body = &bytes[newline + 1..];
    if body.len() != stdout_len + stderr_len {
        return Err(broken("output length does not match the header"));
    }
    if outcome == "refused" {
        if stdout_len != 0 || stderr_len != 0 {
            return Err(broken("a refusal carries output"));
        }
        let text = decode_hex(detail)
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .ok_or_else(|| broken("bad refusal detail"))?;
        let (kind, message) = text.split_once(": ").unwrap_or((text.as_str(), ""));
        let kind = match kind {
            "unsupported_platform" => RefusalKind::UnsupportedPlatform,
            "launch_failed" => RefusalKind::LaunchFailed,
            "resource_limit_exceeded" => RefusalKind::ResourceLimitExceeded,
            "crashed" => RefusalKind::Crashed,
            "spec_too_large" => RefusalKind::SpecTooLarge,
            "invalid_spec" => RefusalKind::InvalidSpec,
            "executable_changed" => RefusalKind::ExecutableChanged,
            _ => return Err(broken("unknown refusal kind")),
        };
        return Ok(Parsed::Refused {
            kind,
            message: message.to_owned(),
        });
    }
    if detail != "-" {
        return Err(broken("a run carries a detail"));
    }
    let outcome = match outcome {
        "exited" => ContainedOutcome::Exited(code),
        "signaled" => ContainedOutcome::Signaled(code),
        "resource_limit" => ContainedOutcome::ResourceLimit,
        "timed_out" => ContainedOutcome::TimedOut,
        "stdout_limit" => ContainedOutcome::OutputLimit(ContainedStream::Stdout),
        "stderr_limit" => ContainedOutcome::OutputLimit(ContainedStream::Stderr),
        // orceld is alive and reading, so the helper cannot have seen it go.
        _ => return Err(broken("unknown outcome")),
    };
    Ok(Parsed::Run(ContainedRun {
        outcome,
        stdout: body[..stdout_len].to_vec(),
        stderr: body[stdout_len..].to_vec(),
    }))
}

/// Every path in the spec must already be canonical: a root reached through a
/// symbolic link (which an earlier contained run could have planted in its
/// writable root) is refused here, before the helper starts, and the helper
/// checks again without following links.
fn check_exact_paths(spec: &ContainedSpec) -> Result<(), ContainedError> {
    let paths = std::iter::once(&spec.executable)
        .chain(std::iter::once(&spec.workdir))
        .chain(&spec.readable)
        .chain(&spec.writable);
    for path in paths {
        let canonical = std::fs::canonicalize(path)
            .map_err(|_| ContainedError::InvalidSpec("a spec path does not exist".into()))?;
        if !same_path(&canonical, path) {
            return Err(ContainedError::InvalidSpec(
                "a spec path is not canonical (a link or relative part)".into(),
            ));
        }
    }
    Ok(())
}

/// The pinned helper, verified and still open.
struct VerifiedHelper {
    path: PathBuf,
    file: std::fs::File,
}

fn verify_helper(pin: &HelperPin) -> Result<VerifiedHelper, ContainedError> {
    let not_pinned = |message: &str| ContainedError::HelperNotPinned(message.to_owned());
    let canonical =
        std::fs::canonicalize(&pin.path).map_err(|_| not_pinned("the helper does not exist"))?;
    if !same_path(&canonical, &pin.path) {
        return Err(not_pinned(
            "the helper path is not canonical (a link or relative part)",
        ));
    }
    let mut file =
        open_helper(&canonical).map_err(|_| not_pinned("the helper cannot be opened"))?;
    let metadata = file
        .metadata()
        .map_err(|_| not_pinned("the helper cannot be inspected"))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_HELPER_BYTES {
        return Err(not_pinned(
            "the helper is not a regular file of a plausible size",
        ));
    }
    check_not_shared_writable(&canonical, &metadata)?;
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    (&mut file)
        .take(MAX_HELPER_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| not_pinned("the helper cannot be read"))?;
    if sha256(&bytes) != pin.sha256 {
        return Err(ContainedError::HelperTampered);
    }
    Ok(VerifiedHelper {
        path: canonical,
        file,
    })
}

fn same_path(canonical: &Path, pinned: &Path) -> bool {
    #[cfg(windows)]
    {
        let strip = |path: &Path| {
            let text = path.to_string_lossy().replace('/', "\\");
            text.strip_prefix(r"\\?\")
                .map_or(text.clone(), str::to_owned)
                .to_ascii_lowercase()
        };
        strip(canonical).trim_end_matches('\\') == strip(pinned).trim_end_matches('\\')
    }
    #[cfg(not(windows))]
    {
        canonical == pinned
    }
}

#[cfg(windows)]
fn open_helper(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    // FILE_SHARE_READ only: while this handle is open nobody can write,
    // rename or delete the helper, which covers the spawn below.
    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0x0000_0001)
        .open(path)
}

#[cfg(not(windows))]
fn open_helper(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

#[cfg(unix)]
fn check_not_shared_writable(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<(), ContainedError> {
    use std::os::unix::fs::PermissionsExt;
    const GROUP_OR_OTHER_WRITE: u32 = 0o022;
    if metadata.permissions().mode() & GROUP_OR_OTHER_WRITE != 0 {
        return Err(ContainedError::HelperNotPinned(
            "the helper is writable by group or others".into(),
        ));
    }
    let parent = path
        .parent()
        .and_then(|parent| std::fs::metadata(parent).ok())
        .ok_or_else(|| ContainedError::HelperNotPinned("the helper has no directory".into()))?;
    if parent.permissions().mode() & GROUP_OR_OTHER_WRITE != 0 {
        return Err(ContainedError::HelperNotPinned(
            "the helper's directory is writable by group or others".into(),
        ));
    }
    Ok(())
}

/// Windows: this crate takes no dependency, so the owner and DACL rule
/// (#384 item 4) is applied where orceld forms the pin
/// (`contained_tier::helper_pin_in`, through
/// `orcel_platform::paths::check_owned_executable_location`). Here a helper
/// replaced before the digest check is refused as tampering, and the share
/// mode in `open_helper` stops a swap between the check and the spawn.
#[cfg(not(unix))]
fn check_not_shared_writable(
    _path: &Path,
    _metadata: &std::fs::Metadata,
) -> Result<(), ContainedError> {
    Ok(())
}

fn spawn_helper(helper: &VerifiedHelper, workdir: &Path) -> Result<Child, ContainedError> {
    let mut command = helper_command(helper);
    command
        .env_clear()
        .current_dir(workdir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // Windows processes need these two to load system components; neither
    // carries user data.
    #[cfg(windows)]
    for name in ["SystemRoot", "windir"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
        .spawn()
        .map_err(|error| ContainedError::Helper(format!("failed to start the helper: {error}")))
}

/// Linux executes the exact open file that was hashed.
#[cfg(target_os = "linux")]
fn helper_command(helper: &VerifiedHelper) -> Command {
    use std::os::fd::AsRawFd;
    let _ = &helper.path;
    Command::new(format!("/proc/self/fd/{}", helper.file.as_raw_fd()))
}

#[cfg(not(target_os = "linux"))]
fn helper_command(helper: &VerifiedHelper) -> Command {
    let _ = &helper.file;
    Command::new(&helper.path)
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 {
        return None;
    }
    let digit = |byte: u8| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    };
    value
        .as_bytes()
        .chunks(2)
        .map(|pair| Some(digit(pair[0])? << 4 | digit(pair[1])?))
        .collect()
}

/// SHA-256 (FIPS 180-4). The kernel crate takes no dependency for one digest;
/// the tests check it against the `sha2` crate and the standard vectors.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_length = (data.len() as u64).wrapping_mul(8);
    let mut message = data.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_length.to_be_bytes());
    for block in message.chunks_exact(64) {
        let mut w = [0_u32; 64];
        for (index, word) in block.chunks_exact(4).enumerate() {
            w[index] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for index in 16..64 {
            let s0 = w[index - 15].rotate_right(7)
                ^ w[index - 15].rotate_right(18)
                ^ (w[index - 15] >> 3);
            let s1 = w[index - 2].rotate_right(17)
                ^ w[index - 2].rotate_right(19)
                ^ (w[index - 2] >> 10);
            w[index] = w[index - 16]
                .wrapping_add(s0)
                .wrapping_add(w[index - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ (!e & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(choose)
                .wrapping_add(K[index])
                .wrapping_add(w[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }
    let mut digest = [0_u8; 32];
    for (chunk, word) in digest.chunks_exact_mut(4).zip(state) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    digest
}

/// Lower-case hex of [`sha256`], the form [`HelperPin::new`] takes.
pub fn sha256_hex(data: &[u8]) -> String {
    encode_hex(&sha256(data))
}

#[cfg(test)]
#[path = "contained_tests.rs"]
mod tests;
