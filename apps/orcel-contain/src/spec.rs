//! The closed, bounded spec orceld sends on stdin and the result the helper
//! writes on stdout. The kernel side is
//! `crates/orcel-provider-process/src/contained.rs`; both ends implement the
//! same format and its tests pin it from each side.
//!
//! Spec, ASCII lines, every value hex-encoded UTF-8 or a decimal integer:
//!
//! ```text
//! orcel-contain-spec 2
//! parent <pid>
//! exe <hex>
//! sha256 <64 hex>    the executable's SHA-256, lower case (#384 item 2)
//! arg <hex>          zero or more, in order
//! workdir <hex>
//! read <hex>         zero or more
//! write <hex>        zero or more
//! memory <bytes>
//! cpu <seconds>
//! timeout_ms <ms>
//! stdout <bytes>
//! stderr <bytes>
//! files <count>
//! end
//! ```
//!
//! Every key but `arg`, `read` and `write` appears exactly once. An unknown
//! key, a repeated key, a missing key, a value out of range or a spec longer
//! than [`MAX_SPEC_BYTES`] is refused before anything is launched. After
//! `end` the supervisor keeps stdin open and writes nothing more; end of file
//! (or any further byte) means the supervisor is gone and the run is killed.
//!
//! Result: one header line, then exactly `stdout_len` and `stderr_len` bytes.
//!
//! ```text
//! orcel-contain-result 1 <outcome> <code> <stdout_len> <stderr_len> <detail hex or ->
//! ```
//!
//! `outcome` is one of `exited`, `signaled`, `resource_limit`, `timed_out`,
//! `stdout_limit`, `stderr_limit`, `parent_gone` or `refused`. A refusal
//! carries `<kind>: <message>` as its detail, where `kind` is
//! `unsupported_platform`, `launch_failed`, `resource_limit_exceeded`,
//! `crashed`, `spec_too_large`, `invalid_spec` or `executable_changed` (the
//! executable did not match `sha256` when the helper opened it).

use std::io::Read;
use std::path::PathBuf;

pub const SPEC_MAGIC: &str = "orcel-contain-spec 2";
pub const RESULT_MAGIC: &str = "orcel-contain-result 1";

/// The whole spec, `end` line included.
pub const MAX_SPEC_BYTES: usize = 64 * 1024;
pub const MAX_ARGS: usize = 256;
pub const MAX_ROOTS: usize = 32;
/// One decoded path or argument.
pub const MAX_VALUE_BYTES: usize = 4096;

pub const MIN_MEMORY_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_MEMORY_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub const MAX_CPU_SECONDS: u64 = 60 * 60;
pub const MAX_TIMEOUT_MS: u64 = 30 * 60 * 1000;
pub const MAX_STDOUT_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_STDERR_BYTES: u64 = 4 * 1024 * 1024;
pub const MIN_OPEN_FILES: u64 = 16;
pub const MAX_OPEN_FILES: u64 = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Spec {
    pub parent: u32,
    pub executable: PathBuf,
    /// The SHA-256 the executable must have when the helper opens it.
    pub executable_sha256: [u8; 32],
    pub args: Vec<String>,
    pub workdir: PathBuf,
    pub read: Vec<PathBuf>,
    pub write: Vec<PathBuf>,
    pub memory_bytes: u64,
    pub cpu_seconds: u64,
    pub timeout_ms: u64,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub open_files: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SpecError {
    TooLarge,
    Invalid(&'static str),
}

impl SpecError {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::TooLarge => "spec_too_large",
            Self::Invalid(_) => "invalid_spec",
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            Self::TooLarge => "the spec exceeds the helper's size bound",
            Self::Invalid(message) => message,
        }
    }
}

/// Read the spec from `input` up to and including its `end` line, never more
/// than [`MAX_SPEC_BYTES`]. Bytes after `end` in the same read are a protocol
/// violation: the supervisor must stay silent until the result arrives.
pub fn read_spec(input: &mut impl Read) -> Result<Spec, SpecError> {
    let mut buffer = Vec::with_capacity(4096);
    let mut chunk = [0_u8; 4096];
    loop {
        if let Some(end) = find_end(&buffer) {
            if end > MAX_SPEC_BYTES {
                return Err(SpecError::TooLarge);
            }
            if end != buffer.len() {
                return Err(SpecError::Invalid("bytes follow the spec's end line"));
            }
            return parse(&buffer);
        }
        if buffer.len() >= MAX_SPEC_BYTES {
            return Err(SpecError::TooLarge);
        }
        // Never read past the bound: one byte over is enough to refuse.
        let room = (MAX_SPEC_BYTES + 1 - buffer.len()).min(chunk.len());
        let count = match input.read(&mut chunk[..room]) {
            Ok(0) => return Err(SpecError::Invalid("the spec ended before its end line")),
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(SpecError::Invalid("the spec could not be read")),
        };
        buffer.extend_from_slice(&chunk[..count]);
    }
}

/// The offset just past the first `end` line, if the buffer has one.
fn find_end(buffer: &[u8]) -> Option<usize> {
    if buffer.starts_with(b"end\n") {
        return Some(4);
    }
    buffer
        .windows(5)
        .position(|window| window == b"\nend\n")
        .map(|position| position + 5)
}

pub fn parse(bytes: &[u8]) -> Result<Spec, SpecError> {
    if bytes.len() > MAX_SPEC_BYTES {
        return Err(SpecError::TooLarge);
    }
    let text =
        std::str::from_utf8(bytes).map_err(|_| SpecError::Invalid("the spec is not UTF-8"))?;
    let body = text
        .strip_suffix("end\n")
        .ok_or(SpecError::Invalid("the spec has no end line"))?;
    let mut lines = body.split('\n');
    if lines.next() != Some(SPEC_MAGIC) {
        return Err(SpecError::Invalid("the spec has the wrong magic line"));
    }
    let mut parent = None;
    let mut executable = None;
    let mut executable_sha256 = None;
    let mut args = Vec::new();
    let mut workdir = None;
    let mut read = Vec::new();
    let mut write = Vec::new();
    let mut memory = None;
    let mut cpu = None;
    let mut timeout = None;
    let mut stdout = None;
    let mut stderr = None;
    let mut files = None;
    for line in lines {
        if line.is_empty() {
            // `body` ends with the newline before `end`.
            continue;
        }
        let (key, value) = line
            .split_once(' ')
            .ok_or(SpecError::Invalid("a spec line has no value"))?;
        match key {
            "parent" => once(&mut parent, number(value, 1, u64::from(u32::MAX))?)?,
            "exe" => once(&mut executable, PathBuf::from(text_value(value)?))?,
            "sha256" => once(&mut executable_sha256, digest_value(value)?)?,
            "arg" => {
                if args.len() == MAX_ARGS {
                    return Err(SpecError::Invalid("the spec has too many arguments"));
                }
                args.push(text_value(value)?);
            }
            "workdir" => once(&mut workdir, PathBuf::from(text_value(value)?))?,
            "read" => {
                if read.len() == MAX_ROOTS {
                    return Err(SpecError::Invalid("the spec has too many read roots"));
                }
                read.push(PathBuf::from(text_value(value)?));
            }
            "write" => {
                if write.len() == MAX_ROOTS {
                    return Err(SpecError::Invalid("the spec has too many write roots"));
                }
                write.push(PathBuf::from(text_value(value)?));
            }
            "memory" => once(
                &mut memory,
                number(value, MIN_MEMORY_BYTES, MAX_MEMORY_BYTES)?,
            )?,
            "cpu" => once(&mut cpu, number(value, 1, MAX_CPU_SECONDS)?)?,
            "timeout_ms" => once(&mut timeout, number(value, 1, MAX_TIMEOUT_MS)?)?,
            "stdout" => once(&mut stdout, number(value, 1, MAX_STDOUT_BYTES)?)?,
            "stderr" => once(&mut stderr, number(value, 1, MAX_STDERR_BYTES)?)?,
            "files" => once(&mut files, number(value, MIN_OPEN_FILES, MAX_OPEN_FILES)?)?,
            _ => return Err(SpecError::Invalid("the spec has an unknown key")),
        }
    }
    let missing = SpecError::Invalid("the spec is missing a required key");
    let spec = Spec {
        parent: u32::try_from(parent.ok_or(missing.clone())?)
            .map_err(|_| SpecError::Invalid("the spec's parent is out of range"))?,
        executable: executable.ok_or(missing.clone())?,
        executable_sha256: executable_sha256.ok_or(missing.clone())?,
        args,
        workdir: workdir.ok_or(missing.clone())?,
        read,
        write,
        memory_bytes: memory.ok_or(missing.clone())?,
        cpu_seconds: cpu.ok_or(missing.clone())?,
        timeout_ms: timeout.ok_or(missing.clone())?,
        stdout_bytes: stdout.ok_or(missing.clone())?,
        stderr_bytes: stderr.ok_or(missing.clone())?,
        open_files: files.ok_or(missing)?,
    };
    for path in std::iter::once(&spec.executable)
        .chain(std::iter::once(&spec.workdir))
        .chain(&spec.read)
        .chain(&spec.write)
    {
        if !path.is_absolute() {
            return Err(SpecError::Invalid("every spec path must be absolute"));
        }
    }
    Ok(spec)
}

fn once<T>(slot: &mut Option<T>, value: T) -> Result<(), SpecError> {
    if slot.is_some() {
        return Err(SpecError::Invalid("the spec repeats a key"));
    }
    *slot = Some(value);
    Ok(())
}

fn number(value: &str, min: u64, max: u64) -> Result<u64, SpecError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) || value.len() > 20 {
        return Err(SpecError::Invalid("a spec number is malformed"));
    }
    let number: u64 = value
        .parse()
        .map_err(|_| SpecError::Invalid("a spec number is malformed"))?;
    if number < min || number > max {
        return Err(SpecError::Invalid("a spec limit is out of range"));
    }
    Ok(number)
}

/// Exactly 64 lower-case hex digits: a SHA-256.
fn digest_value(value: &str) -> Result<[u8; 32], SpecError> {
    let bytes = decode_hex(value)
        .filter(|bytes| bytes.len() == 32)
        .ok_or(SpecError::Invalid("the spec's sha256 is not 64 hex digits"))?;
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(&bytes);
    Ok(digest)
}

/// Lower-case hex of UTF-8 text, at most [`MAX_VALUE_BYTES`] decoded, with no
/// NUL.
fn text_value(value: &str) -> Result<String, SpecError> {
    let bytes = decode_hex(value).ok_or(SpecError::Invalid("a spec value is not hex"))?;
    if bytes.is_empty() || bytes.len() > MAX_VALUE_BYTES {
        return Err(SpecError::Invalid("a spec value is empty or too long"));
    }
    if bytes.contains(&0) {
        return Err(SpecError::Invalid("a spec value contains NUL"));
    }
    String::from_utf8(bytes).map_err(|_| SpecError::Invalid("a spec value is not UTF-8"))
}

pub fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

pub fn decode_hex(value: &str) -> Option<Vec<u8>> {
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

/// The result header for a finished run or a refusal.
pub fn result_header(
    outcome: &str,
    code: i64,
    stdout_len: usize,
    stderr_len: usize,
    detail: Option<&str>,
) -> String {
    let detail = detail.map_or_else(|| "-".to_owned(), |detail| encode_hex(detail.as_bytes()));
    format!("{RESULT_MAGIC} {outcome} {code} {stdout_len} {stderr_len} {detail}\n")
}

#[cfg(test)]
#[path = "spec_tests.rs"]
mod tests;
