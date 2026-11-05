//! Release manifest format and verification.
//!
//! A release directory holds `manifest.json` plus the payload files it lists.
//! Every payload file is verified by size and SHA-256 before anything is
//! copied, and files that are present but not listed are rejected.

use crate::LifecycleError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

pub const MANIFEST_FILE: &str = "manifest.json";
pub const MANIFEST_SCHEMA: &str = "orcel-release-manifest-v1";
const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
const MAX_FILES: usize = 20_000;
const MAX_RELATIVE_PATH: usize = 200;

/// Payload files every installable release must contain.
pub const REQUIRED_FILES: &[&str] = &[
    "orcel.exe",
    "orcel-mcp-host.exe",
    "orceld.exe",
    "Orcel.Desktop.exe",
    "app/orcel-mcp/package.json",
    "app/orcel-mcp/dist/index.js",
    "LICENSE",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigSchemaRange {
    pub min: u32,
    pub max: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestFile {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: String,
    pub version: String,
    pub config_schema: ConfigSchemaRange,
    pub files: Vec<ManifestFile>,
}

/// A manifest whose payload was verified in a specific directory.
#[derive(Debug, Clone)]
pub struct VerifiedRelease {
    pub dir: PathBuf,
    pub manifest: Manifest,
    pub manifest_sha256: String,
}

impl Manifest {
    pub fn validate(&self) -> Result<(), LifecycleError> {
        if self.schema != MANIFEST_SCHEMA {
            return Err(LifecycleError::manifest("unsupported manifest schema"));
        }
        crate::version::Version::parse(&self.version)?;
        if self.config_schema.min == 0 || self.config_schema.min > self.config_schema.max {
            return Err(LifecycleError::manifest(
                "invalid configuration schema range",
            ));
        }
        if self.files.is_empty() || self.files.len() > MAX_FILES {
            return Err(LifecycleError::manifest(
                "manifest file count is out of range",
            ));
        }
        let mut seen = BTreeSet::new();
        for file in &self.files {
            validate_relative_path(&file.path)?;
            if !is_sha256_hex(&file.sha256) {
                return Err(LifecycleError::manifest(format!(
                    "invalid SHA-256 for {}",
                    file.path
                )));
            }
            if !seen.insert(file.path.to_ascii_lowercase()) {
                return Err(LifecycleError::manifest(format!(
                    "duplicate manifest path {}",
                    file.path
                )));
            }
        }
        for required in REQUIRED_FILES {
            if !seen.contains(&required.to_ascii_lowercase()) {
                return Err(LifecycleError::manifest(format!(
                    "release is missing required file {required}"
                )));
            }
        }
        Ok(())
    }
}

/// Reads and verifies a release directory: manifest shape, every listed file's
/// size and digest, and absence of unlisted files or reparse points.
pub fn verify_release(dir: &Path) -> Result<VerifiedRelease, LifecycleError> {
    let manifest_path = dir.join(MANIFEST_FILE);
    let metadata = fs::symlink_metadata(&manifest_path)
        .map_err(|error| LifecycleError::manifest(format!("read manifest: {error}")))?;
    if !metadata.is_file() || metadata.len() > MAX_MANIFEST_BYTES {
        return Err(LifecycleError::manifest(
            "manifest must be a regular file within the size bound",
        ));
    }
    let bytes = fs::read(&manifest_path)
        .map_err(|error| LifecycleError::manifest(format!("read manifest: {error}")))?;
    let manifest: Manifest = serde_json::from_slice(&bytes)
        .map_err(|error| LifecycleError::manifest(format!("parse manifest: {error}")))?;
    manifest.validate()?;
    verify_payload(dir, &manifest)?;
    Ok(VerifiedRelease {
        dir: dir.to_path_buf(),
        manifest,
        manifest_sha256: sha256_bytes(&bytes),
    })
}

/// Verifies that `dir` contains exactly the manifest payload (plus the
/// manifest itself) with matching sizes and digests.
pub fn verify_payload(dir: &Path, manifest: &Manifest) -> Result<(), LifecycleError> {
    let listed: BTreeSet<String> = manifest
        .files
        .iter()
        .map(|file| file.path.to_ascii_lowercase())
        .collect();
    let mut present = Vec::new();
    collect_files(dir, dir, &mut present)?;
    for relative in &present {
        let lowered = relative.to_ascii_lowercase();
        if lowered != MANIFEST_FILE && !listed.contains(&lowered) {
            return Err(LifecycleError::manifest(format!(
                "release contains an unlisted file: {relative}"
            )));
        }
    }
    for file in &manifest.files {
        let path = join_relative(dir, &file.path);
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            LifecycleError::manifest(format!("missing payload file {}: {error}", file.path))
        })?;
        if !metadata.is_file() {
            return Err(LifecycleError::manifest(format!(
                "payload entry is not a regular file: {}",
                file.path
            )));
        }
        if metadata.len() != file.size {
            return Err(LifecycleError::manifest(format!(
                "size mismatch for {}",
                file.path
            )));
        }
        if sha256_file(&path)? != file.sha256 {
            return Err(LifecycleError::manifest(format!(
                "SHA-256 mismatch for {}",
                file.path
            )));
        }
    }
    Ok(())
}

fn collect_files(base: &Path, dir: &Path, out: &mut Vec<String>) -> Result<(), LifecycleError> {
    let entries = fs::read_dir(dir)
        .map_err(|error| LifecycleError::manifest(format!("read release directory: {error}")))?;
    for entry in entries {
        let entry = entry
            .map_err(|error| LifecycleError::manifest(format!("read release entry: {error}")))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| LifecycleError::manifest(format!("inspect release entry: {error}")))?;
        if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
            return Err(LifecycleError::manifest(
                "release directory must not contain links or reparse points",
            ));
        }
        if metadata.is_dir() {
            collect_files(base, &path, out)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(base)
                .map_err(|_| LifecycleError::manifest("release entry escaped its directory"))?;
            let parts = relative
                .components()
                .map(|part| part.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            out.push(parts.join("/"));
            if out.len() > MAX_FILES + 1 {
                return Err(LifecycleError::manifest("release contains too many files"));
            }
        } else {
            return Err(LifecycleError::manifest(
                "release directory contains an unsupported entry",
            ));
        }
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
pub(crate) fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

/// Joins a validated forward-slash manifest path onto `base`.
pub fn join_relative(base: &Path, relative: &str) -> PathBuf {
    let mut path = base.to_path_buf();
    for part in relative.split('/') {
        path.push(part);
    }
    path
}

/// Validates a manifest-relative path: forward slashes, no empty, `.`, or
/// `..` segments, no drive, UNC, stream, or reserved device names, and no
/// characters Windows forbids in file names.
pub fn validate_relative_path(path: &str) -> Result<(), LifecycleError> {
    let invalid =
        |reason: &str| LifecycleError::manifest(format!("invalid path {path:?}: {reason}"));
    if path.is_empty() || path.len() > MAX_RELATIVE_PATH {
        return Err(invalid("length out of range"));
    }
    if path.starts_with('/') {
        return Err(invalid("absolute path"));
    }
    for segment in path.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(invalid("empty or relative segment"));
        }
        if segment.ends_with('.') || segment.ends_with(' ') {
            return Err(invalid("trailing dot or space"));
        }
        if segment
            .chars()
            .any(|c| c.is_control() || matches!(c, '<' | '>' | ':' | '"' | '\\' | '|' | '?' | '*'))
            || !segment.is_ascii()
        {
            return Err(invalid("forbidden character"));
        }
        let stem = segment
            .split('.')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || ((stem.starts_with("COM") || stem.starts_with("LPT"))
                && stem.len() == 4
                && stem.as_bytes()[3].is_ascii_digit());
        if reserved {
            return Err(invalid("reserved device name"));
        }
    }
    Ok(())
}

pub fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

pub fn sha256_file(path: &Path) -> Result<String, LifecycleError> {
    let mut file = File::open(path)
        .map_err(|error| LifecycleError::io(format!("open {}", path.display()), error))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| LifecycleError::io(format!("read {}", path.display()), error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex(&hasher.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{release_dir, temp_dir};

    #[test]
    fn valid_release_verifies() {
        let dir = release_dir("0.2.0");
        let verified = verify_release(&dir).expect("verify");
        assert_eq!(verified.manifest.version, "0.2.0");
        assert!(is_sha256_hex(&verified.manifest_sha256));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn tampered_payload_fails_closed() {
        let dir = release_dir("0.2.0");
        fs::write(dir.join("orceld.exe"), b"tampered-orceld!").unwrap();
        let error = verify_release(&dir).unwrap_err();
        assert!(error.message.contains("mismatch"), "{}", error.message);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn unlisted_file_fails_closed() {
        let dir = release_dir("0.2.0");
        fs::write(dir.join("extra.dll"), b"x").unwrap();
        let error = verify_release(&dir).unwrap_err();
        assert!(error.message.contains("unlisted"), "{}", error.message);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn missing_required_file_fails_closed() {
        let dir = temp_dir("manifest-missing");
        let manifest = Manifest {
            schema: MANIFEST_SCHEMA.into(),
            version: "0.2.0".into(),
            config_schema: ConfigSchemaRange { min: 1, max: 1 },
            files: vec![ManifestFile {
                path: "orcel.exe".into(),
                size: 0,
                sha256: sha256_bytes(b""),
            }],
        };
        let error = manifest.validate().unwrap_err();
        assert!(error.message.contains("missing required file"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn hostile_paths_are_rejected() {
        for path in [
            "",
            "/abs",
            "a//b",
            "../x",
            "a/../b",
            "./a",
            "C:/x",
            "a\\b",
            "a:stream",
            "CON",
            "nul.txt",
            "COM1",
            "lpt9.log",
            "dot.",
            "space ",
            "q?",
            "caf\u{e9}",
        ] {
            assert!(validate_relative_path(path).is_err(), "{path:?} must fail");
        }
        for path in [
            "orcel.exe",
            "app/orcel-mcp/node_modules/@modelcontextprotocol/server/package.json",
            "COM10",
            "console.js",
        ] {
            assert!(validate_relative_path(path).is_ok(), "{path:?} must pass");
        }
    }

    #[test]
    fn unknown_manifest_fields_and_schema_are_rejected() {
        let dir = release_dir("0.2.0");
        let text = fs::read_to_string(dir.join(MANIFEST_FILE)).unwrap();
        fs::write(
            dir.join(MANIFEST_FILE),
            text.replacen("{", "{\"extra\":1,", 1),
        )
        .unwrap();
        assert!(verify_release(&dir).is_err());
        fs::write(
            dir.join(MANIFEST_FILE),
            text.replace(MANIFEST_SCHEMA, "other"),
        )
        .unwrap();
        assert!(verify_release(&dir).is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn duplicate_case_insensitive_paths_are_rejected() {
        let mut manifest = verify_release(&release_dir("0.2.0")).unwrap().manifest;
        let mut dup = manifest.files[0].clone();
        dup.path = dup.path.to_ascii_uppercase();
        manifest.files.push(dup);
        assert!(manifest.validate().is_err());
    }
}
