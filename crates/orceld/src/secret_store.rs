//! XP-19 per-OS secret storage for device identity material.
//!
//! `orceld` is the only process that reads or writes these secrets. The
//! Node edge (`apps/orcel-mcp/src/secret_store.ts`) asks for them by fixed
//! name over its private stdio pipe; nothing here is reachable remotely, from
//! the CR-01 app API or from an MCP tool.
//!
//! Backends (no plaintext fallback anywhere, SECURITY_INTEGRATION S-23):
//!
//! - Windows: DPAPI (`CryptProtectData`, current-user scope, UI forbidden,
//!   per-name entropy). The protected blob is a file in
//!   `<state root>\secrets\`, which inherits the per-user `%LOCALAPPDATA%`
//!   ACL. DPAPI's own MAC refuses a tampered blob.
//! - macOS: the user's default keychain through the `keyring` project's
//!   `apple-native-keyring-store` (T-CUA-34: the crate family Cua's
//!   `cua-auth` uses). User interaction is disabled, so `orceld` never shows
//!   a keychain prompt; a locked keychain is unavailable. Until XP-16/FD-05
//!   sign `orceld`, the item's ACL trusts the unsigned creating binary by
//!   path and hash, so a rebuilt `orceld` is asked (and here refused) like
//!   any other application; no access group is set. The item lives in the
//!   legacy file keychain, which has no `kSecAttrAccessible` class: it is
//!   readable whenever that keychain is unlocked.
//! - Linux: the freedesktop Secret Service over the D-Bus session bus
//!   (`zbus-secret-service-keyring-store`, libsecret-compatible items,
//!   encrypted transport). With no session bus, no Secret Service or a locked
//!   collection the store is unavailable and nothing is written.
//!
//! Every stored value is wrapped in an envelope that names the secret, the
//! owning account and a SHA-256 over both and the payload, so a value moved
//! to another name, written for another account or damaged is refused. The
//! SHA-256 is not keyed: on Windows DPAPI's MAC also refuses a deliberately
//! altered blob, but on macOS and Linux the envelope only detects accidental
//! damage and swaps. A same-user process that can write the keychain or
//! Secret Service item can write a valid envelope; for the device key the
//! binding that matters is the edge's check that the private key matches the
//! recorded public identity (`privateKeyMatchesIdentity`). Values
//! never appear in errors, `Debug` output, logs, argv or the environment; the
//! buffers that hold them are wiped on drop where the code owns them.

use orcel_contracts::{FailureCode, RequestEnvelope};
use orcel_provider_fs::ProviderError;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};

/// Capability name of the local secret requests.
pub const CAPABILITY: &str = "secret";

/// Service attribute of keychain and Secret Service items, and the prefix
/// of the per-name DPAPI entropy.
pub const SERVICE: &str = "ai.orcel.orceld";

/// Largest secret accepted (a device key JWK is about 200 bytes).
pub const MAX_SECRET_BYTES: usize = 16 * 1024;

/// Largest legacy device key record read during migration.
const MAX_LEGACY_RECORD_BYTES: u64 = 64 * 1024;

const MAGIC: &[u8; 8] = b"ORCELSEC";
const VERSION: u8 = 1;

/// The closed set of secrets `orceld` stores. New names are added here,
/// never taken from a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretName {
    /// The SG-000053 Ed25519 device private key (JWK, base64).
    DeviceKey,
    /// WI-06 search API keys, the user's own. Read only inside `orceld` by
    /// the search adapters; `secret.get` refuses them.
    SearchBrave,
    SearchTavily,
    SearchExa,
    SearchSerper,
    /// Test builds only: a name the platform tests can write and delete
    /// without touching a developer's real device key.
    #[cfg(test)]
    Probe,
}

impl SecretName {
    pub const ALL: [SecretName; 5] = [
        SecretName::DeviceKey,
        SecretName::SearchBrave,
        SecretName::SearchTavily,
        SecretName::SearchExa,
        SecretName::SearchSerper,
    ];

    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.as_str() == name)
    }

    /// WI-06 search API keys can be stored and deleted over the request
    /// protocol but never read back out of `orceld`.
    pub fn is_write_only(self) -> bool {
        matches!(
            self,
            SecretName::SearchBrave
                | SecretName::SearchTavily
                | SecretName::SearchExa
                | SecretName::SearchSerper
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            SecretName::DeviceKey => "device.key",
            SecretName::SearchBrave => "search.brave.key",
            SecretName::SearchTavily => "search.tavily.key",
            SecretName::SearchExa => "search.exa.key",
            SecretName::SearchSerper => "search.serper.key",
            #[cfg(test)]
            SecretName::Probe => "xp19.test-probe",
        }
    }
}

/// Owned secret bytes, wiped when dropped. `Debug` shows only the length.
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes(<{} bytes redacted>)", self.0.len())
    }
}

impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(&self.0, &other.0)
    }
}

/// Overwrites `bytes` with zeros in a way the optimizer keeps.
pub fn wipe(bytes: &mut [u8]) {
    bytes.fill(0);
    std::hint::black_box(&*bytes);
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

/// Secret store failures. Messages are fixed text: they never carry a
/// value, a fragment of one, or a platform error string that could.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretError {
    /// No usable platform store (no keyring daemon or session bus, a locked
    /// keychain, DPAPI failure, no state root). Never a plaintext fallback.
    Unavailable(&'static str),
    NotFound,
    /// The stored value failed its integrity, name or owner check, or a
    /// request or legacy record was refused.
    Refused(&'static str),
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretError::Unavailable(reason) => write!(f, "secret store unavailable: {reason}"),
            SecretError::NotFound => f.write_str("secret is not stored"),
            SecretError::Refused(reason) => write!(f, "secret refused: {reason}"),
        }
    }
}

impl SecretError {
    fn into_provider(self) -> ProviderError {
        let code = match self {
            SecretError::Unavailable(_) => FailureCode::ProviderUnavailable,
            SecretError::NotFound => FailureCode::TargetStale,
            SecretError::Refused(_) => FailureCode::CapabilityDenied,
        };
        ProviderError::new(code, format!("XP-19 {self}"))
    }
}

/// One platform store. Implementations see only sealed envelopes.
pub trait SecretBackend {
    /// Stable backend name reported to callers, for example `"dpapi-file"`.
    fn kind(&self) -> &'static str;
    fn write(&self, name: SecretName, envelope: &[u8]) -> Result<(), SecretError>;
    fn read(&self, name: SecretName) -> Result<Option<SecretBytes>, SecretError>;
    /// Returns whether something was removed.
    fn remove(&self, name: SecretName) -> Result<bool, SecretError>;
}

/// The secret store for one account.
pub struct SecretStore {
    backend: Box<dyn SecretBackend>,
    owner: String,
}

impl SecretStore {
    pub fn new(backend: Box<dyn SecretBackend>, owner: String) -> Self {
        Self { backend, owner }
    }

    /// The platform store of this OS for the current account.
    pub fn open_default() -> Result<Self, SecretError> {
        let owner = current_owner()?;
        let backend = platform::open(&|name| std::env::var_os(name))?;
        Ok(Self::new(backend, owner))
    }

    pub fn backend_kind(&self) -> &'static str {
        self.backend.kind()
    }

    pub fn put(&self, name: SecretName, value: &[u8]) -> Result<(), SecretError> {
        if value.is_empty() || value.len() > MAX_SECRET_BYTES {
            return Err(SecretError::Refused("the value is empty or too large"));
        }
        let envelope = seal(name, &self.owner, value);
        self.backend.write(name, envelope.as_slice())
    }

    pub fn get(&self, name: SecretName) -> Result<SecretBytes, SecretError> {
        let envelope = self.backend.read(name)?.ok_or(SecretError::NotFound)?;
        open(name, &self.owner, envelope.as_slice())
    }

    pub fn delete(&self, name: SecretName) -> Result<bool, SecretError> {
        self.backend.remove(name)
    }
}

/// `uid:<euid>` on Unix, `sid:<user SID>` on Windows.
pub fn current_owner() -> Result<String, SecretError> {
    #[cfg(unix)]
    {
        orcel_platform::session::effective_uid()
            .map(|uid| format!("uid:{uid}"))
            .ok_or(SecretError::Unavailable("the current uid is unknown"))
    }
    #[cfg(windows)]
    {
        orcel_policy::full_control::current_windows_identity()
            .map(|identity| format!("sid:{}", identity.windows_user_sid))
            .map_err(|_| SecretError::Unavailable("the current Windows account is unknown"))
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(SecretError::Unavailable("unsupported platform"))
    }
}

/// `MAGIC | VERSION | len name | len owner | u32 len payload | SHA-256`.
/// The digest is unkeyed: it detects damage and name or account swaps, not a
/// writer who recomputes it.
pub fn seal(name: SecretName, owner: &str, value: &[u8]) -> SecretBytes {
    let name = name.as_str().as_bytes();
    let owner = owner.as_bytes();
    let mut out =
        Vec::with_capacity(8 + 1 + 1 + name.len() + 1 + owner.len() + 4 + value.len() + 32);
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.push(name.len() as u8);
    out.extend_from_slice(name);
    out.push(owner.len().min(255) as u8);
    out.extend_from_slice(&owner[..owner.len().min(255)]);
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
    let digest = Sha256::digest(&out);
    out.extend_from_slice(&digest);
    SecretBytes(out)
}

/// Verifies an envelope for `name` and `owner` and returns its payload.
pub fn open(name: SecretName, owner: &str, envelope: &[u8]) -> Result<SecretBytes, SecretError> {
    const DAMAGED: SecretError = SecretError::Refused("the stored secret is damaged or tampered");
    if envelope.len() < 8 + 1 + 1 + 1 + 4 + 32 {
        return Err(DAMAGED);
    }
    let (body, digest) = envelope.split_at(envelope.len() - 32);
    if !constant_time_eq(&Sha256::digest(body), digest) {
        return Err(DAMAGED);
    }
    let mut cursor = Cursor(body);
    if cursor.take(8)? != MAGIC || cursor.take(1)? != [VERSION] {
        return Err(DAMAGED);
    }
    let name_len = cursor.take(1)?[0] as usize;
    if cursor.take(name_len)? != name.as_str().as_bytes() {
        return Err(SecretError::Refused(
            "the stored secret belongs to another name",
        ));
    }
    let owner_len = cursor.take(1)?[0] as usize;
    let stored_owner = cursor.take(owner_len)?;
    let expected = owner.as_bytes();
    if stored_owner != &expected[..expected.len().min(255)] {
        return Err(SecretError::Refused(
            "the stored secret belongs to another account",
        ));
    }
    let mut len = [0u8; 4];
    len.copy_from_slice(cursor.take(4)?);
    let len = u32::from_be_bytes(len) as usize;
    let payload = cursor.take(len)?;
    if !cursor.0.is_empty() || payload.is_empty() || payload.len() > MAX_SECRET_BYTES {
        return Err(DAMAGED);
    }
    Ok(SecretBytes(payload.to_vec()))
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], SecretError> {
        if self.0.len() < n {
            return Err(SecretError::Refused(
                "the stored secret is damaged or tampered",
            ));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
}

/// The SG-000057 device key record `orcel remote enable` wrote before
/// XP-19: `<state root>/state/device/device_key.json`. Only this location in
/// the private per-user state root is ever migrated; copies in the old
/// shared temp directory are never read (XP-01B legacy rule).
pub fn legacy_device_key_path(
    lookup: &dyn Fn(&str) -> Option<OsString>,
) -> Result<PathBuf, SecretError> {
    orcel_platform::paths::state_root_from(lookup)
        .map(|root| root.join("state").join("device").join("device_key.json"))
        .map_err(|_| SecretError::Unavailable("the Orcel state root is unavailable"))
}

/// Outcome of [`migrate_device_key`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Migration {
    /// No record, or a record that already holds public fields only.
    NothingToMigrate,
    /// The plaintext key moved into the store and was scrubbed from disk.
    Migrated,
    /// The store already held this exact key; the plaintext was scrubbed.
    AlreadyStored,
}

impl Migration {
    fn as_str(self) -> &'static str {
        match self {
            Migration::NothingToMigrate => "nothing_to_migrate",
            Migration::Migrated => "migrated",
            Migration::AlreadyStored => "already_stored",
        }
    }
}

/// Moves a legacy plaintext device key into `store`, explicitly asked for
/// by the user (`orcel remote migrate-secrets`): read once, write to the
/// store, read it back, then overwrite the plaintext file with zeros and
/// replace it with the public fields only. Running it again is a no-op.
///
/// The record is refused (and left alone) when it is a link, not a regular
/// file, too large, or on Unix owned by another uid or readable by group or
/// other: such a key may already be exposed and should be re-enrolled.
/// Overwriting is best effort: file systems with copy-on-write, snapshots or
/// SSD remapping can keep older copies.
pub fn migrate_device_key(store: &SecretStore, record: &Path) -> Result<Migration, SecretError> {
    migrate_with(store, record, &mut |_| Ok(()))
}

/// The points of a migration after which a crash leaves state on disk.
/// Tests stop the migration at each one and check that the next run
/// recovers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MigrationStep {
    /// The key is in the store; the plaintext record is untouched.
    Stored,
    /// A public-only temp file is written and synced next to the record.
    TempWritten,
    /// The temp file replaced the record; the old file's bytes are reachable
    /// only through the handle opened before the rename.
    Renamed,
    /// The old file's bytes were overwritten with zeros and synced.
    Zeroed,
}

fn migrate_with(
    store: &SecretStore,
    record: &Path,
    step: &mut dyn FnMut(MigrationStep) -> Result<(), SecretError>,
) -> Result<Migration, SecretError> {
    let metadata = match std::fs::symlink_metadata(record) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Migration::NothingToMigrate)
        }
        Err(_) => {
            return Err(SecretError::Unavailable(
                "the device key record is unreadable",
            ))
        }
    };
    if !metadata.file_type().is_file() || metadata.len() > MAX_LEGACY_RECORD_BYTES {
        return Err(SecretError::Refused(
            "the device key record is not a small regular file",
        ));
    }
    if let Some(parent) = record.parent() {
        orcel_platform::paths::ensure_private_dir(parent)
            .map_err(|_| SecretError::Refused("the device key directory is not private"))?;
    }
    check_private_file(&metadata)?;
    let raw = SecretBytes(
        std::fs::read(record)
            .map_err(|_| SecretError::Unavailable("the device key record is unreadable"))?,
    );
    // A record that an earlier build zeroed in place and then crashed before
    // replacing: the plaintext is gone, so with the key already stored there
    // is nothing left to migrate.
    if !raw.as_slice().is_empty() && raw.as_slice().iter().all(|byte| *byte == 0) {
        return match store.get(SecretName::DeviceKey) {
            Ok(_) => Ok(Migration::AlreadyStored),
            Err(SecretError::NotFound) => Err(SecretError::Refused(
                "the device key record was destroyed and no key is stored; enroll again",
            )),
            Err(error) => Err(error),
        };
    }
    let mut fields: Map<String, Value> = serde_json::from_slice(raw.as_slice())
        .map_err(|_| SecretError::Refused("the device key record is malformed"))?;
    let private = match fields.remove("privateKeyJwkBase64") {
        None => return Ok(Migration::NothingToMigrate),
        Some(Value::String(private)) if !private.is_empty() => SecretBytes(private.into_bytes()),
        Some(_) => return Err(SecretError::Refused("the device key record is malformed")),
    };
    let device_id_ok = fields
        .get("deviceId")
        .and_then(Value::as_str)
        .is_some_and(is_device_id);
    if !device_id_ok
        || !fields
            .get("publicKeyJwkBase64")
            .is_some_and(Value::is_string)
    {
        return Err(SecretError::Refused("the device key record is malformed"));
    }
    let outcome = match store.get(SecretName::DeviceKey) {
        Ok(existing) if existing == private => Migration::AlreadyStored,
        Ok(_) => {
            return Err(SecretError::Refused(
                "the secret store already holds a different device key",
            ))
        }
        Err(SecretError::NotFound) => {
            store.put(SecretName::DeviceKey, private.as_slice())?;
            if store.get(SecretName::DeviceKey)? != private {
                return Err(SecretError::Unavailable(
                    "the secret store did not return the key it stored",
                ));
            }
            Migration::Migrated
        }
        Err(error) => return Err(error),
    };
    step(MigrationStep::Stored)?;
    let public = serde_json::to_vec(&Value::Object(fields))
        .map_err(|_| SecretError::Refused("the device key record is malformed"))?;
    replace_then_scrub(record, raw.as_slice().len(), &public, step)?;
    Ok(outcome)
}

fn is_device_id(id: &str) -> bool {
    id.len() == 36
        && id.starts_with("dev-")
        && id[4..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(unix)]
fn check_private_file(metadata: &std::fs::Metadata) -> Result<(), SecretError> {
    use std::os::unix::fs::MetadataExt;
    let euid = orcel_platform::session::effective_uid();
    if Some(metadata.uid()) != euid || metadata.mode() & 0o077 != 0 {
        return Err(SecretError::Refused(
            "the device key record is owned by another account or readable by others",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private_file(_metadata: &std::fs::Metadata) -> Result<(), SecretError> {
    Ok(())
}

/// Replaces `path` with `public` so that a crash at any point leaves either
/// the old record or the public record at `path`, never a damaged one. A
/// handle to the old file is opened first. The public record is written to
/// a synced temp file and renamed over `path` (directory synced on Unix).
/// Only then are the old file's bytes overwritten with zeros through that
/// handle. A crash before the overwrite leaves the old bytes in an unlinked
/// file that no path reaches.
fn replace_then_scrub(
    path: &Path,
    len: usize,
    public: &[u8],
    step: &mut dyn FnMut(MigrationStep) -> Result<(), SecretError>,
) -> Result<(), SecretError> {
    use std::io::Write;
    const FAILED: SecretError =
        SecretError::Unavailable("the plaintext device key could not be scrubbed");
    let mut old = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|_| FAILED)?;
    let temp = write_private_temp(path, public).map_err(|_| FAILED)?;
    step(MigrationStep::TempWritten)?;
    if std::fs::rename(&temp, path).is_err() {
        let _ = std::fs::remove_file(&temp);
        return Err(FAILED);
    }
    sync_parent(path).map_err(|_| FAILED)?;
    step(MigrationStep::Renamed)?;
    old.write_all(&vec![0u8; len]).map_err(|_| FAILED)?;
    old.sync_all().map_err(|_| FAILED)?;
    step(MigrationStep::Zeroed)?;
    Ok(())
}

/// Writes `bytes` to a fresh owner-only file next to `path` and renames it
/// over `path`.
#[cfg(windows)]
fn write_private_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let temp = write_private_temp(path, bytes)?;
    if let Err(error) = std::fs::rename(&temp, path) {
        let _ = std::fs::remove_file(&temp);
        return Err(error);
    }
    sync_parent(path)
}

/// A fresh, synced, owner-only file next to `path` holding `bytes`.
fn write_private_temp(path: &Path, bytes: &[u8]) -> std::io::Result<PathBuf> {
    use std::io::Write;
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("no parent directory"))?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or_default();
    let temp = parent.join(format!(
        ".{}.tmp-{}-{nanos}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("secret"),
        std::process::id()
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let written = options.open(&temp).and_then(|mut file| {
        file.write_all(bytes)?;
        file.sync_all()
    });
    if let Err(error) = written {
        let _ = std::fs::remove_file(&temp);
        return Err(error);
    }
    Ok(temp)
}

/// Makes a rename in `path`'s directory durable on Unix; NTFS journals the
/// rename itself.
fn sync_parent(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

pub fn is_secret_request(capability: &str) -> bool {
    capability == CAPABILITY
}

/// `secret.get|put|delete|migrate` for one fixed name in `request.target`.
pub fn dispatch(
    store: Result<SecretStore, SecretError>,
    legacy_record: Result<PathBuf, SecretError>,
    request: &RequestEnvelope,
) -> Result<Value, ProviderError> {
    let name = request
        .target
        .as_deref()
        .and_then(SecretName::parse)
        .ok_or_else(|| {
            ProviderError::new(
                FailureCode::InvalidRequest,
                "XP-19 secret requests name one fixed secret as their target",
            )
        })?;
    let operation = request.operation.as_str();
    if !matches!(operation, "get" | "put" | "delete" | "migrate") {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "XP-19 secret operations are get, put, delete and migrate",
        ));
    }
    if operation == "get" && name.is_write_only() {
        return Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "WI-06 search API keys never leave orceld; secret.get refuses them",
        ));
    }
    let store = store.map_err(SecretError::into_provider)?;
    let backend = store.backend_kind();
    match operation {
        "get" => {
            let value = match store.get(name) {
                Ok(value) => value,
                Err(SecretError::NotFound) => {
                    return Ok(json!({ "name": name.as_str(), "backend": backend, "value": null }))
                }
                Err(error) => return Err(error.into_provider()),
            };
            let text = std::str::from_utf8(value.as_slice()).map_err(|_| {
                SecretError::Refused("the stored secret is not text").into_provider()
            })?;
            Ok(json!({ "name": name.as_str(), "backend": backend, "value": text }))
        }
        "put" => {
            let value = request
                .arguments
                .get("value")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    ProviderError::new(
                        FailureCode::InvalidRequest,
                        "XP-19 secret.put needs a string value",
                    )
                })?;
            store
                .put(name, value.as_bytes())
                .map_err(SecretError::into_provider)?;
            Ok(json!({ "name": name.as_str(), "backend": backend, "stored": true }))
        }
        "delete" => {
            let deleted = store.delete(name).map_err(SecretError::into_provider)?;
            Ok(json!({ "name": name.as_str(), "backend": backend, "deleted": deleted }))
        }
        _ => {
            if name != SecretName::DeviceKey {
                return Err(ProviderError::new(
                    FailureCode::InvalidRequest,
                    "XP-19 only the device key has a legacy plaintext record",
                ));
            }
            let record = legacy_record.map_err(SecretError::into_provider)?;
            let outcome =
                migrate_device_key(&store, &record).map_err(SecretError::into_provider)?;
            Ok(json!({ "name": name.as_str(), "backend": backend, "migration": outcome.as_str() }))
        }
    }
}

/// Linux: the session bus may only be a local Unix socket. zbus also
/// honours `tcp:`, `nonce-tcp:`, `unixexec:` (spawns a program) and
/// `launchd:` addresses from the environment; none of those may carry a
/// secret. Unset means zbus's default, `$XDG_RUNTIME_DIR/bus`.
#[cfg(any(test, target_os = "linux"))]
fn session_bus_is_local(address: Option<&std::ffi::OsStr>) -> bool {
    let Some(address) = address else {
        return true;
    };
    let Some(address) = address.to_str() else {
        return false;
    };
    !address.is_empty()
        && address
            .split(';')
            .filter(|entry| !entry.is_empty())
            .all(|entry| {
                entry.strip_prefix("unix:").is_some_and(|keys| {
                    keys.split(',').all(|pair| {
                        pair.starts_with("path=")
                            || pair.starts_with("abstract=")
                            || pair.starts_with("guid=")
                    }) && (keys.contains("path=") || keys.contains("abstract="))
                })
            })
}

#[cfg(windows)]
mod platform {
    //! DPAPI, current-user scope, one blob file per name.

    use super::{SecretBackend, SecretBytes, SecretError, SecretName};
    use std::ffi::OsString;
    use std::path::PathBuf;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    pub(super) fn open(
        lookup: &dyn Fn(&str) -> Option<OsString>,
    ) -> Result<Box<dyn SecretBackend>, SecretError> {
        let dir = orcel_platform::paths::state_root_from(lookup)
            .map(|root| root.join("secrets"))
            .map_err(|_| SecretError::Unavailable("the Orcel state root is unavailable"))?;
        Ok(Box::new(DpapiFiles { dir }))
    }

    pub(crate) struct DpapiFiles {
        pub(crate) dir: PathBuf,
    }

    impl DpapiFiles {
        pub(crate) fn path(&self, name: SecretName) -> PathBuf {
            self.dir.join(format!("{}.dpapi", name.as_str()))
        }
    }

    fn entropy(name: SecretName) -> Vec<u8> {
        format!("{}/1 {}", super::SERVICE, name.as_str()).into_bytes()
    }

    /// Takes ownership of a LocalAlloc'd DPAPI output blob.
    struct Output(CRYPT_INTEGER_BLOB);

    impl Output {
        fn take(self) -> SecretBytes {
            // SAFETY: DPAPI returned `cbData` initialized bytes at `pbData`;
            // they stay valid until `Drop` frees them below.
            let bytes =
                unsafe { std::slice::from_raw_parts(self.0.pbData, self.0.cbData as usize) };
            SecretBytes::new(bytes.to_vec())
        }
    }

    impl Drop for Output {
        fn drop(&mut self) {
            if !self.0.pbData.is_null() {
                // SAFETY: the blob is owned by this value, `cbData` bytes
                // long and writable; it is wiped once and freed once.
                unsafe {
                    super::wipe(std::slice::from_raw_parts_mut(
                        self.0.pbData,
                        self.0.cbData as usize,
                    ));
                    LocalFree(self.0.pbData.cast());
                }
            }
        }
    }

    fn blob(bytes: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB {
            cbData: bytes.len() as u32,
            pbData: bytes.as_ptr().cast_mut(),
        }
    }

    pub(crate) fn protect(name: SecretName, plain: &[u8]) -> Result<SecretBytes, SecretError> {
        let entropy = entropy(name);
        let input = blob(plain);
        let extra = blob(&entropy);
        let mut out = Output(CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        });
        // SAFETY: the input and entropy blobs point at live slices DPAPI only
        // reads; `out` receives a LocalAlloc'd blob that `Output` frees.
        let ok = unsafe {
            CryptProtectData(
                &input,
                std::ptr::null(),
                &extra,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out.0,
            )
        };
        if ok == 0 {
            return Err(SecretError::Unavailable(
                "DPAPI could not protect the secret",
            ));
        }
        Ok(out.take())
    }

    pub(crate) fn unprotect(name: SecretName, sealed: &[u8]) -> Result<SecretBytes, SecretError> {
        let entropy = entropy(name);
        let input = blob(sealed);
        let extra = blob(&entropy);
        let mut out = Output(CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        });
        // SAFETY: as in `protect`; no description is requested.
        let ok = unsafe {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                &extra,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out.0,
            )
        };
        if ok == 0 {
            return Err(SecretError::Refused(
                "DPAPI refused the stored secret (tampered, moved or another account's)",
            ));
        }
        Ok(out.take())
    }

    impl SecretBackend for DpapiFiles {
        fn kind(&self) -> &'static str {
            "windows-dpapi"
        }

        fn write(&self, name: SecretName, envelope: &[u8]) -> Result<(), SecretError> {
            let sealed = protect(name, envelope)?;
            std::fs::create_dir_all(&self.dir)
                .ok()
                .and_then(|()| orcel_platform::paths::ensure_private_dir(&self.dir).ok())
                .ok_or(SecretError::Unavailable(
                    "the secrets directory is unavailable",
                ))?;
            super::write_private_atomic(&self.path(name), sealed.as_slice())
                .map_err(|_| SecretError::Unavailable("the protected secret could not be written"))
        }

        fn read(&self, name: SecretName) -> Result<Option<SecretBytes>, SecretError> {
            let sealed = match std::fs::read(self.path(name)) {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(_) => {
                    return Err(SecretError::Unavailable(
                        "the protected secret could not be read",
                    ))
                }
            };
            unprotect(name, &sealed).map(Some)
        }

        fn remove(&self, name: SecretName) -> Result<bool, SecretError> {
            let path = self.path(name);
            match std::fs::remove_file(&path) {
                Ok(()) => Ok(true),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(_) => Err(SecretError::Unavailable(
                    "the protected secret could not be removed",
                )),
            }
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod platform {
    //! Keychain (macOS) or Secret Service (Linux) through the `keyring`
    //! project's per-OS stores, one item per name under [`super::SERVICE`].

    use super::{SecretBackend, SecretBytes, SecretError, SecretName, SERVICE};
    use keyring_core::api::CredentialStoreApi;
    use keyring_core::Error as KeyringError;
    use std::ffi::OsString;
    use std::sync::Arc;

    #[cfg(target_os = "macos")]
    type PlatformStore = apple_native_keyring_store::keychain::Store;
    #[cfg(target_os = "linux")]
    type PlatformStore = zbus_secret_service_keyring_store::Store;

    #[cfg(target_os = "macos")]
    const KIND: &str = "macos-keychain";
    #[cfg(target_os = "linux")]
    const KIND: &str = "linux-secret-service";

    pub(super) fn open(
        lookup: &dyn Fn(&str) -> Option<OsString>,
    ) -> Result<Box<dyn SecretBackend>, SecretError> {
        #[cfg(target_os = "linux")]
        if !super::session_bus_is_local(lookup("DBUS_SESSION_BUS_ADDRESS").as_deref()) {
            return Err(SecretError::Unavailable(
                "the D-Bus session bus address is not a local Unix socket",
            ));
        }
        #[cfg(not(target_os = "linux"))]
        let _ = lookup;
        let store = PlatformStore::new().map_err(|_| SecretError::Unavailable(UNREACHABLE))?;
        Ok(Box::new(Keyring { store }))
    }

    #[cfg(target_os = "macos")]
    const UNREACHABLE: &str = "the macOS keychain is not reachable";
    #[cfg(target_os = "linux")]
    const UNREACHABLE: &str = "no Secret Service keyring is reachable on the D-Bus session bus";

    struct Keyring {
        store: Arc<PlatformStore>,
    }

    /// Keeps keychain services from showing any UI while it is alive, so a
    /// locked keychain or an ACL question fails instead of prompting.
    #[cfg(target_os = "macos")]
    fn quiet() -> Result<impl Sized, SecretError> {
        security_framework::os::macos::keychain::SecKeychain::disable_user_interaction()
            .map_err(|_| SecretError::Unavailable(UNREACHABLE))
    }

    /// The Secret Service shows no UI of its own to `orceld`; nothing to hold.
    #[cfg(target_os = "linux")]
    struct Quiet;

    #[cfg(target_os = "linux")]
    fn quiet() -> Result<Quiet, SecretError> {
        Ok(Quiet)
    }

    fn mapped(error: KeyringError) -> SecretError {
        match error {
            KeyringError::NoStorageAccess(_) => SecretError::Unavailable(UNREACHABLE),
            KeyringError::NoEntry => SecretError::NotFound,
            KeyringError::Ambiguous(_) => {
                SecretError::Refused("the platform store holds more than one item for this name")
            }
            _ => SecretError::Unavailable("the platform secret store failed"),
        }
    }

    impl Keyring {
        fn entry(&self, name: SecretName) -> Result<keyring_core::Entry, SecretError> {
            self.store
                .build(SERVICE, name.as_str(), None)
                .map_err(mapped)
        }
    }

    impl SecretBackend for Keyring {
        fn kind(&self) -> &'static str {
            KIND
        }

        fn write(&self, name: SecretName, envelope: &[u8]) -> Result<(), SecretError> {
            let _quiet = quiet()?;
            self.entry(name)?.set_secret(envelope).map_err(mapped)
        }

        fn read(&self, name: SecretName) -> Result<Option<SecretBytes>, SecretError> {
            let _quiet = quiet()?;
            match self.entry(name)?.get_secret() {
                Ok(bytes) => Ok(Some(SecretBytes::new(bytes))),
                Err(KeyringError::NoEntry) => Ok(None),
                Err(error) => Err(mapped(error)),
            }
        }

        fn remove(&self, name: SecretName) -> Result<bool, SecretError> {
            let _quiet = quiet()?;
            match self.entry(name)?.delete_credential() {
                Ok(()) => Ok(true),
                Err(KeyringError::NoEntry) => Ok(false),
                Err(error) => Err(mapped(error)),
            }
        }
    }
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
mod platform {
    use super::{SecretBackend, SecretError};
    use std::ffi::OsString;

    pub(super) fn open(
        _lookup: &dyn Fn(&str) -> Option<OsString>,
    ) -> Result<Box<dyn SecretBackend>, SecretError> {
        Err(SecretError::Unavailable(
            "no platform secret store on this OS",
        ))
    }
}

#[cfg(test)]
mod tests;
