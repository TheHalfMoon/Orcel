use super::*;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};

/// A value that must never show up anywhere but the store and the reply.
fn canary() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    format!("xp19-canary-{}-{nanos:x}", std::process::id())
}

fn unique_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!("orcel-xp19-{label}-{}-{nanos}", std::process::id()))
}

/// In-memory backend shared between stores, so one account's write can be
/// read back by a store bound to another account.
#[derive(Clone, Default)]
struct MemoryBackend(Rc<RefCell<HashMap<&'static str, Vec<u8>>>>);

impl SecretBackend for MemoryBackend {
    fn kind(&self) -> &'static str {
        "memory"
    }
    fn write(&self, name: SecretName, envelope: &[u8]) -> Result<(), SecretError> {
        self.0.borrow_mut().insert(name.as_str(), envelope.to_vec());
        Ok(())
    }
    fn read(&self, name: SecretName) -> Result<Option<SecretBytes>, SecretError> {
        Ok(self
            .0
            .borrow()
            .get(name.as_str())
            .map(|bytes| SecretBytes::new(bytes.clone())))
    }
    fn remove(&self, name: SecretName) -> Result<bool, SecretError> {
        Ok(self.0.borrow_mut().remove(name.as_str()).is_some())
    }
}

/// A platform with no keyring daemon, session bus or keychain.
struct AbsentBackend;

impl SecretBackend for AbsentBackend {
    fn kind(&self) -> &'static str {
        "absent"
    }
    fn write(&self, _: SecretName, _: &[u8]) -> Result<(), SecretError> {
        Err(SecretError::Unavailable("no keyring"))
    }
    fn read(&self, _: SecretName) -> Result<Option<SecretBytes>, SecretError> {
        Err(SecretError::Unavailable("no keyring"))
    }
    fn remove(&self, _: SecretName) -> Result<bool, SecretError> {
        Err(SecretError::Unavailable("no keyring"))
    }
}

fn memory_store(owner: &str) -> (SecretStore, MemoryBackend) {
    let backend = MemoryBackend::default();
    (
        SecretStore::new(Box::new(backend.clone()), owner.into()),
        backend,
    )
}

fn reseal(body: &[u8]) -> Vec<u8> {
    let mut out = body.to_vec();
    out.extend_from_slice(&Sha256::digest(body));
    out
}

fn request(operation: &str, target: &str, arguments: Value) -> RequestEnvelope {
    RequestEnvelope {
        version: orcel_contracts::INTERNAL_PROTOCOL_VERSION,
        request_id: "xp19".into(),
        client_session_id: "xp19".into(),
        workspace_id: "default".into(),
        capability: CAPABILITY.into(),
        operation: operation.into(),
        target: Some(target.into()),
        arguments,
    }
}

/// The platform tests share the one probe item of this account.
static PLATFORM_PROBE: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn probe_lock() -> std::sync::MutexGuard<'static, ()> {
    PLATFORM_PROBE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn require_platform_store() -> bool {
    std::env::var_os("ORCEL_REQUIRE_XP19_KEYRING").is_some()
}

#[test]
fn xp19_only_fixed_names_parse() {
    assert_eq!(SecretName::parse("device.key"), Some(SecretName::DeviceKey));
    for name in [
        "",
        "device",
        "device.key ",
        "../device.key",
        "xp19.test-probe",
    ] {
        assert_eq!(SecretName::parse(name), None, "{name:?}");
    }
}

#[test]
fn xp19_envelope_round_trips_and_refuses_tampering() {
    let secret = canary();
    let sealed = seal(SecretName::DeviceKey, "uid:1000", secret.as_bytes());
    let opened = open(SecretName::DeviceKey, "uid:1000", sealed.as_slice()).expect("open");
    assert_eq!(opened.as_slice(), secret.as_bytes());
    // Every single flipped byte is refused.
    for index in 0..sealed.as_slice().len() {
        let mut tampered = sealed.as_slice().to_vec();
        tampered[index] ^= 0x01;
        assert!(
            matches!(
                open(SecretName::DeviceKey, "uid:1000", &tampered),
                Err(SecretError::Refused(_))
            ),
            "byte {index}"
        );
    }
    // Truncation and trailing bytes are refused.
    let bytes = sealed.as_slice();
    assert!(open(SecretName::DeviceKey, "uid:1000", &bytes[..bytes.len() - 1]).is_err());
    let mut longer = bytes.to_vec();
    longer.push(0);
    assert!(open(SecretName::DeviceKey, "uid:1000", &longer).is_err());
    // A re-digested envelope moved to another name is still refused.
    let body = &bytes[..bytes.len() - 32];
    let probe = seal(SecretName::Probe, "uid:1000", secret.as_bytes());
    assert_eq!(
        open(SecretName::DeviceKey, "uid:1000", probe.as_slice()),
        Err(SecretError::Refused(
            "the stored secret belongs to another name"
        ))
    );
    assert!(open(SecretName::DeviceKey, "uid:1000", &reseal(body)).is_ok());
}

#[test]
fn xp19_another_account_cannot_read_the_secret() {
    // Synthetic seam: a store bound to another account wrote the value into
    // the same backend. Real cross-account separation is the platform's
    // (DPAPI user key, per-user keychain, per-user session bus).
    let (other, backend) = memory_store("uid:4242");
    other
        .put(SecretName::DeviceKey, canary().as_bytes())
        .expect("put");
    let mine = SecretStore::new(Box::new(backend), current_owner().expect("owner"));
    assert_eq!(
        mine.get(SecretName::DeviceKey),
        Err(SecretError::Refused(
            "the stored secret belongs to another account"
        ))
    );
}

#[test]
fn xp19_store_put_get_delete_and_limits() {
    let (store, _) = memory_store("uid:1000");
    let secret = canary();
    assert_eq!(store.get(SecretName::DeviceKey), Err(SecretError::NotFound));
    store
        .put(SecretName::DeviceKey, secret.as_bytes())
        .expect("put");
    assert_eq!(
        store.get(SecretName::DeviceKey).expect("get").as_slice(),
        secret.as_bytes()
    );
    assert_eq!(store.delete(SecretName::DeviceKey), Ok(true));
    assert_eq!(store.delete(SecretName::DeviceKey), Ok(false));
    assert!(store.put(SecretName::DeviceKey, b"").is_err());
    assert!(store
        .put(SecretName::DeviceKey, &vec![b'a'; MAX_SECRET_BYTES + 1])
        .is_err());
}

#[test]
fn xp19_missing_keyring_is_unavailable_never_plaintext() {
    let root = unique_dir("absent");
    std::fs::create_dir_all(&root).expect("root");
    let store = SecretStore::new(Box::new(AbsentBackend), "uid:1000".into());
    let secret = canary();
    assert!(matches!(
        store.put(SecretName::DeviceKey, secret.as_bytes()),
        Err(SecretError::Unavailable(_))
    ));
    let error = dispatch(
        Err(SecretError::Unavailable("no keyring")),
        Ok(root.join("device_key.json")),
        &request("put", "device.key", json!({ "value": secret })),
    )
    .expect_err("unavailable");
    assert_eq!(error.code, FailureCode::ProviderUnavailable);
    // Nothing was written anywhere under the state directory.
    assert_eq!(std::fs::read_dir(&root).expect("list").count(), 0);
    let _ = std::fs::remove_dir_all(root);
}

/// Linux CI runs this with `DBUS_SESSION_BUS_ADDRESS` pointing nowhere and
/// `ORCEL_XP19_EXPECT_NO_KEYRING=1`: the real store must be unavailable and
/// no file may appear in the state root.
#[test]
fn xp19_no_session_keyring_makes_the_real_store_unavailable() {
    if std::env::var_os("ORCEL_XP19_EXPECT_NO_KEYRING").is_none() {
        eprintln!("skipped: set ORCEL_XP19_EXPECT_NO_KEYRING=1 with no reachable keyring");
        return;
    }
    let opened = SecretStore::open_default();
    assert!(
        matches!(opened, Err(SecretError::Unavailable(_))),
        "the store must be unavailable without a keyring"
    );
    let lookup = |name: &str| std::env::var_os(name);
    if let Ok(root) = orcel_platform::paths::state_root_from(&lookup) {
        assert!(
            !root.join("secrets").exists(),
            "no secret files without a keyring"
        );
    }
}

#[test]
fn xp19_platform_store_round_trip() {
    let _probe = probe_lock();
    let store = match SecretStore::open_default() {
        Ok(store) => store,
        Err(error) if !require_platform_store() => {
            eprintln!("skipped: {error} (set ORCEL_REQUIRE_XP19_KEYRING=1 to require it)");
            return;
        }
        Err(error) => panic!("platform store required: {error}"),
    };
    let secret = canary();
    let _ = store.delete(SecretName::Probe);
    let put = store.put(SecretName::Probe, secret.as_bytes());
    if put.is_err() && !require_platform_store() {
        eprintln!("skipped: the platform store refused a write (locked keyring?)");
        return;
    }
    put.expect("put");
    assert_eq!(
        store.get(SecretName::Probe).expect("get").as_slice(),
        secret.as_bytes()
    );
    let replaced = canary() + "-2";
    store
        .put(SecretName::Probe, replaced.as_bytes())
        .expect("replace");
    assert_eq!(
        store.get(SecretName::Probe).expect("get").as_slice(),
        replaced.as_bytes()
    );
    assert_eq!(store.delete(SecretName::Probe), Ok(true));
    assert_eq!(store.get(SecretName::Probe), Err(SecretError::NotFound));
    assert_eq!(store.delete(SecretName::Probe), Ok(false));
}

#[cfg(windows)]
#[test]
fn xp19_windows_dpapi_blob_is_not_plaintext_and_tampering_is_refused() {
    let dir = unique_dir("dpapi");
    let backend = platform::DpapiFiles { dir: dir.clone() };
    let path = backend.path(SecretName::Probe);
    let store = SecretStore::new(Box::new(backend), current_owner().expect("owner"));
    let secret = canary();
    store
        .put(SecretName::Probe, secret.as_bytes())
        .expect("put");
    let on_disk = std::fs::read(&path).expect("blob");
    assert!(
        !on_disk
            .windows(secret.len())
            .any(|window| window == secret.as_bytes()),
        "DPAPI blob holds the plaintext"
    );
    assert_eq!(
        store.get(SecretName::Probe).expect("get").as_slice(),
        secret.as_bytes()
    );
    // A blob moved to another name fails the per-name entropy.
    let moved = platform::DpapiFiles { dir: dir.clone() }.path(SecretName::DeviceKey);
    std::fs::copy(&path, &moved).expect("copy");
    assert!(matches!(
        store.get(SecretName::DeviceKey),
        Err(SecretError::Refused(_))
    ));
    let mut tampered = on_disk.clone();
    let middle = tampered.len() / 2;
    tampered[middle] ^= 0x01;
    std::fs::write(&path, &tampered).expect("tamper");
    assert!(matches!(
        store.get(SecretName::Probe),
        Err(SecretError::Refused(_))
    ));
    assert_eq!(store.delete(SecretName::Probe), Ok(true));
    assert!(!path.exists());
    let _ = std::fs::remove_dir_all(dir);
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn xp19_tampered_platform_item_is_refused() {
    let _probe = probe_lock();
    let lookup = |name: &str| std::env::var_os(name);
    let backend = match platform::open(&lookup) {
        Ok(backend) => backend,
        Err(error) if !require_platform_store() => {
            eprintln!("skipped: {error}");
            return;
        }
        Err(error) => panic!("platform store required: {error}"),
    };
    let owner = current_owner().expect("owner");
    let sealed = seal(SecretName::Probe, &owner, canary().as_bytes());
    let mut tampered = sealed.as_slice().to_vec();
    let middle = tampered.len() / 2;
    tampered[middle] ^= 0x01;
    if backend.write(SecretName::Probe, &tampered).is_err() && !require_platform_store() {
        eprintln!("skipped: the platform store refused a write (locked keyring?)");
        return;
    }
    let reader = SecretStore::new(platform::open(&lookup).expect("reopen"), owner);
    assert!(matches!(
        reader.get(SecretName::Probe),
        Err(SecretError::Refused(_))
    ));
    assert_eq!(reader.delete(SecretName::Probe), Ok(true));
}

fn private_dir(label: &str) -> PathBuf {
    let dir = unique_dir(label).join("state").join("device");
    // Unix: ensure_private_dir creates each missing level with mode 0700.
    #[cfg(windows)]
    std::fs::create_dir_all(&dir).expect("create dir");
    orcel_platform::paths::ensure_private_dir(&dir).expect("private dir");
    dir
}

fn write_record(path: &Path, value: &Value) {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .and_then(|mut file| file.write_all(&serde_json::to_vec(value).expect("json")))
        .expect("write record");
}

fn legacy(private: &str) -> Value {
    json!({
        "deviceId": format!("dev-{}", "a".repeat(32)),
        "publicKeyJwkBase64": "cHVibGlj",
        "privateKeyJwkBase64": private,
        "createdAtMs": 1,
        "epoch": 1,
    })
}

#[test]
fn xp19_migration_is_idempotent_and_scrubs_the_plaintext() {
    let dir = private_dir("migrate");
    let record = dir.join("device_key.json");
    let (store, _) = memory_store("uid:1000");
    assert_eq!(
        migrate_device_key(&store, &record),
        Ok(Migration::NothingToMigrate)
    );

    let secret = canary();
    write_record(&record, &legacy(&secret));
    assert_eq!(migrate_device_key(&store, &record), Ok(Migration::Migrated));
    assert_eq!(
        store.get(SecretName::DeviceKey).expect("stored").as_slice(),
        secret.as_bytes()
    );
    let text = std::fs::read_to_string(&record).expect("public record");
    assert!(!text.contains(&secret), "plaintext key left on disk");
    let public: Value = serde_json::from_str(&text).expect("json");
    assert!(public.get("privateKeyJwkBase64").is_none());
    assert_eq!(public["deviceId"], legacy(&secret)["deviceId"]);
    assert_eq!(public["epoch"], 1);
    // Leftover temp files are not plaintext copies either.
    for entry in std::fs::read_dir(&dir).expect("list") {
        let bytes = std::fs::read(entry.expect("entry").path()).expect("read");
        assert!(!String::from_utf8_lossy(&bytes).contains(&secret));
    }

    // Running it again changes nothing.
    assert_eq!(
        migrate_device_key(&store, &record),
        Ok(Migration::NothingToMigrate)
    );
    assert_eq!(
        store.get(SecretName::DeviceKey).expect("stored").as_slice(),
        secret.as_bytes()
    );

    // A restored backup of the same key is scrubbed without a second write.
    write_record(&record, &legacy(&secret));
    assert_eq!(
        migrate_device_key(&store, &record),
        Ok(Migration::AlreadyStored)
    );
    assert!(!std::fs::read_to_string(&record).unwrap().contains(&secret));

    // A different plaintext key never overwrites the stored one.
    let other = canary() + "-other";
    write_record(&record, &legacy(&other));
    assert!(matches!(
        migrate_device_key(&store, &record),
        Err(SecretError::Refused(_))
    ));
    assert!(std::fs::read_to_string(&record).unwrap().contains(&other));
    assert_eq!(
        store.get(SecretName::DeviceKey).expect("stored").as_slice(),
        secret.as_bytes()
    );

    // A store that cannot write leaves the plaintext record untouched.
    let absent = SecretStore::new(Box::new(AbsentBackend), "uid:1000".into());
    assert!(matches!(
        migrate_device_key(&absent, &record),
        Err(SecretError::Unavailable(_))
    ));
    assert!(std::fs::read_to_string(&record).unwrap().contains(&other));
    let _ = std::fs::remove_dir_all(dir.parent().and_then(Path::parent).expect("root"));
}

#[test]
fn xp19_malformed_or_linked_legacy_records_are_refused() {
    let dir = private_dir("refuse");
    let record = dir.join("device_key.json");
    let (store, backend) = memory_store("uid:1000");
    std::fs::write(&record, b"{").expect("write");
    assert!(matches!(
        migrate_device_key(&store, &record),
        Err(SecretError::Refused(_))
    ));
    write_record(
        &record,
        &json!({ "deviceId": "dev-x", "privateKeyJwkBase64": "k" }),
    );
    assert!(matches!(
        migrate_device_key(&store, &record),
        Err(SecretError::Refused(_))
    ));
    std::fs::remove_file(&record).expect("remove");
    std::fs::create_dir(&record).expect("dir in its place");
    assert!(matches!(
        migrate_device_key(&store, &record),
        Err(SecretError::Refused(_))
    ));
    std::fs::remove_dir(&record).expect("remove dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let elsewhere = dir.join("elsewhere.json");
        write_record(&elsewhere, &legacy(&canary()));
        std::os::unix::fs::symlink(&elsewhere, &record).expect("symlink");
        assert!(matches!(
            migrate_device_key(&store, &record),
            Err(SecretError::Refused(_))
        ));
        std::fs::remove_file(&record).expect("unlink");
        write_record(&record, &legacy(&canary()));
        std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        assert!(matches!(
            migrate_device_key(&store, &record),
            Err(SecretError::Refused(_))
        ));
    }
    assert!(backend.0.borrow().is_empty(), "nothing was stored");
    let _ = std::fs::remove_dir_all(dir.parent().and_then(Path::parent).expect("root"));
}

#[test]
fn xp19_legacy_record_comes_only_from_the_private_state_root() {
    let root = unique_dir("root");
    let lookup = |name: &str| match name {
        "LOCALAPPDATA" | "HOME" | "XDG_STATE_HOME" => Some(root.clone().into_os_string()),
        _ => None,
    };
    let path = legacy_device_key_path(&lookup).expect("path");
    assert!(path.starts_with(&root), "{}", path.display());
    assert!(path.ends_with(Path::new("state").join("device").join("device_key.json")));
    // With no per-user root there is no fallback, least of all shared temp.
    assert!(matches!(
        legacy_device_key_path(&|_| None),
        Err(SecretError::Unavailable(_))
    ));
}

#[test]
fn xp19_dispatch_round_trip_and_request_shape() {
    let (store, backend) = memory_store("uid:1000");
    let secret = canary();
    let reply = dispatch(
        Ok(store),
        Err(SecretError::Unavailable("unused")),
        &request("put", "device.key", json!({ "value": secret })),
    )
    .expect("put");
    assert_eq!(reply["stored"], true);
    assert!(!reply.to_string().contains(&secret));
    let reopen = || SecretStore::new(Box::new(backend.clone()), "uid:1000".into());
    let legacy_unused = || Err(SecretError::Unavailable("unused"));
    let reply = dispatch(
        Ok(reopen()),
        legacy_unused(),
        &request("get", "device.key", json!({})),
    )
    .expect("get");
    assert_eq!(reply["value"], secret.as_str());
    let reply = dispatch(
        Ok(reopen()),
        legacy_unused(),
        &request("delete", "device.key", json!({})),
    )
    .expect("delete");
    assert_eq!(reply["deleted"], true);
    let reply = dispatch(
        Ok(reopen()),
        legacy_unused(),
        &request("get", "device.key", json!({})),
    )
    .expect("missing");
    assert!(reply["value"].is_null());
    for (operation, target, arguments) in [
        ("get", "other", json!({})),
        ("list", "device.key", json!({})),
        ("put", "device.key", json!({ "value": 7 })),
    ] {
        let error = dispatch(
            Ok(reopen()),
            legacy_unused(),
            &request(operation, target, arguments),
        )
        .expect_err("refused");
        assert_eq!(
            error.code,
            FailureCode::InvalidRequest,
            "{operation} {target}"
        );
    }
}

/// No secret reaches an error message, `Debug` output, the audit log, the
/// CR-01 event stream or a failure response, and this module never writes
/// to stdout, stderr or a logger outside its tests.
#[test]
fn xp19_secrets_never_reach_logs_errors_or_events() {
    let secret = canary();
    let mut seen = Vec::new();

    let wrapped = SecretBytes::new(secret.clone().into_bytes());
    seen.push(format!("{wrapped:?}"));
    let (store, backend) = memory_store("uid:4242");
    store
        .put(SecretName::DeviceKey, secret.as_bytes())
        .expect("put");
    let mine = SecretStore::new(Box::new(backend.clone()), "uid:1000".into());
    let refused = mine.get(SecretName::DeviceKey).expect_err("refused");
    seen.push(format!("{refused} {refused:?}"));
    let mut tampered = backend.0.borrow()["device.key"].clone();
    tampered[20] ^= 1;
    seen.push(format!(
        "{:?}",
        open(SecretName::DeviceKey, "uid:4242", &tampered)
    ));
    for store in [
        Err(SecretError::Unavailable("no keyring")),
        Ok(SecretStore::new(Box::new(AbsentBackend), "uid:1000".into())),
        Ok(SecretStore::new(
            Box::new(backend.clone()),
            "uid:1000".into(),
        )),
    ] {
        for operation in ["put", "get", "migrate", "bogus"] {
            let result = dispatch(
                match &store {
                    Err(error) => Err(error.clone()),
                    Ok(_) => Ok(SecretStore::new(
                        Box::new(backend.clone()),
                        "uid:1000".into(),
                    )),
                },
                Err(SecretError::Unavailable("no state root")),
                &request(operation, "device.key", json!({ "value": secret })),
            );
            if let Err(error) = result {
                seen.push(format!("{} {:?}", error.message, error.code));
            }
        }
    }

    // The real orceld entry: remote, unknown-workspace and malformed
    // requests carrying the secret are refused before any store opens.
    let root = unique_dir("audit");
    std::fs::create_dir_all(root.join("workspace")).expect("workspace");
    let workspace = orcel_policy::Workspace {
        id: "default".into(),
        root: std::fs::canonicalize(root.join("workspace")).expect("canonical"),
    };
    let policy = orcel_policy::PolicyEngine::new(vec![workspace]).expect("policy");
    let audit_path = root.join("audit.jsonl");
    let audit = orcel_audit::AuditLogger::new(audit_path.clone()).expect("audit");
    let workspaces = crate::remote_lease::WorkspaceSet::from_pairs(&[(
        "default".into(),
        root.join("workspace"),
    )]);
    let approval = orcel_approval::test_support::FixedApprovalBroker(
        orcel_approval::ApprovalDecision::Approved,
    );
    let remote = orcel_contracts::RemoteContext {
        principal: format!("rp-{}", "1".repeat(32)),
        remote_connection_id: format!("rc-{}", "2".repeat(32)),
        connection_id: "conn-xp19".into(),
        device_id: format!("dev-{}", "3".repeat(32)),
        device_epoch: 1,
        provider_kind: "generic".into(),
        client_profile_id: "profile-test".into(),
        client_profile_revision: 1,
        tool_surface_profile: "core".into(),
        scopes: vec!["orcel.read".into()],
    };
    let cases = [
        (
            request("put", "device.key", json!({ "value": secret })),
            Some(remote.clone()),
            FailureCode::CapabilityDenied,
        ),
        (
            request("get", "device.key", json!({ "value": secret })),
            Some(remote),
            FailureCode::CapabilityDenied,
        ),
        (
            RequestEnvelope {
                workspace_id: "missing".into(),
                ..request("put", "device.key", json!({ "value": secret }))
            },
            None,
            FailureCode::WorkspaceDenied,
        ),
        (
            request("bogus", "device.key", json!({ "value": secret })),
            None,
            FailureCode::InvalidRequest,
        ),
        (
            request("put", &secret, json!({ "value": secret })),
            None,
            FailureCode::InvalidRequest,
        ),
    ];
    for (request, remote, expected) in cases {
        let shape = (request.capability.clone(), request.operation.clone());
        let response = crate::handle_envelope(
            &policy,
            &audit,
            &approval,
            &workspaces,
            orcel_contracts::RemoteRequestEnvelope {
                request,
                remote,
                profile: None,
            },
        );
        assert!(!response.ok);
        assert_eq!(response.error.as_ref().expect("error").code, expected);
        seen.push(serde_json::to_string(&response).expect("response"));
        seen.push(crate::request_event(&response, Some(shape)).to_string());
    }
    let audit_text = std::fs::read_to_string(&audit_path).expect("audit log");
    assert!(audit_text.lines().count() >= 4, "{audit_text}");
    seen.push(audit_text);

    for line in &seen {
        assert!(!line.contains(&secret), "secret leaked into: {line}");
        assert!(
            !line.contains("xp19-canary"),
            "secret prefix leaked into: {line}"
        );
    }

    let source = include_str!("../secret_store.rs");
    let shipped = &source[..source.rfind("#[cfg(test)]").expect("tests marker")];
    for forbidden in [
        "println!",
        "eprintln!",
        "dbg!",
        "log::",
        "tracing::",
        "std::env::set_var",
        "Command::new",
    ] {
        assert!(
            !shipped.contains(forbidden),
            "secret_store.rs uses {forbidden}"
        );
    }
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn xp19_linux_session_bus_must_be_a_local_unix_socket() {
    use std::ffi::OsStr;
    for local in [
        None,
        Some("unix:path=/run/user/1000/bus"),
        Some("unix:abstract=/tmp/dbus-x,guid=0123456789abcdef"),
        Some("unix:path=/run/user/1000/bus;unix:abstract=/x"),
    ] {
        assert!(session_bus_is_local(local.map(OsStr::new)), "{local:?}");
    }
    for remote in [
        "",
        "tcp:host=relay.example,port=5555",
        "nonce-tcp:host=127.0.0.1,port=1",
        "unixexec:path=/bin/sh,argv1=-c",
        "launchd:env=DBUS_LAUNCHD_SESSION_BUS_SOCKET",
        "autolaunch:",
        "unix:path=/run/user/1000/bus;tcp:host=x,port=1",
        "unix:tmpdir=/tmp",
        "unix:guid=00",
    ] {
        assert!(!session_bus_is_local(Some(OsStr::new(remote))), "{remote}");
    }
}

/// Standard base64 with padding, as Node's `Buffer` writes it.
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let block = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for index in 0..4 {
            if index <= chunk.len() {
                out.push(ALPHABET[(block >> (18 - 6 * index) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A private and a public Ed25519 JWK, base64-encoded the way the edge
/// stores them, sharing the public `x`. The private `d` is a fresh canary.
fn jwk_pair(x: &str) -> (String, String) {
    let private = json!({ "kty": "OKP", "crv": "Ed25519", "x": x, "d": canary() });
    let public = json!({ "kty": "OKP", "crv": "Ed25519", "x": x });
    (
        base64_encode(&serde_json::to_vec(&private).expect("json")),
        base64_encode(&serde_json::to_vec(&public).expect("json")),
    )
}

fn legacy_pair(private: &str, public: &str) -> Value {
    let mut record = legacy(private);
    record["publicKeyJwkBase64"] = json!(public);
    record
}

fn temp_files(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .expect("list")
        .map(|entry| entry.expect("entry").path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(".device_key.json.tmp-"))
        })
        .collect()
}

#[test]
fn xp19_base64_decode_matches_node_buffer() {
    for input in [
        &b""[..],
        b"f",
        b"fo",
        b"foo",
        b"foob",
        b"fooba",
        b"foobar",
        &[0xff, 0xfe, 0x00],
    ] {
        assert_eq!(
            base64_decode(base64_encode(input).as_bytes()).as_deref(),
            Some(input)
        );
    }
    assert_eq!(base64_decode(b"Zm9v").as_deref(), Some(&b"foo"[..]));
    assert_eq!(base64_decode(b"Zg").as_deref(), Some(&b"f"[..]));
    assert_eq!(base64_decode(b"Zm9v!"), None);
    assert_eq!(base64_decode(b"Zm\n9v"), None);
}

/// A crash after each durable migration step leaves a state the next run
/// finishes: the key stays in the store, the record ends public-only, and
/// no plaintext copy or temp file is left behind.
#[test]
fn xp19_migration_recovers_from_a_crash_at_every_step() {
    for crash_at in [
        MigrationStep::Stored,
        MigrationStep::TempWritten,
        MigrationStep::Zeroed,
        MigrationStep::Renamed,
    ] {
        let dir = private_dir("crash");
        let record = dir.join("device_key.json");
        let (store, _) = memory_store("uid:1000");
        let (secret, public_key) = jwk_pair("crash-x");
        write_record(&record, &legacy_pair(&secret, &public_key));
        let crashed = migrate_with(&store, &record, &mut |step| {
            if step == crash_at {
                Err(SecretError::Unavailable("simulated crash"))
            } else {
                Ok(())
            }
        });
        assert_eq!(
            crashed,
            Err(SecretError::Unavailable("simulated crash")),
            "{crash_at:?}"
        );
        // Whatever the crash left at the record's path parses as JSON, or is
        // the zero-filled record whose public copy waits in the temp file.
        let left = std::fs::read(&record).expect("record");
        if crash_at == MigrationStep::Zeroed {
            assert!(left.iter().all(|byte| *byte == 0), "{crash_at:?}");
            assert_eq!(temp_files(&dir).len(), 1, "{crash_at:?}");
        } else {
            let left: Value = serde_json::from_slice(&left)
                .unwrap_or_else(|_| panic!("record damaged after a crash at {crash_at:?}"));
            assert!(left.get("deviceId").is_some(), "{crash_at:?}");
        }

        let rerun = migrate_device_key(&store, &record).expect("rerun recovers");
        let expected = match crash_at {
            MigrationStep::Stored | MigrationStep::TempWritten | MigrationStep::Zeroed => {
                Migration::AlreadyStored
            }
            MigrationStep::Renamed => Migration::NothingToMigrate,
        };
        assert_eq!(rerun, expected, "{crash_at:?}");
        assert_eq!(
            store.get(SecretName::DeviceKey).expect("stored").as_slice(),
            secret.as_bytes(),
            "{crash_at:?}"
        );
        for entry in std::fs::read_dir(&dir).expect("list") {
            let path = entry.expect("entry").path();
            let text = String::from_utf8_lossy(&std::fs::read(&path).expect("read")).into_owned();
            assert!(
                !text.contains(&secret),
                "{} holds the key after {crash_at:?}",
                path.display()
            );
        }
        assert!(
            temp_files(&dir).is_empty(),
            "temp files left after {crash_at:?}"
        );
        let public: Value =
            serde_json::from_str(&std::fs::read_to_string(&record).expect("public")).expect("json");
        assert!(public.get("privateKeyJwkBase64").is_none(), "{crash_at:?}");
        assert_eq!(
            public["publicKeyJwkBase64"],
            json!(public_key),
            "{crash_at:?}"
        );
        assert_eq!(
            public["deviceId"],
            legacy(&secret)["deviceId"],
            "{crash_at:?}"
        );
        assert_eq!(
            migrate_device_key(&store, &record),
            Ok(Migration::NothingToMigrate),
            "{crash_at:?}"
        );
        let _ = std::fs::remove_dir_all(dir.parent().and_then(Path::parent).expect("root"));
    }
}

/// #382 item 2: a zero-filled record is restored from the public temp file
/// the interrupted run left, and only when that file records the public half
/// of the stored key. Without one the user is told to enroll again.
#[test]
fn xp19_a_zero_filled_record_is_restored_only_from_its_own_public_record() {
    let dir = private_dir("zeroed");
    let record = dir.join("device_key.json");
    let (secret, public_key) = jwk_pair("zeroed-x");
    write_record(&record, &legacy_pair(&secret, &public_key));
    let len = std::fs::metadata(&record).expect("meta").len() as usize;
    let zero = || std::fs::write(&record, vec![0u8; len]).expect("zero");
    zero();

    // No key stored: nothing to restore.
    let (empty, _) = memory_store("uid:1000");
    assert!(matches!(
        migrate_device_key(&empty, &record),
        Err(SecretError::Refused(_))
    ));

    // Key stored but no public record left: enroll again, record untouched.
    let (store, _) = memory_store("uid:1000");
    store
        .put(SecretName::DeviceKey, secret.as_bytes())
        .expect("put");
    assert!(matches!(
        migrate_device_key(&store, &record),
        Err(SecretError::Refused(_))
    ));
    assert!(std::fs::read(&record)
        .unwrap()
        .iter()
        .all(|byte| *byte == 0));

    // A temp record for another key, or one still holding a private key, is
    // never restored.
    let (_, other_public) = jwk_pair("other-x");
    let mut public_only = legacy_pair(&secret, &public_key);
    public_only
        .as_object_mut()
        .expect("object")
        .remove("privateKeyJwkBase64");
    let mut foreign = public_only.clone();
    foreign["publicKeyJwkBase64"] = json!(other_public);
    write_record(&dir.join(".device_key.json.tmp-1-1"), &foreign);
    write_record(
        &dir.join(".device_key.json.tmp-1-2"),
        &legacy_pair(&secret, &public_key),
    );
    assert!(matches!(
        migrate_device_key(&store, &record),
        Err(SecretError::Refused(_))
    ));
    assert!(std::fs::read(&record)
        .unwrap()
        .iter()
        .all(|byte| *byte == 0));

    // A link named like a temp file is ignored.
    #[cfg(unix)]
    {
        let outside = dir.join("outside.json");
        write_record(&outside, &public_only);
        std::os::unix::fs::symlink(&outside, dir.join(".device_key.json.tmp-1-3"))
            .expect("symlink");
        assert!(matches!(
            migrate_device_key(&store, &record),
            Err(SecretError::Refused(_))
        ));
        std::fs::remove_file(dir.join(".device_key.json.tmp-1-3")).expect("unlink");
    }

    // The matching public record is restored and the other temps go.
    write_record(&dir.join(".device_key.json.tmp-1-0"), &public_only);
    assert_eq!(
        migrate_device_key(&store, &record),
        Ok(Migration::AlreadyStored)
    );
    let restored: Value =
        serde_json::from_slice(&std::fs::read(&record).expect("record")).expect("json");
    assert_eq!(restored, public_only);
    assert!(temp_files(&dir).is_empty());
    assert_eq!(
        migrate_device_key(&store, &record),
        Ok(Migration::NothingToMigrate)
    );
    let _ = std::fs::remove_dir_all(dir.parent().and_then(Path::parent).expect("root"));
}

/// #382 item 3: the plaintext bytes themselves are overwritten, so another
/// name of the same file (a hard link made before migrating) reads zeros.
#[test]
fn xp19_migration_zeroes_the_plaintext_bytes_through_every_link() {
    let dir = private_dir("hardlink");
    let record = dir.join("device_key.json");
    let (store, _) = memory_store("uid:1000");
    let (secret, public_key) = jwk_pair("link-x");
    write_record(&record, &legacy_pair(&secret, &public_key));
    let len = std::fs::metadata(&record).expect("meta").len();
    let link = dir.join("device_key.json.link");
    std::fs::hard_link(&record, &link).expect("hard link");
    assert!(std::fs::read_to_string(&link).unwrap().contains(&secret));

    assert_eq!(migrate_device_key(&store, &record), Ok(Migration::Migrated));
    let old = std::fs::read(&link).expect("link");
    assert_eq!(old.len() as u64, len);
    assert!(
        old.iter().all(|byte| *byte == 0),
        "the old bytes were not zeroed"
    );
    assert!(!std::fs::read_to_string(&record).unwrap().contains(&secret));
    let _ = std::fs::remove_dir_all(dir.parent().and_then(Path::parent).expect("root"));
}

/// #382 item 5: temp files an interrupted run left are removed by the next
/// run, while files that merely look similar stay.
#[test]
fn xp19_orphan_migration_temp_files_are_removed() {
    let dir = private_dir("orphans");
    let record = dir.join("device_key.json");
    let (store, _) = memory_store("uid:1000");
    let mut public = legacy(&canary());
    public
        .as_object_mut()
        .expect("object")
        .remove("privateKeyJwkBase64");
    write_record(&record, &public);
    let orphan = dir.join(".device_key.json.tmp-42-1");
    write_record(&orphan, &public);
    let unrelated = dir.join(".other.json.tmp-42-1");
    write_record(&unrelated, &public);
    let nested = dir.join(".device_key.json.tmp-dir");
    std::fs::create_dir(&nested).expect("dir");
    assert_eq!(
        migrate_device_key(&store, &record),
        Ok(Migration::NothingToMigrate)
    );
    assert!(!orphan.exists());
    assert!(unrelated.exists());
    assert!(nested.is_dir());
    let _ = std::fs::remove_dir_all(dir.parent().and_then(Path::parent).expect("root"));
}
