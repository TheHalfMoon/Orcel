//! SG-000026 scoped bounded browser upload tests.
//!
//! These tests live in their own module so the browser provider library keeps
//! one reviewable unit per grain, and so appending upload tests can never
//! realign the established test module in a diff. The module is a child of the
//! crate root, so it observes exactly the private provider surface the upload
//! capability uses and no more.

use super::*;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn next_temp_sequence() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    // macOS clocks tick in microseconds, so a timestamp alone can repeat
    // across parallel tests in one process.
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    SEQUENCE.fetch_add(1, Ordering::Relaxed)
}

fn temp_root(label: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let suffix = format!("{suffix}-{}", next_temp_sequence());
    let root = std::env::temp_dir().join(format!(
        "orcel-upload-{label}-{}-{suffix}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("temporary upload root");
    root
}

fn temp_upload_registry(label: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let suffix = format!("{suffix}-{}", next_temp_sequence());
    std::env::temp_dir().join(format!(
        "orcel-upload-registry-{label}-{}-{suffix}.jsonl",
        std::process::id()
    ))
}

fn upload_test_page() -> PageRecord {
    PageRecord {
        page_id: "pg-1".into(),
        workspace_id: "default".into(),
        profile_identity: "profile-a".into(),
        current_origin: "https://example.com:443".into(),
        generation: 1,
        state: PageState::Active,
        policy_revision: "sg-000026-v1".into(),
    }
}

fn upload_test_node(page: &PageRecord) -> StoredNode {
    let profile_identity = "profile-a";
    let policy_revision = "sg-000026-v1";
    let node_id = node_id_for(
        profile_identity,
        &page.page_id,
        page.generation,
        &page.current_origin,
        page.generation,
        0,
        policy_revision,
    );
    StoredNode {
        schema: NODE_REGISTRY_SCHEMA.to_owned(),
        node_id,
        page_id: page.page_id.clone(),
        workspace_id: page.workspace_id.clone(),
        profile_identity: profile_identity.to_owned(),
        origin: page.current_origin.clone(),
        page_generation: page.generation,
        document_generation: page.generation,
        index: 0,
        role: UPLOAD_NODE_ROLE.to_owned(),
        input_type: UPLOAD_INPUT_TYPE.to_owned(),
        state: ENABLED_NODE_STATE.to_owned(),
        policy_revision: policy_revision.to_owned(),
    }
}

fn upload_test_record(
    page: &PageRecord,
    node: &StoredNode,
    artifact_source_id: &str,
    sha256: &str,
    size: u64,
) -> StoredUpload {
    StoredUpload {
        schema: UPLOAD_REGISTRY_SCHEMA.into(),
        source_id: String::new(),
        workspace_id: page.workspace_id.clone(),
        policy_revision: page.policy_revision.clone(),
        profile_identity: page.profile_identity.clone(),
        page_id: page.page_id.clone(),
        origin: page.current_origin.clone(),
        page_generation: page.generation,
        document_generation: page.generation,
        node_id: node.node_id.clone(),
        node_role: node.role.clone(),
        node_input_type: node.input_type.clone(),
        node_state: node.state.clone(),
        trust_revision: 1,
        artifact_source_id: artifact_source_id.to_owned(),
        artifact_download_id: "dn-seed".into(),
        artifact_relative_destination: "artifact.txt".into(),
        artifact_media_type: "text/plain".into(),
        artifact_sha256: sha256.to_owned(),
        artifact_size_bytes: size,
        upload_policy_revision: UPLOAD_POLICY_REVISION.into(),
        issued_at_ms: 1_000,
        expires_at_ms: 1_000 + UPLOAD_SOURCE_TTL_MS,
        state: UPLOAD_SOURCE_PENDING.into(),
        upload_id: String::new(),
    }
}

fn seal_upload_record(mut record: StoredUpload) -> StoredUpload {
    record.source_id = upload_source_id_for(
        &record.workspace_id,
        &record.policy_revision,
        &record.profile_identity,
        &record.page_id,
        &record.origin,
        record.page_generation,
        record.document_generation,
        &record.node_id,
        &record.node_role,
        &record.node_input_type,
        &record.node_state,
        record.trust_revision,
        &record.artifact_source_id,
        &record.artifact_relative_destination,
        &record.artifact_media_type,
        &record.artifact_sha256,
        record.artifact_size_bytes,
        &record.upload_policy_revision,
        record.issued_at_ms,
    );
    record
}

/// Materialize one recorded approved download artifact: the real file plus
/// the SG-000025 registry record that makes it admissible as an upload
/// source.
fn seed_download_artifact(root: &Path, profile_root: &Path, body: &[u8]) -> String {
    std::fs::write(root.join("artifact.txt"), body).expect("artifact");
    let digest = sha256_hex(body);
    let relative = "artifact.txt";
    let source_id = download_source_id_for(
        "default",
        "sg-000025-v1",
        "profile-a",
        "pg-1",
        "https://example.com:443",
        1,
        1,
        "https://example.com:443",
        "digest",
        relative,
        "text/plain",
        body.len() as u64,
        DOWNLOAD_POLICY_REVISION,
        1_000,
    );
    let mut store = DownloadStore::load_or_create(default_download_registry_path(profile_root));
    store.record_pending(StoredDownload {
        schema: DOWNLOAD_REGISTRY_SCHEMA.into(),
        source_id: source_id.clone(),
        workspace_id: "default".into(),
        policy_revision: "sg-000025-v1".into(),
        profile_identity: "profile-a".into(),
        page_id: "pg-1".into(),
        origin: "https://example.com:443".into(),
        page_generation: 1,
        document_generation: 1,
        source_origin: "https://example.com:443".into(),
        source_url_digest: "digest".into(),
        canonical_relative_destination: relative.into(),
        declared_filename: "artifact.txt".into(),
        declared_media_type: "text/plain".into(),
        declared_size_bytes: body.len() as u64,
        download_policy_revision: DOWNLOAD_POLICY_REVISION.into(),
        issued_at_ms: 1_000,
        expires_at_ms: 1_000 + DOWNLOAD_SOURCE_TTL_MS,
        state: DOWNLOAD_SOURCE_CONSUMED.into(),
        download_id: "dn-seed".into(),
        content_sha256: digest,
    });
    source_id
}

#[test]
fn upload_source_identity_is_one_shot_expiring_and_drift_checked() {
    let root = temp_root("upload-identity");
    let profile_root = temp_root("upload-identity-profile");
    let page = upload_test_page();
    let node = upload_test_node(&page);
    let artifact = seed_download_artifact(&root, &profile_root, b"hello");
    let record = seal_upload_record(upload_test_record(
        &page,
        &node,
        &artifact,
        &sha256_hex(b"hello"),
        5,
    ));
    assert!(record.source_id.starts_with(UPLOAD_SOURCE_PREFIX));
    assert!(is_well_formed_upload_source_id(&record.source_id));
    for malformed in [
        "",
        "ul-",
        "ul-zz",
        "ul-zz/../x",
        "not-a-source",
        "not-an-upload-source-at-all",
    ] {
        assert!(
            !is_well_formed_upload_source_id(malformed),
            "{malformed:?} must not be accepted as an upload source identity"
        );
    }
    for malformed in [
        "",
        "dl-",
        "dl-zz",
        "not-a-source",
        "../../id_rsa",
        "dl-zz/../artifact.txt",
    ] {
        assert!(
            !is_well_formed_download_source_id(malformed),
            "{malformed:?} must not be accepted as a download source identity"
        );
    }
    let verified = check_upload_source(
        &record,
        &page,
        &node,
        "profile-a",
        "sg-000026-v1",
        1,
        1,
        UPLOAD_NODE_ROLE,
        UPLOAD_INPUT_TYPE,
        ENABLED_NODE_STATE,
        1,
        true,
        &root,
        2_000,
    )
    .expect("a fresh one-shot upload source is usable");
    assert_eq!(verified.sha256, sha256_hex(b"hello"));
    assert_eq!(verified.size_bytes, 5);
    assert_eq!(verified.media_type, "text/plain");

    let expired = check_upload_source(
        &record,
        &page,
        &node,
        "profile-a",
        "sg-000026-v1",
        1,
        1,
        UPLOAD_NODE_ROLE,
        UPLOAD_INPUT_TYPE,
        ENABLED_NODE_STATE,
        1,
        true,
        &root,
        record.expires_at_ms + 1,
    )
    .expect_err("an expired upload source must fail closed");
    assert_eq!(expired.code, FailureCode::TargetStale);

    let mut consumed = record.clone();
    consumed.state = UPLOAD_SOURCE_CONSUMED.into();
    let replayed = check_upload_source(
        &consumed,
        &page,
        &node,
        "profile-a",
        "sg-000026-v1",
        1,
        1,
        UPLOAD_NODE_ROLE,
        UPLOAD_INPUT_TYPE,
        ENABLED_NODE_STATE,
        1,
        true,
        &root,
        2_000,
    )
    .expect_err("a consumed upload source must fail closed");
    assert_eq!(replayed.code, FailureCode::CapabilityDenied);

    let mut forged = record.clone();
    forged.artifact_relative_destination = "other.txt".into();
    assert_eq!(
        check_upload_source(
            &forged,
            &page,
            &node,
            "profile-a",
            "sg-000026-v1",
            1,
            1,
            UPLOAD_NODE_ROLE,
            UPLOAD_INPUT_TYPE,
            ENABLED_NODE_STATE,
            1,
            true,
            &root,
            2_000
        )
        .unwrap_err()
        .code,
        FailureCode::TargetStale
    );

    let mut drifted_upload_policy = record.clone();
    drifted_upload_policy.upload_policy_revision = "sg-000025-upload-v1".into();
    assert_eq!(
        check_upload_source(
            &drifted_upload_policy,
            &page,
            &node,
            "profile-a",
            "sg-000026-v1",
            1,
            1,
            UPLOAD_NODE_ROLE,
            UPLOAD_INPUT_TYPE,
            ENABLED_NODE_STATE,
            1,
            true,
            &root,
            2_000
        )
        .unwrap_err()
        .code,
        FailureCode::TargetStale
    );
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(profile_root);
}

#[test]
fn upload_trust_revoke_and_trust_drift_fail_closed() {
    let root = temp_root("upload-trust");
    let profile_root = temp_root("upload-trust-profile");
    let page = upload_test_page();
    let node = upload_test_node(&page);
    let artifact = seed_download_artifact(&root, &profile_root, b"hello");
    let record = seal_upload_record(upload_test_record(
        &page,
        &node,
        &artifact,
        &sha256_hex(b"hello"),
        5,
    ));
    let revoked = check_upload_source(
        &record,
        &page,
        &node,
        "profile-a",
        "sg-000026-v1",
        1,
        1,
        UPLOAD_NODE_ROLE,
        UPLOAD_INPUT_TYPE,
        ENABLED_NODE_STATE,
        1,
        false,
        &root,
        2_000,
    )
    .expect_err("an emergency revoke must fail closed");
    assert_eq!(revoked.code, FailureCode::WorkspaceDenied);
    let drifted = check_upload_source(
        &record,
        &page,
        &node,
        "profile-a",
        "sg-000026-v1",
        1,
        1,
        UPLOAD_NODE_ROLE,
        UPLOAD_INPUT_TYPE,
        ENABLED_NODE_STATE,
        2,
        true,
        &root,
        2_000,
    )
    .expect_err("a trust revision change must fail closed");
    assert_eq!(drifted.code, FailureCode::TargetStale);
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(profile_root);
}

#[test]
fn upload_node_gating_denies_wrong_role_input_type_and_disabled_state() {
    let page = upload_test_page();
    let node = upload_test_node(&page);
    check_node_for_upload(
        &node,
        &page,
        UPLOAD_NODE_ROLE,
        UPLOAD_INPUT_TYPE,
        ENABLED_NODE_STATE,
        "profile-a",
        "sg-000026-v1",
        1,
        1,
    )
    .expect("an enabled textbox file input accepts an upload");

    let wrong_role = check_node_for_upload(
        &node,
        &page,
        "link",
        UPLOAD_INPUT_TYPE,
        ENABLED_NODE_STATE,
        "profile-a",
        "sg-000026-v1",
        1,
        1,
    )
    .expect_err("a non-textbox role must be denied");
    assert_eq!(wrong_role.code, FailureCode::CapabilityDenied);

    let wrong_input_type = check_node_for_upload(
        &node,
        &page,
        UPLOAD_NODE_ROLE,
        "password",
        ENABLED_NODE_STATE,
        "profile-a",
        "sg-000026-v1",
        1,
        1,
    )
    .expect_err("a non-file input type must be denied");
    assert_eq!(wrong_input_type.code, FailureCode::CapabilityDenied);

    let wrong_state = check_node_for_upload(
        &node,
        &page,
        UPLOAD_NODE_ROLE,
        UPLOAD_INPUT_TYPE,
        "disabled",
        "profile-a",
        "sg-000026-v1",
        1,
        1,
    )
    .expect_err("a disabled node must be denied");
    assert_eq!(wrong_state.code, FailureCode::TargetStale);

    let mut disabled = node.clone();
    disabled.state = "disabled".into();
    let denied = check_node_for_upload(
        &disabled,
        &page,
        UPLOAD_NODE_ROLE,
        UPLOAD_INPUT_TYPE,
        ENABLED_NODE_STATE,
        "profile-a",
        "sg-000026-v1",
        1,
        1,
    )
    .expect_err("a disabled node must fail closed");
    assert_eq!(denied.code, FailureCode::CapabilityDenied);

    let stale = check_node_for_upload(
        &node,
        &page,
        UPLOAD_NODE_ROLE,
        UPLOAD_INPUT_TYPE,
        ENABLED_NODE_STATE,
        "profile-a",
        "sg-000026-v1",
        2,
        1,
    )
    .expect_err("a stale generation must fail closed");
    assert_eq!(stale.code, FailureCode::TargetStale);

    let mut replaced = node.clone();
    replaced.index = 9;
    let replaced_node = check_node_for_upload(
        &replaced,
        &page,
        UPLOAD_NODE_ROLE,
        UPLOAD_INPUT_TYPE,
        ENABLED_NODE_STATE,
        "profile-a",
        "sg-000026-v1",
        1,
        1,
    )
    .expect_err("a replaced file input must fail closed");
    assert_eq!(replaced_node.code, FailureCode::TargetStale);

    let mut other_page = page.clone();
    other_page.page_id = "pg-2".into();
    let wrong_page = check_node_for_upload(
        &node,
        &other_page,
        UPLOAD_NODE_ROLE,
        UPLOAD_INPUT_TYPE,
        ENABLED_NODE_STATE,
        "profile-a",
        "sg-000026-v1",
        1,
        1,
    )
    .expect_err("a node from another page must fail closed");
    assert_eq!(wrong_page.code, FailureCode::TargetStale);

    let mut password = node.clone();
    password.input_type = "password".into();
    let credential = check_node_for_upload(
        &password,
        &page,
        UPLOAD_NODE_ROLE,
        "password",
        ENABLED_NODE_STATE,
        "profile-a",
        "sg-000026-v1",
        1,
        1,
    )
    .expect_err("a password target must fail closed");
    assert_eq!(credential.code, FailureCode::CapabilityDenied);
}

#[test]
fn upload_artifact_verification_denies_missing_directory_mutated_and_reparse_escape() {
    let root = temp_root("upload-artifact");
    let profile_root = temp_root("upload-artifact-profile");
    let page = upload_test_page();
    let node = upload_test_node(&page);
    let artifact = seed_download_artifact(&root, &profile_root, b"hello");
    let record = seal_upload_record(upload_test_record(
        &page,
        &node,
        &artifact,
        &sha256_hex(b"hello"),
        5,
    ));
    verify_upload_artifact(&root, &record, 2_000).expect("the recorded artifact is admissible");

    // A replaced artifact fails closed on digest.
    std::fs::write(root.join("artifact.txt"), b"mutated").expect("mutate");
    let mutated = verify_upload_artifact(&root, &record, 2_000)
        .expect_err("a mutated artifact must fail closed");
    assert_eq!(mutated.code, FailureCode::PostconditionFailed);

    // A removed artifact fails closed.
    std::fs::remove_file(root.join("artifact.txt")).expect("remove");
    let missing = verify_upload_artifact(&root, &record, 2_000)
        .expect_err("a removed artifact must fail closed");
    assert_eq!(missing.code, FailureCode::TargetStale);

    // A directory at the recorded destination is never uploadable.
    std::fs::create_dir_all(root.join("artifact.txt")).expect("directory");
    let directory =
        verify_upload_artifact(&root, &record, 2_000).expect_err("a directory must fail closed");
    assert_eq!(directory.code, FailureCode::CapabilityDenied);
    let _ = std::fs::remove_dir_all(root.join("artifact.txt"));

    // An empty artifact and an oversize artifact are both denied.
    let mut empty = record.clone();
    empty.artifact_size_bytes = 0;
    assert_eq!(
        verify_upload_artifact(&root, &empty, 2_000)
            .unwrap_err()
            .code,
        FailureCode::OutputLimit
    );
    let mut oversize = record.clone();
    oversize.artifact_size_bytes = MAX_UPLOAD_BYTES + 1;
    assert_eq!(
        verify_upload_artifact(&root, &oversize, 2_000)
            .unwrap_err()
            .code,
        FailureCode::OutputLimit
    );

    // A destination that escapes the download root through a reparse
    // point is denied.
    let mut escaping = record.clone();
    escaping.artifact_relative_destination = "escape/artifact.txt".into();
    let outside = temp_root("upload-artifact-outside");
    let link = root.join("escape");
    #[cfg(windows)]
    {
        let output = std::process::Command::new("cmd")
            .args([
                "/c",
                "mklink",
                "/J",
                &link.to_string_lossy(),
                &outside.to_string_lossy(),
            ])
            .output()
            .expect("mklink runs");
        assert!(
            output.status.success(),
            "junction creation must succeed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, &link).expect("symlink");
    assert!(link.is_dir());
    let reparse = verify_upload_artifact(&root, &escaping, 2_000)
        .expect_err("a reparse-point redirect must fail closed");
    assert_eq!(reparse.code, FailureCode::PathEscape);

    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(profile_root);
    let _ = std::fs::remove_dir_all(outside);
}

#[test]
fn upload_registry_is_append_only_one_shot_and_bounded() {
    let path = temp_upload_registry("store");
    let page = upload_test_page();
    let node = upload_test_node(&page);
    let mut store = UploadStore::load_or_create(path.clone());
    assert!(store.get("ul-missing").is_none());
    assert_eq!(
        store.mark_consumed("ul-missing", "up-1").unwrap_err().code,
        FailureCode::TargetStale
    );
    for index in 0..MAX_PENDING_UPLOADS_PER_WORKSPACE as u64 {
        let mut record = upload_test_record(&page, &node, "dl-seed", &sha256_hex(b"hello"), 5);
        record.issued_at_ms = 1_000 + index;
        record.expires_at_ms = 1_000 + index + UPLOAD_SOURCE_TTL_MS;
        store.record_pending(seal_upload_record(record));
    }
    assert_eq!(
        store.pending_count("default"),
        MAX_PENDING_UPLOADS_PER_WORKSPACE
    );
    assert_eq!(
        UploadStore::load_or_create(path.clone()).pending_count("default"),
        MAX_PENDING_UPLOADS_PER_WORKSPACE
    );
    let source_id = seal_upload_record(upload_test_record(
        &page,
        &node,
        "dl-seed",
        &sha256_hex(b"hello"),
        5,
    ))
    .source_id;
    store.mark_consumed(&source_id, "up-test").expect("consume");
    assert_eq!(
        store.pending_count("default"),
        MAX_PENDING_UPLOADS_PER_WORKSPACE - 1
    );
    assert_eq!(
        UploadStore::load_or_create(path.clone())
            .get(&source_id)
            .expect("source")
            .state,
        UPLOAD_SOURCE_CONSUMED
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn upload_evidence_and_preview_are_bounded_and_secret_free() {
    let evidence = UploadEvidence {
        upload_id: "up-1".into(),
        source_id: "ul-1".into(),
        page_id: "pg-1".into(),
        workspace_id: "default".into(),
        policy_revision: "sg-000026-v1".into(),
        profile_identity: "profile-a".into(),
        origin: "https://example.com:443".into(),
        page_generation: 1,
        document_generation: 1,
        node_id: "nd-1".into(),
        node_role: UPLOAD_NODE_ROLE.into(),
        node_input_type: UPLOAD_INPUT_TYPE.into(),
        node_state: ENABLED_NODE_STATE.into(),
        trust_revision: 1,
        artifact_source_id: "dl-1".into(),
        artifact_download_id: "dn-1".into(),
        artifact_relative_destination: "artifact.txt".into(),
        artifact_media_type: "text/plain".into(),
        artifact_sha256: "artifact-digest".into(),
        artifact_size_bytes: 5,
        upload_policy_revision: UPLOAD_POLICY_REVISION.into(),
        state: UPLOAD_SOURCE_CONSUMED.into(),
    };
    let json = evidence.to_json("apr-1");
    assert_eq!(json["approval_record_id"], "apr-1");
    assert_eq!(json["page_transfer_performed"], false);
    assert_eq!(json["executed"], false);
    assert_eq!(json["opened"], false);
    assert_eq!(json["extracted"], false);
    assert_eq!(json["cookies"], false);
    assert_eq!(json["credentials"], false);
    for forbidden in [
        "content",
        "content_base64",
        "bytes",
        "data",
        "cookie",
        "password",
        "token",
        "authorization",
        "session",
        "path",
        "absolute_path",
        "source_path",
        "file_path",
    ] {
        assert!(
            json.get(forbidden).is_none(),
            "upload evidence must not carry {forbidden}"
        );
    }

    let base = upload_approval_digest(
        "default",
        "sg-000026-v1",
        "profile-a",
        "pg-1",
        "https://example.com:443",
        1,
        1,
        "nd-1",
        UPLOAD_NODE_ROLE,
        UPLOAD_INPUT_TYPE,
        ENABLED_NODE_STATE,
        1,
        "ul-1",
        "artifact.txt",
        "text/plain",
        "artifact-digest",
        5,
    );
    for drifted in [
        upload_approval_digest(
            "default",
            "sg-000026-v1",
            "profile-a",
            "pg-1",
            "https://example.com:443",
            1,
            1,
            "nd-1",
            UPLOAD_NODE_ROLE,
            UPLOAD_INPUT_TYPE,
            ENABLED_NODE_STATE,
            1,
            "ul-2",
            "artifact.txt",
            "text/plain",
            "artifact-digest",
            5,
        ),
        upload_approval_digest(
            "default",
            "sg-000026-v1",
            "profile-a",
            "pg-1",
            "https://example.com:443",
            1,
            1,
            "nd-2",
            UPLOAD_NODE_ROLE,
            UPLOAD_INPUT_TYPE,
            ENABLED_NODE_STATE,
            1,
            "ul-1",
            "artifact.txt",
            "text/plain",
            "artifact-digest",
            5,
        ),
        upload_approval_digest(
            "default",
            "sg-000026-v1",
            "profile-a",
            "pg-1",
            "https://example.com:443",
            1,
            1,
            "nd-1",
            UPLOAD_NODE_ROLE,
            UPLOAD_INPUT_TYPE,
            ENABLED_NODE_STATE,
            2,
            "ul-1",
            "artifact.txt",
            "text/plain",
            "artifact-digest",
            5,
        ),
        upload_approval_digest(
            "default",
            "sg-000026-v1",
            "profile-a",
            "pg-1",
            "https://example.com:443",
            1,
            1,
            "nd-1",
            UPLOAD_NODE_ROLE,
            UPLOAD_INPUT_TYPE,
            ENABLED_NODE_STATE,
            1,
            "ul-1",
            "other.txt",
            "text/plain",
            "artifact-digest",
            5,
        ),
        upload_approval_digest(
            "default",
            "sg-000026-v1",
            "profile-a",
            "pg-1",
            "https://example.com:443",
            1,
            1,
            "nd-1",
            UPLOAD_NODE_ROLE,
            UPLOAD_INPUT_TYPE,
            ENABLED_NODE_STATE,
            1,
            "ul-1",
            "artifact.txt",
            "text/plain",
            "other-digest",
            5,
        ),
        upload_approval_digest(
            "default",
            "sg-000026-v1",
            "profile-a",
            "pg-1",
            "https://other.example:443",
            1,
            1,
            "nd-1",
            UPLOAD_NODE_ROLE,
            UPLOAD_INPUT_TYPE,
            ENABLED_NODE_STATE,
            1,
            "ul-1",
            "artifact.txt",
            "text/plain",
            "artifact-digest",
            5,
        ),
    ] {
        assert_ne!(base, drifted);
    }
    assert!(upload_id_for("ul-1", "nd-1", "artifact-digest").starts_with(UPLOAD_ID_PREFIX));
    assert_ne!(
        upload_id_for("ul-1", "nd-1", "artifact-digest"),
        upload_id_for("ul-1", "nd-1", "other-digest")
    );
}
