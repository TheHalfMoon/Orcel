//! WI-05 orceld wiring: what is checked before an approval is asked for,
//! what the approval binds, and (end to end, with the real helper and
//! parser) what comes back.

use super::*;
use orcel_approval::test_support::FixedApprovalBroker;
use orcel_approval::{ApprovalDecision, ApprovalError, ApprovedToken};
use std::sync::atomic::{AtomicBool, Ordering};

fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "orceld-wi05-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::canonicalize(dir).unwrap()
}

fn workspace(root: &Path) -> Workspace {
    Workspace {
        id: "default".into(),
        root: root.to_path_buf(),
    }
}

/// Fails the request, and remembers that it was asked.
#[derive(Default)]
struct RecordingBroker {
    asked: AtomicBool,
}

impl ApprovalBroker for RecordingBroker {
    fn request_token(&self, _prompt: &ApprovalPrompt) -> Result<ApprovedToken, ApprovalError> {
        self.asked.store(true, Ordering::SeqCst);
        Err(ApprovalError {
            code: FailureCode::ApprovalUnavailable,
            message: "recording broker".into(),
        })
    }

    fn consume(
        &self,
        _token: &ApprovedToken,
        _expected: &ConsumeExpectation,
        _now_ms: u64,
    ) -> Result<(), ApprovalError> {
        Err(ApprovalError {
            code: FailureCode::ApprovalUnavailable,
            message: "recording broker".into(),
        })
    }
}

const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn dummy_pins(dir: &Path) -> (HelperPin, ParserPin) {
    (
        HelperPin::new(dir.join("orcel-contain"), DIGEST).unwrap(),
        ParserPin::for_test(dir.join(PARSER_NAME), DIGEST.into()),
    )
}

/// A committed download of `bytes` at `folder/relative`.
fn committed(folder: &Path, relative: &str, bytes: &[u8]) -> CommittedDownload {
    let path = folder.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, bytes).unwrap();
    CommittedDownload::new(
        "record-1",
        folder,
        relative,
        sha256_hex(bytes),
        bytes.len() as u64,
        "https://example.test/report.pdf",
    )
}

#[test]
fn wi05_a_missing_parser_or_pin_is_unavailable() {
    let dir = temp_dir("no-parser");
    let error = parser_pin_in(&dir).unwrap_err();
    assert_eq!(error.code, FailureCode::ProviderUnavailable);
    assert!(error.message.contains(PARSER_PIN_NAME), "{}", error.message);
    std::fs::write(dir.join(PARSER_PIN_NAME), format!("{DIGEST}\n")).unwrap();
    let error = parser_pin_in(&dir).unwrap_err();
    assert_eq!(error.code, FailureCode::ProviderUnavailable);
    assert!(error.message.contains(PARSER_NAME), "{}", error.message);
    std::fs::write(dir.join(PARSER_PIN_NAME), "not a digest\n").unwrap();
    std::fs::write(dir.join(PARSER_NAME), b"parser").unwrap();
    assert_eq!(
        parser_pin_in(&dir).unwrap_err().code,
        FailureCode::ProviderUnavailable
    );
    std::fs::write(dir.join(PARSER_PIN_NAME), format!("{DIGEST}\n")).unwrap();
    let pin = parser_pin_in(&dir).expect("a pinned parser");
    assert_eq!(pin.sha256, DIGEST);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn wi05_a_changed_or_moved_download_is_refused_before_any_approval() {
    let dir = temp_dir("stale");
    let (helper, parser) = dummy_pins(&dir);
    let broker = RecordingBroker::default();
    let mut download = committed(&dir, "report.pdf", b"%PDF-1.7 committed");

    std::fs::write(dir.join("report.pdf"), b"%PDF-1.7 replaced!").unwrap();
    let error =
        parse_committed(&workspace(&dir), &broker, &download, &helper, &parser).unwrap_err();
    assert_eq!(error.code, FailureCode::TargetStale, "{}", error.message);

    std::fs::write(dir.join("report.pdf"), b"%PDF-1.7 committed, then grown").unwrap();
    let error =
        parse_committed(&workspace(&dir), &broker, &download, &helper, &parser).unwrap_err();
    assert_eq!(error.code, FailureCode::TargetStale, "{}", error.message);

    std::fs::remove_file(dir.join("report.pdf")).unwrap();
    let error =
        parse_committed(&workspace(&dir), &broker, &download, &helper, &parser).unwrap_err();
    assert_eq!(error.code, FailureCode::TargetStale, "{}", error.message);

    download.relative = "../report.pdf".into();
    let error =
        parse_committed(&workspace(&dir), &broker, &download, &helper, &parser).unwrap_err();
    assert_eq!(error.code, FailureCode::PathEscape, "{}", error.message);

    download.relative = "report.pdf".into();
    download.bytes = MAX_INPUT_BYTES + 1;
    let error =
        parse_committed(&workspace(&dir), &broker, &download, &helper, &parser).unwrap_err();
    assert!(
        error
            .message
            .starts_with("document_parse_refused:input_too_large"),
        "{}",
        error.message
    );

    assert!(
        !broker.asked.load(Ordering::SeqCst),
        "an approval was asked for"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[cfg(unix)]
#[test]
fn wi05_a_download_reached_through_a_link_is_refused_before_any_approval() {
    let dir = temp_dir("link");
    let (helper, parser) = dummy_pins(&dir);
    let broker = RecordingBroker::default();
    let real = dir.join("real");
    let download = committed(&real, "report.pdf", b"%PDF-1.7 committed");
    std::os::unix::fs::symlink(&real, dir.join("linked")).unwrap();
    let mut linked = download.clone();
    linked.folder = dir.clone();
    linked.relative = "linked/report.pdf".into();
    let error = parse_committed(&workspace(&dir), &broker, &linked, &helper, &parser).unwrap_err();
    assert_eq!(error.code, FailureCode::PathEscape, "{}", error.message);
    assert!(!broker.asked.load(Ordering::SeqCst));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn wi05_a_denied_approval_launches_nothing() {
    let dir = temp_dir("denied");
    let (helper, parser) = dummy_pins(&dir);
    let download = committed(&dir, "report.pdf", b"%PDF-1.7 committed");
    let broker = FixedApprovalBroker(ApprovalDecision::Denied);
    let error =
        parse_committed(&workspace(&dir), &broker, &download, &helper, &parser).unwrap_err();
    assert_eq!(error.code, FailureCode::ApprovalDenied, "{}", error.message);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn wi05_the_approval_digest_binds_the_file_the_record_and_the_parser() {
    let dir = temp_dir("digest");
    let (_, parser) = dummy_pins(&dir);
    let download = committed(&dir, "report.pdf", b"%PDF-1.7 committed");
    let base = approval_digest(&workspace(&dir), &download, &parser);
    assert_eq!(base, approval_digest(&workspace(&dir), &download, &parser));
    let mut other_parser = parser.clone();
    other_parser.sha256 = "f".repeat(64);
    let mut other_file = download.clone();
    other_file.sha256 = "e".repeat(64);
    let mut other_record = download.clone();
    other_record.record_id = "record-2".into();
    let mut other_workspace = workspace(&dir);
    other_workspace.id = "other".into();
    for digest in [
        approval_digest(&workspace(&dir), &download, &other_parser),
        approval_digest(&workspace(&dir), &other_file, &parser),
        approval_digest(&workspace(&dir), &other_record, &parser),
        approval_digest(&other_workspace, &download, &parser),
    ] {
        assert_ne!(digest, base);
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn wi05_every_refusal_is_a_typed_invalid_request() {
    for refusal in ParseRefusal::ALL {
        let error = refusal_error(refusal);
        assert_eq!(error.code, FailureCode::InvalidRequest);
        assert!(
            error
                .message
                .starts_with(&format!("document_parse_refused:{}:", refusal.as_str())),
            "{}",
            error.message
        );
    }
}

/// One page drawing `text` in Helvetica (the parser workspace's fixture
/// corpus has the full set; this end-to-end test needs only these two).
fn text_pdf(text: &str, trailer_extra: &str, extra_object: Option<&str>) -> Vec<u8> {
    let content = format!("BT /F1 12 Tf 72 720 Td ({text}) Tj ET");
    let mut objects = vec![
        "<< /Type /Catalog /Pages 2 0 R >>".to_owned(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".into(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
         /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"
            .into(),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".into(),
        format!(
            "<< /Length {} >>\nstream\n{content}\nendstream",
            content.len()
        ),
    ];
    objects.extend(extra_object.map(str::to_owned));
    let mut out = b"%PDF-1.7\n".to_vec();
    let mut offsets = Vec::new();
    for (index, body) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n{body}\nendobj\n", index + 1).as_bytes());
    }
    let xref = out.len();
    out.extend_from_slice(
        format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).as_bytes(),
    );
    for offset in offsets {
        out.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R {trailer_extra}>>\nstartxref\n{xref}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    out
}

/// WI-05 end to end through orceld: a committed download goes through the
/// approval and the real, pinned helper and parser. `ORCEL_TEST_CONTAIN_DIR`
/// names the helper's target directory and `ORCEL_TEST_DOC_PARSER_DIR` the
/// parser's; the Document parser CI job sets both together with
/// `ORCEL_REQUIRE_CONTAINED_PARSER`, which turns a missing one into a
/// failure instead of a skip.
#[test]
fn wi05_orceld_parses_a_committed_download_under_the_contained_tier() {
    let (Some(contain), Some(parser_dir)) = (
        std::env::var_os("ORCEL_TEST_CONTAIN_DIR"),
        std::env::var_os("ORCEL_TEST_DOC_PARSER_DIR"),
    ) else {
        assert!(
            std::env::var_os("ORCEL_REQUIRE_CONTAINED_PARSER").is_none(),
            "ORCEL_TEST_CONTAIN_DIR and ORCEL_TEST_DOC_PARSER_DIR are required"
        );
        return;
    };
    let helper_path = std::fs::canonicalize(contain)
        .unwrap()
        .join(contained_tier::HELPER_NAME);
    let helper = HelperPin::new(
        &helper_path,
        &sha256_hex(&std::fs::read(&helper_path).expect("read the helper")),
    )
    .unwrap();
    // Cargo hard-links its outputs, and a granted file must have one link:
    // the parser runs from a plain copy, as an install would hold it.
    let bin = temp_dir("e2e-bin");
    let parser_path = bin.join(PARSER_NAME);
    std::fs::copy(
        std::path::Path::new(&parser_dir).join(PARSER_NAME),
        &parser_path,
    )
    .unwrap();
    let started = std::time::Instant::now();
    while std::process::Command::new(&parser_path)
        .stdout(std::process::Stdio::null())
        .status()
        .is_err()
    {
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let parser = ParserPin::for_test(
        parser_path.clone(),
        sha256_hex(&std::fs::read(&parser_path).unwrap()),
    );
    let folder = temp_dir("e2e-downloads");
    let approved = FixedApprovalBroker(ApprovalDecision::Approved);

    let download = committed(
        &folder,
        "report.pdf",
        &text_pdf("Orcel WI-05 orceld fixture", "", None),
    );
    let result = parse_committed(&workspace(&folder), &approved, &download, &helper, &parser)
        .expect("a parsed document");
    assert_eq!(result["format"], "pdf");
    assert_eq!(result["pages"], 1);
    assert_eq!(result["execution_tier"], "contained");
    assert_eq!(result["network_class"], "NONE");
    assert_eq!(result["content"]["trust"], "untrusted");
    assert_eq!(result["source"]["sha256"], download.sha256.as_str());
    let markdown = result["content"]["markdown"].as_str().unwrap();
    assert!(
        markdown.contains("Orcel WI-05 orceld fixture"),
        "{markdown}"
    );

    // An encrypted PDF fails closed with its type, through the frame.
    let id = "00112233445566778899aabbccddeeff";
    let handler = format!("<< /Filter /Standard /V 1 /R 2 /O <{id}{id}> /U <{id}{id}> /P -4 >>");
    let encrypted = committed(
        &folder,
        "locked.pdf",
        &text_pdf(
            "secret",
            &format!("/Encrypt 6 0 R /ID [<{id}> <{id}>] "),
            Some(&handler),
        ),
    );
    let error =
        parse_committed(&workspace(&folder), &approved, &encrypted, &helper, &parser).unwrap_err();
    assert_eq!(error.code, FailureCode::InvalidRequest, "{}", error.message);
    assert!(
        error
            .message
            .starts_with("document_parse_refused:encrypted"),
        "{}",
        error.message
    );

    // A parser crash (the debug build's abort trigger) is a failure, never a
    // result.
    let crash = committed(&folder, "crash.pdf", b"ORCEL-WI05-TEST-ABORT");
    let error =
        parse_committed(&workspace(&folder), &approved, &crash, &helper, &parser).unwrap_err();
    assert_eq!(
        error.code,
        FailureCode::PostconditionFailed,
        "{}",
        error.message
    );
    assert!(
        error.message.starts_with("document_parse_failed:crashed"),
        "{}",
        error.message
    );

    // A parser whose bytes no longer match its pin is never launched.
    let tampered = ParserPin::for_test(parser_path, "a".repeat(64));
    let error = parse_committed(
        &workspace(&folder),
        &approved,
        &download,
        &helper,
        &tampered,
    )
    .unwrap_err();
    assert_eq!(error.code, FailureCode::TargetStale, "{}", error.message);

    let _ = std::fs::remove_dir_all(bin);
    let _ = std::fs::remove_dir_all(folder);
}

#[test]
fn wi05_each_parse_gets_its_own_stage() {
    let first = Stage::create(DIGEST).expect("a stage");
    let second = Stage::create(DIGEST).expect("a second stage for the same digest");
    assert_ne!(first.root, second.root);
    std::fs::write(first.input.join(INPUT_NAME), b"first").unwrap();
    drop(second);
    assert_eq!(
        std::fs::read(first.input.join(INPUT_NAME)).unwrap(),
        b"first"
    );
}

#[test]
fn a_stage_name_already_taken_is_skipped_and_left_alone() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base = std::env::temp_dir().join(format!("orcel-dp-claim-{}-{unique}", std::process::id()));
    let runs = base.join("runs");
    let outside = base.join("outside");
    std::fs::create_dir_all(runs.join("taken")).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(runs.join("taken").join("sentinel"), b"keep").unwrap();
    std::fs::write(runs.join("file"), b"keep").unwrap();
    std::fs::write(outside.join("sentinel"), b"keep").unwrap();
    // A link under a predicted name: a directory symlink, or a junction on Windows.
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, runs.join("link")).unwrap();
    #[cfg(windows)]
    assert!(std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(runs.join("link"))
        .arg(&outside)
        .status()
        .unwrap()
        .success());
    // A dangling junction too: creating at its name must not create its missing target.
    #[cfg(windows)]
    {
        assert!(std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(runs.join("dangling"))
            .arg(base.join("missing"))
            .status()
            .unwrap()
            .success());
        assert!(
            contained_tier::claim_dir(&runs, ["dangling".to_owned()].into_iter(), "test").is_err()
        );
        assert!(
            !base.join("missing").exists(),
            "a dangling link's target is never created"
        );
        std::fs::remove_dir(runs.join("dangling")).unwrap();
    }
    let names = ["taken", "file", "link", "fresh"].map(String::from);
    let claimed = contained_tier::claim_dir(&runs, names.into_iter(), "test").unwrap();
    assert_eq!(claimed, runs.join("fresh"));
    assert_eq!(
        std::fs::read(runs.join("taken").join("sentinel")).unwrap(),
        b"keep"
    );
    assert_eq!(std::fs::read(runs.join("file")).unwrap(), b"keep");
    assert_eq!(std::fs::read(outside.join("sentinel")).unwrap(), b"keep");
    assert!(
        std::fs::symlink_metadata(runs.join("link")).is_ok(),
        "the link itself stays"
    );
    // When every name is taken, it fails closed instead of reusing one.
    assert!(contained_tier::claim_dir(&runs, ["taken".to_owned()].into_iter(), "test").is_err());
    #[cfg(windows)]
    std::fs::remove_dir(runs.join("link")).unwrap();
    #[cfg(unix)]
    std::fs::remove_file(runs.join("link")).unwrap();
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn only_leftovers_of_exited_processes_are_swept() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base = std::env::temp_dir().join(format!("orcel-dp-sweep-{}-{unique}", std::process::id()));
    let runs = base.join("runs");
    let outside = base.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("sentinel"), b"keep").unwrap();
    // A process that has exited, so its pid names no running process.
    #[cfg(windows)]
    let mut child = std::process::Command::new("cmd")
        .args(["/C", "exit"])
        .spawn()
        .unwrap();
    #[cfg(unix)]
    let mut child = std::process::Command::new("true").spawn().unwrap();
    let dead = child.id();
    child.wait().unwrap();
    let own = std::process::id();
    // A running process that isn't this one.
    #[cfg(windows)]
    let mut live = std::process::Command::new("ping")
        .args(["-n", "30", "127.0.0.1"])
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    #[cfg(unix)]
    let mut live = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let alive = live.id();
    for name in [
        format!("{dead}-0-0000000000000000-leftover"),
        format!("{own}-0-0000000000000000-mine"),
        format!("{alive}-0-0000000000000000-running"),
        "not-a-run".to_owned(),
    ] {
        std::fs::create_dir_all(runs.join(&name).join("work")).unwrap();
        std::fs::write(runs.join(&name).join("work").join("file"), b"x").unwrap();
    }
    // A link under a dead pid's name is never removed or followed.
    let link = runs.join(format!("{dead}-1-0000000000000000-link"));
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, &link).unwrap();
    #[cfg(windows)]
    assert!(std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&link)
        .arg(&outside)
        .status()
        .unwrap()
        .success());
    // A plain file under a dead pid's name stays too.
    std::fs::write(
        runs.join(format!("{dead}-2-0000000000000000-file")),
        b"keep",
    )
    .unwrap();

    assert_eq!(contained_tier::sweep_leftovers(&runs), 1);
    assert!(!runs
        .join(format!("{dead}-0-0000000000000000-leftover"))
        .exists());
    for kept in [
        format!("{own}-0-0000000000000000-mine"),
        format!("{alive}-0-0000000000000000-running"),
        "not-a-run".to_owned(),
        format!("{dead}-2-0000000000000000-file"),
    ] {
        assert!(runs.join(&kept).exists(), "{kept} stays");
    }
    assert!(
        std::fs::symlink_metadata(&link).is_ok(),
        "the link itself stays"
    );
    assert_eq!(std::fs::read(outside.join("sentinel")).unwrap(), b"keep");
    // A missing runs directory sweeps nothing.
    assert_eq!(contained_tier::sweep_leftovers(&base.join("absent")), 0);

    let _ = live.kill();
    let _ = live.wait();
    #[cfg(windows)]
    std::fs::remove_dir(&link).unwrap();
    #[cfg(unix)]
    std::fs::remove_file(&link).unwrap();
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn only_names_orcel_writes_carry_a_run_pid() {
    let salt = "0123456789abcdef";
    let digest = "ab".repeat(32);
    assert_eq!(
        contained_tier::run_pid(&format!("123-0-{salt}-label")),
        Some(123)
    );
    assert_eq!(contained_tier::run_pid(&format!("123-{digest}")), Some(123));
    for name in [
        format!("+123-0-{salt}-label"),
        format!("0123-0-{salt}-label"),
        format!("0-0-{salt}-label"),
        format!("4294967295-0-{salt}-label"),
        format!("123-0-{salt}-"),
        format!("123-00-{salt}-label"),
        format!("123-0-0123456789ABCDEF-label"),
        format!("123-0-{}-label", &salt[..15]),
        format!("123-{}", &digest[..63]),
        "123-x".to_owned(),
        "123".to_owned(),
        "not-a-run".to_owned(),
    ] {
        assert_eq!(contained_tier::run_pid(&name), None, "{name}");
    }
}
