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
    let Some((helper, parser, bin)) = contained_pins() else {
        return;
    };
    let parser_path = parser.path.clone();
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

/// The real, pinned helper and parser, and the private directory holding
/// the parser's copy. `ORCEL_TEST_CONTAIN_DIR` names the helper's target
/// directory and `ORCEL_TEST_DOC_PARSER_DIR` the parser's; with neither,
/// `None`, unless `ORCEL_REQUIRE_CONTAINED_PARSER` makes that a failure.
fn contained_pins() -> Option<(HelperPin, ParserPin, PathBuf)> {
    let (Some(contain), Some(parser_dir)) = (
        std::env::var_os("ORCEL_TEST_CONTAIN_DIR"),
        std::env::var_os("ORCEL_TEST_DOC_PARSER_DIR"),
    ) else {
        assert!(
            std::env::var_os("ORCEL_REQUIRE_CONTAINED_PARSER").is_none(),
            "ORCEL_TEST_CONTAIN_DIR and ORCEL_TEST_DOC_PARSER_DIR are required"
        );
        return None;
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
    Some((helper, parser, bin))
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
        format!("2147483648-0-{salt}-label"),
        format!("123-0-{salt}-"),
        format!("123-00-{salt}-label"),
        "123-0-0123456789ABCDEF-label".to_owned(),
        format!("123-0-{}-label", &salt[..15]),
        format!("123-{}", &digest[..63]),
        "123-x".to_owned(),
        "123".to_owned(),
        "not-a-run".to_owned(),
    ] {
        assert_eq!(contained_tier::run_pid(&name), None, "{name}");
    }
}

// F5 slice 2: a workspace file to the parser. Nothing below asks for an
// approval; the route asks for none (see `document_parse.rs`).

/// A workspace with `relative` holding `bytes`.
fn workspace_with(label: &str, relative: &str, bytes: &[u8]) -> (PathBuf, Workspace) {
    let root = temp_dir(label);
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, bytes).unwrap();
    let workspace = workspace(&root);
    (root, workspace)
}

#[cfg(windows)]
fn junction(link: &Path, target: &Path) {
    let made = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .output()
        .unwrap();
    assert!(made.status.success(), "{made:?}");
}

#[test]
fn f5_only_an_xlsx_name_reaches_the_workspace_route() {
    let (root, workspace) = workspace_with("ws-names", "data/q3.csv", b"a,b\n1,2\n");
    for name in [
        "data/q3.csv",
        "data/report.pdf",
        "data/book.xlsm",
        "data/book.xlsb",
        "data/book.xls",
        "data/book.xlsx.txt",
        "data/absent.docx",
    ] {
        let error = observe_workspace_file(&workspace, name).unwrap_err();
        assert_eq!(error.code, FailureCode::InvalidRequest, "{name}");
        assert!(
            error
                .message
                .starts_with("document_parse_refused:unsupported_format"),
            "{name}: {}",
            error.message
        );
    }
    std::fs::write(root.join("data").join("Book.XLSX"), b"PK").unwrap();
    let observed = observe_workspace_file(&workspace, "data/Book.XLSX").expect("any case");
    assert_eq!(observed.bytes, 2);
    assert_eq!(observed.sha256, sha256_hex(b"PK"));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn f5_a_workspace_path_must_be_plain_segments_below_the_root() {
    let (root, workspace) = workspace_with("ws-shapes", "data/a.xlsx", b"PK");
    let outside = temp_dir("ws-shapes-outside");
    std::fs::write(outside.join("a.xlsx"), b"PK").unwrap();
    let absolute = outside.join("a.xlsx").to_string_lossy().into_owned();
    for name in [
        "../outside.xlsx",
        "data/../data/a.xlsx",
        "./data/a.xlsx",
        "data//a.xlsx",
        "/data/a.xlsx",
        "\\data\\a.xlsx",
        "C:/data/a.xlsx",
        absolute.as_str(),
        "data/a.xlsx:stream.xlsx",
        "data./a.xlsx",
        "data /a.xlsx",
        "data/\u{1}a.xlsx",
    ] {
        let error = observe_workspace_file(&workspace, name).unwrap_err();
        assert_eq!(
            error.code,
            FailureCode::PathEscape,
            "{name}: {}",
            error.message
        );
    }
    // A directory with a workbook's name isn't a regular file.
    std::fs::create_dir_all(root.join("data").join("folder.xlsx")).unwrap();
    let error = observe_workspace_file(&workspace, "data/folder.xlsx").unwrap_err();
    assert_eq!(error.code, FailureCode::PathEscape, "{}", error.message);
    let error = observe_workspace_file(&workspace, "data/absent.xlsx").unwrap_err();
    assert_eq!(error.code, FailureCode::TargetStale, "{}", error.message);
    // Either separator names the same plain path.
    assert_eq!(
        observe_workspace_file(&workspace, "data\\a.xlsx")
            .unwrap()
            .sha256,
        sha256_hex(b"PK")
    );
    let _ = std::fs::remove_dir_all(outside);
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn f5_a_workspace_file_through_a_junction_or_link_is_refused() {
    let (root, workspace) = workspace_with("ws-junction", "real/a.xlsx", b"PK inside");
    let outside = temp_dir("ws-junction-outside");
    std::fs::write(outside.join("a.xlsx"), b"PK outside").unwrap();
    // A junction to a folder inside the workspace, and to one outside it.
    junction(&root.join("inner"), &root.join("real"));
    junction(&root.join("away"), &outside);
    for name in ["inner/a.xlsx", "away/a.xlsx"] {
        let error = observe_workspace_file(&workspace, name).unwrap_err();
        assert_eq!(
            error.code,
            FailureCode::PathEscape,
            "{name}: {}",
            error.message
        );
    }
    // A file symbolic link needs a privilege a test account may lack; where
    // it can be made, it's refused too.
    if std::os::windows::fs::symlink_file(root.join("real").join("a.xlsx"), root.join("l.xlsx"))
        .is_ok()
    {
        let error = observe_workspace_file(&workspace, "l.xlsx").unwrap_err();
        assert_eq!(error.code, FailureCode::PathEscape, "{}", error.message);
    }
    assert!(observe_workspace_file(&workspace, "real/a.xlsx").is_ok());
    std::fs::remove_dir(root.join("inner")).unwrap();
    std::fs::remove_dir(root.join("away")).unwrap();
    let _ = std::fs::remove_dir_all(outside);
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn f5_a_workspace_file_through_a_link_is_refused() {
    let (root, workspace) = workspace_with("ws-link", "real/a.xlsx", b"PK inside");
    let outside = temp_dir("ws-link-outside");
    std::fs::write(outside.join("a.xlsx"), b"PK outside").unwrap();
    std::os::unix::fs::symlink(root.join("real"), root.join("inner")).unwrap();
    std::os::unix::fs::symlink(&outside, root.join("away")).unwrap();
    std::os::unix::fs::symlink(root.join("real").join("a.xlsx"), root.join("l.xlsx")).unwrap();
    for name in ["inner/a.xlsx", "away/a.xlsx", "l.xlsx"] {
        let error = observe_workspace_file(&workspace, name).unwrap_err();
        assert_eq!(
            error.code,
            FailureCode::PathEscape,
            "{name}: {}",
            error.message
        );
    }
    assert!(observe_workspace_file(&workspace, "real/a.xlsx").is_ok());
    let _ = std::fs::remove_dir_all(outside);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn f5_an_oversized_workspace_file_is_refused_before_it_is_read() {
    let (root, workspace) = workspace_with("ws-large", "big.xlsx", b"");
    std::fs::File::options()
        .write(true)
        .open(root.join("big.xlsx"))
        .unwrap()
        .set_len(MAX_INPUT_BYTES + 1)
        .unwrap();
    let error = observe_workspace_file(&workspace, "big.xlsx").unwrap_err();
    assert!(
        error
            .message
            .starts_with("document_parse_refused:input_too_large"),
        "{}",
        error.message
    );
    // A record claiming more than the bound is refused before any read.
    let (helper, parser) = dummy_pins(&root);
    let forged = WorkspaceFile {
        relative: "big.xlsx".into(),
        bytes: MAX_INPUT_BYTES + 1,
        sha256: DIGEST.into(),
    };
    let error = parse_workspace_file(&workspace, &forged, &helper, &parser).unwrap_err();
    assert!(
        error
            .message
            .starts_with("document_parse_refused:input_too_large"),
        "{}",
        error.message
    );
    let _ = std::fs::remove_dir_all(root);
}

/// Between observing and parsing, a changed, grown, removed or relinked
/// file is refused before anything is staged or launched: the dummy pins
/// name no helper or parser, so reaching the run would fail differently.
#[test]
fn f5_a_workspace_file_changed_after_it_was_observed_is_refused() {
    let (root, workspace) = workspace_with("ws-stale", "data/a.xlsx", b"PK observed");
    let (helper, parser) = dummy_pins(&root);
    let observed = observe_workspace_file(&workspace, "data/a.xlsx").unwrap();
    let path = root.join("data").join("a.xlsx");

    // Same size, other bytes.
    std::fs::write(&path, b"PK replaced").unwrap();
    let error = parse_workspace_file(&workspace, &observed, &helper, &parser).unwrap_err();
    assert_eq!(error.code, FailureCode::TargetStale, "{}", error.message);

    std::fs::write(&path, b"PK observed, then grown").unwrap();
    let error = parse_workspace_file(&workspace, &observed, &helper, &parser).unwrap_err();
    assert_eq!(error.code, FailureCode::TargetStale, "{}", error.message);

    std::fs::remove_file(&path).unwrap();
    let error = parse_workspace_file(&workspace, &observed, &helper, &parser).unwrap_err();
    assert_eq!(error.code, FailureCode::TargetStale, "{}", error.message);

    // The same bytes, now behind a link: refused although the digest matches.
    let real = root.join("real");
    std::fs::create_dir_all(&real).unwrap();
    std::fs::write(real.join("a.xlsx"), b"PK observed").unwrap();
    std::fs::remove_dir(root.join("data")).unwrap();
    #[cfg(windows)]
    junction(&root.join("data"), &real);
    #[cfg(unix)]
    std::os::unix::fs::symlink(&real, root.join("data")).unwrap();
    let error = parse_workspace_file(&workspace, &observed, &helper, &parser).unwrap_err();
    assert_eq!(error.code, FailureCode::PathEscape, "{}", error.message);

    // Put back as plain directories, the unchanged file passes every check
    // and reaches the run, which the dummy pins can't start.
    #[cfg(windows)]
    std::fs::remove_dir(root.join("data")).unwrap();
    #[cfg(unix)]
    std::fs::remove_file(root.join("data")).unwrap();
    std::fs::rename(&real, root.join("data")).unwrap();
    let error = parse_workspace_file(&workspace, &observed, &helper, &parser).unwrap_err();
    assert_eq!(
        error.code,
        FailureCode::ProviderUnavailable,
        "{}",
        error.message
    );
    let _ = std::fs::remove_dir_all(root);
}

/// A file with a second name, inside the workspace or outside it, is refused
/// at observe, and a second name made after observing is refused at parse.
#[test]
fn f5_a_workspace_file_with_another_hard_link_is_refused() {
    let (root, workspace) = workspace_with("ws-hardlink", "data/a.xlsx", b"PK one name");
    std::fs::write(root.join("data").join("b.xlsx"), b"PK two names").unwrap();
    let (helper, parser) = dummy_pins(&root);
    let observed = observe_workspace_file(&workspace, "data/b.xlsx").unwrap();
    std::fs::hard_link(root.join("data").join("b.xlsx"), root.join("b-too.xlsx")).unwrap();
    let error = parse_workspace_file(&workspace, &observed, &helper, &parser).unwrap_err();
    assert_eq!(error.code, FailureCode::PathEscape, "{}", error.message);
    assert!(error.message.contains("hard link"), "{}", error.message);
    for name in ["data/b.xlsx", "b-too.xlsx"] {
        let error = observe_workspace_file(&workspace, name).unwrap_err();
        assert_eq!(error.code, FailureCode::PathEscape, "{name}");
    }
    // A name in the workspace for a file that lives outside it.
    let outside = temp_dir("ws-hardlink-outside");
    std::fs::write(outside.join("secret.xlsx"), b"PK outside").unwrap();
    std::fs::hard_link(
        outside.join("secret.xlsx"),
        root.join("data").join("in.xlsx"),
    )
    .unwrap();
    let error = observe_workspace_file(&workspace, "data/in.xlsx").unwrap_err();
    assert_eq!(error.code, FailureCode::PathEscape, "{}", error.message);
    assert!(observe_workspace_file(&workspace, "data/a.xlsx").is_ok());
    let _ = std::fs::remove_dir_all(outside);
    let _ = std::fs::remove_dir_all(root);
}

/// The race the walks alone can't see: a directory swapped for a link while
/// the file is opened, and back before the next walk (an oplock can hold the
/// open to make it deterministic). The open handle then reached the link's
/// target. Simulated by opening through the link directly: the handle isn't
/// the file at the walked path, by its real path, and by its identity.
#[test]
fn f5_a_handle_that_reached_another_file_is_refused() {
    let (root, _workspace) = workspace_with("ws-raced", "data/a.xlsx", b"PK inside");
    let outside = temp_dir("ws-raced-outside");
    std::fs::write(outside.join("a.xlsx"), b"PK outside").unwrap();
    #[cfg(windows)]
    junction(&root.join("away"), &outside);
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, root.join("away")).unwrap();
    let walked = root.join("away").join("a.xlsx");
    // `File::open` follows the link, as an open raced this way would.
    let raced_handle = std::fs::File::open(&walked).unwrap();
    let error = opened_as(&raced_handle, &walked).unwrap_err();
    assert_eq!(
        error.code,
        FailureCode::PathRaceDetected,
        "{}",
        error.message
    );
    // A handle to one plain file isn't another plain file either.
    let inside = root.join("data").join("a.xlsx");
    let error = opened_as(&raced_handle, &inside).unwrap_err();
    assert_eq!(error.code, FailureCode::PathRaceDetected);
    // Identity: the same file opened twice matches; another file doesn't.
    let first = opened_as(&open_no_follow(&inside).unwrap(), &inside).unwrap();
    let again = opened_as(&open_no_follow(&inside).unwrap(), &inside).unwrap();
    assert_eq!(first, again);
    assert_eq!(first.links, 1);
    std::fs::write(root.join("data").join("b.xlsx"), b"PK inside").unwrap();
    let other_path = root.join("data").join("b.xlsx");
    let other = opened_as(&open_no_follow(&other_path).unwrap(), &other_path).unwrap();
    assert_ne!(first, other);
    drop(raced_handle);
    #[cfg(windows)]
    std::fs::remove_dir(root.join("away")).unwrap();
    let _ = std::fs::remove_dir_all(outside);
    let _ = std::fs::remove_dir_all(root);
}

/// F5 slice 2 end to end: a committed workbook fixture in a workspace, through
/// the route and the real, pinned helper and parser under the contained tier
/// (`wi05_`, so the Document parser CI job runs it with them).
#[test]
fn wi05_f5_a_workspace_workbook_is_parsed_under_the_contained_tier() {
    use crate::report_workbook::tests::{fixture, fixture_parts, stored_zip};
    let Some((helper, parser, bin)) = contained_pins() else {
        return;
    };
    let (root, workspace) = workspace_with(
        "ws-e2e",
        "data/sales.xlsx",
        &fixture("written-by-xlsxwriter"),
    );
    let observed = observe_workspace_file(&workspace, "data/sales.xlsx").unwrap();
    let document =
        parse_workspace_file(&workspace, &observed, &helper, &parser).expect("a parsed workbook");
    assert_eq!(document.format, DocumentFormat::Xlsx);
    assert!(!document.truncated);
    assert_eq!(
        crate::report_workbook::cell_value(&document.markdown, "Sales", "B2"),
        Some("1250.5"),
        "{}",
        document.markdown
    );

    // Another document under a workbook's name is refused after the parse.
    std::fs::write(
        root.join("data").join("fake.xlsx"),
        text_pdf("not a workbook", "", None),
    )
    .unwrap();
    let observed = observe_workspace_file(&workspace, "data/fake.xlsx").unwrap();
    let error = parse_workspace_file(&workspace, &observed, &helper, &parser).unwrap_err();
    assert_eq!(error.code, FailureCode::InvalidRequest, "{}", error.message);
    assert!(
        error
            .message
            .starts_with("document_parse_refused:unsupported_format"),
        "{}",
        error.message
    );

    // A macro workbook is refused with its type, through the frame.
    let mut macros = fixture_parts("written-by-openpyxl");
    macros.push(("xl/vbaProject.bin".into(), b"not really".to_vec()));
    std::fs::write(root.join("data").join("macros.xlsx"), stored_zip(macros)).unwrap();
    let observed = observe_workspace_file(&workspace, "data/macros.xlsx").unwrap();
    let error = parse_workspace_file(&workspace, &observed, &helper, &parser).unwrap_err();
    assert!(
        error
            .message
            .starts_with("document_parse_refused:active_content"),
        "{}",
        error.message
    );

    let _ = std::fs::remove_dir_all(bin);
    let _ = std::fs::remove_dir_all(root);
}
