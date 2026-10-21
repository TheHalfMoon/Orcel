//! WI-05 end-to-end: the real parser under the real contained tier, started
//! exactly as orceld starts it (the std-only client
//! `orcel_provider_process::contained::run_contained`, the pinned
//! `orcel-contain` helper, and the one spec orceld builds,
//! `orcel_provider_process::document_parser::spec`).
//!
//! `ORCEL_TEST_CONTAIN_DIR` names the helper workspace's target directory
//! (`orcel-contain` and its probe). CI sets it with
//! `ORCEL_REQUIRE_CONTAINED_PARSER=1` on every OS, which turns a missing
//! helper into a failure instead of a skip.
//!
//! The boundary tests run XP-13's `orcel-contain-probe` under the parser's
//! own spec (the same input directory, working directory and limits), so a
//! denial is the spec's, and each denial has an uncontained positive control.

mod fixtures;

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use orcel_provider_process::contained::{
    run_contained, sha256_hex, ContainedOutcome, ContainedRun, ContainedSpec, HelperPin,
};
use orcel_provider_process::document_parser::{
    decode_frame, spec, DocumentFormat, FrameError, ParseRefusal, EXIT_REFUSED, INPUT_NAME,
    MAX_PAGES,
};

const WRITE_FAILED: i64 = 10;
const READ_FAILED: i64 = 11;
const NETWORK_FAILED: i64 = 12;
const SPAWN_FAILED: i64 = 13;

fn exe(name: &str) -> String {
    if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_owned()
    }
}

/// The helper directory, or `None` (skip) when it is not configured and not
/// required.
fn helper_dir() -> Option<PathBuf> {
    match std::env::var_os("ORCEL_TEST_CONTAIN_DIR") {
        Some(dir) => Some(std::fs::canonicalize(dir).expect("ORCEL_TEST_CONTAIN_DIR")),
        None => {
            assert!(
                std::env::var_os("ORCEL_REQUIRE_CONTAINED_PARSER").is_none(),
                "ORCEL_TEST_CONTAIN_DIR is required"
            );
            eprintln!("skipped: ORCEL_TEST_CONTAIN_DIR is not set");
            None
        }
    }
}

/// A parallel test's fork may briefly hold a fresh copy open for writing
/// (ETXTBSY on Linux); wait until the copy starts.
fn settle(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Command::new(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_err()
    {
        assert!(
            Instant::now() < deadline,
            "{} never started",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// One parse's tree, laid out as orceld lays it out: the parser copied into
/// its own directory (Cargo hard-links its outputs, and a granted file must
/// have one link), a private input directory holding only `input`, a private
/// working directory, and an outside directory nothing grants.
struct Scene {
    _root: tempfile::TempDir,
    helper: HelperPin,
    parser: PathBuf,
    probe: PathBuf,
    input_dir: PathBuf,
    work: PathBuf,
    outside: PathBuf,
}

impl Scene {
    fn new(input: &[u8]) -> Option<Self> {
        let dir = helper_dir()?;
        let helper_path = dir.join(exe("orcel-contain"));
        let digest = sha256_hex(&std::fs::read(&helper_path).expect("read the helper"));
        let helper = HelperPin::new(&helper_path, &digest).expect("pin the helper");
        let root = tempfile::Builder::new().prefix("wi05-").tempdir().unwrap();
        let base = std::fs::canonicalize(root.path()).unwrap();
        let made = |name: &str| {
            let path = base.join(name);
            std::fs::create_dir(&path).unwrap();
            path
        };
        let bin = made("bin");
        let input_dir = made("input");
        let work = made("work");
        let outside = made("outside");
        let parser = bin.join(exe("orcel-doc-parser"));
        std::fs::copy(env!("CARGO_BIN_EXE_orcel-doc-parser"), &parser).unwrap();
        settle(&parser);
        let probe = bin.join(exe("probe"));
        std::fs::copy(dir.join(exe("orcel-contain-probe")), &probe).unwrap();
        settle(&probe);
        std::fs::write(input_dir.join(INPUT_NAME), input).unwrap();
        std::fs::write(outside.join("secret.txt"), b"outside bytes").unwrap();
        Some(Self {
            _root: root,
            helper,
            parser,
            probe,
            input_dir,
            work,
            outside,
        })
    }

    fn parser_spec(&self) -> ContainedSpec {
        spec(self.parser.clone(), &self.input_dir, self.work.clone())
    }

    /// The probe under the parser's spec, with the probe's own arguments.
    fn probe_spec(&self, args: &[&str]) -> ContainedSpec {
        let mut spec = spec(self.probe.clone(), &self.input_dir, self.work.clone());
        spec.argv = args.iter().map(|arg| (*arg).to_owned()).collect();
        spec
    }

    fn run(&self, spec: &ContainedSpec) -> ContainedRun {
        run_contained(&self.helper, spec)
            .unwrap_or_else(|error| panic!("contained run failed: {error:?}"))
    }

    fn parse(
        &self,
    ) -> (
        i64,
        Result<orcel_provider_process::document_parser::ParsedDocument, FrameError>,
    ) {
        let run = self.run(&self.parser_spec());
        let ContainedOutcome::Exited(code) = run.outcome else {
            panic!(
                "the parser did not exit: {:?}; stderr: {}",
                run.outcome,
                String::from_utf8_lossy(&run.stderr)
            );
        };
        (code, decode_frame(&run.stdout))
    }

    fn probe(&self, args: &[&str]) -> i64 {
        match self.run(&self.probe_spec(args)).outcome {
            ContainedOutcome::Exited(code) => code,
            other => panic!("the probe did not exit: {other:?}"),
        }
    }

    fn uncontained(&self, args: &[&str]) -> i64 {
        let status = Command::new(&self.probe)
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        i64::from(status.code().unwrap_or(-1))
    }
}

fn text(path: &Path) -> &str {
    path.to_str().unwrap()
}

#[test]
fn wi05_the_normal_pdf_and_docx_convert_under_containment() {
    let Some(scene) = Scene::new(&fixtures::text_pdf()) else {
        return;
    };
    let (code, frame) = scene.parse();
    let document = frame.expect("a PDF frame");
    assert_eq!(code, 0);
    assert_eq!(document.format, DocumentFormat::Pdf);
    assert_eq!(document.pages, 1);
    assert!(
        document.markdown.contains("Orcel WI-05 fixture"),
        "{}",
        document.markdown
    );

    let Some(scene) = Scene::new(&fixtures::docx()) else {
        return;
    };
    let (code, frame) = scene.parse();
    let document = frame.expect("a DOCX frame");
    assert_eq!(code, 0);
    assert_eq!(document.format, DocumentFormat::Docx);
    assert!(
        document.markdown.contains("Orcel WI-05 office fixture"),
        "{}",
        document.markdown
    );
    assert!(
        document.markdown.contains("Running header text"),
        "{}",
        document.markdown
    );
}

#[test]
fn wi05_hostile_inputs_fail_closed_under_containment_with_their_type() {
    let corpus: Vec<(&str, Vec<u8>, ParseRefusal)> = vec![
        (
            "malformed PDF",
            fixtures::malformed_pdf(),
            ParseRefusal::Malformed,
        ),
        (
            "encrypted PDF",
            fixtures::encrypted_pdf(),
            ParseRefusal::Encrypted,
        ),
        (
            "PDF with JavaScript",
            fixtures::javascript_pdf(),
            ParseRefusal::ActiveContent,
        ),
        (
            "PDF with a launch action",
            fixtures::launch_pdf(),
            ParseRefusal::ActiveContent,
        ),
        (
            "huge page count",
            fixtures::pages_pdf(MAX_PAGES + 1),
            ParseRefusal::TooManyPages,
        ),
        (
            "deeply nested PDF",
            fixtures::nested_pdf(40),
            ParseRefusal::NestingTooDeep,
        ),
        (
            "PDF flate bomb",
            fixtures::flate_bomb_pdf(),
            ParseRefusal::ArchiveLimit,
        ),
        (
            "PDF flate bomb behind a bare structure name",
            fixtures::struct_name_bomb_pdf(),
            ParseRefusal::ArchiveLimit,
        ),
        (
            "PDF with a non-canonical first header",
            fixtures::shifted_header_pdf(),
            ParseRefusal::Malformed,
        ),
        (
            "PDF with repair-shaped (19-byte) cross-reference entries",
            fixtures::short_xref_pdf(),
            ParseRefusal::NoText,
        ),
        (
            "zip bomb DOCX",
            fixtures::zip_bomb_docx(),
            ParseRefusal::ArchiveLimit,
        ),
        (
            "spread zip bomb DOCX",
            fixtures::spread_bomb_docx(),
            ParseRefusal::ArchiveLimit,
        ),
        (
            "macro-enabled DOCX",
            fixtures::macro_docx(),
            ParseRefusal::ActiveContent,
        ),
        (
            "encrypted Office",
            fixtures::encrypted_office(),
            ParseRefusal::Encrypted,
        ),
        (
            "not a document",
            b"MZ\x90\x00".to_vec(),
            ParseRefusal::UnsupportedFormat,
        ),
    ];
    for (name, bytes, expected) in corpus {
        let Some(scene) = Scene::new(&bytes) else {
            return;
        };
        let (code, frame) = scene.parse();
        assert_eq!(code, EXIT_REFUSED, "{name}");
        assert_eq!(frame, Err(FrameError::Refused(expected)), "{name}");
    }
}

/// #391: a form XObject of just under 64 MiB passes every pre-flight bound,
/// and pdf-inspector decodes it again on each page that draws it. Drawn on
/// 64 pages, that would be 4 GiB of decodes. The decode budget ends the run
/// as a typed `archive_limit` after the fourth, inside the contained tier's
/// memory, CPU and time ceilings, instead of leaving it to them (on macOS
/// the memory ceiling is a sampling watcher, not a hard cap).
#[test]
fn wi05_a_large_form_drawn_on_many_pages_ends_as_archive_limit_under_containment() {
    let bytes = fixtures::repeated_form_pdf(64, fixtures::FORM_ZEROS);
    let Some(scene) = Scene::new(&bytes) else {
        return;
    };
    let (code, frame) = scene.parse();
    assert_eq!(code, EXIT_REFUSED);
    assert_eq!(frame, Err(FrameError::Refused(ParseRefusal::ArchiveLimit)));
    // The control: a small form on every page converts under the same spec.
    let Some(scene) = Scene::new(&fixtures::repeated_form_pdf(16, 1 + 258 * 4_064)) else {
        return;
    };
    let (code, frame) = scene.parse();
    assert_eq!(code, 0);
    assert_eq!(frame.expect("converts").pages, 16);
}

/// A parser crash (the debug-only abort trigger) ends inside the contained
/// process: the helper reports it, and there is no frame to accept.
#[test]
fn wi05_a_parser_crash_is_contained_and_yields_no_frame() {
    let Some(scene) = Scene::new(fixtures::ABORT_TRIGGER) else {
        return;
    };
    let run = scene.run(&scene.parser_spec());
    assert!(
        run.outcome != ContainedOutcome::Exited(0)
            && run.outcome != ContainedOutcome::Exited(EXIT_REFUSED),
        "{:?}",
        run.outcome
    );
    assert!(decode_frame(&run.stdout).is_err());
}

#[test]
fn wi05_the_parser_spec_reads_only_its_input() {
    let Some(scene) = Scene::new(b"staged input") else {
        return;
    };
    let input = scene.input_dir.join(INPUT_NAME);
    assert_eq!(
        scene.probe(&["read", text(&input)]),
        0,
        "the input is readable"
    );
    let secret = scene.outside.join("secret.txt");
    assert_eq!(
        scene.probe(&["read", text(&secret)]),
        READ_FAILED,
        "another file was read"
    );
    assert_eq!(
        scene.uncontained(&["read", text(&secret)]),
        0,
        "positive control"
    );
}

#[test]
fn wi05_the_parser_spec_writes_nothing_outside_its_private_work_directory() {
    let Some(scene) = Scene::new(b"staged input") else {
        return;
    };
    for target in [
        scene.input_dir.join("dropped.txt"),
        scene.input_dir.join(INPUT_NAME),
        scene.outside.join("dropped.txt"),
    ] {
        assert_eq!(
            scene.probe(&["write", text(&target)]),
            WRITE_FAILED,
            "{}",
            target.display()
        );
    }
    assert_eq!(
        std::fs::read(scene.input_dir.join(INPUT_NAME)).unwrap(),
        b"staged input",
        "the input is unchanged"
    );
    assert!(!scene.outside.join("dropped.txt").exists());
    let control = scene.outside.join("control.txt");
    assert_eq!(
        scene.uncontained(&["write", text(&control)]),
        0,
        "positive control"
    );
}

#[test]
fn wi05_the_parser_spec_has_no_network() {
    let Some(scene) = Scene::new(b"staged input") else {
        return;
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    assert_eq!(scene.probe(&["connect", &address]), NETWORK_FAILED);
    assert_eq!(
        scene.uncontained(&["connect", &address]),
        0,
        "positive control"
    );
}

#[test]
fn wi05_the_parser_spec_cannot_create_processes() {
    let Some(scene) = Scene::new(b"staged input") else {
        return;
    };
    assert_eq!(scene.probe(&["spawn"]), SPAWN_FAILED);
    assert_eq!(scene.uncontained(&["spawn"]), 0, "positive control");
}

#[test]
fn wi05_a_run_past_its_timeout_is_killed() {
    let Some(scene) = Scene::new(b"staged input") else {
        return;
    };
    let mut spec = scene.probe_spec(&["spin"]);
    spec.limits.timeout = Duration::from_secs(2);
    let started = Instant::now();
    let run = scene.run(&spec);
    assert!(
        matches!(
            run.outcome,
            ContainedOutcome::TimedOut | ContainedOutcome::ResourceLimit
        ),
        "{:?}",
        run.outcome
    );
    assert!(started.elapsed() < Duration::from_secs(20));
}

/// A bounded mutation run of the normal fixtures under containment: whatever
/// a mutant does to the parser, the result is a well-formed frame whose kind
/// matches the exit status, or a crash the helper reports. No crash escapes
/// the contained process. `ORCEL_WI05_FUZZ_CASES` raises the count.
///
/// `ORCEL_WI05_FUZZ_SECONDS` switches to a timed run (#389, the manually
/// dispatched `doc-parser-fuzz` job): a wider corpus, mutated until the time
/// is up, with `ORCEL_WI05_FUZZ_SEED` to vary the sequence. A crash, ceiling
/// or timeout is contained and counted; with `ORCEL_WI05_FUZZ_CRASH_DIR` set
/// its input is kept there so it can be replayed under containment.
#[test]
fn wi05_mutated_inputs_never_escape_the_contained_process() {
    let cases: usize = std::env::var("ORCEL_WI05_FUZZ_CASES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(12);
    let timed = std::env::var("ORCEL_WI05_FUZZ_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(|seconds| Instant::now() + Duration::from_secs(seconds));
    let mut seed = std::env::var("ORCEL_WI05_FUZZ_SEED")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|seed| *seed != 0)
        .unwrap_or(0x9e37_79b9_u32);
    eprintln!("wi05 mutation run: seed {seed}, timed {}", timed.is_some());
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        seed as usize
    };
    let mut corpus = vec![("pdf", fixtures::text_pdf()), ("docx", fixtures::docx())];
    if timed.is_some() {
        corpus.extend([
            ("pptx", fixtures::pptx(3)),
            ("object-stream pdf", fixtures::object_stream_member_pdf(2)),
            ("bare-name pdf", fixtures::bare_struct_name_pdf()),
            (
                "repeated-form pdf",
                fixtures::repeated_form_pdf(4, 1 + 258 * 4),
            ),
        ]);
    }
    let crash_dir = std::env::var_os("ORCEL_WI05_FUZZ_CRASH_DIR").map(PathBuf::from);
    let (mut total, mut contained_crashes) = (0usize, 0usize);
    let mut case = 0usize;
    loop {
        match timed {
            Some(deadline) if Instant::now() >= deadline => break,
            None if case >= cases => break,
            _ => {}
        }
        for (name, original) in &corpus {
            let mut bytes = original.clone();
            for _ in 0..1 + next() % 8 {
                let at = next() % bytes.len();
                bytes[at] = (next() % 256) as u8;
            }
            if next() % 4 == 0 {
                bytes.truncate(next() % bytes.len());
            }
            let Some(scene) = Scene::new(&bytes) else {
                return;
            };
            let run = scene.run(&scene.parser_spec());
            total += 1;
            match run.outcome {
                ContainedOutcome::Exited(0) => {
                    assert!(decode_frame(&run.stdout).is_ok(), "{name} case {case}")
                }
                ContainedOutcome::Exited(code) if code == EXIT_REFUSED => assert!(
                    matches!(decode_frame(&run.stdout), Err(FrameError::Refused(_))),
                    "{name} case {case}"
                ),
                // A crash, a ceiling or the timeout: contained and reported.
                other => {
                    contained_crashes += 1;
                    eprintln!("{name} case {case}: contained crash {other:?}");
                    if let Some(dir) = &crash_dir {
                        let _ = std::fs::create_dir_all(dir);
                        let _ = std::fs::write(dir.join(format!("crash-{total}.bin")), &bytes);
                    }
                }
            }
        }
        case += 1;
    }
    eprintln!("wi05 mutation run: {total} contained runs, {contained_crashes} contained crashes");
}
