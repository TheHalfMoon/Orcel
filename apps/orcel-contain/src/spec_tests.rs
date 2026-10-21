//! Unit tests for `spec.rs`.

use super::*;

fn line(key: &str, text: &str) -> String {
    format!("{key} {}\n", encode_hex(text.as_bytes()))
}

fn sha256_line(digest: &str) -> String {
    format!("sha256 {digest}\n")
}

fn sample() -> String {
    let (exe, work) = if cfg!(windows) {
        (r"C:\orcel\parser.exe", r"C:\orcel\work")
    } else {
        ("/opt/orcel/parser", "/opt/orcel/work")
    };
    let mut spec = format!("{SPEC_MAGIC}\nparent 42\n");
    spec += &line("exe", exe);
    spec += &sha256_line(&"ab".repeat(32));
    spec += &line("arg", "--input");
    spec += &line("arg", "a b");
    spec += &line("workdir", work);
    spec += "memory 1073741824\ncpu 10\ntimeout_ms 5000\nstdout 1024\nstderr 512\nfiles 64\nend\n";
    spec
}

#[test]
fn a_well_formed_spec_round_trips_every_field() {
    let spec = parse(sample().as_bytes()).unwrap();
    assert_eq!(spec.parent, 42);
    assert_eq!(spec.executable_sha256, [0xab; 32]);
    assert_eq!(spec.args, vec!["--input".to_owned(), "a b".to_owned()]);
    assert!(spec.read.is_empty() && spec.write.is_empty());
    assert_eq!(spec.memory_bytes, 1 << 30);
    assert_eq!(spec.cpu_seconds, 10);
    assert_eq!(spec.timeout_ms, 5000);
    assert_eq!((spec.stdout_bytes, spec.stderr_bytes), (1024, 512));
    assert_eq!(spec.open_files, 64);
}

#[test]
fn an_oversize_spec_is_refused_without_reading_past_the_bound() {
    struct Endless(usize);
    impl std::io::Read for Endless {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            self.0 += buffer.len();
            buffer.fill(b'a');
            Ok(buffer.len())
        }
    }
    let mut input = Endless(0);
    assert_eq!(read_spec(&mut input), Err(SpecError::TooLarge));
    assert!(input.0 <= MAX_SPEC_BYTES + 1, "read {} bytes", input.0);

    let mut padded = sample().replace("end\n", "");
    while padded.len() <= MAX_SPEC_BYTES {
        padded += &line("arg", &"x".repeat(100));
    }
    padded += "end\n";
    assert_eq!(read_spec(&mut padded.as_bytes()), Err(SpecError::TooLarge));
}

#[test]
fn unknown_repeated_missing_and_out_of_range_keys_are_refused() {
    let base = sample();
    for broken in [
        base.replace("files 64\n", "files 64\nnetwork 1\n"),
        base.replace("cpu 10\n", "cpu 10\ncpu 11\n"),
        base.replace("files 64\n", ""),
        base.replace("cpu 10\n", "cpu 0\n"),
        base.replace("memory 1073741824\n", "memory 1\n"),
        base.replace("stdout 1024\n", "stdout 99999999999\n"),
        base.replace("timeout_ms 5000\n", "timeout_ms -5\n"),
        base.replace(SPEC_MAGIC, "orcel-contain-spec 1"),
        base.replace(SPEC_MAGIC, "orcel-contain-spec 3"),
        base.replace("end\n", ""),
        base.replace("parent 42\n", "parent 0\n"),
        // #384 item 2: the digest is required, once, as 64 lower-case hex.
        base.replace(&sha256_line(&"ab".repeat(32)), ""),
        base.replace(
            &sha256_line(&"ab".repeat(32)),
            &sha256_line(&"AB".repeat(32)),
        ),
        base.replace(
            &sha256_line(&"ab".repeat(32)),
            &sha256_line(&"ab".repeat(31)),
        ),
        base.replace(
            &sha256_line(&"ab".repeat(32)),
            &(sha256_line(&"ab".repeat(32)) + &sha256_line(&"cd".repeat(32))),
        ),
    ] {
        assert!(
            matches!(parse(broken.as_bytes()), Err(SpecError::Invalid(_))),
            "accepted:\n{broken}"
        );
    }
}

#[test]
fn relative_paths_nul_and_non_hex_values_are_refused() {
    let base = sample();
    let exe = base
        .lines()
        .find(|l| l.starts_with("exe "))
        .unwrap()
        .to_owned();
    for replacement in [
        line("exe", "parser"),
        line("exe", "/opt/orcel/\0parser"),
        "exe 2F6F7074\n".to_owned(),
        "exe zz\n".to_owned(),
        "exe \n".to_owned(),
    ] {
        let broken = base.replace(&format!("{exe}\n"), &replacement);
        assert!(parse(broken.as_bytes()).is_err(), "accepted:\n{broken}");
    }
}

#[test]
fn bytes_after_the_end_line_are_a_protocol_violation() {
    let spec = sample() + "x";
    assert!(matches!(
        read_spec(&mut spec.as_bytes()),
        Err(SpecError::Invalid(_))
    ));
}

#[test]
fn the_result_header_has_the_documented_shape() {
    assert_eq!(
        result_header("exited", 7, 3, 0, None),
        "orcel-contain-result 1 exited 7 3 0 -\n"
    );
    assert_eq!(
        result_header("refused", 0, 0, 0, Some("ab")),
        "orcel-contain-result 1 refused 0 0 0 6162\n"
    );
    assert_eq!(decode_hex("6162"), Some(b"ab".to_vec()));
}
