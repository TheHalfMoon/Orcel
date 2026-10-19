//! XP-13 kernel-side tests of the contained-tier client: the pin, the spec
//! bound and the result parser. They need no helper binary; the end-to-end
//! tests that drive the real helper live in `apps/orcel-contain/tests/`.

use super::*;
use sha2::Digest as _;

fn scratch(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("xp13-{label}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap();
    std::fs::canonicalize(path).unwrap()
}

fn spec_in(dir: &Path) -> ContainedSpec {
    ContainedSpec {
        executable: dir.join("parser"),
        argv: vec!["--input".into(), "a b".into()],
        workdir: dir.to_path_buf(),
        readable: Vec::new(),
        writable: Vec::new(),
        limits: ContainedLimits {
            timeout: Duration::from_secs(5),
            stdout_bytes: 1024,
            stderr_bytes: 512,
            memory_bytes: 1 << 30,
            cpu_seconds: 10,
            open_files: 64,
        },
    }
}

#[test]
fn xp13_sha256_matches_the_standard_vectors_and_the_sha2_crate() {
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    for length in (0..300).chain([1000, 4096, 65_537]) {
        let data: Vec<u8> = (0..length).map(|index| (index * 31 % 251) as u8).collect();
        assert_eq!(
            sha256(&data).to_vec(),
            sha2::Sha256::digest(&data).to_vec(),
            "length {length}"
        );
    }
}

#[test]
fn xp13_the_spec_encodes_in_the_documented_format() {
    let dir = scratch("encode");
    let encoded = String::from_utf8(encode_spec(&spec_in(&dir), 42).unwrap()).unwrap();
    let mut lines = encoded.lines();
    assert_eq!(lines.next(), Some("orcel-contain-spec 1"));
    assert_eq!(lines.next(), Some("parent 42"));
    assert_eq!(
        lines.next(),
        Some(
            format!(
                "exe {}",
                encode_hex(dir.join("parser").to_str().unwrap().as_bytes())
            )
            .as_str()
        )
    );
    assert_eq!(
        lines.next(),
        Some(format!("arg {}", encode_hex(b"--input")).as_str())
    );
    assert_eq!(
        lines.next(),
        Some(format!("arg {}", encode_hex(b"a b")).as_str())
    );
    assert!(encoded.ends_with(
        "memory 1073741824\ncpu 10\ntimeout_ms 5000\nstdout 1024\nstderr 512\nfiles 64\nend\n"
    ));
}

#[test]
fn xp13_an_oversize_spec_is_refused_before_the_helper_starts() {
    let dir = scratch("oversize");
    let mut spec = spec_in(&dir);
    spec.argv = (0..200).map(|_| "x".repeat(400)).collect();
    assert_eq!(encode_spec(&spec, 42), Err(ContainedError::SpecTooLarge));
    // The helper path does not even need to exist: nothing is launched.
    let pin = HelperPin::new(dir.join("no-such-helper"), &"0".repeat(64)).unwrap();
    assert_eq!(
        run_contained(&pin, &spec),
        Err(ContainedError::SpecTooLarge)
    );
}

#[test]
fn xp13_out_of_range_limits_and_relative_paths_are_refused() {
    let dir = scratch("limits");
    let base = spec_in(&dir);
    let mut broken = Vec::new();
    for change in 0..7 {
        let mut spec = base.clone();
        match change {
            0 => spec.limits.timeout = Duration::ZERO,
            1 => spec.limits.stdout_bytes = 0,
            2 => spec.limits.memory_bytes = 1,
            3 => spec.limits.cpu_seconds = 0,
            4 => spec.limits.open_files = 1,
            5 => spec.executable = PathBuf::from("parser"),
            _ => spec.readable = vec![PathBuf::from("relative/root")],
        }
        broken.push(spec);
    }
    for spec in broken {
        assert!(
            matches!(encode_spec(&spec, 42), Err(ContainedError::InvalidSpec(_))),
            "accepted {spec:?}"
        );
    }
}

#[test]
fn xp13_a_pin_needs_an_absolute_path_and_a_full_digest() {
    assert!(matches!(
        HelperPin::new("orcel-contain", &"0".repeat(64)),
        Err(ContainedError::HelperNotPinned(_))
    ));
    let dir = scratch("pin");
    for digest in ["", "abc", &"0".repeat(63), &"g".repeat(64), &"A".repeat(64)] {
        assert!(
            matches!(
                HelperPin::new(dir.join("orcel-contain"), digest),
                Err(ContainedError::HelperNotPinned(_))
            ),
            "accepted digest {digest:?}"
        );
    }
}

#[test]
fn xp13_a_missing_helper_is_not_pinned() {
    let dir = scratch("missing");
    let pin = HelperPin::new(dir.join("orcel-contain"), &"0".repeat(64)).unwrap();
    assert!(matches!(
        run_contained(&pin, &spec_in(&dir)),
        Err(ContainedError::HelperNotPinned(_))
    ));
}

#[test]
fn xp13_a_helper_whose_bytes_differ_from_the_pin_is_refused() {
    let dir = scratch("tampered");
    let helper = dir.join("orcel-contain");
    std::fs::write(&helper, b"the pinned helper bytes").unwrap();
    let pin = HelperPin::new(&helper, &sha256_hex(b"the pinned helper bytes")).unwrap();
    // Changing one byte after the pin was taken is tampering.
    std::fs::write(&helper, b"the pinned helper bytez").unwrap();
    assert_eq!(
        run_contained(&pin, &spec_in(&dir)),
        Err(ContainedError::HelperTampered)
    );
    // So is a digest that never matched.
    let other = HelperPin::new(&helper, &sha256_hex(b"something else")).unwrap();
    assert_eq!(
        run_contained(&other, &spec_in(&dir)),
        Err(ContainedError::HelperTampered)
    );
}

/// A tampered helper is never executed: the script would leave a marker.
#[cfg(unix)]
#[test]
fn xp13_a_tampered_helper_is_never_started() {
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch("never-started");
    let marker = dir.join("started");
    let helper = dir.join("orcel-contain");
    let script = format!("#!/bin/sh\ntouch '{}'\n", marker.display());
    std::fs::write(&helper, &script).unwrap();
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let pin = HelperPin::new(&helper, &sha256_hex(b"#!/bin/sh\ntrue\n")).unwrap();
    assert_eq!(
        run_contained(&pin, &spec_in(&dir)),
        Err(ContainedError::HelperTampered)
    );
    std::thread::sleep(Duration::from_millis(200));
    assert!(!marker.exists(), "the tampered helper ran");
}

#[cfg(unix)]
#[test]
fn xp13_a_linked_or_shared_writable_helper_is_not_pinned() {
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch("unix-pin");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let helper = dir.join("orcel-contain");
    std::fs::write(&helper, b"helper").unwrap();
    let digest = sha256_hex(b"helper");

    let link = dir.join("link");
    std::os::unix::fs::symlink(&helper, &link).unwrap();
    let pin = HelperPin::new(&link, &digest).unwrap();
    assert!(matches!(
        run_contained(&pin, &spec_in(&dir)),
        Err(ContainedError::HelperNotPinned(_))
    ));

    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o775)).unwrap();
    let pin = HelperPin::new(&helper, &digest).unwrap();
    assert!(matches!(
        run_contained(&pin, &spec_in(&dir)),
        Err(ContainedError::HelperNotPinned(_))
    ));

    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(matches!(
        run_contained(&pin, &spec_in(&dir)),
        Err(ContainedError::HelperNotPinned(_))
    ));
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn result(header: &str, body: &[u8]) -> Vec<u8> {
    let mut bytes = header.as_bytes().to_vec();
    bytes.extend_from_slice(body);
    bytes
}

#[test]
fn xp13_a_well_formed_result_is_parsed_with_exact_output() {
    let limits = spec_in(&scratch("result")).limits;
    let parsed = parse_result(
        &result("orcel-contain-result 1 exited 7 3 2 -\n", b"outer"),
        &limits,
    )
    .unwrap();
    let Parsed::Run(run) = parsed else {
        panic!("a run was parsed as a refusal");
    };
    assert_eq!(run.outcome, ContainedOutcome::Exited(7));
    assert_eq!(run.stdout, b"out");
    assert_eq!(run.stderr, b"er");

    let refused = parse_result(
        &result(
            &format!(
                "orcel-contain-result 1 refused 0 0 0 {}\n",
                encode_hex(b"unsupported_platform: no Landlock")
            ),
            b"",
        ),
        &limits,
    )
    .unwrap();
    assert!(matches!(
        refused,
        Parsed::Refused { kind: RefusalKind::UnsupportedPlatform, ref message } if message == "no Landlock"
    ));
}

#[test]
fn xp13_a_result_that_breaks_its_bounds_or_shape_is_rejected() {
    let limits = spec_in(&scratch("bounds")).limits;
    let oversize = vec![b'o'; limits.stdout_bytes + 1];
    for bytes in [
        result(
            &format!("orcel-contain-result 1 exited 0 {} 0 -\n", oversize.len()),
            &oversize,
        ),
        result("orcel-contain-result 1 exited 0 3 0 -\n", b"ou"),
        result("orcel-contain-result 1 exited 0 3 0 -\n", b"outx"),
        result("orcel-contain-result 1 exited 0 0 0\n", b""),
        result("orcel-contain-result 1 parent_gone 0 0 0 -\n", b""),
        result("orcel-contain-result 1 escaped 0 0 0 -\n", b""),
        result("orcel-contain-result 2 exited 0 0 0 -\n", b""),
        result("orcel-contain-result 1 exited 0 0 0 6162\n", b""),
        result("orcel-contain-result 1 refused 0 1 0 6162\n", b"o"),
        result(
            &format!(
                "orcel-contain-result 1 refused 0 0 0 {}\n",
                encode_hex(b"maybe_later: try again")
            ),
            b"",
        ),
        vec![b'x'; MAX_HEADER_BYTES + 10],
    ] {
        assert!(
            matches!(
                parse_result(&bytes, &limits),
                Err(ContainedError::Helper(_))
            ),
            "accepted {:?}",
            String::from_utf8_lossy(&bytes[..bytes.len().min(80)])
        );
    }
}

/// A spec root reached through a link is refused before the helper starts.
#[cfg(unix)]
#[test]
fn xp13_a_symlinked_spec_root_is_refused_before_the_helper_starts() {
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch("linked-root");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let helper = dir.join("orcel-contain");
    // Not executable and never started: the spec check comes first.
    std::fs::write(&helper, b"helper").unwrap();
    let pin = HelperPin::new(&helper, &sha256_hex(b"helper")).unwrap();
    let outside = scratch("linked-target");
    let link = dir.join("out");
    std::os::unix::fs::symlink(&outside, &link).unwrap();
    std::fs::write(dir.join("parser"), b"parser").unwrap();
    let mut spec = spec_in(&dir);
    spec.readable = vec![link];
    assert!(matches!(
        run_contained(&pin, &spec),
        Err(ContainedError::InvalidSpec(_))
    ));
}
