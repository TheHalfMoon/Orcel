use super::*;

fn document(markdown: &str) -> ParsedDocument {
    ParsedDocument {
        format: DocumentFormat::Pdf,
        pages: 2,
        chars: markdown.chars().count(),
        truncated: false,
        markdown: markdown.to_owned(),
    }
}

#[test]
fn an_ok_frame_round_trips() {
    let parsed = document("# Title\n\nbody é");
    assert_eq!(decode_frame(&encode_ok(&parsed)), Ok(parsed));
}

#[test]
fn every_refusal_round_trips() {
    for refusal in ParseRefusal::ALL {
        assert_eq!(
            decode_frame(&encode_refusal(refusal)),
            Err(FrameError::Refused(refusal))
        );
    }
}

#[test]
fn malformed_frames_are_broken_not_accepted() {
    let good = encode_ok(&document("abc"));
    let mut trailing = good.clone();
    trailing.push(b'x');
    let mut short = good.clone();
    short.pop();
    let cases: Vec<Vec<u8>> = vec![
        Vec::new(),
        b"no newline".to_vec(),
        b"orcel-doc-parser/2 ok pdf 1 3 0 3\nabc".to_vec(),
        b"orcel-doc-parser/1 ok pdf 1 3 0\nabc".to_vec(),
        b"orcel-doc-parser/1 ok exe 1 3 0 3\nabc".to_vec(),
        b"orcel-doc-parser/1 ok pdf 1 4 0 3\nabc".to_vec(),
        b"orcel-doc-parser/1 ok pdf 1 3 2 3\nabc".to_vec(),
        b"orcel-doc-parser/1 ok pdf 01 3 0 3\nabc".to_vec(),
        b"orcel-doc-parser/1 ok pdf 501 3 0 3\nabc".to_vec(),
        b"orcel-doc-parser/1 ok pdf 1 2 0 2\n\xff\xfe".to_vec(),
        b"orcel-doc-parser/1 error encrypted\nleak".to_vec(),
        b"orcel-doc-parser/1 error something_else\n".to_vec(),
        trailing,
        short,
    ];
    for case in cases {
        assert!(
            matches!(decode_frame(&case), Err(FrameError::Broken(_))),
            "{:?}",
            String::from_utf8_lossy(&case)
        );
    }
}

#[test]
fn the_spec_grants_only_the_input_directory_read_only() {
    let input = std::env::temp_dir().join("wi05-spec-input");
    let work = std::env::temp_dir().join("wi05-spec-work");
    let parser = std::env::temp_dir().join("orcel-doc-parser");
    let spec = spec(parser.clone(), &input, work.clone());
    assert_eq!(spec.executable, parser);
    assert_eq!(
        spec.argv,
        vec![input.join(INPUT_NAME).to_string_lossy().into_owned()]
    );
    assert_eq!(spec.readable, vec![input]);
    assert!(spec.writable.is_empty());
    assert_eq!(spec.workdir, work);
    spec.limits
        .validate()
        .expect("limits within the helper's ranges");
    assert_eq!(spec.limits.timeout, Duration::from_secs(30));
    assert!(spec.limits.stdout_bytes >= MAX_CHARS * 4);
}
