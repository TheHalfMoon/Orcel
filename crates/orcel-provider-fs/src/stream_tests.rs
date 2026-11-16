//! Windows alternate data streams and device names: every filesystem entry point refuses
//! them with the same typed error, while ordinary files and the workspace root still work.

use super::*;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg_attr(not(windows), allow(dead_code))]
fn temp_root(name: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "orcel-fs-ads-{name}-{nanos}-{}",
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&root).expect("create temp root");
    root
}

/// The recognisers, on every host: they are pure functions of the spelling.
#[test]
fn stream_and_device_segments_are_recognised_in_any_case() {
    for segment in [
        "a.txt:s",
        "a.txt::$DATA",
        "a.txt:s:$DATA",
        "A.TXT:S:$data",
        "dir:$I30:$INDEX_ALLOCATION",
        "dir::$index_allocation",
        ":s",
        "NUL",
        "nul",
        "Nul.txt",
        "nul .txt",
        "CON",
        "con.tar.gz",
        "PRN",
        "aux",
        "COM1",
        "com9.log",
        "LPT0",
        "lpt\u{b9}",
        "COM\u{b3}",
        "CONIN$",
        "conout$",
    ] {
        assert!(is_windows_stream_or_device(segment), "{segment}");
    }
    for segment in [
        "a.txt",
        "a",
        "console.txt",
        "nuller",
        "nul_file",
        ".nul",
        "xcon",
        "COM",
        "COM10",
        "LPT",
        "lpt1x",
        "CONIN",
        "data$",
        "$DATA",
    ] {
        assert!(!is_windows_stream_or_device(segment), "{segment}");
    }
    for path in [
        "a.txt:s",
        "sub/a.txt::$DATA",
        "./sub/a.txt:s:$DATA",
        "sub:$I30:$INDEX_ALLOCATION/b.txt",
        "sub/nul",
        "x/../a.txt:s",
    ] {
        assert!(names_windows_stream(Path::new(path)), "{path}");
    }
    for path in ["", ".", "a.txt", "sub/b.txt", "sub/.hidden", "x/../a.txt"] {
        assert!(!names_windows_stream(Path::new(path)), "{path}");
    }
}

/// Drive letters and absolute paths on Windows: a drive prefix is not a stream, while a
/// drive-relative spelling (which `a:s` parses as) never names a workspace entry.
#[cfg(windows)]
#[test]
fn drive_prefixes_are_not_streams_but_drive_relative_paths_are_refused() {
    for path in [
        r"C:\ws\a.txt",
        r"c:\ws",
        r"C:\",
        r"\\server\share\a.txt",
        r"sub\b.txt",
    ] {
        assert!(!names_windows_stream(Path::new(path)), "{path}");
        assert!(!resolved_names_stream(Path::new(path)), "{path}");
    }
    for path in [
        "a:s",
        "C:x",
        "C:",
        r"C:\ws\a.txt:s",
        r"C:\ws\sub:$I30:$INDEX_ALLOCATION\b",
    ] {
        assert!(names_windows_stream(Path::new(path)), "{path}");
    }
    for path in [
        r"C:\ws\a.txt:s",
        r"C:\ws\a.txt:s:$DATA",
        r"C:\ws\sub:$I30:$INDEX_ALLOCATION\b.txt",
        r"\\server\share\a.txt:s",
    ] {
        assert!(resolved_names_stream(Path::new(path)), "{path}");
    }
}

/// Off Windows a colon is an ordinary name byte: the guard never refuses, and a file whose
/// name contains one stays readable.
#[cfg(not(windows))]
#[test]
fn colons_and_device_names_stay_ordinary_off_windows() {
    let root = std::env::temp_dir().join(format!(
        "orcel-fs-ads-unix-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("a.txt:s"), "colon").unwrap();
    fs::write(root.join("nul"), "plain").unwrap();
    let provider = FsProvider::new(&root).unwrap();
    assert!(refuse_windows_stream("a.txt:s").is_ok());
    assert_eq!(provider.read_text("a.txt:s").unwrap()["text"], "colon");
    assert_eq!(provider.stat("a.txt:s").unwrap()["kind"], "file");
    assert_eq!(provider.read_text("nul").unwrap()["text"], "plain");
    let _ = fs::remove_dir_all(root);
}

#[cfg(windows)]
const SECRET: &str = "hidden-stream-content";

/// A workspace holding `a.txt` (with an alternate stream `secret`) and `sub/b.txt` (with a
/// stream of its own).
#[cfg(windows)]
fn stream_workspace(name: &str) -> (PathBuf, FsProvider) {
    let root = temp_root(name);
    fs::write(root.join("a.txt"), "visible hello\n").unwrap();
    fs::write(root.join("a.txt:secret"), format!("{SECRET}\n")).unwrap();
    fs::create_dir(root.join("sub")).unwrap();
    fs::write(root.join("sub").join("b.txt"), "inner hello\n").unwrap();
    fs::write(root.join("sub").join("b.txt:secret"), format!("{SECRET}\n")).unwrap();
    // The streams are real: the platform itself reads them.
    assert_eq!(
        fs::read_to_string(root.join("a.txt:secret")).unwrap(),
        format!("{SECRET}\n")
    );
    let provider = FsProvider::new(&root).unwrap();
    (root, provider)
}

#[cfg(windows)]
const REFUSED_SPELLINGS: &[&str] = &[
    "a.txt:secret",
    "A.TXT:SECRET",
    "a.txt:secret:$DATA",
    "a.txt:Secret:$data",
    "a.txt::$DATA",
    "a.txt::$data",
    "sub:$I30:$INDEX_ALLOCATION",
    "sub::$INDEX_ALLOCATION",
    "sub:$I30:$INDEX_ALLOCATION/b.txt",
    r"sub:$I30:$INDEX_ALLOCATION\b.txt",
    "sub/b.txt:secret",
    r"sub\b.txt::$DATA",
    "./a.txt:secret",
    "sub/../a.txt:secret",
    "a:secret",
    "NUL",
    "nul.txt",
    "sub/CON",
    "CONIN$",
    "com1",
];

#[cfg(windows)]
fn assert_refused(result: Result<impl std::fmt::Debug, ProviderError>, what: &str) {
    let error = result.expect_err(what);
    assert_eq!(
        error.code,
        FailureCode::CapabilityDenied,
        "{what}: {error:?}"
    );
}

#[cfg(windows)]
#[test]
fn read_side_entry_points_refuse_every_stream_and_device_spelling() {
    let (root, provider) = stream_workspace("reads");
    for &path in REFUSED_SPELLINGS {
        assert_refused(provider.stat(path), &format!("stat {path}"));
        assert_refused(provider.list(path), &format!("list {path}"));
        assert_refused(provider.read_text(path), &format!("read_text {path}"));
        assert_refused(
            provider.read_bytes(path, 1024),
            &format!("read_bytes {path}"),
        );
        assert_refused(
            provider.read_range(path, 1, 10),
            &format!("read_range {path}"),
        );
        assert_refused(
            provider.search_text(path, "hello", None),
            &format!("search_text {path}"),
        );
        assert_refused(
            provider.find_names(path, "*", 10, 2),
            &format!("find_names {path}"),
        );
    }
    let _ = fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn mutation_entry_points_refuse_every_stream_and_device_spelling() {
    let (root, provider) = stream_workspace("mutations");
    for &path in REFUSED_SPELLINGS {
        assert_refused(
            provider.preview_write(path, "x"),
            &format!("preview_write {path}"),
        );
        assert_refused(
            provider.write_text(path, "x", None, true),
            &format!("write_text {path}"),
        );
        assert_refused(
            provider.create_text(path, "x"),
            &format!("create_text {path}"),
        );
        assert_refused(provider.mkdir(path, true), &format!("mkdir {path}"));
        assert_refused(
            provider.entry_identity(path),
            &format!("entry_identity {path}"),
        );
        assert_refused(
            provider.edit_preview(path, "hello", "bye", "0", 1),
            &format!("edit_preview {path}"),
        );
    }
    assert_eq!(
        fs::read_to_string(root.join("a.txt:secret")).unwrap(),
        format!("{SECRET}\n")
    );
    let _ = fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn ordinary_files_and_the_workspace_root_still_work_beside_streams() {
    let (root, provider) = stream_workspace("ordinary");
    for here in ["", "."] {
        assert_eq!(provider.stat(here).unwrap()["kind"], "directory");
        let names: Vec<String> = provider.list(here).unwrap()["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["name"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(names, ["a.txt", "sub"]);
    }
    assert_eq!(provider.stat("a.txt").unwrap()["kind"], "file");
    assert_eq!(provider.stat("sub").unwrap()["kind"], "directory");
    assert_eq!(provider.list("sub").unwrap()["entries"][0]["name"], "b.txt");
    assert_eq!(
        provider.read_text("a.txt").unwrap()["text"],
        "visible hello\n"
    );
    assert_eq!(
        provider.read_bytes("sub/b.txt", 1024).unwrap(),
        b"inner hello\n"
    );
    assert_eq!(
        provider.read_range(r"sub\b.txt", 1, 5).unwrap()["lines"][0],
        "inner hello"
    );
    // An absolute path inside the workspace keeps its drive letter and is not refused.
    let absolute = root.join("a.txt");
    assert!(absolute.to_string_lossy().contains(':'));
    assert_eq!(
        provider.read_text(&absolute.to_string_lossy()).unwrap()["text"],
        "visible hello\n"
    );
    assert_eq!(
        provider.stat(&root.to_string_lossy()).unwrap()["kind"],
        "directory"
    );
    // Search sees both main streams and never a hidden one.
    let found = provider.search_text("", "hello", None).unwrap();
    assert_eq!(found["matches"].as_array().unwrap().len(), 2);
    let hidden = provider.search_text("", SECRET, None).unwrap();
    assert!(hidden["matches"].as_array().unwrap().is_empty());
    let names = provider.find_names("", "*.txt", 10, 2).unwrap();
    assert_eq!(names["matches"].as_array().unwrap().len(), 2);
    // Ordinary mutations still go through.
    provider.create_text("sub/new.txt", "fresh").unwrap();
    assert_eq!(
        fs::read_to_string(root.join("sub/new.txt")).unwrap(),
        "fresh"
    );
    let _ = fs::remove_dir_all(root);
}

/// A link already inside the workspace whose target is a stream: its submitted spelling is
/// ordinary, so only the resolved-path check can refuse it.
#[cfg(windows)]
#[test]
fn a_link_to_a_stream_is_refused_by_its_resolved_path() {
    let (root, provider) = stream_workspace("link");
    // The real path the provider reads from an open stream handle names the stream, so the
    // resolved-path check sees it however the stream was reached.
    let stream = root.join("a.txt:secret");
    let opened = File::open(&stream).unwrap();
    let real = final_path_from_open_file(&opened, &stream).unwrap();
    assert!(real.to_string_lossy().ends_with("a.txt:secret"), "{real:?}");
    assert!(resolved_names_stream(&real));
    assert_refused(provider.ensure_within(&real), "resolved stream path");
    let real_root = provider.root().to_path_buf();
    assert!(provider.ensure_within(&real_root).is_ok());
    assert!(provider.ensure_within(&real_root.join("a.txt")).is_ok());

    let link = root.join("link.txt");
    if let Err(error) = std::os::windows::fs::symlink_file(&stream, &link) {
        // Creating a symbolic link needs Developer Mode or elevation. The resolved-path
        // decision is still pinned above on the real path of an open stream handle.
        eprintln!("skipping the live link check: symlink creation failed: {error}");
        let _ = fs::remove_dir_all(root);
        return;
    }
    // The platform follows the link into the stream.
    assert_eq!(fs::read_to_string(&link).unwrap(), format!("{SECRET}\n"));
    assert_refused(provider.stat("link.txt"), "stat through link");
    assert_refused(provider.read_text("link.txt"), "read_text through link");
    assert_refused(
        provider.read_bytes("link.txt", 1024),
        "read_bytes through link",
    );
    assert_refused(
        provider.read_range("link.txt", 1, 5),
        "read_range through link",
    );
    assert_refused(
        provider.search_text("link.txt", SECRET, None),
        "search_text through link",
    );
    assert_refused(
        provider.preview_write("link.txt", "x"),
        "preview_write through link",
    );
    assert_refused(
        provider.write_text("link.txt", "x", None, false),
        "write_text through link",
    );
    assert_refused(
        provider.edit_preview("link.txt", SECRET, "x", "0", 1),
        "edit_preview through link",
    );
    // A whole-tree search never reports the stream's content.
    let hidden = provider.search_text("", SECRET, None).unwrap();
    assert!(hidden["matches"].as_array().unwrap().is_empty());
    assert_eq!(
        fs::read_to_string(root.join("a.txt:secret")).unwrap(),
        format!("{SECRET}\n")
    );
    let _ = fs::remove_file(&link);
    let _ = fs::remove_dir_all(root);
}
