//! What a repository must look like before the provider runs Git in it:
//! its index, pointer files, nested folders and recorded state (review of
//! #849). Real Git, local folders only.

use orcel_provider_git::GitProvider;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT: AtomicU64 = AtomicU64::new(0);

fn temp_root(label: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "orcel-shape-{label}-{}-{suffix}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&root).expect("temp root");
    root
}

fn git(cwd: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .expect("git");
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn repository(at: &Path) {
    fs::create_dir_all(at).expect("repository");
    git(at, &["init", "-q", "-b", "main"]);
    git(at, &["config", "user.email", "orcel@example.invalid"]);
    git(at, &["config", "user.name", "Orcel Test"]);
    git(at, &["config", "core.autocrlf", "false"]);
    fs::write(at.join("a.txt"), "a\n").expect("a");
    git(at, &["add", "."]);
    git(at, &["commit", "-q", "-m", "initial"]);
}

/// A folder link: a junction on Windows (no privilege), a symlink elsewhere.
fn link(at: &Path, target: &Path) {
    #[cfg(windows)]
    {
        let made = Command::new("cmd")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(at)
            .arg(target)
            .output()
            .expect("mklink");
        assert!(made.status.success());
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, at).expect("symlink");
}

/// Writes `repo`'s index (version 2) with the given names, each the blob of
/// `a.txt`. Git does not verify the trailing hash when it reads.
fn write_index(repo: &Path, names: &[&[u8]]) {
    let id = git(repo, &["rev-parse", "HEAD:a.txt"]);
    let id: Vec<u8> = (0..20)
        .map(|at| u8::from_str_radix(&id[at * 2..at * 2 + 2], 16).expect("hex"))
        .collect();
    let mut names: Vec<&[u8]> = names.to_vec();
    names.sort_unstable();
    let mut index = b"DIRC".to_vec();
    index.extend(2u32.to_be_bytes());
    index.extend(u32::try_from(names.len()).expect("few").to_be_bytes());
    for name in names {
        let start = index.len();
        index.extend([0u8; 24]);
        index.extend(0o100_644u32.to_be_bytes());
        index.extend([0u8; 12]);
        index.extend(&id);
        index.extend(
            u16::try_from(name.len().min(0xFFF))
                .expect("len")
                .to_be_bytes(),
        );
        index.extend(name);
        index.push(0);
        while (index.len() - start) % 8 != 0 {
            index.push(0);
        }
    }
    index.extend([0u8; 20]);
    fs::write(repo.join(".git").join("index"), index).expect("index");
}

/// The operations that ran.
fn ran(provider: &GitProvider) -> Vec<&'static str> {
    let paths = vec!["a.txt".to_owned()];
    let mut ran = Vec::new();
    for (name, ok) in [
        ("status", provider.status(".").is_ok()),
        ("diff", provider.diff(".", false).is_ok()),
        ("staged diff", provider.diff(".", true).is_ok()),
        ("path state", provider.path_state(".", &paths).is_ok()),
        ("unstage state", provider.unstage_state(".", &paths).is_ok()),
        ("staged state", provider.staged_state(".").is_ok()),
        ("branch state", provider.branch_state(".").is_ok()),
    ] {
        if ok {
            ran.push(name);
        }
    }
    ran
}

#[test]
fn an_index_with_a_name_that_is_not_a_plain_path_is_refused() {
    let root = temp_root("index");
    let repo = root.join("repo");
    repository(&repo);
    fs::write(root.join("outside.txt"), "outside\n").expect("outside");
    let absolute = root
        .join("outside.txt")
        .display()
        .to_string()
        .replace('\\', "/");
    let mut names: Vec<Vec<u8>> = vec![
        absolute.into_bytes(),
        b"../outside.txt".to_vec(),
        b"x/../../outside.txt".to_vec(),
        b"x/./a.txt".to_vec(),
        b"x//a.txt".to_vec(),
        b"/a.txt".to_vec(),
        b".git/config".to_vec(),
        b"x/.GIT/config".to_vec(),
        b"x/git~1/config".to_vec(),
        b"x/\xff\xfe".to_vec(),
        "x/.g\u{200c}it/config".as_bytes().to_vec(),
    ];
    if cfg!(windows) {
        names.extend([
            b"C:outside.txt".to_vec(),
            b"x\\y.txt".to_vec(),
            b"x/a:b".to_vec(),
            b"x/.. /outside.txt".to_vec(),
            b"x/.git./config".to_vec(),
            b"x/nul".to_vec(),
            b"x/COM1.txt".to_vec(),
        ]);
    }
    for name in &names {
        write_index(&repo, &[b"a.txt", name]);
        let provider = GitProvider::new(&repo).expect("provider");
        let ran = ran(&provider);
        assert!(
            ran.is_empty(),
            "{:?}: {ran:?}",
            String::from_utf8_lossy(name)
        );
    }
    // After so many others that a bounded listing would miss it.
    let many: Vec<String> = (0..40_000)
        .map(|at| format!("folder/{}-{at:06}.txt", "n".repeat(60)))
        .collect();
    let mut all: Vec<&[u8]> = many.iter().map(|name| name.as_bytes()).collect();
    all.push(b"z/../../outside.txt");
    write_index(&repo, &all);
    let provider = GitProvider::new(&repo).expect("provider");
    assert!(provider.status(".").is_err());
    assert!(provider.diff(".", false).is_err());
    // A large index of plain names is checked in full and accepted.
    all.pop();
    write_index(&repo, &all);
    assert!(provider.branch_state(".").is_ok());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn recorded_conflict_resolutions_are_neither_present_nor_used() {
    let root = temp_root("rerere");
    let repo = root.join("repo");
    repository(&repo);
    let provider = GitProvider::new(&repo).expect("provider");
    assert!(provider.status(".").is_ok());
    let merge = repo.join(".git").join("MERGE_RR");
    fs::write(&merge, "").expect("MERGE_RR");
    assert!(ran(&provider).is_empty(), "MERGE_RR");
    fs::remove_file(&merge).expect("remove");
    let cache = repo.join(".git").join("rr-cache");
    fs::create_dir(&cache).expect("rr-cache");
    assert!(ran(&provider).is_empty(), "rr-cache");
    fs::remove_dir(&cache).expect("remove");
    git(&repo, &["config", "rerere.enabled", "true"]);
    assert!(ran(&provider).is_empty(), "rerere.enabled");
    git(&repo, &["config", "--unset", "rerere.enabled"]);
    assert!(provider.status(".").is_ok());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_git_file_is_accepted_only_in_gits_own_form() {
    let root = temp_root("gitfile");
    let repo = root.join("repo");
    repository(&repo);
    let separate = root.join("separate");
    fs::rename(repo.join(".git"), &separate).expect("move");
    let at = separate.display().to_string().replace('\\', "/");
    let dot_git = repo.join(".git");
    let provider = GitProvider::new(&root).expect("provider");
    let mut refused: Vec<Vec<u8>> = vec![
        format!("gitdir:{at}\n").into_bytes(),
        format!("gitdir:  {at}\n").into_bytes(),
        format!("gitdir: {at} \n").into_bytes(),
        format!("gitdir: {at}\t\n").into_bytes(),
        format!("gitdir: {at}\u{a0}\n").into_bytes(),
        format!("gitdir: \u{2003}{at}\n").into_bytes(),
        format!("gitdir: {at}\nmore\n").into_bytes(),
        format!("\u{feff}gitdir: {at}\n").into_bytes(),
        format!("GITDIR: {at}\n").into_bytes(),
        format!(" gitdir: {at}\n").into_bytes(),
        b"gitdir: \n".to_vec(),
        b"".to_vec(),
    ];
    if cfg!(windows) {
        let rest = at[2..].to_owned();
        refused.extend([
            format!("gitdir: {rest}\n").into_bytes(),
            format!("gitdir: {}\n", rest.replace('/', "\\")).into_bytes(),
            format!("gitdir: {}../separate\n", &at[..2]).into_bytes(),
            format!("gitdir: {at}.\n").into_bytes(),
            format!("gitdir: {at}::$INDEX_ALLOCATION\n").into_bytes(),
        ]);
    }
    for text in &refused {
        fs::write(&dot_git, text).expect(".git");
        assert!(
            provider.status("repo").is_err(),
            "{:?}",
            String::from_utf8_lossy(text)
        );
    }
    for text in [
        format!("gitdir: {at}\n"),
        format!("gitdir: {at}"),
        format!("gitdir: {at}\r\n"),
        "gitdir: ../separate\n".to_owned(),
    ] {
        fs::write(&dot_git, &text).expect(".git");
        let status = provider.status("repo");
        assert!(status.is_ok(), "{text:?}: {status:?}");
    }
    // The common directory's pointer has the same form.
    fs::write(&dot_git, format!("gitdir: {at}\n")).expect(".git");
    for text in [" .\n", ".\nmore\n", "\u{a0}.\n", ". \n", "\u{feff}.\n"] {
        fs::write(separate.join("commondir"), text).expect("commondir");
        assert!(provider.status("repo").is_err(), "commondir {text:?}");
    }
    let _ = fs::remove_dir_all(&root);
}

/// Git skips a `.git` it does not accept and looks further up; the provider
/// refuses instead, so the repository it checked is the one Git uses.
#[test]
fn a_git_folder_git_would_skip_is_refused() {
    let root = temp_root("skip");
    repository(&root);
    let sub = root.join("sub");
    fs::create_dir_all(sub.join(".git")).expect("sub");
    let provider = GitProvider::new(&root).expect("provider");
    assert!(provider.log("sub", 1).is_err(), "an empty .git");
    fs::write(sub.join(".git").join("HEAD"), "nothing\n").expect("HEAD");
    fs::create_dir_all(sub.join(".git").join("objects")).expect("objects");
    fs::create_dir_all(sub.join(".git").join("refs")).expect("refs");
    assert!(provider.log("sub", 1).is_err(), "no valid HEAD");
    let _ = fs::remove_dir_all(&root);
}

/// Git walks a nested folder whose `.git` it does not accept, and one it
/// tracks files in, so the check goes on there too.
#[test]
fn nested_folders_git_walks_are_checked() {
    let pointer = "gitdir: //orcel-unreachable.invalid/share/x\n";
    let root = temp_root("nested");
    for (name, fill) in [("empty", None), ("not-a-pointer", Some("something else\n"))] {
        let repo = root.join(name);
        repository(&repo);
        let nested = repo.join("nested");
        let deeper = nested.join("deeper");
        fs::create_dir_all(&deeper).expect("deeper");
        match fill {
            None => fs::create_dir(nested.join(".git")).expect(".git"),
            Some(text) => fs::write(nested.join(".git"), text).expect(".git"),
        }
        fs::write(deeper.join(".git"), pointer).expect("pointer");
        let provider = GitProvider::new(&repo).expect("provider");
        assert!(provider.status(".").is_err(), "{name}");
    }
    // A nested repository the outer index has files in.
    let repo = root.join("tracked");
    repository(&repo);
    let nested = repo.join("Nested");
    let deeper = nested.join("deeper");
    fs::create_dir_all(&deeper).expect("deeper");
    fs::write(nested.join("t.txt"), "t\n").expect("t");
    git(&repo, &["add", "Nested/t.txt"]);
    git(&nested, &["init", "-q"]);
    fs::write(deeper.join(".git"), pointer).expect("pointer");
    let provider = GitProvider::new(&repo).expect("provider");
    assert!(provider.status(".").is_err(), "tracked");
    // A nested repository without: Git stops there.
    let repo = root.join("plain");
    repository(&repo);
    let nested = repo.join("nested");
    fs::create_dir_all(&nested).expect("nested");
    repository(&nested);
    let provider = GitProvider::new(&repo).expect("provider");
    assert!(provider.status(".").is_ok());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn the_object_store_is_the_repositorys_own() {
    let root = temp_root("objects");
    let other = root.join("other");
    repository(&other);
    for (name, link_info) in [
        ("alternates", false),
        ("http-alternates", false),
        ("", true),
    ] {
        let repo = root.join(format!("repo-{name}"));
        repository(&repo);
        let info = repo.join(".git").join("objects").join("info");
        if link_info {
            let _ = fs::remove_dir_all(&info);
            link(&info, &other.join(".git").join("objects").join("info"));
        } else {
            fs::create_dir_all(&info).expect("info");
            fs::write(info.join(name), "").expect("file");
        }
        let provider = GitProvider::new(&repo).expect("provider");
        assert!(ran(&provider).is_empty(), "{name}");
    }
    // A link deeper in it.
    let repo = root.join("deeper");
    repository(&repo);
    let info = repo.join(".git").join("objects").join("info");
    fs::create_dir_all(&info).expect("info");
    link(&info.join("commit-graphs"), &root);
    let provider = GitProvider::new(&repo).expect("provider");
    assert!(ran(&provider).is_empty());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_branch_that_differs_only_in_case_is_not_created() {
    let root = temp_root("case");
    repository(&root);
    git(&root, &["branch", "Topic/One"]);
    git(&root, &["pack-refs", "--all"]);
    let provider = GitProvider::new(&root).expect("provider");
    for name in ["topic/one", "TOPIC/ONE", "topic", "Topic/one/more", "MAIN"] {
        let state = provider.branch_state(".").expect("state");
        assert!(provider.create_branch(".", name, &state).is_err(), "{name}");
        assert_eq!(
            git(&root, &["symbolic-ref", "HEAD"]).trim(),
            "refs/heads/main"
        );
    }
    let state = provider.branch_state(".").expect("state");
    assert!(provider.create_branch(".", "Topic/Two", &state).is_ok());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn further_configuration_is_refused() {
    let root = temp_root("keys");
    repository(&root);
    let config = root.join(".git").join("config");
    let original = fs::read_to_string(&config).expect("config");
    let provider = GitProvider::new(&root).expect("provider");
    for text in [
        "[core]\n\tunsetenvvars = PATH\n",
        "[fetch]\n\tbundleURI = https://example.invalid/b\n",
        "[bundle]\n\tversion = 1\n",
        "[bundle \"x\"]\n\turi = https://example.invalid/b\n",
        "[rerere]\n\tautoUpdate = true\n",
        "[remote \"o\"]\n\turl = file:////host/share/x\n",
        "[remote \"o\"]\n\turl = file://host/share/x\n",
        "[remote \"o\"]\n\turl = FILE:\\\\\\\\\\\\\\\\host\\\\share\n",
        "[remote \"o\"]\n\turl = file:///%2F%2Fhost/share\n",
    ] {
        fs::write(&config, format!("{original}{text}")).expect("config");
        assert!(provider.log(".", 1).is_err(), "{text:?}");
    }
    fs::write(
        &config,
        format!("{original}[remote \"o\"]\n\turl = file:///srv/repo.git\n"),
    )
    .expect("config");
    assert!(provider.log(".", 1).is_ok());
    let _ = fs::remove_dir_all(&root);
}
