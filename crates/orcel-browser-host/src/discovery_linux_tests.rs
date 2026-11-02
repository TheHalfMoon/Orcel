//! SG-000115 S-07 (prep/SG-000115.md, "Linux S-07"): the Linux engine
//! verifier against a real dpkg. Each test builds a `google-chrome-stable`
//! fixture package and installs it with an unprivileged dpkg into a private
//! root (`--force-not-root --root`), so the real `dpkg-query -S` and
//! `dpkg --verify` path runs end to end. Test builds only (declared under
//! `cfg(test)` in `discovery.rs`); spawns only `dpkg`, `dpkg-deb` and
//! `chmod`, and since B7 `gpg` (a throwaway fixture key) and `gpgv` (the
//! signature check) (the SG-000085 allowlist admits this file, recorded in
//! the packet). Skipped where dpkg is absent, never on CI.

use super::*;
use std::collections::BTreeMap;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::process::Command;

struct Fixture {
    dir: PathBuf,
    root: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Writable again, so a test that removed write bits can be
        // cleaned up.
        let _ = Command::new("chmod")
            .args(["-R", "u+w"])
            .arg(&self.dir)
            .status();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn tool(program: &str) -> bool {
    Command::new(program)
        .arg("--version")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

/// `google-chrome-stable` with an engine and a library under
/// /opt/google/chrome, installed into a private root. `None` where
/// dpkg is absent.
fn installed(name: &str) -> Option<Fixture> {
    if !tool("dpkg") || !tool("dpkg-deb") {
        // Never a silent skip on CI, where the Ubuntu image has dpkg.
        assert!(std::env::var_os("CI").is_none(), "dpkg is missing on CI");
        eprintln!("dpkg is not installed: the S-07 fixture tests are skipped");
        return None;
    }
    let dir = std::env::temp_dir().join(format!("orcel-s07-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let pkg = dir.join("pkg");
    let root = dir.join("root");
    std::fs::create_dir_all(pkg.join("DEBIAN")).unwrap();
    std::fs::create_dir_all(pkg.join("opt/google/chrome")).unwrap();
    for sub in ["var/lib/dpkg/info", "var/lib/dpkg/updates"] {
        std::fs::create_dir_all(root.join(sub)).unwrap();
    }
    std::fs::write(root.join("var/lib/dpkg/status"), "").unwrap();
    std::fs::write(
        pkg.join("DEBIAN/control"),
        "Package: google-chrome-stable\nVersion: 1.0\nArchitecture: all\n\
         Maintainer: fixture <fixture@example.invalid>\nDescription: S-07 fixture\n",
    )
    .unwrap();
    std::fs::write(pkg.join("opt/google/chrome/chrome"), "fixture engine\n").unwrap();
    std::fs::write(
        pkg.join("opt/google/chrome/libfixture.so"),
        "fixture library\n",
    )
    .unwrap();
    // Explicit modes, whatever the umask: directories 0755, files 0644.
    for path in [
        pkg.clone(),
        pkg.join("DEBIAN"),
        pkg.join("opt"),
        pkg.join("opt/google"),
        pkg.join("opt/google/chrome"),
    ] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    for path in [
        pkg.join("DEBIAN/control"),
        pkg.join("opt/google/chrome/chrome"),
        pkg.join("opt/google/chrome/libfixture.so"),
    ] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let deb = dir.join("fixture.deb");
    let built = Command::new("dpkg-deb")
        .args(["--build", "--root-owner-group"])
        .arg(&pkg)
        .arg(&deb)
        .output()
        .unwrap();
    assert!(built.status.success(), "{built:?}");
    let installed = Command::new("dpkg")
        .args(["--force-not-root", "--log=/dev/null"])
        .arg(format!("--root={}", root.display()))
        .arg("-i")
        .arg(&deb)
        .output()
        .unwrap();
    assert!(installed.status.success(), "{installed:?}");
    Some(Fixture { dir, root })
}

fn db(fixture: &Fixture) -> PackageDb {
    PackageDb {
        root: Some(fixture.root.clone()),
        owner: std::fs::metadata(&fixture.root).unwrap().uid(),
    }
}

fn engine(fixture: &Fixture) -> PathBuf {
    fixture
        .root
        .join("opt/google/chrome/chrome")
        .canonicalize()
        .unwrap()
}

#[test]
fn s07_an_intact_vendor_package_is_verified() {
    let Some(fixture) = installed("intact") else {
        return;
    };
    let verdict = verify_publisher_in(&engine(&fixture), &db(&fixture));
    assert!(matches!(verdict, Ok(true)), "{verdict:?}");
}

#[test]
fn s07_a_tampered_engine_or_library_is_refused() {
    for file in ["chrome", "libfixture.so"] {
        let Some(fixture) = installed(&format!("tampered-{file}")) else {
            return;
        };
        let target = fixture.root.join("opt/google/chrome").join(file);
        let mut bytes = std::fs::read(&target).unwrap();
        bytes[0] ^= 1;
        std::fs::write(&target, bytes).unwrap();
        let verdict = verify_publisher_in(&engine(&fixture), &db(&fixture));
        assert!(
            matches!(
                verdict,
                Err(HostError::Unavailable(UnavailableReason::UnsupportedEngine))
            ),
            "{file}: {verdict:?}"
        );
    }
}

#[test]
fn s07_an_unowned_engine_is_not_verified() {
    let Some(fixture) = installed("unowned") else {
        return;
    };
    // A file no package owns, beside the vendor's engine.
    let stray = fixture.root.join("opt/google/chrome/chromium");
    std::fs::write(&stray, "not packaged\n").unwrap();
    std::fs::set_permissions(&stray, std::fs::Permissions::from_mode(0o644)).unwrap();
    let stray = stray.canonicalize().unwrap();
    let verdict = verify_publisher_in(&stray, &db(&fixture));
    assert!(matches!(verdict, Ok(false)), "{verdict:?}");
}

#[test]
fn s07_an_engine_owned_by_another_account_is_not_verified() {
    let Some(fixture) = installed("owner") else {
        return;
    };
    let mut other = db(&fixture);
    other.owner = other.owner.wrapping_add(1);
    let verdict = verify_publisher_in(&engine(&fixture), &other);
    assert!(matches!(verdict, Ok(false)), "{verdict:?}");
}

/// The package check passes (dpkg compares digests only), yet a file
/// or directory another account can write is refused.
#[test]
fn s07_writable_files_or_directories_are_not_verified() {
    for (relative, mode) in [
        ("opt/google/chrome/chrome", 0o664),
        ("opt/google/chrome/libfixture.so", 0o646),
        ("opt/google/chrome", 0o775),
        ("opt/google", 0o757),
        ("opt", 0o777),
    ] {
        let Some(fixture) = installed(&format!("writable-{}", relative.replace('/', "-"))) else {
            return;
        };
        let target = fixture.root.join(relative);
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode)).unwrap();
        let verdict = verify_publisher_in(&engine(&fixture), &db(&fixture));
        assert!(
            matches!(verdict, Ok(false)),
            "{relative} at {mode:o}: {verdict:?}"
        );
    }
}

#[test]
fn s07_a_link_out_of_the_install_directory_is_not_verified() {
    let Some(fixture) = installed("link") else {
        return;
    };
    let outside = fixture.dir.join("outside.so");
    std::fs::write(&outside, "elsewhere\n").unwrap();
    std::os::unix::fs::symlink(&outside, fixture.root.join("opt/google/chrome/libextra.so"))
        .unwrap();
    let verdict = verify_publisher_in(&engine(&fixture), &db(&fixture));
    assert!(matches!(verdict, Ok(false)), "{verdict:?}");
    // A link that stays inside is allowed.
    std::fs::remove_file(fixture.root.join("opt/google/chrome/libextra.so")).unwrap();
    std::os::unix::fs::symlink(
        "libfixture.so",
        fixture.root.join("opt/google/chrome/libalias.so"),
    )
    .unwrap();
    let verdict = verify_publisher_in(&engine(&fixture), &db(&fixture));
    assert!(matches!(verdict, Ok(true)), "{verdict:?}");
}

#[test]
fn s07_a_linked_engine_path_is_not_verified() {
    let Some(fixture) = installed("linked-engine") else {
        return;
    };
    let link = fixture.dir.join("chrome");
    std::os::unix::fs::symlink(engine(&fixture), &link).unwrap();
    let verdict = verify_publisher_in(&link, &db(&fixture));
    assert!(matches!(verdict, Ok(false)), "{verdict:?}");
}

/// Evidence on hosts with the real vendor package (CI's Ubuntu image ships
/// Chrome): the verifier's verdict follows the install tree as it is on
/// disk. The hosted image leaves it world-writable, so there the tree is
/// reported and the engine stays unverified; a host with the vendor's own
/// modes verifies it. Nothing on the runner is changed.
#[test]
fn s07_the_installed_chrome_verdict_follows_its_install_tree() {
    let chrome = Path::new("/opt/google/chrome/chrome");
    if !chrome.is_file() {
        // CI's Ubuntu image ships Chrome: never a silent skip there.
        assert!(std::env::var_os("CI").is_none(), "no Chrome on CI");
        eprintln!("no /opt/google/chrome/chrome here: skipped");
        return;
    }
    let tree = install_tree_problem(chrome, chrome.parent().unwrap(), &PackageDb::production());
    eprintln!("SG115-EVIDENCE real Chrome install tree: {tree:?}");
    let verdict = verify_publisher(chrome);
    assert!(
        matches!(verdict, Ok(verified) if verified == tree.is_none()),
        "{verdict:?}; install tree: {tree:?}"
    );
}

/// The tree check never weakens a refusal: a tampered vendor package is still
/// refused when its files are also writable by others.
#[test]
fn s07_a_tampered_and_writable_package_is_still_refused() {
    let Some(fixture) = installed("tampered-writable") else {
        return;
    };
    let target = fixture.root.join("opt/google/chrome/libfixture.so");
    let mut bytes = std::fs::read(&target).unwrap();
    bytes[0] ^= 1;
    std::fs::write(&target, bytes).unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o664)).unwrap();
    let verdict = verify_publisher_in(&engine(&fixture), &db(&fixture));
    assert!(
        matches!(
            verdict,
            Err(HostError::Unavailable(UnavailableReason::UnsupportedEngine))
        ),
        "{verdict:?}"
    );
}

/// A link chain that leaves the install directory and comes back is not
/// trusted: its outside hop could be re-pointed later.
#[test]
fn s07_a_link_chain_through_an_outside_hop_is_not_verified() {
    let Some(fixture) = installed("link-chain") else {
        return;
    };
    let hop = fixture.dir.join("hop");
    std::os::unix::fs::symlink(fixture.root.join("opt/google/chrome/libfixture.so"), &hop).unwrap();
    std::os::unix::fs::symlink(&hop, fixture.root.join("opt/google/chrome/libchain.so")).unwrap();
    let verdict = verify_publisher_in(&engine(&fixture), &db(&fixture));
    assert!(matches!(verdict, Ok(false)), "{verdict:?}");
}

// ---- SG-000115 B7: the retained-package signature chain (inert) -------
//
// prep/SG-000115.md, "B7". A cryptographic chain from a vendor's pinned
// signing key to every installed file, possible only while the downloaded
// package and its index entry are still on disk:
// 1. `InRelease` verifies with `gpgv` against a keyring, and the signing
//    key's primary fingerprint is one of the pinned ones;
// 2. the signed release lists the `Packages` file's SHA-256 and size;
// 3. `Packages` names the package at the installed version, with the
//    retained `.deb`'s SHA-256;
// 4. the retained `.deb` hashes to that value;
// 5. every regular file in the package's data matches the installed file
//    byte for byte (SHA-256, through `dpkg-deb --fsys-tarfile`, not dpkg's
//    MD5 list), and the install directory holds nothing the package does
//    not list.
// Any missing or mismatched link leaves the engine unverified. Test builds
// only; nothing is downloaded (every input is a local file).

/// Why the chain did not verify.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ChainError {
    /// `gpgv` refused the signature, or the key is not a pinned one.
    Signature,
    /// The signed release has no digest for the `Packages` file.
    NoReleaseEntry,
    /// The `Packages` file does not hash to the signed digest.
    IndexDigest,
    /// `Packages` has no entry for the package at this version.
    NoPackageEntry,
    /// The retained `.deb` is missing or does not hash to the index value.
    RetainedPackage,
    /// An installed file differs from the package, or is extra.
    Installed(String),
    /// A tool failed or its output could not be read.
    Tool(String),
}

/// The inputs of one chain check, every one a local path or value.
struct ChainInputs<'a> {
    /// The keyring `gpgv` checks against.
    keyring: &'a Path,
    /// The pinned primary key fingerprints (uppercase hex).
    fingerprints: &'a [&'a str],
    in_release: &'a Path,
    packages: &'a Path,
    /// The `Packages` file's name as the release lists it.
    packages_name: &'a str,
    retained_deb: &'a Path,
    package: &'a str,
    version: &'a str,
    /// The filesystem root the package was installed under.
    root: &'a Path,
    /// The install directory, relative to `root` (no leading slash).
    install_dir: &'a str,
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Step 1: the signed text of `InRelease`, if `gpgv` accepts it and the
/// signer's primary key is pinned. `gpgv` runs with a private home, so no
/// user keyring or agent is consulted.
fn signed_release(inputs: &ChainInputs<'_>, scratch: &Path) -> Result<String, ChainError> {
    let home = scratch.join("gpgv-home");
    std::fs::create_dir_all(&home).map_err(|e| ChainError::Tool(e.to_string()))?;
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| ChainError::Tool(e.to_string()))?;
    let out = scratch.join("release.txt");
    let _ = std::fs::remove_file(&out);
    let run = Command::new("gpgv")
        .arg("--homedir")
        .arg(&home)
        .args(["--status-fd", "1", "--keyring"])
        .arg(inputs.keyring)
        .arg("--output")
        .arg(&out)
        .arg(inputs.in_release)
        .output()
        .map_err(|e| ChainError::Tool(e.to_string()))?;
    if !run.status.success() {
        return Err(ChainError::Signature);
    }
    // `[GNUPG:] VALIDSIG <subkey fpr> ... <primary fpr>`: the last field is
    // the primary key's fingerprint.
    let status = String::from_utf8_lossy(&run.stdout);
    let pinned = status
        .lines()
        .filter_map(|line| line.strip_prefix("[GNUPG:] VALIDSIG "))
        .filter_map(|rest| rest.split_whitespace().last())
        .any(|primary| {
            inputs
                .fingerprints
                .contains(&primary.to_ascii_uppercase().as_str())
        });
    if !pinned {
        return Err(ChainError::Signature);
    }
    std::fs::read_to_string(&out).map_err(|e| ChainError::Tool(e.to_string()))
}

/// Step 2: the SHA-256 and size the signed release lists for `name`.
fn release_digest<'r>(release: &'r str, name: &str) -> Option<(&'r str, u64)> {
    let mut in_sha256 = false;
    for line in release.lines() {
        if !line.starts_with(' ') {
            in_sha256 = line.trim_end() == "SHA256:";
            continue;
        }
        if in_sha256 {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if let [digest, size, listed] = fields[..] {
                if listed == name {
                    return Some((digest, size.parse().ok()?));
                }
            }
        }
    }
    None
}

/// Step 3: the SHA-256 that `Packages` gives the package at `version`.
fn package_digest(packages: &str, package: &str, version: &str) -> Option<String> {
    packages.split("\n\n").find_map(|stanza| {
        let field = |name: &str| {
            stanza
                .lines()
                .find_map(|line| line.strip_prefix(&format!("{name}: ")))
                .map(str::trim)
        };
        (field("Package") == Some(package) && field("Version") == Some(version))
            .then(|| field("SHA256").map(str::to_owned))
            .flatten()
    })
}

/// One entry of a package's data, as `dpkg-deb --fsys-tarfile` lists it.
#[derive(Debug)]
enum Entry {
    File(String),
    Directory,
    Link,
}

/// At most this many entries are read from a package's data.
const MAX_PACKAGE_ENTRIES: usize = 100_000;

/// The entries of a ustar/GNU tar stream: path (without a leading `./`) to
/// kind, with a regular file's SHA-256. `None` when the stream does not
/// parse or exceeds the bound.
fn tar_entries(tar: &[u8]) -> Option<BTreeMap<String, Entry>> {
    let mut entries = BTreeMap::new();
    let mut offset = 0usize;
    let mut long_name: Option<String> = None;
    while offset + 512 <= tar.len() {
        let header = &tar[offset..offset + 512];
        if header.iter().all(|byte| *byte == 0) {
            return Some(entries);
        }
        let text = |range: std::ops::Range<usize>| {
            let field = &header[range];
            let end = field
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(field.len());
            String::from_utf8(field[..end].to_vec()).ok()
        };
        let size_text = text(124..136)?;
        let size = u64::from_str_radix(size_text.trim(), 8).ok()? as usize;
        let kind = header[156];
        let body_start = offset + 512;
        let body_end = body_start.checked_add(size)?;
        if body_end > tar.len() {
            return None;
        }
        let body = &tar[body_start..body_end];
        offset = body_start + size.div_ceil(512) * 512;
        if kind == b'L' {
            let end = body
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(body.len());
            long_name = Some(String::from_utf8(body[..end].to_vec()).ok()?);
            continue;
        }
        let name = match long_name.take() {
            Some(name) => name,
            None => {
                let prefix = text(345..500)?;
                let name = text(0..100)?;
                if prefix.is_empty() {
                    name
                } else {
                    format!("{prefix}/{name}")
                }
            }
        };
        let path = name
            .trim_start_matches("./")
            .trim_end_matches('/')
            .to_owned();
        if path.is_empty() || path.split('/').any(|part| part == "..") {
            continue;
        }
        let entry = match kind {
            b'0' | 0 => Entry::File(sha256_hex(body)),
            b'5' => Entry::Directory,
            b'1' | b'2' => Entry::Link,
            _ => return None,
        };
        entries.insert(path, entry);
        if entries.len() > MAX_PACKAGE_ENTRIES {
            return None;
        }
    }
    None
}

/// Step 5: every regular file of the package matches the installed file
/// (not a link, same SHA-256), and the install directory holds nothing the
/// package does not list.
fn installed_matches(inputs: &ChainInputs<'_>) -> Result<(), ChainError> {
    let tar = Command::new("dpkg-deb")
        .arg("--fsys-tarfile")
        .arg(inputs.retained_deb)
        .output()
        .map_err(|e| ChainError::Tool(e.to_string()))?;
    if !tar.status.success() {
        return Err(ChainError::Tool("dpkg-deb --fsys-tarfile failed".into()));
    }
    let entries = tar_entries(&tar.stdout)
        .ok_or_else(|| ChainError::Tool("unreadable package data".into()))?;
    for (path, entry) in &entries {
        let Entry::File(digest) = entry else {
            continue;
        };
        let installed = inputs.root.join(path);
        let regular = std::fs::symlink_metadata(&installed)
            .map(|meta| meta.file_type().is_file())
            .unwrap_or(false);
        let matches = regular
            && std::fs::read(&installed)
                .map(|bytes| sha256_hex(&bytes) == *digest)
                .unwrap_or(false);
        if !matches {
            return Err(ChainError::Installed(path.clone()));
        }
    }
    // Nothing extra in the install directory (`dpkg --verify` ignores extra
    // files): walked without following links, bounded.
    let mut stack = vec![inputs.install_dir.to_owned()];
    let mut seen = 0usize;
    while let Some(relative) = stack.pop() {
        let listing = std::fs::read_dir(inputs.root.join(&relative))
            .map_err(|e| ChainError::Tool(e.to_string()))?;
        for item in listing {
            let item = item.map_err(|e| ChainError::Tool(e.to_string()))?;
            seen += 1;
            if seen > MAX_PACKAGE_ENTRIES {
                return Err(ChainError::Tool("install directory too large".into()));
            }
            let name = item.file_name().to_string_lossy().into_owned();
            let child = format!("{relative}/{name}");
            if !entries.contains_key(&child) {
                return Err(ChainError::Installed(child));
            }
            if item.file_type().map(|kind| kind.is_dir()).unwrap_or(false) {
                stack.push(child);
            }
        }
    }
    Ok(())
}

/// The whole chain, steps 1 to 5; `Ok(())` only when every link holds.
fn retained_package_chain(inputs: &ChainInputs<'_>, scratch: &Path) -> Result<(), ChainError> {
    let release = signed_release(inputs, scratch)?;
    let packages = std::fs::read(inputs.packages).map_err(|_| ChainError::IndexDigest)?;
    let (digest, size) =
        release_digest(&release, inputs.packages_name).ok_or(ChainError::NoReleaseEntry)?;
    if sha256_hex(&packages) != digest || packages.len() as u64 != size {
        return Err(ChainError::IndexDigest);
    }
    let packages = String::from_utf8(packages).map_err(|_| ChainError::IndexDigest)?;
    let expected = package_digest(&packages, inputs.package, inputs.version)
        .ok_or(ChainError::NoPackageEntry)?;
    let deb = std::fs::read(inputs.retained_deb).map_err(|_| ChainError::RetainedPackage)?;
    if sha256_hex(&deb) != expected {
        return Err(ChainError::RetainedPackage);
    }
    installed_matches(inputs)
}

/// The primary fingerprint of Google's Linux package signing key, pinned
/// for the real-host evidence below. Pinning it for activation is a founder
/// decision (prep/SG-000115.md, "B7").
const GOOGLE_LINUX_SIGNING_KEY: &str = "EB4C1BFD4F042F6DDDCCEC917721F63BD38B4796";

/// A throwaway signing key, a signed release and a `Packages` index for an
/// installed fixture package, all under the fixture's directory.
struct Repo {
    keyring: PathBuf,
    fingerprint: String,
    in_release: PathBuf,
    packages: PathBuf,
    deb: PathBuf,
    scratch: PathBuf,
}

fn gpg(home: &Path, args: &[&str]) -> std::process::Output {
    Command::new("gpg")
        .arg("--homedir")
        .arg(home)
        .args(["--batch", "--pinentry-mode", "loopback", "--passphrase", ""])
        .args(args)
        .output()
        .unwrap()
}

/// `None` where gpg is absent (never on CI).
fn signed_repo(fixture: &Fixture) -> Option<Repo> {
    if !tool("gpg") || !tool("gpgv") {
        assert!(std::env::var_os("CI").is_none(), "gpg is missing on CI");
        eprintln!("gpg is not installed: the B7 chain tests are skipped");
        return None;
    }
    let scratch = fixture.dir.join("b7");
    let home = scratch.join("gnupg");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
    let made = gpg(
        &home,
        &[
            "--quick-gen-key",
            "Orcel B7 fixture <b7@example.invalid>",
            "ed25519",
            "sign",
            "1d",
        ],
    );
    assert!(made.status.success(), "{made:?}");
    let listed = gpg(&home, &["--with-colons", "--list-keys"]);
    let fingerprint = String::from_utf8_lossy(&listed.stdout)
        .lines()
        .find_map(|line| line.strip_prefix("fpr:"))
        .and_then(|rest| rest.split(':').find(|field| field.len() == 40))
        .unwrap()
        .to_owned();
    let keyring = scratch.join("keyring.gpg");
    let exported = gpg(&home, &["--output", keyring.to_str().unwrap(), "--export"]);
    assert!(exported.status.success(), "{exported:?}");
    let deb = fixture.dir.join("fixture.deb");
    let deb_digest = sha256_hex(&std::fs::read(&deb).unwrap());
    let packages_text = format!(
        "Package: google-chrome-stable\nVersion: 1.0\nArchitecture: all\n\
         Filename: pool/main/g/google-chrome-stable/fixture.deb\nSHA256: {deb_digest}\n\n"
    );
    let packages = scratch.join("Packages");
    std::fs::write(&packages, &packages_text).unwrap();
    let release = scratch.join("Release");
    std::fs::write(
        &release,
        format!(
            "Origin: Orcel B7 fixture\nSuite: stable\nSHA256:\n {} {} main/binary-all/Packages\n",
            sha256_hex(packages_text.as_bytes()),
            packages_text.len()
        ),
    )
    .unwrap();
    let in_release = scratch.join("InRelease");
    let signed = gpg(
        &home,
        &[
            "--output",
            in_release.to_str().unwrap(),
            "--clearsign",
            release.to_str().unwrap(),
        ],
    );
    assert!(signed.status.success(), "{signed:?}");
    Some(Repo {
        keyring,
        fingerprint,
        in_release,
        packages,
        deb,
        scratch,
    })
}

fn chain(
    fixture: &Fixture,
    repo: &Repo,
    fingerprints: &[&str],
    version: &str,
) -> Result<(), ChainError> {
    let inputs = ChainInputs {
        keyring: &repo.keyring,
        fingerprints,
        in_release: &repo.in_release,
        packages: &repo.packages,
        packages_name: "main/binary-all/Packages",
        retained_deb: &repo.deb,
        package: "google-chrome-stable",
        version,
        root: &fixture.root,
        install_dir: "opt/google/chrome",
    };
    retained_package_chain(&inputs, &repo.scratch)
}

#[test]
fn b7_an_intact_signed_chain_verifies_every_installed_file() {
    let Some(fixture) = installed("b7-intact") else {
        return;
    };
    let Some(repo) = signed_repo(&fixture) else {
        return;
    };
    assert_eq!(chain(&fixture, &repo, &[&repo.fingerprint], "1.0"), Ok(()));
}

#[test]
fn b7_every_broken_link_leaves_the_engine_unverified() {
    let Some(fixture) = installed("b7-broken") else {
        return;
    };
    let Some(repo) = signed_repo(&fixture) else {
        return;
    };
    let fpr = repo.fingerprint.clone();
    // A key that is not pinned.
    assert_eq!(
        chain(&fixture, &repo, &[GOOGLE_LINUX_SIGNING_KEY], "1.0"),
        Err(ChainError::Signature)
    );
    // Another version than the one installed.
    assert_eq!(
        chain(&fixture, &repo, &[&fpr], "2.0"),
        Err(ChainError::NoPackageEntry)
    );
    // A signed release altered after signing.
    let original = std::fs::read_to_string(&repo.in_release).unwrap();
    std::fs::write(
        &repo.in_release,
        original.replace("Suite: stable", "Suite: stablf"),
    )
    .unwrap();
    assert_eq!(
        chain(&fixture, &repo, &[&fpr], "1.0"),
        Err(ChainError::Signature)
    );
    std::fs::write(&repo.in_release, &original).unwrap();
    // A Packages index changed after signing.
    let packages = std::fs::read_to_string(&repo.packages).unwrap();
    std::fs::write(
        &repo.packages,
        packages.replace("Version: 1.0", "Version: 1.1"),
    )
    .unwrap();
    assert_eq!(
        chain(&fixture, &repo, &[&fpr], "1.0"),
        Err(ChainError::IndexDigest)
    );
    std::fs::write(&repo.packages, &packages).unwrap();
    // An installed file changed by one byte.
    let library = fixture.root.join("opt/google/chrome/libfixture.so");
    let bytes = std::fs::read(&library).unwrap();
    let mut changed = bytes.clone();
    changed[0] ^= 1;
    std::fs::write(&library, &changed).unwrap();
    assert_eq!(
        chain(&fixture, &repo, &[&fpr], "1.0"),
        Err(ChainError::Installed(
            "opt/google/chrome/libfixture.so".into()
        ))
    );
    std::fs::write(&library, &bytes).unwrap();
    // A file the package does not list, added to the install directory.
    let extra = fixture.root.join("opt/google/chrome/libextra.so");
    std::fs::write(&extra, "planted").unwrap();
    assert_eq!(
        chain(&fixture, &repo, &[&fpr], "1.0"),
        Err(ChainError::Installed(
            "opt/google/chrome/libextra.so".into()
        ))
    );
    std::fs::remove_file(&extra).unwrap();
    // The retained package changed, then gone.
    let deb = std::fs::read(&repo.deb).unwrap();
    let mut longer = deb.clone();
    longer.push(0);
    std::fs::write(&repo.deb, &longer).unwrap();
    assert_eq!(
        chain(&fixture, &repo, &[&fpr], "1.0"),
        Err(ChainError::RetainedPackage)
    );
    std::fs::remove_file(&repo.deb).unwrap();
    assert_eq!(
        chain(&fixture, &repo, &[&fpr], "1.0"),
        Err(ChainError::RetainedPackage)
    );
    std::fs::write(&repo.deb, &deb).unwrap();
    // Restored, the chain holds again.
    assert_eq!(chain(&fixture, &repo, &[&fpr], "1.0"), Ok(()));
}

/// B7 on the host: which links of a real Chrome chain are on disk. Evidence
/// only (printed), never a pass of the chain: a missing link leaves the real
/// engine unverified.
#[test]
fn b7_what_a_real_chrome_chain_has_on_this_host() {
    let lists = std::fs::read_dir("/var/lib/apt/lists")
        .map(|dir| {
            dir.flatten()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .filter(|name| name.contains("dl.google.com") && name.ends_with("InRelease"))
                .count()
        })
        .unwrap_or(0);
    let keyrings = [
        "/usr/share/keyrings/google-chrome.gpg",
        "/etc/apt/trusted.gpg.d/google-chrome.gpg",
    ]
    .iter()
    .filter(|path| Path::new(path).exists())
    .count();
    let retained = std::fs::read_dir("/var/cache/apt/archives")
        .map(|dir| {
            dir.flatten()
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with("google-chrome-stable_")
                })
                .count()
        })
        .unwrap_or(0);
    println!(
        "SG115-EVIDENCE B7 real Chrome chain links on this host: signed index {lists}, \
         vendor keyring {keyrings}, retained package {retained} (all three are needed; \
         otherwise the engine stays unverified)"
    );
}
