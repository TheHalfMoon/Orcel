//! SG-000115 S-07 (prep/SG-000115.md, "Linux S-07"): the Linux engine
//! verifier against a real dpkg. Each test builds a `google-chrome-stable`
//! fixture package and installs it with an unprivileged dpkg into a private
//! root (`--force-not-root --root`), so the real `dpkg-query -S` and
//! `dpkg --verify` path runs end to end. Test builds only (declared under
//! `cfg(test)` in `discovery.rs`); spawns only `dpkg`, `dpkg-deb` and
//! `chmod` (the SG-000085 allowlist admits this file, recorded in the
//! packet). Skipped where dpkg is absent, never on CI.

use super::*;
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

/// Evidence on hosts with the real vendor package (CI's Ubuntu image
/// ships Chrome): its install tree meets the ownership rule.
#[test]
fn s07_the_installed_chrome_tree_is_root_owned_where_present() {
    let chrome = Path::new("/opt/google/chrome/chrome");
    if !chrome.is_file() {
        // CI's Ubuntu image ships Chrome: never a silent skip there.
        assert!(std::env::var_os("CI").is_none(), "no Chrome on CI");
        eprintln!("no /opt/google/chrome/chrome here: skipped");
        return;
    }
    assert!(
        install_tree_trusted(chrome, chrome.parent().unwrap(), &PackageDb::production()),
        "the vendor install tree is root-owned and not group or other writable"
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
