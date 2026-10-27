//! XP-14: macOS discovery and verification tests (test-only; the copy
//! and `codesign` processes live here, never in product code).

use super::*;

fn fake_bundle(root: &Path, bundle: &Bundle, version: &str) -> PathBuf {
    let contents = root
        .join(format!("{}.app", bundle.executable))
        .join("Contents");
    std::fs::create_dir_all(contents.join("MacOS")).unwrap();
    std::fs::write(
        contents.join("Info.plist"),
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<plist version=\"1.0\"><dict>
             <key>CFBundleExecutable</key><string>{}</string>
             <key>CFBundleIdentifier</key><string>{}</string>
             <key>CFBundleShortVersionString</key><string>{version}</string>
</dict></plist>
",
            bundle.executable, bundle.identifier
        ),
    )
    .unwrap();
    let executable = contents.join("MacOS").join(bundle.executable);
    std::fs::copy("/bin/echo", &executable).unwrap();
    executable
}

#[test]
fn requirements_pin_anchor_team_and_identifier() {
    assert_eq!(
        requirement(&BUNDLES[0]),
        "anchor apple generic and identifier \"com.google.Chrome\" and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"EQHXZ8M8AV\""
    );
    assert_eq!(
        bundle_for_executable("Microsoft Edge").map(|b| b.team),
        Some("UBF8T346G9")
    );
    assert!(bundle_for_executable("Chromium").is_none());
}

#[test]
fn a_bundle_with_chrome_metadata_but_no_google_signature_is_refused() {
    let root = std::env::temp_dir().join(format!("orcel-xp14-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let executable = fake_bundle(&root, &BUNDLES[0], "156.0.7000.1");
    // The metadata reads as Chrome's...
    assert_eq!(bundle_version(&executable).unwrap(), "156.0.7000.1");
    // ...but the copied binary carries Apple's signature, not Google's.
    assert!(!verify_signature(&executable).unwrap());
    assert!(matches!(
        super::super::verify_candidate(&executable),
        Err(HostError::Unavailable(UnavailableReason::UnsupportedEngine))
    ));
    // A version string that is not exactly a version is refused.
    let bad = fake_bundle(&root.join("bad"), &BUNDLES[0], "156.0.7000.1 beta");
    assert!(bundle_version(&bad).is_err());
    // An executable outside a bundle is refused.
    assert!(bundle_version(Path::new("/bin/echo")).is_err());
    std::fs::remove_dir_all(&root).unwrap();
}

/// On a machine with Chrome or Edge installed (GitHub's macOS runners
/// have both), the real bundle verifies, and its signature does not
/// satisfy the other vendor's requirement. Under CI at least one must
/// be present.
#[test]
fn installed_vendor_bundles_verify_and_only_as_themselves() {
    let mut seen = 0;
    for (index, bundle) in BUNDLES.iter().enumerate() {
        let executable = Path::new("/Applications")
            .join(format!("{}.app", bundle.executable))
            .join("Contents/MacOS")
            .join(bundle.executable);
        if !executable.is_file() {
            continue;
        }
        seen += 1;
        let engine =
            super::super::verify_candidate(&executable).expect("installed engine verifies");
        assert!(engine.publisher_verified());
        let expected = if index == 0 {
            super::super::EngineKind::Chromium
        } else {
            super::super::EngineKind::Edge
        };
        assert_eq!(engine.kind(), expected);
        eprintln!(
            "XP14-EVIDENCE {} {} verified",
            bundle.identifier,
            engine.version()
        );
        let other = &BUNDLES[1 - index];
        assert!(!check_bundle(bundle_dir(&executable).unwrap(), other).unwrap());
    }
    if std::env::var_os("CI").is_some() {
        assert!(
            seen > 0,
            "no Chrome or Edge in /Applications on this CI runner"
        );
    }
}

/// A clone of the installed Chrome (an APFS copy-on-write clone, so
/// nothing large is written) is refused once a nested framework binary
/// changes, or once the bundle is re-signed by anyone else.
#[test]
fn a_tampered_or_re_signed_chrome_is_refused() {
    let installed = Path::new("/Applications/Google Chrome.app");
    if !installed.is_dir() {
        assert!(
            std::env::var_os("CI").is_none(),
            "Chrome is expected on the CI runner"
        );
        return;
    }
    let root = std::env::temp_dir().join(format!("orcel-xp14-tamper-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let clone = |name: &str| {
        let app = root.join(name).join("Google Chrome.app");
        std::fs::create_dir_all(app.parent().unwrap()).unwrap();
        let status = std::process::Command::new("cp")
            .args(["-cR"])
            .arg(installed)
            .arg(&app)
            .status()
            .unwrap();
        assert!(status.success(), "cp -c failed");
        app
    };
    // The untouched clone still verifies: the check is about content.
    let pristine = clone("pristine");
    assert!(check_bundle(&pristine, &BUNDLES[0]).unwrap());
    // One byte flipped inside the nested framework's binary, so a code
    // page's hash no longer matches its signature.
    let tampered = clone("tampered");
    let framework = tampered
        .join("Contents/Frameworks/Google Chrome Framework.framework/Versions/Current/Google Chrome Framework");
    assert!(
        framework.is_file(),
        "framework binary at {}",
        framework.display()
    );
    let mut bytes = std::fs::read(&framework).unwrap();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0xff;
    // Replace the file (the clone shares blocks with the original until
    // written; writing a new file never touches the original).
    std::fs::remove_file(&framework).unwrap();
    std::fs::write(&framework, &bytes).unwrap();
    assert!(!check_bundle(&tampered, &BUNDLES[0]).unwrap());
    // Re-signed ad hoc (not by Google's Developer ID).
    let resigned = clone("resigned");
    // codesign refuses a bundle carrying extended attributes ("resource
    // fork, Finder information, or similar detritus"); the clone's are
    // cleared first (the clone only, never the installed app).
    let cleared = std::process::Command::new("xattr")
        .arg("-cr")
        .arg(&resigned)
        .status()
        .unwrap();
    assert!(cleared.success(), "xattr -cr failed");
    // Only the outer signature is replaced: the bundle is then signed by
    // no Developer ID at all, whatever its nested code carries.
    let output = std::process::Command::new("codesign")
        .args(["--force", "--sign", "-"])
        .arg(&resigned)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "codesign failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!check_bundle(&resigned, &BUNDLES[0]).unwrap());
    eprintln!("XP14-EVIDENCE tampered and re-signed Chrome clones refused");
    let _ = std::fs::remove_dir_all(&root);
}
