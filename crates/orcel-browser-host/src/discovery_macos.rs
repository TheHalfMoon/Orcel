//! XP-14 (slice 1): engine discovery and verification on macOS.
//!
//! An engine is a stable-channel app bundle in `/Applications` or the
//! user's `~/Applications`. Its version comes from the bundle's
//! `Contents/Info.plist` (nothing is run), and its code signature is
//! checked by Security.framework against a designated requirement: an
//! Apple-anchored Developer ID chain whose leaf names the vendor's team
//! (Google `EQHXZ8M8AV`, Microsoft `UBF8T346G9`) and the bundle's own
//! identifier. Anything else is refused. Launching remains Windows-only.
//!
//! Orcel-owned (BUILD_NEW). The backlog names trycua/cua's
//! `libs/cua/crates/cua-keyvault/src/macos.rs` (a802eaf, blob a630391a) as
//! a reference; it checks *running* peers through the security-framework
//! crate and SecCodeCopySigningInformation. No code is taken from it: this
//! checks a bundle on disk (SecStaticCode) against a designated requirement
//! with SecStaticCodeCheckValidity, calling the frameworks directly, so no
//! dependency is added.

use crate::error::{HostError, UnavailableReason};
use std::ffi::c_void;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// A supported bundle: its executable's name (which gives the kind, see
/// `verify_candidate`), bundle identifier and the vendor's Apple team.
pub(super) struct Bundle {
    pub executable: &'static str,
    pub identifier: &'static str,
    pub team: &'static str,
}

pub(super) const BUNDLES: [Bundle; 2] = [
    Bundle {
        executable: "Google Chrome",
        identifier: "com.google.Chrome",
        team: "EQHXZ8M8AV",
    },
    Bundle {
        executable: "Microsoft Edge",
        identifier: "com.microsoft.edgemac",
        team: "UBF8T346G9",
    },
];

pub(super) fn bundle_for_executable(name: &str) -> Option<&'static Bundle> {
    BUNDLES.iter().find(|bundle| bundle.executable == name)
}

/// The designated requirement a genuine stable-channel bundle satisfies:
/// Apple's anchor, a Developer ID intermediate and a Developer ID
/// Application leaf (so the team's development and distribution
/// certificates do not qualify), the vendor's team and the bundle's
/// identifier.
pub(super) fn requirement(bundle: &Bundle) -> String {
    format!(
        "anchor apple generic and identifier \"{}\" and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"{}\"",
        bundle.identifier, bundle.team
    )
}

/// `/Applications/<Name>.app/Contents/MacOS/<Name>` and the same under the
/// user's `~/Applications`.
pub(super) fn candidates() -> Vec<PathBuf> {
    let mut roots = vec![PathBuf::from("/Applications")];
    if let Some(home) = std::env::var_os("HOME") {
        roots.push(Path::new(&home).join("Applications"));
    }
    let mut out = Vec::new();
    for root in roots {
        for bundle in &BUNDLES {
            out.push(
                root.join(format!("{}.app", bundle.executable))
                    .join("Contents/MacOS")
                    .join(bundle.executable),
            );
        }
    }
    out
}

/// The `.app` directory an executable at `<app>/Contents/MacOS/<name>`
/// belongs to.
fn bundle_dir(executable: &Path) -> Option<&Path> {
    let macos = executable.parent()?;
    let contents = macos.parent()?;
    let app = contents.parent()?;
    (macos.file_name()? == "MacOS"
        && contents.file_name()? == "Contents"
        && app.extension()? == "app")
        .then_some(app)
}

/// The engine version from `Contents/Info.plist`, which must name the
/// expected bundle identifier. Nothing is executed.
pub(super) fn bundle_version(executable: &Path) -> Result<String, HostError> {
    let unsupported = || HostError::Unavailable(UnavailableReason::UnsupportedEngine);
    let name = executable
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(unsupported)?;
    let bundle = bundle_for_executable(name).ok_or_else(unsupported)?;
    let app = bundle_dir(executable).ok_or_else(unsupported)?;
    let plist = app.join("Contents/Info.plist");
    let metadata = std::fs::metadata(&plist).map_err(|_| unsupported())?;
    if metadata.len() > 1 << 20 {
        return Err(unsupported());
    }
    let text = std::fs::read_to_string(&plist).map_err(|_| unsupported())?;
    if super::plist_string(&text, "CFBundleIdentifier").as_deref() != Some(bundle.identifier)
        || super::plist_string(&text, "CFBundleExecutable").as_deref() != Some(bundle.executable)
    {
        return Err(unsupported());
    }
    let version =
        super::plist_string(&text, "CFBundleShortVersionString").ok_or_else(unsupported)?;
    super::parse_version(&version)
        .filter(|parsed| *parsed == version)
        .ok_or_else(unsupported)
}

type OSStatus = i32;
type CFTypeRef = *const c_void;
type CFAllocatorRef = *const c_void;
type CFURLRef = *const c_void;
type CFStringRef = *const c_void;
type SecStaticCodeRef = *const c_void;
type SecRequirementRef = *const c_void;

const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
/// kSecCSDefaultFlags.
const K_SEC_CS_DEFAULT_FLAGS: u32 = 0;
/// kSecCSCheckAllArchitectures | kSecCSCheckNestedCode |
/// kSecCSStrictValidate: every architecture slice, every nested framework
/// and helper app fully (as `codesign --verify --deep --strict`), and the
/// strict format checks Gatekeeper applies.
const K_SEC_CS_VALIDITY_FLAGS: u32 = (1 << 0) | (1 << 3) | (1 << 4);

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    fn CFURLCreateFromFileSystemRepresentation(
        allocator: CFAllocatorRef,
        buffer: *const u8,
        length: isize,
        is_directory: u8,
    ) -> CFURLRef;
    fn CFStringCreateWithBytes(
        allocator: CFAllocatorRef,
        bytes: *const u8,
        length: isize,
        encoding: u32,
        is_external_representation: u8,
    ) -> CFStringRef;
    fn CFRelease(object: CFTypeRef);
}

#[link(name = "Security", kind = "framework")]
extern "C" {
    fn SecStaticCodeCreateWithPath(
        path: CFURLRef,
        flags: u32,
        static_code: *mut SecStaticCodeRef,
    ) -> OSStatus;
    fn SecRequirementCreateWithString(
        text: CFStringRef,
        flags: u32,
        requirement: *mut SecRequirementRef,
    ) -> OSStatus;
    fn SecStaticCodeCheckValidity(
        static_code: SecStaticCodeRef,
        flags: u32,
        requirement: SecRequirementRef,
    ) -> OSStatus;
}

/// Releases a Core Foundation object when dropped.
struct Owned(CFTypeRef);

impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: a +1 reference from a Create function, released once.
            unsafe { CFRelease(self.0) };
        }
    }
}

/// Whether the bundle holding `executable` is a validly signed, untampered
/// stable-channel Chrome or Edge from its vendor.
pub(super) fn verify_signature(executable: &Path) -> Result<bool, HostError> {
    let unsupported = || HostError::Unavailable(UnavailableReason::UnsupportedEngine);
    let name = executable
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(unsupported)?;
    let bundle = bundle_for_executable(name).ok_or_else(unsupported)?;
    let app = bundle_dir(executable).ok_or_else(unsupported)?;
    check_bundle(app, bundle)
}

/// Whether the app bundle at `app` satisfies `bundle`'s requirement.
fn check_bundle(app: &Path, bundle: &Bundle) -> Result<bool, HostError> {
    let unsupported = || HostError::Unavailable(UnavailableReason::UnsupportedEngine);
    let path = app.as_os_str().as_bytes();
    let text = requirement(bundle);
    // SAFETY: every Create result is checked for null and owned by `Owned`,
    // which releases it once; the byte buffers outlive the calls.
    unsafe {
        let url = Owned(CFURLCreateFromFileSystemRepresentation(
            std::ptr::null(),
            path.as_ptr(),
            path.len() as isize,
            1,
        ));
        let requirement_text = Owned(CFStringCreateWithBytes(
            std::ptr::null(),
            text.as_ptr(),
            text.len() as isize,
            K_CF_STRING_ENCODING_UTF8,
            0,
        ));
        if url.0.is_null() || requirement_text.0.is_null() {
            return Err(unsupported());
        }
        let mut code: SecStaticCodeRef = std::ptr::null();
        if SecStaticCodeCreateWithPath(url.0, K_SEC_CS_DEFAULT_FLAGS, &mut code) != 0
            || code.is_null()
        {
            return Ok(false);
        }
        let code = Owned(code);
        let mut parsed: SecRequirementRef = std::ptr::null();
        if SecRequirementCreateWithString(requirement_text.0, K_SEC_CS_DEFAULT_FLAGS, &mut parsed)
            != 0
            || parsed.is_null()
        {
            return Err(unsupported());
        }
        let parsed = Owned(parsed);
        Ok(SecStaticCodeCheckValidity(code.0, K_SEC_CS_VALIDITY_FLAGS, parsed.0) == 0)
    }
}

#[cfg(test)]
mod tests {
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
        // One byte appended to the nested framework's binary.
        let tampered = clone("tampered");
        let framework = tampered
            .join("Contents/Frameworks/Google Chrome Framework.framework/Versions/Current/Google Chrome Framework");
        assert!(
            framework.is_file(),
            "framework binary at {}",
            framework.display()
        );
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&framework)
            .unwrap();
        std::io::Write::write_all(&mut file, b"\0").unwrap();
        drop(file);
        assert!(!check_bundle(&tampered, &BUNDLES[0]).unwrap());
        // Re-signed ad hoc (not by Google's Developer ID).
        let resigned = clone("resigned");
        let status = std::process::Command::new("codesign")
            .args(["--force", "--deep", "--sign", "-"])
            .arg(&resigned)
            .status()
            .unwrap();
        assert!(status.success(), "codesign failed");
        assert!(!check_bundle(&resigned, &BUNDLES[0]).unwrap());
        eprintln!("XP14-EVIDENCE tampered and re-signed Chrome clones refused");
        std::fs::remove_dir_all(&root).unwrap();
    }
}
