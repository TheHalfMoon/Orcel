//! SG-000132 slice 1: static checks of `scripts/install-orcel-authority.ps1`.
//! The script is never executed here (it changes the system and needs
//! elevation); it is parsed and its install path is checked for the
//! supply-chain and ACL rules the review asked for.

use std::path::PathBuf;

fn script() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("scripts")
        .join("install-orcel-authority.ps1");
    std::fs::read_to_string(path).expect("the install script")
}

fn position(text: &str, needle: &str) -> usize {
    text.find(needle)
        .unwrap_or_else(|| panic!("the script lacks {needle:?}"))
}

#[test]
fn install_takes_only_hash_pinned_binaries_and_verifies_before_and_after_copying() {
    let text = script();
    for parameter in [
        "[string]$ArtifactDir",
        "[string]$AuthoritySha256",
        "[string]$OrceldSha256",
    ] {
        assert!(text.contains(parameter), "{parameter}");
    }
    assert!(
        !text.contains("target\\release"),
        "no implicit build directory"
    );
    assert!(
        !text.contains("$PSScriptRoot"),
        "no repository-relative binaries"
    );
    let install = &text[position(&text, "function Install-Authority")..];
    let first_hash = position(install, "Assert-Hash $sourceAuthority $AuthoritySha256");
    let copy = position(install, "Copy-Item -LiteralPath $sourceAuthority");
    let rehash = position(install, "Assert-Hash $InstalledAuthority $AuthoritySha256");
    assert!(first_hash < copy && copy < rehash, "hash, copy, hash again");
    assert!(install.contains("Assert-Hash $sourceOrceld $OrceldSha256"));
    assert!(install.contains("Assert-Hash $InstalledOrceld $OrceldSha256"));
    assert!(
        text.contains("SHA-256 of this script"),
        "the script prints its own hash"
    );
}

#[test]
fn the_trusted_orceld_is_the_program_files_copy_and_directories_are_created_protected() {
    let text = script();
    assert!(text.contains("$InstalledOrceld = Join-Path $ProgramFilesOrcel 'orceld.exe'"));
    assert!(text.contains("trusted_orceld_images = @($InstalledOrceld)"));
    for sddl in [
        "'O:BAG:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)'",
        "\"O:BAG:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;$serviceSid)\"",
    ] {
        assert!(text.contains(sddl), "{sddl}");
    }
    assert!(text.contains("[System.IO.Directory]::CreateDirectory($Path, $security)"));
    assert!(
        text.contains("AreAccessRulesProtected") && text.contains("GetOwner($sidType)"),
        "security is read back"
    );
    assert!(!text.contains("icacls"), "no create-then-protect window");
}

#[test]
fn uninstall_waits_for_the_stop_and_removes_the_profile() {
    let text = script();
    let uninstall = &text[position(&text, "function Uninstall-Authority")..];
    let wait = position(uninstall, "Wait-ServiceStopped $ServiceName 60");
    let delete = position(uninstall, "'delete', $ServiceName");
    assert!(wait < delete);
    assert!(uninstall.contains("Win32_UserProfile"));
}

#[cfg(windows)]
#[test]
fn the_script_parses() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("scripts")
        .join("install-orcel-authority.ps1");
    let command = format!(
        "$errors = $null; [System.Management.Automation.Language.Parser]::ParseFile('{}', [ref]$null, [ref]$errors) | Out-Null; if ($errors.Count) {{ $errors | ForEach-Object {{ $_.ToString() }}; exit 1 }}",
        path.display()
    );
    let output = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &command])
        .output()
        .expect("powershell.exe");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}
