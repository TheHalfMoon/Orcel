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
        "[string]$OrcelSha256",
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
    // Slice 2 review F1 (b): the owner CLI is hash-pinned the same way.
    assert!(install.contains("Assert-Hash $sourceOrcel $OrcelSha256"));
    assert!(install.contains("Assert-Hash $InstalledOrcel $OrcelSha256"));
    assert!(
        text.contains("SHA-256 of this script"),
        "the script prints its own hash"
    );
}

#[test]
fn the_trusted_orceld_is_the_program_files_copy_and_directories_are_created_protected() {
    let text = script();
    assert!(text.contains("$InstalledOrceld = Join-Path $ProgramFilesOrcel 'orceld.exe'"));
    assert!(text.contains(
        "trusted_orceld_images = @($InstalledOrceld); trusted_owner_cli_images = @($InstalledOrcel)"
    ));
    assert!(text.contains("$InstalledOrcel = Join-Path $ProgramFilesOrcel 'orcel.exe'"));
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
fn script_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("scripts")
        .join("install-orcel-authority.ps1")
}

/// Windows PowerShell 5.1 always; PowerShell 7 when `pwsh` is installed.
#[cfg(windows)]
fn shells() -> Vec<&'static str> {
    let mut shells = vec!["powershell.exe"];
    let pwsh = std::process::Command::new("pwsh")
        .args(["-NoProfile", "-NonInteractive", "-Command", "exit 0"])
        .output();
    if pwsh.is_ok_and(|output| output.status.success()) {
        shells.push("pwsh");
    }
    shells
}

#[cfg(windows)]
#[test]
fn the_script_parses_in_every_shell() {
    let command = format!(
        "$errors = $null; [System.Management.Automation.Language.Parser]::ParseFile('{}', [ref]$null, [ref]$errors) | Out-Null; if ($errors.Count) {{ $errors | ForEach-Object {{ $_.ToString() }}; exit 1 }}",
        script_path().display()
    );
    for shell in shells() {
        let output = std::process::Command::new(shell)
            .args(["-NoProfile", "-NonInteractive", "-Command", &command])
            .output()
            .expect("a PowerShell");
        assert!(
            output.status.success(),
            "{shell}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

/// The `-WhatIf` preview runs without elevation and changes nothing: it
/// verifies the artifact hashes and prints every planned change. A wrong
/// hash stops it. (If the service is installed on this machine, the
/// preview stops at "already exists", which is also no change.)
#[cfg(windows)]
#[test]
fn the_whatif_preview_runs_unelevated_in_every_shell_and_checks_hashes() {
    use sha2::{Digest, Sha256};
    let dir = std::env::temp_dir().join(format!("orcel-authority-artifact-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("artifact dir");
    let hash = |bytes: &[u8]| {
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    std::fs::write(dir.join("orcel-authority.exe"), b"authority bytes").expect("write");
    std::fs::write(dir.join("orceld.exe"), b"orceld bytes").expect("write");
    std::fs::write(dir.join("orcel.exe"), b"orcel bytes").expect("write");
    let good_orcel = hash(b"orcel bytes");
    let good_authority = hash(b"authority bytes");
    let good_orceld = hash(b"orceld bytes");
    println!("shells: {:?}", shells());
    for shell in shells() {
        let run = |authority: &str| {
            std::process::Command::new(shell)
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                ])
                .arg(script_path())
                .arg("-WhatIf")
                .arg("-ArtifactDir")
                .arg(&dir)
                .args(["-AuthoritySha256", authority, "-OrceldSha256", &good_orceld])
                .args(["-OrcelSha256", &good_orcel])
                .output()
                .expect("a PowerShell")
        };
        let output = run(&good_authority);
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if text.contains("already exists") {
            continue;
        }
        assert!(output.status.success(), "{shell}: {text}");
        assert!(text.contains("SHA-256 of this script"), "{shell}: {text}");
        assert!(
            text.contains(&good_authority),
            "{shell}: the hash is printed"
        );
        assert!(text.contains("What if"), "{shell}: {text}");
        let wrong = run(&"0".repeat(64));
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&wrong.stdout),
            String::from_utf8_lossy(&wrong.stderr)
        );
        assert!(
            !wrong.status.success(),
            "{shell}: a wrong hash must stop the preview"
        );
        assert!(text.contains("SHA-256 mismatch"), "{shell}: {text}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
