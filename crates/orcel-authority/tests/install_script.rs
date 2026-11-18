//! SG-000132: static checks of `scripts/install-orcel-authority.ps1` and of
//! the one installation procedure in SG132_INSTALL_RUNBOOK.md. The script is
//! never executed with elevation here (it changes the system); it is parsed,
//! its refusals are run unelevated, and its install path is checked for the
//! supply-chain, location and ACL rules the reviews asked for. The elevated
//! procedure itself runs in CI only (job "Authority install E2E").

use std::path::PathBuf;

fn repo_file(relative: &[&str]) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    for part in relative {
        path = path.join(part);
    }
    path
}

fn script() -> String {
    std::fs::read_to_string(repo_file(&["scripts", "install-orcel-authority.ps1"]))
        .expect("the install script")
}

fn runbook() -> String {
    std::fs::read_to_string(repo_file(&[
        "docs",
        "orcel",
        "implementation-readiness",
        "prep",
        "SG132_INSTALL_RUNBOOK.md",
    ]))
    .expect("the runbook")
}

fn position(text: &str, needle: &str) -> usize {
    text.find(needle)
        .unwrap_or_else(|| panic!("the text lacks {needle:?}"))
}

/// The staging folder's DACL, as the runbook's Stage line creates it.
const STAGING_SDDL: &str = "O:BAG:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";

#[test]
fn install_takes_only_hash_pinned_binaries_through_one_held_handle() {
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
    assert!(
        !text.contains("Copy-Item"),
        "binaries are copied from the held handle only"
    );
    let install = &text[position(&text, "function Install-Authority")..];
    let location = position(install, "Assert-TrustedLocation @($PSCommandPath");
    let held = position(
        install,
        "[System.IO.File]::Open($pair[1], [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)",
    );
    let first_hash = position(
        install,
        "Assert-StreamHash $held.Authority $sourceAuthority $AuthoritySha256",
    );
    let copy = position(
        install,
        "Copy-FromHeldStream $held.Authority $InstalledAuthority $AuthoritySha256",
    );
    let rehash = position(install, "Assert-Hash $InstalledAuthority $AuthoritySha256");
    assert!(
        location < held && held < first_hash && first_hash < copy && copy < rehash,
        "location check, open without write or delete sharing, hash, copy from that handle, hash again"
    );
    for (source, installed, hash) in [
        ("$sourceOrceld", "$InstalledOrceld", "$OrceldSha256"),
        ("$sourceOrcel", "$InstalledOrcel", "$OrcelSha256"),
    ] {
        let name = source.trim_start_matches("$source");
        assert!(install.contains(&format!("Assert-StreamHash $held.{name} {source} {hash}")));
        assert!(install.contains(&format!(
            "Copy-FromHeldStream $held.{name} {installed} {hash}"
        )));
        assert!(install.contains(&format!("Assert-Hash {installed} {hash}")));
    }
    // The copy is a new file (never written through something pre-placed)
    // and is hashed through its own handle.
    assert!(text.contains("[System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None"));
    assert!(
        text.contains("SHA-256 of this script"),
        "the script prints its own hash"
    );
}

#[test]
fn every_consumed_path_and_parent_must_be_admin_only() {
    let text = script();
    // Install: the script, its folder, the artifact folder and each binary.
    assert!(text.contains(
        "Assert-TrustedLocation @($PSCommandPath, (Split-Path -Parent $PSCommandPath), $ArtifactDir, $sourceAuthority, $sourceOrceld, $sourceOrcel)"
    ));
    // Uninstall runs elevated from the same place and is checked too.
    let uninstall = &text[position(&text, "function Uninstall-Authority")..];
    let checked = position(uninstall, "Assert-TrustedLocation @($PSCommandPath");
    assert!(checked < position(uninstall, "Stop-Service"));
    // Owner, reparse points, raw ACEs (unknown types refused), inherit-only
    // skipped, every parent up to the volume root, fixed local drives only.
    for needle in [
        "$PrivilegedSids -notcontains $owner",
        "[System.IO.FileAttributes]::ReparsePoint",
        "[System.Security.AccessControl.RawSecurityDescriptor]::new(",
        "$ace -isnot [System.Security.AccessControl.QualifiedAce]",
        "[System.Security.AccessControl.AceFlags]::InheritOnly",
        "has no DACL, so everyone has full control",
        "$next = Split-Path -Parent $parent",
        "[System.IO.DriveType]::Fixed",
    ] {
        assert!(text.contains(needle), "{needle}");
    }
    // The rights: on the consumed object every write, append, add, delete,
    // permission and owner right; on parents the entry rights.
    assert!(text.contains(
        "$EntryChangeRights = $FILE_DELETE_CHILD -bor $DELETE -bor $WRITE_DAC -bor $WRITE_OWNER -bor $GENERIC_ALL -bor $GENERIC_WRITE"
    ));
    assert!(text.contains(
        "$ContentChangeRights = $EntryChangeRights -bor $FILE_WRITE_DATA -bor $FILE_APPEND_DATA -bor $FILE_WRITE_EA -bor $FILE_WRITE_ATTRIBUTES"
    ));
    for (name, value) in [
        ("$FILE_WRITE_DATA", "0x2"),
        ("$FILE_APPEND_DATA", "0x4"),
        ("$FILE_WRITE_EA", "0x10"),
        ("$FILE_DELETE_CHILD", "0x40"),
        ("$FILE_WRITE_ATTRIBUTES", "0x100"),
        ("$DELETE", "0x10000"),
        ("$WRITE_DAC", "0x40000"),
        ("$WRITE_OWNER", "0x80000"),
        ("$GENERIC_ALL", "0x10000000"),
        ("$GENERIC_WRITE", "0x40000000"),
    ] {
        assert!(text.contains(&format!("{name} = {value}")), "{name}");
    }
}

#[test]
fn a_failed_install_rolls_back_every_change_it_made() {
    let text = script();
    let held = &text[position(&text, "function Install-Held")..];
    let try_at = position(held, "  try {");
    let catch_at = position(held, "$failed = @(Undo-Install $made $serviceSid)");
    // Each change is recorded before it is made, inside the try.
    for (flag, change) in [
        (
            "$made.Authority = $true",
            "Copy-FromHeldStream $held.Authority",
        ),
        (
            "$made.Service = $true",
            "Invoke-Checked 'sc.exe' @('create'",
        ),
        ("$made.StateDir = $true", "New-ProtectedDirectory $StateDir"),
        (
            "$made.PublicDir = $true",
            "New-ProtectedDirectory $PublicDir",
        ),
        ("$made.EventSource = $true", "New-Item -Path $EventKey"),
    ] {
        let at = position(held, flag);
        assert!(
            try_at < at && at < position(held, change) && position(held, change) < catch_at,
            "{flag}"
        );
    }
    assert!(
        position(held, "Wait-ServiceReady 30") < catch_at,
        "a start that does not come up fails the install"
    );
    let undo = &text
        [position(&text, "function Undo-Install")..position(&text, "function Install-Authority")];
    for when in [
        "$Made.Service",
        "$Made.EventSource",
        "$Made.PublicDir",
        "$Made.StateDir",
        "$Made.ProgramDataOrcel",
        "$Made.Orcel",
        "$Made.Orceld",
        "$Made.Authority",
        "$Made.ProgramFilesDir",
        "$Made.ProgramFilesOrcel",
    ] {
        assert!(undo.contains(&format!("When = {when}")), "{when}");
    }
    assert!(text.contains("every change it made was rolled back"));
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
fn uninstall_waits_for_the_stop_and_removes_the_profile_and_only_the_staged_files() {
    let text = script();
    let uninstall = &text[position(&text, "function Uninstall-Authority")..];
    let wait = position(uninstall, "Wait-ServiceStopped $ServiceName 60");
    let delete = position(uninstall, "'delete', $ServiceName");
    assert!(wait < delete);
    assert!(text.contains("Win32_UserProfile"));
    assert!(text.contains(
        "$StagedFiles = @('install-orcel-authority.ps1', 'orcel-authority.exe', 'orceld.exe', 'orcel.exe')"
    ));
    assert!(text.contains("$StagingDir = Join-Path $env:ProgramFiles 'OrcelStaging'"));
    let staging = &uninstall[position(uninstall, "if ($RemoveStaging) {\n")..];
    assert!(
        !staging[..position(staging, "Write-Host 'Uninstalled.")].contains("-Recurse"),
        "no recursive delete of the staging"
    );
}

/// PowerShell single-quoted string contents: `''` is one quote.
fn unquote_single(text: &str) -> String {
    text.replace("''", "'")
}

/// (FilePath, ArgumentList) of every `Start-Process -Verb RunAs` line.
fn start_process_lines(runbook: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in runbook.lines() {
        let Some(rest) = line.strip_prefix("Start-Process -Verb RunAs -FilePath '") else {
            continue;
        };
        let (file, arguments) = rest
            .split_once("' -ArgumentList '")
            .unwrap_or_else(|| panic!("FilePath then ArgumentList: {line}"));
        let arguments = arguments
            .strip_suffix('\'')
            .unwrap_or_else(|| panic!("the line ends its ArgumentList: {line}"));
        out.push((unquote_single(file), unquote_single(arguments)));
    }
    out
}

/// (step, program location, exact command line) of the UAC table.
fn uac_table(runbook: &str) -> Vec<(String, String, String)> {
    let start = position(runbook, "| Step | Program location | Exact command line |");
    runbook[start..]
        .lines()
        .skip(2)
        .take_while(|line| line.starts_with("| "))
        .map(|line| {
            let cells: Vec<&str> = line.trim_matches('|').split(" | ").map(str::trim).collect();
            assert_eq!(cells.len(), 3, "{line}");
            let code = |cell: &str| {
                cell.strip_prefix('`')
                    .and_then(|c| c.strip_suffix('`'))
                    .unwrap_or_else(|| panic!("a code cell: {cell}"))
                    .to_owned()
            };
            (cells[0].to_owned(), code(cells[1]), code(cells[2]))
        })
        .collect()
}

/// ONE procedure: every UAC table row is produced by exactly one
/// `Start-Process` line and the other way round, so the founder's checked
/// command line, the line he runs and the line CI runs are the same text.
#[test]
fn the_runbook_table_and_its_start_process_lines_are_the_same_commands() {
    let text = runbook();
    let table = uac_table(&text);
    let lines = start_process_lines(&text);
    assert_eq!(
        table.len(),
        lines.len(),
        "one Start-Process line per table row"
    );
    for (file, arguments) in &lines {
        let command = format!("\"{file}\" {arguments}");
        let rows: Vec<_> = table
            .iter()
            .filter(|(_, _, exact)| *exact == command)
            .collect();
        assert_eq!(rows.len(), 1, "exactly one table row for {command}");
        assert_eq!(&rows[0].1, file, "program location of {}", rows[0].0);
    }
    let steps: Vec<&str> = table.iter().map(|(step, _, _)| step.as_str()).collect();
    for step in [
        "Stage",
        "Install",
        "Uninstall",
        "Uninstall, keeping the state",
    ] {
        assert!(steps.contains(&step), "{step}");
    }
    let long: Vec<&str> = text
        .lines()
        .filter(|line| line.len() >= 2000)
        .map(|line| &line[..80])
        .collect();
    assert!(
        long.is_empty(),
        "runbook lines of 2000 characters or more: {long:?}"
    );
}

#[test]
fn the_stage_line_creates_an_admin_only_folder_and_pins_the_script_hash() {
    let text = runbook();
    let lines = start_process_lines(&text);
    let stage: Vec<_> = lines
        .iter()
        .filter(|(_, a)| a.contains("SetSecurityDescriptorSddlForm"))
        .collect();
    assert_eq!(stage.len(), 1);
    let (file, arguments) = stage[0];
    assert_eq!(
        file,
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    );
    let command = arguments
        .split_once("-Command \"")
        .map(|(_, rest)| rest.strip_suffix('"').expect("closing quote"))
        .expect("-Command");
    assert!(
        !command.contains('"'),
        "no inner double quotes on the -Command line"
    );
    let ordered = [
        "$d = Join-Path $env:ProgramFiles 'OrcelStaging'",
        "if (Test-Path -LiteralPath $d) { throw",
        &format!("$s.SetSecurityDescriptorSddlForm('{STAGING_SDDL}')"),
        "[void][IO.Directory]::CreateDirectory($d, $s)",
        "foreach ($n in 'install-orcel-authority.ps1', 'orcel-authority.exe', 'orceld.exe', 'orcel.exe')",
        "$a.SetOwner([Security.Principal.SecurityIdentifier]'S-1-5-32-544')",
        "(Get-FileHash -LiteralPath (Join-Path $d 'install-orcel-authority.ps1')).Hash -ne '<script-sha256>'",
        "Remove-Item -LiteralPath $d -Recurse -Force; throw",
        "icacls $d",
    ];
    let mut last = 0;
    for needle in ordered {
        let at = position(command, needle);
        assert!(at >= last, "in order: {needle}");
        last = at;
    }
    assert!(command.starts_with("$ErrorActionPreference = 'Stop';"));
    // The installer's staging path and file list agree with the Stage line.
    let script = script();
    assert!(script.contains("$StagingDir = Join-Path $env:ProgramFiles 'OrcelStaging'"));
    // Install and uninstall run the staged script, and install takes the
    // binaries from the staging folder.
    let staged = r#"-File "C:\Program Files\OrcelStaging\install-orcel-authority.ps1""#;
    let install: Vec<_> = lines
        .iter()
        .filter(|(_, a)| a.contains("-ArtifactDir"))
        .collect();
    assert_eq!(install.len(), 1);
    assert!(install[0].1.contains(&format!(
        r#"{staged} -ArtifactDir "C:\Program Files\OrcelStaging" -AuthoritySha256 <authority-sha256> -OrceldSha256 <orceld-sha256> -OrcelSha256 <orcel-sha256>"#
    )));
    for (_, arguments) in lines.iter().filter(|(_, a)| a.contains("-Uninstall")) {
        assert!(
            arguments.contains(staged) && arguments.ends_with("-RemoveStaging"),
            "{arguments}"
        );
    }
    // The weaker alternatives are gone.
    for old in [
        r"C:\OrcelBuild\install-orcel-authority.ps1",
        "/d /c mkdir",
        "Admin-only build",
    ] {
        assert!(!text.contains(old), "the runbook still offers {old}");
    }
}

#[test]
fn the_runbook_documents_provenance_and_the_expected_staging_acl() {
    let text = runbook();
    assert!(text.contains(
        "gh attestation verify (Join-Path '<download-folder>' $n) --repo TheHalfMoon/Orcel --signer-workflow TheHalfMoon/Orcel/.github/workflows/ci.yml --source-ref refs/heads/main --source-digest <commit> --deny-self-hosted-runners"
    ));
    let block = &text[position(&text, "<!-- expected-staging-acl -->\n```text\n")..];
    let block = &block[..position(block, "\n```\n")];
    for line in [
        r"C:\Program Files\OrcelStaging NT AUTHORITY\SYSTEM:(OI)(CI)(F)",
        r"BUILTIN\Users:(OI)(CI)(RX)",
        r"BUILTIN\Administrators:(OI)(CI)(F)",
        r"C:\Program Files\OrcelStaging\orcel-authority.exe NT AUTHORITY\SYSTEM:(F)",
        r"BUILTIN\Administrators protected=True",
    ] {
        assert!(block.contains(line), "{line}");
    }
    for other in [
        "Authenticated Users",
        "Everyone",
        "INTERACTIVE",
        "CREATOR OWNER",
        "OWNER RIGHTS",
    ] {
        assert!(!block.contains(other), "{other}");
    }
    assert!(text.contains("authority-install-e2e-report"));
}

#[cfg(windows)]
fn script_path() -> PathBuf {
    repo_file(&["scripts", "install-orcel-authority.ps1"])
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
fn run_shell(shell: &str, command: &str) -> (bool, String) {
    let output = std::process::Command::new(shell)
        .args(["-NoProfile", "-NonInteractive", "-Command", command])
        .output()
        .expect("a PowerShell");
    (
        output.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )
}

#[cfg(windows)]
#[test]
fn the_scripts_parse_in_every_shell() {
    for path in [
        script_path(),
        repo_file(&["scripts", "authority-install-e2e.ps1"]),
    ] {
        let command = format!(
            "$errors = $null; [System.Management.Automation.Language.Parser]::ParseFile('{}', [ref]$null, [ref]$errors) | Out-Null; if ($errors.Count) {{ $errors | ForEach-Object {{ $_.ToString() }}; exit 1 }}",
            path.display()
        );
        for shell in shells() {
            let (ok, text) = run_shell(shell, &command);
            assert!(ok, "{shell} {}: {text}", path.display());
        }
    }
}

/// The location check, dot-sourced (dot-sourcing changes nothing): System32
/// passes, the user's temp folder and a junction are refused.
#[cfg(windows)]
#[test]
fn the_location_check_accepts_system32_and_refuses_user_folders_and_junctions() {
    let dir = std::env::temp_dir().join(format!("orcel-location-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("target")).expect("dir");
    let junction = dir.join("junction");
    let made = std::process::Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&junction)
        .arg(dir.join("target"))
        .output()
        .expect("mklink");
    assert!(
        made.status.success(),
        "{}",
        String::from_utf8_lossy(&made.stdout)
    );
    let command = format!(
        ". '{script}'; $a = @(Get-LocationProblems (Join-Path $env:SystemRoot 'System32\\cmd.exe')); $b = @(Get-LocationProblems '{temp}'); $c = @(Get-LocationProblems '{junction}'); 'system32=' + $a.Count; $b; $c",
        script = script_path().display(),
        temp = dir.display(),
        junction = junction.display(),
    );
    for shell in shells() {
        let (ok, text) = run_shell(shell, &command);
        assert!(ok, "{shell}: {text}");
        assert!(
            text.contains("system32=0"),
            "{shell}: System32 is admin-only: {text}"
        );
        assert!(
            text.contains("not SYSTEM, Administrators or TrustedInstaller"),
            "{shell}: {text}"
        );
        assert!(text.contains("is a reparse point"), "{shell}: {text}");
    }
    let _ = std::fs::remove_dir(&junction);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Unelevated, from a user-writable folder, even the `-WhatIf` preview is
/// refused by the location check before any file is hashed (a wrong hash is
/// not even reached), and nothing changes.
#[cfg(windows)]
#[test]
fn a_user_writable_location_is_refused_before_anything_is_read() {
    let dir = std::env::temp_dir().join(format!("orcel-authority-artifact-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("artifact dir");
    for name in ["orcel-authority.exe", "orceld.exe", "orcel.exe"] {
        std::fs::write(dir.join(name), name.as_bytes()).expect("write");
    }
    let zero = "0".repeat(64);
    for shell in shells() {
        for what_if in [true, false] {
            let mut command = std::process::Command::new(shell);
            command
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                ])
                .arg(script_path());
            if what_if {
                command.arg("-WhatIf");
            }
            let output = command
                .arg("-ArtifactDir")
                .arg(&dir)
                .args([
                    "-AuthoritySha256",
                    &zero,
                    "-OrceldSha256",
                    &zero,
                    "-OrcelSha256",
                    &zero,
                ])
                .output()
                .expect("a PowerShell");
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(!output.status.success(), "{shell}: {text}");
            assert!(text.contains("SHA-256 of this script"), "{shell}: {text}");
            if text.contains("Run this script elevated") {
                // Not elevated and no -WhatIf: refused before the location check.
                assert!(!what_if, "{shell}: {text}");
                continue;
            }
            assert!(text.contains("refused:"), "{shell}: {text}");
            assert!(text.contains("Nothing was changed"), "{shell}: {text}");
            assert!(
                !text.contains("SHA-256 mismatch"),
                "{shell}: refused before hashing: {text}"
            );
            assert!(
                !text.contains("What if"),
                "{shell}: nothing planned: {text}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
