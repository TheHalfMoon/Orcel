//! SG-000132 install hardening: static checks that the one installation
//! procedure in SG132_INSTALL_RUNBOOK.md, the native installer
//! (`orcel-authority install|uninstall`, `src/win/install.rs`) and the CI
//! install E2E (`scripts/authority-install-e2e.ps1`) are the same procedure.
//! Nothing here runs elevated; the elevated procedure runs in CI only (job
//! "Authority install E2E").

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

/// The file's text with LF line ends (a Windows checkout may convert them).
fn read_lf(relative: &[&str]) -> String {
    std::fs::read_to_string(repo_file(relative))
        .unwrap_or_else(|error| panic!("{relative:?}: {error}"))
        .replace("\r\n", "\n")
}

fn runbook() -> String {
    read_lf(&[
        "docs",
        "orcel",
        "implementation-readiness",
        "prep",
        "SG132_INSTALL_RUNBOOK.md",
    ])
}

fn installer() -> String {
    read_lf(&["crates", "orcel-authority", "src", "win", "install.rs"])
}

fn installer_os() -> String {
    read_lf(&["crates", "orcel-authority", "src", "win", "install_os.rs"])
}

fn e2e() -> String {
    read_lf(&["scripts", "authority-install-e2e.ps1"])
}

fn position(text: &str, needle: &str) -> usize {
    text.find(needle)
        .unwrap_or_else(|| panic!("the text lacks {needle:?}"))
}

const SYSTEM32: &str = r"C:\Windows\System32\";
const STAGED_AUTHORITY: &str = r"C:\Program Files\OrcelStaging\orcel-authority.exe";
const STAGING: &str = r"C:\Program Files\OrcelStaging";

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

/// (step, program location, exact command line) of the UAC table; `\|`
/// in a cell is a plain `|`.
fn uac_table(runbook: &str) -> Vec<(String, String, String)> {
    let start = position(runbook, "| Step | Program location | Exact command line |");
    runbook[start..]
        .lines()
        .skip(2)
        .take_while(|line| line.starts_with("| "))
        .map(|line| {
            let cells: Vec<String> = line
                .trim_matches('|')
                .split(" | ")
                .map(|cell| cell.trim().replace("\\|", "|"))
                .collect();
            assert_eq!(cells.len(), 3, "{line}");
            let code = |cell: &str| {
                cell.strip_prefix('`')
                    .and_then(|c| c.strip_suffix('`'))
                    .unwrap_or_else(|| panic!("a code cell: {cell}"))
                    .to_owned()
            };
            (cells[0].clone(), code(&cells[1]), code(&cells[2]))
        })
        .collect()
}

fn command_for<'a>(lines: &'a [(String, String)], needle: &str) -> &'a (String, String) {
    let found: Vec<_> = lines.iter().filter(|(_, a)| a.contains(needle)).collect();
    assert_eq!(
        found.len(),
        1,
        "exactly one Start-Process line with {needle:?}"
    );
    found[0]
}

/// ONE procedure: every UAC table row is produced by exactly one
/// `Start-Process` line and the other way round, so the founder's checked
/// command line, the line he runs and the line CI runs are the same text.
#[test]
fn the_runbook_table_and_its_start_process_lines_are_the_same_commands() {
    let text = runbook();
    let table = uac_table(&text);
    let lines = start_process_lines(&text);
    assert_eq!(table.len(), 9);
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

/// Review finding 1 and 2: no elevated step starts PowerShell or a .NET
/// program; each is cmd.exe or sc.exe from System32, the staged native
/// installer or the installed native CLI.
#[test]
fn no_elevated_step_runs_powershell_or_dotnet() {
    let text = runbook();
    for (step, program, exact) in uac_table(&text) {
        let allowed = [
            r"C:\Windows\System32\cmd.exe",
            r"C:\Windows\System32\sc.exe",
            STAGED_AUTHORITY,
            r"C:\Program Files\Orcel\orcel.exe",
        ];
        assert!(allowed.contains(&program.as_str()), "{step}: {program}");
        let lowered = exact.to_lowercase();
        for forbidden in ["powershell", "pwsh", ".ps1", "dotnet", "-command", "-file"] {
            assert!(!lowered.contains(forbidden), "{step} names {forbidden}");
        }
    }
    assert!(
        !repo_file(&["scripts", "install-orcel-authority.ps1"]).exists(),
        "the PowerShell installer is gone"
    );
}

/// Every program a cmd step runs is named by its full System32 path (or is
/// the staged binary): nothing is found through PATH, and PATH, SystemRoot
/// and windir are reset first.
#[test]
fn cmd_steps_name_every_program_by_full_path_and_reset_the_environment() {
    let text = runbook();
    for (step, program, exact) in uac_table(&text) {
        if program != r"C:\Windows\System32\cmd.exe" {
            continue;
        }
        let body = exact
            .split_once(" /s /c \"")
            .map(|(head, rest)| {
                assert_eq!(
                    head, "\"C:\\Windows\\System32\\cmd.exe\" /d /e:on /v:off",
                    "{step}: AutoRun off, extensions on, delayed expansion off"
                );
                rest
            })
            .unwrap_or_else(|| panic!("{step}: /s /c"));
        assert!(body.starts_with(
            "set \"PATH=C:\\Windows\\System32\" && set \"SystemRoot=C:\\Windows\" && set \"windir=C:\\Windows\" && set \"COMSPEC=C:\\Windows\\System32\\cmd.exe\" && "
        ), "{step}");
        // Every program file named in the line sits in System32, the
        // staging folder or (as a copy source) the download folder.
        let lowered = body.to_lowercase();
        for (at, _) in lowered.match_indices(".exe") {
            let head = &body[..at + 4];
            let name_start = head.rfind('\\').map_or(0, |i| i + 1);
            let name = &head[name_start..];
            let named = |prefix: &str| head.ends_with(&format!("{prefix}{name}"));
            assert!(
                named(SYSTEM32)
                    || named(r"C:\Program Files\OrcelStaging\")
                    || named(r"<download-folder>\"),
                "{step}: {name} is not named by an allowed full path"
            );
        }
        assert!(!body.contains('%') && !body.contains('!') && !body.contains('^'));
    }
}

#[test]
fn the_stage_line_locks_the_folder_and_checks_every_copy_before_anything_runs_from_it() {
    let text = runbook();
    let lines = start_process_lines(&text);
    let (file, stage) = command_for(&lines, &format!("mkdir \"{STAGING}\""));
    assert_eq!(file, r"C:\Windows\System32\cmd.exe");
    let ordered = [
        &format!("mkdir \"{STAGING}\" && ("),
        &format!(r#"C:\Windows\System32\icacls.exe "{STAGING}" /setowner *S-1-5-32-544"#),
        &format!(
            r#"C:\Windows\System32\icacls.exe "{STAGING}" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX""#
        ),
        // Each copy names its destination file: a source that is really a
        // folder cannot bring other files (a DLL) into the staging folder.
        &format!(
            r#"copy /b /y "<download-folder>\orcel-authority.exe" "{STAGING}\orcel-authority.exe""#
        ),
        &format!(r#"copy /b /y "<download-folder>\orceld.exe" "{STAGING}\orceld.exe""#),
        &format!(r#"copy /b /y "<download-folder>\orcel.exe" "{STAGING}\orcel.exe""#),
        &format!(r#"C:\Windows\System32\icacls.exe "{STAGING}\*" /setowner *S-1-5-32-544 /L"#),
        &format!(r#"C:\Windows\System32\icacls.exe "{STAGING}\*" /reset /L"#),
        // Exactly three entries in the folder.
        &format!(
            r#"C:\Windows\System32\cmd.exe /d /c dir /b /a "{STAGING}" | C:\Windows\System32\find.exe /c /v "" | C:\Windows\System32\findstr.exe /l /x /c:"3""#
        ),
        &format!(
            r#"C:\Windows\System32\certutil.exe -hashfile "{STAGING}\orcel-authority.exe" SHA256 | C:\Windows\System32\findstr.exe /l /x /i /c:"<authority-sha256>""#
        ),
        &format!(
            r#"C:\Windows\System32\certutil.exe -hashfile "{STAGING}\orceld.exe" SHA256 | C:\Windows\System32\findstr.exe /l /x /i /c:"<orceld-sha256>""#
        ),
        &format!(
            r#"C:\Windows\System32\certutil.exe -hashfile "{STAGING}\orcel.exe" SHA256 | C:\Windows\System32\findstr.exe /l /x /i /c:"<orcel-sha256>""#
        ),
        &"echo STAGED: exactly the three files, each with its SHA-256 || (".to_owned(),
        &format!(r#"rmdir /s /q "{STAGING}" & echo STAGING REFUSED"#),
        &r"C:\Windows\System32\cmd.exe /d /c exit 1)) & pause".to_owned(),
    ];
    let mut last = 0;
    for needle in ordered {
        let at = position(stage, needle);
        assert!(at >= last, "in order: {needle}");
        last = at;
    }
    // Each step is chained with && inside the group, so any failure reaches
    // the cleanup; a pre-existing folder fails mkdir before the group.
    let group = &stage[position(stage, "&& (") + 4..position(stage, " || (")];
    assert!(!group.contains(" & "), "only && inside the checked group");
    // The installer copies exactly what the Stage line staged.
    let source = installer();
    assert!(source.contains(
        "pub const STAGED_FILES: [&str; 3] = [\"orcel-authority.exe\", \"orceld.exe\", \"orcel.exe\"];"
    ));
    assert!(source.contains("pub const STAGING_DIR_NAME: &str = \"OrcelStaging\";"));
    // No copy names the folder alone as its destination.
    assert!(!stage.contains(&format!(r#"" "{STAGING}" &&"#)));
}

/// Review 2 finding 1 (d) and 5: removing a staging folder that failed the
/// check runs nothing from it, and every cmd window closes after a key.
#[test]
fn removing_the_staging_runs_nothing_from_it_and_windows_close() {
    let text = runbook();
    let lines = start_process_lines(&text);
    let (file, remove) = command_for(&lines, "echo REMOVED");
    assert_eq!(file, r"C:\Windows\System32\cmd.exe");
    assert!(remove.contains(&format!(r#"rmdir /s /q "{STAGING}" && echo REMOVED"#)));
    assert!(
        !remove.contains(&format!("{STAGING}\\")),
        "runs no program from the folder"
    );
    for (_, arguments) in lines.iter().filter(|(file, _)| file.ends_with(r"\cmd.exe")) {
        assert!(arguments.ends_with(" & pause\""), "{arguments}");
        assert!(
            !arguments.contains(" /k "),
            "no elevated prompt is left open"
        );
    }
    let step5 = &text
        [position(&text, "### 5. Check the staging folder")..position(&text, "### 6. Preview")];
    assert!(step5.contains("run the Remove the staging line"));
    assert!(!step5.contains("run the Uninstall line"));
}

/// Review 2 finding 1 (c): the authority image resolves its imports from
/// System32 only (DependentLoadFlags 0x800, set by build.rs), whatever is in
/// its folder. The C runtime is linked statically in the CI release build;
/// scripts/check-authority-binaries.ps1 checks that on the artifact.
#[cfg(windows)]
#[test]
fn the_authority_image_resolves_its_imports_from_system32_only() {
    let bytes = std::fs::read(env!("CARGO_BIN_EXE_orcel-authority")).expect("the binary");
    let u16_at = |at: usize| u16::from_le_bytes([bytes[at], bytes[at + 1]]);
    let u32_at =
        |at: usize| u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
    let pe = u32_at(0x3c) as usize;
    assert_eq!(u32_at(pe), 0x0000_4550, "PE signature");
    let coff = pe + 4;
    let sections = u16_at(coff + 2) as usize;
    let optional = coff + 20;
    assert_eq!(u16_at(optional), 0x20b, "PE32+");
    let table = optional + u16_at(coff + 16) as usize;
    let load_config_rva = u32_at(optional + 112 + 8 * 10);
    assert_ne!(load_config_rva, 0, "a load configuration directory");
    let offset = (0..sections)
        .map(|i| table + 40 * i)
        .find_map(|s| {
            let va = u32_at(s + 12);
            let size = u32_at(s + 8).max(u32_at(s + 16));
            (load_config_rva >= va && load_config_rva < va + size)
                .then(|| (load_config_rva - va + u32_at(s + 20)) as usize)
        })
        .expect("the section holding the load configuration");
    assert!(
        u32_at(offset) >= 0x50,
        "the load configuration holds DependentLoadFlags"
    );
    assert_eq!(
        u16_at(offset + 0x4e),
        0x0800,
        "LOAD_LIBRARY_SEARCH_SYSTEM32"
    );
    let build = read_lf(&["crates", "orcel-authority", "build.rs"]);
    assert!(build.contains("cargo:rustc-link-arg-bins=/DEPENDENTLOADFLAG:0x800"));

    // Review 3 finding 1: the DLLs that are not KnownDLLs are delay-loaded
    // (after main restricted every load to System32), never imported.
    let to_offset = |rva: u32| {
        (0..sections)
            .map(|i| table + 40 * i)
            .find_map(|s| {
                let va = u32_at(s + 12);
                let size = u32_at(s + 8).max(u32_at(s + 16));
                (rva >= va && rva < va + size).then(|| (rva - va + u32_at(s + 20)) as usize)
            })
            .expect("an RVA inside a section")
    };
    let name_at = |at: usize| {
        let end = at + bytes[at..].iter().position(|b| *b == 0).expect("NUL");
        String::from_utf8_lossy(&bytes[at..end]).to_lowercase()
    };
    let names = |directory: usize, stride: usize, name_field: usize| {
        let mut out = Vec::new();
        let rva = u32_at(optional + 112 + 8 * directory);
        if rva == 0 {
            return out;
        }
        let mut entry = to_offset(rva);
        while u32_at(entry + name_field) != 0 {
            out.push(name_at(to_offset(u32_at(entry + name_field))));
            entry += stride;
        }
        out
    };
    let imports = names(1, 20, 12);
    let delayed = names(13, 32, 4);
    for dll in ["wtsapi32.dll", "bcrypt.dll", "crypt32.dll"] {
        assert!(
            !imports.contains(&dll.to_owned()),
            "{dll} is imported: {imports:?}"
        );
        assert!(
            delayed.contains(&dll.to_owned()),
            "{dll} is not delay-loaded: {delayed:?}"
        );
        assert!(build.contains(dll), "build.rs names {dll}");
    }
    for dll in &imports {
        assert!(
            ["kernel32.dll", "advapi32.dll", "oleaut32.dll", "ntdll.dll"].contains(&dll.as_str())
                || dll.starts_with("api-ms-win-")
                || dll.starts_with("vcruntime")
                || dll.starts_with("api-ms-win-crt-"),
            "{dll} is imported but is not a KnownDLL (the debug build may import the C runtime; the release build must not)"
        );
    }
    // main restricts the DLL search before anything else.
    let main = read_lf(&[
        "crates",
        "orcel-authority",
        "src",
        "bin",
        "orcel-authority.rs",
    ]);
    let body = &main[position(&main, "fn main()")..];
    assert!(
        position(body, "harden_dll_search()") < position(body, "match args.first()"),
        "the DLL search is restricted first"
    );
}

#[test]
fn install_and_uninstall_run_the_staged_native_installer() {
    let text = runbook();
    let lines = start_process_lines(&text);
    let (file, install) = command_for(&lines, "install --authority-sha256");
    assert_eq!(file, STAGED_AUTHORITY);
    assert_eq!(
        install,
        "install --authority-sha256 <authority-sha256> --orceld-sha256 <orceld-sha256> --orcel-sha256 <orcel-sha256> --pause"
    );
    for (needle, tail) in [
        (" uninstall && ", "uninstall && rmdir"),
        (
            " uninstall --keep-state && ",
            "uninstall --keep-state && rmdir",
        ),
    ] {
        let (file, uninstall) = command_for(&lines, needle);
        assert_eq!(file, r"C:\Windows\System32\cmd.exe");
        assert!(uninstall.contains(&format!(
            "\"{STAGED_AUTHORITY}\" {tail} /s /q \"{STAGING}\""
        )));
    }
    // The binary dispatches both subcommands before anything else.
    let main = read_lf(&[
        "crates",
        "orcel-authority",
        "src",
        "bin",
        "orcel-authority.rs",
    ]);
    assert!(main.contains("Some(\"install\") => {"));
    assert!(main
        .contains("std::process::exit(orcel_authority::win::install::install_main(&args[1..]))"));
    assert!(main.contains("orcel_authority::win::install::uninstall_main(&args[1..])"));
}

/// The native installer's guarantees the review asked for, pinned in its
/// source (its unit tests exercise them).
#[test]
fn the_native_installer_hardens_itself_before_reading_anything() {
    let source = installer();
    let os = installer_os();
    for function in [
        "fn install(args: &InstallArgs)",
        "fn uninstall(args: &UninstallArgs)",
    ] {
        let body = &source[position(&source, function)..];
        let harden = position(body, "os::harden_dll_search()?;");
        let paths = position(body, "Paths::resolve()?");
        let location = position(body, "check_location(&paths)?;");
        assert!(harden < paths && paths < location, "{function}");
    }
    let install = &source[position(&source, "fn install(args: &InstallArgs)")..];
    assert!(
        position(install, "check_location(&paths)?;")
            < position(install, "hold_and_hash(&paths, args)?")
    );
    assert!(position(install, "hold_and_hash(&paths, args)?") < position(install, "match apply("));
    for needle in [
        "SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)",
        "SetDllDirectoryW(empty.as_ptr())",
        "LoadLibraryExW(wide_dll.as_ptr(), 0, LOAD_LIBRARY_SEARCH_SYSTEM32)",
        "SHGetKnownFolderPath",
        "GetSystemWindowsDirectoryW",
        ".share_mode(FILE_SHARE_READ)",
        ".create_new(true)",
        "nNumberOfLinks",
        "GetFinalPathNameByHandleW",
        "CreateDirectoryW(wide_path.as_ptr(), &attributes)",
        "REG_CREATED_NEW_KEY",
        "refuse_reparse_in_tree(path)?;",
    ] {
        assert!(os.contains(needle), "{needle}");
    }
    for needle in [
        "unexpected entry",
        "hard links",
        "every change it made was rolled back",
        "PROFILE LEFT",
        "check_key_rights(&key",
    ] {
        assert!(source.contains(needle), "{needle}");
    }
    // No helper programs and no environment folders.
    for forbidden in ["Command::new(", "env::var"] {
        assert!(
            !source.contains(forbidden) || forbidden == "env::var",
            "{forbidden}"
        );
        let code_os = &os[..position(&os, "#[cfg(test)]")];
        assert!(!code_os.contains(forbidden), "install_os: {forbidden}");
    }
}

#[test]
fn the_runbook_documents_the_commit_proof_provenance_and_the_expected_staging_acl() {
    let text = runbook();
    for needle in [
        "gh api repos/TheHalfMoon/Orcel/commits/<commit> --jq '.parents[].sha'",
        "gh api repos/TheHalfMoon/Orcel/compare/<reviewed-head>...<commit> --jq '.files | length'",
        "foreach ($n in 'orcel-authority.exe', 'orceld.exe', 'orcel.exe') {",
        "gh attestation verify (Join-Path '<download-folder>' $n) --repo TheHalfMoon/Orcel --signer-workflow TheHalfMoon/Orcel/.github/workflows/ci.yml --source-ref refs/heads/main --source-digest <commit> --deny-self-hosted-runners",
        "authority-install-e2e-report",
        "not_verified",
    ] {
        assert!(text.contains(needle), "{needle}");
    }
    let block = &text[position(&text, "<!-- expected-staging-acl -->\n```text\n")..];
    let block = &block[..position(block, "\n```\n")];
    for line in [
        r"C:\Program Files\OrcelStaging BUILTIN\Users:(OI)(CI)(RX)",
        r"NT AUTHORITY\SYSTEM:(OI)(CI)(F)",
        r"BUILTIN\Administrators:(OI)(CI)(F)",
        r"C:\Program Files\OrcelStaging\orcel-authority.exe BUILTIN\Users:(I)(OI)(CI)(RX)",
        r"Successfully processed 3 files; Failed processing 0 files",
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
}

/// The E2E launches the runbook's own lines in a hostile environment and
/// fails on any mismatch.
#[test]
fn the_e2e_runs_the_runbook_lines_in_a_hostile_environment() {
    let text = e2e();
    for needle in [
        "Get-RunbookCommands",
        ".Replace(' & pause', '').Replace(' --pause', '')",
        "COR_PROFILER_PATH",
        "WindowsPowerShell\\Modules\\OrcelE2ECanary",
        "[Environment]::SetEnvironmentVariable($pair[0], $pair[1], 'User')",
        "SystemRoot = $Hostile",
        "hostile environment armed",
        "no planted module and no profiler DLL ran in any elevated step",
        "NotVerified 'pinned TPM root equals the certificate on this machine'",
        "runbook command lines found: 9 Start-Process lines, each matching its UAC table row",
        "if ($Report.result -ne 'pass') { exit 1 }",
    ] {
        assert!(text.contains(needle), "{needle}");
    }
}

#[cfg(windows)]
#[test]
fn the_e2e_script_parses_in_windows_powershell() {
    let path = repo_file(&["scripts", "authority-install-e2e.ps1"]);
    let command = format!(
        "$errors = $null; [System.Management.Automation.Language.Parser]::ParseFile('{}', [ref]$null, [ref]$errors) | Out-Null; if ($errors.Count) {{ $errors | ForEach-Object {{ $_.ToString() }}; exit 1 }}",
        path.display()
    );
    let output =
        std::process::Command::new(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &command])
            .env_remove("PSModulePath")
            .output()
            .expect("Windows PowerShell");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}
