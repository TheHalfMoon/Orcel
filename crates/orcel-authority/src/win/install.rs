//! SG-000132 install hardening: `orcel-authority install` and
//! `orcel-authority uninstall`, the founder's elevated steps (runbook
//! docs/orcel/implementation-readiness/prep/SG132_INSTALL_RUNBOOK.md). They
//! replace the PowerShell installer: an elevated PowerShell or any .NET
//! process loads code a standard user can plant (a module in the user's
//! Documents folder, a profiler named in HKCU\Environment), and its folders
//! come from environment variables the user controls.
//!
//! This program runs from `<Program Files>\OrcelStaging`, which the
//! runbook's native Stage step created admin-only and filled with the three
//! hash-checked binaries. Before it reads or changes anything it checks
//! where it runs: its own image is `<Program Files>\OrcelStaging\
//! orcel-authority.exe`; that file, the folder, every binary in it and
//! every parent up to the volume root are owned by SYSTEM, Administrators
//! or TrustedInstaller, are not reparse points, and give nobody else a
//! right to change them; the folder holds exactly the three binaries, each
//! with one hard link. Folders come from the shell's known folders and the
//! Windows directory, never from environment variables; after start, DLLs
//! load only from System32. Each binary is held open without write or
//! delete sharing, hashed, and copied from that handle. Any failing change
//! rolls back every change already made.
//!
//! Install makes exactly the changes the runbook's table lists; uninstall
//! reverses them. The table and this module are tied together by
//! `tests/install_script.rs`, and CI runs both steps on a disposable runner
//! (`scripts/authority-install-e2e.ps1`).

use super::acl::{ADMINISTRATORS_SID, SYSTEM_SID};
use super::install_os::{self as os, ServiceSpec};
use std::path::{Path, PathBuf};

pub const STAGING_DIR_NAME: &str = "OrcelStaging";
pub const STAGED_FILES: [&str; 3] = ["orcel-authority.exe", "orceld.exe", "orcel.exe"];
pub const EVENT_KEY: &str = r"SYSTEM\CurrentControlSet\Services\EventLog\Application\Orcel";
pub const MARKER: &str = "orcel-authority install";
pub const MARKER_FILE: &str = ".created-by-install-orcel-authority";
const DESCRIPTION: &str = "Orcel Full Control authority (SG-000132): holds the lease-signing key, leases, epoch and audit outside the user session. It never elevates anything.";
const PRIVILEGES: [&str; 3] = [
    "SeChangeNotifyPrivilege",
    "SeImpersonatePrivilege",
    "SeCreateGlobalPrivilege",
];
/// `%ProgramData%\Orcel`: SYSTEM and Administrators full, Users read.
pub const ORCEL_DATA_SDDL: &str =
    "O:BAG:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";
/// `%ProgramFiles%\Orcel` and `Authority`: the same, so nobody else can
/// replace an installed binary.
pub const ORCEL_FILES_SDDL: &str = ORCEL_DATA_SDDL;
const FULL: u32 = 0x001f_01ff;
const READ_EXECUTE: u32 = 0x0012_00a9;
const MODIFY: u32 = 0x0013_01bf;
const USERS: &str = "S-1-5-32-545";

/// Every path the install touches, from the known folders.
pub struct Paths {
    pub staging: PathBuf,
    pub files_orcel: PathBuf,
    pub files_authority: PathBuf,
    pub installed_authority: PathBuf,
    pub installed_orceld: PathBuf,
    pub installed_orcel: PathBuf,
    pub data_orcel: PathBuf,
    pub state_dir: PathBuf,
    pub public_dir: PathBuf,
    pub public_key: PathBuf,
    pub marker: PathBuf,
    pub event_messages: PathBuf,
}

impl Paths {
    pub fn resolve() -> Result<Self, String> {
        use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramData, FOLDERID_ProgramFiles};
        let program_files = os::known_folder(&FOLDERID_ProgramFiles)?;
        let program_data = os::known_folder(&FOLDERID_ProgramData)?;
        let windows = os::windows_directory()?;
        Ok(Self::under(&program_files, &program_data, &windows))
    }

    pub fn under(program_files: &Path, program_data: &Path, windows: &Path) -> Self {
        let files_orcel = program_files.join("Orcel");
        let files_authority = files_orcel.join("Authority");
        let data_orcel = program_data.join("Orcel");
        let public_dir = data_orcel.join("authority-public");
        Self {
            staging: program_files.join(STAGING_DIR_NAME),
            installed_authority: files_authority.join("orcel-authority.exe"),
            installed_orceld: files_orcel.join("orceld.exe"),
            installed_orcel: files_orcel.join("orcel.exe"),
            files_orcel,
            files_authority,
            state_dir: data_orcel.join("authority"),
            public_key: public_dir.join("lease-signing-key.json"),
            public_dir,
            marker: data_orcel.join(MARKER_FILE),
            data_orcel,
            event_messages: windows
                .join(r"Microsoft.NET\Framework64\v4.0.30319\EventLogMessages.dll"),
        }
    }
}

/// Parsed `install` arguments.
#[derive(Debug, PartialEq, Eq)]
pub struct InstallArgs {
    pub authority: String,
    pub orceld: String,
    pub orcel: String,
    pub dry_run: bool,
    pub pause: bool,
}

/// Parsed `uninstall` arguments.
#[derive(Debug, PartialEq, Eq)]
pub struct UninstallArgs {
    pub keep_state: bool,
    pub dry_run: bool,
    pub pause: bool,
}

fn is_sha256(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn parse_install(args: &[String]) -> Result<InstallArgs, String> {
    let mut authority = None;
    let mut orceld = None;
    let mut orcel = None;
    let mut dry_run = false;
    let mut pause = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--authority-sha256" => authority = iter.next().cloned(),
            "--orceld-sha256" => orceld = iter.next().cloned(),
            "--orcel-sha256" => orcel = iter.next().cloned(),
            "--dry-run" => dry_run = true,
            "--pause" => pause = true,
            other => return Err(format!("unknown install argument {other:?}")),
        }
    }
    let (Some(authority), Some(orceld), Some(orcel)) = (authority, orceld, orcel) else {
        return Err("install needs --authority-sha256, --orceld-sha256 and --orcel-sha256 (from the reviewed commit's CI job log)".to_owned());
    };
    for hash in [&authority, &orceld, &orcel] {
        if !is_sha256(hash) {
            return Err(format!("not a SHA-256: {hash}"));
        }
    }
    Ok(InstallArgs {
        authority: authority.to_lowercase(),
        orceld: orceld.to_lowercase(),
        orcel: orcel.to_lowercase(),
        dry_run,
        pause,
    })
}

pub fn parse_uninstall(args: &[String]) -> Result<UninstallArgs, String> {
    let mut out = UninstallArgs {
        keep_state: false,
        dry_run: false,
        pause: false,
    };
    for arg in args {
        match arg.as_str() {
            "--keep-state" => out.keep_state = true,
            "--dry-run" => out.dry_run = true,
            "--pause" => out.pause = true,
            other => return Err(format!("unknown uninstall argument {other:?}")),
        }
    }
    Ok(out)
}

fn pause_if(pause: bool) {
    if pause {
        println!("Press Enter to close this window.");
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
    }
}

/// `orcel-authority install ...`: the exit code.
pub fn install_main(args: &[String]) -> i32 {
    let parsed = match parse_install(args) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("orcel-authority install: {error}. Nothing was changed.");
            return 2;
        }
    };
    let code = match install(&parsed) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("orcel-authority install: {error}");
            1
        }
    };
    pause_if(parsed.pause);
    code
}

/// `orcel-authority uninstall ...`: the exit code.
pub fn uninstall_main(args: &[String]) -> i32 {
    let parsed = match parse_uninstall(args) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("orcel-authority uninstall: {error}. Nothing was changed.");
            return 2;
        }
    };
    let code = match uninstall(&parsed) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("orcel-authority uninstall: {error}");
            1
        }
    };
    pause_if(parsed.pause);
    code
}

/// The image this process runs from, by its final path.
fn own_image() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|error| format!("this program's path: {error}"))?;
    let held = os::open_held(&exe)?;
    os::final_path(&held)
}

fn same_path(a: &Path, b: &Path) -> bool {
    a.to_string_lossy()
        .trim_end_matches('\\')
        .eq_ignore_ascii_case(b.to_string_lossy().trim_end_matches('\\'))
}

/// The location check: this program is the staged copy, and the staging
/// folder, its three binaries and every parent are admin-only, with nothing
/// else in the folder and no extra hard links.
fn check_location(paths: &Paths) -> Result<(), String> {
    let image = own_image()?;
    let expected = paths.staging.join("orcel-authority.exe");
    let mut problems = Vec::new();
    if !same_path(&image, &expected) {
        problems.push(format!(
            "this program runs from {}, not from the staging folder ({}); stage the files with the runbook's Stage step",
            image.display(),
            expected.display()
        ));
    } else {
        problems.extend(os::location_problems(&paths.staging));
        match std::fs::read_dir(&paths.staging) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if !STAGED_FILES.iter().any(|f| f.eq_ignore_ascii_case(&name)) {
                        problems.push(format!(
                            "{} holds an unexpected entry {name} (a DLL there would load into this elevated program)",
                            paths.staging.display()
                        ));
                    }
                }
            }
            Err(error) => problems.push(format!("list {}: {error}", paths.staging.display())),
        }
        for name in STAGED_FILES {
            let file = paths.staging.join(name);
            problems.extend(os::object_problems(&file, os::CONTENT_CHANGE_RIGHTS));
        }
    }
    if problems.is_empty() {
        println!(
            "Location checked (admin-only up to the volume root, nothing else in it): {}",
            paths.staging.display()
        );
        return Ok(());
    }
    problems.sort();
    problems.dedup();
    for problem in &problems {
        println!("  refused: {problem}");
    }
    Err("a file or folder this elevated step consumes could be changed by a non-administrator, or is not the staged copy. Nothing was changed.".to_owned())
}

/// The three staged binaries, held open and hashed.
struct Held {
    authority: std::fs::File,
    orceld: std::fs::File,
    orcel: std::fs::File,
}

fn hold_and_hash(paths: &Paths, args: &InstallArgs) -> Result<Held, String> {
    let open = |name: &str, expected: &str| -> Result<std::fs::File, String> {
        let path = paths.staging.join(name);
        let mut file = os::open_held(&path)?;
        let links = os::link_count(&file)?;
        if links != 1 {
            return Err(format!(
                "{} has {links} hard links; refused. Nothing was changed.",
                path.display()
            ));
        }
        let actual = os::sha256_of(&mut file)?;
        println!(
            "SHA-256 {actual}  {} (held open, no write or delete sharing)",
            path.display()
        );
        if actual != expected {
            return Err(format!(
                "SHA-256 mismatch for {}: expected {expected}, found {actual}. Nothing was changed.",
                path.display()
            ));
        }
        Ok(file)
    };
    Ok(Held {
        authority: open("orcel-authority.exe", &args.authority)?,
        orceld: open("orceld.exe", &args.orceld)?,
        orcel: open("orcel.exe", &args.orcel)?,
    })
}

/// A folder that may pre-exist: admin-owned, and nobody else may add,
/// delete or rename entries or change it.
fn check_existing_dir(path: &Path, owners: &[&str], protected: bool) -> Result<(), String> {
    if std::fs::symlink_metadata(path).is_err() {
        return Ok(());
    }
    let mut problems = os::object_problems(path, os::CONTENT_CHANGE_RIGHTS);
    match super::acl::read_security(path, false) {
        Ok((owner, is_protected, _)) => {
            if !owners.iter().any(|ok| ok.eq_ignore_ascii_case(&owner)) {
                problems.push(format!("{} is owned by {owner}", path.display()));
            }
            if protected && !is_protected {
                problems.push(format!(
                    "{} inherits permissions (its DACL is not protected)",
                    path.display()
                ));
            }
        }
        Err(error) => problems.push(error.message),
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{}; inspect it, fix its ACL or remove it first. Nothing was changed.",
            problems.join("; ")
        ))
    }
}

/// Who may own an existing `%ProgramData%\Orcel`.
const DATA_OWNERS: [&str; 2] = [SYSTEM_SID, ADMINISTRATORS_SID];

/// Creates `path` with its protected DACL, or, if it already exists, checks
/// it as [`check_existing_dir`] does: `Ok(true)` when this run created it.
/// The create is the existence test, so a folder a user slips in after the
/// checks is refused, never written into.
fn create_or_verify(
    path: &Path,
    sddl: &str,
    expected: &[(&str, u32)],
    owners: &[&str],
    protected: bool,
) -> Result<bool, String> {
    match os::create_protected_dir_unless_present(path, sddl, expected)? {
        os::Created::New => Ok(true),
        os::Created::AlreadyPresent => {
            check_existing_dir(path, owners, protected)?;
            println!(
                "{} exists; checked (admin-owned, nobody else may change it).",
                path.display()
            );
            Ok(false)
        }
    }
}

fn check_key_rights(key: &os::Key, label: &str) -> Result<(), String> {
    let (owner, aces) = os::key_security(key, label)?;
    let problems = os::rights_problems(label, &owner, &aces, os::KEY_CHANGE_RIGHTS);
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("; "))
    }
}

/// What this run has changed, for the rollback.
#[derive(Default)]
struct Made {
    files_orcel: bool,
    files_authority: bool,
    authority: bool,
    orceld: bool,
    orcel: bool,
    service: bool,
    service_sid: Option<String>,
    data_orcel: bool,
    state_dir: bool,
    public_dir: bool,
    event_source: bool,
}

fn install(args: &InstallArgs) -> Result<(), String> {
    os::harden_dll_search()?;
    let elevated = os::process_is_elevated();
    if !elevated && !args.dry_run {
        return Err(
            "run this step elevated, started as the runbook says. Nothing was changed.".to_owned(),
        );
    }
    let paths = Paths::resolve()?;
    check_location(&paths)?;
    let mut held = hold_and_hash(&paths, args)?;

    if os::open_service(crate::SERVICE_NAME)?.is_some() {
        return Err(format!(
            "the service {} already exists; uninstall first. Nothing was changed.",
            crate::SERVICE_NAME
        ));
    }
    for dir in [&paths.state_dir, &paths.public_dir] {
        if dir.exists() {
            return Err(format!(
                "{} already exists; someone may have pre-created it. Inspect and remove it (or uninstall). Nothing was changed.",
                dir.display()
            ));
        }
    }
    for file in [
        &paths.installed_authority,
        &paths.installed_orceld,
        &paths.installed_orcel,
    ] {
        if file.exists() {
            return Err(format!(
                "{} already exists (left from an earlier install?); uninstall first. Nothing was changed.",
                file.display()
            ));
        }
    }
    let privileged = os::PRIVILEGED;
    check_existing_dir(&paths.files_orcel, &privileged, false)?;
    check_existing_dir(&paths.files_authority, &privileged, false)?;
    check_existing_dir(&paths.data_orcel, &DATA_OWNERS, true)?;
    if let Some(key) = os::open_key(EVENT_KEY) {
        check_key_rights(&key, &format!(r"HKLM\{EVENT_KEY}"))
            .map_err(|error| format!("{error}; inspect it first. Nothing was changed."))?;
    }

    println!("Planned system changes:");
    println!(
        "  copy the verified binaries to {}, {} and {}",
        paths.installed_authority.display(),
        paths.installed_orceld.display(),
        paths.installed_orcel.display()
    );
    println!(
        "  SCM: create {} (Orcel Authority) as {}, automatic start, SID type unrestricted, privileges {}",
        crate::SERVICE_NAME,
        crate::SERVICE_ACCOUNT,
        PRIVILEGES.join(", ")
    );
    println!(
        "  directories created with protected ACLs: {} (no user access), {} (users read)",
        paths.state_dir.display(),
        paths.public_dir.display()
    );
    println!("  Event Log source Orcel (Application) unless present, then start the service");
    if args.dry_run {
        println!("Dry run: nothing was changed.");
        return Ok(());
    }

    let mut made = Made::default();
    match apply(&paths, &mut held, args, &mut made) {
        Ok(()) => {
            println!(
                "Installed. Next: run \"{}\" authority-status as your normal user (not elevated).",
                paths.installed_orceld.display()
            );
            Ok(())
        }
        Err(cause) => {
            println!("WARNING: the install failed ({cause}); undoing every change it made.");
            let failed = rollback(&paths, &made);
            if failed.is_empty() {
                Err(format!(
                    "the install failed ({cause}); every change it made was rolled back."
                ))
            } else {
                for item in &failed {
                    println!("  ROLLBACK FAILED: {item}");
                }
                Err(format!("the install failed ({cause}) and the rollback could not undo everything; inspect the items above, then uninstall."))
            }
        }
    }
}

fn apply(
    paths: &Paths,
    held: &mut Held,
    args: &InstallArgs,
    made: &mut Made,
) -> Result<(), String> {
    let files_expected = [
        (SYSTEM_SID, FULL),
        (ADMINISTRATORS_SID, FULL),
        (USERS, READ_EXECUTE),
    ];
    // Each folder is created, or, if it exists (even if it appeared after the
    // checks), verified again; a change is recorded only once this run made it.
    made.files_orcel = create_or_verify(
        &paths.files_orcel,
        ORCEL_FILES_SDDL,
        &files_expected,
        &os::PRIVILEGED,
        false,
    )?;
    made.files_authority = create_or_verify(
        &paths.files_authority,
        ORCEL_FILES_SDDL,
        &files_expected,
        &os::PRIVILEGED,
        false,
    )?;
    os::copy_held(
        &mut held.authority,
        &paths.installed_authority,
        &args.authority,
    )?;
    made.authority = true;
    os::copy_held(&mut held.orceld, &paths.installed_orceld, &args.orceld)?;
    made.orceld = true;
    os::copy_held(&mut held.orcel, &paths.installed_orcel, &args.orcel)?;
    made.orcel = true;
    for (path, expected) in [
        (&paths.installed_authority, &args.authority),
        (&paths.installed_orceld, &args.orceld),
        (&paths.installed_orcel, &args.orcel),
    ] {
        let actual = os::sha256_of(&mut os::open_held(path)?)?;
        println!("SHA-256 {actual}  {}", path.display());
        if &actual != expected {
            return Err(format!("SHA-256 mismatch for {}", path.display()));
        }
    }

    made.service = true;
    let service = os::create_service(&ServiceSpec {
        name: crate::SERVICE_NAME,
        display_name: "Orcel Authority",
        description: DESCRIPTION,
        binary: &paths.installed_authority,
        account: crate::SERVICE_ACCOUNT,
        privileges: &PRIVILEGES,
    })?;
    println!(
        "Created the service {} as {}.",
        crate::SERVICE_NAME,
        crate::SERVICE_ACCOUNT
    );
    let service_sid = super::account_sid(crate::SERVICE_ACCOUNT).map_err(|error| error.message)?;
    made.service_sid = Some(service_sid.clone());

    made.data_orcel = create_or_verify(
        &paths.data_orcel,
        ORCEL_DATA_SDDL,
        &files_expected,
        &DATA_OWNERS,
        true,
    )?;
    if made.data_orcel {
        std::fs::write(&paths.marker, MARKER).map_err(|error| error.to_string())?;
    }
    os::create_protected_dir(
        &paths.state_dir,
        &format!("O:BAG:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{service_sid})"),
        &[
            (SYSTEM_SID, FULL),
            (ADMINISTRATORS_SID, FULL),
            (&service_sid, FULL),
        ],
    )?;
    made.state_dir = true;
    let config = serde_json::json!({
        "trusted_orceld_images": [paths.installed_orceld],
        "trusted_owner_cli_images": [paths.installed_orcel],
    });
    std::fs::write(
        paths.state_dir.join(super::service::CONFIG_FILE),
        config.to_string(),
    )
    .map_err(|error| format!("write config.json: {error}"))?;
    os::create_protected_dir(
        &paths.public_dir,
        &format!("O:BAG:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;{service_sid})(A;OICI;0x1200a9;;;BU)"),
        &[(SYSTEM_SID, FULL), (ADMINISTRATORS_SID, FULL), (&service_sid, MODIFY), (USERS, READ_EXECUTE)],
    )?;
    made.public_dir = true;

    match os::create_new_key(EVENT_KEY)? {
        Some(key) => {
            made.event_source = true;
            os::set_expand_string(
                &key,
                "EventMessageFile",
                &paths.event_messages.to_string_lossy(),
            )?;
            os::set_dword(&key, "TypesSupported", 7)?;
            os::set_string(&key, "OrcelInstalledBy", MARKER)?;
            check_key_rights(&key, &format!(r"HKLM\{EVENT_KEY}"))?;
            println!("Registered the Event Log source Orcel.");
        }
        None => println!("The Event Log source Orcel already exists; left unchanged."),
    }

    let public_key = paths.public_key.clone();
    os::start_and_wait(&service, 30, &move || public_key.exists())?;
    println!("The service {} is running.", crate::SERVICE_NAME);
    Ok(())
}

/// Removes the virtual account's profile if Windows created one; if Windows
/// still holds it loaded, says so and leaves it (never fatal).
fn remove_profile(sid: &str) {
    if !os::profile_exists(sid) {
        return;
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        match os::delete_profile(sid) {
            Ok(()) => {
                println!("Removed the virtual account profile ({sid}).");
                return;
            }
            Err(error) => {
                if !os::profile_exists(sid) {
                    return;
                }
                if std::time::Instant::now() >= deadline {
                    println!("WARNING: PROFILE LEFT: the virtual account profile ({sid}) is still loaded ({error}), so it was not removed. After the next restart of Windows, remove it elevated in Settings > System > About > Advanced system settings > User Profiles.");
                    return;
                }
                std::thread::sleep(std::time::Duration::from_secs(2));
            }
        }
    }
}

fn rollback(paths: &Paths, made: &Made) -> Vec<String> {
    let mut failed = Vec::new();
    let mut step = |when: bool, what: &str, action: &mut dyn FnMut() -> Result<(), String>| {
        if !when {
            return;
        }
        match action() {
            Ok(()) => println!("  rolled back: {what}"),
            Err(error) => failed.push(format!("{what}: {error}")),
        }
    };
    step(made.service, "stop and delete the service", &mut || {
        if let Some(service) = os::open_service(crate::SERVICE_NAME)? {
            os::stop_and_wait(&service, 60)?;
            os::delete_and_wait(service, crate::SERVICE_NAME, 30)?;
        }
        Ok(())
    });
    if let Some(sid) = &made.service_sid {
        remove_profile(sid);
    }
    step(
        made.event_source,
        "remove the Event Log source",
        &mut || os::delete_key_tree(EVENT_KEY),
    );
    step(
        made.public_dir,
        &format!("delete {}", paths.public_dir.display()),
        &mut || os::remove_tree(&paths.public_dir),
    );
    step(
        made.state_dir,
        &format!("delete {}", paths.state_dir.display()),
        &mut || os::remove_tree(&paths.state_dir),
    );
    step(
        made.data_orcel,
        &format!("delete {}", paths.data_orcel.display()),
        &mut || os::remove_tree(&paths.data_orcel),
    );
    for (when, path) in [
        (made.orcel, &paths.installed_orcel),
        (made.orceld, &paths.installed_orceld),
        (made.authority, &paths.installed_authority),
    ] {
        step(when, &format!("delete {}", path.display()), &mut || {
            if path.exists() {
                std::fs::remove_file(path).map_err(|error| error.to_string())
            } else {
                Ok(())
            }
        });
    }
    step(
        made.files_authority,
        &format!("delete {}", paths.files_authority.display()),
        &mut || os::remove_tree(&paths.files_authority),
    );
    step(
        made.files_orcel,
        &format!("delete {}", paths.files_orcel.display()),
        &mut || os::remove_tree(&paths.files_orcel),
    );
    failed
}

fn uninstall(args: &UninstallArgs) -> Result<(), String> {
    os::harden_dll_search()?;
    if !os::process_is_elevated() && !args.dry_run {
        return Err(
            "run this step elevated, started as the runbook says. Nothing was changed.".to_owned(),
        );
    }
    let paths = Paths::resolve()?;
    check_location(&paths)?;
    if args.dry_run {
        println!("Dry run: the uninstall would stop and delete {}, remove the profile, the Event Log source (if this install made it), the installed binaries, {} and {}.", crate::SERVICE_NAME, paths.public_dir.display(), if args.keep_state { "keep the state directory" } else { "the state directory" });
        return Ok(());
    }
    let mut errors = Vec::new();
    let mut service_sid = super::account_sid(crate::SERVICE_ACCOUNT).ok();
    match os::open_service(crate::SERVICE_NAME) {
        Ok(Some(service)) => {
            if service_sid.is_none() {
                service_sid = super::account_sid(crate::SERVICE_ACCOUNT).ok();
            }
            match os::stop_and_wait(&service, 60)
                .and_then(|()| os::delete_and_wait(service, crate::SERVICE_NAME, 30))
            {
                Ok(()) => println!("Stopped and deleted the service {}.", crate::SERVICE_NAME),
                Err(error) => return Err(format!("{error}. Retry the uninstall.")),
            }
        }
        Ok(None) => println!("The service {} is not installed.", crate::SERVICE_NAME),
        Err(error) => return Err(error),
    }
    if let Some(sid) = &service_sid {
        remove_profile(sid);
    }
    if let Some(key) = os::open_key(EVENT_KEY) {
        let ours = os::query_string(&key, "OrcelInstalledBy").as_deref() == Some(MARKER)
            || os::query_string(&key, "OrcelInstalledBy").as_deref()
                == Some("install-orcel-authority.ps1");
        drop(key);
        if ours {
            match os::delete_key_tree(EVENT_KEY) {
                Ok(()) => println!("Removed the Event Log source Orcel."),
                Err(error) => errors.push(error),
            }
        } else {
            println!("The Event Log source Orcel was not created by this install; left unchanged.");
        }
    }
    for file in [&paths.installed_orceld, &paths.installed_orcel] {
        if file.exists() {
            match std::fs::remove_file(file) {
                Ok(()) => println!("Deleted {}.", file.display()),
                Err(error) => errors.push(format!("delete {}: {error}", file.display())),
            }
        }
    }
    let mut trees = vec![&paths.files_authority, &paths.public_dir];
    if !args.keep_state {
        trees.push(&paths.state_dir);
    }
    for tree in trees {
        if tree.exists() {
            match os::remove_tree(tree) {
                Ok(()) => println!("Deleted {}.", tree.display()),
                Err(error) => errors.push(error),
            }
        }
    }
    if paths.marker.exists() {
        let only_marker = std::fs::read_dir(&paths.data_orcel)
            .map(|entries| entries.flatten().all(|entry| entry.path() == paths.marker))
            .unwrap_or(false);
        if only_marker {
            match std::fs::remove_file(&paths.marker)
                .and_then(|()| std::fs::remove_dir(&paths.data_orcel))
            {
                Ok(()) => println!("Deleted {}.", paths.data_orcel.display()),
                Err(error) => {
                    errors.push(format!("delete {}: {error}", paths.data_orcel.display()))
                }
            }
        }
    }
    if paths.files_orcel.exists()
        && std::fs::read_dir(&paths.files_orcel)
            .map(|mut entries| entries.next().is_none())
            .unwrap_or(false)
    {
        match std::fs::remove_dir(&paths.files_orcel) {
            Ok(()) => println!("Deleted {}.", paths.files_orcel.display()),
            Err(error) => errors.push(format!("delete {}: {error}", paths.files_orcel.display())),
        }
    }
    if errors.is_empty() {
        println!("Uninstalled. Events already written to the Application log remain there.");
        Ok(())
    } else {
        for error in &errors {
            println!("  NOT REMOVED: {error}");
        }
        Err(
            "the uninstall could not remove everything; inspect the items above and retry."
                .to_owned(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn install_arguments_need_three_sha256_values() {
        let good = "a".repeat(64);
        let parsed = parse_install(&strings(&[
            "--authority-sha256",
            &good,
            "--orceld-sha256",
            &good,
            "--orcel-sha256",
            &"B".repeat(64),
            "--pause",
        ]))
        .expect("parsed");
        assert_eq!(parsed.orcel, "b".repeat(64));
        assert!(parsed.pause && !parsed.dry_run);
        assert!(parse_install(&strings(&["--authority-sha256", &good])).is_err());
        assert!(parse_install(&strings(&[
            "--authority-sha256",
            "xyz",
            "--orceld-sha256",
            &good,
            "--orcel-sha256",
            &good,
        ]))
        .is_err());
        assert!(parse_install(&strings(&["--artifact-dir", "C:\\x"])).is_err());
        assert_eq!(
            parse_uninstall(&strings(&["--keep-state"])).expect("parsed"),
            UninstallArgs {
                keep_state: true,
                dry_run: false,
                pause: false
            }
        );
        assert!(parse_uninstall(&strings(&["--remove-everything"])).is_err());
    }

    #[test]
    fn paths_come_from_the_known_folders_and_ignore_the_environment() {
        let paths = Paths::under(
            Path::new(r"C:\Program Files"),
            Path::new(r"C:\ProgramData"),
            Path::new(r"C:\Windows"),
        );
        assert_eq!(paths.staging, Path::new(r"C:\Program Files\OrcelStaging"));
        assert_eq!(
            paths.installed_authority,
            Path::new(r"C:\Program Files\Orcel\Authority\orcel-authority.exe")
        );
        assert_eq!(
            paths.state_dir,
            Path::new(r"C:\ProgramData\Orcel\authority")
        );
        assert_eq!(
            paths.public_key,
            Path::new(r"C:\ProgramData\Orcel\authority-public\lease-signing-key.json")
        );
        assert!(paths.event_messages.starts_with(r"C:\Windows"));
        // Resolving never reads ProgramFiles or ProgramData from the environment.
        let source = include_str!("install.rs").to_owned() + include_str!("install_os.rs");
        // (The needles are assembled here so this test does not find itself.)
        for variable in [
            ["env", "::var("].concat(),
            ["env", "::var_os("].concat(),
            ["\"Program", "Files\""].concat(),
            ["\"Program", "Data\""].concat(),
            ["\"System", "Root\""].concat(),
        ] {
            assert!(!source.contains(&variable), "{variable}");
        }
    }

    #[test]
    fn a_copy_outside_the_staging_folder_is_refused_before_anything_is_read() {
        // This test binary runs from target\, not from the staging folder.
        let paths = Paths::resolve().expect("paths");
        let error = check_location(&paths).unwrap_err();
        assert!(error.contains("Nothing was changed"), "{error}");
    }
}
