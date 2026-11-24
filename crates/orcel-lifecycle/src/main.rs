use orcel_lifecycle::install::{InstallOptions, Installer, UninstallOptions};
use orcel_lifecycle::layout::Layout;
use orcel_lifecycle::manifest::MANIFEST_FILE;
use orcel_lifecycle::{host_platform, ErrorKind, LifecycleError};
use serde_json::json;
use std::path::PathBuf;

const HELP: &str = "\
Orcel - Computer Orchestration & Trusted Runtime Access

Install and maintenance:
  orcel install [--source <release-dir>] [--node <node.exe>] [--no-path]
      Install or repair the per-user install under %USERPROFILE%\\.orcel, adding it to your
      PATH and the Start Menu, neither of which --no-path touches. The release
      directory defaults to the directory containing this orcel.exe. Every payload
      file is verified against manifest.json before anything is copied. Administrator
      rights are not required; an elevated \"Run as administrator\" prompt is refused.
  orcel uninstall [--purge-data --yes]
      Stop Orcel, then remove binaries, the version pointer, and the PATH entry.
      Configuration, secrets, logs, and audit/approval/trust history are kept unless
      --purge-data --yes is given. Workspaces are never touched.
  orcel version
      Show this CLI version and the installed and previous versions.
  orcel state status | migrate | keep-separate
      Decide what happens to state an earlier build left at %LOCALAPPDATA%\\Orcel, which
      orceld requires before it starts. migrate copies user data, only if nobody else could
      have changed it; keep-separate records that it stays where it is, unused. Neither
      deletes or changes it.

Configuration:
  orcel workspace add <id> <directory>    Add a workspace the agent may use.
  orcel workspace remove <id>             Remove a workspace from configuration.
  orcel workspace list                    List workspaces and their trust state.
  orcel workspace trust <id>              Grant workspace trust (Windows Hello).
  orcel workspace untrust <id>            Revoke workspace trust (Windows Hello).
  orcel tunnel setup --client <tunnel-client.exe> --tunnel-id <tunnel_...> [--key-file <path>] [--profile core|browser_full]
      Configure the official OpenAI tunnel client. Without --key-file the runtime key
      is read from a hidden console prompt. The key is stored owner-only and passed to
      the tunnel client by file reference; it is never printed or logged. Needs a
      workspace; changing the tunnel id or profile also needs a working orceld (its
      audit chain included), to end the old route's leases. Changing the tunnel id,
      profile or key is refused while the tunnel runs (`orcel stop` first).
  orcel tunnel show                       Show the tunnel configuration (never the key).
  orcel tunnel allow [--workspaces <a,b>] [--scopes <s,...>] [--minutes <1-15>] [--read-mode <m>]
      Allow one finite ChatGPT tunnel session (Windows Hello). Tunnel clients see only
      the one profile the tunnel was set up for (`core`, or `browser_full`), and every
      tunnel request needs this lease.
  orcel tunnel revoke                     End the tunnel session leases (both profiles) now
      and say, for each connection, how many ended, that orceld refused, or that the
      revoke could not be confirmed (orceld did not start, take the request or answer
      within 30 seconds, its answer could not be read or had no count or code, or it
      reported an internal error). An unended lease expires within 15 minutes.

Updates:
  orcel update --source <release-dir> [--check] [--allow-downgrade] [--reinstall]
      Verify a downloaded release and switch to it. Orcel never downloads or checks
      for updates itself; get releases from the project's GitHub Releases page. A
      running instance is stopped and restarted. If the new version fails its own
      integrity check, the previous version is restored automatically.
  orcel rollback                          Switch back to the retained previous version.

Runtime:
  orcel start [--wait <seconds>]          Start the supervised tunnel client.
  orcel stop [--wait <seconds>]           Stop it and verify termination.
  orcel status                            Show install, configuration, and runtime state.
  orcel doctor                            Run diagnostics; exits non-zero on failures.
  orcel app                               Open the Windows app from the verified install.

Local MCP (no tunnel required):
  orcel mcp stdio                         Run the authoritative MCP server over stdio
      for local AI clients (Claude Desktop, Codex, Mistral Vibe Code, generic
      MCP clients). Uses the active verified install with the sanitized
      environment. Standard output stays the MCP channel.
  orcel mcp serve [--port <1-65535>]      Serve the same MCP server over loopback
      Streamable HTTP at http://127.0.0.1:<port>/mcp (ephemeral port by
      default). Requires ORCEL_LOOPBACK_TOKEN of at least 32 characters in
      the environment. Binds 127.0.0.1 only and never opens a LAN port.

Approvals:
  orcel approvals [--limit <n>]           Show recent approval decisions.
  orcel approvals previews [content|sizes]
      Show or save what approval prompts show of the content they approve:
      a short preview hidden when it looks like a credential (content, the
      default), or sizes only. Applies to sessions started afterwards.
  orcel approvals recover                 Quarantine an approval ledger that fails
                                          verification and start a new one.
  orcel emergency-revoke                  Invalidate all pending approvals, Full User
      desktop control, and every remote session lease (Windows Hello).

Full User desktop control (local only):
  orcel full-control grant [--minutes <1-720>] [--executors <list>] [--root <path>]...
      [--shells] [--client <name>] [--task <label>]
      With the Orcel authority service installed: record a grant intent, print a
      one-time code, then lock (Win+L) and unlock; the service shows the scope and
      code, and after Yes Windows Hello signs. Default scope: desktop input only,
      no roots, no shells, 30 minutes. Without the service: the deprecated per-user
      grant of this exact live Orcel runtime session (Windows Hello). Agents, MCP,
      donors, relay, and remote callers cannot mint, widen, or renew a lease.
  orcel full-control revoke               Revoke Full User desktop input immediately.
  orcel full-control status               Show Safe/Full User state and expiry.
  orcel full-control standing grant --client <cl-ref> --task <label> --root <path>...
      --operations <list> --folder <path>... [--program <exe>]... [--minutes <1-720>]
      [--standing-minutes <n>]
      With the Orcel authority service: a Full User lease (filesystem and shells over the
      roots) and a standing approval for one client and task, granted together through the
      same lock, unlock, service box and Windows Hello. The listed operations (run; Git
      operations are off until Git runs confined) inside the folders then do not ask each
      time. run needs --program: each is pinned now to its contents (SHA-256) and file, shown
      in the box, and asks again once either changes. Never Admin, remote callers or browser
      actions. Needs a live Orcel indicator; until it exists the service refuses.
  orcel full-control standing revoke [--id <sa-...>]
                                          End standing approvals; their leases stay.
  orcel full-control standing status      List standing approvals and the indicator state.

Orcel authority service (SG-000132; Windows):
  orcel authority status                  Show the service's mode, epoch and enrollment.
  orcel authority enroll [--replace] [--pause]
      Started ELEVATED and directly (Start-Process -Verb RunAs on
      %ProgramFiles%\\Orcel\\orcel.exe, never an elevated shell): create the Windows Hello
      key beside any enrolled one, send its TPM attestation, confirm its fingerprint in the
      service's box, and sign once with Windows Hello. --pause waits for Enter at the end.
  orcel authority reset [--pause]         Started the same way: remove the enrolled key.
  orcel audit reset-anchor [--pause]      Started the same way: the owner's recovery when orceld's
      audit chain was lost or replaced and every dispatch is refused. The service's box names
      the held head it abandons; on Yes a new first chain file opens, reported as reset_by_owner.

Orcel Browser Full Access (SG-000135; leases come from the authority service only):
  orcel browser grant --session <bs-...> --client-ref <cl-...> --origin <https://host>...
      [--families navigate,click,type,select,tabs] [--task <label>] [--minutes <1-720>]
      Up to 16 exact origins, routine families only, at most 12 hours. Local sessions
      only: a remote (ChatGPT) session's client reference is refused, and no lease
      covers its actions.
  orcel browser leases                    Show this session's active browser leases.
  orcel browser revoke <lease id>         Revoke one browser lease.

Protected executables (process_spawn never runs shells or interpreters):
  orcel exec add <id> <path.exe> [--subcommands a,b] [--deny-args x,y] [--max-args N]
      Register one native executable outside every workspace (Windows Hello). Its path,
      size, and SHA-256 are pinned and re-verified before every launch.
  orcel exec remove <id>                  Remove a registered executable.
  orcel exec list                         Show registered executables.

Remote sessions (outbound-only; no inbound port is opened):
  orcel remote enable --relay <origin> [--workspace <id>]
      Create this device's key and register it with a relay (Windows Hello).
  orcel remote pair                       Pair an AI client that asks for a pairing code
      (Windows Hello, then confirm the exact client and scopes on this console).
  orcel remote connect                    Run the device uplink to the paired relay.
  orcel remote allow --connection <rc-id> [--workspaces <id,...>] [--scopes <s,...>]
      [--minutes <1-15>] [--read-mode session|per_request|disabled]
      Allow one paired remote connection for at most 15 minutes (Windows Hello).
      Without an active lease every remote request fails with REMOTE_SESSION_INACTIVE.
  orcel remote revoke [--connection <rc-id>]  End one or every remote session lease.
  orcel remote status                     Show remote session leases.
  orcel remote migrate-secrets            Move a device key written by an earlier version
      from a plaintext file into the OS secret store, then remove the plaintext.

Optional web search (off until a provider is enabled in ORCEL_SEARCH_PROVIDERS_JSON):
  orcel search status                     Show each provider's readiness; never shows a key.
  orcel search set-key <brave|tavily|exa|serper> [--key-file <path> [--delete-key-file]]
      Store your own provider API key in the OS secret store (input hidden).
      A key file stays plaintext on disk: delete it, or pass --delete-key-file.
  orcel search delete-key <provider>      Delete a stored provider API key.

Every command accepts --json for machine-readable output.
";

mod authority_commands;
mod commands;

pub(crate) struct Args {
    command: String,
    rest: Vec<String>,
}

impl Args {
    /// Takes the next argument that is not an option.
    pub(crate) fn positional(&mut self, what: &str) -> Result<String, LifecycleError> {
        match self.rest.iter().position(|arg| !arg.starts_with("--")) {
            Some(index) => Ok(self.rest.remove(index)),
            None => Err(LifecycleError::usage(format!("missing {what}"))),
        }
    }

    pub(crate) fn flag(&mut self, name: &str) -> bool {
        match self.rest.iter().position(|arg| arg == name) {
            Some(index) => {
                self.rest.remove(index);
                true
            }
            None => false,
        }
    }

    pub(crate) fn value(&mut self, name: &str) -> Result<Option<String>, LifecycleError> {
        match self.rest.iter().position(|arg| arg == name) {
            Some(index) if index + 1 < self.rest.len() => {
                let value = self.rest.remove(index + 1);
                self.rest.remove(index);
                Ok(Some(value))
            }
            Some(_) => Err(LifecycleError::usage(format!("{name} requires a value"))),
            None => Ok(None),
        }
    }

    pub(crate) fn finish(&self) -> Result<(), LifecycleError> {
        match self.rest.first() {
            Some(extra) => Err(LifecycleError::usage(format!(
                "unexpected argument {extra:?}; run `orcel help`"
            ))),
            None => Ok(()),
        }
    }
}

fn main() {
    let mut raw = std::env::args().skip(1);
    let command = raw.next().unwrap_or_else(|| "help".into());
    let mut args = Args {
        command,
        rest: raw.collect(),
    };
    if args.command == "supervise" {
        let code = match Layout::for_current_user() {
            Ok(layout) => orcel_lifecycle::lifecycle::supervise(&layout),
            Err(error) => {
                eprintln!("orcel supervise: {}", error.message);
                2
            }
        };
        std::process::exit(code);
    }
    if args.command == "remote"
        && matches!(
            args.rest.first().map(String::as_str),
            Some("enable") | Some("pair")
        )
    {
        let action = args.rest.remove(0);
        let code = match commands::remote_enroll(&mut args, &action) {
            Ok(code) => code,
            Err(error) => {
                eprintln!("orcel: {}", error.message);
                error.kind.exit_code()
            }
        };
        std::process::exit(code);
    }
    if args.command == "remote" && args.rest.first().map(String::as_str) == Some("connect") {
        args.rest.remove(0);
        let code = match commands::remote_connect(&mut args) {
            Ok(code) => code,
            Err(error) => {
                eprintln!("orcel: {}", error.message);
                error.kind.exit_code()
            }
        };
        std::process::exit(code);
    }
    if args.command == "mcp" {
        let code = match commands::mcp(&mut args) {
            Ok(code) => code,
            Err(error) => {
                eprintln!("orcel: {}", error.message);
                error.kind.exit_code()
            }
        };
        std::process::exit(code);
    }
    let json_output = args.flag("--json");
    match run(&mut args, json_output) {
        Ok(output) => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&output.json).unwrap_or_default()
                );
            } else {
                print!("{}", output.human);
            }
            if output.exit_code != 0 {
                std::process::exit(output.exit_code);
            }
        }
        Err(error) => {
            if json_output {
                println!(
                    "{}",
                    json!({"ok": false, "error": {"kind": error.kind, "message": error.message}})
                );
            } else {
                eprintln!("orcel: {}", error.message);
            }
            std::process::exit(error.kind.exit_code());
        }
    }
}

pub(crate) struct Output {
    /// Process exit code for a command that produced output but must still
    /// report failure (for example `doctor` with failing checks).
    pub(crate) exit_code: i32,
    pub(crate) human: String,
    pub(crate) json: serde_json::Value,
}

/// The action as `Args::positional` reads it: the first argument not starting with `--`.
fn action_of(rest: &[String]) -> Option<&str> {
    rest.iter()
        .find(|arg| !arg.starts_with("--"))
        .map(String::as_str)
}

/// Whether a command holds the lifecycle lock for its whole run. Two kinds don't:
/// - taking desktop control away, or reading its status: a grant can hold the lock for a
///   whole Windows Hello prompt, and an emergency stop must not wait behind it. The authority
///   store's own short lock orders a revoke against a grant, and a grant approved across a
///   revoke is refused (`full_control_store::grant_local_at_epoch`);
/// - listing workspaces, which only reads (see below).
fn holds_lifecycle_lock(command: &str, rest: &[String]) -> bool {
    let action = action_of(rest);
    // SG-000132 slice 2: with the authority service installed, a grant
    // waits on the person (unlock, confirmation, Hello) in the service, not
    // on this install's state, so it does not hold the lock either.
    let reduces_or_reads_authority = command == "full-control"
        && (matches!(action, Some("revoke" | "status"))
            || orcel_authority::client::service_installed());
    // Listing workspaces only reads the configuration (saved atomically) and asks orceld
    // for each folder's trust, up to 20 s each. Holding the lock for that blocked a grant,
    // an update or a workspace change for as long as the listing took.
    let reads_workspaces = command == "workspace" && action == Some("list");
    !reduces_or_reads_authority
        && !reads_workspaces
        && matches!(
            command,
            "install"
                | "uninstall"
                | "update"
                | "rollback"
                | "start"
                | "stop"
                | "workspace"
                | "tunnel"
                | "full-control"
        )
}

/// Whether a command first passes the legacy-state gate: every command that holds the lock,
/// except stopping and uninstalling, and also `workspace list`, which would otherwise read an
/// empty configuration at the new root while the earlier one is undecided and tell the
/// person to add a workspace the gate would then refuse.
fn checks_legacy_gate(command: &str, rest: &[String]) -> bool {
    (holds_lifecycle_lock(command, rest) && !matches!(command, "stop" | "uninstall"))
        || (command == "workspace" && action_of(rest) == Some("list"))
}

fn run(args: &mut Args, json_output: bool) -> Result<Output, LifecycleError> {
    // State-changing commands hold the per-install lifecycle lock for their
    // whole duration so they never interleave across processes.
    let mutating = holds_lifecycle_lock(&args.command, &args.rest);
    // Nothing writes to the current root over undecided earlier state, which is what orceld
    // refuses too. Stopping and uninstalling stay possible, and `state` is how to decide.
    if checks_legacy_gate(&args.command, &args.rest) {
        orcel_platform::legacy::gate(
            &|name| std::env::var_os(name),
            &Layout::for_current_user()?.root,
        )
        .map_err(LifecycleError::conflict)?;
    }
    let _lock = if mutating {
        Some(orcel_lifecycle::lifecycle::lock(
            &Layout::for_current_user()?,
        )?)
    } else {
        None
    };
    match args.command.as_str() {
        "help" | "--help" | "-h" => {
            args.finish()?;
            Ok(Output {
                exit_code: 0,
                human: HELP.into(),
                json: json!({"ok": true, "help": HELP}),
            })
        }
        "install" => install(args),
        "uninstall" => uninstall(args),
        "version" | "--version" => version(args),
        "workspace" => commands::workspace(args),
        "tunnel" => commands::tunnel(args),
        "start" => commands::start(args),
        "stop" => commands::stop(args),
        "status" => commands::status(args),
        "doctor" => commands::doctor(args),
        "state" => commands::state(args),
        "app" => commands::app(args, json_output),
        "approvals" => commands::approvals(args),
        "emergency-revoke" => commands::emergency_revoke(args),
        "full-control" => commands::full_control(args),
        "authority" => authority_commands::authority(args),
        "audit" => authority_commands::audit(args),
        "browser" => authority_commands::browser(args),
        "exec" => commands::exec(args),
        "remote" => commands::remote(args),
        "search" => commands::search(args),
        "update" => commands::update(args),
        "rollback" => commands::rollback(args),
        "self-check" => commands::self_check(args),
        other => Err(LifecycleError::usage(format!(
            "unknown command {other:?}; run `orcel help`"
        ))),
    }
}

fn install(args: &mut Args) -> Result<Output, LifecycleError> {
    let source = match args.value("--source")? {
        Some(source) => PathBuf::from(source),
        None => default_release_dir()?,
    };
    let node = args.value("--node")?.map(PathBuf::from);
    let add_to_path = !args.flag("--no-path");
    args.finish()?;
    let platform = host_platform();
    let layout = Layout::for_current_user()?;
    let installer = Installer::new(layout.clone(), platform.as_ref());
    let report = installer.install(&source, &InstallOptions { node, add_to_path })?;
    let mut human = format!(
        "Orcel {} {} at {}\n  lifecycle CLI: {}\n  Node.js: {}\n",
        report.version,
        if report.repaired_existing {
            "verified and repaired"
        } else {
            "installed and verified"
        },
        report.version_dir.display(),
        report.cli.display(),
        report.node_path.display(),
    );
    if report.path_entry_added {
        human.push_str(
            "  PATH: the Orcel bin directory is on your user PATH (open a new terminal)\n",
        );
    } else {
        human.push_str("  PATH: not modified\n");
    }
    if report.start_menu_added {
        human.push_str("  Start Menu: Orcel opens the app\n");
    } else if add_to_path && !report.app_included {
        human.push_str("  Start Menu: no entry, since this release has no Orcel app\n");
    } else if let Some(problem) = &report.start_menu_problem {
        human.push_str(&format!(
            "  Start Menu: no entry ({problem}). `orcel app` opens the app\n"
        ));
    }
    let pathext = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into());
    let other = std::env::var_os("PATH")
        .and_then(|path| earlier_on_path(&layout.bin_dir(), &path, &pathext));
    if let Some(other) = other {
        human.push_str(&format!(
            "  Note: {} comes first on this terminal's PATH, so `orcel` runs that copy. If it's an \
             earlier Orcel, uninstall it with its own `orcel uninstall`; otherwise take its folder \
             off PATH. Until then, run {} directly\n",
            other.display(),
            layout.bin_cli().display()
        ));
    }
    // Only what exists yet; the rest is created when first used, and kept the same way.
    let kept: Vec<_> = report
        .retained_data
        .iter()
        .filter(|path| path.exists())
        .collect();
    if !kept.is_empty() {
        human.push_str("  User data kept across updates and uninstall:\n");
        for path in kept {
            human.push_str(&format!("    {}\n", path.display()));
        }
    }
    let workspaces = orcel_lifecycle::config::Config::load(&layout)
        .map(|config| config.workspaces.len())
        .ok();
    human.push_str(if workspaces == Some(0) {
        "Next: add the folder Orcel may work in with `orcel workspace add <id> <folder>`, then \
         connect your MCP client as the README describes\n"
    } else {
        "Next: run `orcel doctor` to check everything\n"
    });
    Ok(Output {
        exit_code: 0,
        human,
        json: json!({"ok": true, "install": report}),
    })
}

/// The first `orcel` command on this process's PATH, when it isn't the installed one in `bin`.
/// Folders are compared as the file system resolves them, so another spelling of `bin` (a short
/// name, `..`, a junction) isn't mistaken for a different copy.
fn earlier_on_path(
    bin: &std::path::Path,
    path: &std::ffi::OsStr,
    pathext: &str,
) -> Option<PathBuf> {
    // PowerShell also runs scripts by name.
    let names: Vec<String> = pathext
        .split(';')
        .filter(|ext| !ext.is_empty())
        .chain([".ps1"])
        .map(|ext| format!("orcel{}", ext.to_ascii_lowercase()))
        .collect();
    let bin = std::fs::canonicalize(bin).ok()?;
    std::env::split_paths(path)
        .filter(|dir| dir.is_absolute())
        .find_map(|dir| {
            let found = names
                .iter()
                .map(|name| dir.join(name))
                .find(|candidate| candidate.is_file())?;
            Some((std::fs::canonicalize(&dir).ok()? != bin).then_some(found))
        })
        .flatten()
}

fn default_release_dir() -> Result<PathBuf, LifecycleError> {
    let exe =
        std::env::current_exe().map_err(|error| LifecycleError::io("locate orcel.exe", error))?;
    let dir = exe
        .parent()
        .ok_or_else(|| LifecycleError::usage("pass --source <release-dir>"))?
        .to_path_buf();
    if dir.join(MANIFEST_FILE).is_file() {
        Ok(dir)
    } else {
        Err(LifecycleError::usage(
            "no manifest.json next to orcel.exe; pass --source <release-dir>",
        ))
    }
}

/// The refusal of `--purge-data` without `--yes`. On macOS the install root
/// is Orcel's whole state folder (`~/Library/Application Support/Orcel`), so
/// it is named: audit log, approvals, trust and configuration all go. The
/// Windows and Linux text is unchanged.
fn purge_needs_yes(root: Option<&std::path::Path>) -> String {
    match root.filter(|_| cfg!(target_os = "macos")) {
        Some(root) => format!(
            "--purge-data permanently deletes configuration, secrets, logs, and history: everything Orcel keeps in {} (the audit log, approvals, trust and configuration); add --yes to confirm",
            root.display()
        ),
        None => "--purge-data permanently deletes configuration, secrets, logs, and history; add --yes to confirm".to_owned(),
    }
}

fn uninstall(args: &mut Args) -> Result<Output, LifecycleError> {
    let purge_data = args.flag("--purge-data");
    let confirmed = args.flag("--yes");
    args.finish()?;
    if purge_data && !confirmed {
        // Only macOS names the folder, so only macOS reads the layout here.
        let root = cfg!(target_os = "macos")
            .then(|| Layout::for_current_user().ok().map(|layout| layout.root))
            .flatten();
        return Err(LifecycleError::usage(purge_needs_yes(root.as_deref())));
    }
    let layout = Layout::for_current_user()?;
    let mut human = String::new();
    if layout.supervisor_record().exists() {
        let stopped = orcel_lifecycle::lifecycle::stop(&layout, std::time::Duration::from_secs(20))
            .map_err(|error| {
                LifecycleError::conflict(format!(
                    "Orcel could not be stopped, so nothing was uninstalled: {}",
                    error.message
                ))
            })?;
        human.push_str(&format!("Stopped Orcel first: {}.\n", stopped.detail));
    }
    let platform = host_platform();
    let installer = Installer::new(layout, platform.as_ref());
    let report = installer.uninstall(&UninstallOptions { purge_data })?;
    human.push_str("Orcel uninstalled.\n");
    for (label, paths) in [
        ("Removed", &report.removed),
        (
            if purge_data {
                // Linux and macOS only; a purge keeps nothing else.
                "Kept (the lock file; delete the folder when no Orcel command runs)"
            } else {
                "Kept (user data)"
            },
            &report.retained,
        ),
        ("Purged", &report.purged),
        ("Could not remove", &report.residual),
    ] {
        if !paths.is_empty() {
            human.push_str(&format!("  {label}:\n"));
            for path in paths {
                human.push_str(&format!("    {}\n", path.display()));
            }
        }
    }
    if report.path_entry_removed {
        human.push_str("  PATH: the Orcel bin directory was removed from your user PATH\n");
    }
    if report.start_menu_removed {
        human.push_str("  Start Menu: the Orcel entry was removed\n");
    }
    if let Some(problem) = &report.start_menu_problem {
        human.push_str(&format!("  Start Menu: left as it is ({problem})\n"));
    }
    if let Some(relocated) = &report.relocated_cli {
        human.push_str(&format!(
            "  The running orcel.exe was moved to {} for OS temp cleanup\n",
            relocated.display()
        ));
    }
    if !report.residual.is_empty() {
        return Err(LifecycleError::new(
            ErrorKind::Io,
            format!(
                "{human}Some items were not removed. Close any program using them and rerun. \
                 Anything there that isn't Orcel's is left on purpose: move it first if you \
                 want the folder gone"
            ),
        ));
    }
    Ok(Output {
        exit_code: 0,
        human,
        json: json!({"ok": true, "uninstall": report}),
    })
}

fn version(args: &mut Args) -> Result<Output, LifecycleError> {
    args.finish()?;
    let cli = env!("CARGO_PKG_VERSION");
    let layout = Layout::for_current_user()?;
    let current: Option<orcel_lifecycle::layout::CurrentRecord> =
        orcel_lifecycle::layout::read_current(&layout)?;
    let record: Option<orcel_lifecycle::layout::InstallRecord> =
        orcel_lifecycle::layout::read_install(&layout)?;
    let installed = current.as_ref().map(|current| current.version.clone());
    let previous = record.and_then(|record| record.previous);
    let human = format!(
        "orcel CLI {cli}\ninstalled: {}\nprevious: {}\n",
        installed.as_deref().unwrap_or("not installed"),
        previous.as_deref().unwrap_or("none"),
    );
    Ok(Output {
        exit_code: 0,
        human,
        json: json!({"ok": true, "cli": cli, "installed": installed, "previous": previous}),
    })
}

#[cfg(test)]
mod tests {
    use super::earlier_on_path;
    use super::{checks_legacy_gate, holds_lifecycle_lock};
    #[test]
    fn revoking_or_reading_desktop_control_never_waits_for_the_lifecycle_lock() {
        let rest = |args: &[&str]| args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
        assert!(!holds_lifecycle_lock("full-control", &rest(&["revoke"])));
        assert!(!holds_lifecycle_lock("full-control", &rest(&["status"])));
        assert!(holds_lifecycle_lock(
            "full-control",
            &rest(&["grant", "--minutes", "30"])
        ));
        assert!(holds_lifecycle_lock(
            "full-control",
            &rest(&["--minutes", "30", "grant"])
        ));
        assert!(holds_lifecycle_lock("full-control", &rest(&[])));
        // The action is the first argument not starting with `--`, as `Args::positional`
        // reads it, so a revoke followed by anything is still a revoke, and the command
        // then refuses the extra arguments without granting.
        assert!(!holds_lifecycle_lock(
            "full-control",
            &rest(&["revoke", "grant"])
        ));
        assert!(!holds_lifecycle_lock(
            "full-control",
            &rest(&["--minutes", "revoke", "grant"])
        ));
        assert!(holds_lifecycle_lock("workspace", &rest(&["add", "a", "b"])));
        assert!(holds_lifecycle_lock("workspace", &rest(&["remove", "a"])));
        assert!(holds_lifecycle_lock("workspace", &rest(&["trust", "a"])));
        assert!(!holds_lifecycle_lock("workspace", &rest(&["list"])));
        // `list` followed by anything is still `list`, and `finish()` then refuses the rest.
        assert!(!holds_lifecycle_lock("workspace", &rest(&["list", "add"])));
        // The workspace list still passes the legacy-state gate, without the lock.
        assert!(checks_legacy_gate("workspace", &rest(&["list"])));
        assert!(checks_legacy_gate("workspace", &rest(&["add", "a", "b"])));
        assert!(!checks_legacy_gate("full-control", &rest(&["revoke"])));
        assert!(!checks_legacy_gate("stop", &rest(&[])));
        assert!(!checks_legacy_gate("status", &rest(&[])));
        assert!(!holds_lifecycle_lock("status", &rest(&[])));
        // SG-000135 OB-09: a setup and a start, stop or update never overlap.
        for command in ["start", "stop", "tunnel", "update", "rollback"] {
            assert!(holds_lifecycle_lock(command, &rest(&[])), "{command}");
        }
        assert!(holds_lifecycle_lock("tunnel", &rest(&["setup"])));
        assert!(holds_lifecycle_lock("tunnel", &rest(&["allow"])));
    }
    use std::fs;

    #[test]
    fn the_purge_confirmation_names_the_macos_folder_and_is_unchanged_elsewhere() {
        let root = std::path::Path::new("/Users/ana/Library/Application Support/Orcel");
        let text = super::purge_needs_yes(Some(root));
        assert_eq!(
            super::purge_needs_yes(None),
            "--purge-data permanently deletes configuration, secrets, logs, and history; add --yes to confirm"
        );
        if cfg!(target_os = "macos") {
            assert!(
                text.contains("/Users/ana/Library/Application Support/Orcel"),
                "{text}"
            );
            assert!(text.contains("audit log"), "{text}");
            assert!(text.ends_with("add --yes to confirm"), "{text}");
        } else {
            assert_eq!(
                text,
                "--purge-data permanently deletes configuration, secrets, logs, and history; add --yes to confirm"
            );
        }
    }

    #[test]
    fn only_another_copy_earlier_on_path_is_reported() {
        let base =
            std::env::temp_dir().join(format!("orcel-earlier-on-path-{}", std::process::id()));
        let bin = base.join("bin");
        let other = base.join("other");
        fs::create_dir_all(&bin).unwrap();
        fs::create_dir_all(&other).unwrap();
        fs::write(bin.join("orcel.exe"), b"").unwrap();
        let path = |dirs: &[&std::path::Path]| std::env::join_paths(dirs).unwrap();
        let ext = ".COM;.EXE;.BAT;.CMD";
        // The installed copy, however its folder is spelled, isn't another one.
        assert_eq!(earlier_on_path(&bin, &path(&[&bin]), ext), None);
        let spelled = base.join("other").join("..").join("bin");
        assert_eq!(earlier_on_path(&bin, &path(&[&spelled]), ext), None);
        // A relative entry is skipped, as Node.js lookup skips it.
        assert_eq!(
            earlier_on_path(&bin, &path(&[std::path::Path::new("x"), &bin]), ext),
            None
        );
        // A script earlier on PATH is.
        fs::write(other.join("orcel.cmd"), b"").unwrap();
        assert_eq!(
            earlier_on_path(&bin, &path(&[&other, &bin]), ext),
            Some(other.join("orcel.cmd"))
        );
        assert_eq!(earlier_on_path(&bin, &path(&[&bin, &other]), ext), None);
        let _ = fs::remove_dir_all(&base);
    }
}
