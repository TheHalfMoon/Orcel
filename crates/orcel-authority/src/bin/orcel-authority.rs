//! `orcel-authority.exe`: the Orcel authority service (SG-000132).
//!
//! - No arguments: run under the service control manager as
//!   `OrcelAuthority` (installed by `scripts/install-orcel-authority.ps1`).
//! - `--console --state-dir <dir> --pipe-suffix <suffix> [--trusted-orceld
//!   <path>]...`: the development and test harness. It runs the same core
//!   and pipe protocol under the current user with the given state
//!   directory, on `\\.\pipe\orcel-authority-console-<suffix>` (never the
//!   service's name), writes events to `<dir>\events.jsonl`, prints one
//!   JSON "ready" line on stdout, and stops when stdin closes. Guarantees
//!   that hold only when installed (state unreadable by the user, a pipe
//!   owner no user process runs as, session changes observed, so grants
//!   possible) do not hold here; see SG132_SLICE1.md.
//! - `--version`.

#[cfg(windows)]
fn console(args: &[String]) -> Result<(), String> {
    use orcel_authority::caller::ClientPolicy;
    use orcel_authority::win::runtime::{run_loop, start, Control, RunConfig};
    use orcel_authority::RunMode;
    use std::io::Read;
    use std::path::PathBuf;

    let mut state_dir: Option<PathBuf> = None;
    let mut suffix: Option<String> = None;
    let mut trusted = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--console" => {}
            "--state-dir" => state_dir = iter.next().map(PathBuf::from),
            "--pipe-suffix" => suffix = iter.next().cloned(),
            "--trusted-orceld" => {
                if let Some(path) = iter.next() {
                    trusted.push(PathBuf::from(path));
                }
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    let state_dir = state_dir.ok_or("--state-dir is required in console mode")?;
    let suffix = suffix.ok_or("--pipe-suffix is required in console mode")?;
    if suffix.is_empty()
        || suffix.len() > 40
        || !suffix
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err("--pipe-suffix is 1 to 40 lowercase letters, digits or hyphens".to_owned());
    }
    let lowered = state_dir
        .to_string_lossy()
        .to_lowercase()
        .replace('/', "\\");
    if lowered.contains("\\orcel\\authority") {
        return Err("console mode never uses the installed service's state directory".to_owned());
    }
    std::fs::create_dir_all(&state_dir)
        .map_err(|error| format!("create the state directory: {error}"))?;
    let owner_sid =
        orcel_authority::win::current_process_sid().map_err(|error| error.to_string())?;
    let pipe_name = format!("{}{suffix}", orcel_authority::CONSOLE_PIPE_PREFIX);
    let config = RunConfig {
        mode: RunMode::Console,
        public_dir: state_dir.join("public"),
        state_dir,
        pipe_name: pipe_name.clone(),
        owner_sid: owner_sid.clone(),
        policy: ClientPolicy {
            trusted_orceld_images: trusted,
        },
    };
    let runtime = start(config).map_err(|error| error.to_string())?;
    let ready = serde_json::json!({
        "ready": true,
        "mode": "console",
        "pipe": pipe_name,
        "pid": std::process::id(),
        "owner_sid": owner_sid,
    });
    println!("{ready}");
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut sink = [0u8; 256];
        let mut stdin = std::io::stdin();
        while matches!(stdin.read(&mut sink), Ok(n) if n > 0) {}
        let _ = sender.send(Control::Stop);
    });
    run_loop(&runtime, &receiver).map_err(|error| error.to_string())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--version") {
        println!("orcel-authority {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    #[cfg(windows)]
    {
        let result = if args.first().map(String::as_str) == Some("--console") {
            console(&args)
        } else if args.is_empty() {
            orcel_authority::win::service::dispatch().map_err(|error| error.to_string())
        } else {
            Err(format!(
                "unknown arguments {args:?}; run with no arguments under the SCM, or --console"
            ))
        };
        if let Err(error) = result {
            eprintln!("orcel-authority: {error}");
            std::process::exit(1);
        }
    }
    #[cfg(not(windows))]
    {
        eprintln!(
            "orcel-authority: {}",
            orcel_authority::AuthorityError::unsupported()
        );
        std::process::exit(2);
    }
}
