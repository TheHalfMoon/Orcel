//! SG-000074 `orcel-browser-host` binary.
//!
//! Launched only by Orcel supervision with `--engine`, `--profile-dir`,
//! and `--host-id`. The binary re-verifies the engine and profile, spawns
//! the engine supervised with the frozen command line, and serves the
//! closed hello/ping/shutdown vocabulary over piped stdio. End of input,
//! shutdown, or any protocol violation stops the engine and exits. There
//! is no listener, no tool, and no other input surface.

use orcel_browser_host::{
    adopt_profile, assert_argv_clean, build_argv, decode_frame, discover_engine,
    engine_launch_admitted, Engine, HostReply, HostRequest, SearchConfig, SupervisedChild,
    PROTOCOL_GENERATION,
};
use std::io::{BufReader, Write};
use std::path::PathBuf;

fn main() {
    if let Err(err) = run() {
        eprintln!("orcel-browser-host: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    // SG-000108 product caller: worker mode exists only in builds with the
    // test-only `live-browser-test` feature or the development-only
    // `live-browser-dev` feature. Elsewhere `--worker` is an unknown
    // argument, and the host exits.
    #[cfg(all(
        windows,
        any(feature = "live-browser-test", feature = "live-browser-dev")
    ))]
    if std::env::args().nth(1).as_deref() == Some("--worker") {
        return run_worker_mode();
    }
    let mut engine: Option<PathBuf> = None;
    let mut profile_dir: Option<PathBuf> = None;
    let mut host_id: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("missing value for {arg}"))?;
        match arg.as_str() {
            "--engine" => engine = Some(PathBuf::from(value)),
            "--profile-dir" => profile_dir = Some(PathBuf::from(value)),
            "--host-id" => host_id = Some(value),
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }
    let engine_path = engine.ok_or_else(|| "--engine is required".to_string())?;
    let profile_dir = profile_dir.ok_or_else(|| "--profile-dir is required".to_string())?;
    let host_id = host_id.ok_or_else(|| "--host-id is required".to_string())?;
    if host_id.is_empty() || host_id.len() > 64 {
        return Err("invalid --host-id".to_string());
    }
    // XP-14: nothing launches on macOS until SG-000115 admits it.
    engine_launch_admitted().map_err(|err| format!("engine launch refused: {err}"))?;
    // Re-verify: the engine must still be a supported verified executable
    // and the profile must still be Orcel-owned for it.
    let verified: Engine = discover_engine(&SearchConfig::production())
        .map_err(|err| format!("engine verification failed: {err}"))?;
    if verified.path() != engine_path {
        return Err("engine path is not the verified engine".to_string());
    }
    let profile = adopt_profile(&profile_dir, &verified.fingerprint())
        .map_err(|err| format!("profile verification failed: {err}"))?;
    let argv = build_argv(profile.dir()).map_err(|err| format!("argv refused: {err}"))?;
    assert_argv_clean(&argv).map_err(|err| format!("argv refused: {err}"))?;
    let env = scrubbed_env();
    let engine_child = orcel_browser_host::spawn_engine_null(verified.path(), &argv, &env)
        .map_err(|err| format!("engine launch failed: {err}"))?;
    serve(host_id, engine_child)
}

/// Worker mode: `--worker --host-id <id> --profile-root <dir> --temp-dir
/// <dir>`, every value from Orcel supervision, never from a caller.
///
/// Where the worker runtime comes from (decision 7):
/// - a `live-browser-dev` build runs only the runtime it compiled in, which
///   every launch verifies against the build's pin and holds; `--node` and
///   `--worker-main` are unknown arguments there, and a build without a
///   whole, well-formed pin refuses every lifetime, typed;
/// - a test-only build takes `--node <node.exe> --worker-main <main.js>`
///   from the test harness (a source no other build has).
#[cfg(all(
    windows,
    any(feature = "live-browser-test", feature = "live-browser-dev")
))]
fn run_worker_mode() -> Result<(), String> {
    #[cfg(feature = "live-browser-dev")]
    const RUNTIME_ARGUMENTS: &[&str] = &[];
    #[cfg(not(feature = "live-browser-dev"))]
    const RUNTIME_ARGUMENTS: &[&str] = &["--node", "--worker-main"];
    let mut values = std::collections::HashMap::new();
    let mut args = std::env::args().skip(2);
    while let Some(arg) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("missing value for {arg}"))?;
        if matches!(arg.as_str(), "--host-id" | "--profile-root" | "--temp-dir")
            || RUNTIME_ARGUMENTS.contains(&arg.as_str())
        {
            if values.insert(arg.clone(), value).is_some() {
                return Err(format!("repeated argument: {arg}"));
            }
        } else {
            return Err(format!("unknown argument: {arg}"));
        }
    }
    let mut take = |name: &str| {
        values
            .remove(name)
            .ok_or_else(|| format!("{name} is required"))
    };
    let host_id = take("--host-id")?;
    if host_id.is_empty() || host_id.len() > 64 {
        return Err("invalid --host-id".to_string());
    }
    let profile_root = PathBuf::from(take("--profile-root")?);
    let temp_dir = PathBuf::from(take("--temp-dir")?);
    #[cfg(feature = "live-browser-dev")]
    let runtime = orcel_browser_host::compiled_runtime(
        option_env!("ORCEL_LIVE_BROWSER_NODE"),
        option_env!("ORCEL_LIVE_BROWSER_WORKER_MAIN"),
        option_env!("ORCEL_LIVE_BROWSER_NODE_SHA256"),
        option_env!("ORCEL_LIVE_BROWSER_TREE_SHA256"),
    )
    .map(|compiled| orcel_browser_host::worker_host::WorkerRuntime {
        node: compiled.node,
        worker_main: compiled.worker_main,
        pin: Some(compiled.pin),
    });
    #[cfg(not(feature = "live-browser-dev"))]
    let runtime = Some(orcel_browser_host::worker_host::WorkerRuntime {
        node: PathBuf::from(take("--node")?),
        worker_main: PathBuf::from(take("--worker-main")?),
        pin: None,
    });
    let mut paths = vec![&profile_root, &temp_dir];
    if let Some(runtime) = &runtime {
        paths.extend([&runtime.node, &runtime.worker_main]);
    }
    if paths.iter().any(|path| !path.is_absolute()) {
        return Err("worker-mode paths must be absolute".to_string());
    }
    let worker_args = orcel_browser_host::worker_host::WorkerHostArgs {
        host_id,
        runtime,
        profile_root,
        temp_dir,
    };
    let stdin = std::io::stdin();
    let mut input = BufReader::new(stdin.lock());
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    orcel_browser_host::worker_host::serve_worker_mode(&worker_args, &mut input, &mut output)
}

/// Scrubbed environment for the engine: OS locations plus profile-scoped
/// temp only. No caller, user-profile, or Orcel secret variable is
/// inherited: USERPROFILE, APPDATA, and LOCALAPPDATA are deliberately
/// absent so the engine can never resolve the personal profile.
fn scrubbed_env() -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    #[cfg(windows)]
    {
        let system_root = std::env::var_os("SystemRoot")
            .unwrap_or_else(|| std::ffi::OsString::from("C:\\Windows"));
        let system32 = PathBuf::from(&system_root).join("System32");
        // TEMP/TMP stay inside Orcel state in the supervised launch path;
        // the host binary itself has no profile yet, so system temp applies.
        let system_temp = PathBuf::from(&system_root).join("Temp");
        vec![
            (std::ffi::OsString::from("SystemRoot"), system_root.clone()),
            (
                std::ffi::OsString::from("SystemDrive"),
                std::env::var_os("SystemDrive").unwrap_or_else(|| std::ffi::OsString::from("C:")),
            ),
            (
                std::ffi::OsString::from("PATH"),
                std::ffi::OsString::from(system32.to_string_lossy().into_owned()),
            ),
            (
                std::ffi::OsString::from("TEMP"),
                system_temp.clone().into_os_string(),
            ),
            (
                std::ffi::OsString::from("TMP"),
                system_temp.into_os_string(),
            ),
        ]
    }
    #[cfg(not(windows))]
    {
        vec![
            (
                std::ffi::OsString::from("PATH"),
                std::ffi::OsString::from("/usr/bin:/bin"),
            ),
            (
                std::ffi::OsString::from("LANG"),
                std::ffi::OsString::from("C"),
            ),
        ]
    }
}

fn serve(host_id: String, engine_child: SupervisedChild) -> Result<(), String> {
    let stdin = std::io::stdin();
    let mut input = BufReader::new(stdin.lock());
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    loop {
        let request: HostRequest =
            decode_frame(&mut input).map_err(|_| "protocol violation".to_string())?;
        match request {
            HostRequest::Hello { generation } => {
                if generation != PROTOCOL_GENERATION {
                    return Err("protocol generation mismatch".to_string());
                }
                write_reply(
                    &mut output,
                    &HostReply::Hello {
                        generation: PROTOCOL_GENERATION,
                        host: host_id.clone(),
                    },
                )?;
            }
            HostRequest::Ping { nonce } => {
                if nonce.is_empty() || nonce.len() > 256 {
                    write_reply(
                        &mut output,
                        &HostReply::Error {
                            code: "bad_nonce".into(),
                        },
                    )?;
                    continue;
                }
                write_reply(&mut output, &HostReply::Pong { nonce })?;
            }
            HostRequest::Shutdown {} => {
                let _ = write_reply(&mut output, &HostReply::Bye {});
                let _ = engine_child.shutdown();
                return Ok(());
            }
        }
    }
    // `decode_frame` enforces the closed vocabulary with
    // `deny_unknown_fields`: anything reaching the match above is known.
    // Any I/O or framing failure returns early; the supervised engine dies
    // with this process through job and drop cleanup.
}

fn write_reply(output: &mut impl Write, reply: &HostReply) -> Result<(), String> {
    orcel_browser_host::write_frame(output, reply).map_err(|_| "reply failed".to_string())?;
    output.flush().map_err(|_| "reply flush failed".to_string())
}
