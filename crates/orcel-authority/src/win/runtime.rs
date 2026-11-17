//! The authority runtime shared by the installed service and the console
//! harness: open the core, publish the public key, own the pipe name,
//! serve connections, and turn session changes and the clock into core
//! calls.

use super::confirm;
use super::crypto::{EcdsaP256Signer, HelloKeyVerifier, SystemEntropy};
use super::eventlog::{EventLogSink, FileEventSink};
use super::identity;
use super::pipe::{create_instance, CreateError, Pipe};
use crate::caller::{CallerFacts, ClientPolicy};
use crate::core::{AuthorityCore, EventSink, Services};
use crate::error::AuthorityError;
use crate::lease::key_id_of;
use crate::protocol::{read_frame, write_frame, Request, Response};
use crate::{hex, RunMode};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    WTS_CONSOLE_DISCONNECT, WTS_REMOTE_DISCONNECT, WTS_SESSION_LOCK, WTS_SESSION_LOGOFF,
    WTS_SESSION_UNLOCK,
};

/// The signing key file in the state directory (DPAPI-wrapped).
pub const SIGNING_KEY_FILE: &str = "lease-signing.key";
/// The published public key, in the public directory.
pub const PUBLIC_KEY_FILE: &str = "lease-signing-key.json";
/// Console mode's event file.
pub const EVENT_FILE: &str = "events.jsonl";

/// Concurrent connections served; more are closed at once.
const MAX_CONNECTIONS: usize = 32;
/// Requests served on one connection.
const MAX_REQUESTS_PER_CONNECTION: usize = 64;
/// Per-frame read and write timeout.
const IO_TIMEOUT: Duration = Duration::from_secs(10);

pub struct RunConfig {
    pub mode: RunMode,
    pub state_dir: PathBuf,
    pub public_dir: PathBuf,
    pub pipe_name: String,
    /// The pipe owner: the service SID, or the console user's SID.
    pub owner_sid: String,
    pub policy: ClientPolicy,
}

/// What the service control handler (or the console's stdin watcher)
/// tells the runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Control {
    SessionChange { event: u32, session: u32 },
    Stop,
}

pub struct Runtime {
    pub core: Arc<Mutex<AuthorityCore>>,
    pub config: RunConfig,
}

fn lock(
    core: &Arc<Mutex<AuthorityCore>>,
) -> Result<std::sync::MutexGuard<'_, AuthorityCore>, AuthorityError> {
    core.lock()
        .map_err(|_| AuthorityError::internal("the authority core lock is poisoned"))
}

/// Opens the core and takes the pipe name. Fails (and the service does not
/// run) when the name already exists.
pub fn start(config: RunConfig) -> Result<Runtime, AuthorityError> {
    let events: Box<dyn EventSink> = match config.mode {
        RunMode::Service => Box::new(EventLogSink::open()?),
        RunMode::Console => Box::new(FileEventSink::new(config.state_dir.join(EVENT_FILE))),
    };
    // Take the name first: a squatted name stops everything before any
    // state is touched.
    let first = match create_instance(&config.pipe_name, &config.owner_sid, true) {
        Ok(pipe) => pipe,
        Err(CreateError::NameTaken(message)) => {
            let _ = events.record(
                crate::EVENT_SERVICE_ERROR,
                true,
                &format!("orcel-authority/1|refused-start|{message}"),
            );
            return Err(AuthorityError::unavailable(message));
        }
        Err(CreateError::Failed(error)) => {
            let _ = events.record(
                crate::EVENT_SERVICE_ERROR,
                true,
                &format!("orcel-authority/1|refused-start|{}", error.message),
            );
            return Err(error);
        }
    };
    crate::core::check_signing_key_history(&config.state_dir, SIGNING_KEY_FILE)?;
    let signer = EcdsaP256Signer::load_or_create(&config.state_dir.join(SIGNING_KEY_FILE))?;
    let services = Services {
        signer: Box::new(signer),
        presence: Box::new(HelloKeyVerifier),
        events,
        entropy: Box::new(SystemEntropy),
        clock: crate::now_ms,
    };
    let core = AuthorityCore::open(
        config.mode,
        &config.state_dir,
        config.policy.clone(),
        services,
    )?;
    publish_public_key(&config, &core.public_key())?;
    let core = Arc::new(Mutex::new(core));
    let accept_core = Arc::clone(&core);
    let name = config.pipe_name.clone();
    let owner = config.owner_sid.clone();
    std::thread::Builder::new()
        .name("orcel-authority-accept".to_owned())
        .spawn(move || accept_loop(first, &name, &owner, &accept_core))
        .map_err(|error| AuthorityError::internal(format!("start the accept thread: {error}")))?;
    Ok(Runtime { core, config })
}

fn publish_public_key(config: &RunConfig, public: &[u8]) -> Result<(), AuthorityError> {
    std::fs::create_dir_all(&config.public_dir).map_err(|error| {
        AuthorityError::internal(format!("create the public key directory: {error}"))
    })?;
    let document = serde_json::json!({
        "contract": "orcel.authority-public-key/1",
        "service": crate::SERVICE_NAME,
        "mode": config.mode.as_str(),
        "algorithm": "ECDSA_P256_SHA256",
        "format": "BCRYPT_ECCPUBLIC_BLOB",
        "key_id": key_id_of(public),
        "public_key_hex": hex(public),
        "written_at_ms": crate::now_ms(),
    });
    let text = serde_json::to_vec_pretty(&document)
        .map_err(|error| AuthorityError::internal(format!("encode the public key: {error}")))?;
    crate::core::write_atomically(&config.public_dir.join(PUBLIC_KEY_FILE), &text)
}

fn accept_loop(first: Pipe, name: &str, owner: &str, core: &Arc<Mutex<AuthorityCore>>) {
    let active = Arc::new(AtomicUsize::new(0));
    let mut listener = first;
    loop {
        let connected = listener.connect();
        // Always keep an instance listening, owned by us, before serving.
        let next = loop {
            match create_instance(name, owner, false) {
                Ok(pipe) => break pipe,
                Err(_) => std::thread::sleep(Duration::from_millis(200)),
            }
        };
        let conn = std::mem::replace(&mut listener, next);
        if connected.is_err() {
            continue;
        }
        if active.load(Ordering::Acquire) >= MAX_CONNECTIONS {
            continue;
        }
        active.fetch_add(1, Ordering::AcqRel);
        let core = Arc::clone(core);
        let counter = Arc::clone(&active);
        let spawned = std::thread::Builder::new()
            .name("orcel-authority-conn".to_owned())
            .spawn(move || {
                serve_connection(conn, &core);
                counter.fetch_sub(1, Ordering::AcqRel);
            });
        if spawned.is_err() {
            active.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

fn serve_connection(mut conn: Pipe, core: &Arc<Mutex<AuthorityCore>>) {
    conn.set_timeouts(Some(IO_TIMEOUT), Some(IO_TIMEOUT));
    // Read once the first frame is in: ImpersonateNamedPipeClient takes
    // the security context of the last message read from the pipe.
    let mut facts: Option<Result<CallerFacts, AuthorityError>> = None;
    for _ in 0..MAX_REQUESTS_PER_CONNECTION {
        let frame = match read_frame(&mut conn) {
            Ok(Some(frame)) => frame,
            Ok(None) | Err(_) => return,
        };
        let facts = facts.get_or_insert_with(|| identity::client_facts(conn.raw()));
        let response = match (&*facts, serde_json::from_slice::<Request>(&frame)) {
            (Err(error), _) => Response::failure(&AuthorityError::denied(format!(
                "the caller's identity could not be read: {}",
                error.message
            ))),
            (_, Err(error)) => Response::failure(&AuthorityError::invalid(format!(
                "not an authority request: {error}"
            ))),
            (Ok(facts), Ok(request)) => match lock(core) {
                Ok(mut core) => match core.handle(facts, request) {
                    Ok(result) => Response::success(result),
                    Err(error) => Response::failure(&error),
                },
                Err(error) => Response::failure(&error),
            },
        };
        let Ok(bytes) = serde_json::to_vec(&response) else {
            return;
        };
        if write_frame(&mut conn, &bytes).is_err() {
            return;
        }
    }
}

/// Runs until [`Control::Stop`]: session changes, confirmations and the
/// one-second expiry tick.
pub fn run_loop(runtime: &Runtime, control: &Receiver<Control>) -> Result<(), AuthorityError> {
    loop {
        match control.recv_timeout(Duration::from_secs(1)) {
            Ok(Control::Stop) | Err(RecvTimeoutError::Disconnected) => break,
            Ok(Control::SessionChange { event, session }) => {
                handle_session_change(runtime, event, session)?;
            }
            Err(RecvTimeoutError::Timeout) => {}
        }
        lock(&runtime.core)?.tick()?;
    }
    lock(&runtime.core)?.shutdown()
}

fn handle_session_change(
    runtime: &Runtime,
    event: u32,
    session: u32,
) -> Result<(), AuthorityError> {
    let mut core = lock(&runtime.core)?;
    match event {
        WTS_SESSION_UNLOCK => {
            if let Some(task) = core.observe_unlock(session) {
                drop(core);
                let core = Arc::clone(&runtime.core);
                std::thread::Builder::new()
                    .name("orcel-authority-confirm".to_owned())
                    .spawn(move || {
                        let answer = confirm::render(&task);
                        if let Ok(mut core) = core.lock() {
                            let _ = core.confirmation_answer(&task.intent_id, answer);
                        }
                    })
                    .map_err(|error| {
                        AuthorityError::internal(format!("start the confirmation: {error}"))
                    })?;
            }
            Ok(())
        }
        WTS_SESSION_LOCK => core.session_ended(session, "session_lock", true),
        WTS_SESSION_LOGOFF => core.session_ended(session, "session_logoff", false),
        WTS_CONSOLE_DISCONNECT => core.session_ended(session, "console_disconnect", false),
        WTS_REMOTE_DISCONNECT => core.session_ended(session, "remote_disconnect", false),
        _ => Ok(()),
    }
}
