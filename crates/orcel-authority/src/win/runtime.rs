//! The authority runtime shared by the installed service and the console
//! harness: open the core, publish the public key, own the pipe name,
//! serve connections, and turn session changes and the clock into core
//! calls.

use super::confirm;
use super::crypto::{CngRsaVerifier, EcdsaP256Signer, HelloKeyVerifier, SystemEntropy};
use super::eventlog::{EventLogSink, FileEventSink};
use super::identity;
use super::pipe::{create_instance, CreateError, Pipe};
use crate::attestation::AttestationReport;
use crate::caller::{CallerFacts, ClientPolicy};
use crate::core::{
    AttestationVerifier, AuthorityCore, ConfirmAnswer, ConfirmationTask, EventSink,
    PresenceVerifier, Services,
};
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
    /// TEST BUILDS ONLY (`authority-scripted-consent`): console mode stands in for the
    /// unlock, the confirmation (answered Yes, its text appended to this
    /// log) and Windows Hello. Refused at start in every other build and
    /// in service mode.
    pub scripted_consent_log: Option<PathBuf>,
}

/// Slice 2: TPM key attestation with the pinned roots found on this PC.
pub struct TpmAttestationVerifier {
    roots: Vec<Vec<u8>>,
}

impl TpmAttestationVerifier {
    pub fn on_this_pc() -> Self {
        Self {
            roots: super::roots::pinned_roots_on_this_pc(),
        }
    }
}

impl AttestationVerifier for TpmAttestationVerifier {
    fn available(&self) -> bool {
        !self.roots.is_empty()
    }

    fn verify(
        &self,
        spki_der: &[u8],
        attestation: &[u8],
        chain: &[u8],
        now_ms: u64,
    ) -> Result<AttestationReport, AuthorityError> {
        crate::attestation::verify(
            spki_der,
            attestation,
            chain,
            &self.roots,
            now_ms,
            &CngRsaVerifier,
        )
    }
}

/// The domain of the scripted presence signature (test builds only).
pub const SCRIPTED_PRESENCE_DOMAIN: &[u8] = b"orcel-e2e-scripted-presence/1\n";

/// TEST BUILDS ONLY: accepts `SHA-256(SCRIPTED_PRESENCE_DOMAIN || challenge)`
/// in place of a Windows Hello signature.
#[cfg(feature = "authority-scripted-consent")]
struct ScriptedPresence;

#[cfg(feature = "authority-scripted-consent")]
impl PresenceVerifier for ScriptedPresence {
    fn check_public_key(&self, _spki_der: &[u8]) -> Result<(), AuthorityError> {
        Err(AuthorityError::denied("scripted consent enrolls no key"))
    }

    fn verify(
        &self,
        _spki_der: &[u8],
        challenge: &[u8],
        signature: &[u8],
    ) -> Result<(), AuthorityError> {
        let mut input = SCRIPTED_PRESENCE_DOMAIN.to_vec();
        input.extend_from_slice(challenge);
        if hex(signature) == crate::sha256_hex(&input) {
            Ok(())
        } else {
            Err(AuthorityError::denied(
                "the scripted presence does not match",
            ))
        }
    }
}

fn presence_verifier(config: &RunConfig) -> Result<Box<dyn PresenceVerifier>, AuthorityError> {
    match &config.scripted_consent_log {
        None => Ok(Box::new(HelloKeyVerifier)),
        #[cfg(feature = "authority-scripted-consent")]
        Some(_) if config.mode == RunMode::Console => Ok(Box::new(ScriptedPresence)),
        Some(_) => Err(AuthorityError::denied(
            "scripted consent exists only in console mode of an authority-scripted-consent test build",
        )),
    }
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
    let presence = presence_verifier(&config)?;
    let signer = EcdsaP256Signer::load_or_create(&config.state_dir.join(SIGNING_KEY_FILE))?;
    let services = Services {
        signer: Box::new(signer),
        presence,
        attestation: Box::new(TpmAttestationVerifier::on_this_pc()),
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
    let serving = Serving {
        mode: config.mode,
        scripted_log: config.scripted_consent_log.clone(),
    };
    std::thread::Builder::new()
        .name("orcel-authority-accept".to_owned())
        .spawn(move || accept_loop(first, &name, &owner, &accept_core, &serving))
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

/// How connections are served.
#[derive(Clone)]
struct Serving {
    mode: RunMode,
    #[cfg_attr(not(feature = "authority-scripted-consent"), allow(dead_code))]
    scripted_log: Option<PathBuf>,
}

/// Renders a confirmation on its own thread and reports the answer.
fn spawn_confirmation(core: &Arc<Mutex<AuthorityCore>>, task: ConfirmationTask) {
    let intent_id = task.intent_id.clone();
    let shared = Arc::clone(core);
    let spawned = std::thread::Builder::new()
        .name("orcel-authority-confirm".to_owned())
        .spawn(move || {
            let answer = confirm::render(&task);
            if let Ok(mut core) = shared.lock() {
                let _ = core.confirmation_answer(&task.intent_id, answer);
            }
        });
    if spawned.is_err() {
        if let Ok(mut core) = core.lock() {
            let _ = core.confirmation_answer(
                &intent_id,
                ConfirmAnswer::Failed("the confirmation could not start".to_owned()),
            );
        }
    }
}

/// TEST BUILDS ONLY: stand in for the unlock and a Yes, logging the text.
#[cfg(feature = "authority-scripted-consent")]
fn scripted_consent(core: &mut AuthorityCore, log: &std::path::Path) {
    use std::io::Write;
    for session in core.sessions_awaiting_unlock() {
        if let Some(task) = core.observe_unlock(session) {
            let line = serde_json::json!({
                "intent_id": task.intent_id,
                "title": task.title,
                "text": task.text,
            });
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(log)
            {
                let _ = writeln!(file, "{line}");
            }
            let _ = core.confirmation_answer(&task.intent_id, ConfirmAnswer::Yes);
        }
    }
}

fn accept_loop(
    first: Pipe,
    name: &str,
    owner: &str,
    core: &Arc<Mutex<AuthorityCore>>,
    serving: &Serving,
) {
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
        let serving = serving.clone();
        let spawned = std::thread::Builder::new()
            .name("orcel-authority-conn".to_owned())
            .spawn(move || {
                serve_connection(conn, &core, &serving);
                counter.fetch_sub(1, Ordering::AcqRel);
            });
        if spawned.is_err() {
            active.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

fn serve_connection(mut conn: Pipe, core: &Arc<Mutex<AuthorityCore>>, serving: &Serving) {
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
                Ok(mut guard) => {
                    #[cfg(feature = "authority-scripted-consent")]
                    if serving.scripted_log.is_some()
                        && matches!(request, Request::GrantBegin { .. })
                    {
                        let _ = guard.enroll_scripted(&facts.user_sid);
                    }
                    let response = match guard.handle(facts, request) {
                        Ok(result) => Response::success(result),
                        Err(error) => Response::failure(&error),
                    };
                    #[cfg(feature = "authority-scripted-consent")]
                    if let Some(log) = &serving.scripted_log {
                        scripted_consent(&mut guard, log);
                    }
                    // Enrollment confirmations: rendered by the installed
                    // service only (console mode never shows a box and never
                    // enrolls).
                    let tasks = guard.take_pending_confirmations();
                    drop(guard);
                    if serving.mode == RunMode::Service {
                        for task in tasks {
                            spawn_confirmation(core, task);
                        }
                    }
                    response
                }
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
                spawn_confirmation(&runtime.core, task);
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
