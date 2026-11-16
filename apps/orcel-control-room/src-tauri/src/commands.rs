//! SG-000119 slice A3: the five read-only commands, the only things the web
//! view can call (prep packet, "What the web view can call").
//!
//! | Command | Argument | Answer |
//! |---|---|---|
//! | `app_status` | none | `status.get`, sanitised |
//! | `app_capabilities` | none | `capabilities.get`, sanitised |
//! | `app_events` | `channel` (a `tauri::ipc::Channel`), optional `from: {after_seq, epoch}` | sanitised stream items on the channel |
//! | `app_tasks` | none | `task.list`, sanitised |
//! | `app_task` | `task_id` (identifier rule) | `task.get`, sanitised |
//!
//! - **Each needs its own permission.** `build.rs` lists exactly these five
//!   in the app's ACL manifest; the capability file grants exactly their five
//!   `allow-*` permissions to the `main` window, and [`register`] hands
//!   exactly these five to `generate_handler!`. `tests/acl.rs` compares the
//!   lists and runs the real ACL.
//! - **Only the sanitiser's output.** Every answer is the A1 client's
//!   sanitised type, re-serialized from Rust types; nothing orceld wrote is
//!   passed through as text.
//! - **Typed, bounded arguments.** Each command reads its arguments itself
//!   from the request body, which must be a JSON object with no key beyond
//!   the command's own (or nothing, for the three without arguments); an
//!   extra argument, a raw body, a malformed `task_id` or `from` is refused
//!   with a [`CommandError`] before anything is sent to orceld.
//! - **Typed, non-leaking errors.** [`CommandError`] carries a kind and, for
//!   an orceld refusal, orceld's error code only (`[A-Z_]`, at most 32, as
//!   the client keeps it); never orceld's message, a path, a pid or the SID.
//!   The web view receives it as `{"error": "<kind>", ...}`
//!   ([`CommandError::to_value`]), built with `serde_json`, so the shell
//!   needs no `serde` dependency of its own and its lock stays A2's.
//! - **One subscription per window.** `app_events` goes through the client's
//!   [`Window`]: a new call ends the previous subscription (its orceld
//!   connection closed, its channel sent `{"type":"ended"}`) before it opens
//!   one; frames wait in the client's bounded queue (256); the window uses at
//!   most two orceld client slots (this subscription and one serialized
//!   request). Closing the window ends the subscription.
//! - **Blocking reads off the main thread.** The commands are `async` and
//!   run the client's blocking calls on Tauri's blocking pool, so the window
//!   never waits on orceld.
//!
//! Every call that reaches one of these handlers is counted for the exit
//! report's `SG119-IPC commands=<n>`; a call the ACL refuses never reaches
//! them.

use crate::report;
use orcel_app_api_client::error::Unavailable;
use orcel_app_api_client::sanitize::capabilities::Capabilities;
use orcel_app_api_client::sanitize::status::Status;
use orcel_app_api_client::sanitize::tasks::{TaskDetail, TaskList};
use orcel_app_api_client::{
    AppApiClient, ClientError, Cursor, Feed, Next, StreamItem, TaskId, Window,
};
use serde_json::{json, Map, Value};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tauri::ipc::{Channel, InvokeBody, JavaScriptChannelId, Request};
use tauri::{AppHandle, Builder, Manager, RunEvent, Runtime, State, Webview, WindowEvent};

/// The five commands, in the order `build.rs` lists them.
pub const COMMANDS: [&str; 5] = [
    "app_status",
    "app_capabilities",
    "app_events",
    "app_tasks",
    "app_task",
];

/// A command's refusal. The web view receives `{"error": "<kind>"}`, plus
/// `reason` for `unavailable` and `code` for `refused` ([`Self::to_value`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandError {
    /// orceld is not there or did not answer in time.
    Unavailable { reason: UnavailableReason },
    /// "orceld could not be confirmed as yours"; nothing was written to it.
    NotYours,
    /// orceld is not read-only: the window shows this and nothing else.
    Incompatible,
    /// orceld's client slots are all taken.
    Busy,
    /// orceld refused the request with this code (`[A-Z_]`, at most 32).
    Refused { code: String },
    /// A frame larger than 64 KiB.
    FrameTooLarge,
    /// A frame that is not this protocol.
    Protocol,
    /// `task.get` answered a record the sanitiser refused entirely.
    TaskWithheld,
    /// The request body is not this command's arguments (an extra or
    /// missing argument, a raw body, a malformed channel or cursor).
    InvalidArguments,
    /// `task_id` is not 1 to 128 of `[A-Za-z0-9_-]`.
    InvalidTaskId,
    /// The shell could not run the read (a worker or thread failed).
    Internal,
}

/// Why orceld is unavailable, without OS detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnavailableReason {
    NotRunning,
    NoFreeInstance,
    TimedOut,
    ConnectionLost,
    NoLocation,
}

impl UnavailableReason {
    pub fn name(self) -> &'static str {
        match self {
            UnavailableReason::NotRunning => "not_running",
            UnavailableReason::NoFreeInstance => "no_free_instance",
            UnavailableReason::TimedOut => "timed_out",
            UnavailableReason::ConnectionLost => "connection_lost",
            UnavailableReason::NoLocation => "no_location",
        }
    }
}

impl CommandError {
    /// The kind, as the web view reads it in `error`.
    pub fn kind(&self) -> &'static str {
        match self {
            CommandError::Unavailable { .. } => "unavailable",
            CommandError::NotYours => "not_yours",
            CommandError::Incompatible => "incompatible",
            CommandError::Busy => "busy",
            CommandError::Refused { .. } => "refused",
            CommandError::FrameTooLarge => "frame_too_large",
            CommandError::Protocol => "protocol",
            CommandError::TaskWithheld => "task_withheld",
            CommandError::InvalidArguments => "invalid_arguments",
            CommandError::InvalidTaskId => "invalid_task_id",
            CommandError::Internal => "internal",
        }
    }

    /// What the web view receives.
    pub fn to_value(&self) -> Value {
        match self {
            CommandError::Unavailable { reason } => {
                json!({ "error": self.kind(), "reason": reason.name() })
            }
            CommandError::Refused { code } => json!({ "error": self.kind(), "code": code }),
            _ => json!({ "error": self.kind() }),
        }
    }
}

impl From<ClientError> for CommandError {
    fn from(error: ClientError) -> Self {
        match error {
            ClientError::Unavailable(unavailable) => CommandError::Unavailable {
                reason: match unavailable {
                    Unavailable::NotRunning => UnavailableReason::NotRunning,
                    Unavailable::NoFreeInstance => UnavailableReason::NoFreeInstance,
                    Unavailable::TimedOut => UnavailableReason::TimedOut,
                    Unavailable::ConnectionLost(_) => UnavailableReason::ConnectionLost,
                    Unavailable::NoLocation => UnavailableReason::NoLocation,
                },
            },
            ClientError::NotYours(_) => CommandError::NotYours,
            ClientError::Incompatible => CommandError::Incompatible,
            ClientError::Busy => CommandError::Busy,
            ClientError::Refused(code) => CommandError::Refused { code },
            ClientError::FrameTooLarge => CommandError::FrameTooLarge,
            ClientError::Protocol(_) => CommandError::Protocol,
            ClientError::TaskWithheld => CommandError::TaskWithheld,
        }
    }
}

/// One subscription's stream, as the commands read it.
pub trait Events: Send + Sync {
    /// The next item, waiting at most `wait`.
    fn next(&self, wait: Duration) -> Next;
}

impl Events for Feed {
    fn next(&self, wait: Duration) -> Next {
        Feed::next(self, wait)
    }
}

/// What the commands read from: orceld through the A1 client ([`Orceld`]),
/// or a stand-in in the ACL tests. Every method is a read.
pub trait Source: Send + Sync {
    fn status(&self) -> Result<Status, ClientError>;
    fn capabilities(&self) -> Result<Capabilities, ClientError>;
    fn tasks(&self) -> Result<TaskList, ClientError>;
    fn task(&self, task_id: &TaskId) -> Result<TaskDetail, ClientError>;
    /// Ends any earlier subscription first, then subscribes from `from`.
    fn subscribe(&self, from: Option<Cursor>) -> Result<Arc<dyn Events>, ClientError>;
    /// Ends the live subscription, if any.
    fn unsubscribe(&self);
}

/// This user's orceld, through the A1 client: the fixed endpoint, the
/// identity checks before the first write, the closed method enum, the
/// sanitiser, and one [`Window`] (one subscription, one serialized request).
pub struct Orceld {
    window: Result<Window, ClientError>,
}

impl Orceld {
    /// The client of this user's endpoint, derived from this process alone.
    pub fn for_this_user() -> Self {
        Self {
            window: AppApiClient::for_this_user().map(|client| Window::new(Arc::new(client))),
        }
    }

    fn window(&self) -> Result<&Window, ClientError> {
        self.window.as_ref().map_err(Clone::clone)
    }
}

impl Source for Orceld {
    fn status(&self) -> Result<Status, ClientError> {
        self.window()?.client().status()
    }

    fn capabilities(&self) -> Result<Capabilities, ClientError> {
        self.window()?.client().capabilities()
    }

    fn tasks(&self) -> Result<TaskList, ClientError> {
        self.window()?.client().tasks()
    }

    fn task(&self, task_id: &TaskId) -> Result<TaskDetail, ClientError> {
        self.window()?.client().task(task_id)
    }

    fn subscribe(&self, from: Option<Cursor>) -> Result<Arc<dyn Events>, ClientError> {
        let feed: Arc<dyn Events> = self.window()?.subscribe(from);
        Ok(feed)
    }

    fn unsubscribe(&self) {
        if let Ok(window) = &self.window {
            window.unsubscribe();
        }
    }
}

/// The commands' shared state: the one source of this window.
pub struct Bridge {
    source: Arc<dyn Source>,
}

impl Bridge {
    fn source(&self) -> Arc<dyn Source> {
        Arc::clone(&self.source)
    }
}

/// One stream item as `app_events` sends it on its channel, exactly as the
/// client serializes it: `{"type": "event" | "withheld" | "cleared" | "gap" |
/// "unavailable" | "not_yours" | "incompatible", ...}`.
pub fn delivery(item: &StreamItem) -> Option<Value> {
    serde_json::to_value(item).ok()
}

/// The channel's last message, `{"type": "ended"}`: the subscription ended
/// (a newer `app_events` call replaced it, or the window closed).
pub fn ended() -> Value {
    json!({ "type": "ended" })
}

/// How long the channel pump waits for an item before looking again.
const PUMP_WAIT: Duration = Duration::from_millis(500);

/// The app's context from `tauri.conf.json`, the capability file and the ACL
/// manifest `build.rs` generates, for any runtime (the shell's, or the ACL
/// tests' `tauri::test` runtime).
pub fn context<R: Runtime>() -> tauri::Context<R> {
    tauri::generate_context!()
}

/// Registers exactly the five commands over `source`, and ends the window's
/// subscription when the window closes.
pub fn register<R: Runtime>(builder: Builder<R>, source: Arc<dyn Source>) -> Builder<R> {
    let closing = Arc::clone(&source);
    builder
        .manage(Bridge { source })
        .invoke_handler(tauri::generate_handler![
            app_status,
            app_capabilities,
            app_events,
            app_tasks,
            app_task
        ])
        .on_window_event(move |window, event| {
            if window.label() == crate::shell::MAIN_WINDOW
                && matches!(
                    event,
                    WindowEvent::CloseRequested { .. } | WindowEvent::Destroyed
                )
            {
                closing.unsubscribe();
            }
        })
}

/// Ends the window's subscription when the main window closes or the app
/// exits. The shell's run loop calls this for every run event; on the real
/// runtime the window-event hook of [`register`] sees the same close (ending
/// a subscription twice is harmless), and Tauri's test runtime delivers
/// window events to the run loop only.
pub fn on_run_event<R: Runtime>(app: &AppHandle<R>, event: &RunEvent) {
    let closing = match event {
        RunEvent::WindowEvent {
            label,
            event: WindowEvent::CloseRequested { .. } | WindowEvent::Destroyed,
            ..
        } => label == crate::shell::MAIN_WINDOW,
        RunEvent::Exit => true,
        _ => false,
    };
    if closing {
        if let Some(bridge) = app.try_state::<Bridge>() {
            bridge.source.unsubscribe();
        }
    }
}

/// The request's arguments: a JSON object whose keys are all in `allowed`
/// (an absent body counts as no argument). Anything else is refused.
fn arguments<'a>(
    request: &'a Request<'_>,
    allowed: &[&str],
) -> Result<Option<&'a Map<String, Value>>, CommandError> {
    match request.body() {
        InvokeBody::Json(Value::Null) => Ok(None),
        InvokeBody::Json(Value::Object(map))
            if map.keys().all(|key| allowed.contains(&key.as_str())) =>
        {
            Ok(Some(map))
        }
        _ => Err(CommandError::InvalidArguments),
    }
}

/// `task_id`, `app_task`'s only argument, under the identifier rule.
fn task_id(request: &Request<'_>) -> Result<TaskId, CommandError> {
    arguments(request, &["task_id"])?
        .and_then(|arguments| arguments.get("task_id"))
        .ok_or(CommandError::InvalidArguments)?
        .as_str()
        .and_then(TaskId::parse)
        .ok_or(CommandError::InvalidTaskId)
}

/// `from`: absent or `null` (the start of orceld's ring), or exactly
/// `{after_seq: <u64>, epoch: <orceld's epoch format>}`.
fn cursor(from: Option<&Value>) -> Result<Option<Cursor>, CommandError> {
    match from {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(map))
            if map.len() == 2 && map.contains_key("after_seq") && map.contains_key("epoch") =>
        {
            let after_seq = map["after_seq"]
                .as_u64()
                .ok_or(CommandError::InvalidArguments)?;
            let epoch = map["epoch"]
                .as_str()
                .ok_or(CommandError::InvalidArguments)?;
            Cursor::new(epoch, after_seq)
                .map(Some)
                .ok_or(CommandError::InvalidArguments)
        }
        Some(_) => Err(CommandError::InvalidArguments),
    }
}

/// Runs one blocking read on Tauri's blocking pool.
async fn blocking<T: Send + 'static>(
    read: impl FnOnce() -> Result<T, ClientError> + Send + 'static,
) -> Result<T, CommandError> {
    tauri::async_runtime::spawn_blocking(read)
        .await
        .map_err(|_| CommandError::Internal)?
        .map_err(CommandError::from)
}

/// `status.get`, sanitised.
#[tauri::command]
async fn app_status(request: Request<'_>, bridge: State<'_, Bridge>) -> Result<Status, Value> {
    report::command();
    let source = bridge.source();
    let read = async move {
        arguments(&request, &[])?;
        blocking(move || source.status()).await
    };
    read.await.map_err(|error| error.to_value())
}

/// `capabilities.get`, sanitised.
#[tauri::command]
async fn app_capabilities(
    request: Request<'_>,
    bridge: State<'_, Bridge>,
) -> Result<Capabilities, Value> {
    report::command();
    let source = bridge.source();
    let read = async move {
        arguments(&request, &[])?;
        blocking(move || source.capabilities()).await
    };
    read.await.map_err(|error| error.to_value())
}

/// `task.list`, sanitised.
#[tauri::command]
async fn app_tasks(request: Request<'_>, bridge: State<'_, Bridge>) -> Result<TaskList, Value> {
    report::command();
    let source = bridge.source();
    let read = async move {
        arguments(&request, &[])?;
        blocking(move || source.tasks()).await
    };
    read.await.map_err(|error| error.to_value())
}

/// `task.get` for `task_id`, sanitised.
#[tauri::command]
async fn app_task(request: Request<'_>, bridge: State<'_, Bridge>) -> Result<TaskDetail, Value> {
    report::command();
    let source = bridge.source();
    let read = async move {
        let task_id = task_id(&request)?;
        blocking(move || source.task(&task_id)).await
    };
    read.await.map_err(|error| error.to_value())
}

/// `events.subscribe` from `from`, its sanitised items sent on `channel`.
/// Ends any earlier subscription first; answers once subscribed.
#[tauri::command]
async fn app_events<R: Runtime>(
    webview: Webview<R>,
    request: Request<'_>,
    bridge: State<'_, Bridge>,
) -> Result<(), Value> {
    report::command();
    let source = bridge.source();
    subscribe(webview, &request, source)
        .await
        .map_err(|error| error.to_value())
}

async fn subscribe<R: Runtime>(
    webview: Webview<R>,
    request: &Request<'_>,
    source: Arc<dyn Source>,
) -> Result<(), CommandError> {
    let arguments =
        arguments(request, &["channel", "from"])?.ok_or(CommandError::InvalidArguments)?;
    let channel: Channel<Value> = arguments
        .get("channel")
        .and_then(Value::as_str)
        .and_then(|id| JavaScriptChannelId::from_str(id).ok())
        .ok_or(CommandError::InvalidArguments)?
        .channel_on(webview);
    let from = cursor(arguments.get("from"))?;
    let subscribing = Arc::clone(&source);
    let events = blocking(move || subscribing.subscribe(from)).await?;
    let pumped = std::thread::Builder::new()
        .name("orcel-control-room-events".into())
        .spawn(move || pump(events.as_ref(), &channel));
    if pumped.is_err() {
        source.unsubscribe();
        return Err(CommandError::Internal);
    }
    Ok(())
}

/// Sends each item of one subscription on its channel until it ends, then
/// `{"type": "ended"}`. A channel that cannot be sent to (the web view is
/// gone) stops the pump; closing the window ends the subscription itself.
fn pump(events: &dyn Events, channel: &Channel<Value>) {
    loop {
        match events.next(PUMP_WAIT) {
            Next::Item(item) => {
                if let Some(message) = delivery(&item) {
                    if channel.send(message).is_err() {
                        return;
                    }
                }
            }
            Next::Idle => {}
            Next::Ended => {
                let _ = channel.send(ended());
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Value {
        serde_json::from_str(text).unwrap()
    }

    #[test]
    fn client_errors_map_to_kinds_without_detail() {
        let cases = [
            (
                ClientError::Unavailable(Unavailable::ConnectionLost(Some(232))),
                r#"{"error":"unavailable","reason":"connection_lost"}"#,
            ),
            (
                ClientError::Unavailable(Unavailable::NotRunning),
                r#"{"error":"unavailable","reason":"not_running"}"#,
            ),
            (ClientError::Busy, r#"{"error":"busy"}"#),
            (
                ClientError::Refused("TASK_NOT_FOUND".into()),
                r#"{"code":"TASK_NOT_FOUND","error":"refused"}"#,
            ),
            (
                ClientError::Protocol("reply to another request"),
                r#"{"error":"protocol"}"#,
            ),
            (ClientError::Incompatible, r#"{"error":"incompatible"}"#),
            (ClientError::TaskWithheld, r#"{"error":"task_withheld"}"#),
            (ClientError::FrameTooLarge, r#"{"error":"frame_too_large"}"#),
        ];
        for (error, expected) in cases {
            assert_eq!(CommandError::from(error).to_value(), parse(expected));
        }
        for (error, expected) in [
            (
                CommandError::InvalidArguments,
                r#"{"error":"invalid_arguments"}"#,
            ),
            (
                CommandError::InvalidTaskId,
                r#"{"error":"invalid_task_id"}"#,
            ),
            (CommandError::NotYours, r#"{"error":"not_yours"}"#),
            (CommandError::Internal, r#"{"error":"internal"}"#),
        ] {
            assert_eq!(error.to_value(), parse(expected));
        }
    }

    #[test]
    fn a_cursor_is_exactly_after_seq_and_an_orceld_epoch() {
        let epoch = format!("{:x}-{:x}", 4242u32, 1_763_301_234_567_890_123u128);
        assert_eq!(cursor(None), Ok(None));
        assert_eq!(cursor(Some(&Value::Null)), Ok(None));
        let good = json!({ "after_seq": 7, "epoch": epoch });
        assert_eq!(
            cursor(Some(&good))
                .unwrap()
                .map(|cursor| (cursor.after_seq(), cursor.epoch().to_owned())),
            Some((7, epoch.clone()))
        );
        for bad in [
            json!({ "after_seq": 7 }),
            json!({ "after_seq": 7, "epoch": epoch, "extra": 1 }),
            json!({ "after_seq": -1, "epoch": epoch }),
            json!({ "after_seq": "7", "epoch": epoch }),
            json!({ "after_seq": 7, "epoch": "NOT-AN-EPOCH" }),
            json!([7, epoch]),
            json!("7"),
        ] {
            assert_eq!(
                cursor(Some(&bad)),
                Err(CommandError::InvalidArguments),
                "{bad}"
            );
        }
    }

    #[test]
    fn the_channel_messages_are_typed() {
        assert_eq!(ended().to_string(), r#"{"type":"ended"}"#);
        assert_eq!(
            delivery(&StreamItem::Gap).unwrap().to_string(),
            r#"{"type":"gap"}"#
        );
        assert_eq!(
            delivery(&StreamItem::Unavailable {
                reason: "orceld is not running".into()
            })
            .unwrap()
            .to_string(),
            r#"{"reason":"orceld is not running","type":"unavailable"}"#
        );
    }
}
