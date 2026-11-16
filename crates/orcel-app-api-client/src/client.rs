//! Requests: one at a time per client (a mutex serializes them), each on its
//! own confirmed connection, each answer re-shaped by the sanitiser before it
//! is returned.

use crate::cursor::Cursor;
use crate::error::ClientError;
use crate::frame::{self, FrameReader, Incoming};
use crate::method::{Method, TaskId};
use crate::sanitize::capabilities::{self, Capabilities};
use crate::sanitize::rules;
use crate::sanitize::status::{self, Status};
use crate::sanitize::tasks::{self, TaskDetail, TaskList};
use crate::transport::{self, Cancel, Conn, Endpoint};
use serde_json::Value;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// How long connecting may wait for a free pipe instance.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// How long a request waits for its answer.
pub const REPLY_TIMEOUT: Duration = Duration::from_secs(5);

/// The client of this user's orceld app API.
pub struct AppApiClient {
    endpoint: Endpoint,
    /// Held for the whole of each request, so one window never uses more
    /// than one request connection at a time.
    requests: Mutex<()>,
    next_id: AtomicU64,
}

/// orceld's acknowledgement of a subscription.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ack {
    pub epoch: String,
}

impl AppApiClient {
    /// The client of this user's endpoint, derived from this process alone.
    pub fn for_this_user() -> Result<Self, ClientError> {
        Endpoint::for_this_user().map(Self::with_endpoint)
    }

    /// A client of a side-by-side orceld. This crate's own tests only.
    #[cfg(test)]
    pub(crate) fn with_instance(instance: &str) -> Result<Self, ClientError> {
        Endpoint::with_instance(instance).map(Self::with_endpoint)
    }

    fn with_endpoint(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            requests: Mutex::new(()),
            next_id: AtomicU64::new(1),
        }
    }

    /// A client of the socket a test's orceld logged it listens on: on
    /// Linux the location follows the environment, and the test's orceld
    /// has its own. This crate's own tests only.
    #[cfg(all(test, unix))]
    pub(crate) fn with_socket(path: std::path::PathBuf) -> Self {
        Self::with_endpoint(Endpoint { path })
    }

    #[cfg(all(test, windows))]
    pub(crate) fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    fn id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Sends one request on a new connection and returns its `result`.
    fn call(&self, method: &Method) -> Result<Value, ClientError> {
        let _one_at_a_time = self
            .requests
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut conn = transport::connect(&self.endpoint, CONNECT_TIMEOUT, None)?;
        conn.set_read_timeout(Some(REPLY_TIMEOUT))
            .map_err(|error| ClientError::io(&error))?;
        let id = self.id();
        frame::write_frame(&mut conn, &method.request(id))?;
        let mut reader = FrameReader::default();
        read_reply(&mut reader, &mut conn, id)?
    }

    /// `status.get`, sanitised.
    pub fn status(&self) -> Result<Status, ClientError> {
        status::sanitize(&self.call(&Method::StatusGet)?).map_err(|_| ClientError::Incompatible)
    }

    /// `capabilities.get`, sanitised.
    pub fn capabilities(&self) -> Result<Capabilities, ClientError> {
        capabilities::sanitize(&self.call(&Method::CapabilitiesGet)?)
            .map_err(|_| ClientError::Incompatible)
    }

    /// `task.list`, sanitised.
    pub fn tasks(&self) -> Result<TaskList, ClientError> {
        Ok(tasks::list(&self.call(&Method::TaskList)?))
    }

    /// `task.get`, sanitised.
    pub fn task(&self, task_id: &TaskId) -> Result<TaskDetail, ClientError> {
        tasks::detail(&self.call(&Method::TaskGet(task_id.clone()))?)
            .map_err(|_| ClientError::TaskWithheld)
    }

    /// Opens a subscription connection (not under the request mutex: it is
    /// the window's one other connection) and reads orceld's
    /// acknowledgement.
    pub(crate) fn open_subscription(
        &self,
        from: Option<&Cursor>,
        cancel: &Arc<Cancel>,
    ) -> Result<(Box<dyn Conn>, FrameReader, Ack), ClientError> {
        let mut conn =
            transport::connect(&self.endpoint, CONNECT_TIMEOUT, Some(Arc::clone(cancel)))?;
        conn.set_read_timeout(Some(REPLY_TIMEOUT))
            .map_err(|error| ClientError::io(&error))?;
        let id = self.id();
        frame::write_frame(
            &mut conn,
            &Method::EventsSubscribe(from.cloned()).request(id),
        )?;
        let mut reader = FrameReader::default();
        let result = read_reply(&mut reader, &mut conn, id)??;
        let epoch = result
            .get("epoch")
            .and_then(Value::as_str)
            .and_then(rules::epoch)
            .ok_or(ClientError::Protocol("subscription acknowledgement"))?;
        Ok((conn, reader, Ack { epoch }))
    }
}

/// Reads the reply to request `id`: `Ok(Ok(result))`, `Ok(Err(refusal))`
/// for an error frame, or the connection's failure.
fn read_reply(
    reader: &mut FrameReader,
    conn: &mut Box<dyn Conn>,
    id: u64,
) -> Result<Result<Value, ClientError>, ClientError> {
    let Some(bytes) = reader.next(conn)? else {
        return Err(ClientError::Unavailable(
            crate::error::Unavailable::ConnectionLost(None),
        ));
    };
    match frame::parse(&bytes)? {
        Incoming::Reply {
            id: reply_id,
            result,
        } => match result {
            Ok(value) if reply_id == Some(id) => Ok(Ok(value)),
            Ok(_) => Err(ClientError::Protocol("reply to another request")),
            // orceld answers connection-level refusals (BUSY,
            // FRAME_TOO_LARGE) with a null id.
            Err(code) if reply_id == Some(id) || reply_id.is_none() => Ok(Err(if code == "BUSY" {
                ClientError::Busy
            } else {
                ClientError::Refused(code)
            })),
            Err(_) => Err(ClientError::Protocol("reply to another request")),
        },
        Incoming::Event(_) | Incoming::Heartbeat => {
            Err(ClientError::Protocol("event before the reply"))
        }
    }
}
