//! One connection to orceld's endpoint, with its server already confirmed
//! (Windows: this user at Medium integrity or above, and a pipe object this
//! user owns labeled Medium or above; Unix: this uid) before the connection
//! is handed out, so nothing can be written to an unconfirmed server.

use crate::error::ClientError;
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// A confirmed connection.
pub(crate) trait Conn: Read + Write + Send {
    /// How long a read may wait; `None` waits until data, the end of the
    /// stream or a cancel.
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()>;
}

/// Ends, from another thread, the wait for a free endpoint instance and
/// every read of the connections opened with it. Created before the
/// connection, so a subscription can be ended while it connects or waits
/// for orceld's acknowledgement. Once cancelled it stays cancelled.
pub(crate) struct Cancel {
    cancelled: AtomicBool,
    #[cfg(windows)]
    event: crate::win::CancelEvent,
    #[cfg(unix)]
    stream: std::sync::Mutex<Option<std::os::unix::net::UnixStream>>,
}

impl Cancel {
    pub(crate) fn new() -> io::Result<Arc<Self>> {
        Ok(Arc::new(Self {
            cancelled: AtomicBool::new(false),
            #[cfg(windows)]
            event: crate::win::CancelEvent::new()?,
            #[cfg(unix)]
            stream: std::sync::Mutex::new(None),
        }))
    }

    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        #[cfg(windows)]
        self.event.set();
        #[cfg(unix)]
        if let Some(stream) = self
            .stream
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
        {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    #[cfg(windows)]
    pub(crate) fn event(&self) -> &crate::win::CancelEvent {
        &self.event
    }

    /// Unix: keeps a handle to `stream` so a cancel shuts it down; a cancel
    /// that came first shuts it down at once.
    #[cfg(unix)]
    pub(crate) fn watch(&self, stream: &std::os::unix::net::UnixStream) -> io::Result<()> {
        let clone = stream.try_clone()?;
        *self
            .stream
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(clone);
        if self.is_cancelled() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        Ok(())
    }
}

/// This user's endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Endpoint {
    #[cfg(windows)]
    pub(crate) name: String,
    #[cfg(unix)]
    pub(crate) path: std::path::PathBuf,
}

impl Endpoint {
    /// The endpoint derived from this process alone (Windows: its token's
    /// SID). No environment variable, argument or file changes it on
    /// Windows.
    pub(crate) fn for_this_user() -> Result<Self, ClientError> {
        #[cfg(windows)]
        {
            crate::win::pipe_name("").map(|name| Self { name })
        }
        #[cfg(unix)]
        {
            crate::unix::socket_path("").map(|path| Self { path })
        }
        #[cfg(not(any(windows, unix)))]
        {
            Err(ClientError::Unavailable(
                crate::error::Unavailable::NoLocation,
            ))
        }
    }

    /// A side-by-side orceld's endpoint (`ORCEL_APP_API_INSTANCE` on its
    /// side). This crate's own tests only: the shell has no such path.
    #[cfg(test)]
    pub(crate) fn with_instance(instance: &str) -> Result<Self, ClientError> {
        assert!(
            !instance.is_empty()
                && instance.len() <= 32
                && instance
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "an instance is 1-32 of a-z, 0-9 and -"
        );
        let suffix = format!("-{instance}");
        #[cfg(windows)]
        {
            crate::win::pipe_name(&suffix).map(|name| Self { name })
        }
        #[cfg(unix)]
        {
            crate::unix::socket_path(&suffix).map(|path| Self { path })
        }
        #[cfg(not(any(windows, unix)))]
        {
            let _ = suffix;
            Err(ClientError::Unavailable(
                crate::error::Unavailable::NoLocation,
            ))
        }
    }
}

/// Opens the endpoint and confirms its server, or refuses before writing.
/// `cancel` (a fresh one when `None`) can end the connect wait and every
/// read from another thread.
pub(crate) fn connect(
    endpoint: &Endpoint,
    timeout: Duration,
    cancel: Option<Arc<Cancel>>,
) -> Result<Box<dyn Conn>, ClientError> {
    let cancel = match cancel {
        Some(cancel) => cancel,
        None => Cancel::new().map_err(|error| ClientError::io(&error))?,
    };
    if cancel.is_cancelled() {
        return Err(ClientError::Unavailable(
            crate::error::Unavailable::ConnectionLost(None),
        ));
    }
    #[cfg(windows)]
    {
        crate::win::connect(&endpoint.name, timeout, cancel)
            .map(|pipe| Box::new(pipe) as Box<dyn Conn>)
    }
    #[cfg(unix)]
    {
        let _ = timeout;
        crate::unix::connect(&endpoint.path, &cancel)
            .map(|stream| Box::new(stream) as Box<dyn Conn>)
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = (endpoint, timeout, cancel);
        Err(ClientError::Unavailable(
            crate::error::Unavailable::NoLocation,
        ))
    }
}
