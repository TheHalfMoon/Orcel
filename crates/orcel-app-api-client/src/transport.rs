//! One connection to orceld's endpoint, with its server already confirmed
//! (Windows: this user at Medium integrity or above; Unix: this uid) before
//! the connection is handed out, so nothing can be written to an
//! unconfirmed server.

use crate::error::ClientError;
use std::io::{self, Read, Write};
use std::time::Duration;

/// A confirmed connection.
pub(crate) trait Conn: Read + Write + Send {
    /// How long a read may wait; `None` waits until data, the end of the
    /// stream or a cancel.
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()>;
    /// A handle another thread uses to end a blocked read at once.
    fn canceller(&self) -> io::Result<Canceller>;
}

/// Ends a connection's blocked read from another thread.
pub(crate) struct Canceller(Box<dyn Fn() + Send + Sync>);

impl Canceller {
    pub(crate) fn new(cancel: impl Fn() + Send + Sync + 'static) -> Self {
        Self(Box::new(cancel))
    }

    pub(crate) fn cancel(&self) {
        (self.0)()
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
pub(crate) fn connect(
    endpoint: &Endpoint,
    timeout: Duration,
) -> Result<Box<dyn Conn>, ClientError> {
    #[cfg(windows)]
    {
        crate::win::connect(&endpoint.name, timeout).map(|pipe| Box::new(pipe) as Box<dyn Conn>)
    }
    #[cfg(unix)]
    {
        let _ = timeout;
        crate::unix::connect(&endpoint.path).map(|stream| Box::new(stream) as Box<dyn Conn>)
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = (endpoint, timeout);
        Err(ClientError::Unavailable(
            crate::error::Unavailable::NoLocation,
        ))
    }
}
