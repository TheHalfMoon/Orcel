//! SG-000120: the orceld run that wrote a journal line, shared by every
//! kernel journal so liveness is judged one way only.

use serde::{Deserialize, Serialize};

/// The orceld run that wrote a line: its process instance and run id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Owner {
    pub(crate) run: String,
    pub(crate) pid: u32,
    pub(crate) generation: u64,
    /// Linux boot id, as decimal text (a u128 does not survive JSON).
    pub(crate) boot_id: Option<String>,
}

impl Owner {
    /// This process, as run `run`; `None` when the OS will not say.
    pub(crate) fn current(run: &str) -> Option<Self> {
        let instance = orcel_platform::process::current_instance().ok()?;
        Some(Self {
            run: run.to_owned(),
            pid: instance.pid,
            generation: instance.generation,
            boot_id: instance.boot_id.map(|id| id.to_string()),
        })
    }

    /// Whether this run's process has exited: its pid is gone or now names
    /// another process instance. An identity the OS will not report counts
    /// as running, so a live orceld's open intent is never reconciled.
    pub(crate) fn has_exited(&self) -> bool {
        match orcel_platform::process::start_generation(self.pid) {
            Ok(now) => {
                now.generation != self.generation
                    || now.boot_id.map(|id| id.to_string()) != self.boot_id
            }
            Err(orcel_platform::PlatformError::ProcessGone(_)) => true,
            Err(_) => false,
        }
    }

    /// An owner whose process does not exist, for tests.
    #[cfg(test)]
    pub(crate) fn exited(run: &str) -> Self {
        Self {
            run: run.to_owned(),
            pid: 0x7FFF_FFF0,
            generation: 1,
            boot_id: None,
        }
    }
}
