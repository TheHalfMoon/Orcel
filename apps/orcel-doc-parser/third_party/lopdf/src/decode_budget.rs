//! Orcel patch P-02 (`PATCHES.md` beside this crate): one decode budget
//! shared by every stream decode in the process.
//!
//! Every decode of a stream's content, whichever public method asks for it
//! (`decompressed_content`, `decompressed_content_with_limit`,
//! `get_plain_content*`, `decompress*`, `ObjectStream::new*`,
//! `Document::get_page_content*`, `extract_text*`, and the object and xref
//! streams a load reads), runs through `Stream::decode_filters`, which asks
//! this module first.
//!
//! While a [`Scope`] is open, every decode on every thread draws from its
//! budget, so a stream decoded twice is charged twice:
//! - a decode may produce at most `min(per_decode, remaining)` bytes, and
//!   the caller's own limit if that is smaller. Each filter layer is capped
//!   while it decodes, as lopdf already does for a bounded decode;
//! - what a decode produced is charged. A decode that fails for any reason
//!   other than the limit is charged the stream's raw length, because that
//!   is what callers fall back to reading;
//! - once a decode is refused because the budget, not the caller's own
//!   limit, ran out, the scope is exhausted. Every later decode is refused
//!   and the scope's handler, if one is set, runs once.
//!
//! With no scope open, a decode with a limit behaves as upstream, and a
//! decode without one is refused. So no unbounded decode can happen in this
//! process, inside a scope or outside one.
//!
//! Scopes are serialised: [`Scope::enter`] waits for any open scope to
//! close. It is not re-entrant: a second `enter` on the thread that holds a
//! scope waits for itself. The budget is process-wide, so a decode on a
//! thread with no scope of its own is charged to whichever scope is open.
//!
//! A decode reserves its whole grant up front (`min(per_decode, remaining)`)
//! and gives back what it did not use. Under parallel decodes the unreserved
//! budget can reach zero while most of it is unused, which exhausts the
//! scope; callers fail closed. The parser opens one scope per phase, so a
//! document can draw up to twice the total across its phases.

use crate::{DecompressError, Error, Result};
use std::sync::{Mutex, MutexGuard, PoisonError};

struct State {
    open: bool,
    remaining: usize,
    per_decode: usize,
    charged: usize,
    exhausted: bool,
    on_exhausted: Option<fn()>,
}

impl State {
    const CLOSED: State = State {
        open: false,
        remaining: 0,
        per_decode: 0,
        charged: 0,
        exhausted: false,
        on_exhausted: None,
    };

    /// Mark the budget exhausted. Returns the handler to run, the first
    /// time only.
    fn exhaust(&mut self) -> Option<fn()> {
        self.remaining = 0;
        if self.exhausted {
            return None;
        }
        self.exhausted = true;
        self.on_exhausted.take()
    }
}

static STATE: Mutex<State> = Mutex::new(State::CLOSED);
static SERIAL: Mutex<()> = Mutex::new(());

fn state() -> MutexGuard<'static, State> {
    STATE.lock().unwrap_or_else(PoisonError::into_inner)
}

fn refused() -> Error {
    DecompressError::MemoryLimitExceeded { limit: 0 }.into()
}

/// An open decode budget. Dropping it closes the budget.
pub struct Scope {
    _serial: MutexGuard<'static, ()>,
}

impl Scope {
    /// Open a budget of `total` decoded bytes, at most `per_decode` of them
    /// from any one decode.
    pub fn enter(total: usize, per_decode: usize) -> Scope {
        let serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
        *state() = State {
            open: true,
            remaining: total,
            per_decode,
            ..State::CLOSED
        };
        Scope { _serial: serial }
    }

    /// Run `handler` once, on the thread whose decode exhausts the budget,
    /// before that decode returns.
    pub fn on_exhausted(self, handler: fn()) -> Scope {
        state().on_exhausted = Some(handler);
        self
    }

    /// Whether a decode was refused because the budget ran out.
    pub fn exhausted(&self) -> bool {
        state().exhausted
    }

    /// The decoded bytes charged so far.
    pub fn charged(&self) -> usize {
        state().charged
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        *state() = State::CLOSED;
    }
}

/// Holds the budget closed: no scope opens while it lives. A caller that
/// must decode with no budget open (to rely on the refusal of unbounded
/// decodes, say) takes it first.
pub struct Closed {
    _serial: MutexGuard<'static, ()>,
}

/// Wait for any open scope to close, and keep the budget closed while the
/// returned guard lives.
pub fn closed() -> Closed {
    Closed {
        _serial: SERIAL.lock().unwrap_or_else(PoisonError::into_inner),
    }
}

/// The part of the budget one decode may use.
pub(crate) struct Grant {
    limit: Option<usize>,
    /// The budget, not the caller, set `limit`.
    capped: bool,
    scoped: bool,
}

impl Grant {
    /// The limit the decode runs under.
    pub(crate) fn limit(&self) -> Option<usize> {
        self.limit
    }

    /// Charge what the decode produced and return the rest of the grant.
    pub(crate) fn settle(self, decoded: &Result<Vec<u8>>, raw_len: usize) {
        if !self.scoped {
            return;
        }
        let allowance = self.limit.unwrap_or(0);
        let (used, over) = match decoded {
            Ok(content) => (content.len(), false),
            Err(Error::Decompress(DecompressError::MemoryLimitExceeded { .. })) => (allowance, self.capped),
            Err(_) => (raw_len, false),
        };
        let handler = {
            let mut state = state();
            state.remaining += allowance - used.min(allowance);
            state.charged = state.charged.saturating_add(used);
            let extra = used.saturating_sub(allowance);
            if over || extra > state.remaining {
                state.exhaust()
            } else {
                state.remaining -= extra;
                None
            }
        };
        if let Some(handler) = handler {
            handler();
        }
    }
}

/// Reserve the budget for one decode the caller limits to `requested`
/// (`None`: no limit of its own).
pub(crate) fn reserve(requested: Option<usize>) -> Result<Grant> {
    let handler = {
        let mut state = state();
        if !state.open {
            return match requested {
                Some(_) => Ok(Grant {
                    limit: requested,
                    capped: false,
                    scoped: false,
                }),
                None => Err(refused()),
            };
        }
        if state.exhausted {
            return Err(refused());
        }
        let cap = state.per_decode.min(state.remaining);
        let capped = requested.is_none_or(|requested| cap < requested);
        let allowance = requested.map_or(cap, |requested| requested.min(cap));
        if allowance == 0 && capped {
            state.exhaust()
        } else {
            state.remaining -= allowance;
            return Ok(Grant {
                limit: Some(allowance),
                capped,
                scoped: true,
            });
        }
    };
    if let Some(handler) = handler {
        handler();
    }
    Err(refused())
}
