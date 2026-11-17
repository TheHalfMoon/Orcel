//! The gate's only notion of time: a monotonic millisecond count from an
//! injectable [`Clock`]. Nothing in this crate sleeps or runs a timer. Every
//! decision compares the instant it is asked at with the instants it
//! recorded, so a tick that comes late can never stretch the quiet period
//! (the donor's "deadlines end a lock, not timers" rule).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// A monotonic instant, in milliseconds since the clock's own origin.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Millis(pub u64);

impl Millis {
    /// `self + ms`, saturating at the top.
    #[must_use]
    pub const fn plus(self, ms: u64) -> Self {
        Self(self.0.saturating_add(ms))
    }

    /// Milliseconds from `earlier` to `self`; zero if `earlier` is later.
    #[must_use]
    pub const fn since(self, earlier: Self) -> u64 {
        self.0.saturating_sub(earlier.0)
    }
}

/// A source of monotonic instants.
pub trait Clock {
    /// The current instant.
    fn now(&self) -> Millis;
}

impl<C: Clock + ?Sized> Clock for &C {
    fn now(&self) -> Millis {
        (**self).now()
    }
}

/// The process's monotonic clock, counted from when this value was made.
#[derive(Clone, Copy, Debug)]
pub struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    /// A clock whose origin is now.
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Millis {
        let elapsed = self.origin.elapsed().as_millis();
        Millis(u64::try_from(elapsed).unwrap_or(u64::MAX))
    }
}

/// A clock that moves only when told to, for deterministic tests and
/// replays. Clones share one instant.
#[derive(Clone, Debug, Default)]
pub struct ManualClock {
    now: Arc<AtomicU64>,
}

impl ManualClock {
    /// A clock standing at `start` milliseconds.
    #[must_use]
    pub fn at(start: u64) -> Self {
        Self {
            now: Arc::new(AtomicU64::new(start)),
        }
    }

    /// Move the clock forward by `ms`.
    pub fn advance(&self, ms: u64) {
        let _ = self
            .now
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |now| {
                Some(now.saturating_add(ms))
            });
    }

    /// Set the clock to `ms`. A monotonic clock never goes back, so a
    /// smaller value is ignored.
    pub fn set(&self, ms: u64) {
        self.now.fetch_max(ms, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Millis {
        Millis(self.now.load(Ordering::SeqCst))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_clock_moves_only_forward_and_clones_share_it() {
        let clock = ManualClock::at(100);
        let other = clock.clone();
        clock.advance(50);
        assert_eq!(other.now(), Millis(150));
        clock.set(120);
        assert_eq!(
            clock.now(),
            Millis(150),
            "a monotonic clock never goes back"
        );
        clock.set(400);
        assert_eq!(other.now(), Millis(400));
    }

    #[test]
    fn millis_arithmetic_saturates() {
        assert_eq!(Millis(u64::MAX).plus(1), Millis(u64::MAX));
        assert_eq!(Millis(5).since(Millis(9)), 0);
        assert_eq!(Millis(9).since(Millis(5)), 4);
    }

    #[test]
    fn system_clock_is_monotonic() {
        let clock = SystemClock::new();
        let first = clock.now();
        let second = clock.now();
        assert!(second >= first);
    }
}
