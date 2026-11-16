//! Epoch-aware event cursors. A cursor names a position in one daemon run
//! (`epoch`), so it never carries over to another run, and a gap is rejected
//! before the cursor moves: the subscription then resubscribes from the
//! unmoved cursor, and orceld answers with a snapshot when it can no longer
//! serve it.

use crate::sanitize::rules;
use serde::Serialize;

/// The last event seen (or delivered) in one epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Cursor {
    epoch: String,
    after_seq: u64,
}

/// What an incoming event's position means for a cursor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Position {
    /// The next event of this epoch.
    Next,
    /// Already seen; dropped.
    Duplicate,
    /// Events were skipped; rejected, the cursor does not move.
    Gap { expected: u64, got: u64 },
    /// Another epoch: a daemon restart. Only a snapshot may carry one.
    OtherEpoch,
}

impl Cursor {
    /// A cursor from the web view's `{after_seq, epoch}`; `None` when the
    /// epoch is not in orceld's format.
    pub fn new(epoch: &str, after_seq: u64) -> Option<Self> {
        rules::epoch(epoch).map(|epoch| Self { epoch, after_seq })
    }

    pub fn epoch(&self) -> &str {
        &self.epoch
    }

    pub fn after_seq(&self) -> u64 {
        self.after_seq
    }

    /// Judges an event's position without moving.
    pub fn check(&self, epoch: &str, seq: u64) -> Position {
        if epoch != self.epoch {
            Position::OtherEpoch
        } else if seq <= self.after_seq {
            Position::Duplicate
        } else if seq == self.after_seq + 1 {
            Position::Next
        } else {
            Position::Gap {
                expected: self.after_seq + 1,
                got: seq,
            }
        }
    }

    /// Moves to `seq` only when it is [`Position::Next`]; returns what the
    /// position was, so a gap or another epoch leaves the cursor unmoved.
    pub fn advance(&mut self, epoch: &str, seq: u64) -> Position {
        let position = self.check(epoch, seq);
        if position == Position::Next {
            self.after_seq = seq;
        }
        position
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// orceld's `new_epoch`: `format!("{:x}-{:x}", pid, nanos)`.
    fn orceld_epoch(pid: u32, nanos: u128) -> String {
        format!("{:x}-{:x}", pid, nanos)
    }

    #[test]
    fn a_gap_is_rejected_before_the_cursor_moves() {
        let epoch = orceld_epoch(4242, 1_763_000_000_123_456_789);
        let mut cursor = Cursor::new(&epoch, 5).unwrap();
        assert_eq!(
            cursor.advance(&epoch, 8),
            Position::Gap {
                expected: 6,
                got: 8
            }
        );
        assert_eq!(cursor.after_seq(), 5);
        assert_eq!(cursor.advance(&epoch, 6), Position::Next);
        assert_eq!(cursor.after_seq(), 6);
        assert_eq!(cursor.advance(&epoch, 6), Position::Duplicate);
        assert_eq!(cursor.advance(&epoch, 3), Position::Duplicate);
        assert_eq!(cursor.after_seq(), 6);
    }

    #[test]
    fn another_epoch_never_moves_the_cursor() {
        let epoch = orceld_epoch(4242, 1);
        let restarted = orceld_epoch(4243, 2);
        let mut cursor = Cursor::new(&epoch, 9).unwrap();
        assert_eq!(cursor.advance(&restarted, 10), Position::OtherEpoch);
        assert_eq!(cursor.advance(&restarted, 1), Position::OtherEpoch);
        assert_eq!((cursor.epoch(), cursor.after_seq()), (epoch.as_str(), 9));
    }

    #[test]
    fn a_cursor_needs_an_epoch_in_orcelds_format() {
        assert!(Cursor::new(&orceld_epoch(u32::MAX, u128::MAX), 1).is_some());
        assert!(Cursor::new("", 1).is_none());
        assert!(Cursor::new("1a2b-17F", 1).is_none());
        assert!(Cursor::new("1a2b", 1).is_none());
    }
}
