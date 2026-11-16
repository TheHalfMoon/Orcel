//! Subscriptions: one live subscription per window, a bounded queue toward
//! the web view, and at most two of orceld's client slots per window (this
//! subscription and one serialized request).
//!
//! - **One per window.** [`Window::subscribe`] first ends the previous
//!   subscription (its orceld connection is closed, its thread joined and
//!   its [`Feed`] ended) and only then opens one connection.
//! - **Bounded queue.** At most [`QUEUE_FRAMES`] items wait for the web
//!   view. On overflow the queue is cleared, the orceld connection is
//!   closed, the web view receives [`StreamItem::Gap`], and once it has taken
//!   that marker the subscription resumes from the last cursor it delivered,
//!   so orceld answers with a snapshot when that cursor can no longer be
//!   served.
//! - **Cursors.** An event that skips ahead or carries another epoch is
//!   rejected before the cursor moves and the subscription resumes from the
//!   unmoved cursor. A snapshot whose epoch differs from the timeline's is
//!   preceded by [`StreamItem::Cleared`]: a new epoch clears the timeline.
//!   Heartbeats are consumed here.

use crate::client::AppApiClient;
use crate::cursor::{Cursor, Position};
use crate::error::ClientError;
use crate::frame::{self, FrameReader, Incoming};
use crate::identity::IdentityRefusal;
use crate::sanitize::events::{self, Event, EventBody};
use crate::transport::{Canceller, Conn};
use serde::Serialize;
use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// The most items waiting for the web view.
pub const QUEUE_FRAMES: usize = 256;
/// A subscription that sends nothing for this long (orceld heartbeats every
/// 15 seconds) is reopened.
const IDLE_TIMEOUT: Duration = Duration::from_secs(45);
/// How long to wait before opening the endpoint again after a failure.
const RETRY: Duration = Duration::from_secs(2);

/// One item for the web view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StreamItem {
    /// A sanitised event (a snapshot included).
    Event { event: Box<Event> },
    /// An event the sanitiser dropped (an unknown kind, say): "event
    /// withheld".
    Withheld,
    /// A new epoch: clear the timeline before the snapshot that follows.
    Cleared,
    /// The queue overflowed and was cleared; the missed events, or a
    /// snapshot, follow.
    Gap,
    /// orceld is unavailable; the subscription keeps trying.
    Unavailable { reason: String },
    /// "orceld could not be confirmed as yours"; nothing was written to it.
    NotYours {
        #[serde(skip)]
        refusal: IdentityRefusal,
    },
    /// orceld is not read-only: the window shows this and nothing else. The
    /// subscription ends.
    Incompatible,
}

/// What [`Feed::next`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Next {
    Item(StreamItem),
    /// Nothing within the wait.
    Idle,
    /// The subscription was ended (a newer one replaced it, or the window
    /// closed).
    Ended,
}

#[derive(Default)]
struct FeedState {
    items: VecDeque<(StreamItem, Option<Cursor>)>,
    /// The cursor of the last item the web view took.
    delivered: Option<Cursor>,
    /// A gap marker is queued and not yet taken.
    gap_pending: bool,
    cancelled: bool,
    ended: bool,
}

/// The queue between one subscription and the web view.
#[derive(Default)]
pub struct Feed {
    state: Mutex<FeedState>,
    changed: Condvar,
}

enum Pushed {
    Queued,
    Overflowed,
    Cancelled,
}

impl Feed {
    fn new(from: Option<Cursor>) -> Self {
        let feed = Self::default();
        feed.lock().delivered = from;
        feed
    }

    fn lock(&self) -> MutexGuard<'_, FeedState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The next item, waiting at most `timeout`.
    pub fn next(&self, timeout: Duration) -> Next {
        let deadline = Instant::now() + timeout;
        let mut state = self.lock();
        loop {
            if state.cancelled {
                return Next::Ended;
            }
            if let Some((item, position)) = state.items.pop_front() {
                if position.is_some() {
                    state.delivered = position;
                }
                if item == StreamItem::Gap {
                    state.gap_pending = false;
                }
                drop(state);
                self.changed.notify_all();
                return Next::Item(item);
            }
            if state.ended {
                return Next::Ended;
            }
            let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                return Next::Idle;
            };
            state = self
                .changed
                .wait_timeout(state, left)
                .map(|(guard, _)| guard)
                .unwrap_or_else(|poisoned| poisoned.into_inner().0);
        }
    }

    /// The cursor of the last event the web view took.
    pub fn delivered(&self) -> Option<Cursor> {
        self.lock().delivered.clone()
    }

    /// How many items wait.
    pub fn len(&self) -> usize {
        self.lock().items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether a gap marker waits to be taken (tests only).
    #[cfg(test)]
    pub(crate) fn overflowed(&self) -> bool {
        self.lock().gap_pending
    }

    fn push(&self, item: StreamItem, position: Option<Cursor>) -> Pushed {
        let mut state = self.lock();
        if state.cancelled {
            return Pushed::Cancelled;
        }
        let pushed = if state.items.len() >= QUEUE_FRAMES {
            state.items.clear();
            state.items.push_back((StreamItem::Gap, None));
            state.gap_pending = true;
            Pushed::Overflowed
        } else {
            state.items.push_back((item, position));
            Pushed::Queued
        };
        drop(state);
        self.changed.notify_all();
        pushed
    }

    fn cancelled(&self) -> bool {
        self.lock().cancelled
    }

    fn cancel(&self) {
        self.lock().cancelled = true;
        self.changed.notify_all();
    }

    fn end(&self) {
        self.lock().ended = true;
        self.changed.notify_all();
    }

    /// Waits until the web view took the gap marker; false when cancelled.
    fn wait_gap_taken(&self) -> bool {
        let mut state = self.lock();
        while state.gap_pending && !state.cancelled {
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        !state.cancelled
    }

    /// Sleeps for `duration` unless cancelled first; false when cancelled.
    fn sleep(&self, duration: Duration) -> bool {
        let deadline = Instant::now() + duration;
        let mut state = self.lock();
        while !state.cancelled {
            let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                return true;
            };
            state = self
                .changed
                .wait_timeout(state, left)
                .map(|(guard, _)| guard)
                .unwrap_or_else(|poisoned| poisoned.into_inner().0);
        }
        false
    }
}

/// How one subscription connection ended.
enum End {
    /// Resubscribe at once from the cursor (after a snapshot, a rejected
    /// gap, or orceld closing the stream).
    Resubscribe,
    /// Resubscribe after [`RETRY`]: the connection ended before any frame,
    /// or carried one that is not this protocol, so an immediate retry
    /// could spin against a misbehaving server.
    Retry,
    /// The queue overflowed.
    Overflow,
    Incompatible,
    Cancelled,
}

type CancelSlot = Arc<Mutex<Option<Canceller>>>;

struct Running {
    feed: Arc<Feed>,
    connection: CancelSlot,
    thread: Option<JoinHandle<()>>,
}

impl Running {
    /// Ends the subscription: its connection is closed and its thread
    /// joined before this returns.
    fn stop(mut self) {
        self.feed.cancel();
        let canceller = self
            .connection
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(canceller) = canceller {
            canceller.cancel();
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        self.feed.end();
    }
}

/// One window's use of orceld: requests through [`Window::client`] (one at a
/// time) and at most one live subscription.
pub struct Window {
    client: Arc<AppApiClient>,
    current: Mutex<Option<Running>>,
}

impl Window {
    pub fn new(client: Arc<AppApiClient>) -> Self {
        Self {
            client,
            current: Mutex::new(None),
        }
    }

    pub fn client(&self) -> &AppApiClient {
        &self.client
    }

    /// Ends any earlier subscription, then subscribes from `from` (the start
    /// of orceld's ring when `None`). The lock is held throughout, so two
    /// calls never hold two subscription connections.
    pub fn subscribe(&self, from: Option<Cursor>) -> Arc<Feed> {
        let mut current = self
            .current
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(running) = current.take() {
            running.stop();
        }
        let feed = Arc::new(Feed::new(from.clone()));
        let connection: CancelSlot = Arc::new(Mutex::new(None));
        let thread = {
            let client = Arc::clone(&self.client);
            let feed = Arc::clone(&feed);
            let connection = Arc::clone(&connection);
            std::thread::Builder::new()
                .name("orcel-app-api-subscription".into())
                .spawn(move || run(&client, &feed, &connection, from))
                .ok()
        };
        if thread.is_none() {
            feed.push(
                StreamItem::Unavailable {
                    reason: "the subscription thread could not start".into(),
                },
                None,
            );
            feed.end();
        }
        *current = Some(Running {
            feed: Arc::clone(&feed),
            connection,
            thread,
        });
        feed
    }

    /// Ends the live subscription, if any.
    pub fn unsubscribe(&self) {
        let running = self
            .current
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(running) = running {
            running.stop();
        }
    }
}

impl Drop for Window {
    fn drop(&mut self) {
        self.unsubscribe();
    }
}

fn set_canceller(slot: &CancelSlot, canceller: Option<Canceller>) {
    *slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = canceller;
}

/// The subscription thread.
fn run(client: &AppApiClient, feed: &Feed, slot: &CancelSlot, from: Option<Cursor>) {
    let mut cursor = from;
    let mut reported: Option<String> = None;
    loop {
        if feed.cancelled() {
            return;
        }
        let (mut conn, mut reader, ack) = match client.open_subscription(cursor.as_ref()) {
            Ok(opened) => opened,
            Err(error) => {
                let item = match error {
                    ClientError::NotYours(refusal) => StreamItem::NotYours { refusal },
                    ClientError::Incompatible => {
                        feed.push(StreamItem::Incompatible, None);
                        return;
                    }
                    error => StreamItem::Unavailable {
                        reason: error.to_string(),
                    },
                };
                // Reported once per outage, not on every retry.
                let key = format!("{item:?}");
                if reported.as_deref() != Some(key.as_str()) {
                    reported = Some(key);
                    if let Pushed::Cancelled = feed.push(item, None) {
                        return;
                    }
                }
                if !feed.sleep(RETRY) {
                    return;
                }
                continue;
            }
        };
        reported = None;
        match conn.canceller() {
            Ok(canceller) => set_canceller(slot, Some(canceller)),
            Err(_) => {
                if !feed.sleep(RETRY) {
                    return;
                }
                continue;
            }
        }
        // A cancel that came before the canceller was registered.
        if feed.cancelled() {
            return;
        }
        if conn.set_read_timeout(Some(IDLE_TIMEOUT)).is_err() {
            set_canceller(slot, None);
            continue;
        }
        let mut received = match cursor.take() {
            Some(cursor) => cursor,
            // From the start of the ring: the acknowledged epoch, before
            // its first event.
            None => match Cursor::new(&ack.epoch, 0) {
                Some(cursor) => cursor,
                None => return,
            },
        };
        let end = stream(&mut conn, &mut reader, &mut received, feed);
        set_canceller(slot, None);
        drop(conn);
        cursor = Some(received);
        match end {
            End::Resubscribe => {}
            End::Retry => {
                if !feed.sleep(RETRY) {
                    return;
                }
            }
            End::Overflow => {
                if !feed.wait_gap_taken() {
                    return;
                }
                cursor = feed.delivered();
            }
            End::Incompatible => {
                feed.push(StreamItem::Incompatible, None);
                return;
            }
            End::Cancelled => return,
        }
    }
}

/// Reads one subscription connection until it ends.
fn stream(
    conn: &mut Box<dyn Conn>,
    reader: &mut FrameReader,
    cursor: &mut Cursor,
    feed: &Feed,
) -> End {
    let push = |item: StreamItem, position: Option<Cursor>| match feed.push(item, position) {
        Pushed::Queued => None,
        Pushed::Overflowed => Some(End::Overflow),
        Pushed::Cancelled => Some(End::Cancelled),
    };
    let mut frames = 0usize;
    loop {
        let bytes = match reader.next(conn) {
            Ok(Some(bytes)) => bytes,
            // orceld closed the stream, the frame was over the bound, or the
            // connection failed: resubscribe from the cursor, unless this
            // subscription was ended.
            Ok(None) | Err(_) => {
                return if feed.cancelled() {
                    End::Cancelled
                } else if frames == 0 {
                    End::Retry
                } else {
                    End::Resubscribe
                };
            }
        };
        frames += 1;
        let value = match frame::parse(&bytes) {
            Ok(Incoming::Event(value)) => value,
            Ok(Incoming::Heartbeat) => continue,
            Ok(Incoming::Reply { .. }) | Err(_) => return End::Retry,
        };
        let Some((seq, epoch)) = events::position(&value) else {
            // No usable position: withheld. The next event is judged against
            // the unmoved cursor.
            if let Some(end) = push(StreamItem::Withheld, None) {
                return end;
            }
            continue;
        };
        let is_snapshot = value.get("kind").and_then(|kind| kind.as_str()) == Some("snapshot");
        if is_snapshot {
            let event = match events::sanitize(&value) {
                Ok(Some(event)) => event,
                Ok(None) => {
                    if let Some(end) = push(StreamItem::Withheld, None) {
                        return end;
                    }
                    return End::Resubscribe;
                }
                Err(_) => return End::Incompatible,
            };
            let EventBody::Snapshot { resubscribe, .. } = &event.body else {
                return End::Resubscribe;
            };
            let Some(next) = Cursor::new(&resubscribe.epoch, resubscribe.after_seq) else {
                return End::Resubscribe;
            };
            if next.epoch() != cursor.epoch() {
                if let Some(end) = push(StreamItem::Cleared, None) {
                    return end;
                }
            }
            if let Some(end) = push(
                StreamItem::Event {
                    event: Box::new(event),
                },
                Some(next.clone()),
            ) {
                return end;
            }
            *cursor = next;
            // orceld closes the connection after a snapshot.
            return End::Resubscribe;
        }
        match cursor.advance(&epoch, seq) {
            Position::Duplicate => continue,
            Position::Gap { .. } | Position::OtherEpoch => return End::Resubscribe,
            Position::Next => {}
        }
        let item = match events::sanitize(&value) {
            Ok(Some(event)) => StreamItem::Event {
                event: Box::new(event),
            },
            Ok(None) => StreamItem::Withheld,
            Err(_) => return End::Incompatible,
        };
        if let Some(end) = push(item, Some(cursor.clone())) {
            return end;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cursor(seq: u64) -> Option<Cursor> {
        Cursor::new("1a-2b", seq)
    }

    #[test]
    fn overflow_clears_the_queue_and_leaves_one_gap_marker() {
        let feed = Feed::new(None);
        for seq in 1..=QUEUE_FRAMES as u64 {
            assert!(matches!(
                feed.push(StreamItem::Withheld, cursor(seq)),
                Pushed::Queued
            ));
        }
        assert_eq!(feed.len(), QUEUE_FRAMES);
        assert!(matches!(
            feed.push(StreamItem::Withheld, cursor(257)),
            Pushed::Overflowed
        ));
        assert_eq!(feed.len(), 1);
        assert_eq!(feed.next(Duration::ZERO), Next::Item(StreamItem::Gap));
        assert!(feed.is_empty());
        // Nothing past the gap was delivered.
        assert_eq!(feed.delivered(), None);
    }

    #[test]
    fn the_delivered_cursor_moves_only_when_the_web_view_takes_an_item() {
        let feed = Feed::new(cursor(4));
        feed.push(StreamItem::Withheld, cursor(5));
        feed.push(StreamItem::Withheld, cursor(6));
        assert_eq!(feed.delivered(), cursor(4));
        feed.next(Duration::ZERO);
        assert_eq!(feed.delivered(), cursor(5));
    }

    #[test]
    fn a_gap_marker_holds_the_resubscription_until_it_is_taken() {
        let feed = Arc::new(Feed::new(None));
        for seq in 0..=QUEUE_FRAMES as u64 {
            feed.push(StreamItem::Withheld, cursor(seq));
        }
        let waiter = {
            let feed = Arc::clone(&feed);
            std::thread::spawn(move || feed.wait_gap_taken())
        };
        std::thread::sleep(Duration::from_millis(50));
        assert!(!waiter.is_finished());
        assert_eq!(feed.next(Duration::ZERO), Next::Item(StreamItem::Gap));
        assert!(waiter.join().unwrap());
    }

    #[test]
    fn a_cancelled_feed_ends() {
        let feed = Feed::new(None);
        feed.push(StreamItem::Withheld, None);
        feed.cancel();
        assert_eq!(feed.next(Duration::ZERO), Next::Ended);
        assert!(matches!(
            feed.push(StreamItem::Withheld, None),
            Pushed::Cancelled
        ));
        assert!(!feed.sleep(Duration::from_secs(5)));
        assert!(!feed.wait_gap_taken());
    }
}
