//! Event bus — a single channel for all async-to-sync boundary crossings.
//!
//! The event bus decouples the Rust domain layer from any particular consumer
//! (Tauri WebSocket server, native macOS FFI bridge, CLI harness, …). Every
//! "push" event (PTY output, transfer progress, connection status change) is
//! serialised into a `CoreEvent` and sent over a broadcast channel. A single
//! external callback (registered via `set_event_callback`) drains the channel
//! and dispatches to the native layer.
//!
//! This avoids a sprawling FFI surface where every event type needs its own
//! callback registration.
//!
//! # Thread Safety
//!
//! - `CoreEvent`: `Send + Sync`.
//! - The sender and receiver are behind `OnceLock` — safe to call from any
//!   thread.
//! - The broadcast channel has a fixed capacity (1024). If the consumer falls
//!   behind, the oldest events are dropped. This is intentional — PTY output
//!   and progress events are latency-sensitive, not reliability-sensitive.

#![allow(dead_code)]

use std::sync::OnceLock;

use tokio::sync::broadcast;

/// All event kinds that cross the async-to-sync boundary.
#[derive(Debug, Clone)]
pub enum CoreEvent {
    /// PTY output data for a connection.
    ///
    /// `generation` is the PTY-session counter the publisher captured at
    /// `start_pty_connection` time. Consumers (Swift native, future
    /// CLI harness) compare it against the latest generation they've
    /// seen to discard frames from a PTY session that has since been
    /// torn down and replaced — without it, the brief tail of in-flight
    /// output from an old session can spill into a new one.
    PtyOutput {
        connection_id: String,
        generation: u64,
        data: Vec<u8>,
    },
    /// A connection's status changed.
    ConnectionStatus {
        connection_id: String,
        status: ConnectionStatus,
    },
    /// File transfer progress.
    TransferProgress {
        connection_id: String,
        path: String,
        bytes_transferred: u64,
        total_bytes: u64,
    },
    /// One line from a streaming `tcpdump` capture. Stderr lines (e.g.
    /// libpcap startup banner) carry `is_stderr = true` so the UI can
    /// dim them.
    TcpdumpLine {
        capture_id: u64,
        line: String,
        is_stderr: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionStatus {
    Connected,
    Disconnected,
    Error { reason: &'static str },
}

// ---------------------------------------------------------------------------
// Singleton channel
// ---------------------------------------------------------------------------

const EVENT_CHANNEL_CAPACITY: usize = 1024;

static EVENT_TX: OnceLock<broadcast::Sender<CoreEvent>> = OnceLock::new();

/// Get a sender handle to the event bus. The channel is lazily created on
/// first call with a capacity of 1024 events.
pub fn event_sender() -> Option<broadcast::Sender<CoreEvent>> {
    let tx = EVENT_TX.get_or_init(|| {
        let (tx, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        tx
    });
    Some(tx.clone())
}

/// Subscribe to all events. Returns a receiver that starts with a `RecvError::Lagged`
/// for any events produced before this subscription.
pub fn subscribe() -> broadcast::Receiver<CoreEvent> {
    let tx = EVENT_TX.get_or_init(|| {
        let (tx, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        tx
    });
    tx.subscribe()
}

// ---------------------------------------------------------------------------
// Tests — uses a private channel to avoid interference from the global static
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::broadcast;

    #[test]
    fn event_bus_send_and_receive() {
        let (tx, mut rx) = broadcast::channel(16);
        tx.send(CoreEvent::ConnectionStatus {
            connection_id: "test-1".into(),
            status: ConnectionStatus::Connected,
        })
        .ok();

        let received = rx.try_recv().expect("should have event");
        match received {
            CoreEvent::ConnectionStatus {
                connection_id,
                status,
            } => {
                assert_eq!(connection_id, "test-1");
                assert_eq!(status, ConnectionStatus::Connected);
            }
            other => panic!("unexpected event: {:?}", other),
        }
    }

    #[test]
    fn multiple_subscribers_get_all_events() {
        let (tx, mut rx1) = broadcast::channel(16);
        let mut rx2 = tx.subscribe();

        tx.send(CoreEvent::PtyOutput {
            connection_id: "c1".into(),
            generation: 1,
            data: vec![1, 2, 3],
        })
        .ok();

        assert!(rx1.try_recv().is_ok());
        assert!(rx2.try_recv().is_ok());
    }
}
