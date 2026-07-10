//! The `SyncEvent` stream (design **A.9**, #205 PR4).
//!
//! Sage streams `SyncEvent`s to its desktop UI as Tauri events, not HTTP; clients that only
//! have Sage's `endpoints.json` HTTP surface poll `get_sync_status` instead (design A.9: "MAY
//! expose an equivalent (SSE / WebSocket / poll)... not required for extension parity").
//! This module is that equivalent: an in-process [`EventBus`] the direct-peer sync loop
//! ([`crate::sage::sync`]) publishes to, exposed over the shared transport (design C.3) as a
//! Server-Sent-Events stream at `GET /events` (see [`crate::sage::transport`]) — so clients
//! that want push updates get them, while `get_sync_status` polling keeps working unchanged.
//!
//! [`SyncEvent`]'s variants and wire shape mirror Sage's `events.rs` (`#[serde(tag = "type",
//! rename_all = "snake_case")]`): `start`, `stop`, `subscribed`, `derivation`, `coin_state`,
//! `transaction_failed`, `puzzle_batch_synced`, `cat_info`, `did_info`, `nft_data`.

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

/// A sync-lifecycle event, byte-parity with Sage's `events.rs` wire shape (design A.9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SyncEvent {
    /// A peer connection started syncing.
    Start {
        /// The peer's IP address (empty if unknown).
        ip: String,
    },
    /// The sync loop stopped (peer disconnected / shutdown).
    Stop,
    /// The wallet's puzzle hashes were subscribed on a peer.
    Subscribed,
    /// A new HD derivation was generated.
    Derivation,
    /// A coin-state update was applied to the wallet DB.
    CoinState,
    /// A transaction failed to broadcast.
    TransactionFailed {
        /// The transaction id (hex).
        transaction_id: String,
        /// The failure reason, if known.
        error: Option<String>,
    },
    /// A batch of subscribed puzzle hashes finished its initial catch-up.
    PuzzleBatchSynced,
    /// CAT metadata was resolved/updated.
    CatInfo,
    /// DID metadata was resolved/updated.
    DidInfo,
    /// NFT off-chain data was resolved/updated.
    NftData,
}

/// The default channel capacity: generous enough that a slow SSE consumer does not miss a
/// burst of sync events under normal operation; a consumer that falls further behind than
/// this sees `RecvError::Lagged` (handled by the SSE bridge, see `sage::transport`) rather
/// than blocking the publisher.
const DEFAULT_CAPACITY: usize = 256;

/// An in-process publish/subscribe bus for [`SyncEvent`]s. Cheap to clone (an `Arc`-backed
/// `broadcast::Sender` under the hood); every subscriber gets every event published after it
/// subscribed. Publishing when there are no subscribers is a harmless no-op (broadcast's
/// `send` only errors when the channel has zero receivers, which this bus ignores — nothing
/// depends on delivery, this is a best-effort push channel; `get_sync_status` is the
/// authoritative poll-based source of truth).
#[derive(Clone)]
pub struct EventBus {
    tx: broadcast::Sender<SyncEvent>,
}

impl EventBus {
    /// A bus with the given channel capacity (events buffered per-subscriber before older
    /// ones are dropped for a lagging subscriber).
    pub fn with_capacity(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity.max(1));
        Self { tx }
    }

    /// Publish `event` to every current subscriber. A no-op if nobody is listening.
    pub fn publish(&self, event: SyncEvent) {
        let _ = self.tx.send(event);
    }

    /// Subscribe to future events (does not replay history).
    pub fn subscribe(&self) -> broadcast::Receiver<SyncEvent> {
        self.tx.subscribe()
    }

    /// The number of current subscribers (test/diagnostic helper).
    pub fn subscriber_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Proves:** the wire shape matches Sage's tagged-union convention — `type` +
    /// snake_case variant names, with the payload fields flattened alongside `type`.
    #[test]
    fn wire_shape_matches_sage_tagged_union() {
        assert_eq!(
            serde_json::to_string(&SyncEvent::Start {
                ip: "1.2.3.4".into()
            })
            .unwrap(),
            r#"{"type":"start","ip":"1.2.3.4"}"#
        );
        assert_eq!(
            serde_json::to_string(&SyncEvent::Stop).unwrap(),
            r#"{"type":"stop"}"#
        );
        assert_eq!(
            serde_json::to_string(&SyncEvent::PuzzleBatchSynced).unwrap(),
            r#"{"type":"puzzle_batch_synced"}"#
        );
        assert_eq!(
            serde_json::to_string(&SyncEvent::TransactionFailed {
                transaction_id: "abc".into(),
                error: None,
            })
            .unwrap(),
            r#"{"type":"transaction_failed","transaction_id":"abc","error":null}"#
        );
    }

    /// **Proves:** a published event reaches every subscriber that subscribed BEFORE the
    /// publish (basic fan-out).
    #[tokio::test]
    async fn published_event_reaches_all_subscribers() {
        let bus = EventBus::with_capacity(8);
        let mut a = bus.subscribe();
        let mut b = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 2);

        bus.publish(SyncEvent::Subscribed);

        assert_eq!(a.recv().await.unwrap(), SyncEvent::Subscribed);
        assert_eq!(b.recv().await.unwrap(), SyncEvent::Subscribed);
    }

    /// **Proves:** publishing with zero subscribers does not error/panic — a best-effort
    /// push channel with no listener is a harmless no-op.
    #[test]
    fn publish_with_no_subscribers_is_a_noop() {
        let bus = EventBus::default();
        bus.publish(SyncEvent::Stop); // must not panic
        assert_eq!(bus.subscriber_count(), 0);
    }

    /// **Proves:** a subscriber only sees events published AFTER it subscribed (no replay of
    /// history) — matches a live push-stream's expected semantics.
    #[tokio::test]
    async fn subscriber_does_not_see_history() {
        let bus = EventBus::with_capacity(8);
        bus.publish(SyncEvent::Stop); // before anyone subscribes
        let mut rx = bus.subscribe();
        bus.publish(SyncEvent::Subscribed);
        assert_eq!(rx.recv().await.unwrap(), SyncEvent::Subscribed);
    }
}
