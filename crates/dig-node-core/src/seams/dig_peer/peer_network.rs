//! Seam 2's public surface (#1285/#1303) — the DIG-peer connectivity operations the standalone
//! peer-network bring-up ([`crate::peer::spawn_peer_network`]) and the control surface
//! (`control.peerStatus`, DHT refresh) drive on [`Node`].
//!
//! `PeerNetwork` is implemented by [`Node`] with its EXISTING method bodies (carved unchanged
//! from `lib.rs`, #1285 W1b-2) — a behaviour-preserving trait extraction, not a new
//! implementation. `async_trait`-boxed (matching [`crate::shared::AnchoredRootResolver`] and
//! `crate::seams::content::ContentServer`) so it stays dyn-compatible for the future
//! `Arc<dyn PeerNetwork>` handle (W1c).
//!
//! The self-reference bring-up hooks (`set_self_ref`/`arc_self`, backing the capsule backfill
//! background task) are DELIBERATELY left OUT of this trait — the locked W1 plan (tangle b)
//! calls for them to become an `Arc<dyn CapsuleStore>` handle injection when seam 6 is carved
//! (W1b-4), not a peer-network concern. They stay on `Node`'s own inherent impl for now.

use std::sync::Arc;

use crate::peer::PeerStatus;
use crate::InventoryRefresher;
use crate::Node;

/// Seam 2 (DIG peer connectivity) — status/bring-up wiring the standalone peer-network task and
/// the control surface use. See the module doc for what is (and isn't) covered here in W1b-2.
#[async_trait::async_trait]
pub trait PeerNetwork: Send + Sync {
    /// The shared peer-network status (for the standalone `run` to hand to the peer-network task and
    /// for `control.peerStatus`).
    fn peer_status(&self) -> Arc<PeerStatus>;

    /// Install the DHT inventory-refresh hook (the standalone peer-network bring-up calls this once;
    /// the FFI path never does). Idempotent — a second install is ignored.
    fn set_inventory_refresher(&self, refresher: InventoryRefresher);

    /// Retain the live gossip pool handle (the standalone peer-network bring-up calls this once with
    /// the [`dig_gossip::GossipHandle`] it starts; the FFI path never does). Idempotent — a second
    /// install is ignored. Enables the control surface to dial peers + enumerate the connected pool.
    fn set_gossip_handle(&self, handle: dig_gossip::GossipHandle);

    /// The live gossip pool handle, if the peer network is running. `None` on the FFI path (no pool)
    /// and before bring-up — callers degrade honestly (empty peer list; "no peer network" on connect).
    fn gossip_handle(&self) -> Option<&dig_gossip::GossipHandle>;

    /// Refresh the node's DHT provider records against its current inventory, if a peer network is
    /// running (SPEC §14.1). A no-op on the FFI path (no hook installed) or before bring-up.
    async fn refresh_dht_inventory(&self);
}

#[async_trait::async_trait]
impl PeerNetwork for Node {
    fn peer_status(&self) -> Arc<PeerStatus> {
        self.peer_status.clone()
    }

    fn set_inventory_refresher(&self, refresher: InventoryRefresher) {
        let _ = self.inventory_refresher.set(refresher);
    }

    fn set_gossip_handle(&self, handle: dig_gossip::GossipHandle) {
        let _ = self.gossip.set(handle);
    }

    fn gossip_handle(&self) -> Option<&dig_gossip::GossipHandle> {
        self.gossip.get()
    }

    async fn refresh_dht_inventory(&self) {
        if let Some(refresh) = self.inventory_refresher.get() {
            refresh().await;
        }
    }
}
