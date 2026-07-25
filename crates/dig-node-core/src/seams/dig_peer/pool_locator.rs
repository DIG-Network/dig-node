//! [`PoolProviderLocator`] — offer the node's CONNECTED pool peers as content-fetch candidates
//! (#1590, the #836 read-leg blocker).
//!
//! # Why this exists
//!
//! On a relayed / isolated network a capsule holder is DISCOVERED via the DHT, but its advertised
//! provider record carries addresses the reader cannot dial (a direct `10.x` it never reaches). The
//! multi-source download's locate step then yields no REACHABLE source, so Tier-2 peer fetch
//! (`serve_content_plaintext` → `peer_serve_plaintext` → [`crate::download::NodeContent::fetch_resource`])
//! gives up and the read falls through to the §21 upstream whole-store backfill → 404 — even though
//! the reader is ALREADY CONNECTED to that holder in the gossip pool (run e2e-1062-20260725-043357:
//! CONNECT ✅ / ANNOUNCE ✅ / DISCOVER ✅ / DATA ❌).
//!
//! # What it does
//!
//! This locator offers EVERY currently-connected pool peer as a fetch candidate for ANY content id,
//! reachable over the connection the node already holds. dig-download's confirm step
//! (`dig.getAvailability` per candidate) filters the peers that do not hold the content, and the
//! whole-resource merkle check binds every served byte to the chain-anchored root — so offering a
//! connected NON-holder is safe (it answers not-available and is skipped) and a connected HOLDER the
//! DHT could not point us at reachably is finally reached. Bounded fan-out: the candidate set is the
//! gossip pool, which is capacity-bounded, so this can never fan a fetch across an unbounded set.
//!
//! It is unioned into the DOWNLOAD locator ONLY (never the engine's raw discovery locator that feeds
//! `find_providers` / the redirect-on-miss hint): a redirect must name genuine announced holders, not
//! every connected peer. The connected set is fed live from the gossip pool churn
//! ([`crate::download::NodeContent::on_pool_event`]).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use dig_dht::{CandidateAddr, ContentId, PeerId};
use dig_download::{DownloadError, ProviderLocator, ProviderRecord};

/// The shared live map of currently-connected pool peers → their observed connection addresses,
/// keyed by 64-hex `peer_id`. Owned by [`crate::download::NodeContent`] and updated on every pool
/// churn event; the locator reads it on each locate. `Arc<Mutex<…>>` (not an async lock) because the
/// map is tiny + touched at low rate (pool churn), never held across an `.await`.
pub(crate) type ConnectedPool = Arc<Mutex<HashMap<String, Vec<SocketAddr>>>>;

/// Offers the connected pool peers as fetch candidates for any content id (#1590). See the module
/// docs for the DHT-unreachable-holder gap it closes and why it is a DOWNLOAD-only source.
pub(crate) struct PoolProviderLocator {
    connected: ConnectedPool,
}

impl PoolProviderLocator {
    /// Wrap the shared connected-pool map as a download provider source.
    pub(crate) fn new(connected: ConnectedPool) -> Arc<Self> {
        Arc::new(PoolProviderLocator { connected })
    }
}

#[async_trait]
impl ProviderLocator for PoolProviderLocator {
    async fn find_providers(
        &self,
        content: &ContentId,
    ) -> Result<Vec<ProviderRecord>, DownloadError> {
        let key = content.to_key();
        let guard = self
            .connected
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let records = guard
            .iter()
            .filter_map(|(peer_hex, addrs)| {
                // A pool peer always has a transport-verified 64-hex identity; skip a malformed one
                // defensively rather than surface an error (best-effort — never break locate).
                let peer = PeerId::from_hex(peer_hex)?;
                let candidates = addrs
                    .iter()
                    .map(|a| CandidateAddr::direct(a.ip().to_string(), a.port()))
                    .collect();
                // `u64::MAX` expiry: a live pool entry is authoritative for as long as it is present;
                // staleness is governed by pool churn removing it, not a wall-clock TTL.
                Some(ProviderRecord::new(&key, &peer, candidates, u64::MAX))
            })
            .collect();
        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(entries: &[(u8, &str)]) -> ConnectedPool {
        let mut map = HashMap::new();
        for (n, addr) in entries {
            map.insert(
                PeerId::from_bytes([*n; 32]).to_hex(),
                vec![addr.parse::<SocketAddr>().unwrap()],
            );
        }
        Arc::new(Mutex::new(map))
    }

    /// Every connected pool peer is offered as a candidate for the requested content, keyed to that
    /// content and carrying the peer's connection address.
    #[tokio::test]
    async fn offers_every_connected_peer_for_the_requested_content() {
        let locator = PoolProviderLocator::new(pool(&[(1, "10.0.0.1:9444"), (2, "10.0.0.2:9444")]));
        let content = ContentId::resource([9; 32], [8; 32], [7; 32]);

        let found = locator.find_providers(&content).await.expect("locate ok");

        assert_eq!(found.len(), 2, "both connected peers offered");
        let key = content.to_key().to_hex();
        for record in &found {
            assert_eq!(record.content_key, key, "keyed to the requested content");
            assert!(!record.addresses.is_empty(), "carries a dial address");
        }
        let ids: std::collections::HashSet<String> =
            found.iter().map(|r| r.provider_peer_id.clone()).collect();
        assert!(ids.contains(&PeerId::from_bytes([1; 32]).to_hex()));
        assert!(ids.contains(&PeerId::from_bytes([2; 32]).to_hex()));
    }

    /// An empty pool offers nobody (a locate that never starves nor errors).
    #[tokio::test]
    async fn empty_pool_offers_no_candidates() {
        let locator = PoolProviderLocator::new(Arc::new(Mutex::new(HashMap::new())));
        let content = ContentId::capsule([1; 32], [2; 32]);
        assert!(locator
            .find_providers(&content)
            .await
            .expect("locate ok")
            .is_empty());
    }
}
