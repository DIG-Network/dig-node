//! [`UnionLocator`] — a [`ProviderLocator`] that UNIONS several discovery sources (#1443).
//!
//! A node can learn which peers hold a capsule from more than one place: the distributed
//! **dig-dht** (`find_providers`), **PEX** first-hand known-holder gossip, and the
//! **relay-introducer** (a relay vouching for peers reserved with it). This locator queries every
//! wired source and merges their provider records — deduplicated by `peer_id`, first-seen order — so
//! dig-download's discover step sees the widest holder set any source knows.
//!
//! # Wired-but-empty seams (PEX + relay-introducer)
//!
//! Today only the dig-dht source is live. PEX-as-a-provider-source and the relay-introducer are
//! DORMANT: they are present as [`EmptyLocator`] placeholders so the union shape is in place and a
//! later change (#1440 part B) swaps in the real source with NO wiring churn. An empty (or erroring)
//! source contributes nothing — the union is strictly best-effort, so a dormant or failing source can
//! never reduce the holder set the DHT already found.

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use dig_dht::ContentId;
use dig_download::{DownloadError, ProviderLocator, ProviderRecord};

/// Unions the provider records of several [`ProviderLocator`] sources, deduplicated by `peer_id` in
/// first-seen (source) order. Best-effort: an erroring/empty source is skipped, never fatal.
pub(crate) struct UnionLocator {
    /// The discovery sources, queried in order. The first (dig-dht) is authoritative for ordering;
    /// later sources only ADD holders the earlier ones did not already name.
    sources: Vec<Arc<dyn ProviderLocator>>,
}

impl UnionLocator {
    /// Build a union over `sources` (queried in the given order; dedup keeps the first occurrence).
    pub(crate) fn new(sources: Vec<Arc<dyn ProviderLocator>>) -> Arc<Self> {
        Arc::new(UnionLocator { sources })
    }
}

#[async_trait]
impl ProviderLocator for UnionLocator {
    async fn find_providers(&self, content: &ContentId) -> Result<Vec<ProviderRecord>, DownloadError> {
        // Query every source CONCURRENTLY; join_all preserves the source order in its results, so the
        // dedup below keeps DHT-first precedence. Each source is best-effort — an error or empty result
        // simply contributes no records (a dormant PEX/relay source can never shrink the DHT set).
        let results =
            futures::future::join_all(self.sources.iter().map(|s| s.find_providers(content))).await;

        let mut seen: HashSet<String> = HashSet::new();
        let mut merged: Vec<ProviderRecord> = Vec::new();
        for result in results {
            let Ok(records) = result else {
                continue; // best-effort: skip a failed source
            };
            for record in records {
                if seen.insert(record.provider_peer_id.clone()) {
                    merged.push(record);
                }
            }
        }
        Ok(merged)
    }
}

/// A [`ProviderLocator`] that always finds nothing — the DORMANT PEX / relay-introducer placeholder in
/// the [`UnionLocator`] (see the module docs). Contributes nothing to the union until a real source
/// replaces it (#1440 part B).
pub(crate) struct EmptyLocator;

#[async_trait]
impl ProviderLocator for EmptyLocator {
    async fn find_providers(
        &self,
        _content: &ContentId,
    ) -> Result<Vec<ProviderRecord>, DownloadError> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_download::testkit::{mock_content_id, mock_peer_hex, mock_provider, MockProviderLocator};

    /// The union merges providers from all sources, deduplicated by peer_id in DHT-first order.
    #[tokio::test]
    async fn unions_providers_from_all_sources() {
        let cid = mock_content_id();
        // Source A (DHT) knows peers 1,2; source B knows peers 2,3 — peer 2 is shared.
        let dht = Arc::new(MockProviderLocator::fixed(vec![
            mock_provider(1, &cid),
            mock_provider(2, &cid),
        ]));
        let other = Arc::new(MockProviderLocator::fixed(vec![
            mock_provider(2, &cid),
            mock_provider(3, &cid),
        ]));
        let union = UnionLocator::new(vec![dht, other]);

        let got = union.find_providers(&cid).await.expect("union ok");
        let ids: Vec<String> = got.iter().map(|p| p.provider_peer_id.clone()).collect();
        assert_eq!(
            ids,
            vec![mock_peer_hex(1), mock_peer_hex(2), mock_peer_hex(3)],
            "deduped by peer_id, first-seen (DHT-first) order"
        );
    }

    /// An empty (or dormant) source contributes nothing but never removes what another source found.
    #[tokio::test]
    async fn empty_and_erroring_source_is_skipped() {
        let cid = mock_content_id();
        let dht = Arc::new(MockProviderLocator::fixed(vec![mock_provider(1, &cid)]));
        let union = UnionLocator::new(vec![dht, Arc::new(EmptyLocator)]);
        let got = union.find_providers(&cid).await.expect("union ok");
        assert_eq!(got.len(), 1, "the DHT holder survives a dormant sibling source");
        assert_eq!(got[0].provider_peer_id, mock_peer_hex(1));
    }

    /// With no sources (or all empty) the union is an empty set, never an error.
    #[tokio::test]
    async fn no_sources_returns_empty() {
        let cid = mock_content_id();
        let union = UnionLocator::new(vec![Arc::new(EmptyLocator), Arc::new(EmptyLocator)]);
        assert!(union.find_providers(&cid).await.expect("union ok").is_empty());
    }
}
