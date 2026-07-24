//! [`CapsuleFallbackLocator`] — bridge a RESOURCE-granularity locate to the CAPSULE record that is
//! actually announced (#1580).
//!
//! # Why this exists
//!
//! Holders announce their inventory into the DHT at STORE and CAPSULE (`store_id:root`) granularity
//! ONLY — resource granularity is deliberately NOT announced ([`super::dht::inventory_content_ids`]):
//! a capsule holder serves EVERY resource inside it, so a per-resource provider record would be
//! redundant with the capsule record and would explode the DHT write volume.
//!
//! But a `/s` resource read miss (`serve_content_plaintext` → `peer_serve_plaintext` →
//! [`crate::download::miss_content_for`]) builds a [`ContentId::Resource`] and hands it to
//! dig-download, whose discover step locates providers by that EXACT resource key. Since no holder
//! ever announced the resource key, the locate found NOBODY — so Tier-2 peer fetch gave up even
//! though `find_providers` at capsule granularity would have returned the holder. The read then fell
//! through to the whole-store §21 backfill / public RPC and 404'd (#1580, the #836 read-leg blocker).
//!
//! # What it does
//!
//! This locator wraps the real provider source. On a [`ContentId::Resource`] lookup it ALSO queries
//! the parent [`ContentId::capsule`]`(store_id, root)` — the granularity that IS announced — and
//! unions the two holder sets (deduped by `peer_id`, resource-key hits first). A capsule holder found
//! this way holds the resource, so dig-download's next step (`dig.getAvailability` for the resource,
//! then `dig.fetchRange`) confirms + fetches it from that peer. Non-resource lookups pass straight
//! through unchanged. Best-effort throughout: an error from either query never removes what the other
//! found.

use std::sync::Arc;

use async_trait::async_trait;
use dig_dht::ContentId;
use dig_download::{DownloadError, ProviderLocator, ProviderRecord};

/// Wraps an inner [`ProviderLocator`] so a RESOURCE lookup also resolves the announced parent CAPSULE
/// record (#1580). See the module docs for the announce-vs-locate granularity mismatch it repairs.
pub(crate) struct CapsuleFallbackLocator {
    inner: Arc<dyn ProviderLocator>,
}

impl CapsuleFallbackLocator {
    /// Wrap `inner` with the resource→capsule fallback.
    pub(crate) fn new(inner: Arc<dyn ProviderLocator>) -> Arc<Self> {
        Arc::new(CapsuleFallbackLocator { inner })
    }
}

#[async_trait]
impl ProviderLocator for CapsuleFallbackLocator {
    async fn find_providers(
        &self,
        content: &ContentId,
    ) -> Result<Vec<ProviderRecord>, DownloadError> {
        // Non-resource lookups (store / capsule) name a granularity that IS announced — pass through.
        let ContentId::Resource { store_id, root, .. } = content else {
            return self.inner.find_providers(content).await;
        };

        // Resource granularity is never announced (see the module docs): query BOTH the resource key
        // (forward-compatible if a future writer DOES announce it) and the parent capsule key (the one
        // holders actually announce today), then union the holders. Resource-key hits keep precedence.
        let capsule = ContentId::capsule(*store_id, *root);
        let by_resource = self.inner.find_providers(content).await.unwrap_or_default();
        let by_capsule = self
            .inner
            .find_providers(&capsule)
            .await
            .unwrap_or_default();

        let mut merged: Vec<ProviderRecord> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for record in by_resource.into_iter().chain(by_capsule) {
            if seen.insert(record.provider_peer_id.clone()) {
                merged.push(record);
            }
        }
        Ok(merged)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_dht::{CandidateAddr, PeerId};
    use std::sync::Mutex;

    /// A locator that answers a FIXED provider set ONLY for the exact `ContentId` it was primed with —
    /// modelling a real DHT where a holder announced ONE granularity. Records every content id queried.
    struct GranularityLocator {
        answers_for: ContentId,
        providers: Vec<ProviderRecord>,
        queried: Mutex<Vec<ContentId>>,
    }

    #[async_trait]
    impl ProviderLocator for GranularityLocator {
        async fn find_providers(
            &self,
            content: &ContentId,
        ) -> Result<Vec<ProviderRecord>, DownloadError> {
            self.queried.lock().unwrap().push(content.clone());
            if content == &self.answers_for {
                Ok(self.providers.clone())
            } else {
                Ok(Vec::new())
            }
        }
    }

    fn holder(n: u8, content: &ContentId) -> ProviderRecord {
        ProviderRecord::new(
            &content.to_key(),
            &PeerId::from_bytes([n; 32]),
            vec![CandidateAddr::direct(format!("10.0.0.{n}"), 9444)],
            u64::MAX,
        )
    }

    /// #1580 regression: a RESOURCE lookup finds the holder that announced only the CAPSULE record.
    /// Without the fallback, `find_providers(resource)` returned empty and Tier-2 peer fetch gave up
    /// (DATA 404 despite a discoverable holder).
    #[tokio::test]
    async fn resource_lookup_falls_back_to_the_announced_capsule_holder() {
        let store = [9u8; 32];
        let root = [8u8; 32];
        let rk = [7u8; 32];
        let resource = ContentId::resource(store, root, rk);
        let capsule = ContentId::capsule(store, root);

        // The holder announced ONLY at capsule granularity (as real inventory does).
        let inner = Arc::new(GranularityLocator {
            answers_for: capsule.clone(),
            providers: vec![holder(1, &capsule)],
            queried: Mutex::new(Vec::new()),
        });
        let locator = CapsuleFallbackLocator::new(inner.clone());

        let found = locator.find_providers(&resource).await.expect("locate ok");

        assert_eq!(
            found.len(),
            1,
            "the capsule holder must be found for a resource-granularity lookup"
        );
        assert_eq!(
            found[0].provider_peer_id,
            PeerId::from_bytes([1; 32]).to_hex()
        );
        // The fallback actually queried the parent capsule id (not only the resource id).
        assert!(
            inner.queried.lock().unwrap().contains(&capsule),
            "the fallback must query the announced parent capsule id"
        );
    }

    /// A resource holder found at BOTH granularities is not double-counted; resource-key hits keep
    /// precedence, capsule-only holders are added.
    #[tokio::test]
    async fn resource_and_capsule_holders_union_without_duplicates() {
        let store = [1u8; 32];
        let root = [2u8; 32];
        let resource = ContentId::resource(store, root, [3u8; 32]);
        let capsule = ContentId::capsule(store, root);

        // Answers BOTH ids: peer 1 for the resource key, peers 1 (dup) + 2 for the capsule key.
        struct BothLocator {
            resource: ContentId,
            capsule: ContentId,
        }
        #[async_trait]
        impl ProviderLocator for BothLocator {
            async fn find_providers(
                &self,
                content: &ContentId,
            ) -> Result<Vec<ProviderRecord>, DownloadError> {
                if content == &self.resource {
                    Ok(vec![holder(1, content)])
                } else if content == &self.capsule {
                    Ok(vec![holder(1, content), holder(2, content)])
                } else {
                    Ok(Vec::new())
                }
            }
        }
        let locator = CapsuleFallbackLocator::new(Arc::new(BothLocator {
            resource: resource.clone(),
            capsule,
        }));

        let found = locator.find_providers(&resource).await.expect("locate ok");
        let ids: Vec<String> = found.iter().map(|p| p.provider_peer_id.clone()).collect();
        assert_eq!(
            ids,
            vec![
                PeerId::from_bytes([1; 32]).to_hex(),
                PeerId::from_bytes([2; 32]).to_hex()
            ],
            "deduped by peer_id, resource-hit first then capsule-only holders"
        );
    }

    /// A non-resource (capsule) lookup passes straight through — no extra fallback query.
    #[tokio::test]
    async fn capsule_lookup_passes_through_unchanged() {
        let store = [4u8; 32];
        let root = [5u8; 32];
        let capsule = ContentId::capsule(store, root);
        let inner = Arc::new(GranularityLocator {
            answers_for: capsule.clone(),
            providers: vec![holder(3, &capsule)],
            queried: Mutex::new(Vec::new()),
        });
        let locator = CapsuleFallbackLocator::new(inner.clone());

        let found = locator.find_providers(&capsule).await.expect("locate ok");
        assert_eq!(found.len(), 1);
        assert_eq!(
            inner.queried.lock().unwrap().as_slice(),
            &[capsule],
            "a capsule lookup queries exactly once (no resource→capsule fan-out)"
        );
    }
}
