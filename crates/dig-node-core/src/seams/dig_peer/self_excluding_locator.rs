//! [`SelfExcludingLocator`] — drop THIS node's own `peer_id` from any discovered provider set (#1584).
//!
//! # Why this exists
//!
//! A reader must NEVER fetch content from itself. The authoritative guard is in dig-gossip, which now
//! refuses a self-`peer_id` on every pool-add path (inbound AND the two outbound paths a relay
//! introducer can reach), so the connected pool — and thus the selector's candidate registry — never
//! contains self. This locator is the belt-and-suspenders complement on the DISCOVERY leg: even if a
//! provider record naming this node's own `peer_id` reaches the download engine from some source (a
//! stale DHT `add_provider` record this node itself published, a future PEX / relay-introducer source,
//! a replayed announce), it is filtered out BEFORE the fetch dial — so the reader can never "discover"
//! itself, self-dial (Direct → own IP → connection refused; Relayed → refused self-dial), and dead-end
//! the read at HTTP 404 instead of fetching from the real holder.
//!
//! It wraps the innermost provider source so the exclusion applies to EVERY granularity (store /
//! capsule / resource) uniformly, including the non-resource pass-through in [`CapsuleFallbackLocator`]
//! layered above it. A node with no known `peer_id` (identity not yet resolved) filters nothing.

use std::sync::Arc;

use async_trait::async_trait;
use dig_dht::ContentId;
use dig_download::{DownloadError, ProviderLocator, ProviderRecord};

/// Drop every record in `records` whose `provider_peer_id` is `self_peer_id` — the ONE
/// implementation of "no source can ever offer self" (`SPEC.md` §19.3), shared by every source that
/// must honour it.
///
/// # Why this is a free function and not just the locator's body
///
/// The rule is stated of EVERY source, but the sources do not share a type. The DHT walk arrives as a
/// [`ProviderLocator`] and can be WRAPPED; the forwarded availability ask
/// ([`crate::download::NodeContent::locate_holders`]) arrives as a plain `Vec` returned by an
/// untrusted peer and cannot. Before dig-node#261 that difference had produced two hand-written
/// copies of the filter and one source with none — so a reader who checked the wrapped leg,
/// found the exclusion, and concluded the invariant held was reading a habit rather than an
/// invariant. Every caller now spends one line on the same function, which is the only shape in which
/// "some sources" cannot quietly become the truth again.
///
/// A node whose identity is not yet resolved (`None`) has nothing to exclude and filters nothing.
pub(crate) fn retain_excluding_self(records: &mut Vec<ProviderRecord>, self_peer_id: Option<&str>) {
    if let Some(me) = self_peer_id {
        records.retain(|record| record.provider_peer_id != me);
    }
}

/// Wraps an inner [`ProviderLocator`] and removes any provider record whose `provider_peer_id` equals
/// this node's own `self_peer_id` (hex, matching [`ProviderRecord::provider_peer_id`]). See the module
/// docs for why the reader must never be discovered as its own provider (#1584).
pub(crate) struct SelfExcludingLocator {
    inner: Arc<dyn ProviderLocator>,
    /// This node's own `peer_id` in hex, or `None` when the identity is not yet known (filter nothing).
    self_peer_id: Option<String>,
}

impl SelfExcludingLocator {
    /// Wrap `inner` so its results never include `self_peer_id`. When `self_peer_id` is `None` the
    /// wrapper is a transparent pass-through (nothing to exclude).
    pub(crate) fn new(inner: Arc<dyn ProviderLocator>, self_peer_id: Option<String>) -> Arc<Self> {
        Arc::new(SelfExcludingLocator {
            inner,
            self_peer_id,
        })
    }
}

#[async_trait]
impl ProviderLocator for SelfExcludingLocator {
    async fn find_providers(
        &self,
        content: &ContentId,
    ) -> Result<Vec<ProviderRecord>, DownloadError> {
        let mut records = self.inner.find_providers(content).await?;
        retain_excluding_self(&mut records, self.self_peer_id.as_deref());
        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_download::testkit::{
        mock_content_id, mock_peer_hex, mock_provider, MockProviderLocator,
    };

    /// #1584 regression: the reader's OWN `peer_id`, if it ever appears in a discovered provider set,
    /// is filtered out before the fetch dial — so the reader can never self-dial and dead-end the read.
    #[tokio::test]
    async fn self_peer_id_is_excluded_from_discovered_providers() {
        let cid = mock_content_id();
        // The DHT returns three holders: peer 1, peer 2 (== THIS node), peer 3.
        let inner = Arc::new(MockProviderLocator::fixed(vec![
            mock_provider(1, &cid),
            mock_provider(2, &cid),
            mock_provider(3, &cid),
        ]));
        let locator = SelfExcludingLocator::new(inner, Some(mock_peer_hex(2)));

        let got = locator.find_providers(&cid).await.expect("locate ok");
        let ids: Vec<String> = got.iter().map(|p| p.provider_peer_id.clone()).collect();
        assert_eq!(
            ids,
            vec![mock_peer_hex(1), mock_peer_hex(3)],
            "the node's own peer_id must be dropped; the real holders survive"
        );
    }

    /// A node whose identity is not yet known (`None`) filters nothing — every holder passes through.
    #[tokio::test]
    async fn unknown_self_identity_passes_every_provider_through() {
        let cid = mock_content_id();
        let inner = Arc::new(MockProviderLocator::fixed(vec![
            mock_provider(1, &cid),
            mock_provider(2, &cid),
        ]));
        let locator = SelfExcludingLocator::new(inner, None);
        assert_eq!(
            locator.find_providers(&cid).await.expect("locate ok").len(),
            2,
            "with no known self identity nothing is excluded"
        );
    }

    /// When THIS node is the ONLY discovered provider, the result is empty (never self) — the read then
    /// correctly falls through to the public-RPC tier instead of self-dialing.
    #[tokio::test]
    async fn self_only_provider_set_becomes_empty() {
        let cid = mock_content_id();
        let inner = Arc::new(MockProviderLocator::fixed(vec![mock_provider(7, &cid)]));
        let locator = SelfExcludingLocator::new(inner, Some(mock_peer_hex(7)));
        assert!(
            locator
                .find_providers(&cid)
                .await
                .expect("locate ok")
                .is_empty(),
            "a self-only provider set must resolve to empty, never a self-dial"
        );
    }
}
