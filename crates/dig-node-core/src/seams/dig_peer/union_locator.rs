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
//!
//! # Untrusted address hints — no dial amplification (#1490)
//!
//! An advertised address in a provider record (from dig-dht `find_providers`, and the future PEX /
//! relay-introducer sources) is an UNTRUSTED HINT: any producer can put ANY address on a record, so a
//! record is NEVER authenticated by its address. The authenticated identity is the `peer_id`
//! (`= SHA-256(SPKI DER)`), enforced by the SPKI cert-pin at CONNECT — a wrong/spoofed address simply
//! fails the pinned dial, and no impostor is ever accepted. To stop a hostile source from turning one
//! record into a dial storm, this locator DEDUPES and CAPS the advertised addresses of every merged
//! record at [`MAX_ADDRS_PER_PROVIDER`] before it is handed downstream — so the reach-hint set a
//! consumer (the fetch dial, a redirect) ever sees is bounded regardless of what a source advertised.

use std::sync::Arc;

use async_trait::async_trait;
use dig_dht::ContentId;
use dig_download::{DownloadError, ProviderLocator, ProviderRecord};

/// The maximum advertised addresses kept per provider record after dedup (#1490). Addresses are
/// untrusted reach-hints authenticated only by the SPKI pin at connect; capping the set bounds the
/// dial fan-out a single (possibly hostile) provider record can trigger. IPv6-first order is preserved
/// (records from `ProviderRecord::new` arrive already sorted), so the cap keeps the most-preferred
/// hints.
const MAX_ADDRS_PER_PROVIDER: usize = 8;

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
    async fn find_providers(
        &self,
        content: &ContentId,
    ) -> Result<Vec<ProviderRecord>, DownloadError> {
        // Query every source CONCURRENTLY; join_all preserves the source order in its results, so the
        // dedup below keeps DHT-first precedence. Each source is best-effort — an error or empty result
        // simply contributes no records (a dormant PEX/relay source can never shrink the DHT set).
        let results =
            futures::future::join_all(self.sources.iter().map(|s| s.find_providers(content))).await;

        // Tier-2 ground-truth tracing (#1590/#836): per-source output counts for the queried content
        // id, so an e2e run shows WHICH source (pool vs DHT/capsule-fallback) offered the holder — the
        // decisive fact the prior misdiagnoses lacked.
        let per_source: Vec<usize> = results
            .iter()
            .map(|r| r.as_ref().map(Vec::len).unwrap_or(0))
            .collect();

        let mut index_of: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        let mut merged: Vec<ProviderRecord> = Vec::new();
        for result in results {
            let Ok(records) = result else {
                continue; // best-effort: skip a failed source
            };
            for record in records {
                match index_of.get(&record.provider_peer_id).copied() {
                    // #1590/#836: the SAME authenticated peer_id named by a later source (e.g. the
                    // connected-pool locator) carries an ADDITIONAL reach hint for that peer — MERGE it
                    // into the first-seen record rather than discarding the whole record. The peer_id is
                    // the authenticated identity (SPKI-pinned at connect); its addresses are untrusted
                    // hints, so unioning them across sources is safe. Dropping the later record instead
                    // (the prior behaviour) let an earlier source's UNREACHABLE hint (a stale DHT provider
                    // record) SHADOW a later source's REACHABLE one (the live pool connection) for the
                    // same peer, so the fetch dialed only the unreachable address and the read 404'd
                    // despite a connected, dialable holder (arbiter e2e c0954369). First-seen record
                    // ORDER is preserved (dig-dht stays authoritative for ordering).
                    Some(i) => {
                        let existing: &mut ProviderRecord = &mut merged[i];
                        existing.addresses.extend(record.addresses);
                        // #1490: re-dedup + re-cap the combined hint set so merging can never let a
                        // provider's advertised addresses grow past the dial-amplification bound.
                        sanitize_address_hints(existing);
                    }
                    None => {
                        let mut record = record;
                        // #1490: the advertised addresses are untrusted hints — dedup + cap them so a
                        // hostile record can never fan a single provider into a dial storm.
                        sanitize_address_hints(&mut record);
                        index_of.insert(record.provider_peer_id.clone(), merged.len());
                        merged.push(record);
                    }
                }
            }
        }
        tracing::debug!(
            content = %content.to_key().to_hex(),
            per_source = ?per_source,
            merged = merged.len(),
            "union_locator: merged provider sources"
        );
        Ok(merged)
    }
}

/// Dedup (order-preserving) and CAP a provider record's advertised addresses at
/// [`MAX_ADDRS_PER_PROVIDER`] (#1490). The addresses are untrusted reach-hints — the SPKI pin at
/// connect is what authenticates the peer — so bounding the set stops dial amplification without
/// affecting correctness (a real holder is reachable at its most-preferred, IPv6-first hints, which
/// the cap keeps). Dedup is O(n²) over a tiny list; `CandidateAddr` is `Eq` but not `Hash`.
fn sanitize_address_hints(record: &mut ProviderRecord) {
    let mut kept: Vec<dig_dht::CandidateAddr> = Vec::with_capacity(MAX_ADDRS_PER_PROVIDER);
    for addr in record.addresses.drain(..) {
        if kept.len() >= MAX_ADDRS_PER_PROVIDER {
            break;
        }
        if !kept.contains(&addr) {
            kept.push(addr);
        }
    }
    record.addresses = kept;
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
    use dig_download::testkit::{
        mock_content_id, mock_peer_hex, mock_provider, MockProviderLocator,
    };

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
        assert_eq!(
            got.len(),
            1,
            "the DHT holder survives a dormant sibling source"
        );
        assert_eq!(got[0].provider_peer_id, mock_peer_hex(1));
    }

    /// With no sources (or all empty) the union is an empty set, never an error.
    #[tokio::test]
    async fn no_sources_returns_empty() {
        let cid = mock_content_id();
        let union = UnionLocator::new(vec![Arc::new(EmptyLocator), Arc::new(EmptyLocator)]);
        assert!(union
            .find_providers(&cid)
            .await
            .expect("union ok")
            .is_empty());
    }

    /// #1590/#836: when two sources name the SAME peer_id with DIFFERENT addresses, the union MERGES
    /// their address hints into one record (deduped by peer_id) rather than dropping the later record —
    /// so a reachable hint from a later source (the connected pool) is never shadowed by an earlier
    /// source's unreachable hint (a stale DHT provider record) for the same authenticated peer.
    #[tokio::test]
    async fn same_peer_across_sources_merges_address_hints() {
        use dig_dht::CandidateAddr;
        let cid = mock_content_id();
        // Source A (DHT) names peer 1 at an unreachable address; source B (pool) names the SAME peer 1
        // at a reachable address.
        let dht_hint = ProviderRecord {
            content_key: cid.to_key().to_hex(),
            provider_peer_id: mock_peer_hex(1),
            addresses: vec![CandidateAddr::direct("10.9.9.9", 1)],
            expires_at: u64::MAX,
        };
        let pool_hint = ProviderRecord {
            content_key: cid.to_key().to_hex(),
            provider_peer_id: mock_peer_hex(1),
            addresses: vec![CandidateAddr::direct("10.0.0.1", 9444)],
            expires_at: u64::MAX,
        };
        let dht = Arc::new(MockProviderLocator::fixed(vec![dht_hint]));
        let pool = Arc::new(MockProviderLocator::fixed(vec![pool_hint]));
        let union = UnionLocator::new(vec![dht, pool]);

        let got = union.find_providers(&cid).await.expect("union ok");
        assert_eq!(got.len(), 1, "the same peer is one record, not two");
        let hosts: Vec<(&str, u16)> = got[0]
            .addresses
            .iter()
            .map(|a| (a.host.as_str(), a.port))
            .collect();
        assert!(
            hosts.contains(&("10.0.0.1", 9444)),
            "the later source's reachable hint survives the merge (got {hosts:?})"
        );
        assert!(
            hosts.contains(&("10.9.9.9", 1)),
            "the earlier source's hint is kept too (both are dial candidates)"
        );
        // ORDER is load-bearing: the FIRST-seen source's addresses lead the merged list, so they win
        // `best_address()` (the first dialable candidate) on the real single-address dial path. The
        // download union relies on this by querying the connection-verified POOL source first (#836).
        assert_eq!(
            hosts.first().copied(),
            Some(("10.9.9.9", 1)),
            "the first-seen source's address leads the merged list (best_address ordering, #836)"
        );
    }

    /// #1490: a provider record advertising many (untrusted) addresses — even duplicates — is capped
    /// and deduped at ingest, so a hostile source cannot fan one record into a dial storm. The record
    /// is built via a struct literal (bypassing `ProviderRecord::new`'s own cap, exactly as a
    /// wire-deserialized record would) so the union's OWN defensive cap is what is under test.
    #[tokio::test]
    async fn provider_address_hints_are_capped_and_deduped() {
        use dig_dht::CandidateAddr;
        let cid = mock_content_id();
        // 30 distinct addresses + 5 duplicates of the first — 35 advertised in total.
        let mut addresses: Vec<CandidateAddr> = (0..30)
            .map(|i| CandidateAddr::direct(format!("10.0.{i}.1"), 9444))
            .collect();
        for _ in 0..5 {
            addresses.push(CandidateAddr::direct("10.0.0.1", 9444));
        }
        let bloated = ProviderRecord {
            content_key: cid.to_key().to_hex(),
            provider_peer_id: mock_peer_hex(1),
            addresses,
            expires_at: u64::MAX,
        };
        let src = Arc::new(MockProviderLocator::fixed(vec![bloated]));
        let union = UnionLocator::new(vec![src]);

        let got = union.find_providers(&cid).await.expect("union ok");
        assert_eq!(got.len(), 1);
        assert!(
            got[0].addresses.len() <= super::MAX_ADDRS_PER_PROVIDER,
            "advertised address hints capped at {} (got {})",
            super::MAX_ADDRS_PER_PROVIDER,
            got[0].addresses.len()
        );
        // No duplicate survived the dedup.
        let mut seen = std::collections::HashSet::new();
        for a in &got[0].addresses {
            assert!(
                seen.insert(format!("{}:{}", a.host, a.port)),
                "no duplicate address hint survives ingest"
            );
        }
    }
}
