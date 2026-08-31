//! Acting on a peer's mirror-coin claim (dig-node#466).
//!
//! A holder may attach a mirror-coin id to its provider record — the field dig-dht names
//! `unverified_mirror_coin_id`, and the name is the whole point: any peer can publish any 32 bytes,
//! at no cost, bonding nothing. Until this module existed nothing anywhere read that field against a
//! chain, so the collateral economy's one economic guarantee was unenforced end to end.
//!
//! # What lives here, and what deliberately does not
//!
//! This module owns the **decision**: a three-state verdict, and what a holder set does with it. It
//! owns no chain access at all. The chain read — fetching the coin, re-deriving it from its creating
//! spend, and putting the declared triple through `MirrorCoin::advertises` — belongs to whoever
//! implements [`MirrorBondVerifier`], because only the host binary has a chain source. The seam is
//! what keeps `dig-node-core` free of the whole chia dependency set.
//!
//! # Three states, never two
//!
//! [`BondVerdict`] keeps *the chain said no* apart from *this node could not look*, the same
//! discipline `absence_established` holds on the discovery wire. Collapsing them is how a partitioned
//! node starts punishing honest peers: a chain outage, an epoch rollover and a deliberate lie all
//! look identical at the moment of reading, and only one of them is an attack.
//!
//! # The verdict REORDERS; it never refuses
//!
//! [`BondRankingLocator`] sorts a located holder set — proven bonds first, unprovable ones next,
//! disproven ones last — and **drops nothing**. Refusing a holder would turn every one of those
//! indistinguishable causes into a failed read, and absence of a pointer is the ordinary case today:
//! an older publisher, a publisher that has not created its coin, and one mid-epoch-rollover all
//! legitimately omit it. Ranking is the smallest thing that is genuinely an action — a lying
//! publisher is served last on every read, and an honest one that cannot prove itself loses nothing.

use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
pub use dig_dht::ContentId;
use dig_dht::ProviderRecord;
use dig_download::{DownloadError, ProviderLocator};

/// What a chain had to say about one holder's claimed bond.
///
/// The ordering of the variants is the ranking: `Bonded` before `Unverified` before `Unbonded`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BondVerdict {
    /// A chain answered, and the coin the holder named binds this exact `(store, root, epoch)` —
    /// declared tuple and recomputed hint both, with the owner taken from the coin's own lineage
    /// proof.
    Bonded,

    /// Nothing could be established. The holder named no coin, the chain could not be reached, or a
    /// figure the check depends on is not known to this node yet.
    ///
    /// **Not a soft failure.** It is the honest state of a claim nobody looked at, and it is the
    /// majority state of the network today.
    Unverified,

    /// A chain answered and the claim is false: no such coin, a coin that is not a mirror coin, or a
    /// mirror coin bonding some other store, root, owner or epoch.
    Unbonded,
}

/// Reads a holder's claimed mirror coin against a chain.
///
/// `claimed_coin_id` is attacker-supplied and may be absent, wrong, stale, or a real coin bonding
/// something else entirely; an implementation owes it exactly one chain lookup and no retry loop.
///
/// The parameter is an `Option` rather than a requirement so an implementation that can establish a
/// holder's owner puzzle hash by some other route may fall back to `dig-mirror-coin`'s hint scan
/// without a change to this seam.
#[async_trait]
pub trait MirrorBondVerifier: Send + Sync {
    /// Whether `claimed_coin_id` bonds `content` for the current collateral epoch.
    async fn verify(&self, content: &ContentId, claimed_coin_id: Option<[u8; 32]>) -> BondVerdict;
}

/// The verifier handle a [`BondRankingLocator`] reads, set once by the host binary after bring-up.
///
/// Shared rather than owned because the locator chain is assembled while the node is still starting
/// and the chain source does not exist yet. Until it is set the locator is a pass-through, which is
/// exactly the shipped behaviour of every embedder that has no chain — the in-process browser node,
/// and every test that does not care.
pub type BondVerifierSlot = Arc<OnceLock<Arc<dyn MirrorBondVerifier>>>;

/// A fresh, unset verifier slot.
pub fn bond_verifier_slot() -> BondVerifierSlot {
    Arc::new(OnceLock::new())
}

/// The outermost provider-locator layer: verifies each located holder's claimed bond and ranks the
/// set by the answer.
///
/// Wrapping the locator rather than the download executor is what puts the verdict on **every**
/// production consumer of a provider record at once — the multi-source fetch, the redirect-on-miss
/// hint, and the capsule warm all draw from the same chain.
pub struct BondRankingLocator {
    inner: Arc<dyn ProviderLocator>,
    verifier: BondVerifierSlot,
}

impl BondRankingLocator {
    /// Wrap `inner`, ranking with whatever verifier `verifier` eventually holds.
    pub fn new(inner: Arc<dyn ProviderLocator>, verifier: BondVerifierSlot) -> Arc<Self> {
        Arc::new(BondRankingLocator { inner, verifier })
    }
}

#[async_trait]
impl ProviderLocator for BondRankingLocator {
    async fn find_providers(
        &self,
        content: &ContentId,
    ) -> Result<Vec<ProviderRecord>, DownloadError> {
        let found = self.inner.find_providers(content).await?;

        let Some(verifier) = self.verifier.get() else {
            return Ok(found);
        };

        // Verdicts are collected before sorting so each holder is read exactly once. Sorting with an
        // async comparator is not expressible anyway, but the reason to want it here is the reason
        // not to: a comparison-driven lookup would read the same coin O(n log n) times.
        let mut ranked: Vec<(BondVerdict, ProviderRecord)> = Vec::with_capacity(found.len());
        for record in found {
            let verdict = verifier
                .verify(content, record.unverified_mirror_coin_id_bytes())
                .await;
            if verdict == BondVerdict::Unbonded {
                // Worth an operator's attention and nobody's ban list: this is a holder whose own
                // pointer disproves its own claim.
                tracing::debug!(
                    peer = %record.provider_peer_id,
                    "located holder's claimed mirror coin does not bond this content; ranked last"
                );
            }
            ranked.push((verdict, record));
        }

        // STABLE, so holders sharing a verdict keep the order their source gave them. The download
        // union deliberately puts connection-verified pool addresses first (#836); a ranking that
        // reshuffled within a class would quietly undo that.
        ranked.sort_by_key(|(verdict, _)| *verdict);

        Ok(ranked.into_iter().map(|(_, record)| record).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_dht::{CandidateAddr, PeerId};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const STORE: [u8; 32] = [0x11; 32];
    const ROOT: [u8; 32] = [0x22; 32];

    fn capsule() -> ContentId {
        ContentId::capsule(STORE, ROOT)
    }

    /// A holder record for `peer`, carrying `coin` as its claimed bond.
    fn holder(peer: u8, coin: Option<[u8; 32]>) -> ProviderRecord {
        let record = ProviderRecord::new(
            &capsule().to_key(),
            &PeerId::from_bytes([peer; 32]),
            vec![CandidateAddr::direct("::1", 9444)],
            u64::MAX,
        );
        match coin {
            Some(id) => record.with_unverified_mirror_coin_id(id),
            None => record,
        }
    }

    fn peer_ids(records: &[ProviderRecord]) -> Vec<String> {
        records
            .iter()
            .map(|r| r.provider_peer_id[..2].to_string())
            .collect()
    }

    /// A locator that answers with a fixed slate, so a test controls the ORDER the ranking is given.
    struct Slate(Vec<ProviderRecord>);

    #[async_trait]
    impl ProviderLocator for Slate {
        async fn find_providers(
            &self,
            _content: &ContentId,
        ) -> Result<Vec<ProviderRecord>, DownloadError> {
            Ok(self.0.clone())
        }
    }

    /// A verifier driven by the claimed coin id's FIRST byte, counting every chain-facing call.
    ///
    /// Keyed on the coin id rather than on the peer so a test cannot accidentally assert a property
    /// of the peer ordering while believing it asserted one about the bond.
    struct ByCoinByte {
        verdicts: Vec<(u8, BondVerdict)>,
        absent: BondVerdict,
        calls: AtomicUsize,
    }

    impl ByCoinByte {
        fn new(verdicts: &[(u8, BondVerdict)]) -> Arc<Self> {
            Arc::new(ByCoinByte {
                verdicts: verdicts.to_vec(),
                absent: BondVerdict::Unverified,
                calls: AtomicUsize::new(0),
            })
        }
    }

    #[async_trait]
    impl MirrorBondVerifier for ByCoinByte {
        async fn verify(&self, _content: &ContentId, claimed: Option<[u8; 32]>) -> BondVerdict {
            let Some(coin) = claimed else {
                return self.absent;
            };
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.verdicts
                .iter()
                .find(|(byte, _)| *byte == coin[0])
                .map(|(_, verdict)| *verdict)
                .unwrap_or(BondVerdict::Unverified)
        }
    }

    fn installed(verifier: Arc<dyn MirrorBondVerifier>) -> BondVerifierSlot {
        let slot = bond_verifier_slot();
        let _ = slot.set(verifier);
        slot
    }

    /// **Proves:** a holder whose named coin does not bond the content is ranked LAST, and is still
    /// offered.
    ///
    /// **Catches:** the two opposite wrong answers at once. A no-op ranking leaves the input order,
    /// and a refusing one returns two records instead of three. The input order is chosen so that
    /// neither the identity permutation NOR its reverse is the expected answer — a fixture ordered
    /// `[liar, unverified, honest]` would be satisfied by a ranking that merely reversed the slate
    /// and never read a verdict at all.
    #[tokio::test]
    async fn a_holder_whose_coin_does_not_bond_the_content_is_ranked_last_and_never_dropped() {
        let slate = Slate(vec![
            holder(0xAA, None),             // nothing claimed  -> Unverified
            holder(0xBB, Some([0x02; 32])), // claims a coin bonding something else
            holder(0xCC, Some([0x01; 32])), // claims a coin that really bonds this
        ]);
        let verifier = ByCoinByte::new(&[
            (0x01, BondVerdict::Bonded),
            (0x02, BondVerdict::Unbonded),
        ]);
        let locator = BondRankingLocator::new(Arc::new(slate), installed(verifier));

        let got = locator.find_providers(&capsule()).await.expect("located");

        assert_eq!(
            peer_ids(&got),
            vec!["cc", "aa", "bb"],
            "bonded first, unprovable next, disproven last"
        );
        assert_eq!(got.len(), 3, "a disproven claim is demoted, never refused");
    }

    /// **Proves:** holders sharing a verdict keep the relative order their source gave them.
    ///
    /// **Catches:** an unstable sort silently reshuffling the download union's deliberate
    /// pool-address-first ordering (#836) — a regression invisible to any test that only ever puts
    /// one holder in each verdict class.
    #[tokio::test]
    async fn holders_sharing_a_verdict_keep_the_order_their_source_gave_them() {
        let slate = Slate(vec![
            holder(0xAA, Some([0x01; 32])),
            holder(0xBB, Some([0x01; 32])),
            holder(0xCC, Some([0x02; 32])),
            holder(0xDD, Some([0x01; 32])),
        ]);
        let verifier = ByCoinByte::new(&[
            (0x01, BondVerdict::Bonded),
            (0x02, BondVerdict::Unbonded),
        ]);
        let locator = BondRankingLocator::new(Arc::new(slate), installed(verifier));

        let got = locator.find_providers(&capsule()).await.expect("located");

        assert_eq!(peer_ids(&got), vec!["aa", "bb", "dd", "cc"]);
    }

    /// **Proves:** a holder that names no coin costs ZERO chain reads and keeps its position.
    ///
    /// **Catches:** treating absence as something to look up — a lookup of a null coin id answers
    /// "no such coin", which is `Unbonded`, which would demote every publisher that has not created
    /// its coin yet. Asserting the ORDER alone cannot see that: absence and a genuine miss would
    /// both sort last together when every holder lacks a pointer. The call COUNT is what makes the
    /// distinction observable.
    #[tokio::test]
    async fn an_absent_pointer_costs_no_chain_read_and_does_not_move_the_holder() {
        let slate = Slate(vec![
            holder(0xAA, None),
            holder(0xBB, Some([0x01; 32])),
            holder(0xCC, None),
        ]);
        let verifier = ByCoinByte::new(&[(0x01, BondVerdict::Bonded)]);
        let locator = BondRankingLocator::new(Arc::new(slate), installed(verifier.clone()));

        let got = locator.find_providers(&capsule()).await.expect("located");

        assert_eq!(
            peer_ids(&got),
            vec!["bb", "aa", "cc"],
            "the two pointerless holders stay unverified, in their original order"
        );
        assert_eq!(
            verifier.calls.load(Ordering::SeqCst),
            1,
            "only the holder that named a coin is looked up"
        );
    }

    /// **Proves:** a chain this node cannot reach yields `Unverified`, so nobody is demoted — while
    /// the SAME slate with a reachable chain does demote the liar.
    ///
    /// **Catches:** collapsing "could not look" into "looked and found nothing", which makes a
    /// partitioned node rank every honest peer below a peer that claims nothing. The two halves are
    /// one test on purpose: the partitioned half alone is satisfied by a ranking that does nothing
    /// whatsoever, and the reachable half is the truthful control that proves the machinery was
    /// live. Only ONE thing varies between them — whether the chain answers.
    #[tokio::test]
    async fn an_unreachable_chain_is_unverified_not_unbonded() {
        let slate = || {
            Slate(vec![
                holder(0xCC, Some([0x02; 32])), // lies
                holder(0xAA, Some([0x01; 32])), // honest bond
                holder(0xBB, None),             // claims nothing
            ])
        };

        let partitioned = Arc::new(ByCoinByte {
            verdicts: vec![
                (0x01, BondVerdict::Unverified),
                (0x02, BondVerdict::Unverified),
            ],
            absent: BondVerdict::Unverified,
            calls: AtomicUsize::new(0),
        });
        let got = BondRankingLocator::new(Arc::new(slate()), installed(partitioned))
            .find_providers(&capsule())
            .await
            .expect("located");
        assert_eq!(
            peer_ids(&got),
            vec!["cc", "aa", "bb"],
            "an outage demotes nobody -- the slate is returned exactly as located, liar included"
        );

        let reachable = ByCoinByte::new(&[
            (0x01, BondVerdict::Bonded),
            (0x02, BondVerdict::Unbonded),
        ]);
        let got = BondRankingLocator::new(Arc::new(slate()), installed(reachable))
            .find_providers(&capsule())
            .await
            .expect("located");
        assert_eq!(
            peer_ids(&got),
            vec!["aa", "bb", "cc"],
            "control: the SAME slate, reached by a live chain, moves the liar to last"
        );
    }

    /// **Proves:** with no verifier installed the slate passes through untouched.
    ///
    /// **Catches:** an embedder without a chain source — the in-process browser node — silently
    /// having its holder order changed by a layer that cannot possibly have an opinion.
    #[tokio::test]
    async fn an_uninstalled_verifier_leaves_the_slate_exactly_as_found() {
        let slate = Slate(vec![
            holder(0xCC, Some([0x02; 32])),
            holder(0xAA, None),
            holder(0xBB, Some([0x01; 32])),
        ]);
        let locator = BondRankingLocator::new(Arc::new(slate), bond_verifier_slot());

        let got = locator.find_providers(&capsule()).await.expect("located");

        assert_eq!(peer_ids(&got), vec!["cc", "aa", "bb"]);
    }

    /// **Proves:** a locate FAILURE stays a failure and is never rewritten into an empty slate.
    ///
    /// **Catches:** the dig-node#273 class one layer up — a wrapper that swallows the inner error
    /// would let this node assert a proven absence for content it merely could not look up.
    #[tokio::test]
    async fn a_failed_locate_is_not_turned_into_an_empty_one() {
        struct Broken;

        #[async_trait]
        impl ProviderLocator for Broken {
            async fn find_providers(
                &self,
                _content: &ContentId,
            ) -> Result<Vec<ProviderRecord>, DownloadError> {
                Err(DownloadError::State("the walk failed".into()))
            }
        }

        let verifier = ByCoinByte::new(&[]);
        let locator = BondRankingLocator::new(Arc::new(Broken), installed(verifier));

        assert!(locator.find_providers(&capsule()).await.is_err());
    }
}
