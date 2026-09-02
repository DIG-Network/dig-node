//! Acting on a peer's mirror-coin claim (dig-node#466).
//!
//! A holder may attach a mirror-coin id to its provider record — the field dig-dht names
//! `unverified_mirror_coin_id`, and the name is the whole point: any peer can publish any 32 bytes,
//! at no cost, bonding nothing. Until this module existed nothing anywhere read that field against a
//! chain, so the collateral economy's one economic guarantee was unenforced end to end.
//!
//! # This layer is LIVE, and what makes promotion sound
//!
//! Promotion requires TWO independent bindings, and neither is sufficient alone.
//!
//! 1. **coin -> content**, from `MirrorCoin::advertises`: the coin declares exactly this
//!    `(store, root, epoch)`, with the hint recomputed from the coin's own lineage proof.
//! 2. **coin -> peer id**, from the coin's owner-written `dig-peer:` declaration
//!    (`dig-mirror-coin` 0.8.0, its `SPEC.md` §5.1). Memos are written by the spend that creates the
//!    coin and only the owner's key can produce that spend, so the term is an owner attestation
//!    carried by executed on-chain code.
//!
//! Without (2), promotion is itself an attack: coin ids travel the DHT in cleartext by design, so a
//! stranger republishing an honest holder's id would rank first at zero collateral. That is why this
//! module shipped inert until dig-node#473 supplied the declaration.
//!
//! # The binding this module does NOT make, and who does
//!
//! (2) binds a coin to a `peer_id`. It does **not** bind that `peer_id` to the addresses beside it
//! in the provider record, and no chain read can: a provider record is unsigned, and dig-dht says so
//! outright. A record carrying an honest holder's peer id, that holder's real coin id, and an
//! ATTACKER's addresses therefore satisfies everything above and IS promoted here.
//!
//! It is refused one layer down, by the transport, which pins the claimed `peer_id` against the
//! certificate the far end actually presents — `dig-download`'s `provider_peer_id` becomes the
//! `PeerTarget` pin, enforced in `dig-tls`'s verifier as `peer_id mismatch: expected …, got …`, with
//! `dig-peer` re-checking it after connect. So the attacker buys a failed handshake, not a served
//! byte, and the content is merkle-verified against the caller's own requested root regardless.
//!
//! What this layer owes in return is a BOUND: at most one record is promoted per claimed peer id, so
//! a single stolen identity cannot occupy every promoted slot. See `SPEC.md` §25.6a.
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
//! # The verdict gives CREDIT; it never takes it away
//!
//! [`BondRankingLocator`] promotes a proven bond and leaves everything else exactly where its source
//! put it. There are two tiers, not three: `Bonded` and *baseline*, where baseline holds an absent
//! pointer, an unprovable one and a disproven one together.
//!
//! That collapse is deliberate and it is a security property, not a simplification. A provider record
//! is hearsay -- the peer that answers a lookup chooses every field of it, including the coin id it
//! attributes to somebody else. If a disproven pointer ranked a holder BELOW where no pointer would
//! have put it, attaching a bogus coin id to an honest holder's record would be a way to demote that
//! holder, and a lookup answer would become a demotion primitive available to any stranger for free.
//! Withholding credit cannot be abused that way: the worst a liar achieves is the ranking that would
//! have existed had it said nothing at all.
//!
//! Nothing is ever dropped, for the reason it was never dropped before: absence of a pointer is the
//! ordinary case today, and a chain outage, an epoch rollover and a deliberate lie are
//! indistinguishable at the moment of reading.
//!
//! # A locate is bounded work
//!
//! Verification is chain I/O, and a stranger answering one lookup chooses how many records the slate
//! carries. At most [`MAX_VERIFIED_PER_LOCATE`] records are verified per locate, in source order;
//! the rest keep their place at baseline. Promotion is a bonus, so declining to compute it for the
//! tail costs a holder nothing it was owed — but note that where a caller later TRUNCATES the ranked
//! slate, a denied promotion can become a denied disclosure. Skipping is never a demotion; it can
//! still be a credit-denial, and a budget sized to the truncation point is what keeps the two apart.
//!
//! "Costs nothing" is about I/O, not about zero work: a locate still allocates per record and sorts
//! the slate. What it does not do while inert is read the chain or the disk, or change any order.

use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
// The seam's own vocabulary is re-exported, so an implementer of [`MirrorBondVerifier`] -- or a
// test of the ranking -- needs no direct dependency on the discovery and download crates to name
// the types this trait already speaks in.
pub use dig_dht::{CandidateAddr, ContentId, PeerId, ProviderRecord};
pub use dig_download::{DownloadError, ProviderLocator};

/// What a chain had to say about one holder's claimed bond.
///
/// The variants are NOT a ranking. Only [`BondVerdict::Bonded`] earns promotion; the other two form
/// one baseline tier (see the module docs for why a disproven claim must not sink a holder). The
/// three states stay distinct because they mean different things to an operator reading a log, not
/// because they sort.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BondVerdict {
    /// A chain answered, the coin the holder named binds this exact `(store, root, epoch)` —
    /// declared tuple and recomputed hint both, with the owner taken from the coin's own lineage
    /// proof — **and that coin declares the peer claiming it**.
    ///
    /// The second half is not optional. A coin id is a public fact: whoever answers a lookup can
    /// attribute an honest holder's real coin to any record it likes, including one carrying its own
    /// addresses. Without the coin naming the claimant, `Bonded` would mean only "some coin bonds
    /// this content", which a stranger can say truthfully while pointing the record at itself.
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
/// `claimed_coin_id` AND the claiming `peer_id` are both attacker-supplied: the coin id may be
/// absent, wrong, stale, or a real coin bonding something else entirely, and the peer id may name a
/// holder that never published this record. An implementation owes the pair exactly one chain lookup
/// and no retry loop.
///
/// The parameter is an `Option` rather than a requirement so an implementation that can establish a
/// holder's owner puzzle hash by some other route may fall back to `dig-mirror-coin`'s hint scan
/// without a change to this seam.
#[async_trait]
pub trait MirrorBondVerifier: Send + Sync {
    /// Whether `claimed_coin_id` bonds `content` for the current collateral epoch **on behalf of
    /// `claiming_peer_id`**.
    ///
    /// Both arguments come off the same untrusted record and neither implies the other. An
    /// implementation that ignores `claiming_peer_id` answers a strictly weaker question — "does
    /// some coin bond this content" — which a stranger republishing an honest holder's coin id
    /// passes.
    async fn verify(
        &self,
        content: &ContentId,
        claiming_peer_id: &str,
        claimed_coin_id: Option<[u8; 32]>,
    ) -> BondVerdict;
}

/// The verifier handle a [`BondRankingLocator`] reads, set once by the host binary after bring-up.
///
/// Shared rather than owned because the locator chain is assembled while the node is still starting
/// and the chain source does not exist yet. Until it is set the locator is a pass-through, which is
/// exactly the shipped behaviour of every embedder that has no chain — the in-process browser node,
/// and every test that does not care.
pub type BondVerifierSlot = Arc<OnceLock<Arc<dyn MirrorBondVerifier>>>;

/// The most records whose bond is read against a chain during one locate.
///
/// A slate's size is chosen by whoever answered the lookup, and each verification is a blocking
/// chain read drawn on the budget the discovery path is sized for. Small on purpose: promotion only
/// has to reach the holders a download would try first.
pub const MAX_VERIFIED_PER_LOCATE: usize = 8;

/// Promotion tier for a verdict — `Bonded` first, everything else in one baseline tier.
fn credit_rank(verdict: BondVerdict) -> u8 {
    match verdict {
        BondVerdict::Bonded => 0,
        BondVerdict::Unverified | BondVerdict::Unbonded => 1,
    }
}

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

        // Verdicts are collected before sorting so each holder is read at most once. Sorting with an
        // async comparator is not expressible anyway, but the reason to want it here is the reason
        // not to: a comparison-driven lookup would read the same coin O(n log n) times.
        let mut ranked: Vec<(u8, ProviderRecord)> = Vec::with_capacity(found.len());
        let mut verified = 0usize;
        let mut promoted_peers: std::collections::HashSet<String> = std::collections::HashSet::new();
        for record in found {
            let claimed = record.unverified_mirror_coin_id_bytes();
            // A holder that claims nothing, and every record past the budget, keeps its place with
            // no chain read at all. Both belong at baseline, which is where they already are.
            if claimed.is_none() || verified == MAX_VERIFIED_PER_LOCATE {
                ranked.push((credit_rank(BondVerdict::Unverified), record));
                continue;
            }
            verified += 1;
            let verdict = verifier
                .verify(content, &record.provider_peer_id, claimed)
                .await;
            let mut rank = credit_rank(verdict);
            // At most ONE record is promoted per claimed peer id. A coin declares one peer and a
            // peer needs its own collateralised coin, so promotion is meant to cost collateral --
            // but nothing stops a stranger republishing one honest holder's peer id and coin id
            // across the whole slate with addresses of its choosing. Each copy satisfies the
            // declaration check on the strength of the same single bond, and without this the
            // budget's worth of promoted slots could all be spent on one stolen identity.
            //
            // This is a BOUND, not a punishment: a duplicate falls back to the baseline tier it
            // would have occupied with no verifier at all, never below it, so the lattice stays
            // credit-only. It also costs an honest holder nothing -- a peer that legitimately
            // announces twice keeps its first record promoted.
            if rank == credit_rank(BondVerdict::Bonded)
                && !promoted_peers.insert(record.provider_peer_id.clone())
            {
                rank = credit_rank(BondVerdict::Unverified);
            }
            if verdict == BondVerdict::Unbonded {
                // Worth an operator's attention and nobody's ban list: this record's own pointer
                // disproves its own claim. Logged and NOT demoted — the record may be a stranger's
                // lie ABOUT an honest holder, and demoting on it is what would make that lie pay.
                tracing::debug!(
                    peer = %record.provider_peer_id,
                    "located holder's claimed mirror coin does not bond this content; no promotion"
                );
            }
            ranked.push((rank, record));
        }

        // STABLE, so holders sharing a tier keep the order their source gave them. The download
        // union deliberately puts connection-verified pool addresses first (#836); a ranking that
        // reshuffled within a tier would quietly undo that.
        ranked.sort_by_key(|(rank, _)| *rank);

        Ok(ranked.into_iter().map(|(_, record)| record).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_dht::{CandidateAddr, PeerId};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

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
        async fn verify(
            &self,
            _content: &ContentId,
            _claiming_peer_id: &str,
            claimed: Option<[u8; 32]>,
        ) -> BondVerdict {
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

    /// A chain in which exactly one coin exists, it bonds this content, and its memo declares
    /// exactly one peer — the binding `dig-mirror-coin` 0.8.0's typed accessor will expose.
    ///
    /// This is the shape of the REAL guarantee, so a test built on it cannot pass by giving the
    /// layer a weaker question than production asks. It also records every `(peer, coin)` pair it
    /// was asked about, which is how a test proves the claiming peer id actually reached the chain
    /// side rather than being dropped on the way.
    struct CoinDeclaringOnePeer {
        coin_first_byte: u8,
        declared_peer_prefix: String,
        asked: Mutex<Vec<(String, u8)>>,
    }

    impl CoinDeclaringOnePeer {
        fn new(coin_first_byte: u8, declared_peer: u8) -> Arc<Self> {
            Arc::new(CoinDeclaringOnePeer {
                coin_first_byte,
                declared_peer_prefix: PeerId::from_bytes([declared_peer; 32]).to_hex(),
                asked: Mutex::new(Vec::new()),
            })
        }
    }

    #[async_trait]
    impl MirrorBondVerifier for CoinDeclaringOnePeer {
        async fn verify(
            &self,
            _content: &ContentId,
            claiming_peer_id: &str,
            claimed: Option<[u8; 32]>,
        ) -> BondVerdict {
            let Some(coin) = claimed else {
                return BondVerdict::Unverified;
            };
            self.asked
                .lock()
                .expect("asked")
                .push((claiming_peer_id.to_string(), coin[0]));
            if coin[0] != self.coin_first_byte {
                // The chain answered and no such bond exists.
                return BondVerdict::Unbonded;
            }
            if claiming_peer_id != self.declared_peer_prefix {
                // The coin is real and bonds this content, but it names somebody else. Credit is
                // withheld, never subtracted.
                return BondVerdict::Unverified;
            }
            BondVerdict::Bonded
        }
    }

    fn installed(verifier: Arc<dyn MirrorBondVerifier>) -> BondVerifierSlot {
        let slot = bond_verifier_slot();
        let _ = slot.set(verifier);
        slot
    }

    /// **Proves (dig-node#466, HIGH finding 2):** a stranger that republishes an honest holder's
    /// real coin id under its OWN peer id is not promoted, and the claiming peer id genuinely
    /// reaches the verifier.
    ///
    /// **Catches:** the missing peer parameter. Without it the verifier can only ask "does some coin
    /// bond this content", which the liar's record passes truthfully — the coin is real, it is fully
    /// collateralised, and it bonds exactly this `(store, root, epoch)`. The liar is then ranked
    /// FIRST, ahead of the honest holder whose coin it copied. Asserting the ORDER alone would not
    /// prove the fix: the second assertion pins that the record's own peer id was what was asked
    /// about, so an implementation passing a constant or the honest peer's id fails here.
    #[tokio::test]
    async fn a_liar_republishing_an_honest_holders_coin_id_is_not_promoted() {
        let honest = 0xAA;
        let liar = 0xBB;
        let slate = Slate(vec![
            holder(honest, Some([0x01; 32])), // the coin is really its own
            holder(liar, Some([0x01; 32])),   // the same coin id, under a different peer
        ]);
        let verifier = CoinDeclaringOnePeer::new(0x01, honest);
        let locator = BondRankingLocator::new(Arc::new(slate), installed(verifier.clone()));

        let got = locator.find_providers(&capsule()).await.expect("located");

        assert_eq!(
            peer_ids(&got),
            vec!["aa", "bb"],
            "the coin's declared holder is promoted; the peer that merely copied its id is baseline"
        );
        let asked = verifier.asked.lock().expect("asked").clone();
        let liar_hex = PeerId::from_bytes([liar; 32]).to_hex();
        assert!(
            asked.iter().any(|(peer, _)| *peer == liar_hex),
            "the CLAIMING peer id must reach the chain side; asked {asked:?}"
        );
    }

    /// **Proves (dig-node#466, HIGH finding 1):** a disproven pointer attached to an honest holder
    /// leaves that holder EXACTLY where a slate with no pointers at all would have left it.
    ///
    /// **Catches:** the demotion primitive. A provider record is hearsay, so a stranger can answer a
    /// lookup with an honest holder's peer id and addresses plus a bogus coin id; under a three-tier
    /// ranking that sinks the honest holder to last. The control is the SAME slate with the pointers
    /// removed — not a reversal — because asserting "it moved down less" would be satisfied by a fix
    /// that still sinks it.
    #[tokio::test]
    async fn a_bogus_pointer_leaves_an_honest_holder_exactly_where_no_pointer_would() {
        let with_bogus_pointers = Slate(vec![
            holder(0xAA, Some([0x09; 32])), // a stranger's lie ABOUT this holder
            holder(0xBB, None),
            holder(0xCC, Some([0x09; 32])),
        ]);
        let without_pointers = Slate(vec![
            holder(0xAA, None),
            holder(0xBB, None),
            holder(0xCC, None),
        ]);
        let verifier = || ByCoinByte::new(&[(0x09, BondVerdict::Unbonded)]);

        let smeared = BondRankingLocator::new(Arc::new(with_bogus_pointers), installed(verifier()))
            .find_providers(&capsule())
            .await
            .expect("located");
        let baseline = BondRankingLocator::new(Arc::new(without_pointers), installed(verifier()))
            .find_providers(&capsule())
            .await
            .expect("located");

        assert_eq!(
            peer_ids(&smeared),
            peer_ids(&baseline),
            "a disproven pointer must not rank a holder below where NO pointer would have put it"
        );
        assert_eq!(peer_ids(&smeared), vec!["aa", "bb", "cc"]);
    }

    /// **Proves:** one locate reads at most [`MAX_VERIFIED_PER_LOCATE`] bonds off the chain, whatever
    /// the slate's size, and every unverified record keeps its place.
    ///
    /// **Catches:** the amplification. A stranger answering a single lookup chooses the slate, so an
    /// unbounded loop turns one cheap DHT lookup into as many blocking chain reads as the answer
    /// carries records. Asserted on the chain-read COUNT rather than on elapsed time: a timeout test
    /// passes on a fast machine with the bound removed.
    #[tokio::test]
    async fn a_locate_reads_at_most_the_budget_off_the_chain() {
        let slate = Slate(
            (0u8..40)
                .map(|i| holder(i, Some([0x07; 32])))
                .collect::<Vec<_>>(),
        );
        let verifier = ByCoinByte::new(&[(0x07, BondVerdict::Unverified)]);
        let locator = BondRankingLocator::new(Arc::new(slate), installed(verifier.clone()));

        let got = locator.find_providers(&capsule()).await.expect("located");

        assert_eq!(got.len(), 40, "every located holder is still offered");
        assert_eq!(
            verifier.calls.load(Ordering::SeqCst),
            MAX_VERIFIED_PER_LOCATE,
            "a stranger cannot choose how many chain reads one locate costs"
        );
    }

    /// **Proves:** holders sharing a tier keep the relative order their source gave them.
    ///
    /// **Catches:** an unstable sort silently reshuffling the download union's deliberate
    /// pool-address-first ordering (#836) — a regression invisible to any test that only ever puts
    /// one holder in each tier.
    #[tokio::test]
    async fn holders_sharing_a_tier_keep_the_order_their_source_gave_them() {
        let slate = Slate(vec![
            holder(0xAA, Some([0x01; 32])),
            holder(0xBB, Some([0x01; 32])),
            holder(0xCC, Some([0x02; 32])),
            holder(0xDD, Some([0x01; 32])),
        ]);
        let verifier =
            ByCoinByte::new(&[(0x01, BondVerdict::Bonded), (0x02, BondVerdict::Unbonded)]);
        let locator = BondRankingLocator::new(Arc::new(slate), installed(verifier));

        let got = locator.find_providers(&capsule()).await.expect("located");

        assert_eq!(peer_ids(&got), vec!["aa", "bb", "dd", "cc"]);
    }

    /// **Proves:** a holder that names no coin costs ZERO chain reads and keeps its position.
    ///
    /// **Catches:** treating absence as something to look up — a lookup of a null coin id answers
    /// "no such coin", which is `Unbonded`, and while that no longer demotes anyone it would spend a
    /// chain read per pointerless holder on every locate. The call COUNT is what makes the
    /// distinction observable; the order alone cannot.
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
            "the proven holder is promoted; the two pointerless ones keep their original order"
        );
        assert_eq!(
            verifier.calls.load(Ordering::SeqCst),
            1,
            "only the holder that named a coin is looked up"
        );
    }

    /// **Proves:** a chain this node cannot reach demotes nobody, while the SAME slate with a
    /// reachable chain still promotes the holder that can prove itself.
    ///
    /// **Catches:** collapsing "could not look" into "looked and found nothing". The two halves are
    /// one test on purpose: the partitioned half alone is satisfied by a ranking that does nothing
    /// whatsoever, and the reachable half is the truthful control proving the machinery is live.
    /// Only ONE thing varies between them — whether the chain answers.
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
            "an outage promotes nobody -- the slate is returned exactly as located"
        );

        let reachable =
            ByCoinByte::new(&[(0x01, BondVerdict::Bonded), (0x02, BondVerdict::Unbonded)]);
        let got = BondRankingLocator::new(Arc::new(slate()), installed(reachable))
            .find_providers(&capsule())
            .await
            .expect("located");
        assert_eq!(
            peer_ids(&got),
            vec!["aa", "cc", "bb"],
            "control: the SAME slate, reached by a live chain, promotes the provable holder -- and \
             the liar keeps its place rather than sinking below the holder that claimed nothing"
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
