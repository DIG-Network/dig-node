//! This node's tier sources, expressed as `dig-sex` [`ExchangeAlgorithm`]s.
//!
//! `dig-sex` owns the store-exchange DECISIONS; this module supplies the FACTS they decide over.
//! Three independent sources hold an opinion about which tier a cached store sits in, and the crate
//! composes them — the effective tier is the MAXIMUM across every source that claims the store, so a
//! claim can only ever promote (`AlgorithmSet::facts_or_default`). That composition used to live here
//! as a hand-rolled `effective_tier(...)` fold; only the FACTS remain.
//!
//! | source | claims | why it exists |
//! |---|---|---|
//! | [`InboundDemandTier`] | whatever the in-memory demand ledger tagged | a store a real read reached is protected |
//! | [`PrecacheLandTier`] | `Tier0Precache` | the self-driven precache loop's lands are the sacrificial tier |
//! | [`PersistedTierTag`] | whatever `<cache>/modules/<store>/.tier` records | precedence survives a RESTART (#2015) |
//!
//! A store none of them names resolves to [`DEFAULT_TIER`](dig_sex::DEFAULT_TIER) — `Tier1Demand`,
//! the PROTECTED tier — so every failure of a source (a lost in-memory ledger on a fresh process, an
//! unreadable sidecar) fails SAFE: the sweep can never sacrifice genuinely-demanded content merely
//! because nothing labelled it.
//!
//! # Purity lives in the crate; the I/O lives here
//!
//! `dig-sex` reads no clock, socket or filesystem. [`PersistedTierTag`] reads the sidecar and
//! [`InboundDemandTier`] locks a live ledger, because supplying facts IS this node's job — the
//! boundary is that no DECISION is taken on either side of those reads.
//!
//! # Why every source scores on XOR proximity alone
//!
//! Within a tier, `dig-sex` ranks by size first and then by score. The only score available at sweep
//! time that no peer can move is the XOR proximity of the capsule's keyspace key to THIS node's own
//! `peer_id` — the same ungameable primary the inbound-demand admission gate and the tier-0 selector
//! anchor on. The demand ledger's read COUNT is deliberately not scored: it is incremented by inbound
//! peer requests, so scoring it would let peers order this node's eviction — the defect
//! [`dig_sex::eviction`] exists to keep out (dig-store-cache#3).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use dig_sex::algorithm::{ExchangeAlgorithm, StoreFacts};
use dig_sex::{
    relevance, AlgorithmSet, CacheTier, CapsuleIdentity, NodeContext, RelevanceInputs,
    RelevanceValue, RelevanceWeights,
};

use crate::inbound_demand::InboundDemand;

/// The lowercase 64-hex store id every tier source is keyed by — the `<cache>/modules/<store>`
/// directory name, and the key both in-memory ledgers use.
fn store_hex(id: &CapsuleIdentity) -> String {
    hex::encode(id.store_id)
}

/// The within-tier score: XOR proximity of the capsule's keyspace key to this node's own `peer_id`.
///
/// Shared by all three sources because the score is a property of the CAPSULE, not of the reason a
/// source claims it — the sources differ in the tier they assert, never in desirability within it.
///
/// A node that has not yet learned its own `peer_id` (the FFI/consumer path, or before peer-network
/// bring-up) has no anchor for "near us", so every capsule scores zero and the size objective alone
/// orders each tier. That degrades ranking; it can never mis-assign a tier.
pub struct NeighbourhoodScore {
    context: Option<NodeContext>,
}

impl NeighbourhoodScore {
    /// Anchor scoring on this node's own `peer_id`, or on nothing when it is not yet known.
    #[must_use]
    pub fn new(peer_id: Option<[u8; 32]>) -> Self {
        Self {
            context: peer_id.map(|peer_id| NodeContext {
                peer_id,
                weights: RelevanceWeights::default(),
            }),
        }
    }

    /// Score `id`, neutralising every secondary signal: a sweep knows neither a provider count nor a
    /// LOCAL read count, and the peer-drivable counts it does know must not reach an ordering (see
    /// the module docs). What is left is the XOR primary, which is the point.
    fn of(&self, id: &CapsuleIdentity) -> RelevanceValue {
        let Some(context) = self.context.as_ref() else {
            return RelevanceValue(0.0);
        };
        let key = dig_dht::ContentId::capsule(id.store_id.into(), id.root_hash.into()).to_key();
        relevance(
            &RelevanceInputs {
                content_id: *key.as_bytes(),
                size_bytes: 0,
                known_provider_count: 0,
                local_read_count: 0,
                reads_recency_ticks: None,
                is_pinned: false,
                pin_adjacent: false,
            },
            context,
        )
    }
}

/// The in-memory inbound-demand ledger: a store a real read reached is tagged, and that tag protects
/// it from the tier-0 sweep. Holds no opinion about a store the ledger has never seen.
pub struct InboundDemandTier {
    ledger: Arc<InboundDemand>,
    score: Arc<NeighbourhoodScore>,
}

impl ExchangeAlgorithm<CapsuleIdentity> for InboundDemandTier {
    fn facts(&self, id: &CapsuleIdentity) -> Option<StoreFacts> {
        self.ledger.tier(&store_hex(id)).map(|tier| StoreFacts {
            tier,
            score: self.score.of(id),
        })
    }
}

/// The in-memory tier-0 land ledger: a store the self-driven precache loop landed in THIS process is
/// speculative, and speculative content is sacrificed first.
///
/// Claiming `Tier0Precache` is not a demotion of anything — a store also named by the demand ledger
/// is promoted by the MAX composition, which is exactly how a precached store that someone then read
/// stops being sacrificial.
pub struct PrecacheLandTier {
    score: Arc<NeighbourhoodScore>,
}

impl ExchangeAlgorithm<CapsuleIdentity> for PrecacheLandTier {
    fn facts(&self, id: &CapsuleIdentity) -> Option<StoreFacts> {
        crate::tier0_live::is_tier0_precache(&store_hex(id)).then(|| StoreFacts {
            tier: CacheTier::Tier0Precache,
            score: self.score.of(id),
        })
    }
}

/// The persisted `<cache>/modules/<store>/.tier` sidecar — the only source that survives a restart.
///
/// Both in-memory ledgers are process-lifetime, so on a fresh node they are empty and the composition
/// would collapse to the protected default for every module on disk, losing the sacrifice-tier-0-first
/// order until content was re-precached. This source restores it the moment the node comes back up
/// (#2015). An absent or malformed sidecar is `None`, never a guess.
pub struct PersistedTierTag {
    cache_dir: PathBuf,
    score: Arc<NeighbourhoodScore>,
}

impl ExchangeAlgorithm<CapsuleIdentity> for PersistedTierTag {
    fn facts(&self, id: &CapsuleIdentity) -> Option<StoreFacts> {
        crate::module_tier_tag::read_tier_tag(&self.cache_dir, &store_hex(id)).map(|tier| {
            StoreFacts {
                tier,
                score: self.score.of(id),
            }
        })
    }
}

/// Compose this node's three tier sources into the set `dig-sex` decides over.
///
/// Registration order is irrelevant — the composition is a maximum, not a last-writer-wins — so a
/// caller cannot change policy by reordering this call.
#[must_use]
pub fn algorithms(
    ledger: Arc<InboundDemand>,
    cache_dir: &Path,
    peer_id: Option<[u8; 32]>,
) -> AlgorithmSet<CapsuleIdentity> {
    let score = Arc::new(NeighbourhoodScore::new(peer_id));
    AlgorithmSet::new()
        .with(Box::new(InboundDemandTier {
            ledger,
            score: Arc::clone(&score),
        }))
        .with(Box::new(PrecacheLandTier {
            score: Arc::clone(&score),
        }))
        .with(Box::new(PersistedTierTag {
            cache_dir: cache_dir.to_path_buf(),
            score,
        }))
}

#[cfg(test)]
mod tests {
    use super::*;

    use dig_sex::DEFAULT_TIER;

    fn capsule(store: u8, root: u8) -> CapsuleIdentity {
        CapsuleIdentity {
            store_id: [store; 32].into(),
            root_hash: [root; 32].into(),
        }
    }

    fn ledger() -> Arc<InboundDemand> {
        Arc::new(InboundDemand::new())
    }

    /// The fail-safe the whole composition rests on: a module on disk that no source names is
    /// PROTECTED, never sacrificed. A legacy cache with no sidecar, or a fresh process whose
    /// in-memory ledgers are empty, is exactly this case.
    #[test]
    fn a_store_no_source_names_defaults_to_the_protected_tier() {
        let dir = tempfile::tempdir().unwrap();
        let set = algorithms(ledger(), dir.path(), Some([0x11; 32]));

        assert_eq!(set.facts(&capsule(0xAA, 0xBB)), None);
        assert_eq!(
            set.facts_or_default(&capsule(0xAA, 0xBB)).tier,
            DEFAULT_TIER
        );
    }

    /// The persisted sidecar is what makes precedence survive a restart (#2015). Both in-memory
    /// ledgers are empty here — as they are on a fresh process — so a `Tier0Precache` verdict can
    /// only have come from disk. Without the third source this returns the protected default.
    #[test]
    fn the_persisted_sidecar_alone_still_yields_the_sacrificial_tier() {
        let dir = tempfile::tempdir().unwrap();
        let store = "aa".repeat(32);
        std::fs::create_dir_all(dir.path().join("modules").join(&store)).unwrap();
        crate::module_tier_tag::write_tier_tag(dir.path(), &store, CacheTier::Tier0Precache);

        let set = algorithms(ledger(), dir.path(), Some([0x11; 32]));
        assert_eq!(
            set.facts_or_default(&capsule(0xAA, 0xBB)).tier,
            CacheTier::Tier0Precache
        );
    }

    /// SPEC §2.2 through THIS node's sources: a store both precached and demanded is PROMOTED. The
    /// fixture makes the two sources disagree — the sidecar says sacrificial, the demand ledger says
    /// protected — so a composition that took either source alone, or the last one registered,
    /// returns the wrong answer.
    #[test]
    fn a_demanded_store_outranks_its_own_persisted_precache_tag() {
        let dir = tempfile::tempdir().unwrap();
        let store = "aa".repeat(32);
        std::fs::create_dir_all(dir.path().join("modules").join(&store)).unwrap();
        crate::module_tier_tag::write_tier_tag(dir.path(), &store, CacheTier::Tier0Precache);

        let demand = ledger();
        demand.record(&store);

        let set = algorithms(demand, dir.path(), Some([0x11; 32]));
        assert_eq!(
            set.facts_or_default(&capsule(0xAA, 0xBB)).tier,
            CacheTier::Tier1Demand,
            "a real read must promote a store its sidecar still calls speculative"
        );
    }

    /// The XOR distance of a capsule's DHT key from this node's peer id, big-endian.
    ///
    /// Computed here by hand rather than via `dig_sex::relevance::xor_proximity`, deliberately: this
    /// is what CHOOSES the fixtures, and the scoring function is what is under test. Using the same
    /// function for both would make the test agree with itself no matter what either did.
    fn key_distance_from(id: &CapsuleIdentity, peer_id: &[u8; 32]) -> [u8; 32] {
        let key = dig_dht::ContentId::capsule(id.store_id.into(), id.root_hash.into()).to_key();
        let bytes = *key.as_bytes();
        let mut distance = [0u8; 32];
        for (slot, (left, right)) in distance.iter_mut().zip(bytes.iter().zip(peer_id.iter())) {
            *slot = left ^ right;
        }
        distance
    }

    /// A capsule whose DHT key is nearer this node's peer id scores above one that is further.
    ///
    /// The fixtures are FOUND, not assumed. An earlier version of this test built its "near" capsule
    /// from all-zero bytes against an all-zero peer id and asserted only that the two scores
    /// differed. That assertion passed while the relationship it was named for did not hold at all:
    /// `content_id` is `ContentId::capsule(..).to_key()`, a HASH, so a capsule of zero bytes lands at
    /// an arbitrary point in the keyspace and is no nearer the origin than any other. Tightening the
    /// assertion to `>` is what exposed it — the far capsule scored 0.936 against the near one's
    /// 0.658, and the code was right both times.
    #[test]
    fn a_capsule_nearer_this_nodes_identity_scores_above_a_further_one() {
        let peer_id = [0x00; 32];
        let score = NeighbourhoodScore::new(Some(peer_id));

        // Search a deterministic family for the genuinely nearest and furthest keys.
        let family: Vec<CapsuleIdentity> = (0u8..=255).map(|tag| capsule(tag, tag)).collect();
        let nearest = family
            .iter()
            .min_by_key(|id| key_distance_from(id, &peer_id))
            .expect("the family is non-empty");
        let furthest = family
            .iter()
            .max_by_key(|id| key_distance_from(id, &peer_id))
            .expect("the family is non-empty");

        let near = score.of(nearest);
        let far = score.of(furthest);

        assert!(
            near.get() > far.get(),
            "the nearest-key capsule must score above the furthest: near={} far={}",
            near.get(),
            far.get()
        );
    }

    /// A node with no known identity has no anchor for "near us". Scoring must degrade to a constant
    /// rather than to an arbitrary one, so the size objective alone orders each tier.
    #[test]
    fn an_unknown_self_identity_scores_every_capsule_identically() {
        let score = NeighbourhoodScore::new(None);
        assert_eq!(score.of(&capsule(0x00, 0x00)).get(), 0.0);
        assert_eq!(score.of(&capsule(0xFF, 0xFF)).get(), 0.0);
    }
}
