//! Reading a peer's claimed mirror coin against the chain (dig-node#466).
//!
//! [`dig_node_core::mirror_bond`] owns the DECISION — three verdicts, and a locator layer that ranks
//! a holder set by them. This module owns the half that needs a chain: fetching the coin a holder
//! named, re-deriving it from the spend that created it, and asking whether it bonds the content
//! that was actually requested.
//!
//! # The algorithm is `SYSTEM.md`'s, not this module's
//!
//! Four steps, in order, and none of them is optional:
//!
//! 1. the coin sits at [`mirror_coin_puzzle_hash`];
//! 2. it is $DIG, with the asset id re-derived from the creating spend;
//! 3. it carries the full collateral;
//! 4. [`MirrorCoin::advertises`] — **exact equality** on the coin's declared
//!    `(store, root, epoch)`, plus the hint recomputed with the owner taken from the coin's own
//!    lineage proof.
//!
//! Steps 1-3 establish only that *a* valid mirror coin exists somewhere. **Step 4 is what binds it
//! to the claim**, and it is why nothing here recomputes the morph by hand: `mirror_hint` sums four
//! terms, one of them a freely chosen `epoch`, so an author can solve for a value landing on any
//! other advertisement's hint. `dig-mirror-coin` asserts exactly that about itself. Both halves of
//! `advertises` are needed and neither is redundant.
//!
//! # The order of steps 3 and 4 is deliberate
//!
//! The tuple binding is checked BEFORE collateral sufficiency. A node that has not yet censused an
//! epoch cannot price a bond, and if that were checked first every verdict on such a node would be
//! `Unverified` — including a holder naming a coin that plainly bonds someone else's store. Binding
//! first means the lie is caught by any node with a chain, censused or not; an unknown requirement
//! then downgrades an otherwise-good answer to `Unverified` rather than promoting it to `Bonded`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chia_protocol::Bytes32;
use dig_chainsource_interface::ChainSource;
use dig_mirror_coin::{mirror_coin_puzzle_hash, MirrorCoin, MirrorError};
use dig_node_core::mirror_bond::{BondVerdict, ContentId, MirrorBondVerifier};
use num_bigint::BigInt;

use crate::collateral::{current_epoch_now, requirement, EpochRecordStore};
use dig_node_control_interface::results::CollateralRequirementResult;

/// How long a DEFINITE verdict stays usable before the chain is asked again.
///
/// Short relative to an epoch (seven days) so a rollover is picked up long before a stale `Bonded`
/// could outlive the coin that earned it, and long enough that a burst of reads for one capsule
/// costs one chain lookup rather than one per holder per read.
const VERDICT_TTL: Duration = Duration::from_secs(600);

/// The most cached verdicts held at once.
///
/// The key includes a coin id chosen by whoever published the provider record, so the map's growth
/// is driven by attacker-writable input and MUST be bounded. Overflow evicts ONE entry rather than
/// clearing: clearing hands a stranger a cheap way to discard every honest verdict this node has
/// earned simply by rotating coin ids, which converts a memoisation into an amplifier.
const MAX_CACHED_VERDICTS: usize = 1024;

/// A verdict is only ever cached for the exact question it answered.
///
/// The coin id alone is not the key: one coin bonds one `(store, root, epoch)`, so caching by coin
/// would let a genuine `Bonded` for one capsule answer for a different capsule the same coin does
/// not bond — the precise substitution `advertises` exists to refuse.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct VerdictKey {
    coin_id: [u8; 32],
    store_launcher_id: [u8; 32],
    root_hash: [u8; 32],
    epoch: u64,
}

/// What a mirror coin's advertised terms say about the peer claiming it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeerDeclaration {
    /// The coin's owner declared this exact peer, in code the chain executed.
    DeclaresThisPeer,
    /// The coin declares some other peer, or none. Credit is withheld — never subtracted, because
    /// the record naming this coin may be a stranger's lie ABOUT the coin's real holder.
    Silent,
    /// This node cannot read the declaration at all, so it knows nothing either way.
    NotReadable,
}

/// Whether `advertised_terms` — the free tail of a mirror coin's memo — declares `claiming_peer_id`.
///
/// **This is deliberately unreadable today, and that is the promotion gate.** The tail is arbitrary
/// UTF-8 and `MirrorCoin::urls()` already hands it over, so a `dig-peer:<64-hex>` term COULD be
/// parsed here — and must not be. `dig-mirror-coin` 0.8.0 is about to own that format with a typed
/// accessor; parsing it here would create a second parser for a security-critical format, in the
/// consumer, where a divergence between the two would be a silent authorization difference rather
/// than a compile error (CLAUDE.md 2.0, centralize rival implementations).
///
/// So promotion is switched OFF until that accessor exists: with no sound source for the
/// coin -> peer binding, `Bonded` cannot be established, and the layer withholds credit from
/// everyone rather than granting it on a check it cannot make. Nothing is demoted by this
/// (mirror_bond's lattice is credit-only), so the interim behaviour is exactly the behaviour of a
/// node with no verifier at all.
///
/// Replacing the body with the 0.8.0 accessor is the whole of the change that makes promotion live —
/// and the authoritative-record restriction on dig-node#466 MUST land with it, never after.
pub(crate) fn peer_declaration(
    _advertised_terms: &[String],
    _claiming_peer_id: &str,
) -> PeerDeclaration {
    PeerDeclaration::NotReadable
}

/// Whether `claimed_coin_id` genuinely bonds `store_launcher_id` at `root_hash` for `epoch`
/// **on behalf of `claiming_peer_id`**.
///
/// `required_collateral` is this node's censused per-store requirement, or `None` when it has no
/// record for the epoch. Pure over the source, so a test can drive every branch with real coins
/// built from real CAT spends.
///
/// `Err` from the source is always [`BondVerdict::Unverified`] and never `Unbonded`: a source that
/// could not answer has said nothing about the holder.
///
/// `claiming_peer_id` is the peer id off the same untrusted record as `claimed_coin_id`. A coin id
/// is a public fact, so a coin that bonds the content proves nothing about WHO is offering it; the
/// last step asks the coin whether it declares this claimant, and only that answer promotes.
pub fn verdict_for<S: ChainSource>(
    source: &S,
    store_launcher_id: Bytes32,
    root_hash: Bytes32,
    epoch: &BigInt,
    required_collateral: Option<u64>,
    claiming_peer_id: &str,
    claimed_coin_id: Bytes32,
) -> BondVerdict {
    let record = match source.coin_record(claimed_coin_id) {
        Ok(Some(record)) => record,
        // The chain answered and there is no such coin. The publisher named something that does not
        // exist, which is a claim disproven rather than a claim unexamined.
        Ok(None) => return BondVerdict::Unbonded,
        Err(_) => return BondVerdict::Unverified,
    };

    // A spent coin locks nothing. Collateral is the coin remaining unspent; a reclaimed one is a
    // bond that has already been taken back.
    if record.is_spent() {
        return BondVerdict::Unbonded;
    }

    // Step 1. Every mirror coin in existence shares this puzzle hash, so failing here says the coin
    // is not collateral of any kind.
    if record.coin.puzzle_hash != mirror_coin_puzzle_hash() {
        return BondVerdict::Unbonded;
    }

    // Steps 2 and 3's asset id, and the owner step 4 needs, all come from EXECUTED on-chain code:
    // the parent's puzzle is run and its `CREATE_COIN` conditions searched for this coin. Nothing
    // here is taken from a memo, which is the only part of a mirror coin its publisher writes
    // freely.
    let creating_spend = match source.coin_spend(record.coin.parent_coin_info) {
        Ok(Some(spend)) => spend,
        // The coin exists, so its parent was spent; a source that cannot produce that spend has a
        // gap rather than an answer.
        Ok(None) | Err(_) => return BondVerdict::Unverified,
    };

    let mirror = match MirrorCoin::from_creating_spend(&creating_spend, claimed_coin_id) {
        Ok(Some(mirror)) => mirror,
        // Established, and the answer is no: not a $DIG-collateral coin, or one advertising nothing.
        Ok(None) => return BondVerdict::Unbonded,
        Err(MirrorError::ChainUnavailable(_)) => return BondVerdict::Unverified,
        // Memos that will not decode. The publisher chose this coin id and chose those memos, so
        // this is its claim failing, not this node failing to look.
        Err(_) => return BondVerdict::Unbonded,
    };

    // Step 4 — the one that binds the coin to THIS claim.
    if !mirror.advertises(store_launcher_id, root_hash, epoch) {
        return BondVerdict::Unbonded;
    }

    // Step 3's magnitude (see the module docs for why it is not first).
    match required_collateral {
        Some(required) if mirror.collateral() < required => return BondVerdict::Unbonded,
        Some(_) => {}
        None => return BondVerdict::Unverified,
    }

    // Step 5 — WHOSE bond is it? A valid, fully-collateralised coin bonding exactly this content
    // still says nothing about the peer offering the record; every field of that record, including
    // the coin id, was chosen by whoever answered the lookup. Only the coin's own declaration of a
    // peer can close that, and this node cannot read one yet (see `peer_declaration`), so no claim
    // is promoted today.
    match peer_declaration(mirror.urls(), claiming_peer_id) {
        PeerDeclaration::DeclaresThisPeer => BondVerdict::Bonded,
        // Credit withheld, never subtracted: this record may be a stranger's lie about an honest
        // holder's coin, and demoting on it is what would make that lie pay.
        PeerDeclaration::Silent | PeerDeclaration::NotReadable => BondVerdict::Unverified,
    }
}

/// The production [`MirrorBondVerifier`]: one bounded chain read per distinct claim, memoised.
pub struct ChainBondVerifier {
    chain: Arc<dig_wallet::sage::chain::ChainTransport>,
    cache: Mutex<HashMap<VerdictKey, (Instant, BondVerdict)>>,
    /// The epoch of the most recent definite verdict, plus one; `0` means none yet. Read to probe
    /// the cache before paying for the epoch file.
    last_epoch: AtomicU64,
}

impl ChainBondVerifier {
    /// Verify against the node's own chain transport.
    pub fn new(chain: Arc<dig_wallet::sage::chain::ChainTransport>) -> Arc<Self> {
        Arc::new(ChainBondVerifier {
            chain,
            cache: Mutex::new(HashMap::new()),
            last_epoch: AtomicU64::new(0),
        })
    }

    fn cached(&self, key: &VerdictKey) -> Option<BondVerdict> {
        let cache = self.cache.lock().ok()?;
        cache
            .get(key)
            .filter(|(taken, _)| taken.elapsed() < VERDICT_TTL)
            .map(|(_, verdict)| *verdict)
    }

    /// The epoch the last definite verdict was taken under, or `None` when nothing is cached.
    ///
    /// Lets the cache be probed without re-reading the epoch file. It is only a HINT: a miss falls
    /// through to the real read, and a stale value can only produce a cache miss, never a verdict
    /// taken under the wrong epoch, because the epoch remains part of the key.
    fn cached_epoch(&self) -> Option<u64> {
        self.last_epoch.load(Ordering::Relaxed).checked_sub(1)
    }

    /// The chain half: one bounded read, memoised.
    #[allow(clippy::too_many_arguments)]
    async fn verify_against_chain(
        &self,
        store: Bytes32,
        root: Bytes32,
        epoch: u64,
        required: Option<u64>,
        claiming_peer_id: &str,
        coin_id: [u8; 32],
    ) -> BondVerdict {
        let key = VerdictKey {
            coin_id,
            store_launcher_id: store.to_bytes(),
            root_hash: root.to_bytes(),
            epoch,
        };
        if let Some(hit) = self.cached(&key) {
            return hit;
        }

        // Re-read per call rather than held from bring-up, matching the mirror pass: a transport
        // built once would make a node that started offline one that never verifies again.
        let Ok(source) = self
            .chain
            .chain_source(tokio::runtime::Handle::current())
            .await
        else {
            return BondVerdict::Unverified;
        };

        // `ChainSource` is blocking, so the read leaves the async worker rather than parking it.
        let epoch_big = BigInt::from(epoch);
        let verdict = tokio::task::block_in_place(|| {
            verdict_for(
                &source,
                store,
                root,
                &epoch_big,
                required,
                claiming_peer_id,
                Bytes32::new(coin_id),
            )
        });

        self.remember(key, verdict);
        verdict
    }

    /// Remember a DEFINITE verdict. `Unverified` is never cached: it records this node's own
    /// momentary inability to look, and holding it would keep an outage in force after it ended.
    fn remember(&self, key: VerdictKey, verdict: BondVerdict) {
        if verdict == BondVerdict::Unverified {
            return;
        }
        // +1 so that "never set" and "epoch 0" stay distinguishable in one atomic.
        self.last_epoch.store(key.epoch + 1, Ordering::Relaxed);
        let Ok(mut cache) = self.cache.lock() else {
            return;
        };
        if cache.len() >= MAX_CACHED_VERDICTS {
            // Evict one arbitrary entry, not the map. `HashMap` iteration order is unspecified, so
            // the victim is not attacker-selectable either; the cost of a wrong guess is one chain
            // read, never a wrong answer.
            if let Some(victim) = cache.keys().next().copied() {
                cache.remove(&victim);
            }
        }
        cache.insert(key, (Instant::now(), verdict));
    }
}

/// The `(store, root)` a bond could be checked against, or `None` for a store-granularity id.
///
/// A mirror coin bonds a `(store, root, owner, epoch)` tuple, so a claim about a whole STORE names
/// no generation and is not a thing a coin can advertise. That is a limit of the question, not a
/// failed verification.
fn bondable_tuple(content: &ContentId) -> Option<(Bytes32, Bytes32)> {
    match content {
        ContentId::Store { .. } => None,
        ContentId::Root { store_id, root } | ContentId::Resource { store_id, root, .. } => {
            Some((Bytes32::new(*store_id), Bytes32::new(*root)))
        }
    }
}

/// This node's current epoch and its censused per-store requirement, or `None` when the epoch itself
/// is not yet settled.
fn epoch_and_requirement() -> Option<(u64, Option<u64>)> {
    let current = current_epoch_now();
    let epoch = match current {
        crate::collateral::CurrentEpoch::Final(epoch) => epoch,
        _ => return None,
    };
    let required = match requirement(&EpochRecordStore::in_state_dir(), current) {
        CollateralRequirementResult::Known {
            required_per_store_dig_base_units,
            ..
        } => Some(required_per_store_dig_base_units),
        _ => None,
    };
    Some((epoch, required))
}

#[async_trait]
impl MirrorBondVerifier for ChainBondVerifier {
    async fn verify(
        &self,
        content: &ContentId,
        claiming_peer_id: &str,
        claimed_coin_id: Option<[u8; 32]>,
    ) -> BondVerdict {
        // No pointer is the ORDINARY case and costs no chain read at all: an older publisher, one
        // that has not created its coin, and one mid-rollover all legitimately omit it.
        let Some(coin_id) = claimed_coin_id else {
            return BondVerdict::Unverified;
        };
        let Some((store, root)) = bondable_tuple(content) else {
            return BondVerdict::Unverified;
        };
        // The epoch read is a file read plus a line-by-line JSON parse, so it happens AFTER the
        // cheap in-memory probe rather than before it: a slate of records for one capsule otherwise
        // pays that parse per record even when every verdict is already known. The cache is keyed
        // on the epoch, so the probe uses the epoch the last read established and re-reads only on a
        // miss.
        let Some(epoch) = self.cached_epoch() else {
            let Some((epoch, required)) = epoch_and_requirement() else {
                return BondVerdict::Unverified;
            };
            return self
                .verify_against_chain(store, root, epoch, required, claiming_peer_id, coin_id)
                .await;
        };
        let key = VerdictKey {
            coin_id,
            store_launcher_id: store.to_bytes(),
            root_hash: root.to_bytes(),
            epoch,
        };
        if let Some(hit) = self.cached(&key) {
            return hit;
        }
        let Some((epoch, required)) = epoch_and_requirement() else {
            return BondVerdict::Unverified;
        };

        self.verify_against_chain(store, root, epoch, required, claiming_peer_id, coin_id)
            .await
    }
}

/// Install the bond verifier on the node's content engine once the peer network has brought it up.
///
/// Detached and best-effort, because the engine is created asynchronously by
/// `peer::spawn_peer_network` and this call site runs beside it. A node whose peer network never
/// comes up simply never installs a verifier, and its locator layer stays the pass-through it is
/// before installation — the shipped behaviour, not a degraded one.
pub fn spawn_bond_verifier_install(
    node: Arc<dig_node_core::Node>,
    chain: Arc<dig_wallet::sage::chain::ChainTransport>,
) {
    tokio::spawn(async move {
        for _ in 0..BOND_VERIFIER_INSTALL_ATTEMPTS {
            if let Some(content) = node.p2p_content() {
                if content.set_bond_verifier(ChainBondVerifier::new(chain)) {
                    tracing::info!(
                        "mirror-coin bond verification is live: located holders are now ranked by \
                         whether their claimed collateral actually bonds the content (#466)"
                    );
                }
                return;
            }
            tokio::time::sleep(BOND_VERIFIER_INSTALL_INTERVAL).await;
        }
        tracing::debug!(
            "no P2P content engine after peer-network bring-up; mirror-coin bond ranking stays off"
        );
    });
}

/// Long enough to outlast an ordinary peer-network bring-up, bounded so the task cannot outlive a
/// node that will never have an engine.
const BOND_VERIFIER_INSTALL_ATTEMPTS: usize = 60;
const BOND_VERIFIER_INSTALL_INTERVAL: Duration = Duration::from_secs(2);

#[cfg(test)]
mod tests {
    use super::*;

    /// **Proves (dig-node#466):** no advertised term this node can see promotes a claim today.
    ///
    /// **Catches:** the rival parser. The tail of a mirror coin's memo is arbitrary UTF-8 and
    /// `MirrorCoin::urls()` hands it straight over, so a well-meaning change could make promotion
    /// reachable immediately by parsing `dig-peer:` here — a second implementation of a
    /// security-critical format that `dig-mirror-coin` 0.8.0 is about to own, where a divergence
    /// between the two parsers is a silent authorization difference rather than a compile error.
    /// A well-formed term is included in the fixture precisely because that is the input a rival
    /// parser would accept; a fixture of only junk terms would pass against one.
    ///
    /// This test is expected to FAIL when 0.8.0's typed accessor lands. That is its second job: the
    /// authoritative-record restriction must land in the same change that makes promotion live.
    #[test]
    fn no_visible_term_promotes_a_claim_before_the_typed_accessor_exists() {
        let peer = "aa".repeat(32);
        for terms in [
            vec![],
            vec![format!("dig-peer:{peer}")],
            vec![format!("dig-peer:{}", "bb".repeat(32))],
            vec!["https://mirror.example/store".to_string()],
        ] {
            assert_ne!(
                peer_declaration(&terms, &peer),
                PeerDeclaration::DeclaresThisPeer,
                "promotion must stay unreachable until the binding has a typed source; terms {terms:?}"
            );
        }
    }
}
