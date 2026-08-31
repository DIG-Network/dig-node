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
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chia_protocol::Bytes32;
use dig_chainsource_interface::ChainSource;
use dig_dht::ContentId;
use dig_mirror_coin::{mirror_coin_puzzle_hash, MirrorCoin, MirrorError};
use dig_node_core::mirror_bond::{BondVerdict, MirrorBondVerifier};
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
/// is driven by attacker-writable input and MUST be bounded. Overflow clears rather than evicts
/// cleverly: the cache is an optimisation, and a cleared one costs a chain read, never a wrong
/// answer.
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

/// Whether `claimed_coin_id` genuinely bonds `store_launcher_id` at `root_hash` for `epoch`.
///
/// `required_collateral` is this node's censused per-store requirement, or `None` when it has no
/// record for the epoch. Pure over the source, so a test can drive every branch with real coins
/// built from real CAT spends.
///
/// `Err` from the source is always [`BondVerdict::Unverified`] and never `Unbonded`: a source that
/// could not answer has said nothing about the holder, and a node that treats the two alike ranks
/// every honest peer last the moment its own connectivity fails.
pub fn verdict_for<S: ChainSource>(
    source: &S,
    store_launcher_id: Bytes32,
    root_hash: Bytes32,
    epoch: &BigInt,
    required_collateral: Option<u64>,
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

    // Step 3's magnitude, last (see the module docs for why it is not first).
    match required_collateral {
        Some(required) if mirror.collateral() < required => BondVerdict::Unbonded,
        Some(_) => BondVerdict::Bonded,
        None => BondVerdict::Unverified,
    }
}

/// The production [`MirrorBondVerifier`]: one bounded chain read per distinct claim, memoised.
pub struct ChainBondVerifier {
    chain: Arc<dig_wallet::sage::chain::ChainTransport>,
    cache: Mutex<HashMap<VerdictKey, (Instant, BondVerdict)>>,
}

impl ChainBondVerifier {
    /// Verify against the node's own chain transport.
    pub fn new(chain: Arc<dig_wallet::sage::chain::ChainTransport>) -> Arc<Self> {
        Arc::new(ChainBondVerifier {
            chain,
            cache: Mutex::new(HashMap::new()),
        })
    }

    fn cached(&self, key: &VerdictKey) -> Option<BondVerdict> {
        let cache = self.cache.lock().ok()?;
        cache
            .get(key)
            .filter(|(taken, _)| taken.elapsed() < VERDICT_TTL)
            .map(|(_, verdict)| *verdict)
    }

    /// Remember a DEFINITE verdict. `Unverified` is never cached: it records this node's own
    /// momentary inability to look, and holding it would keep an outage in force after it ended.
    fn remember(&self, key: VerdictKey, verdict: BondVerdict) {
        if verdict == BondVerdict::Unverified {
            return;
        }
        let Ok(mut cache) = self.cache.lock() else {
            return;
        };
        if cache.len() >= MAX_CACHED_VERDICTS {
            cache.clear();
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
        ContentId::Root { store_id, root }
        | ContentId::Resource { store_id, root, .. } => {
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
    async fn verify(&self, content: &ContentId, claimed_coin_id: Option<[u8; 32]>) -> BondVerdict {
        // No pointer is the ORDINARY case and costs no chain read at all: an older publisher, one
        // that has not created its coin, and one mid-rollover all legitimately omit it.
        let Some(coin_id) = claimed_coin_id else {
            return BondVerdict::Unverified;
        };
        let Some((store, root)) = bondable_tuple(content) else {
            return BondVerdict::Unverified;
        };
        let Some((epoch, required)) = epoch_and_requirement() else {
            return BondVerdict::Unverified;
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
                Bytes32::new(coin_id),
            )
        });

        self.remember(key, verdict);
        verdict
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
