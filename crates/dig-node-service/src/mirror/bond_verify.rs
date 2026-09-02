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
///
/// **The claiming peer is part of the key for the same reason.** [`verdict_for`] answers a
/// peer-DEPENDENT question: the chain half establishes that a coin bonds this content, and the
/// ownership half asks whether that coin declares the peer offering the record. A key without the
/// claimant would let a `Bonded` earned by the coin's real holder be served, for the whole
/// [`VERDICT_TTL`], to any stranger republishing the same public coin id — reinstating through the
/// memo layer the exact substitution the ownership half exists to refuse. It is inert only while
/// [`peer_declaration`] cannot return `DeclaresThisPeer`, and it must not depend on that.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct VerdictKey {
    coin_id: [u8; 32],
    store_launcher_id: [u8; 32],
    root_hash: [u8; 32],
    epoch: u64,
    /// `SHA-256` of the claiming peer id. Hashed rather than held so the key stays `Copy` and
    /// fixed-size against an attacker-chosen string; only equality is ever needed.
    claiming_peer: [u8; 32],
}

impl VerdictKey {
    fn new(
        coin_id: [u8; 32],
        store: Bytes32,
        root: Bytes32,
        epoch: u64,
        claiming_peer_id: &str,
    ) -> Self {
        let mut hasher = chia_sha2::Sha256::new();
        hasher.update(claiming_peer_id.as_bytes());
        VerdictKey {
            coin_id,
            store_launcher_id: store.to_bytes(),
            root_hash: root.to_bytes(),
            epoch,
            claiming_peer: hasher.finalize(),
        }
    }
}

/// What a mirror coin's advertised terms say about the peer claiming it.
///
/// `DeclaresThisPeer` and `Silent` are matched but not yet constructed: nothing can construct them
/// until [`peer_declaration`] has a typed source for the binding, which is exactly the promotion gate
/// described there. They are written now so the shape of the answer is fixed before the source
/// arrives, and so the call site reads as the full decision rather than a placeholder.
#[allow(dead_code)]
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
/// Replacing the body with the 0.8.0 accessor turns promotion on, and three things MUST land in
/// that same change, never after: the authoritative-record restriction on dig-node#466, the
/// claiming peer id staying part of [`VerdictKey`] (a peer-agnostic key would serve one peer's
/// earned `Bonded` to a stranger republishing the same public coin id), and the cost analysis on
/// [`declaration_source_is_readable`], whose short-circuit lifts itself the moment this function
/// can answer.
pub(crate) fn peer_declaration(
    _advertised_terms: &[String],
    _claiming_peer_id: &str,
) -> PeerDeclaration {
    PeerDeclaration::NotReadable
}

/// Whether [`peer_declaration`] can bind a coin to a peer AT ALL — probed through the real
/// function, on the most favourable input that exists.
///
/// While the answer is `false`, [`verdict_for`] cannot return `Bonded` for any input, so every
/// chain read it would perform buys a verdict that is discarded: `Unverified` and `Unbonded` share
/// a rank in `credit_rank`, and the sort is stable, so the located slate is returned unchanged.
/// Paying four third-party HTTPS reads per holder, up to the locate budget, for a provably
/// discarded answer converts one cheap-lookup token into attacker-directed egress at
/// `api.coinset.org` — which degrades the same transport this node's wallet reads through.
///
/// **The gate is the condition itself, not a flag beside it.** The probe asks the production
/// function for the one term a coin owned by `probe_peer` would carry; a typed accessor that can
/// answer returns `DeclaresThisPeer` for it, the probe flips, and the short-circuit removes itself
/// with no second switch to remember. An accessor that needs more than the term list stays
/// unreadable here, which withholds credit rather than granting it — the fail-closed direction.
fn declaration_source_is_readable() -> bool {
    let probe_peer = "00".repeat(32);
    let terms = [format!("dig-peer:{probe_peer}")];
    peer_declaration(&terms, &probe_peer) == PeerDeclaration::DeclaresThisPeer
}

/// Whether `claimed_coin_id` genuinely bonds `store_launcher_id` at `root_hash` for `epoch`.
///
/// This is the CHAIN half only. `Bonded` here means a real coin bonds this content — it does NOT
/// mean the peer offering the record is that coin's holder. [`verdict_for`] adds that question, and
/// it is the one that decides promotion.
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
pub fn chain_bond_verdict<S: ChainSource>(
    source: &S,
    store_launcher_id: Bytes32,
    root_hash: Bytes32,
    epoch: &BigInt,
    required_collateral: Option<u64>,
    claimed_coin_id: Bytes32,
) -> BondVerdict {
    chain_bond_verdict_and_coin(
        source,
        store_launcher_id,
        root_hash,
        epoch,
        required_collateral,
        claimed_coin_id,
    )
    .0
}

/// [`chain_bond_verdict`], additionally handing back the coin it read.
///
/// The ownership half needs the SAME `MirrorCoin` the chain half just re-derived. Returning it is
/// what keeps a bonded holder at two chain reads rather than four: the reads are outbound HTTPS to
/// a shared third party, so re-fetching to ask a second question about one coin doubles this
/// node's egress for no new information.
///
/// The coin is returned only alongside [`BondVerdict::Bonded`] — every other verdict is reached
/// before, or instead of, a coin that binds this claim.
fn chain_bond_verdict_and_coin<S: ChainSource>(
    source: &S,
    store_launcher_id: Bytes32,
    root_hash: Bytes32,
    epoch: &BigInt,
    required_collateral: Option<u64>,
    claimed_coin_id: Bytes32,
) -> (BondVerdict, Option<MirrorCoin>) {
    let record = match source.coin_record(claimed_coin_id) {
        Ok(Some(record)) => record,
        // The chain answered and there is no such coin. The publisher named something that does not
        // exist, which is a claim disproven rather than a claim unexamined.
        Ok(None) => return (BondVerdict::Unbonded, None),
        Err(_) => return (BondVerdict::Unverified, None),
    };

    // A spent coin locks nothing. Collateral is the coin remaining unspent; a reclaimed one is a
    // bond that has already been taken back.
    if record.is_spent() {
        return (BondVerdict::Unbonded, None);
    }

    // Step 1. Every mirror coin in existence shares this puzzle hash, so failing here says the coin
    // is not collateral of any kind.
    if record.coin.puzzle_hash != mirror_coin_puzzle_hash() {
        return (BondVerdict::Unbonded, None);
    }

    // Steps 2 and 3's asset id, and the owner step 4 needs, all come from EXECUTED on-chain code:
    // the parent's puzzle is run and its `CREATE_COIN` conditions searched for this coin. Nothing
    // here is taken from a memo, which is the only part of a mirror coin its publisher writes
    // freely.
    let creating_spend = match source.coin_spend(record.coin.parent_coin_info) {
        Ok(Some(spend)) => spend,
        // The coin exists, so its parent was spent; a source that cannot produce that spend has a
        // gap rather than an answer.
        Ok(None) | Err(_) => return (BondVerdict::Unverified, None),
    };

    let mirror = match MirrorCoin::from_creating_spend(&creating_spend, claimed_coin_id) {
        Ok(Some(mirror)) => mirror,
        // Established, and the answer is no: not a $DIG-collateral coin, or one advertising nothing.
        Ok(None) => return (BondVerdict::Unbonded, None),
        Err(MirrorError::ChainUnavailable(_)) => return (BondVerdict::Unverified, None),
        // Memos that will not decode. The publisher chose this coin id and chose those memos, so
        // this is its claim failing, not this node failing to look.
        Err(_) => return (BondVerdict::Unbonded, None),
    };

    // Step 4 — the one that binds the coin to THIS claim.
    if !mirror.advertises(store_launcher_id, root_hash, epoch) {
        return (BondVerdict::Unbonded, None);
    }

    // Step 3's magnitude (see the module docs for why it is not first).
    match required_collateral {
        Some(required) if mirror.collateral() < required => return (BondVerdict::Unbonded, None),
        Some(_) => {}
        None => return (BondVerdict::Unverified, None),
    }

    // The chain half is satisfied. WHOSE bond it is is a separate question -- see `verdict_for`.
    (BondVerdict::Bonded, Some(mirror))
}

/// The full verdict: the chain half, then **whose bond it is**.
///
/// A valid, fully-collateralised coin bonding exactly this content still says nothing about the
/// peer offering the record — every field of that record, the coin id included, was chosen by
/// whoever answered the lookup. Only the coin's own owner-written declaration of a peer closes that,
/// and this node cannot read one yet (see [`peer_declaration`]), so nothing is promoted today.
///
/// Credit is withheld, never subtracted: a record naming this coin may be a stranger's lie ABOUT the
/// coin's real holder, and demoting on it is what would make that lie pay.
///
/// **No chain is read at all while the ownership half has no source** (see
/// [`declaration_source_is_readable`]): with `Bonded` unreachable, the reads would be paid for an
/// answer this function is about to discard.
pub fn verdict_for<S: ChainSource>(
    source: &S,
    store_launcher_id: Bytes32,
    root_hash: Bytes32,
    epoch: &BigInt,
    required_collateral: Option<u64>,
    claiming_peer_id: &str,
    claimed_coin_id: Bytes32,
) -> BondVerdict {
    // Before any chain read: while nothing can bind a coin to a peer, `Bonded` is unreachable and
    // the reads below would be paid for a verdict this function is about to discard.
    if !declaration_source_is_readable() {
        return BondVerdict::Unverified;
    }
    let (chain, coin) = chain_bond_verdict_and_coin(
        source,
        store_launcher_id,
        root_hash,
        epoch,
        required_collateral,
        claimed_coin_id,
    );
    let Some(mirror) = coin else {
        // Every non-`Bonded` verdict arrives without a coin, and `Bonded` never arrives without one.
        return chain;
    };
    match peer_declaration(mirror.urls(), claiming_peer_id) {
        PeerDeclaration::DeclaresThisPeer => BondVerdict::Bonded,
        PeerDeclaration::Silent | PeerDeclaration::NotReadable => BondVerdict::Unverified,
    }
}

/// The memo of definite verdicts, keyed on the exact question each one answered.
///
/// Its own type, rather than two fields on the verifier, so the key/lookup/eviction rules can be
/// exercised directly — including the one that matters most and is invisible from the outside:
/// that a verdict earned by one claiming peer is never served to another.
#[derive(Default)]
struct VerdictCache {
    entries: Mutex<HashMap<VerdictKey, (Instant, BondVerdict)>>,
}

impl VerdictCache {
    /// The verdict recorded for exactly this question, if one is recorded and still fresh.
    fn get(&self, key: &VerdictKey) -> Option<BondVerdict> {
        let entries = self.entries.lock().ok()?;
        entries
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
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        if entries.len() >= MAX_CACHED_VERDICTS {
            // Evict one arbitrary entry, not the map. `HashMap` iteration order is unspecified, so
            // the victim is not attacker-selectable either; the cost of a wrong guess is one chain
            // read, never a wrong answer.
            if let Some(victim) = entries.keys().next().copied() {
                entries.remove(&victim);
            }
        }
        entries.insert(key, (Instant::now(), verdict));
    }
}

/// The production [`MirrorBondVerifier`]: one bounded chain read per distinct claim, memoised.
pub struct ChainBondVerifier {
    chain: Arc<dig_wallet::sage::chain::ChainTransport>,
    cache: VerdictCache,
}

impl ChainBondVerifier {
    /// Verify against the node's own chain transport.
    pub fn new(chain: Arc<dig_wallet::sage::chain::ChainTransport>) -> Arc<Self> {
        Arc::new(ChainBondVerifier {
            chain,
            cache: VerdictCache::default(),
        })
    }

    /// The chain half: one bounded read, memoised.
    #[allow(clippy::too_many_arguments)]
    async fn verify_against_chain(
        &self,
        key: VerdictKey,
        store: Bytes32,
        root: Bytes32,
        epoch: u64,
        required: Option<u64>,
        claiming_peer_id: &str,
        coin_id: [u8; 32],
    ) -> BondVerdict {
        // Corroborated, never the router (dig-node#503). `chain_source` asks `api.coinset.org`
        // first and consults this node's peers only when that read fails -- its own `ProviderInfo`
        // says `trustless: false` -- so a `Bonded` verdict taken from it rests on ONE source's
        // word. Every check below is internal consistency of a coin and its creating spend, and
        // all of them pass on a coin curried around an invented parent that was never on mainnet.
        // Only chain MEMBERSHIP disproves that, and membership is what a single endpoint cannot
        // settle.
        //
        // No fallback here, deliberately: `corroborated_chain_source` errs rather than handing
        // back the router, and this reads that as `Unverified`. Falling back would let one
        // endpoint overrule the peers exactly when they failed to agree.
        //
        // Re-read per call rather than held from bring-up, matching the mirror pass: a transport
        // built once would make a node that started offline one that never verifies again.
        let Ok(source) = self
            .chain
            .corroborated_chain_source(tokio::runtime::Handle::current())
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

        self.cache.remember(key, verdict);
        verdict
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

/// This node's current epoch, or `None` when it is not yet settled.
///
/// Clock arithmetic only — no file is touched, which is why the cache can be probed under the TRUE
/// current epoch rather than under a remembered hint. A hint would hit an entry stored under the
/// previous epoch for up to [`VERDICT_TTL`] after a rollover, which is a verdict taken under the
/// wrong epoch and not merely a miss.
fn settled_epoch() -> Option<u64> {
    match current_epoch_now() {
        crate::collateral::CurrentEpoch::Final(epoch) => Some(epoch),
        _ => None,
    }
}

/// This node's censused per-store requirement for the current epoch, or `None` when it has no
/// record for it.
///
/// A file read plus a line-by-line JSON parse, so it is paid only on a cache miss.
fn current_requirement() -> Option<u64> {
    let current = current_epoch_now();
    match requirement(&EpochRecordStore::in_state_dir(), current) {
        CollateralRequirementResult::Known {
            required_per_store_dig_base_units,
            ..
        } => Some(required_per_store_dig_base_units),
        _ => None,
    }
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
        // Nothing below can produce `Bonded` while the ownership half has no source, so the whole
        // leg — cache, epoch, chain — is skipped rather than paid for a discarded answer.
        if !declaration_source_is_readable() {
            return BondVerdict::Unverified;
        }
        let Some(epoch) = settled_epoch() else {
            return BondVerdict::Unverified;
        };
        // The cheap in-memory probe first: a slate of records for one capsule otherwise pays the
        // epoch-record parse per record even when every verdict is already known.
        let key = VerdictKey::new(coin_id, store, root, epoch, claiming_peer_id);
        if let Some(hit) = self.cache.get(&key) {
            return hit;
        }

        self.verify_against_chain(
            key,
            store,
            root,
            epoch,
            current_requirement(),
            claiming_peer_id,
            coin_id,
        )
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
    use async_trait::async_trait;
    use dig_chainsource_interface::{CoinRecord, SingletonLineage};
    use dig_node_core::mirror_bond::{
        bond_verifier_slot, BondRankingLocator, CandidateAddr, DownloadError, PeerId,
        ProviderLocator, ProviderRecord,
    };
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    /// A chain that counts every read reaching it and answers nothing.
    ///
    /// Answering nothing is deliberate: the property under test is that the source is not consulted
    /// AT ALL, so a double that could satisfy a read would let a short-circuit that merely fails
    /// fast look identical to one that never asks.
    struct CountingChain {
        reads: Arc<AtomicUsize>,
    }

    impl CountingChain {
        fn counted<T>(&self, answer: T) -> Result<T, String> {
            self.reads.fetch_add(1, AtomicOrdering::Relaxed);
            Ok(answer)
        }
    }

    impl ChainSource for CountingChain {
        type Error = String;

        fn coin_record(&self, _coin_id: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
            self.counted(None)
        }

        fn coin_records_by_puzzle_hash(
            &self,
            _puzzle_hash: Bytes32,
            _include_spent: bool,
        ) -> Result<Vec<CoinRecord>, Self::Error> {
            self.counted(Vec::new())
        }

        fn coin_records_by_parent(&self, _parent: Bytes32) -> Result<Vec<CoinRecord>, Self::Error> {
            self.counted(Vec::new())
        }

        fn coin_spend(
            &self,
            _coin_id: Bytes32,
        ) -> Result<Option<chia_protocol::CoinSpend>, Self::Error> {
            self.counted(None)
        }

        fn resolve_singleton_lineage(
            &self,
            _launcher_id: Bytes32,
        ) -> Result<Option<SingletonLineage>, Self::Error> {
            self.counted(None)
        }

        fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
            self.counted(Some(1_000))
        }

        fn block_timestamp(&self, _height: u32) -> Result<Option<u64>, Self::Error> {
            self.counted(Some(1_700_000_000))
        }
    }

    const STORE: [u8; 32] = [0x11; 32];
    const ROOT: [u8; 32] = [0x22; 32];

    fn capsule() -> ContentId {
        ContentId::capsule(STORE, ROOT)
    }

    fn holder_at(peer: u8, coin: Option<[u8; 32]>, host: &str) -> ProviderRecord {
        let record = ProviderRecord::new(
            &capsule().to_key(),
            &PeerId::from_bytes([peer; 32]),
            vec![CandidateAddr::direct(host, 9444)],
            u64::MAX,
        );
        match coin {
            Some(id) => record.with_unverified_mirror_coin_id(id),
            None => record,
        }
    }

    /// A slate exactly as a single lookup answer would deliver it.
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

    /// A chain that answers YES to everything `verdict_for` can check without this node's own
    /// judgement: the coin exists, is unspent, is a mirror coin, is fully collateralised, and
    /// advertises exactly this `(store, root, epoch)`. The ONLY step left is the real production
    /// gate — [`peer_declaration`] — so this double cannot make the layer look safer than it is.
    struct EveryChainCheckPasses;

    #[async_trait]
    impl dig_node_core::mirror_bond::MirrorBondVerifier for EveryChainCheckPasses {
        async fn verify(
            &self,
            _content: &ContentId,
            claiming_peer_id: &str,
            claimed: Option<[u8; 32]>,
        ) -> BondVerdict {
            if claimed.is_none() {
                return BondVerdict::Unverified;
            }
            // The coin's memo tail as a coin owned by this claimant would carry it.
            let terms = vec![format!("dig-peer:{claiming_peer_id}")];
            match peer_declaration(&terms, claiming_peer_id) {
                PeerDeclaration::DeclaresThisPeer => BondVerdict::Bonded,
                PeerDeclaration::Silent | PeerDeclaration::NotReadable => BondVerdict::Unverified,
            }
        }
    }

    /// **Proves (dig-node#466, HIGH finding 2 — the residual the credit-only lattice does NOT
    /// close):** a hearsay record naming an honest holder's peer id AND its real coin id, but
    /// carrying the ATTACKER's addresses, is not promoted — so the address a redirected reader
    /// dials is unchanged by it.
    ///
    /// **Catches:** the hole neither other test can see. Every field of this record is honest
    /// except the one that matters, so a coin-id check passes, a peer-id check passes, and the peer
    /// id is IDENTICAL in the passing and failing versions of the code — which is why the assertion
    /// is on the addresses. `stop_on_providers` means one answer can be the whole slate, so a
    /// promotion here puts the attacker's host first for every reader that trusts the ranking, and
    /// the dial does not pin the peer id (DIG-Network/dig-gossip#85) to catch it afterwards.
    ///
    /// The verifier is driven through the REAL [`peer_declaration`] gate rather than a hand-written
    /// verdict, so this test measures production's answer: with no sound coin -> peer binding
    /// available, nothing is promoted at all.
    #[tokio::test]
    async fn an_honest_peer_id_with_attacker_addresses_is_not_promoted() {
        let slate = Slate(vec![
            holder_at(0xCC, None, "honest.example"), // an ordinary holder, no pointer
            holder_at(0xAA, Some([0x01; 32]), "attacker.example"),
        ]);
        let slot = bond_verifier_slot();
        let _ = slot.set(Arc::new(EveryChainCheckPasses));
        let locator = BondRankingLocator::new(Arc::new(slate), slot);

        let got = locator.find_providers(&capsule()).await.expect("located");
        let hosts: Vec<String> = got.iter().map(|r| r.addresses[0].host.clone()).collect();

        assert_eq!(
            hosts,
            vec!["honest.example", "attacker.example"],
            "a record whose peer id and coin id are both honest must still not promote the \
             addresses it chose for itself"
        );
    }

    /// **Proves (dig-node#466, review round 2):** a verdict earned by one claiming peer is never
    /// served from the memo to a DIFFERENT peer naming the same coin for the same content.
    ///
    /// **Catches:** the ownership check being reinstated-then-bypassed through the cache. A coin id
    /// is a public fact published in provider records by design, so a stranger can republish
    /// another peer's coin id verbatim; if the key omitted the claimant, that stranger would be
    /// served the real holder's `Bonded` for the whole TTL and `verdict_for`'s second question
    /// would never be asked of it.
    ///
    /// The two lookups differ in EXACTLY one field — the claiming peer — and the same-peer read is
    /// asserted as a control, so a key that simply never hits would not pass.
    #[test]
    fn a_verdict_earned_by_one_peer_is_not_served_to_another() {
        let store = Bytes32::new(STORE);
        let root = Bytes32::new(ROOT);
        let coin = [0x33; 32];
        let holder = "aa".repeat(32);
        let stranger = "bb".repeat(32);

        let cache = VerdictCache::default();
        cache.remember(
            VerdictKey::new(coin, store, root, 7, &holder),
            BondVerdict::Bonded,
        );

        assert_eq!(
            cache.get(&VerdictKey::new(coin, store, root, 7, &holder)),
            Some(BondVerdict::Bonded),
            "control: the peer that earned the verdict is still served it"
        );
        assert_eq!(
            cache.get(&VerdictKey::new(coin, store, root, 7, &stranger)),
            None,
            "a stranger republishing the same coin id must re-ask, not inherit the holder's verdict"
        );
    }

    /// **Proves (dig-node#466, security F1):** no chain is read at all while nothing can bind a
    /// coin to a peer.
    ///
    /// **Catches:** the amplifier. The production `ChainSource` reaches `api.coinset.org`, and a
    /// `Bonded` that degrades to `Unverified` is the one verdict the cache refuses to hold — so
    /// each read is re-paid on every locate, up to the locate budget, for an answer the stable
    /// credit-only sort provably discards. The counting source makes the absence of that egress an
    /// assertion rather than a claim.
    ///
    /// The count is asserted at zero AND the verdict at `Unverified`, so a short-circuit that
    /// changed the answer would fail here rather than pass quietly.
    #[test]
    fn nothing_is_read_from_the_chain_while_the_declaration_has_no_source() {
        let reads = Arc::new(AtomicUsize::new(0));
        let source = CountingChain {
            reads: Arc::clone(&reads),
        };

        let verdict = verdict_for(
            &source,
            Bytes32::new(STORE),
            Bytes32::new(ROOT),
            &BigInt::from(7u64),
            Some(1),
            &"aa".repeat(32),
            Bytes32::new([0x33; 32]),
        );

        assert_eq!(
            verdict,
            BondVerdict::Unverified,
            "withholding credit is the answer the short-circuit must preserve"
        );
        assert_eq!(
            reads.load(AtomicOrdering::Relaxed),
            0,
            "a verdict that cannot be `Bonded` must cost no chain read"
        );
        assert!(
            !declaration_source_is_readable(),
            "control: the short-circuit is active precisely because the source is unreadable — \
             when 0.8.0's accessor lands this flips and the reads resume"
        );
    }

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
