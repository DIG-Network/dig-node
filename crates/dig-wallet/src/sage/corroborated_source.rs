//! [`CorroboratedChainSource`] — the canonical [`ChainSource`] served by the node's OWN Chia peers,
//! believed only on agreement (dig-node#503).
//!
//! # The single-source hole this closes
//!
//! [`super::chain::ChainTransport::chain_source`] hands out `chia-query`'s router, and its own
//! `ProviderInfo` says what that means: `trustless: false`, because with `coinset_fallback_enabled`
//! — the default every production fabric is built from — it asks `api.coinset.org` FIRST and
//! consults this node's dialled peers only when that read fails. The peers do not corroborate the
//! answer.
//!
//! For a balance read that is a latency choice. For a verdict that RANKS a peer — dig-node's mirror
//! bond verdict is the case this was built for — it is a forgery surface: the checks that promote a
//! holder to `Bonded` are all *internal consistency* of a coin and its creating spend, and every one
//! of them passes on a coin that was never on mainnet. An attacker can curry the real, public $DIG
//! CAT puzzle around an invented parent, compute the child id, and publish that id. Only chain
//! MEMBERSHIP disproves it, and membership is exactly what one endpoint's word cannot settle.
//!
//! # Why corroboration rather than a proof
//!
//! [`ChainSource`] exposes no block header, no merkle path, no inclusion proof; its one
//! proof-shaped primitive is `resolve_singleton_lineage`, and a mirror coin is a CAT with no
//! launcher. So verification-by-proof is not available here and agreement across independently
//! drawn peers is the answer — which is cheap in this case, because the whole verdict reduces to
//! two primitive reads: the coin record, and the spend that created it.
//!
//! [`super::peer_reads::PeerCorroboratedReads`] already corroborates exactly those two reads over
//! the peers this node dialled itself, inheriting `super::quorum::CORROBORATION_FLOOR` (never one
//! source) and `super::quorum::required_agreement`. This module is a thin [`ChainSource`] face over
//! it and invents no second agreement mechanism.
//!
//! # The failure direction, stated
//!
//! Every method here is allowed to be wrong in ONE direction only: it may refuse an answer the
//! chain would have given, and it may NEVER manufacture an absence. `Err` is UNKNOWN; `Ok(None)` is
//! reserved for the peers having AGREED the thing does not exist. That is why the reads this
//! surface cannot serve return `Err` rather than an empty `Vec` or `Ok(None)`: a caller reads an
//! empty answer as *the chain has no such thing* and acts on it, and on the bond path acting on a
//! fabricated absence is how a real holder gets demoted.
//!
//! There is deliberately NO fallback to the router. Falling through to one endpoint exactly when
//! the peers failed to agree would let that endpoint overrule them, which is the dependency this
//! whole module exists to remove.

use std::sync::Arc;

use chia_protocol::{Bytes32, Coin, CoinSpend, Program};
use chia_query::provider_registry::interface::{
    ChainSource, ChainSourceError, CoinRecord, SingletonLineage,
};

use super::fallback::{FallbackCoin, FallbackCoinSpend};
use super::peer_reads::PeerCorroboratedReads;

/// A [`ChainSource`] whose every answer came from several of the node's own peers agreeing.
///
/// Synchronous, because [`ChainSource`] is: each read bridges to the async corroborated round
/// through `handle`. `handle` MUST belong to a **multi-thread** tokio runtime — the bridge fails
/// closed with a clear error on a current-thread one rather than deadlocking.
pub struct CorroboratedChainSource {
    reads: Arc<PeerCorroboratedReads>,
    handle: tokio::runtime::Handle,
    /// How many peers must corroborate each read. [`super::quorum::CORROBORATION_FLOOR`] unless a
    /// caller asked for more via [`CorroboratedChainSource::requiring_corroboration`].
    floor: usize,
}

impl CorroboratedChainSource {
    /// A source over `reads`, bridging each blocking call onto `handle`.
    #[must_use]
    pub fn new(reads: Arc<PeerCorroboratedReads>, handle: tokio::runtime::Handle) -> Self {
        Self {
            reads,
            handle,
            floor: super::quorum::CORROBORATION_FLOOR,
        }
    }

    /// The same source, refusing any read fewer than `floor` peers corroborate.
    ///
    /// The seam a caller whose verdict RANKS a peer uses -- dig-node's mirror bond path passes
    /// [`super::quorum::BOND_CORROBORATION_FLOOR`] here. It is a caller's choice rather than this
    /// type's default because the two callers pay opposite prices for a refusal: the sync path
    /// stalls a replica, the bond path merely declines a promotion.
    ///
    /// A `floor` below [`super::quorum::CORROBORATION_FLOOR`] is not honoured; this can only
    /// tighten.
    #[must_use]
    pub fn requiring_corroboration(mut self, floor: usize) -> Self {
        self.floor = floor.max(super::quorum::CORROBORATION_FLOOR);
        self
    }

    /// Drives one corroborated read to completion from a synchronous caller.
    ///
    /// The same three-way shape `chia-query`'s own facade uses (its `run_blocking` is
    /// crate-private, so it cannot be called from here): inside a multi-thread runtime the read
    /// leaves the async worker via `block_in_place`; outside any runtime it blocks directly; on a
    /// CURRENT-THREAD runtime it refuses with a clear error instead of raising tokio's opaque
    /// panic.
    fn block_on<F: std::future::Future>(&self, fut: F) -> Result<F::Output, ChainSourceError> {
        match tokio::runtime::Handle::try_current() {
            Ok(current)
                if current.runtime_flavor() == tokio::runtime::RuntimeFlavor::CurrentThread =>
            {
                Err(ChainSourceError::Transport(
                    "corroborated chain source cannot block on a current-thread runtime"
                        .to_string(),
                ))
            }
            Ok(_) => guard_panics(|| tokio::task::block_in_place(|| self.handle.block_on(fut))),
            Err(_) => guard_panics(|| self.handle.block_on(fut)),
        }
    }
}

/// Runs `f`, converting a panic into a [`ChainSourceError::Transport`] so the synchronous
/// [`ChainSource`] boundary never unwinds (dig-node#513).
///
/// `chia-query`'s own bridge carries this backstop (`provider_registry::bridge::guard_panics`) and
/// this adapter, which replaces that bridge on the bond path, must not be weaker than the thing it
/// replaces. The runtime-flavour check above catches the misuse we can NAME; this catches the ones
/// we cannot. A panic crossing a `ChainSource` method has no defined behaviour for the caller --
/// on the bond path it would unwind out of a `block_in_place` inside a locate, taking a read-path
/// task with it, which turns a chain hiccup into a denial of the read the verdict was decorating.
///
/// `AssertUnwindSafe` because the future is consumed exactly once and a panic leaves no observable
/// half-mutated state behind this facade -- the same reasoning `chia-query` records for its own.
fn guard_panics<T>(f: impl FnOnce() -> T) -> Result<T, ChainSourceError> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).map_err(|_| {
        ChainSourceError::Transport(
            "corroborated chain source caught a panic while blocking on the async runtime"
                .to_string(),
        )
    })
}

/// The one spelling of a coin id [`PeerCorroboratedReads`] keys its cache on: lowercase hex, no
/// `0x`. `hex::encode` of the 32 bytes produces exactly that, so the key can never drift from the
/// bytes the caller asked about.
fn key_for(coin_id: Bytes32) -> String {
    hex::encode(coin_id)
}

/// 64 lowercase hex characters as the 32 bytes a coin field is.
fn bytes32(hex_str: &str, what: &str) -> Result<Bytes32, ChainSourceError> {
    let bytes = hex::decode(hex_str)
        .map_err(|_| ChainSourceError::Malformed(format!("{what} is not hex")))?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ChainSourceError::Malformed(format!("{what} is not 32 bytes")))?;
    Ok(Bytes32::from(array))
}

/// The coin an answer describes, refused unless it hashes to the id that was ASKED for.
///
/// A coin id IS `SHA256(parent | puzzle_hash | amount)`, so this is arithmetic no vote can outrank.
/// [`PeerCorroboratedReads`] already binds its own answers this way; repeating it here is what
/// makes THIS adapter's contract local and checkable rather than inherited — a caller holding a
/// [`CorroboratedChainSource`] can rely on it without reading the layer below. It also closes a gap
/// the bond path leaves open, since that path never asserts the record it got back IS the claimed
/// coin.
fn coin_bound_to(
    parent: &str,
    puzzle_hash: &str,
    amount: u64,
    requested: Bytes32,
) -> Result<Coin, ChainSourceError> {
    let coin = Coin {
        parent_coin_info: bytes32(parent, "parent coin id")?,
        puzzle_hash: bytes32(puzzle_hash, "puzzle hash")?,
        amount,
    };
    if coin.coin_id() != requested {
        return Err(ChainSourceError::Malformed(format!(
            "corroborated answer is about coin {} but {} was asked for",
            hex::encode(coin.coin_id()),
            hex::encode(requested)
        )));
    }
    Ok(coin)
}

/// A corroborated coin as the canonical record shape.
fn record_from(coin: &FallbackCoin, requested: Bytes32) -> Result<CoinRecord, ChainSourceError> {
    Ok(CoinRecord {
        coin: coin_bound_to(
            &coin.parent_coin_info,
            &coin.puzzle_hash,
            coin.amount,
            requested,
        )?,
        confirmed_height: coin.created_height,
        spent_height: coin.spent_height,
        timestamp: coin.created_timestamp,
        // A peer's coin state carries no coinbase flag. `false` is the shape
        // `CoinRecord::from_coin_state` already uses for the same absence, and nothing on the bond
        // path reads it.
        coinbase: false,
    })
}

/// A corroborated spend as the canonical spend shape.
fn spend_from(
    spend: &FallbackCoinSpend,
    requested: Bytes32,
) -> Result<CoinSpend, ChainSourceError> {
    let coin = coin_bound_to(
        &spend.parent_coin_info,
        &spend.puzzle_hash,
        spend.amount,
        requested,
    )?;
    let reveal = hex::decode(&spend.puzzle_reveal)
        .map_err(|_| ChainSourceError::Malformed("puzzle reveal is not hex".to_string()))?;
    let solution = hex::decode(&spend.solution)
        .map_err(|_| ChainSourceError::Malformed("solution is not hex".to_string()))?;
    Ok(CoinSpend::new(
        coin,
        Program::from(reveal),
        Program::from(solution),
    ))
}

impl ChainSource for CorroboratedChainSource {
    type Error = ChainSourceError;

    /// `Ok(Some(..))` — the peers agreed this coin exists and agreed on its fields.
    /// `Ok(None)` — they agreed it does NOT exist, which is a corroborated absence and safe to act
    /// on. `Err` — too few answered, or they disagreed: UNKNOWN, never absence.
    fn coin_record(&self, coin_id: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
        let key = key_for(coin_id);
        let answer = self
            .block_on(async {
                self.reads
                    .coin_record_by_id_at_floor(&key, self.floor)
                    .await
            })?
            .map_err(|e| ChainSourceError::Transport(e.to_string()))?;
        answer
            .as_ref()
            .map(|coin| record_from(coin, coin_id))
            .transpose()
    }

    /// The spend that spent `coin_id`, with the same three-way meaning as
    /// [`coin_record`](Self::coin_record).
    fn coin_spend(&self, coin_id: Bytes32) -> Result<Option<CoinSpend>, Self::Error> {
        let key = key_for(coin_id);
        let answer = self
            .block_on(async { self.reads.coin_spend_at_floor(&key, self.floor).await })?
            .map_err(|e| ChainSourceError::Transport(e.to_string()))?;
        answer
            .as_ref()
            .map(|spend| spend_from(spend, coin_id))
            .transpose()
    }

    /// Not served. **`Err`, never an empty `Vec`** — the corroborated surface answers by coin id
    /// only, and an empty list here would read as *no coin pays this puzzle hash*, which is a
    /// fabricated absence rather than an unanswered question.
    fn coin_records_by_puzzle_hash(
        &self,
        _puzzle_hash: Bytes32,
        _include_spent: bool,
    ) -> Result<Vec<CoinRecord>, Self::Error> {
        Err(ChainSourceError::Unsupported(
            "corroborated peer reads answer by coin id, not by puzzle hash",
        ))
    }

    /// Not served, for the same reason as
    /// [`coin_records_by_puzzle_hash`](Self::coin_records_by_puzzle_hash).
    fn coin_records_by_parent(
        &self,
        _parent_coin_id: Bytes32,
    ) -> Result<Vec<CoinRecord>, Self::Error> {
        Err(ChainSourceError::Unsupported(
            "corroborated peer reads answer by coin id, not by parent",
        ))
    }

    /// Not served. `Ok(None)` would claim the launcher never existed or the singleton was melted;
    /// this source simply cannot walk one.
    fn resolve_singleton_lineage(
        &self,
        _launcher_id: Bytes32,
    ) -> Result<Option<SingletonLineage>, Self::Error> {
        Err(ChainSourceError::Unsupported(
            "corroborated peer reads do not walk singleton lineages",
        ))
    }

    /// The peak the node's peers SETTLED on.
    ///
    /// The two `None`s here mean different things, and collapsing them would be a lie in the
    /// permissive direction. `PeerCorroboratedReads::peak_height` returns `None` for *the peers did
    /// not agree, or too few of them spoke* — an unknown. `ChainSource::peak_height`'s `Ok(None)`
    /// means *this source does not expose a peak at all* — a settled fact a caller may act on. So
    /// the unknown maps to `Err`.
    fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
        match self.block_on(async { self.reads.peak_height().await })? {
            Some(height) => Ok(Some(height)),
            None => Err(ChainSourceError::Transport(
                "the node's peers did not settle on a peak height".to_string(),
            )),
        }
    }

    /// Not served. A peer round here answers coin questions; `Ok(None)` would assert there is no
    /// such block.
    fn block_timestamp(&self, _height: u32) -> Result<Option<u64>, Self::Error> {
        Err(ChainSourceError::Unsupported(
            "corroborated peer reads do not resolve block timestamps",
        ))
    }
}

#[cfg(test)]
mod tests {
    //! dig-node#513 item 5 -- this adapter replaces `chia-query`'s bridge on the bond path, and
    //! must not be weaker than the thing it replaces.

    use std::sync::Arc;

    use super::*;
    use crate::sage::peer_reads::{CoinPeer, PeerSample};
    use crate::sage::db::WalletDb;

    /// A sample that holds no peers -- enough to build a source, since these cases never read.
    struct NoPeers;

    #[async_trait::async_trait]
    impl PeerSample for NoPeers {
        async fn draw(&self) -> Vec<Arc<dyn CoinPeer>> {
            Vec::new()
        }
    }

    async fn source() -> CorroboratedChainSource {
        let db = WalletDb::open_in_memory()
            .await
            .expect("in-memory wallet db");
        let reads = Arc::new(PeerCorroboratedReads::new(Arc::new(NoPeers), db));
        CorroboratedChainSource::new(reads, tokio::runtime::Handle::current())
    }

    /// PROPERTY: a panic raised while blocking becomes a `ChainSourceError`, and does NOT unwind
    /// out of the synchronous trait boundary.
    ///
    /// NEAREST WRONG IMPLEMENTATION: the runtime-flavour check alone, which is what this adapter
    /// shipped with. It catches the misuse we can NAME and nothing else, while the bridge it
    /// replaces (`chia_query::provider_registry::bridge::guard_panics`) catches the rest. The
    /// assertion is on the RETURN, not on `catch_unwind` being present: a test that merely called
    /// `guard_panics` directly would pass with the backstop deleted from `block_on`, so this drives
    /// it through the real path.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_panic_while_blocking_becomes_an_error_rather_than_unwinding() {
        let source = source().await;
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));

        let outcome: Result<(), ChainSourceError> =
            source.block_on(async { panic!("a read panicked") });

        std::panic::set_hook(previous);
        assert!(
            matches!(outcome, Err(ChainSourceError::Transport(_))),
            "a panic crossed the ChainSource boundary instead of becoming an error"
        );
    }

    /// PROPERTY: the control -- the guarded path still RETURNS an ordinary value, so the case above
    /// is not satisfied by a `block_on` that errs unconditionally.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_ordinary_read_still_returns_its_value_through_the_guard() {
        let source = source().await;
        assert_eq!(source.block_on(async { 7u32 }).ok(), Some(7));
    }

    /// PROPERTY: the bond floor is a caller's choice and can only TIGHTEN.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_corroboration_floor_can_only_tighten() {
        let strict = source()
            .await
            .requiring_corroboration(super::super::quorum::BOND_CORROBORATION_FLOOR);
        assert_eq!(strict.floor, super::super::quorum::BOND_CORROBORATION_FLOOR);

        let relaxed = source().await.requiring_corroboration(1);
        assert_eq!(
            relaxed.floor,
            super::super::quorum::CORROBORATION_FLOOR,
            "a caller talked the source down to a single source"
        );
    }
}
