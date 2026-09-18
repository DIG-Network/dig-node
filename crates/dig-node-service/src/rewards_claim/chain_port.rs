//! `RealClaimChainPort` -- the production [`super::port::ClaimChainPort`] adapter over
//! `dig-rewards-coin` 0.7.0 and this node's own [`dig_wallet::sage::corroborated_source::CorroboratedChainSource`]
//! (DIG-Network/dig_ecosystem#3347). Until this file existed, [`super::port::UnavailableClaimChainPort`]
//! was the ONLY adapter this trait had, so every real cycle reported `ChainSourceUnavailable` --
//! see [`super`]'s module doc, "the chain seam", for the history.
//!
//! # What this adapter can and cannot do on 0.7.0
//!
//! Discovery, comment resolution, the reserve asset id and the chain-curried payout threshold are
//! all real reads. [`RealClaimChainPort::own_entry`] is real for `payout_puzzle_hash` and
//! `counter`, but 0.7.0 exposes no PUBLIC, PURE function that computes an entry's accrued amount
//! without also spending it -- the only place that arithmetic exists is
//! `chia_sdk_driver::RewardDistributorInitiatePayoutAction::spend`, which mutates the distributor
//! and the entry slot as a side effect of computing it. Re-deriving the same
//! `shares * (cumulative_payout - initial_cumulative_payout) / precision` formula here would be
//! the exact hand-rolled-money-arithmetic-in-the-wrong-layer shape DIG-Network/dig_ecosystem#3286
//! named, and returning `0` would misreport a real accrual as "below threshold" -- so `own_entry`
//! refuses instead, naming the blocker: `dig_ecosystem#3356`.
//!
//! [`RealClaimChainPort::submit_initiate_payout`] refuses for a harder reason: 0.7.0's
//! `payout::initiate_payout` needs an `EntrySlotSource` yielding a `Slot<RewardDistributorEntrySlotValue>`
//! carrying the CREATING distributor coin's real `LineageProof`, and `state.rs`'s own module doc
//! says its reader fabricates a dummy (all-zero) `LineageProof` for exactly this shape --
//! `DistributorSnapshot` is a READ model, not a spendable one. Building a real proof here would be
//! reconstructing spend machinery in the wrong crate layer, so this refuses too, naming the same
//! blocker.
//!
//! Both refusals map, via `ClaimEngine`, to a NAMED `ClaimOutcome::Faulted` -- visible on the
//! status surface, never a silent success.

use std::sync::Arc;

use async_trait::async_trait;
use chia_protocol::Bytes32;
use dig_chainsource_interface::ChainSource;

use crate::rewards::chain_source::{read_distributor_guarded, GuardedReadError};

use super::port::{ClaimChainPort, ClaimPortError};
use super::types::{DiscoveredDistributor, OwnEntry};

/// DIG-Network/dig_ecosystem#3356 -- the `dig-rewards-coin` 0.8.0 ticket this adapter's two
/// unbuildable methods are blocked on. Named once so both refusal strings (and any future one)
/// stay in agreement about which ticket to point at.
const ACCRUED_AND_SUBMIT_BLOCKER: &str = "dig_ecosystem#3356";

/// The longest a chain port's own error text is allowed to carry before it is truncated -- the
/// same 200-char discipline [`super::types::ClaimOutcome::Faulted`]'s `reason` field documents,
/// applied here at the source so every producer of a bounded string agrees on the bound.
const MAX_ERROR_CHARS: usize = 200;

fn bounded(message: impl Into<String>) -> String {
    let message = message.into();
    if message.chars().count() <= MAX_ERROR_CHARS {
        message
    } else {
        let truncated: String = message.chars().take(MAX_ERROR_CHARS).collect();
        format!("{truncated}... (truncated)")
    }
}

/// Proposes launcher ids for [`RealClaimChainPort::discover_distributors`] to try -- SPEC 13.1
/// clause 2 needs a chain-wide enumerator and [`ChainSource`] has none of its own. An index only
/// PROPOSES: every id it returns is still re-verified through `dig_rewards_coin::discover_distributor`
/// inside `discover_distributors`, so an index that lies (or is merely stale) yields nothing,
/// never a forged discovery.
#[async_trait]
pub trait LauncherIndex: Send + Sync {
    /// The launcher ids this index currently believes are worth trying. May include ids that turn
    /// out not to be DIG rewards distributors at all -- that is `discover_distributors`'s filter to
    /// apply, not this trait's.
    async fn launcher_ids(&self) -> Result<Vec<Bytes32>, ClaimPortError>;
}

/// The real, chain-backed [`ClaimChainPort`] -- generic over the [`ChainSource`] (production:
/// [`dig_wallet::sage::corroborated_source::CorroboratedChainSource`], tests:
/// `dig_chainsource_interface::MockChainSource`) and the [`LauncherIndex`] (production:
/// [`HintedLauncherIndex`], tests: a small fixture in this crate's own test binaries).
pub struct RealClaimChainPort<S, I>
where
    S: ChainSource + Send + Sync + 'static,
    I: LauncherIndex,
{
    source: Arc<S>,
    index: I,
}

impl<S, I> RealClaimChainPort<S, I>
where
    S: ChainSource + Send + Sync + 'static,
    I: LauncherIndex,
{
    /// Wraps an already-constructed chain source and launcher index. Takes the source by `Arc`
    /// (mirroring `rewards::chain_port::RealRewardsChainPort::new`) since a blocking read clones it
    /// into a `spawn_blocking` closure on every call.
    #[must_use]
    pub fn new(source: Arc<S>, index: I) -> Self {
        Self { source, index }
    }
}

/// Maps a [`GuardedReadError`] (this crate's own `epoch_seconds == 0` refusal, or
/// `dig_rewards_coin::state::read_distributor`'s own error) onto [`ClaimPortError`].
fn guarded_read_error_to_claim_port_error(error: GuardedReadError) -> ClaimPortError {
    match error {
        GuardedReadError::NonTerminatingEpochSeconds => ClaimPortError::Other(bounded(
            "refused: this distributor's epoch_seconds is 0, which would hang \
             commit_incentives's generation walk (see chain_source.rs's module doc)",
        )),
        GuardedReadError::Reader(dig_rewards_coin::RewardsError::ChainUnavailable(_)) => {
            ClaimPortError::Unavailable
        }
        GuardedReadError::Reader(other) => ClaimPortError::Other(bounded(other.to_string())),
    }
}

/// Maps a `dig_rewards_coin::RewardsError` from `discover_distributor` onto [`ClaimPortError`] --
/// the same `ChainUnavailable` split as [`guarded_read_error_to_claim_port_error`], applied to the
/// discovery module's own error type instead of the guarded-read one.
fn rewards_error_to_claim_port_error(error: dig_rewards_coin::RewardsError) -> ClaimPortError {
    match error {
        dig_rewards_coin::RewardsError::ChainUnavailable(_) => ClaimPortError::Unavailable,
        other => ClaimPortError::Other(bounded(other.to_string())),
    }
}

/// Re-derives one launcher id's generation over `source`, verifying it through the real
/// parent-spend memo decode rather than trusting the id alone (SPEC 13.1 clause 6: a discovered
/// distributor's own fields are never caller input). `Ok(None)` covers BOTH "unknown to `source`"
/// and "not a DIG rewards distributor" -- neither is an error (SPEC §1.3).
fn resolve_via_chain<S>(
    source: &S,
    launcher_id: Bytes32,
) -> Result<Option<DiscoveredDistributor>, ClaimPortError>
where
    S: ChainSource,
{
    let discovered = dig_rewards_coin::discover_distributor(source, launcher_id)
        .map_err(rewards_error_to_claim_port_error)?;

    Ok(discovered.map(|d| {
        let generation = d.generation();
        DiscoveredDistributor {
            launcher_id: d.launcher_id(),
            store_id: generation.store_id,
            root: generation.root,
        }
    }))
}

#[async_trait]
impl<S, I> ClaimChainPort for RealClaimChainPort<S, I>
where
    S: ChainSource + Send + Sync + 'static,
    I: LauncherIndex,
{
    /// `&'static str` naming this adapter -- see the trait's own doc. Never a default impl, so a
    /// new adapter must choose its own name rather than silently inheriting one that describes a
    /// different adapter.
    fn kind(&self) -> &'static str {
        "real-corroborated"
    }

    async fn discover_distributors(&self) -> Result<Vec<DiscoveredDistributor>, ClaimPortError> {
        let candidate_ids = self.index.launcher_ids().await?;
        let source = Arc::clone(&self.source);

        tokio::task::spawn_blocking(move || {
            let mut discovered = Vec::new();
            for launcher_id in candidate_ids {
                // SPEC 13.1 clause 6: the index only PROPOSES; every id is re-verified through the
                // real memo decode. An id the decode rejects (unknown to `source`, or a spend that
                // is not a DIG rewards launch) is DROPPED, never echoed back.
                match resolve_via_chain(source.as_ref(), launcher_id) {
                    Ok(Some(distributor)) => discovered.push(distributor),
                    Ok(None) => {}
                    Err(ClaimPortError::Unavailable) => return Err(ClaimPortError::Unavailable),
                    Err(other) => return Err(other),
                }
            }
            Ok(discovered)
        })
        .await
        .map_err(|join_error| {
            ClaimPortError::Other(bounded(format!(
                "discover_distributors task panicked: {join_error}"
            )))
        })?
    }

    async fn resolve_launch_comment(
        &self,
        launcher_id: Bytes32,
    ) -> Result<Option<DiscoveredDistributor>, ClaimPortError> {
        let source = Arc::clone(&self.source);
        tokio::task::spawn_blocking(move || resolve_via_chain(source.as_ref(), launcher_id))
            .await
            .map_err(|join_error| {
                ClaimPortError::Other(bounded(format!(
                    "resolve_launch_comment task panicked: {join_error}"
                )))
            })?
    }

    async fn reserve_asset_id(&self, launcher_id: Bytes32) -> Result<Bytes32, ClaimPortError> {
        let source = Arc::clone(&self.source);
        tokio::task::spawn_blocking(move || {
            let snapshot = read_distributor_guarded(source.as_ref(), launcher_id)
                .map_err(guarded_read_error_to_claim_port_error)?
                .ok_or_else(|| {
                    ClaimPortError::Other(bounded("not a distributor: launcher coin unspent"))
                })?;
            Ok(snapshot.distributor().info.constants.reserve_asset_id)
        })
        .await
        .map_err(|join_error| {
            ClaimPortError::Other(bounded(format!("reserve_asset_id task panicked: {join_error}")))
        })?
    }

    async fn payout_threshold(&self, launcher_id: Bytes32) -> Result<u64, ClaimPortError> {
        let source = Arc::clone(&self.source);
        tokio::task::spawn_blocking(move || {
            let snapshot = read_distributor_guarded(source.as_ref(), launcher_id)
                .map_err(guarded_read_error_to_claim_port_error)?
                .ok_or_else(|| {
                    ClaimPortError::Other(bounded("not a distributor: launcher coin unspent"))
                })?;
            // Chain-curried, per SPEC §8.3 -- never `dig_rewards_coin::PAYOUT_THRESHOLD_BASE_UNITS`
            // (that constant is this distributor's DEFAULT launch value, not what any given
            // on-chain distributor was actually launched with; a distributor with a
            // non-default threshold would silently mis-evaluate against the literal).
            Ok(dig_rewards_coin::payout::payout_threshold_base_units(
                snapshot.distributor(),
            ))
        })
        .await
        .map_err(|join_error| {
            ClaimPortError::Other(bounded(format!("payout_threshold task panicked: {join_error}")))
        })?
    }

    async fn own_entry(
        &self,
        launcher_id: Bytes32,
        payout_puzzle_hash: Bytes32,
    ) -> Result<Option<OwnEntry>, ClaimPortError> {
        let source = Arc::clone(&self.source);
        tokio::task::spawn_blocking(move || {
            // SPEC §10.2/§12.5: fresh on EVERY call -- no cache field of any kind on this adapter.
            let snapshot = read_distributor_guarded(source.as_ref(), launcher_id)
                .map_err(guarded_read_error_to_claim_port_error)?
                .ok_or_else(|| {
                    ClaimPortError::Other(bounded("not a distributor: launcher coin unspent"))
                })?;

            let Some(entry) = snapshot
                .slots()
                .entries
                .iter()
                .find(|e| e.payout_puzzle_hash == payout_puzzle_hash)
            else {
                return Ok(None);
            };

            // See this module's doc: 0.7.0 has no public, pure function to compute what this entry
            // has accrued without also spending it, and this adapter refuses to re-derive the
            // money arithmetic itself or to fabricate a `0`.
            Err(ClaimPortError::Other(bounded(format!(
                "accrued amount unreadable on dig-rewards-coin 0.7.0: no public function computes \
                 an entry's accrued base units without spending it; blocked on \
                 {ACCRUED_AND_SUBMIT_BLOCKER}"
            ))))
        })
        .await
        .map_err(|join_error| {
            ClaimPortError::Other(bounded(format!("own_entry task panicked: {join_error}")))
        })?
    }

    async fn required_fee_mojos(&self, _launcher_id: Bytes32) -> Result<u64, ClaimPortError> {
        // This adapter attaches no fee coin and signs nothing: `InitiatePayout` is permissionless
        // (SPEC §7.1, `require_payout_approval = false`) and the reserve pays out via a
        // singleton-delegated announcement, not a fee this node fronts. Node policy, not a chain
        // read -- so `0` here is not a fabricated chain answer, it is what this adapter charges.
        Ok(0)
    }

    async fn submit_initiate_payout(
        &self,
        _launcher_id: Bytes32,
        _payout_puzzle_hash: Bytes32,
        _fee_mojos: u64,
    ) -> Result<(), ClaimPortError> {
        // See this module's doc: 0.7.0 exposes no chain-backed spendable entry slot and no real
        // reserve lineage proof -- `DistributorSnapshot` is a read model. Reconstructing one here
        // would be hand-rolled spend machinery in the wrong crate layer. Refused, named, visible
        // via `ClaimEngine`'s mapping to `ClaimOutcome::Faulted` -- never a silent success.
        Err(ClaimPortError::Other(bounded(format!(
            "payout submission blocked on {ACCRUED_AND_SUBMIT_BLOCKER}: dig-rewards-coin 0.7.0 has \
             no chain-backed spendable entry slot or real reserve lineage proof"
        ))))
    }
}

/// The production [`LauncherIndex`]: proposes every launcher coin this node's own peers have seen
/// hinted with the DIG rewards distributor hint (SPEC 13.1 clause 5's literal,
/// `"Reward Distributor v1"`, tree-hashed here rather than written as a hash literal), filtered to
/// an actual singleton-launcher coin.
///
/// Every id this proposes is still re-verified through `discover_distributor` by
/// [`RealClaimChainPort::discover_distributors`] -- a hinted coin that is not really a
/// DIG-rewards-launching singleton launcher yields nothing, it is never trusted directly.
pub struct HintedLauncherIndex {
    wallet_chain: Arc<dig_wallet::sage::chain::ChainTransport>,
}

impl HintedLauncherIndex {
    /// Wraps the node's own wallet chain transport -- the SAME `Arc` `server.rs` holds as
    /// `state.wallet_chain`.
    #[must_use]
    pub fn new(wallet_chain: Arc<dig_wallet::sage::chain::ChainTransport>) -> Self {
        Self { wallet_chain }
    }
}

#[async_trait]
impl LauncherIndex for HintedLauncherIndex {
    async fn launcher_ids(&self) -> Result<Vec<Bytes32>, ClaimPortError> {
        use dig_wallet::sage::fallback::ChainFallback;

        // SPEC 13.1 clause 5: the hint is COMPUTED as the tree hash of the literal string, never a
        // hash literal -- the identical discipline `dig_rewards_coin::discovery`'s own decode
        // applies to the same constant.
        let mut allocator = clvmr::Allocator::new();
        let hint_ptr = clvmr::serde::node_from_bytes(
            &mut allocator,
            &clvm_traits::ToClvm::to_clvm(&"Reward Distributor v1", &mut allocator)
                .map_err(|error| {
                    ClaimPortError::Other(bounded(format!(
                        "could not allocate the launcher hint literal: {error}"
                    )))
                })?
                .to_bytes(&allocator),
        )
        .map_err(|error| {
            ClaimPortError::Other(bounded(format!(
                "could not re-decode the launcher hint literal: {error}"
            )))
        })?;
        let hint: chia_protocol::Bytes32 = clvm_utils::tree_hash(&allocator, hint_ptr).into();
        let hint_hex = hex::encode(hint.to_bytes());

        let coins = self
            .wallet_chain
            .coin_records_by_hints(&[hint_hex])
            .await
            .map_err(|error| ClaimPortError::Other(bounded(error.to_string())))?;

        let launcher_hash_hex = hex::encode(chia_puzzles::SINGLETON_LAUNCHER_HASH);

        Ok(coins
            .into_iter()
            .filter(|coin| coin.puzzle_hash == launcher_hash_hex)
            .filter_map(|coin| {
                hex::decode(&coin.coin_id)
                    .ok()
                    .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                    .map(Bytes32::from)
            })
            .collect())
    }
}
