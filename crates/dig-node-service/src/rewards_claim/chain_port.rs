//! `RealClaimChainPort` -- the production [`super::port::ClaimChainPort`] adapter over
//! `dig-rewards-coin` 0.8.0 and this node's own [`dig_wallet::sage::corroborated_source::CorroboratedChainSource`]
//! (DIG-Network/dig_ecosystem#3347). Until this file existed, [`super::port::UnavailableClaimChainPort`]
//! was the ONLY adapter this trait had, so every real cycle reported `ChainSourceUnavailable` --
//! see [`super`]'s module doc, "the chain seam", for the history.
//!
//! # Every method is a real chain read or a real broadcast
//!
//! Discovery, comment resolution, the reserve asset id and the chain-curried payout threshold are
//! all real reads. [`RealClaimChainPort::own_entry`] reads the real accrued amount via
//! `dig_rewards_coin::accrued_base_units` -- a public, pure function 0.8.0 added -- applied to a
//! freshly chain-read entry slot; it never fabricates `0` and never caches across calls.
//! [`RealClaimChainPort::submit_initiate_payout`] builds and broadcasts a real `InitiatePayout`
//! spend: the entry slot comes ONLY from `dig_rewards_coin::ChainEntrySlotSource` (a fresh,
//! authenticated chain walk, `SPEC.md` §12.5 clause 3a on `dig-rewards-coin`'s side) -- **never**
//! `RewardDistributor::created_slot_value_to_slot` on a chain-rebuilt distributor, which derives a
//! well-formed but PHANTOM `LineageProof` for a slot an earlier generation created
//! (DIG-Network/dig_ecosystem#3357). `initiate_payout`'s returned `conditions` are a CALLER-SIDE
//! assertion for a coin the caller would add to the same bundle; this adapter adds no coin of its
//! own (no fee coin, no key, nothing to sign -- `required_fee_mojos` is `0`), so it drops them when
//! it proceeds -- the simulator acceptance test in `tests/rewards_claim_chain_port_3347.rs` is the
//! proof the resulting bundle is accepted without them for `require_payout_approval = false`. When
//! the chain-curried `require_payout_approval` is `true` instead, dropping `conditions` would be
//! dropping the manager's approval assertion, not a no-op -- [`RealClaimChainPort::submit_initiate_payout`]
//! REFUSES by name in that case, before building anything, rather than broadcasting a bundle this
//! adapter cannot honestly satisfy (DIG-Network/dig_ecosystem#3362).
//!
//! A silent no-op would be the exact defect this ticket exists to prevent -- a refused method
//! reports a NAMED [`ClaimPortError`], never a fabricated success.

use std::sync::Arc;

use async_trait::async_trait;
use chia_protocol::{Bytes32, SpendBundle};
use chia_sdk_driver::{RewardDistributorConstants, RewardDistributorState, SpendContext};
use chia_sdk_types::puzzles::RewardDistributorEntrySlotValue;
use dig_chainsource_interface::ChainSource;
use dig_rewards_coin::payout::{initiate_payout, PayoutOutcome};
use dig_rewards_coin::ChainEntrySlotSource;
use dig_wallet::sage::spend::Broadcaster;

use crate::rewards::chain_source::{read_distributor_guarded, GuardedReadError};

use super::port::{ClaimChainPort, ClaimPortError};
use super::types::{DiscoveredDistributor, Discovery, OwnEntry};

/// The longest a chain port's own error text is allowed to carry before it is truncated -- the
/// same 200-char discipline [`super::types::ClaimOutcome::Faulted`]'s `reason` field documents,
/// applied here at the source so every producer of a bounded string agrees on the bound.
const MAX_ERROR_CHARS: usize = 200;

/// DIG-Network/dig_ecosystem#3358: the most hinted launcher candidates
/// [`RealClaimChainPort::discover_distributors`] will decode in one call.
///
/// # Where the number comes from
/// `dig_rewards_coin`'s own `DECODE_MAX_SERIALIZED_BYTES` bounds ONE candidate's decode at 64 KiB
/// (65_536 bytes); `256 * 65_536 = 16_777_216` bytes -- a 16 MiB decode ceiling for one
/// `discover_distributors` call -- plus 256 parent-spend chain reads, one per candidate.
///
/// # What this bound does NOT cover -- read this before assuming discovery is safe
/// 1. It does not bound gossip hints: `ClaimEngine::run_cycle`'s hint loop (`engine.rs`,
///    `self.hints.hints()`, feeding `resolve_launch_comment` one candidate at a time) is a
///    SEPARATE, unbounded path -- out of scope for this cap, named here so it is not mistaken for
///    covered.
/// 2. It does not choose WHICH candidates survive: this adapter decodes the index's first N in
///    WHATEVER ORDER the chain transport returned them, and that order is attacker-influenceable
///    (`HintedLauncherIndex` proposes every hinted coin its peers have seen) -- a flood of bogus
///    hinted coins ahead of a legitimate launcher in that order can push the legitimate one past
///    the cap and out of this cycle's candidate set.
/// 3. It does not persist "already decoded and rejected" across calls -- a dropped-for-real
///    candidate is re-attempted (and can be re-dropped) every cycle rather than being remembered
///    and skipped cheaply; left as a follow-up, not implemented here.
/// 4. It does not bound the COST of decoding one candidate -- that is
///    `DECODE_MAX_SERIALIZED_BYTES`'s job, not this cap's.
/// 5. It authenticates nothing -- every surviving candidate is still re-verified through the real
///    memo decode in [`resolve_via_chain`] exactly as before this cap existed; this cap only
///    decides how many candidates get that far.
///
/// A drop is never silent: [`RealClaimChainPort::discover_distributors`] reports how many
/// candidates it declined via [`Discovery::candidates_dropped`], and
/// [`super::engine::ClaimEngine::run_cycle`] copies that count into
/// [`super::types::ClaimStatus::discovery_candidates_dropped_this_cycle`] and logs a `warn!` when
/// it is nonzero -- a silent cap on discovery is the exact censorship-primitive shape this ticket
/// exists to avoid.
pub const MAX_HINTED_LAUNCHER_CANDIDATES_PER_CYCLE: usize = 256;

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
    broadcaster: Arc<dyn Broadcaster>,
    /// DIG-Network/dig_ecosystem#3358: how many hinted candidates one `discover_distributors` call
    /// will decode -- [`MAX_HINTED_LAUNCHER_CANDIDATES_PER_CYCLE`] in production;
    /// [`Self::with_candidate_cap`] overrides it for a test that needs a small cap to exercise
    /// dropping without decoding hundreds of candidates.
    candidate_cap: usize,
}

impl<S, I> RealClaimChainPort<S, I>
where
    S: ChainSource + Send + Sync + 'static,
    I: LauncherIndex,
{
    /// Wraps an already-constructed chain source, launcher index and broadcaster. Takes the source
    /// by `Arc` (mirroring `rewards::chain_port::RealRewardsChainPort::new`) since a blocking read
    /// clones it into a `spawn_blocking` closure on every call. Uses the production
    /// [`MAX_HINTED_LAUNCHER_CANDIDATES_PER_CYCLE`] cap -- see [`Self::with_candidate_cap`] to
    /// override it.
    #[must_use]
    pub fn new(source: Arc<S>, index: I, broadcaster: Arc<dyn Broadcaster>) -> Self {
        Self {
            source,
            index,
            broadcaster,
            candidate_cap: MAX_HINTED_LAUNCHER_CANDIDATES_PER_CYCLE,
        }
    }

    /// Same as [`Self::new`] with an explicit candidate cap -- production never calls this; it
    /// exists so a test can pin a small cap and prove the drop-and-report behaviour without
    /// decoding hundreds of candidates.
    #[must_use]
    pub fn with_candidate_cap(
        source: Arc<S>,
        index: I,
        broadcaster: Arc<dyn Broadcaster>,
        candidate_cap: usize,
    ) -> Self {
        Self {
            source,
            index,
            broadcaster,
            candidate_cap,
        }
    }
}

/// The pure decision [`RealClaimChainPort::own_entry`] delegates to once it has (or has not)
/// found a matching entry slot -- kept separate from the chain read itself so it is unit-testable
/// without a real launch: no entry means `Ok(None)`, honestly; a found entry's accrual is computed
/// via `dig_rewards_coin::accrued_base_units`, the puzzle's own arithmetic (never re-derived here,
/// per DIG-Network/dig_ecosystem#3286) -- `None` from THAT means the arithmetic overflowed or
/// underflowed, refused by name rather than reported as a fabricated `0`.
fn own_entry_from_slot(
    payout_puzzle_hash: Bytes32,
    constants: &RewardDistributorConstants,
    state: &RewardDistributorState,
    entry: Option<&RewardDistributorEntrySlotValue>,
) -> Result<Option<OwnEntry>, ClaimPortError> {
    let Some(entry) = entry else {
        return Ok(None);
    };

    match dig_rewards_coin::accrued_base_units(constants, state, entry) {
        Some(accrued_base_units) => Ok(Some(OwnEntry {
            payout_puzzle_hash,
            counter: entry.counter,
            accrued_base_units,
        })),
        None => Err(ClaimPortError::Other(bounded(
            "accrued amount overflowed the puzzle's arithmetic; refusing rather than reporting 0",
        ))),
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

    async fn discover_distributors(&self) -> Result<Discovery, ClaimPortError> {
        let candidate_ids = self.index.launcher_ids().await?;
        let source = Arc::clone(&self.source);
        let candidate_cap = self.candidate_cap;

        tokio::task::spawn_blocking(move || {
            // DIG-Network/dig_ecosystem#3358: bound how many candidates one call will decode --
            // see MAX_HINTED_LAUNCHER_CANDIDATES_PER_CYCLE's doc for what this does and does not
            // protect. The drop count is REPORTED, never silently absorbed.
            let total = candidate_ids.len();
            let candidates_dropped = total.saturating_sub(candidate_cap) as u32;

            let mut discovered = Vec::new();
            for launcher_id in candidate_ids.into_iter().take(candidate_cap) {
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
            Ok(Discovery {
                distributors: discovered,
                candidates_dropped,
            })
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
            ClaimPortError::Other(bounded(format!(
                "reserve_asset_id task panicked: {join_error}"
            )))
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
            ClaimPortError::Other(bounded(format!(
                "payout_threshold task panicked: {join_error}"
            )))
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

            let entry = snapshot
                .entry_slot(payout_puzzle_hash)
                .map_err(rewards_error_to_claim_port_error)?;
            own_entry_from_slot(
                payout_puzzle_hash,
                &snapshot.distributor().info.constants,
                &snapshot.distributor().info.state,
                entry.map(|slot| &slot.info.value),
            )
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
        launcher_id: Bytes32,
        payout_puzzle_hash: Bytes32,
        fee_mojos: u64,
    ) -> Result<(), ClaimPortError> {
        // This adapter attaches no fee coin (see `required_fee_mojos`'s doc): a non-zero fee has
        // nowhere to be paid from here, so refuse by name rather than silently dropping it.
        if fee_mojos != 0 {
            return Err(ClaimPortError::Other(bounded(
                "this adapter attaches no fee coin; required_fee_mojos is 0 and a non-zero fee \
                 cannot be paid here",
            )));
        }

        let source = Arc::clone(&self.source);
        let built = tokio::task::spawn_blocking(move || {
            // SPEC §10.2/§12.5: fresh on EVERY call -- the same guarded, authenticated read every
            // other method here uses.
            let snapshot = read_distributor_guarded(source.as_ref(), launcher_id)
                .map_err(guarded_read_error_to_claim_port_error)?
                .ok_or_else(|| {
                    ClaimPortError::Other(bounded("not a distributor: launcher coin unspent"))
                })?;

            // DIG-Network/dig_ecosystem#3362: this distributor curries `require_payout_approval =
            // true`, meaning `InitiatePayout` needs a manager-signed approval assertion in the same
            // bundle. This adapter has no such assertion to attach and, per this module's doc,
            // DROPS `initiate_payout`'s returned `conditions` unconditionally -- proceeding here
            // would build a bundle the chain rejects, but only AFTER this adapter's caller had
            // already reported `Paid` to whatever recorded the attempt. Refuse by name instead,
            // before any spend is built.
            if snapshot
                .distributor()
                .info
                .constants
                .require_payout_approval
            {
                return Err(ClaimPortError::Other(bounded(
                    "refused: distributor curries require_payout_approval = true; this adapter \
                     carries no approval message (it drops initiate_payout's returned conditions), \
                     so the bundle it would build is one the chain rejects after reporting Paid",
                )));
            }

            // NEVER `snapshot.distributor().created_slot_value_to_slot(..)` -- that derives a
            // well-formed but PHANTOM `LineageProof` for a slot an earlier generation created
            // (DIG-Network/dig_ecosystem#3357, this module's doc). The entry slot for THIS spend
            // comes only from a fresh `ChainEntrySlotSource` walk.
            let mut distributor = snapshot.distributor().clone();
            let mut ctx = SpendContext::new();
            let slots = ChainEntrySlotSource::new(source.as_ref(), launcher_id);

            let outcome = initiate_payout(&mut ctx, &mut distributor, &slots, payout_puzzle_hash)
                .map_err(rewards_error_to_claim_port_error)?;

            let (_conditions, amount_base_units, counter) =
                match outcome {
                    PayoutOutcome::Paid {
                        conditions,
                        amount_base_units,
                        counter,
                    } => (conditions, amount_base_units, counter),
                    PayoutOutcome::EntrySlotAbsent => return Err(ClaimPortError::Other(bounded(
                        "entry slot absent at submission; the entry set moved between own_entry \
                         and submit",
                    ))),
                };
            // `conditions` is a CALLER-SIDE assertion for a coin the caller would add to the same
            // bundle (this module's doc) -- this adapter adds none, so it is dropped here rather
            // than threaded into a bundle with nothing to satisfy it.

            let (_distributor, signature) = distributor
                .finish_spend(&mut ctx, vec![])
                .map_err(|error| ClaimPortError::Other(bounded(error.to_string())))?;

            let bundle = SpendBundle::new(ctx.take(), signature);
            Ok::<_, ClaimPortError>((bundle, amount_base_units, counter))
        })
        .await
        .map_err(|join_error| {
            ClaimPortError::Other(bounded(format!(
                "submit_initiate_payout task panicked: {join_error}"
            )))
        })??;

        let (bundle, amount_base_units, counter) = built;
        let coin_spends = bundle.coin_spends.len();

        self.broadcaster.broadcast(&bundle).await.map_err(|error| {
            ClaimPortError::Other(bounded(format!("broadcast refused: {error}")))
        })?;

        tracing::info!(
            target: "rewards_claim",
            %launcher_id,
            amount_base_units,
            counter,
            coin_spends,
            "InitiatePayout submitted"
        );

        Ok(())
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
        let hint_ptr = clvm_traits::ToClvm::to_clvm(&"Reward Distributor v1", &mut allocator)
            .map_err(|error| {
                ClaimPortError::Other(bounded(format!(
                    "could not allocate the launcher hint literal: {error}"
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

#[cfg(test)]
mod tests {
    use super::*;
    use chia_sdk_driver::{RewardDistributorType, RoundRewardInfo, RoundTimeInfo};
    use chia_sdk_types::puzzles::RewardDistributorEntrySlotValue;

    fn some_constants(precision: u64) -> RewardDistributorConstants {
        RewardDistributorConstants {
            launcher_id: Bytes32::new([1; 32]),
            reward_distributor_type: RewardDistributorType::Managed {
                manager_singleton_launcher_id: Bytes32::new([7; 32]),
            },
            fee_payout_puzzle_hash: Bytes32::new([2; 32]),
            epoch_seconds: 1,
            precision,
            max_seconds_offset: 0,
            payout_threshold: 0,
            require_payout_approval: false,
            fee_bps: 0,
            withdrawal_share_bps: 0,
            reserve_asset_id: Bytes32::new([3; 32]),
            reserve_inner_puzzle_hash: Bytes32::new([4; 32]),
            reserve_full_puzzle_hash: Bytes32::new([5; 32]),
        }
    }

    fn some_state(cumulative_payout: u128) -> RewardDistributorState {
        RewardDistributorState {
            total_reserves: 0,
            active_shares: 0,
            round_reward_info: RoundRewardInfo {
                cumulative_payout,
                remaining_rewards: 0,
            },
            round_time_info: RoundTimeInfo {
                last_update: 0,
                epoch_end: 0,
            },
        }
    }

    /// No matching entry slot reads `Ok(None)` -- "no entry", never fabricated.
    #[test]
    fn no_entry_reads_ok_none() {
        let constants = some_constants(100);
        let state = some_state(1_000);
        assert_eq!(
            own_entry_from_slot(Bytes32::from([0x42; 32]), &constants, &state, None),
            Ok(None)
        );
    }

    /// SHAPE guard: a found entry's accrued amount comes from `dig_rewards_coin::accrued_base_units`
    /// -- the puzzle's own arithmetic -- never a fabricated `0`. Mutation-proved: replacing this
    /// function's `Some(accrued_base_units)` arm with `Some(0)` turns this test red.
    #[test]
    fn a_found_entry_reports_the_real_accrued_amount_never_zero() {
        let constants = some_constants(100);
        let state = some_state(1_000);
        let payout_puzzle_hash = Bytes32::from([0x42; 32]);
        let entry = RewardDistributorEntrySlotValue {
            counter: 1,
            payout_puzzle_hash,
            initial_cumulative_payout: 200,
            shares: 10,
        };

        let result = own_entry_from_slot(payout_puzzle_hash, &constants, &state, Some(&entry));

        // (1_000 - 200) * 10 / 100 = 80 -- the puzzle's own figure, mirroring
        // `dig_rewards_coin::payout`'s own equality-tested arithmetic.
        assert_eq!(
            result,
            Ok(Some(OwnEntry {
                payout_puzzle_hash,
                counter: 1,
                accrued_base_units: 80,
            }))
        );
    }

    /// A diverged read (`state`'s cumulative payout behind the entry's own) refuses rather than
    /// reporting a wrapped or fabricated figure.
    #[test]
    fn a_diverged_read_refuses_rather_than_wraps() {
        let constants = some_constants(100);
        let state = some_state(50);
        let payout_puzzle_hash = Bytes32::from([0x42; 32]);
        let entry = RewardDistributorEntrySlotValue {
            counter: 1,
            payout_puzzle_hash,
            initial_cumulative_payout: 200,
            shares: 10,
        };

        let result = own_entry_from_slot(payout_puzzle_hash, &constants, &state, Some(&entry));
        assert!(
            matches!(result, Err(ClaimPortError::Other(_))),
            "an overflowed/underflowed accrual must refuse by name, never answer Ok at all: \
             got {result:?}"
        );
    }

    /// #3357's phantom-slot trap: `RewardDistributor::created_slot_value_to_slot` on a
    /// chain-rebuilt distributor derives a well-formed but PHANTOM `LineageProof` for a slot an
    /// earlier generation created. This adapter must read every entry slot through
    /// `ChainEntrySlotSource`/`snapshot.entry_slot(..)`, never that method. A literal-string check
    /// rather than a compile-time one so it still catches the call even via a re-export or a fully
    /// qualified path.
    ///
    /// Scoped to CODE lines only (comment lines, `//`/`///`/`//!`, are dropped first) -- the module
    /// doc and this file's own inline warning both name the trap in prose, which must not trip the
    /// guard meant to catch an actual call. Also scoped to the file's own non-test region: this
    /// test's name/assertion text contains the literal string, so an unscoped scan over the whole
    /// file would be self-defeating.
    #[test]
    fn adapter_source_never_calls_created_slot_value_to_slot() {
        let production_src = production_region(include_str!("chain_port.rs"));
        let code_only: String = production_src
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !code_only.contains("created_slot_value_to_slot"),
            "chain_port.rs must never call created_slot_value_to_slot -- #3357 phantom-slot trap"
        );
    }

    /// The slice of this source file before its own `#[cfg(test)]` module -- i.e. what actually
    /// ships. Falls back to the whole file if there is no such marker.
    fn production_region(source: &str) -> &str {
        match source.find("#[cfg(test)]") {
            Some(test_module_start) => &source[..test_module_start],
            None => source,
        }
    }
}
