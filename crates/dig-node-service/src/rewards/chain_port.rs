//! [`RealRewardsChainPort`] -- the production `RewardsChainPort` (dig_ecosystem#3310): serves
//! `distributor_report` for real, over `dig-wallet`'s `CorroboratedChainSource` and this module's
//! [`super::chain_source::read_distributor_guarded`]. The other four methods on the trait are out
//! of this ticket's named scope (`funded_distributors`/#3269's funder-registry blocker,
//! `distributor_state`/`submit_entry_writes`/`spend_new_epoch`/#3250's prover cycle) and answer
//! [`ChainPortError::Unavailable`], exactly as `UnavailableChainPort` does for all five -- this
//! adapter narrows that surface by one call, it does not widen it.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use dig_chainsource_interface::ChainSource;
use dig_node_core::rewards::port::{
    Bytes32 as PortBytes32, ChainPortError, CommitmentSlot, DistributorChainState, DistributorRef,
    DistributorReport, EntryWriteBundle, RewardsChainPort,
};
use dig_rewards_coin::clawback::recoverable_base_units;
use dig_rewards_coin::state::DistributorSnapshot;
use dig_rewards_coin::RewardsError;
use dig_wallet::sage::corroborated_source::CorroboratedChainSource;

use super::chain_source::{
    read_distributor_guarded, read_launch_comment, read_launch_constants, GuardedReadError,
    LaunchCommentError,
};

/// The funder-side `RewardsChainPort` over a [`ChainSource`] -- `dig-wallet`'s
/// `CorroboratedChainSource` in production (the default `S`, and the only type `server.rs`'s
/// `enable_chain_sync` install site ever names). Construct with [`RealRewardsChainPort::new`] and
/// install once via `dig_node_core::Node::install_reward_chain_port`.
///
/// Generic over `S` (rather than hard-wired to `CorroboratedChainSource`) so `distributor_report`
/// -- the real adapter body, over the real `read_distributor_guarded` -- can be driven directly in
/// tests by a source whose coin records/spends came from a real `chia-sdk-test` simulator launch
/// (dig_ecosystem#3310 acceptance A3, `tests/rewards_chain_port_a3.rs`), without also having to
/// fake `dig-wallet`'s peer-corroboration transport. That double replaces the socket only: every
/// byte the adapter reads still comes from `dig_rewards_coin::state::read_distributor` parsing a
/// genuine, simulator-produced `CoinSpend`.
pub struct RealRewardsChainPort<S: ChainSource + Send + Sync + 'static = CorroboratedChainSource> {
    source: Arc<S>,
    /// Set once `distributor_report` fails, cleared on its next success -- so the WARN in
    /// `distributor_report` below fires once per failure->success transition, not once per call
    /// (dig_ecosystem#3310 gate leg 3, R4). A caller may poll this every few seconds; without this
    /// a degraded chain source would either log nothing (the defect the gate found) or flood the
    /// log on every single poll -- neither of which an operator can act on.
    report_degraded: std::sync::atomic::AtomicBool,
}

impl<S: ChainSource + Send + Sync + 'static> RealRewardsChainPort<S> {
    /// Wraps an already-constructed chain source (`ChainTransport::corroborated_chain_source` in
    /// production). Takes ownership via `Arc` rather than borrowing: the port trait's
    /// `install_reward_chain_port` stores `Arc<dyn RewardsChainPort>` for the process's remaining
    /// life, so the source must outlive it too.
    #[must_use]
    pub fn new(source: Arc<S>) -> Self {
        Self {
            source,
            report_degraded: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl<S: ChainSource + Send + Sync + 'static> RewardsChainPort for RealRewardsChainPort<S> {
    async fn funded_distributors(&self) -> Result<Vec<DistributorRef>, ChainPortError> {
        // dig_node_core::rewards::port's own module doc, "Blocker 2": no funder-ownership
        // registry exists anywhere in this codebase yet. Answering here would mean inventing one
        // unreviewed, which is exactly the shape fork this ticket's brief says to leave alone.
        Err(ChainPortError::Unavailable)
    }

    async fn distributor_state(
        &self,
        _launcher_id: PortBytes32,
    ) -> Result<DistributorChainState, ChainPortError> {
        // #3250's prover-cycle surface, a sibling ticket -- not this one.
        Err(ChainPortError::Unavailable)
    }

    async fn submit_entry_writes(&self, _bundle: EntryWriteBundle) -> Result<(), ChainPortError> {
        Err(ChainPortError::Unavailable)
    }

    async fn spend_new_epoch(&self, _launcher_id: PortBytes32) -> Result<(), ChainPortError> {
        Err(ChainPortError::Unavailable)
    }

    async fn distributor_report(
        &self,
        launcher_id: PortBytes32,
    ) -> Result<DistributorReport, ChainPortError> {
        let source = Arc::clone(&self.source);
        // `ChainSource` is synchronous and does its own socket I/O underneath; running it on a
        // blocking-pool thread keeps a slow read from stalling the async runtime it is called
        // from, without using `spawn_blocking` as a hang REMEDY (the guard, not this, is what
        // prevents the hang itself -- see `chain_source.rs`'s module doc).
        let result =
            tokio::task::spawn_blocking(move || build_report(source.as_ref(), launcher_id))
                .await
                .map_err(|join_error| {
                    ChainPortError::Other(format!("report task panicked: {join_error}"))
                })?;

        // R4 (dig_ecosystem#3310 gate leg 3, §4): a failing chain source must be observable, not
        // only correctly typed. `swap` both reads and sets `report_degraded` atomically, so the
        // warn fires exactly once per failure->success transition even under concurrent callers.
        match &result {
            Ok(_) => {
                self.report_degraded
                    .store(false, std::sync::atomic::Ordering::Relaxed);
            }
            Err(port_error) => {
                let was_already_degraded = self
                    .report_degraded
                    .swap(true, std::sync::atomic::Ordering::Relaxed);
                if !was_already_degraded {
                    tracing::warn!(
                        launcher_id = %hex::encode(launcher_id),
                        error = ?port_error,
                        "distributor_report failed; reward-distributor reads for this launcher \
                         stay refused until the chain source recovers"
                    );
                }
            }
        }

        result
    }
}

/// The synchronous body of `distributor_report`, run off the async runtime by `spawn_blocking`.
fn build_report<S>(
    source: &S,
    launcher_id: PortBytes32,
) -> Result<DistributorReport, ChainPortError>
where
    S: ChainSource,
{
    let launcher_id = chia_protocol::Bytes32::new(launcher_id);

    let snapshot = read_distributor_guarded(source, launcher_id)
        .map_err(guarded_read_error_to_port_error)?
        .ok_or(ChainPortError::Unavailable)?;

    let comment =
        read_launch_comment(source, launcher_id).map_err(launch_comment_error_to_port_error)?;

    let (_constants, first_epoch_state) =
        read_launch_constants(source, launcher_id).ok_or_else(|| {
            ChainPortError::Other(
                "launch constants unreadable after a successful guarded read".to_string(),
            )
        })?;
    let first_epoch_start = first_epoch_state.round_time_info.last_update;

    report_from_snapshot(&snapshot, launcher_id, comment, first_epoch_start)
}

/// Maps a [`DistributorSnapshot`] plus the launch comment onto the port's [`DistributorReport`].
/// Every field's source is named in its own comment so this mapping can be re-checked field by
/// field against the port's doc (dig_ecosystem#3310 acceptance A5).
fn report_from_snapshot(
    snapshot: &DistributorSnapshot,
    launcher_id: chia_protocol::Bytes32,
    comment: dig_rewards_coin::comment::LaunchComment,
    first_epoch_start: u64,
) -> Result<DistributorReport, ChainPortError> {
    let distributor = snapshot.distributor();
    let constants = distributor.info.constants;

    if launcher_id == chia_protocol::Bytes32::default()
        || comment.store_id == chia_protocol::Bytes32::default()
    {
        return Err(ChainPortError::ZeroIdentity);
    }

    let withdrawal_share_bps: u16 = constants
        .withdrawal_share_bps
        .try_into()
        .map_err(|_| ChainPortError::InvalidWithdrawalShare)?;
    if withdrawal_share_bps > 10_000 {
        return Err(ChainPortError::InvalidWithdrawalShare);
    }
    let fee_bps: u16 = constants.fee_bps.try_into().map_err(|_| {
        ChainPortError::Other(format!("fee_bps {} does not fit u16", constants.fee_bps))
    })?;

    let epoch_seconds = constants.epoch_seconds;
    let epoch_end = distributor.info.state.round_time_info.epoch_end;
    // `epoch_seconds != 0` is guaranteed here: `build_report` only reaches this function after
    // `read_distributor_guarded` succeeded, and that call refuses `epoch_seconds == 0` twice over
    // (this crate's own guard, then `dig-rewards-coin`'s `state.rs:1015`) before ever returning
    // `Ok(Some(..))`.
    let current_distributor_epoch = epoch_ordinal(epoch_end, first_epoch_start, epoch_seconds);

    let commitments = snapshot
        .slots()
        .commitments
        .iter()
        .map(|commitment| {
            let recoverable = recoverable_base_units(commitment.rewards, withdrawal_share_bps)
                .ok_or(ChainPortError::InvalidWithdrawalShare)?;
            Ok(CommitmentSlot {
                epoch_start: commitment.epoch_start,
                clawback_puzzle_hash: commitment.clawback_ph.into(),
                rewards_base_units: commitment.rewards,
                recoverable_base_units: recoverable,
            })
        })
        .collect::<Result<Vec<_>, ChainPortError>>()?;

    let observed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);

    Ok(DistributorReport {
        launcher_id: launcher_id.into(),
        store_id: comment.store_id.into(),
        root: comment.root.into(),
        epoch_seconds,
        first_epoch_start,
        payout_threshold: constants.payout_threshold,
        fee_bps,
        withdrawal_share_bps,
        reserve_base_units: snapshot.reserve_base_units(),
        entry_count: snapshot.entry_count() as u64,
        current_distributor_epoch,
        last_entry_write_at: snapshot.observed().last_entry_write_unix(),
        entry_set_stale: snapshot.entry_set_stale(),
        commitments,
        observed_at,
    })
}

/// The report's only non-trivial computed field, pulled out of [`report_from_snapshot`] so it can
/// be unit-tested directly (dig_ecosystem#3310 gate leg 3, R3): a gut that replaces
/// `current_distributor_epoch` with a constant leaves every test in this crate green unless this
/// function's own tests catch it, because at a bare launch `epoch_end == first_epoch_start` and
/// the CORRECT answer is already `0` -- indistinguishable from the gutted value on that one case
/// alone. `epoch_seconds == 0` never reaches here -- see the caller's comment.
fn epoch_ordinal(epoch_end: u64, first_epoch_start: u64, epoch_seconds: u64) -> u64 {
    epoch_end.saturating_sub(first_epoch_start) / epoch_seconds
}

/// Maps [`GuardedReadError`] onto [`ChainPortError`] -- see the module's own mapping table
/// (dig_ecosystem#3310 brief): `RewardsError::ChainUnavailable` is the ONLY variant that becomes
/// [`ChainPortError::Unavailable`]; `RewardsError::UnreadableDistributorConstants` becomes
/// [`ChainPortError::InvalidWithdrawalShare`] (the port's own name for the identical refusal);
/// every other reader error, and this crate's own [`GuardedReadError::NonTerminatingEpochSeconds`],
/// become [`ChainPortError::Other`] -- never `Unavailable`, so a caller cannot mistake a refused
/// read for a merely offline chain.
fn guarded_read_error_to_port_error(error: GuardedReadError) -> ChainPortError {
    match error {
        GuardedReadError::NonTerminatingEpochSeconds => ChainPortError::Other(
            "distributor launch constants carry epoch_seconds == 0, a non-terminating replay \
             hazard (chia-sdk-driver-0.36.0's commit_incentives backfill loop never terminates on \
             this value); refusing to read rather than hang"
                .to_string(),
        ),
        GuardedReadError::Reader(reward_error) => reader_error_to_port_error(reward_error),
    }
}

/// Maps [`LaunchCommentError`] onto [`ChainPortError`] (dig_ecosystem#3310 gate leg 3, R5).
/// `ParentSpendUnavailable` is a chain-source GAP (the source does not yet hold the launcher's
/// parent spend), not a classification of the distributor's identity -- it maps onto the same
/// `Unavailable` `read_distributor_guarded`'s own `Ok(None)` already answers with, not `Other`,
/// which would render it to a caller as a definitive "not a DIG distributor". Every other variant
/// genuinely is a refused/malformed read, or a real classification, so it stays `Other`.
fn launch_comment_error_to_port_error(error: LaunchCommentError) -> ChainPortError {
    match error {
        LaunchCommentError::ParentSpendUnavailable => ChainPortError::Unavailable,
        other => ChainPortError::Other(format!("launch comment unreadable: {other}")),
    }
}

/// The `RewardsError` half of [`guarded_read_error_to_port_error`]'s mapping table.
fn reader_error_to_port_error(error: RewardsError) -> ChainPortError {
    match error {
        RewardsError::ChainUnavailable(_) => ChainPortError::Unavailable,
        RewardsError::UnreadableDistributorConstants { .. } => {
            ChainPortError::InvalidWithdrawalShare
        }
        other => ChainPortError::Other(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use dig_chainsource_interface::{ChainSourceError, MockChainSource};
    use dig_node_core::rewards::port::{ChainPortError, RewardsChainPort};

    use super::RealRewardsChainPort;

    /// R3 (dig_ecosystem#3310 gate leg 3, §2/§3.2): a bare launch has `epoch_end ==
    /// first_epoch_start`, so `0` is the CORRECT answer there, not just what a gutted
    /// implementation would also return -- this test proves the non-zero, multi-epoch case
    /// instead, which a `0`-returning gut cannot pass.
    #[test]
    fn epoch_ordinal_counts_whole_epochs_elapsed_since_first_epoch_start() {
        let first_epoch_start = 1_000;
        let epoch_seconds = 100;
        let epoch_end = first_epoch_start + 3 * epoch_seconds + 40; // partway into epoch 3

        assert_eq!(
            super::epoch_ordinal(epoch_end, first_epoch_start, epoch_seconds),
            3
        );
    }

    /// The `saturating_sub` branch: a clock-skewed or not-yet-advanced read can have
    /// `epoch_end < first_epoch_start`. Must refuse to underflow and answer epoch `0`, not panic
    /// or wrap.
    #[test]
    fn epoch_ordinal_saturates_to_zero_when_epoch_end_precedes_first_epoch_start() {
        assert_eq!(super::epoch_ordinal(500, 1_000, 100), 0);
    }

    /// The bare-launch case itself: `epoch_end == first_epoch_start` -- correctly `0`, and named
    /// here so the two tests above are read as a PAIR, not as this single (weak, gut-indistinct)
    /// case alone.
    #[test]
    fn epoch_ordinal_is_zero_at_a_bare_launch() {
        assert_eq!(super::epoch_ordinal(1_234, 1_234, 100), 0);
    }

    /// This ticket's own filed complaint (dig_ecosystem#3310): a failing chain source must
    /// surface as a NAMED error, never as reassuring emptiness -- an `Ok` carrying a
    /// zero/default-valued report. `MockChainSource::fail_with` forces every read `Err`
    /// (`ChainSourceError::Timeout`), which `dig_rewards_coin::state::read_distributor` maps to
    /// `RewardsError::ChainUnavailable`, which this adapter's own `reader_error_to_port_error`
    /// maps to `ChainPortError::Unavailable` -- checked here end to end through the public
    /// `RewardsChainPort::distributor_report` call, not just the internal mapping function, so a
    /// future refactor of `build_report`'s plumbing cannot silently reopen the gap.
    #[tokio::test]
    async fn a_failing_chain_source_reports_a_named_unavailable_never_an_ok_default() {
        let source = MockChainSource::new().fail_with(ChainSourceError::Timeout);
        let port = RealRewardsChainPort::<MockChainSource>::new(Arc::new(source));

        let result = port.distributor_report([0x11; 32]).await;

        assert_eq!(
            result,
            Err(ChainPortError::Unavailable),
            "a failing chain source must report the named Unavailable variant, never Ok(_) with \
             a default-valued report, got {result:?}"
        );
    }

    /// dig_ecosystem#3342, the money-surface defect: a chain source that ANSWERS and holds no
    /// reward distributor at `launcher_id` is an ABSENCE, never an OUTAGE. An empty
    /// `MockChainSource` answers every read successfully with `None`, which
    /// `dig_rewards_coin::state::read_distributor` reports as `Ok(None)` -- the chain saying
    /// "nothing here", not "I could not look". A funder deciding whether to claw back must be
    /// able to tell that apart from an unreachable chain, so it must NOT be `Unavailable`.
    #[tokio::test]
    async fn an_answering_chain_with_no_distributor_is_an_absence_not_an_outage() {
        let source = MockChainSource::new();
        let port = RealRewardsChainPort::<MockChainSource>::new(Arc::new(source));

        let result = port.distributor_report([0x22; 32]).await;

        assert_ne!(
            result,
            Err(ChainPortError::Unavailable),
            "an answering chain that holds no distributor is an absence, not an unreachable \
             chain, got {result:?}"
        );
    }

    /// The adjacent guard this crate's own `epoch_seconds == 0` refusal must keep: that refusal is
    /// a NAMED distributor-level refusal (`ChainPortError::Other`), never conflated with
    /// `ChainPortError::Unavailable` -- which must mean the CHAIN SOURCE could not answer, not
    /// that a read was refused for a reason unrelated to reachability. Regresses a case where
    /// `GuardedReadError::NonTerminatingEpochSeconds` maps onto the same variant an offline chain
    /// would report, which would let a caller mistake "chain source is fine, this distributor
    /// carries a replay hazard" for "the chain source itself is unreachable".
    #[test]
    fn non_terminating_epoch_seconds_is_not_reported_as_chain_unavailable() {
        let mapped = super::guarded_read_error_to_port_error(
            super::super::chain_source::GuardedReadError::NonTerminatingEpochSeconds,
        );

        assert_ne!(
            mapped,
            ChainPortError::Unavailable,
            "epoch_seconds == 0 is a named refusal, not an absent/unreachable chain, got {mapped:?}"
        );
    }

    /// R5's regression (dig_ecosystem#3310 gate leg 3): a chain-source GAP on the launcher's
    /// parent spend must never be reported as the definitive "not a DIG distributor" verdict --
    /// it must agree with the OTHER absence path (`read_distributor_guarded`'s own `Ok(None)`),
    /// which answers `Unavailable`.
    #[test]
    fn parent_spend_gap_is_reported_as_unavailable_not_as_a_distributor_identity_verdict() {
        let mapped = super::launch_comment_error_to_port_error(
            super::super::chain_source::LaunchCommentError::ParentSpendUnavailable,
        );

        assert_eq!(
            mapped,
            ChainPortError::Unavailable,
            "a missing parent spend is a chain-source gap, not an identity verdict, got {mapped:?}"
        );
    }

    /// dig_ecosystem#3310 acceptance A4: neither adapter file in this module may import the
    /// withdraw-incentives driver call -- that is #3250's prover-cycle surface, not this ticket's.
    /// A literal-string check rather than a compile-time one because the point is to catch the
    /// import even if it compiled (e.g. via a re-export or a fully qualified path elsewhere).
    ///
    /// Scoped to the NON-TEST region of each file (everything before its own `#[cfg(test)]`
    /// marker): this very test's name and assertion messages contain the literal string, so an
    /// unscoped `contains` over the whole file (this one included) can never pass -- it would be
    /// self-defeating, not a real containment check.
    #[test]
    fn adapter_source_never_imports_withdraw_committed_incentives() {
        let chain_port_production_src = production_region(include_str!("chain_port.rs"));
        let chain_source_production_src = production_region(include_str!("chain_source.rs"));

        assert!(
            !chain_port_production_src.contains("withdraw_committed_incentives"),
            "chain_port.rs must not reference withdraw_committed_incentives (out of #3310's scope)"
        );
        assert!(
            !chain_source_production_src.contains("withdraw_committed_incentives"),
            "chain_source.rs must not reference withdraw_committed_incentives (out of #3310's scope)"
        );
    }

    /// The slice of a source file before its own `#[cfg(test)]` module -- i.e. what actually
    /// ships. Falls back to the whole file if there is no such marker (there always is one here,
    /// but a missing marker should widen the scan, not silently skip it).
    fn production_region(source: &str) -> &str {
        match source.find("#[cfg(test)]") {
            Some(test_module_start) => &source[..test_module_start],
            None => source,
        }
    }
}
