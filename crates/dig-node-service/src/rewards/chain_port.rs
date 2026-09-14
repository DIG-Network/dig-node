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
};

/// The funder-side `RewardsChainPort` over `dig-wallet`'s `CorroboratedChainSource`. Construct with
/// [`RealRewardsChainPort::new`] and install once via `dig_node_core::Node::install_reward_chain_port`
/// -- see `server.rs`'s `enable_chain_sync` install site.
pub struct RealRewardsChainPort {
    source: Arc<CorroboratedChainSource>,
}

impl RealRewardsChainPort {
    /// Wraps an already-constructed `CorroboratedChainSource` (`ChainTransport::corroborated_chain_source`).
    /// Takes ownership via `Arc` rather than borrowing: the port trait's `install_reward_chain_port`
    /// stores `Arc<dyn RewardsChainPort>` for the process's remaining life, so the source must
    /// outlive it too.
    #[must_use]
    pub fn new(source: Arc<CorroboratedChainSource>) -> Self {
        Self { source }
    }
}

#[async_trait]
impl RewardsChainPort for RealRewardsChainPort {
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
        tokio::task::spawn_blocking(move || build_report(source.as_ref(), launcher_id))
            .await
            .map_err(|join_error| ChainPortError::Other(format!("report task panicked: {join_error}")))?
    }
}

/// The synchronous body of `distributor_report`, run off the async runtime by `spawn_blocking`.
fn build_report(
    source: &CorroboratedChainSource,
    launcher_id: PortBytes32,
) -> Result<DistributorReport, ChainPortError> {
    let launcher_id = chia_protocol::Bytes32::new(launcher_id);

    let snapshot = read_distributor_guarded(source, launcher_id)
        .map_err(guarded_read_error_to_port_error)?
        .ok_or(ChainPortError::Unavailable)?;

    let comment = read_launch_comment(source, launcher_id)
        .map_err(|error| ChainPortError::Other(format!("launch comment unreadable: {error:?}")))?;

    let (_constants, first_epoch_state) = read_launch_constants(source, launcher_id).ok_or_else(|| {
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
    let current_distributor_epoch = epoch_end.saturating_sub(first_epoch_start) / epoch_seconds;

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

/// The `RewardsError` half of [`guarded_read_error_to_port_error`]'s mapping table.
fn reader_error_to_port_error(error: RewardsError) -> ChainPortError {
    match error {
        RewardsError::ChainUnavailable(_) => ChainPortError::Unavailable,
        RewardsError::UnreadableDistributorConstants { .. } => ChainPortError::InvalidWithdrawalShare,
        other => ChainPortError::Other(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    /// dig_ecosystem#3310 acceptance A4: neither adapter file in this module may import the
    /// withdraw-incentives driver call -- that is #3250's prover-cycle surface, not this ticket's.
    /// A literal-string check rather than a compile-time one because the point is to catch the
    /// import even if it compiled (e.g. via a re-export or a fully qualified path elsewhere).
    #[test]
    fn adapter_source_never_imports_withdraw_committed_incentives() {
        let chain_port_src = include_str!("chain_port.rs");
        let chain_source_src = include_str!("chain_source.rs");

        assert!(
            !chain_port_src.contains("withdraw_committed_incentives"),
            "chain_port.rs must not reference withdraw_committed_incentives (out of #3310's scope)"
        );
        assert!(
            !chain_source_src.contains("withdraw_committed_incentives"),
            "chain_source.rs must not reference withdraw_committed_incentives (out of #3310's scope)"
        );
    }
}
