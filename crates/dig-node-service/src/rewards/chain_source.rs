//! The ONE guarded chain read every adapter in this module funnels through
//! (dig_ecosystem#3310) -- `read_distributor_guarded`, plus the launch-comment recovery
//! `distributor_report` needs for `store_id`/`root`.
//!
//! # The guard: `epoch_seconds == 0` is the non-terminating case, not the finite one
//!
//! `chia-sdk-driver-0.36.0`'s `commit_incentives.rs` (~lines 101-111) runs
//! `while end_epoch_time > start_epoch_time { start_epoch_time += epoch_seconds; }`. At
//! `epoch_seconds == 0` the induction variable never advances -- an infinite, non-yielding CPU
//! loop, with no `.await` anywhere in that file. `tokio::time::timeout` cannot rescue a caller from
//! it: with no await point the timeout future is never polled and the worker thread hangs
//! regardless (upstream report: `xch-dev/chia-wallet-sdk#436`). `epoch_seconds` is curried into
//! the action puzzle at launch, so an attacker picks it, and the resulting puzzle hash is still a
//! legitimately recognised member of `dig-rewards-coin`'s eleven action hashes -- a distributor
//! carrying this value is not malformed by that measure, only hazardous to replay.
//!
//! The only remedy that is real: refuse `epoch_seconds == 0` BEFORE ever reaching that loop, read
//! from the launch constants alone (`RewardDistributor::from_launcher_solution`), which is cheap
//! and does not touch the hazardous code path at all.
//!
//! `dig-rewards-coin` 0.5.0 already performs exactly this refusal, INSIDE
//! `state::read_distributor` itself, before any generation is walked --
//! `RewardsError::UnreadableEpochSeconds` at `state.rs:1015`. The check in this file is therefore
//! **defence in depth at this crate's own edge, not a substitute for theirs**: it exists so a
//! future `dig-rewards-coin` regression, or any other function this crate might one day call over
//! the same hazardous constant, does not silently reopen the hang.
//!
//! This is a DIFFERENT bound from `dig_rewards_coin::state::MAX_COMMIT_INCENTIVES_BACKFILL_SLOTS`
//! (`state.rs:73`, enforced ~`:659-670`): that one refuses a backfill that is large but FINITE.
//! This one refuses the case that never finishes at all.
//!
//! # Recovering `store_id`/`root`: the launch comment is a memo, not a reader field
//!
//! `dig_rewards_coin::state::read_distributor` reports everything the distributor's own puzzle
//! state carries, but the `(store_id, root)` a distributor pays out for is not part of that state
//! at all -- it is a CLVM memo `chia-sdk-driver` attaches to the `CREATE_COIN` that creates the
//! LAUNCHER coin (`launch_drivers.rs:643-644`:
//! `Launcher::with_memos(security_coin.coin_id(), 1, ctx.memos(&(reward_distributor_hint,
//! (comment, ())))?)`), rendered with `dig_rewards_coin::comment::LaunchComment::to_string()`
//! (`dig-rewards:v1:<store_id_hex>:<root_hex>`). No `dig-rewards-coin` function reads it back off
//! chain; only `LaunchComment::parse(&str)` on an already-obtained string exists. Recovering it is
//! this crate's own job: read the launcher's CREATING spend (its parent's spend, not its own),
//! run that parent's puzzle, find the `CREATE_COIN` that creates the launcher coin, and decode its
//! memos. This mirrors `dig-mirror-coin`'s `MirrorCoin::from_creating_spend`/`read_parent_outputs`
//! (same crate family, same shape of problem: an unauthenticated memo declaring which generation a
//! chain object is about).

use chia_protocol::{Bytes, Bytes32, Coin, CoinSpend};
use chia_puzzle_types::Memos;
use chia_sdk_driver::{Puzzle, RewardDistributor, SpendContext};
use chia_sdk_types::{run_puzzle, Condition, Conditions};
use clvm_traits::FromClvm;
use clvm_utils::tree_hash;
use clvmr::{Allocator, NodePtr};
use dig_chainsource_interface::ChainSource;
use dig_rewards_coin::comment::LaunchComment;
use dig_rewards_coin::state::DistributorSnapshot;
use dig_rewards_coin::RewardsError;

/// Why the guarded read could not produce a [`DistributorSnapshot`].
///
/// Never confused with an absence: both variants mean the read could not be trusted, not that the
/// distributor does not exist (that remains `Ok(None)` from `read_distributor` itself).
#[derive(Debug)]
pub(crate) enum GuardedReadError {
    /// THIS crate's own edge refusal -- see the module doc's "the guard" section. Distinct from
    /// [`GuardedReadError::Reader`] carrying `dig-rewards-coin`'s OWN identical refusal: this
    /// variant is produced by code in *this* file and never reaches `read_distributor` at all.
    NonTerminatingEpochSeconds,
    /// `dig_rewards_coin::state::read_distributor` itself returned an error -- including its own
    /// `epoch_seconds == 0` refusal (`state.rs:1015`), a chain-source failure, malformed chain
    /// data, or an out-of-domain `withdrawal_share_bps`.
    Reader(RewardsError),
}

/// Reads distributor `launcher_id` over `source`, refusing the non-terminating
/// `epoch_seconds == 0` hazard BEFORE calling `dig_rewards_coin::state::read_distributor` at all.
///
/// Every adapter in this crate MUST call this function rather than `read_distributor` directly --
/// see the module doc for why, and [`GuardedReadError`] for the two ways it can refuse.
pub(crate) fn read_distributor_guarded<S>(
    source: &S,
    launcher_id: Bytes32,
) -> Result<Option<DistributorSnapshot>, GuardedReadError>
where
    S: ChainSource,
{
    refuse_non_terminating_epoch_seconds(source, launcher_id)?;
    dig_rewards_coin::state::read_distributor(source, launcher_id).map_err(GuardedReadError::Reader)
}

/// Refuses `launcher_id` when its launch constants carry `epoch_seconds == 0`, reading ONLY the
/// launcher's own spend and its `key_value_list` -- never a generation walk, so this cannot itself
/// reach the hazard it exists to screen for.
///
/// Deliberately permissive on every read it cannot complete (unspent/unknown launcher, an
/// undecodable solution, launch terms `RewardDistributor::from_launcher_solution` itself refuses):
/// this guard's only job is to catch the ONE named hazard early. Every other outcome -- including
/// absence and chain-source failure -- is `dig_rewards_coin::state::read_distributor`'s to answer
/// honestly, and it does.
fn refuse_non_terminating_epoch_seconds<S>(
    source: &S,
    launcher_id: Bytes32,
) -> Result<(), GuardedReadError>
where
    S: ChainSource,
{
    match read_launch_constants(source, launcher_id) {
        Some((constants, _state)) if constants.epoch_seconds == 0 => {
            Err(GuardedReadError::NonTerminatingEpochSeconds)
        }
        _ => Ok(()),
    }
}

/// Reads `launcher_id`'s launch constants and initial state directly off the launcher's own
/// spend, via [`RewardDistributor::from_launcher_solution`] -- the same cheap, generation-walk-free
/// read [`refuse_non_terminating_epoch_seconds`] uses, exposed so [`super::chain_port`] can recover
/// [`chia_sdk_driver::RewardDistributorState::initial`]'s `first_epoch_start`
/// (`round_time_info.last_update`, equivalently `.epoch_end`, at this point) without a second
/// design for the same read. `None` for anything that could not be read or decoded -- absence and
/// chain-source failure are `read_distributor`'s to answer, not this helper's.
pub(crate) fn read_launch_constants<S>(
    source: &S,
    launcher_id: Bytes32,
) -> Option<(
    chia_sdk_driver::RewardDistributorConstants,
    chia_sdk_driver::RewardDistributorState,
)>
where
    S: ChainSource,
{
    let spend = source.coin_spend(launcher_id).ok()??;

    let mut ctx = SpendContext::new();
    let solution_ptr = ctx.alloc(&spend.solution).ok()?;

    let (constants, state, _eve_coin) =
        RewardDistributor::from_launcher_solution(&mut ctx, spend.coin, solution_ptr).ok()??;
    Some((constants, state))
}

/// Why `launcher_id`'s launch comment (`store_id`/`root`) could not be recovered.
#[derive(Debug)]
pub(crate) enum LaunchCommentError {
    /// The source could not answer the launcher's creating (parent) spend at all -- an actual
    /// transport error from `ChainSource::parent_spend`.
    ChainSource(String),
    /// The creating spend was read, but its puzzle reveal, solution, or emitted conditions could
    /// not be interpreted -- the read is untrustworthy, so this fails closed rather than treating
    /// the comment as absent.
    Malformed(String),
    /// `ChainSource::parent_spend` answered `Ok(None)`: the source does not (yet) hold the
    /// launcher's creating spend. This is a GAP, not a classification -- every launcher coin
    /// created by a security coin has a parent spend on a complete chain, so `Ok(None)` here means
    /// the source is lagging or pruned, never that the distributor is definitively not DIG's
    /// (dig_ecosystem#3310 gate leg 3, R5). Maps to `ChainPortError::Unavailable` in
    /// `chain_port.rs`, the same variant `read_distributor_guarded`'s own `Ok(None)` already
    /// produces, so both absence paths agree.
    ParentSpendUnavailable,
    /// The creating spend was read and understood, and it simply carries no DIG rewards launch
    /// comment: a CHIP-0051 distributor legitimately launched for a purpose other than DIG's own
    /// (`dig_rewards_coin::comment`'s module doc), so this is a genuine classification, not a
    /// failure to read.
    NotADigDistributor,
}

/// Manual (not derived) `Display`: reads the `String` payload of `ChainSource`/`Malformed` into
/// the message a caller logs. A derived `Debug` alone does not count, to rustc's own dead-code
/// analysis, as a genuine read of a private tuple field -- see `chain_port.rs`'s
/// `build_report`, the only caller, which now formats via `{error}` rather than `{error:?}`.
impl std::fmt::Display for LaunchCommentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChainSource(reason) => write!(f, "chain source unavailable: {reason}"),
            Self::Malformed(reason) => write!(f, "malformed launch comment data: {reason}"),
            Self::ParentSpendUnavailable => write!(
                f,
                "chain source does not (yet) hold the launcher's parent spend"
            ),
            Self::NotADigDistributor => {
                write!(
                    f,
                    "not a DIG rewards distributor (no matching launch comment)"
                )
            }
        }
    }
}

/// Recovers `launcher_id`'s `(store_id, root)` from the `CREATE_COIN` memo on the spend that
/// CREATES the launcher coin -- see the module doc's second section for why this cannot come from
/// `dig_rewards_coin` itself.
pub(crate) fn read_launch_comment<S>(
    source: &S,
    launcher_id: Bytes32,
) -> Result<LaunchComment, LaunchCommentError>
where
    S: ChainSource,
{
    let creating_spend = source
        .parent_spend(launcher_id)
        .map_err(|error| LaunchCommentError::ChainSource(error.to_string()))?
        .ok_or(LaunchCommentError::ParentSpendUnavailable)?;

    parse_launch_comment(&creating_spend, launcher_id)
}

/// Runs `creating_spend`'s puzzle once and reads the launch comment off the `CREATE_COIN` that
/// creates `launcher_id`.
fn parse_launch_comment(
    creating_spend: &CoinSpend,
    launcher_id: Bytes32,
) -> Result<LaunchComment, LaunchCommentError> {
    let mut allocator = Allocator::new();

    let puzzle_ptr =
        program_to_node(&mut allocator, &creating_spend.puzzle_reveal).map_err(|error| {
            LaunchCommentError::Malformed(format!("undecodable puzzle reveal: {error}"))
        })?;
    let solution_ptr = program_to_node(&mut allocator, &creating_spend.solution)
        .map_err(|error| LaunchCommentError::Malformed(format!("undecodable solution: {error}")))?;

    // The reveal must be the parent's ACTUAL puzzle -- nothing below re-derives that, so a
    // substituted reveal must be caught here, before it is run.
    let revealed: Bytes32 = tree_hash(&allocator, puzzle_ptr).into();
    if revealed != creating_spend.coin.puzzle_hash {
        return Err(LaunchCommentError::Malformed(
            "puzzle reveal does not hash to the creating coin's puzzle hash".to_string(),
        ));
    }
    let parent_puzzle = Puzzle::parse(&allocator, puzzle_ptr);
    let _ = parent_puzzle; // parsed only to prove `puzzle_ptr` is a real puzzle tree; unused otherwise.

    let output = run_puzzle(&mut allocator, puzzle_ptr, solution_ptr).map_err(|error| {
        LaunchCommentError::Malformed(format!("parent puzzle did not run: {error}"))
    })?;
    let conditions = Conditions::<NodePtr>::from_clvm(&allocator, output).map_err(|error| {
        LaunchCommentError::Malformed(format!("undecodable conditions: {error}"))
    })?;

    let parent_id = creating_spend.coin.coin_id();
    for condition in conditions {
        let Condition::CreateCoin(created) = condition else {
            continue;
        };
        let candidate = Coin::new(parent_id, created.puzzle_hash, created.amount);
        if candidate.coin_id() != launcher_id {
            continue;
        }

        return match memo_comment(&allocator, created.memos) {
            Some(comment) => Ok(comment),
            None => Err(LaunchCommentError::NotADigDistributor),
        };
    }

    Err(LaunchCommentError::Malformed(format!(
        "creating spend of coin {parent_id} emitted no CREATE_COIN for launcher {launcher_id}"
    )))
}

/// Decodes a `CREATE_COIN`'s memos as `[hint, comment_utf8, ..]` and parses the second entry as a
/// [`LaunchComment`] -- the layout `launch_drivers.rs` writes:
/// `ctx.memos(&(reward_distributor_hint, (comment, ())))`. `None` for anything that does not
/// match: absent memos, a memo list that is not at least two entries, or a second entry that is
/// not a valid launch comment string.
fn memo_comment(allocator: &Allocator, memos: Memos<NodePtr>) -> Option<LaunchComment> {
    let Memos::Some(node) = memos else {
        return None;
    };

    let entries = Vec::<Bytes>::from_clvm(allocator, node).ok()?;
    let comment_bytes = entries.get(1)?;
    let comment_str = std::str::from_utf8(comment_bytes.as_ref()).ok()?;
    LaunchComment::parse(comment_str)
}

/// Deserializes a [`chia_protocol::Program`] into an allocated [`NodePtr`].
fn program_to_node(
    allocator: &mut Allocator,
    program: &chia_protocol::Program,
) -> Result<NodePtr, String> {
    clvmr::serde::node_from_bytes_backrefs(allocator, program.as_ref())
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use chia_puzzle_types::singleton::LauncherSolution;
    use chia_sdk_driver::{RewardDistributorConstants, RewardDistributorType, SpendContext};
    use dig_chainsource_interface::{ChainSourceError, CoinRecord, SingletonLineage};

    use super::*;

    /// A `ChainSource` double answering exactly the `coin_spend`s it was built with, and
    /// `Ok(None)`/`Ok(empty)` for everything else -- the A1 acceptance test (dig_ecosystem#3310)
    /// only needs the guard's ONE read, `coin_spend`.
    struct StubSource {
        spends: HashMap<chia_protocol::Bytes32, CoinSpend>,
    }

    impl ChainSource for StubSource {
        type Error = ChainSourceError;

        fn coin_record(&self, _coin_id: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
            Ok(None)
        }

        fn coin_records_by_puzzle_hash(
            &self,
            _puzzle_hash: Bytes32,
            _include_spent: bool,
        ) -> Result<Vec<CoinRecord>, Self::Error> {
            Ok(Vec::new())
        }

        fn coin_records_by_parent(
            &self,
            _parent_coin_id: Bytes32,
        ) -> Result<Vec<CoinRecord>, Self::Error> {
            Ok(Vec::new())
        }

        fn coin_spend(&self, coin_id: Bytes32) -> Result<Option<CoinSpend>, Self::Error> {
            Ok(self.spends.get(&coin_id).cloned())
        }

        fn resolve_singleton_lineage(
            &self,
            _launcher_id: Bytes32,
        ) -> Result<Option<SingletonLineage>, Self::Error> {
            Ok(None)
        }

        fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
            Ok(None)
        }

        fn block_timestamp(&self, _height: u32) -> Result<Option<u64>, Self::Error> {
            Ok(None)
        }
    }

    /// Builds a launcher `CoinSpend` whose `key_value_list` decodes to `(first_epoch_start,
    /// constants)`, exactly the shape `RewardDistributor::from_launcher_solution` extracts --
    /// letting a test drive the guard without a live chain or a real distributor launch.
    fn launcher_spend_with(epoch_seconds: u64) -> (Bytes32, CoinSpend) {
        let launcher_coin = Coin::new(Bytes32::from([7u8; 32]), Bytes32::from([9u8; 32]), 1);
        let launcher_id = launcher_coin.coin_id();

        // `.with_launcher_id(launcher_id)` is not a formality: it recomputes
        // `reserve_inner_puzzle_hash`/`reserve_full_puzzle_hash` from `launcher_id` and
        // `reserve_asset_id` (curried tree hashes). `from_launcher_solution` rejects any
        // constants for which `constants != constants.with_launcher_id(launcher_id)` -- leaving
        // those two fields zeroed here made that comparison fail on every call, deterministically
        // (never actually flaky), which sent every read down the guard's deliberately-permissive
        // "could not decode" path instead of exercising the epoch_seconds check at all.
        let constants = RewardDistributorConstants {
            launcher_id,
            reward_distributor_type: RewardDistributorType::Managed {
                manager_singleton_launcher_id: Bytes32::default(),
            },
            fee_payout_puzzle_hash: Bytes32::default(),
            epoch_seconds,
            precision: 1,
            max_seconds_offset: 0,
            payout_threshold: 0,
            require_payout_approval: false,
            fee_bps: 0,
            withdrawal_share_bps: 0,
            reserve_asset_id: Bytes32::default(),
            reserve_inner_puzzle_hash: Bytes32::default(),
            reserve_full_puzzle_hash: Bytes32::default(),
        }
        .with_launcher_id(launcher_id);

        let mut ctx = SpendContext::new();
        let solution = ctx
            .serialize(&LauncherSolution {
                singleton_puzzle_hash: Bytes32::default(),
                amount: 1,
                key_value_list: (0u64, constants),
            })
            .expect("a plain LauncherSolution always serializes");

        let spend = CoinSpend::new(launcher_coin, chia_protocol::Program::default(), solution);
        (launcher_id, spend)
    }

    /// A1 (dig_ecosystem#3310): a distributor whose launch constants carry `epoch_seconds == 0`
    /// is refused by THIS crate's own guard, before `dig_rewards_coin::state::read_distributor`
    /// is ever called -- proven here by never wiring a real reader into `StubSource` at all: if
    /// the guard did not refuse first, this test would panic somewhere else entirely (a
    /// `read_distributor` call against a source with no reward-distributor coin state), not
    /// cleanly return the expected error.
    #[test]
    fn guard_refuses_epoch_seconds_zero_before_reading_the_distributor() {
        let (launcher_id, spend) = launcher_spend_with(0);
        let source = StubSource {
            spends: HashMap::from([(launcher_id, spend)]),
        };

        let result = read_distributor_guarded(&source, launcher_id);

        assert!(
            matches!(result, Err(GuardedReadError::NonTerminatingEpochSeconds)),
            "expected NonTerminatingEpochSeconds, got {result:?}"
        );
    }

    /// The guard's inverse: a legitimate, non-zero `epoch_seconds` is NOT refused by this guard --
    /// the read proceeds to `dig_rewards_coin::state::read_distributor`, which then answers on its
    /// own terms (here, `RewardsError::ChainUnavailable`, since `StubSource` holds no reward-slot
    /// state at all -- the guard's job is only to not be the reason this call failed).
    #[test]
    fn guard_passes_through_a_legitimate_epoch_seconds() {
        let (launcher_id, spend) = launcher_spend_with(3600);
        let source = StubSource {
            spends: HashMap::from([(launcher_id, spend)]),
        };

        let result = read_distributor_guarded(&source, launcher_id);

        assert!(
            !matches!(result, Err(GuardedReadError::NonTerminatingEpochSeconds)),
            "a legitimate epoch_seconds must not be refused by this crate's own guard, got {result:?}"
        );
    }
}
