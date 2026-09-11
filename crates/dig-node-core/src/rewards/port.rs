//! The chain port — the seam this whole engine is built against instead of `dig-rewards-coin`.
//!
//! `dig-rewards-coin` was SPEC-only as of the tag this lane first read it: `src/lib.rs` was a
//! documented placeholder and `pub mod distributor {}` was empty. So the prover engine is built
//! COMPLETELY against a narrow trait derived from the SPEC's own described surface (not from the
//! driver's internals, so it is stable across the driver landing), tested with an in-memory fake, and
//! the production adapter reports [`ChainPortError::Unavailable`] and runs no cycles. See
//! [`UnavailableChainPort`] for that adapter.
//!
//! # The reader HAS shipped (corrected: the text here was written against 0.2.0)
//!
//! `dig-rewards-coin` publishes **0.4.1** (latest on the crates.io index as this was written; 0.4.0
//! read first-hand from the local registry cache, since this crate deliberately does not depend on
//! it) and it ships the chain reader the paragraph below said it withheld:
//! `state::read_distributor(&impl ChainSource, launcher_id) -> Result<Option<DistributorSnapshot>,
//! RewardsError>`, plus `clawback::recoverable_base_units(rewards_base_units,
//! withdrawal_share_bps) -> Option<u64>`, which refuses above `10_000` bps exactly as this seam's
//! own range check does. **Blocker 1 is CLOSED**, and what follows it described a crate two
//! releases old; it is kept only because the SHAPE argument it makes still holds.
//!
//! What dig-node still lacks is an ADAPTER, which is a different thing from a reader:
//! `read_distributor` takes a caller-supplied `ChainSource` and does no socket I/O of its own, so
//! something must hold the chain source, call the reader and map its answers onto this trait. That
//! is dig_ecosystem#3310's job, in `dig-node-service`, injected down through
//! [`crate::Node::install_reward_chain_port`]. It is NOT #3249, the driver ticket: a crate that
//! does no I/O can never be the adapter, so every "until #3249 lands" written about an adapter was
//! a pointer at a ticket that structurally cannot ship it — and a blocker filed on such a ticket
//! is never read.
//!
//! The historical 0.2.0 finding, for the reasoning it carries:
//! 0.2.0's own `state.rs:1-31` module doc says so directly: SPEC §12.1's `read_distributor` "does not
//! publish one, deliberately" — the implementation that existed applied
//! `RewardDistributor::from_parent_spend` to the eve coin's spend (the launch inner puzzle) instead
//! of `from_eve_coin_spend`, so every read reported `Malformed`; the correct hop additionally needs
//! `reserve_parent_id`/`reserve_lineage_proof` provenance a reader starting from a launcher id cannot
//! currently discover. That is tracked as real design work at
//! <https://github.com/DIG-Network/dig_ecosystem/issues/3267> — as of this unit, open, with a PR up
//! (`DIG-Network/dig-rewards-coin#6`, `feat/3267-chain-reader`, +950/-80, targeting `0.3.0`) — and
//! 0.2.0's own doc states the rule the future reader must honour: "every `ChainSource` error MUST
//! become `RewardsError::ChainUnavailable` … a distributor whose read failed MUST NOT render as 'no
//! entries' or 'nothing accrued'". Read this adapter against `0.3.0`'s actual reader shape when it
//! ships, not against this description.
//!
//! **Blocker 2, independent of #3267:** nothing in this codebase today records which distributors
//! this node funds. `funded_distributors` (below) needs that identity set as its starting point —
//! there is no chain-wide "list every distributor and filter to mine" call this crate can make. The
//! only adjacent registry is the CLAIM side's `ClaimChainPort::discover_distributors` in
//! `dig-node-service`'s `rewards_claim::port` — a **different trait**, filtering by mirror-admission
//! (which distributors this node might claim FROM), not by funder ownership (which distributors this
//! node funds); it is not a substitute. A repo-wide search for a funder-ownership registry —
//! `grep -rln "funded_launcher_ids\|FundedDistributor\|reward_distributor_registry\|create_distributor\|launch_distributor" crates/ --include=*.rs`
//! — returned **no matches** as of this unit's tip (worth re-running before assuming this is still
//! true; a negative search is a claim about a point in time, not a permanent fact). No launch flow, no
//! config, no persisted launcher-id list exists in this crate or in `dig-node-service` today. Tracked
//! as a separate ticket, parallel to #3267 (not downstream of it): a working reader tells a caller HOW
//! to read one distributor; it does not tell the caller WHICH launcher ids are its own. Both must land
//! before any of `dig.getRewardDistributor` / `dig.listRewardDistributorCommitments` /
//! `dig.listRewardDistributors`'s `funded` half can answer honestly.
//!
//! So no adapter can honestly live HERE, which is a narrower claim than the one this paragraph used
//! to make: `funded_distributors` still has no identity source (blocker 2, below, and still true),
//! and the reader 0.4 does ship needs a `ChainSource` that `dig-node-core` deliberately does not
//! hold — wiring one up in this crate would re-add the `dig-rewards-coin` dependency unit 0 removed. Writing one anyway — either by
//! reimplementing `read_distributor` myself or by inventing a funded-distributor registry with no
//! writer — would be exactly the kind of restated, unreviewed money-shape work SPEC §0.1 clause 1 and
//! this crate's own withholding of a broken reader argue against, and is the shape fork this ticket's
//! kernel invariant 6 says to escalate rather than guess. Escalated to the L1, and settled: no new
//! adapter and no dispatch arm land here until the funder-ownership registry exists and #3310's
//! adapter lands in `dig-node-service`. The reader half of that condition is now met. **`dig.listRewardDistributors` stays `-32601` deliberately** — serving it through
//! `UnavailableChainPort` was considered and rejected: it would be a false capability signal (a
//! feature-probe or `rpc.discover` reading the method as implemented when it always errors) and the
//! exact "dispatch surface with no function behind it" pattern DIG-Network/dig-node#593 was the last
//! PR allowed to land on. `UnavailableChainPort` remains the only production adapter for now — still
//! correct, since every real call would fail for one of the two reasons above regardless. No
//! `dig-rewards-coin` dependency is added by this unit: an unused dependency with no consumer is
//! inert weight; the version it will want is whatever is current when #3310 adds it in
//! `dig-node-service`, the unit that actually consumes it. Do not add it here.

use super::admission::AdmittedPeer;
use async_trait::async_trait;

/// A 32-byte chain identifier (launcher id, store id, root, puzzle hash — all the same shape).
pub type Bytes32 = [u8; 32];

/// One distributor this node funds, as SPEC §1.3 names it: the generation it rewards plus its
/// launcher id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistributorRef {
    pub launcher_id: Bytes32,
    pub store_id: Bytes32,
    pub root: Bytes32,
}

/// One occupied entry slot, as SPEC §10.2 shapes it: keyed by a payout PUZZLE HASH, never a pubkey.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntrySlot {
    pub payout_puzzle_hash: Bytes32,
    pub counter: u64,
    /// SPEC §11.1: always `1` in the MVP; carried here because the chain state reports what is
    /// actually on the slot, not what this crate would choose to write.
    pub shares: u64,
}

/// One distributor's chain-derived state (SPEC §2.3 `counters`, §8, §12.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistributorChainState {
    pub reserve_base_units: u64,
    pub entries: Vec<EntrySlot>,
    /// The `RewardDistributorConstants::epoch_seconds` accrual window ordinal this distributor is
    /// currently in. NOT the mirror-collateral epoch (SPEC §0.3) — an unrelated clock.
    pub current_distributor_epoch: u64,
    /// SPEC §12.4: derived from the singleton's own spend history, never a self-report. `None`
    /// means the entry set has never been written to.
    pub last_entry_write_at: Option<u64>,
    pub total_paid_out_base_units: u64,
}

/// One add/remove decision destined for a bundle (SPEC §6.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryAction {
    /// Carries [`AdmittedPeer`] rather than loose fields: `AdmittedPeer` is mintable only by
    /// `admission::admit`, so an `Add` cannot be constructed from a discovery path that skipped
    /// admission — self-exclusion becomes a compile-time property of this type, not a convention
    /// every future discovery path must remember to honour (SPEC §5.3; DIG-Network/dig-node#261).
    Add(AdmittedPeer),
    Remove {
        payout_puzzle_hash: Bytes32,
        launcher_id: Bytes32,
    },
}

/// One distributor spend bundle: at most [`super::spec_constants::MAX_ENTRY_WRITES_PER_BUNDLE`]
/// actions, one fee (SPEC §6.3 clause 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryWriteBundle {
    pub launcher_id: Bytes32,
    pub actions: Vec<EntryAction>,
    pub fee_mojos: u64,
}

/// Why a chain port call could not complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainPortError {
    /// No chain source is wired yet — the [`unavailable`] adapter's only answer, and what any real
    /// adapter should answer for an unreachable chain too (SPEC §12.2 clause 4).
    Unavailable,
    /// dig_ecosystem#3269/#3284/#3303: the distributor's `withdrawal_share_bps` (a `u64` on the
    /// puzzle) either does not fit the wire's `u16` domain or exceeds the legitimate `0..=10_000`
    /// bps range. The adapter MUST refuse the WHOLE [`RewardsChainPort::distributor_report`] call
    /// rather than silently narrowing (`as u16` would wrap `65_536` to `0`) or omitting the figure:
    /// `withdrawal_share_bps` is curried once per distributor (launch-time, immutable), so an
    /// invalid value can never affect one row of a caller's answer and not another. Refusing the
    /// whole call here therefore blinds zero good rows and needs no wire change — see the module
    /// doc on [`DistributorReport`].
    InvalidWithdrawalShare,
    /// A chain answered but the call failed for a reason worth a message (bounded before logging —
    /// SPEC §3.7 clause 4 applies to every attacker-adjacent string, and a chain error is not
    /// exempt).
    Other(String),
}

/// One clawback commitment slot, as `dig.listRewardDistributorCommitments` (SPEC §7.4 clause 5)
/// needs it.
///
/// `recoverable_base_units` is the adapter's PRE-COMPUTED share — never restated by a caller of
/// this port, and never recomputed by `dig-node-core` itself. NO production adapter exists yet,
/// and no crate in this seam depends on `dig-rewards-coin` today: the adapter that WILL compute
/// this figure is dig_ecosystem#3310's, in `dig-node-service` (that ticket names both
/// `distributor_report` and `Node::install_reward_chain_port` explicitly), and as of this writing
/// that crate's manifest declares no such dependency. When it lands it will be the one crate in
/// this seam that depends on `dig-rewards-coin` (dig_ecosystem#3269 unit 0 removed that dependency
/// from THIS crate deliberately), and it will compute this figure with
/// `dig_rewards_coin::recoverable_base_units` — that crate's own tested, simulator-bound
/// restatement of the puzzle's share arithmetic (u128 intermediate, multiply-then-divide,
/// truncated; see that function's doc for the equality proof against `chia-sdk-driver`). If
/// `withdrawal_share_bps` does not fit `u16` or exceeds `10_000`, that adapter must refuse the
/// WHOLE [`RewardsChainPort::distributor_report`] call with
/// [`ChainPortError::InvalidWithdrawalShare`] instead of returning a `CommitmentSlot` with a
/// wrong, zeroed or omitted `recoverable_base_units` — see that variant's doc for why a
/// per-distributor curried value makes a whole-call refusal the correct shape. The same range is
/// ALSO enforced at the dispatch seam (`seams::dig_rpc::dispatch`'s `range_checked_report`,
/// dig_ecosystem#3284), so an adapter that forgets cannot put an out-of-range share on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitmentSlot {
    /// The distributor epoch this commitment slot funds.
    pub epoch_start: u64,
    /// The chain's `clawback_ph`: the puzzle hash whose key holder alone may claw this slot back
    /// (SPEC §7.4 clause 3) — an entitlement fact, never a display label.
    pub clawback_puzzle_hash: Bytes32,
    /// The committed amount, in base units, as the puzzle records it.
    pub rewards_base_units: u64,
    /// The amount actually recoverable on clawback, in base units. See the type doc: always
    /// pre-computed by the adapter, never by a caller of this trait.
    pub recoverable_base_units: u64,
}

/// One distributor's chain-derived report — everything `dig.getRewardDistributor` and
/// `dig.listRewardDistributorCommitments` (dig_ecosystem#3269 units 1-2) need for one launcher id,
/// from the ONE port call [`RewardsChainPort::distributor_report`] designs once so neither handler
/// can diverge from the other's view of the same distributor.
///
/// Deliberately a NEW type, not a widened [`DistributorChainState`]: that type is the prover cycle
/// engine's own shape (SPEC §2.3, §8, §12.4, dig_ecosystem#3250) and widening it would reach into
/// that ticket's territory for a need this one does not share (`fee_bps`, `withdrawal_share_bps`,
/// commitments, and the distributor's launch constants are irrelevant to the prover cycle).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistributorReport {
    pub launcher_id: Bytes32,
    pub store_id: Bytes32,
    pub root: Bytes32,
    /// The payout epoch length, in seconds — a launch-curried, immutable distributor constant.
    pub epoch_seconds: u64,
    /// Unix seconds the first epoch started.
    pub first_epoch_start: u64,
    /// The reserve threshold, in base units, that triggers a payout.
    pub payout_threshold: u64,
    /// The distributor's fee, in basis points.
    pub fee_bps: u16,
    /// Already narrowed to the wire's `u16` domain and validated `<= 10_000` by the adapter — see
    /// [`ChainPortError::InvalidWithdrawalShare`] for what happens when the chain's raw `u64`
    /// constant fails either check.
    pub withdrawal_share_bps: u16,
    pub reserve_base_units: u64,
    pub entry_count: u64,
    pub current_distributor_epoch: u64,
    /// Unix seconds of the most recent entry-set write on chain, if any. `None` is a positive
    /// fact (no write has ever happened since launch), never "unknown" — SPEC §2.4 clause 1.
    pub last_entry_write_at: Option<u64>,
    /// SPEC §12.4: computed by the adapter from the chain-derived write history against
    /// `dig_rewards_coin::STALE_ENTRY_SET_SECONDS` at read time — never self-reported by a
    /// possibly-wedged prover loop, and never a hardcoded constant in this crate or its callers.
    pub entry_set_stale: bool,
    /// One entry per outstanding commitment slot. Empty is legitimate (SPEC §7.4 clause 5): a
    /// distributor funded only via `AddIncentives` has no clawback-eligible slots at all.
    pub commitments: Vec<CommitmentSlot>,
    /// Unix seconds this report was assembled.
    pub observed_at: u64,
}

/// Reads and the one write this engine needs from the reward-distributor chain state. Derived from
/// the SPEC's described surface (§1.3 reads, §6.3 write), not from `dig-rewards-coin`'s internals.
#[async_trait]
pub trait RewardsChainPort: Send + Sync {
    /// SPEC §1.3: every distributor this node funds, with its `(store_id, root)`.
    async fn funded_distributors(&self) -> Result<Vec<DistributorRef>, ChainPortError>;

    /// SPEC §2.3, §8, §12.4: one distributor's current chain-derived state.
    async fn distributor_state(
        &self,
        launcher_id: Bytes32,
    ) -> Result<DistributorChainState, ChainPortError>;

    /// SPEC §6.3: submit ONE bundle of at most `MAX_ENTRY_WRITES_PER_BUNDLE` actions with a fee.
    async fn submit_entry_writes(&self, bundle: EntryWriteBundle) -> Result<(), ChainPortError>;

    /// SPEC §2.1: spend the distributor singleton's `NewEpoch` action when a synced state is
    /// needed for an entry-set write (§8.2) and the epoch has rolled. Idempotent in effect — SPEC
    /// §2.1 clause 3 names TWO willing spenders (this prover and #3251's claim loop) as correct,
    /// not a conflict, and neither MUST treat a not-yet-rolled epoch as an error or assume the
    /// other already did it.
    async fn spend_new_epoch(&self, launcher_id: Bytes32) -> Result<(), ChainPortError>;

    /// SPEC §2.6/§7.4/§12.4, dig_ecosystem#3269 units 1-2: one distributor's full chain-derived
    /// report, feeding both `dig.getRewardDistributor` and `dig.listRewardDistributorCommitments`
    /// from a single call — see [`DistributorReport`]'s doc for why this is a new type rather than
    /// a widened [`DistributorChainState`], and [`ChainPortError::InvalidWithdrawalShare`] for the
    /// one refusal path this call can produce beyond [`ChainPortError::Unavailable`].
    async fn distributor_report(
        &self,
        launcher_id: Bytes32,
    ) -> Result<DistributorReport, ChainPortError>;
}

/// The production adapter until dig_ecosystem#3310 lands: reports
/// [`ChainPortError::Unavailable`] on every call and runs no cycles.
///
/// This is the named state `ChainSourceUnavailable` (SPEC §2.3), not a silent no-op — a no-op that
/// reported progress would be the exact honesty violation §2.4 forbids. #3310 replaces it with an
/// adapter built in `dig-node-service` over `dig-rewards-coin`'s reader and injected through
/// [`crate::Node::install_reward_chain_port`]; nothing above this seam changes.
///
/// This used to cite #3249, the `dig-rewards-coin` DRIVER ticket. That was a dead pointer: the
/// driver crate does no socket I/O — `read_distributor` takes a caller-supplied `ChainSource` — so
/// it can never be this adapter, and #3310 is the ticket that owns it (it names both
/// `distributor_report` and the install call).
pub struct UnavailableChainPort;

#[async_trait]
impl RewardsChainPort for UnavailableChainPort {
    async fn funded_distributors(&self) -> Result<Vec<DistributorRef>, ChainPortError> {
        Err(ChainPortError::Unavailable)
    }

    async fn distributor_state(
        &self,
        _launcher_id: Bytes32,
    ) -> Result<DistributorChainState, ChainPortError> {
        Err(ChainPortError::Unavailable)
    }

    async fn submit_entry_writes(&self, _bundle: EntryWriteBundle) -> Result<(), ChainPortError> {
        Err(ChainPortError::Unavailable)
    }

    async fn spend_new_epoch(&self, _launcher_id: Bytes32) -> Result<(), ChainPortError> {
        Err(ChainPortError::Unavailable)
    }

    async fn distributor_report(
        &self,
        _launcher_id: Bytes32,
    ) -> Result<DistributorReport, ChainPortError> {
        Err(ChainPortError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unavailable_adapter_never_reports_a_cycle_ran() {
        let port = UnavailableChainPort;
        assert_eq!(
            port.funded_distributors().await,
            Err(ChainPortError::Unavailable)
        );
        assert_eq!(
            port.distributor_state([0u8; 32]).await,
            Err(ChainPortError::Unavailable)
        );
        assert_eq!(
            port.submit_entry_writes(EntryWriteBundle {
                launcher_id: [0u8; 32],
                actions: vec![],
                fee_mojos: 0,
            })
            .await,
            Err(ChainPortError::Unavailable)
        );
        assert_eq!(
            port.spend_new_epoch([0u8; 32]).await,
            Err(ChainPortError::Unavailable)
        );
        assert_eq!(
            port.distributor_report([0u8; 32]).await,
            Err(ChainPortError::Unavailable)
        );
    }
}
