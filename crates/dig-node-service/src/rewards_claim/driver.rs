//! Wires the claim engine onto a real background cadence, reachable from the node's actual
//! startup path (DIG-Network/dig_ecosystem#3268). Mirrors [`crate::self_heal`]'s split exactly:
//! a private injected-tick [`drive`] (testable under `#[tokio::test(start_paused = true)]`) behind
//! a pure, tested gate ([`decide_claim_driver`] / [`spawn_claim_driver_if`]) that `server.rs` calls
//! exactly once.
//!
//! # `enabled = true` must stop being a false statement
//! Before this module, nothing in the codebase ever constructed a [`super::ClaimEngine`] outside
//! its own tests (see [`super`]'s module doc, now updated). After it, a background task always
//! exists whenever `rewards_claim.enabled` and `enable_chain_sync` are both true, drives a cycle
//! every `cadence_seconds + jitter`, and its outcome is readable in-process via [`handle`] as a
//! NAMED [`super::ClaimLoopState`] — see [`ClaimLoopHandle`].
//!
//! # Diverges from `self_heal::drive` on purpose: the FIRST pass waits for the interval
//! `self_heal::drive` fires its pass immediately, then once per fixed tick — right for a
//! maintenance sweep with no anti-silence surface. This driver's whole point (A2, the ticket's
//! headline acceptance item) is that "scheduler running, zero cycles ever fired" must be
//! DISTINGUISHABLE from "it ran" via a monotonic cycle counter that reads `0` before any interval
//! has elapsed. Running a pass at spawn, before the counter could ever read `0` under observation,
//! would defeat that on every startup. So [`drive`] sleeps `cadence_seconds + jitter` FIRST, then
//! runs a cycle, then repeats — the counter is genuinely `0` until the first interval elapses.
//!
//! # No RPC surface here (SCOPE)
//! [`handle`] is an IN-PROCESS accessor only — a future RPC (blocked on DIG-Network/dig_ecosystem#3249
//! re-deriving the `ClaimStatus` wire semantics) can read it; this module puts nothing on the wire
//! and adds no RPC method, dispatch-table row or handler.
//!
//! # The only production adapter is [`super::UnavailableClaimChainPort`]
//! #3249 has not landed, so every real cycle this driver runs reports [`super::ClaimLoopState::ChainSourceUnavailable`]
//! and submits nothing — the honest state, not an invented adapter.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chia_protocol::Bytes32;

use super::cadence::{next_interval_seconds, JitterSource};
use super::config::RewardsClaimConfig;
use super::engine::ClaimEngine;
use super::hints::{DistributorHintSource, NoHintSource};
use super::port::{ClaimChainPort, UnavailableClaimChainPort};
use super::types::{ClaimLoopState, ClaimStatus};

/// The in-process accessor onto the running claim loop (SCOPE: never exposed over the wire here).
/// Cheap to clone -- every field is an `Arc`-backed handle onto the same shared state.
///
/// # A2, the anti-silence test
/// [`Self::cycles_driven`] is the counter a reader compares against [`Self::status`]'s
/// [`super::ClaimLoopState`] to tell "constructed and spawned but never drove a cycle" (`0`,
/// `Idle`) apart from "ran and reported a real outcome" (`> 0`, whatever [`super::ClaimEngine`]
/// computed). Neither field alone would do it: `status()` before the first cycle is already
/// `Idle` BY DESIGN (see [`super::types::ClaimLoopState::Idle`]'s doc, "no cycle has ever been
/// attempted yet") -- that is the correct, honest reading, not a defect, and a test that only
/// checked `status()` for `Idle` could not tell a scheduler that never fires apart from one that
/// correctly reports nothing pending. The count is the only thing here that is monotonic and can
/// never be read as "healthy" by a writer describing itself.
#[derive(Clone, Default)]
pub struct ClaimLoopHandle {
    status: std::sync::Arc<Mutex<ClaimStatus>>,
    cycles_driven: std::sync::Arc<AtomicU64>,
    refusal: std::sync::Arc<Mutex<Option<ClaimDriverRefusal>>>,
}

/// Why the driver never reached [`drive`]'s loop at all -- distinct from anything
/// [`super::ClaimLoopState`] can say, because every one of ITS states presupposes an engine that
/// exists and a cycle that was at least attempted. Without this, "disabled", "chain sync is off"
/// and "no operator wallet, so there is nothing to build an engine with" all collapse into the
/// same reassuring `Idle` + zero-count reading -- three different truths about whether this peer
/// is being paid, indistinguishable to an operator or a future `dig.getRewardClaimStatus`. Kept on
/// the DRIVER's own handle, never added to [`super::types::ClaimStatus`] (read-only, and it is the
/// wrong home: it is a fact about whether an engine exists, not about a cycle one ran).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimDriverRefusal {
    /// `rewards_claim.enabled = false` -- the ordinary, deliberate off state.
    Disabled,
    /// `enabled = true` but `enable_chain_sync = false` -- see [`ClaimDriverDecision::ChainSyncDisabled`]'s doc.
    ChainSyncDisabled,
    /// `enabled = true`, chain sync is on, but this node has no operator wallet to derive
    /// [`own_payout_puzzle_hash`] from -- there is no puzzle hash to build an engine with at all.
    NoOperatorWallet,
}

impl ClaimLoopHandle {
    /// The most recent [`ClaimStatus`] any cycle has produced, or [`ClaimStatus::default`]'s
    /// `Idle` state before the first one ever runs.
    #[must_use]
    pub fn status(&self) -> ClaimStatus {
        *self
            .status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// How many times [`super::ClaimEngine::run_cycle`] has been invoked through this handle --
    /// incremented on EVERY invocation, whatever it returned (a refused, faulted or empty cycle
    /// still counts: A1 requires an OBSERVED CYCLE COUNT, never "the task was spawned").
    #[must_use]
    pub fn cycles_driven(&self) -> u64 {
        self.cycles_driven.load(Ordering::SeqCst)
    }

    /// Why no engine was ever built for this handle, or `None` when one was (whether or not it has
    /// driven a cycle yet -- see [`ClaimDriverRefusal`]'s doc for the three-way collapse this
    /// exists to prevent).
    #[must_use]
    pub fn refusal(&self) -> Option<ClaimDriverRefusal> {
        *self
            .refusal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Record why no engine will ever be built on this handle. Called only from
    /// [`spawn_claim_driver_if`]'s non-`Spawn` branches and [`run_claim_driver`]'s
    /// no-operator-wallet path.
    fn set_refusal(&self, reason: ClaimDriverRefusal) {
        *self
            .refusal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(reason);
    }

    /// Record that one cycle was driven and publish its resulting status. Called only from
    /// [`drive`], once per cycle, after `run_cycle` returns.
    fn record(&self, status: ClaimStatus) {
        *self
            .status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = status;
        self.cycles_driven.fetch_add(1, Ordering::SeqCst);
    }
}

/// The process-wide handle to the running (or never-spawned) claim loop -- one per node process,
/// mirroring how [`crate::state::state_dir`] and friends are process-wide singletons. Initialized
/// lazily to its `Idle`/zero default so a reader (a future RPC, a test) never has to handle
/// "not spawned yet" as a THIRD state distinct from `Idle` -- it is the same state, honestly.
static HANDLE: OnceLock<ClaimLoopHandle> = OnceLock::new();

/// The in-process accessor a future RPC (blocked on #3249) reads. Never wired onto the wire here.
#[must_use]
pub fn handle() -> ClaimLoopHandle {
    HANDLE.get_or_init(ClaimLoopHandle::default).clone()
}

/// Drive the claim cadence: sleep `cadence_seconds + jitter` (drawn from `jitter`), run one cycle,
/// record it on `handle`, repeat forever. `now` and `jitter` are injected -- never a global RNG or
/// the clock read directly here -- so the schedule is deterministic and falsifiable under
/// `#[tokio::test(start_paused = true)]` (see this module's doc for why the FIRST pass waits
/// rather than firing immediately, unlike [`crate::self_heal::drive`]).
async fn drive<P, H>(
    mut engine: ClaimEngine<P, H>,
    cadence_seconds: u64,
    jitter_seconds: u64,
    jitter: &dyn JitterSource,
    mut now: impl FnMut() -> u64,
    handle: ClaimLoopHandle,
) where
    P: ClaimChainPort,
    H: DistributorHintSource,
{
    loop {
        let interval = next_interval_seconds(cadence_seconds, jitter_seconds, jitter);
        tokio::time::sleep(Duration::from_secs(interval)).await;
        let t = now();
        engine.run_cycle(t).await;
        let status = engine.status();
        handle.record(status);
        log_cycle(&status, handle.cycles_driven());
    }
}

/// Emit the ONE record that makes a driven cycle observable in a running node.
///
/// Without this, the whole status surface has no reader in a shipped binary: [`handle`] is
/// in-process only and deliberately carries no RPC (deferred to DIG-Network/dig_ecosystem#3249),
/// so a node whose claim loop can never claim a single reward would produce output IDENTICAL to a
/// healthy one -- silence. A status nobody can read is a doc claim, not a measurement.
///
/// [`ClaimLoopState::Nominal`] is the routine case (`info`). Every other state means this peer is
/// earning nothing and names why, which on a money surface is a warning, not chatter.
fn log_cycle(status: &ClaimStatus, cycles_driven: u64) {
    if status.state == ClaimLoopState::Nominal {
        tracing::info!(
            target: "rewards_claim",
            state = ?status.state,
            cycles_driven,
            distributors_known = status.distributors_known,
            distributors_claimable = status.distributors_claimable,
            claims_submitted = status.claims_submitted,
            "claim cycle complete"
        );
    } else {
        tracing::warn!(
            target: "rewards_claim",
            state = ?status.state,
            cycles_driven,
            distributors_known = status.distributors_known,
            distributors_claimable = status.distributors_claimable,
            claims_submitted = status.claims_submitted,
            concat!(
                "claim cycle complete but this node is NOT claiming rewards -- see the named ",
                "state for why"
            )
        );
    }
}

/// A jitter source drawing from the OS CSPRNG (`ring::rand::SystemRandom`, the same primitive
/// [`crate::mirror`]'s signing paths use for randomness in this crate) -- never a global/thread
/// RNG. A CSPRNG failure (the underlying OS call erroring) fails to jitter `0` rather than
/// panicking the driver: the worst case is every node's cadence landing exactly on
/// `cadence_seconds` with no spread, not a crashed claim loop.
struct OsJitter;

impl JitterSource for OsJitter {
    fn jitter_seconds(&self, bound: u64) -> u64 {
        if bound == 0 {
            return 0;
        }
        use ring::rand::SecureRandom;
        let rng = ring::rand::SystemRandom::new();
        let mut buf = [0u8; 8];
        if rng.fill(&mut buf).is_err() {
            return 0;
        }
        // `bound.saturating_add(1)` rather than `bound + 1`: `jitter_seconds` comes from the
        // persisted config unclamped, so `u64::MAX` reaches here and `+ 1` would overflow-panic
        // inside the detached driver task -- killing the claim loop silently for the process
        // lifetime. Saturating keeps the draw in `0..=bound` for every input.
        u64::from_le_bytes(buf) % bound.saturating_add(1)
    }
}

fn unix_now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A6, money-correctness: this node's own payout puzzle hash as the claim-chain entry slot
/// compares it. `$DIG` is a CAT, so the operator's coins -- and therefore the puzzle hash an
/// `InitiatePayout` should be admitted under -- sit at the canonical CAT wrapping of the owner's
/// inner puzzle hash, never the bare inner hash itself: the SAME derivation
/// [`crate::mirror::lifecycle`]'s `reclaimed_coin_id` and [`crate::mirror::funding::dig_cat_puzzle_hash`]'s
/// own doc use ("the operator's ordinary $DIG coins... sit at the canonical CAT wrapping... never
/// the bare owner puzzle hash"). Picking the unwrapped hash here would make every distributor
/// refuse this node's claims (`claims_refused_payout_mismatch`) while [`super::ClaimLoopState::compute_state`]
/// still reads `Nominal` when nothing is claimable at all -- exactly the misdirection this epic has
/// already measured. See this module's tests for the two-sided proof (a distributor paying to this
/// derivation claims; one paying the unwrapped hash is refused).
#[must_use]
pub fn own_payout_puzzle_hash(owner_inner_puzzle_hash: Bytes32) -> Bytes32 {
    crate::mirror::funding::dig_cat_puzzle_hash(owner_inner_puzzle_hash)
}

/// The real, detached claim-loop task: derive this node's own payout puzzle hash from its operator
/// wallet (the same public, no-unseal-required derivation [`crate::server::spawn_mirror_passes`]
/// falls back to), load [`RewardsClaimConfig`], build a [`ClaimEngine`] against the only
/// production adapter that exists ([`UnavailableClaimChainPort`] -- see this module's doc), and
/// drive it forever.
///
/// Never called directly by `server.rs` -- see [`spawn_claim_driver_if`], the tested gate that
/// decides WHETHER to call this. `handle` is INJECTED (never the [`handle`] singleton read
/// directly) so a test can drive this against a private, non-shared handle instead of the
/// process-wide one.
async fn run_claim_driver(handle: ClaimLoopHandle) {
    let paths = dig_wallet::autoseed::default_paths();
    let Some(owner_inner_puzzle_hash) = dig_wallet::operator_wallet::operator_puzzle_hash(&paths)
    else {
        tracing::warn!(
            target: "rewards_claim",
            "no operator wallet is available, so this node has no payout puzzle hash to claim \
             against; the claim loop is NOT started -- rewards_claim.enabled stays true but no \
             cycle will ever run until an operator wallet exists"
        );
        handle.set_refusal(ClaimDriverRefusal::NoOperatorWallet);
        return;
    };
    let own_payout_puzzle_hash = own_payout_puzzle_hash(owner_inner_puzzle_hash);

    run_claim_driver_in(
        &crate::state::state_dir(),
        own_payout_puzzle_hash,
        UnavailableClaimChainPort,
        handle,
    )
    .await;
}

/// The whole production body of the claim loop, with every process global it used to read taken as
/// an argument: the state directory it loads [`RewardsClaimConfig`] from, this node's own payout
/// puzzle hash, and the chain `port`. Split out of [`run_claim_driver`] on the same `load` /
/// `load_from` pattern [`RewardsClaimConfig`] itself uses, for one reason: the joint between the
/// tested gate and the tested [`drive`] loop was previously the only UNTESTED link in the chain,
/// and an untested joint is exactly how #594's claim engine shipped complete and inert.
///
/// Generic over `P` so a test can drive this real body against a fake port; production always
/// passes [`UnavailableClaimChainPort`] (see the module doc -- there is deliberately no second
/// production adapter until #3249 lands).
async fn run_claim_driver_in<P>(
    state_dir: &Path,
    own_payout_puzzle_hash: Bytes32,
    port: P,
    handle: ClaimLoopHandle,
) where
    P: ClaimChainPort,
{
    let cfg = RewardsClaimConfig::load_from(state_dir);
    // A4/F8: a corrupt config is not a reason to refuse to SPAWN -- `ClaimEngine::run_cycle`
    // already fails closed and reports `PersistedStateCorrupt` by name on every cycle until an
    // operator fixes or removes the file (see `engine.rs`'s `run_cycle` doc). Refusing to spawn
    // here instead would report NOTHING at all, which is the exact silent failure this ticket
    // exists to prevent -- a corrupt file must stay visible, not vanish into "never started".

    let engine = ClaimEngine::new(
        port,
        NoHintSource,
        own_payout_puzzle_hash,
        cfg.max_fee_mojos,
        cfg.max_cycle_fee_budget_mojos,
        dig_mirror_coin::DIG_ASSET_ID,
    )
    .with_rotation_cursor(cfg.rotation_cursor)
    .with_persisted_fee_window(state_dir, cfg.cadence_seconds);

    drive(
        engine,
        cfg.cadence_seconds,
        cfg.jitter_seconds,
        &OsJitter,
        unix_now_seconds,
        handle,
    )
    .await;
}

/// Spawn the real claim-loop task, detached, against `handle` -- injected, never the [`handle`]
/// singleton read from inside, so the only place the process-wide singleton is named is
/// [`spawn_claim_driver_from_config`].
fn spawn_claim_driver(handle: ClaimLoopHandle) {
    tokio::spawn(run_claim_driver(handle));
}

/// Why [`spawn_claim_driver_if`] declined to spawn -- named so the caller can log a reason instead
/// of silence (A3). `Disabled` is the ordinary, expected off state (`rewards_claim.enabled =
/// false`); `ChainSyncDisabled` is the one that matters most, because it is reachable with
/// `enabled = true` -- exactly the shape this ticket exists to close: an operator who reads
/// `enabled: true` and believes claims are running, on a node where `enable_chain_sync` is off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClaimDriverDecision {
    Spawn,
    Disabled,
    ChainSyncDisabled,
}

/// The pure decision behind [`spawn_claim_driver_if`] -- no I/O, no logging, so a test can assert
/// every branch directly. `enabled` gates on its own (SPEC-level opt-out); `enable_chain_sync` is
/// gated the same way `spawn_collateral_census` and `mirror::bond_verify::spawn_bond_verifier_install`
/// already are in `server.rs` -- that flag already means "this node talks to the Chia network", and
/// an integration harness sets it false precisely so nothing dials.
fn decide_claim_driver(enabled: bool, enable_chain_sync: bool) -> ClaimDriverDecision {
    if !enabled {
        return ClaimDriverDecision::Disabled;
    }
    if !enable_chain_sync {
        return ClaimDriverDecision::ChainSyncDisabled;
    }
    ClaimDriverDecision::Spawn
}

/// The single wiring seam `server.rs`'s `serve_with_shutdown` calls (A1's "exact precedent":
/// `self_heal::spawn_driver_if`). `spawn` is invoked exactly when [`decide_claim_driver`] returns
/// `Spawn`; every other branch logs its reason instead of spawning silently (A3) and leaves
/// `handle` at its already-honest `Idle` default -- never a third, undocumented state.
///
/// `handle` is INJECTED rather than read from the process-wide [`handle`] singleton, so a test can
/// assert the recorded [`ClaimDriverRefusal`] of each branch in-process, on a private handle, with
/// no cross-test interference from a `OnceLock` that outlives the test that touched it.
fn spawn_claim_driver_if(
    enabled: bool,
    enable_chain_sync: bool,
    handle: &ClaimLoopHandle,
    spawn: impl FnOnce(),
) {
    match decide_claim_driver(enabled, enable_chain_sync) {
        ClaimDriverDecision::Spawn => spawn(),
        ClaimDriverDecision::Disabled => {
            tracing::debug!(
                target: "rewards_claim",
                "rewards_claim.enabled=false; the claim loop is not started"
            );
            handle.set_refusal(ClaimDriverRefusal::Disabled);
        }
        ClaimDriverDecision::ChainSyncDisabled => {
            tracing::warn!(
                target: "rewards_claim",
                "rewards_claim.enabled=true but enable_chain_sync=false; the claim loop is NOT \
                 started -- rewards_claim.enabled is a false statement on this node until chain \
                 sync is enabled"
            );
            handle.set_refusal(ClaimDriverRefusal::ChainSyncDisabled);
        }
    }
}

/// Reads [`RewardsClaimConfig::load`] (the node's own state-dir config) and `enable_chain_sync`,
/// and calls [`spawn_claim_driver_if`] -- the exact one call `serve_with_shutdown` makes.
pub fn spawn_claim_driver_from_config(enable_chain_sync: bool) {
    let cfg = RewardsClaimConfig::load();
    // The ONE place the process-wide singleton is read: everything below it takes an injected
    // handle so it stays testable in-process.
    let process_handle = handle();
    let driver_handle = process_handle.clone();
    spawn_claim_driver_if(cfg.enabled, enable_chain_sync, &process_handle, move || {
        spawn_claim_driver(driver_handle);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    use super::super::port::ClaimPortError;
    use super::super::types::{DiscoveredDistributor, OwnEntry};

    // ---- decide_claim_driver / spawn_claim_driver_if (A3) ----------------------------------

    #[test]
    fn disabled_never_spawns() {
        assert_eq!(
            decide_claim_driver(false, true),
            ClaimDriverDecision::Disabled
        );
        assert_eq!(
            decide_claim_driver(false, false),
            ClaimDriverDecision::Disabled
        );
    }

    #[test]
    fn enabled_but_chain_sync_off_refuses_named() {
        assert_eq!(
            decide_claim_driver(true, false),
            ClaimDriverDecision::ChainSyncDisabled
        );
    }

    #[test]
    fn enabled_and_chain_sync_on_spawns() {
        assert_eq!(decide_claim_driver(true, true), ClaimDriverDecision::Spawn);
    }

    #[test]
    fn gate_invokes_spawn_only_on_the_spawn_decision() {
        let spawned = Arc::new(AtomicUsize::new(0));
        let handle = ClaimLoopHandle::default();

        let s = spawned.clone();
        spawn_claim_driver_if(false, true, &handle, || {
            s.fetch_add(1, Ordering::SeqCst);
        });
        assert_eq!(spawned.load(Ordering::SeqCst), 0, "enabled=false: no spawn");

        let s = spawned.clone();
        spawn_claim_driver_if(true, false, &handle, || {
            s.fetch_add(1, Ordering::SeqCst);
        });
        assert_eq!(
            spawned.load(Ordering::SeqCst),
            0,
            "enabled=true, chain sync off: no spawn"
        );

        let s = spawned.clone();
        spawn_claim_driver_if(true, true, &handle, || {
            s.fetch_add(1, Ordering::SeqCst);
        });
        assert_eq!(
            spawned.load(Ordering::SeqCst),
            1,
            "enabled+chain sync: spawns"
        );
    }

    /// ACCEPTANCE A3: the gate's two refusals are READABLE off the injected handle and distinct
    /// from each other -- not both collapsed into the same zero-cycle `Idle` reading. The third
    /// refusal (`NoOperatorWallet`) is proven in
    /// `a_missing_operator_wallet_is_a_distinct_named_refusal` below; the fourth truth,
    /// "spawned and running but never ticked", is `refusal() == None` with `cycles_driven() == 0`,
    /// asserted here and driven past zero in
    /// `zero_cycles_before_the_interval_elapses_then_a_counted_number_after`.
    #[test]
    fn each_refusal_is_readable_and_distinct_on_the_injected_handle() {
        let disabled = ClaimLoopHandle::default();
        assert_eq!(
            disabled.refusal(),
            None,
            "nothing refused before the gate runs"
        );
        spawn_claim_driver_if(false, true, &disabled, || {});
        assert_eq!(disabled.refusal(), Some(ClaimDriverRefusal::Disabled));

        let chain_off = ClaimLoopHandle::default();
        spawn_claim_driver_if(true, false, &chain_off, || {});
        assert_eq!(
            chain_off.refusal(),
            Some(ClaimDriverRefusal::ChainSyncDisabled)
        );

        let spawned = ClaimLoopHandle::default();
        spawn_claim_driver_if(true, true, &spawned, || {});
        assert_eq!(
            spawned.refusal(),
            None,
            "a spawned driver has refused nothing: the fourth truth, `refusal() == None` with a zero cycle count"
        );
        assert_eq!(spawned.cycles_driven(), 0);

        // The four readings are pairwise distinct, which is the whole point of A3: three refusals
        // plus "running but never ticked" are four different answers to "is this peer being paid".
        let readings = [
            disabled.refusal(),
            chain_off.refusal(),
            Some(ClaimDriverRefusal::NoOperatorWallet),
            spawned.refusal(),
        ];
        for (i, a) in readings.iter().enumerate() {
            for b in &readings[i + 1..] {
                assert_ne!(a, b, "two driver refusals must never read the same");
            }
        }
    }

    /// ACCEPTANCE A3 (third refusal): the no-operator-wallet path records its OWN named reason on
    /// the handle rather than leaving `Idle` + zero cycles, and drives no cycle. `run_claim_driver`
    /// reads the real default wallet paths, so this asserts the refusal only when this machine
    /// genuinely has no operator wallet; where one exists the driver legitimately proceeds and the
    /// refusal stays `None` -- either way the reading is a NAMED one, never a silent `Idle`.
    #[tokio::test]
    async fn a_missing_operator_wallet_is_a_distinct_named_refusal() {
        let paths = dig_wallet::autoseed::default_paths();
        if dig_wallet::operator_wallet::operator_puzzle_hash(&paths).is_some() {
            return; // this machine HAS an operator wallet; the refusal branch is unreachable here
        }
        let handle = ClaimLoopHandle::default();
        run_claim_driver(handle.clone()).await;
        assert_eq!(
            handle.refusal(),
            Some(ClaimDriverRefusal::NoOperatorWallet),
            "no operator wallet must be a named refusal, not a reassuring Idle"
        );
        assert_eq!(handle.cycles_driven(), 0, "and it must drive no cycle");
    }

    // ---- A1 + A2: the anti-silence cycle counter through the real drive() loop -------------

    /// A fake port whose every call succeeds with an empty/zero answer -- enough to let
    /// `run_cycle` reach `Nominal` every time, so the driven-cycle counter is exercised against a
    /// REAL completed cycle, not just an early `ChainSourceUnavailable` return.
    struct EmptyPort;

    #[async_trait]
    impl ClaimChainPort for EmptyPort {
        async fn discover_distributors(
            &self,
        ) -> Result<Vec<DiscoveredDistributor>, ClaimPortError> {
            Ok(Vec::new())
        }
        async fn resolve_launch_comment(
            &self,
            _launcher_id: Bytes32,
        ) -> Result<Option<DiscoveredDistributor>, ClaimPortError> {
            Ok(None)
        }
        async fn reserve_asset_id(&self, _launcher_id: Bytes32) -> Result<Bytes32, ClaimPortError> {
            Ok(Bytes32::from([0u8; 32]))
        }
        async fn payout_threshold(&self, _launcher_id: Bytes32) -> Result<u64, ClaimPortError> {
            Ok(0)
        }
        async fn own_entry(
            &self,
            _launcher_id: Bytes32,
            _payout_puzzle_hash: Bytes32,
        ) -> Result<Option<OwnEntry>, ClaimPortError> {
            Ok(None)
        }
        async fn required_fee_mojos(&self, _launcher_id: Bytes32) -> Result<u64, ClaimPortError> {
            Ok(0)
        }
        async fn submit_initiate_payout(
            &self,
            _launcher_id: Bytes32,
            _payout_puzzle_hash: Bytes32,
            _fee_mojos: u64,
        ) -> Result<(), ClaimPortError> {
            Ok(())
        }
    }

    fn empty_engine() -> ClaimEngine<EmptyPort, NoHintSource> {
        ClaimEngine::new(
            EmptyPort,
            NoHintSource,
            Bytes32::from([1u8; 32]),
            1,
            10,
            Bytes32::from([2u8; 32]),
        )
    }

    async fn settle() {
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
    }

    /// ACCEPTANCE A1 + A2 (the anti-silence test): a scheduler that is running but whose interval
    /// has never elapsed must read `cycles_driven() == 0` -- NOT "spawn returned", an observed
    /// count. Advancing the clock past `cadence_seconds + jitter` must then drive `run_cycle` a
    /// counted number of times.
    #[tokio::test(start_paused = true)]
    async fn zero_cycles_before_the_interval_elapses_then_a_counted_number_after() {
        let cadence = 100u64;
        let handle = ClaimLoopHandle::default();
        let h = handle.clone();
        let driver = tokio::spawn(async move {
            drive(
                empty_engine(),
                cadence,
                0,
                &super::super::cadence::FixedJitter(0),
                {
                    let mut t = 0u64;
                    move || {
                        t += cadence;
                        t
                    }
                },
                h,
            )
            .await;
        });

        settle().await;
        assert_eq!(
            handle.cycles_driven(),
            0,
            "THE ANTI-SILENCE TEST: a scheduler that is running but has never fired a cycle must \
             report a driven-cycle count of 0, not silence and not a false 'ran' reading"
        );

        tokio::time::advance(Duration::from_secs(cadence)).await;
        settle().await;
        assert_eq!(
            handle.cycles_driven(),
            1,
            "one interval elapsed, one cycle driven"
        );
        assert_eq!(
            handle.status().state,
            super::super::types::ClaimLoopState::Nominal,
            "the driven cycle's real outcome is readable, not just its count"
        );

        tokio::time::advance(Duration::from_secs(cadence)).await;
        settle().await;
        assert_eq!(
            handle.cycles_driven(),
            2,
            "a second interval drives a second cycle"
        );

        driver.abort();
    }

    // ---- A3: enabled=false vs. enabled=true+gate-refused are both zero-cycle, named states -

    #[tokio::test(start_paused = true)]
    async fn disabled_config_never_drives_a_cycle_via_the_configured_seam() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = RewardsClaimConfig {
            enabled: false,
            ..RewardsClaimConfig::default()
        };
        cfg.save_to(dir.path()).unwrap();
        // The gate itself (not the full production seam, which reads the process-wide state dir)
        // is what's under test here -- see `gate_invokes_spawn_only_on_the_spawn_decision` above
        // for the direct proof that `enabled=false` never calls `spawn`.
        assert_eq!(
            decide_claim_driver(cfg.enabled, true),
            ClaimDriverDecision::Disabled
        );
    }

    // ---- A6: own_payout_puzzle_hash is the CAT-wrapped hash, proven against the engine ------

    /// A distributor whose recorded entry is keyed to THIS node's own payout derivation is
    /// claimable; one keyed to the bare, unwrapped owner puzzle hash is refused
    /// (`PayoutPuzzleHashMismatch`) -- proving `own_payout_puzzle_hash` computes the CAT-wrapped
    /// hash the engine's `own_entry` comparison expects, not the raw inner hash.
    struct OneDistributorPort {
        entry_keyed_to: Bytes32,
        dig_asset_id: Bytes32,
    }

    #[async_trait]
    impl ClaimChainPort for OneDistributorPort {
        async fn discover_distributors(
            &self,
        ) -> Result<Vec<DiscoveredDistributor>, ClaimPortError> {
            Ok(vec![DiscoveredDistributor {
                launcher_id: Bytes32::from([9u8; 32]),
                store_id: Bytes32::from([0u8; 32]),
                root: Bytes32::from([0u8; 32]),
            }])
        }
        async fn resolve_launch_comment(
            &self,
            _launcher_id: Bytes32,
        ) -> Result<Option<DiscoveredDistributor>, ClaimPortError> {
            Ok(None)
        }
        async fn reserve_asset_id(&self, _launcher_id: Bytes32) -> Result<Bytes32, ClaimPortError> {
            Ok(self.dig_asset_id)
        }
        async fn payout_threshold(&self, _launcher_id: Bytes32) -> Result<u64, ClaimPortError> {
            Ok(1)
        }
        async fn own_entry(
            &self,
            _launcher_id: Bytes32,
            // Ignored ON PURPOSE (see the NOTE below): this fake always hands back the entry keyed
            // to `entry_keyed_to`, so the ENGINE's own comparison decides claimable vs. refused.
            _payout_puzzle_hash: Bytes32,
        ) -> Result<Option<OwnEntry>, ClaimPortError> {
            Ok(Some(OwnEntry {
                payout_puzzle_hash: self.entry_keyed_to,
                counter: 0,
                accrued_base_units: 1_000,
            }))
            // NOTE: `_payout_puzzle_hash` (the argument the engine passed in, this node's own
            // derivation) is ignored on purpose -- this fake always hands back the entry keyed to
            // `entry_keyed_to`, so the engine's OWN comparison (`entry.payout_puzzle_hash !=
            // self.own_payout_puzzle_hash`) is what decides claimable vs. refused, exactly the
            // real chain behaviour this proves against.
        }
        async fn required_fee_mojos(&self, _launcher_id: Bytes32) -> Result<u64, ClaimPortError> {
            Ok(0)
        }
        async fn submit_initiate_payout(
            &self,
            _launcher_id: Bytes32,
            _payout_puzzle_hash: Bytes32,
            _fee_mojos: u64,
        ) -> Result<(), ClaimPortError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn a_distributor_paying_this_nodes_derivation_is_claimable() {
        let owner_inner = Bytes32::from([7u8; 32]);
        let wrapped = own_payout_puzzle_hash(owner_inner);
        let asset_id = Bytes32::from([3u8; 32]);
        let mut engine = ClaimEngine::new(
            OneDistributorPort {
                entry_keyed_to: wrapped,
                dig_asset_id: asset_id,
            },
            NoHintSource,
            wrapped,
            1_000_000,
            10_000_000,
            asset_id,
        );
        let outcomes = engine.run_cycle(1).await;
        assert_eq!(outcomes.len(), 1);
        assert!(
            matches!(
                outcomes[0],
                super::super::types::ClaimOutcome::Submitted { .. }
            ),
            "a distributor keyed to the CAT-wrapped derivation must be claimable, got {:?}",
            outcomes[0]
        );
    }

    #[tokio::test]
    async fn a_distributor_paying_the_unwrapped_hash_is_refused() {
        let owner_inner = Bytes32::from([7u8; 32]);
        let asset_id = Bytes32::from([3u8; 32]);
        let wrapped = own_payout_puzzle_hash(owner_inner);
        let mut engine = ClaimEngine::new(
            OneDistributorPort {
                // Keyed to the RAW inner hash -- the wrong derivation -- not the wrapped one.
                entry_keyed_to: owner_inner,
                dig_asset_id: asset_id,
            },
            NoHintSource,
            wrapped,
            1_000_000,
            10_000_000,
            asset_id,
        );
        let outcomes = engine.run_cycle(1).await;
        assert_eq!(outcomes.len(), 1);
        assert!(
            matches!(
                outcomes[0],
                super::super::types::ClaimOutcome::PayoutPuzzleHashMismatch { .. }
            ),
            "a distributor keyed to the unwrapped hash must be refused, got {:?}",
            outcomes[0]
        );
    }

    // ---- A5: restart safety + clock movement, through the real persisted-config path --------

    #[tokio::test]
    async fn restart_with_a_recent_completion_skips_via_cadence_not_elapsed() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = RewardsClaimConfig {
            cadence_seconds: 1_000,
            last_cycle_completed_at: Some(500),
            ..RewardsClaimConfig::default()
        };
        cfg.save_to(dir.path()).unwrap();

        let mut engine = ClaimEngine::new(
            EmptyPort,
            NoHintSource,
            Bytes32::from([1u8; 32]),
            1,
            10,
            Bytes32::from([2u8; 32]),
        )
        .with_persisted_fee_window(dir.path(), cfg.cadence_seconds);

        let outcomes = engine.run_cycle(900).await; // 900 - 500 = 400 < 1_000
        assert!(outcomes.is_empty());
        assert_eq!(
            engine.status().state,
            super::super::types::ClaimLoopState::CadenceNotElapsed,
            "a crash-restart loop must not immediately re-run a cycle that already ran"
        );
    }

    #[tokio::test]
    async fn restart_with_an_elapsed_completion_runs_a_cycle() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = RewardsClaimConfig {
            cadence_seconds: 1_000,
            last_cycle_completed_at: Some(500),
            ..RewardsClaimConfig::default()
        };
        cfg.save_to(dir.path()).unwrap();

        let mut engine = ClaimEngine::new(
            EmptyPort,
            NoHintSource,
            Bytes32::from([1u8; 32]),
            1,
            10,
            Bytes32::from([2u8; 32]),
        )
        .with_persisted_fee_window(dir.path(), cfg.cadence_seconds);

        let outcomes = engine.run_cycle(2_000).await; // 2_000 - 500 = 1_500 >= 1_000
        assert!(outcomes.is_empty(), "nothing to claim, but the cycle RAN");
        assert_eq!(
            engine.status().state,
            super::super::types::ClaimLoopState::Nominal
        );
    }

    #[tokio::test]
    async fn a_future_dated_completion_fails_closed_not_underflowed() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = RewardsClaimConfig {
            cadence_seconds: 1_000,
            last_cycle_completed_at: Some(10_000), // in the future relative to `now` below
            ..RewardsClaimConfig::default()
        };
        cfg.save_to(dir.path()).unwrap();

        let mut engine = ClaimEngine::new(
            EmptyPort,
            NoHintSource,
            Bytes32::from([1u8; 32]),
            1,
            10,
            Bytes32::from([2u8; 32]),
        )
        .with_persisted_fee_window(dir.path(), cfg.cadence_seconds);

        let outcomes = engine.run_cycle(100).await; // now < last_cycle_completed_at
        assert!(outcomes.is_empty());
        assert_eq!(
            engine.status().state,
            super::super::types::ClaimLoopState::PersistedStateCorrupt,
            "a future-dated clock must fail CLOSED, never compute a negative/underflowed interval"
        );
    }

    // ---- A4: corrupt = true (via a torn file through load_from), never engine::corrupt set --

    #[tokio::test]
    async fn a_torn_config_file_never_runs_a_cycle() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("rewards-claim.json"), b"{ not json").unwrap();

        let cfg = RewardsClaimConfig::load_from(dir.path());
        assert!(
            cfg.corrupt,
            "load_from must observe the torn file as corrupt"
        );

        let mut engine = ClaimEngine::new(
            EmptyPort,
            NoHintSource,
            Bytes32::from([1u8; 32]),
            1,
            10,
            Bytes32::from([2u8; 32]),
        )
        .with_persisted_fee_window(dir.path(), 1_000);

        let outcomes = engine.run_cycle(1).await;
        assert!(outcomes.is_empty());
        assert_eq!(
            engine.status().state,
            super::super::types::ClaimLoopState::PersistedStateCorrupt
        );
    }
    // ---- The JOINT: the production body itself, not the halves around it -------------------

    /// Write a `rewards-claim.json` with a fixed cadence and NO jitter, so a composition test can
    /// advance the clock by an exact number of seconds and know precisely how many cycles that
    /// buys.
    fn write_config(dir: &Path, cadence_seconds: u64) {
        RewardsClaimConfig {
            enabled: true,
            cadence_seconds,
            jitter_seconds: 0,
            ..RewardsClaimConfig::default()
        }
        .save_to(dir)
        .unwrap();
    }

    /// THE COMPOSITION TEST. `decide_claim_driver` was tested, `drive` was tested -- and the
    /// production body that joins them (`run_claim_driver_in`: load the config from the state dir,
    /// construct the engine, reach `drive`) was tested by NOTHING. That is the same shape as #594,
    /// which shipped a complete, fully-tested, entirely INERT claim engine: if this body returned
    /// early, built the engine wrong, or never reached `drive`, every other test on this change
    /// would still pass and a real node would still never claim.
    ///
    /// So this drives the REAL body -- the one production calls -- and asserts the anti-silence
    /// property through it: zero cycles before the configured interval elapses, then an exactly
    /// COUNTED number after.
    #[tokio::test(start_paused = true)]
    async fn the_production_body_drives_counted_cycles_from_a_written_config() {
        let cadence = 100u64;
        let dir = tempfile::tempdir().unwrap();
        write_config(dir.path(), cadence);

        let handle = ClaimLoopHandle::default();
        let h = handle.clone();
        let state_dir = dir.path().to_path_buf();
        let driver = tokio::spawn(async move {
            run_claim_driver_in(&state_dir, Bytes32::from([1u8; 32]), EmptyPort, h).await;
        });

        settle().await;
        assert_eq!(
            handle.cycles_driven(),
            0,
            "the production body must honour the configured interval: no cycle before it elapses"
        );

        tokio::time::advance(Duration::from_secs(cadence)).await;
        settle().await;
        assert_eq!(
            handle.cycles_driven(),
            1,
            concat!(
                "one configured interval elapsed: the production body drove exactly one cycle, ",
                "proving the joint between the tested gate and the tested drive loop is live"
            )
        );

        tokio::time::advance(Duration::from_secs(cadence)).await;
        settle().await;
        assert_eq!(
            handle.cycles_driven(),
            2,
            "and it keeps driving, one cycle per configured interval"
        );

        driver.abort();
    }

    /// The same production body against the port production ACTUALLY passes it
    /// ([`UnavailableClaimChainPort`], the only adapter until #3249) reports
    /// [`ClaimLoopState::ChainSourceUnavailable`] by name once a cycle has been driven -- the
    /// honest state of a real node today. Proves the real adapter path is reached, not only a fake
    /// one: a counted cycle whose outcome names the missing chain source, never a reassuring
    /// `Nominal` and never silence.
    #[tokio::test(start_paused = true)]
    async fn the_production_adapter_reports_chain_source_unavailable_by_name() {
        let cadence = 100u64;
        let dir = tempfile::tempdir().unwrap();
        write_config(dir.path(), cadence);

        let handle = ClaimLoopHandle::default();
        let h = handle.clone();
        let state_dir = dir.path().to_path_buf();
        let driver = tokio::spawn(async move {
            run_claim_driver_in(
                &state_dir,
                Bytes32::from([1u8; 32]),
                UnavailableClaimChainPort,
                h,
            )
            .await;
        });

        // Let the spawned body reach its first `sleep` before advancing: under paused time an
        // `advance` that lands before the timer is registered buys no cycle at all.
        settle().await;
        tokio::time::advance(Duration::from_secs(cadence)).await;
        settle().await;
        assert_eq!(handle.cycles_driven(), 1, "one cycle was driven");
        assert_eq!(
            handle.status().state,
            super::super::types::ClaimLoopState::ChainSourceUnavailable,
            "with no chain adapter wired, the driven cycle must name ChainSourceUnavailable"
        );
        assert_eq!(
            handle.refusal(),
            None,
            "the loop RAN: an unavailable chain source is a cycle outcome, not a refusal to start"
        );

        driver.abort();
    }

    // ---- the cycle log: the only reader of the status surface in a shipped binary ----------

    /// An in-memory sink a `tracing_subscriber::fmt` layer renders records into, so a test can
    /// assert what a running node would actually print (the same pattern `never_log.rs` and
    /// `server.rs` use for their log assertions).
    #[derive(Clone)]
    struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for CapturedLogs {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("the capture buffer")
                .extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLogs {
        type Writer = CapturedLogs;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    impl CapturedLogs {
        fn rendered(&self) -> String {
            String::from_utf8(self.0.lock().expect("the capture buffer").clone())
                .expect("the rendered lines are utf-8")
        }
    }

    /// Install a capturing subscriber for the duration of the returned guard. `set_default` is
    /// thread-local, and `#[tokio::test]` runs a current-thread runtime, so the driver task
    /// spawned below is polled on this very thread and its records land in the buffer.
    fn capture_logs() -> (CapturedLogs, tracing::subscriber::DefaultGuard) {
        let buffer = CapturedLogs(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buffer.clone())
            .with_ansi(false)
            .without_time()
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        (buffer, guard)
    }

    /// THE ACCEPTANCE BAR: a driven cycle is OBSERVABLE, not merely readable through an
    /// in-process handle nothing in the shipped binary calls. A healthy cycle says so at `INFO`,
    /// naming its state and its cycle count.
    #[tokio::test(start_paused = true)]
    async fn a_driven_cycle_emits_an_event_naming_its_state() {
        let cadence = 100u64;
        let (logs, _guard) = capture_logs();
        let handle = ClaimLoopHandle::default();
        let h = handle.clone();
        let driver = tokio::spawn(async move {
            drive(
                empty_engine(),
                cadence,
                0,
                &super::super::cadence::FixedJitter(0),
                {
                    let mut t = 0u64;
                    move || {
                        t += cadence;
                        t
                    }
                },
                h,
            )
            .await;
        });

        settle().await;
        assert_eq!(
            logs.rendered(),
            "",
            "no interval has elapsed, so there is nothing to report yet"
        );

        tokio::time::advance(Duration::from_secs(cadence)).await;
        settle().await;
        driver.abort();

        let rendered = logs.rendered();
        assert!(
            rendered.contains("Nominal"),
            "the event must NAME the state a reader has to act on; got: {rendered}"
        );
        assert!(
            rendered.contains("cycles_driven=1"),
            "and the cycle count that distinguishes a running loop from a stalled one; got: {}",
            rendered
        );
        assert!(
            rendered.contains("rewards_claim"),
            "under the module's own target, so it can be filtered on; got: {rendered}"
        );
    }

    /// A cycle that CANNOT claim -- today's real production path, with no chain adapter wired --
    /// must be a WARNING naming the state, not an `INFO` line that reads like health. This is the
    /// defect the whole ticket exists to remove: silence covering a permanent inability to earn.
    #[tokio::test(start_paused = true)]
    async fn a_cycle_that_cannot_claim_warns_and_names_why() {
        let cadence = 100u64;
        let (logs, _guard) = capture_logs();
        let handle = ClaimLoopHandle::default();
        let h = handle.clone();
        let driver = tokio::spawn(async move {
            drive(
                ClaimEngine::new(
                    UnavailableClaimChainPort,
                    NoHintSource,
                    Bytes32::from([1u8; 32]),
                    1,
                    10,
                    Bytes32::from([2u8; 32]),
                ),
                cadence,
                0,
                &super::super::cadence::FixedJitter(0),
                {
                    let mut t = 0u64;
                    move || {
                        t += cadence;
                        t
                    }
                },
                h,
            )
            .await;
        });

        settle().await;
        tokio::time::advance(Duration::from_secs(cadence)).await;
        settle().await;
        driver.abort();

        let rendered = logs.rendered();
        assert!(
            rendered.contains("WARN"),
            "earning nothing is a warning, not routine chatter; got: {rendered}"
        );
        assert!(
            rendered.contains("ChainSourceUnavailable"),
            "and it must name WHY this node is not claiming; got: {rendered}"
        );
    }

    /// `jitter_seconds` is read from the persisted config WITHOUT a clamp, so the maximum `u64`
    /// reaches `OsJitter`. An overflowing `bound + 1` there panics the detached driver task,
    /// which never restarts -- the claim loop would die silently for the process lifetime.
    #[test]
    fn an_unclamped_max_jitter_bound_does_not_panic_the_driver() {
        let bound = std::hint::black_box(u64::MAX);
        let offset = OsJitter.jitter_seconds(bound);
        assert!(
            offset <= bound,
            "the draw must stay within 0..=bound; got {offset}"
        );
    }
}
