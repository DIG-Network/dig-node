//! This node's peer-side claim-loop preferences (requirement 5) — persisted the same way
//! `crate::collateral::CollateralConfig` is: a dedicated JSON file in the node's state dir, every
//! field `#[serde(default = "...")]` so a config written before a field existed loads that field's
//! DEFAULT, never a fabricated deliberate choice.

use std::path::Path;

use chia_protocol::Bytes32;
use serde::{Deserialize, Serialize};

use super::cadence::CLAIM_JITTER_SECONDS_DEFAULT;

/// SPEC §8.6: the peer-side claim cadence default.
pub const CLAIM_CADENCE_SECONDS_DEFAULT: u64 = 86_400;

/// The max fee ceiling this node will spend on ONE claim (requirement 2). Not a floor: a true
/// "net > 0" floor is not computable here — the fee is XCH mojos, the reward is $DIG base units,
/// and the node holds no exchange rate between them. SPEC §8.3 clause 2 already asserts
/// `payout_threshold` (1 $DIG) is "above any plausible fee", so the threshold IS the economic floor
/// by construction; this constant only caps what the node will pay to collect it.
///
/// # Defect C1: the magnitude, not the reasoning, was wrong
/// This constant originally reused `crate::mirror::signer::MIRROR_SPEND_FEE_CEILING_MOJOS`
/// (1_000_000_000 mojos = 0.001 XCH) — a number sized for a mirror-coin spend, not a per-distributor
/// claim repeated daily. Against a routine Chia transaction fee of 5,000-100,000 mojos, that ceiling
/// was four to five orders of magnitude too loose to ever bind a real fee: a peer could still lose
/// money inside it whenever 1 $DIG is worth less than 0.001 XCH, and the ceiling would never notice.
/// 200,000 mojos is 2x the top of the observed routine-fee range — enough headroom to survive a
/// congested mempool without giving up the one computable control this loop has.
pub const CLAIM_FEE_CEILING_MOJOS_DEFAULT: u64 = 200_000;

/// The per-cycle AGGREGATE fee budget (Defect C2): a cap on what this node will spend across ALL
/// claims in one cycle, independent of [`CLAIM_FEE_CEILING_MOJOS_DEFAULT`]'s per-claim cap.
///
/// `required_fee_mojos(launcher_id)` is per-distributor state that anyone may create: a DIG-asset
/// distributor may be launched over any widely mirrored store. Without an aggregate cap, an
/// attacker funding K such distributors and getting a victim peer's payout puzzle hash admitted to
/// each could force that peer to spend up to `K * CLAIM_FEE_CEILING_MOJOS_DEFAULT` of its own XCH
/// per cycle, at a cost to the attacker of only K $DIG. Defaulting this to 10x the per-claim ceiling
/// bounds a single cycle to roughly 10 distributors' worth of fees before the loop stops claiming
/// for the rest of that cycle and reports it by name
/// (`ClaimOutcome::SkippedCycleBudgetExhausted`) — configurable for an operator who mirrors more
/// than that many distributors' worth of stores.
pub const CLAIM_CYCLE_FEE_BUDGET_MOJOS_DEFAULT: u64 = CLAIM_FEE_CEILING_MOJOS_DEFAULT * 10;

/// F10 (§8.6 floor): the lowest `cadence_seconds` this config will honour. SPEC §8.6 sets the
/// default at `86_400` but never floors an operator-supplied override, so an unvalidated `0` (or a
/// handful of seconds) would hot-loop `ClaimEngine::run_cycle` — a chain read on every tick with no
/// cadence protection at all, the same class of unbounded-work defect F7 closed for spend. One
/// minute is short enough to never bind a legitimate operator (SPEC's own default is a full day)
/// and long enough that a degenerate value cannot turn this loop into a busy-poll.
pub const CLAIM_CADENCE_FLOOR_SECONDS: u64 = 60;

const REWARDS_CLAIM_CONFIG_FILE: &str = "rewards-claim.json";

/// This node's peer-side claim-loop preferences.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewardsClaimConfig {
    /// Whether the claim loop runs at all. Default-on: a peer earning rewards and never claiming
    /// them is the silent-failure case this ticket exists to prevent, so opting IN by default is
    /// the honest posture — see [`crate::rewards_claim`]'s module doc.
    ///
    /// # R5: `true` here does not mean the loop is running yet
    /// Nothing in this codebase constructs a [`super::ClaimEngine`] outside this module's own tests
    /// (DIG-Network/dig_ecosystem#3268, not yet landed) — see [`crate::rewards_claim`]'s module doc,
    /// "Not yet wired into node startup". An operator who reads their own `rewards-claim.json` and
    /// sees `enabled: true` is exactly the person who needs to know that; the module doc alone does
    /// not reach them.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// SPEC §8.6: base cadence between claim cycles, before jitter.
    #[serde(default = "default_cadence_seconds")]
    pub cadence_seconds: u64,

    /// SPEC §8.6: the jitter spread applied on top of `cadence_seconds` (see
    /// [`super::cadence::next_interval_seconds`]).
    #[serde(default = "default_jitter_seconds")]
    pub jitter_seconds: u64,

    /// The PER-CLAIM fee ceiling (requirement 2) — see [`CLAIM_FEE_CEILING_MOJOS_DEFAULT`]'s doc for
    /// why this is a ceiling, not a floor, and for the magnitude reasoning (Defect C1).
    #[serde(default = "default_max_fee_mojos")]
    pub max_fee_mojos: u64,

    /// The PER-CYCLE aggregate fee budget (Defect C2) — see
    /// [`CLAIM_CYCLE_FEE_BUDGET_MOJOS_DEFAULT`]'s doc for the attacker-cost reasoning.
    #[serde(default = "default_max_cycle_fee_budget_mojos")]
    pub max_cycle_fee_budget_mojos: u64,

    /// Defect B2: the tie-break cursor [`super::ClaimEngine::order_for_budget`] uses to rotate a
    /// legitimately starved tail (a set of equal-accrual honest distributors whose combined fee
    /// exceeds one cycle's budget every cycle) so the SAME distributors are not dropped every
    /// cycle forever. Persisted here — not just held in the in-memory [`super::ClaimEngine`] — so
    /// a node that restarts daily does not reset the rotation and starve the tail permanently.
    /// `None` until the first cycle defers something; absent from a config written before this
    /// field existed, which is the same as `None` (no rotation history yet).
    #[serde(default)]
    pub rotation_cursor: Option<Bytes32>,

    /// F7: the start (unix seconds) of the CURRENT aggregate-fee-budget window. Read alongside
    /// [`Self::fee_spent_in_window_mojos`] to decide, on each cycle, whether the window has rolled
    /// over (`now - fee_window_start_unix >= cadence_seconds`) or whether spend must keep
    /// accumulating into it. `None` until the first cycle ever runs; absent from a config written
    /// before this field existed, which is the same as `None` (no window has started yet, so the
    /// next cycle starts one fresh rather than reading a fabricated "already spent" history).
    #[serde(default)]
    pub fee_window_start_unix: Option<u64>,

    /// F7: fee mojos already spent inside [`Self::fee_window_start_unix`]'s window. This is the
    /// field that actually bounds a crash-restart loop: without it, every fresh process starts
    /// this at zero and re-grants a full [`Self::max_cycle_fee_budget_mojos`] on every restart, no
    /// matter how many restarts happen inside one cadence period. Defaults to `0` — a config
    /// written before this field existed had spent nothing in a window that did not exist either.
    #[serde(default)]
    pub fee_spent_in_window_mojos: u64,

    /// F7: the unix-second timestamp of the last cycle that ran to completion. The cadence gate
    /// (`now - last_cycle_completed_at < cadence_seconds`) refuses to START a new cycle at all
    /// until the cadence has genuinely elapsed since this time, so a crash-restart loop cannot
    /// immediately re-run a cycle that already ran, independent of the fee-window check above.
    /// `None` until the first cycle ever completes; absent from a config written before this field
    /// existed is the same as `None` (no completed cycle on record, so the next cycle is allowed to
    /// run immediately -- the honest reading for a node that has never run this loop before).
    #[serde(default)]
    pub last_cycle_completed_at: Option<u64>,

    /// F8: set by [`Self::load_from`] (never persisted, never read from the file itself) when the
    /// file was present but unparsable, unreadable, or carried a `fee_spent_in_window_mojos`
    /// exceeding its own `max_cycle_fee_budget_mojos` (F14) — corrupt state, not a fresh peer.
    /// `ClaimEngine` reads this to fail CLOSED (treat the window as fully spent, submit nothing)
    /// rather than the old behaviour of falling back to [`Self::default`], which re-granted a full
    /// budget through the exact crash-restart loop F7 exists to bound. `#[serde(skip)]` because a
    /// value read off disk can never itself declare "I am corrupt" — that fact lives only in
    /// *how* the read failed, decided once, here, at load time.
    #[serde(skip)]
    pub corrupt: bool,
}

fn default_enabled() -> bool {
    true
}

fn default_cadence_seconds() -> u64 {
    CLAIM_CADENCE_SECONDS_DEFAULT
}

fn default_jitter_seconds() -> u64 {
    CLAIM_JITTER_SECONDS_DEFAULT
}

fn default_max_fee_mojos() -> u64 {
    CLAIM_FEE_CEILING_MOJOS_DEFAULT
}

fn default_max_cycle_fee_budget_mojos() -> u64 {
    CLAIM_CYCLE_FEE_BUDGET_MOJOS_DEFAULT
}

impl Default for RewardsClaimConfig {
    fn default() -> Self {
        RewardsClaimConfig {
            enabled: default_enabled(),
            cadence_seconds: default_cadence_seconds(),
            jitter_seconds: default_jitter_seconds(),
            max_fee_mojos: default_max_fee_mojos(),
            max_cycle_fee_budget_mojos: default_max_cycle_fee_budget_mojos(),
            rotation_cursor: None,
            fee_window_start_unix: None,
            fee_spent_in_window_mojos: 0,
            last_cycle_completed_at: None,
            corrupt: false,
        }
    }
}

impl RewardsClaimConfig {
    /// Load from the node's own machine-wide state directory (production entry point).
    pub fn load() -> Self {
        RewardsClaimConfig::load_from(&crate::state::state_dir())
    }

    /// Persist to the node's own machine-wide state directory.
    pub fn save(&self) -> std::io::Result<()> {
        self.save_to(&crate::state::state_dir())
    }

    /// F8: the fail-CLOSED reading for a file this process could not trust — present but
    /// unparsable, unreadable, or carrying a spend that exceeds its own budget (F14). Deliberately
    /// NOT [`Self::default`]: a missing file is a clean first run and defaults are the honest
    /// reading for it, but a corrupt one must never be treated the same way, because `default()`
    /// re-grants a full spend budget into exactly the crash-restart loop F7 exists to bound.
    /// `corrupt: true` is the only signal a caller needs — every other field here is a placeholder
    /// `ClaimEngine` must not act on, and [`Self::save_to`] must never be called with this value
    /// (see [`super::engine::ClaimEngine::persist_fee_window`]'s corrupt-file guard).
    fn poisoned() -> Self {
        RewardsClaimConfig {
            corrupt: true,
            ..Self::default()
        }
    }

    /// Load from an explicit directory.
    ///
    /// A MISSING file is a clean first run: [`Self::default`] is the honest reading, because
    /// nothing has ever been decided or spent yet.
    ///
    /// A file this process cannot trust — unreadable, unparsable, or (F14) carrying a persisted
    /// spend larger than its own budget — is a DIFFERENT fact and must never share `default()`'s
    /// code path (F8): it becomes [`Self::poisoned`], visibly logged, and never fatal to node
    /// start over one preferences file, but never silently re-granting a budget either.
    pub fn load_from(dir: &Path) -> Self {
        let path = dir.join(REWARDS_CLAIM_CONFIG_FILE);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Self::poisoned(),
            Err(e) => {
                tracing::error!(
                    path = %path.display(),
                    error = %e,
                    "the rewards-claim preference file could not be read; failing closed, not \
                     using defaults"
                );
                return Self::poisoned();
            }
        };
        match serde_json::from_str::<RewardsClaimConfig>(&text) {
            Ok(cfg) => {
                // F10 (§8.6 floor): an operator-supplied cadence below the floor is clamped, not
                // corrupt -- see `CLAIM_CADENCE_FLOOR_SECONDS`'s doc for why this is the one F7
                // field that is safe to correct upward rather than fail closed over.
                // THROWAWAY REVERT-CHECK (Finding 3): both enforcement blocks removed to prove
                // `a_cadence_below_the_floor_is_clamped_up_on_load` and
                // `a_spend_exceeding_its_own_budget_fails_closed` are not vacuous. Never merged.
                cfg
            }
            Err(e) => {
                tracing::error!(
                    path = %path.display(),
                    error = %e,
                    "the rewards-claim preference file could not be parsed; failing closed, not \
                     using defaults"
                );
                // THROWAWAY REVERT-CHECK (Finding 3): fail-open instead of `Self::poisoned()`, to
                // prove `a_corrupt_file_fails_closed_not_default` is not vacuous. Never merged.
                Self::default()
            }
        }
    }

    /// Persist to `dir`, ATOMICALLY: written to a temp file beside the real path, then renamed
    /// over it — the same pattern `crate::mirror::reconcile_state::ReconcileState::save_to` uses
    /// for the same class of state in this crate (F8). Without this, a crash mid-`write` can leave
    /// a torn file that [`Self::load_from`] would previously have read as [`Self::default`] and
    /// re-granted a full budget into — the exact restart-loop F7 was written to close, reopened
    /// through F7's own persist path. A rename is atomic on the same filesystem, so the file this
    /// process's crash leaves behind is always either the old complete contents or the new
    /// complete contents, never a half-write.
    pub fn save_to(&self, dir: &Path) -> std::io::Result<()> {
        crate::state::ensure_dir_restricted(dir)?;
        let path = dir.join(REWARDS_CLAIM_CONFIG_FILE);
        let temp = path.with_extension("json.tmp");
        let body = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        std::fs::write(&temp, &body)?;
        crate::control::restrict_permissions(&temp);
        std::fs::rename(&temp, &path)?;
        crate::control::restrict_permissions(&path);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_spec_8_6_and_the_fee_ceiling() {
        let cfg = RewardsClaimConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.cadence_seconds, 86_400);
        assert_eq!(cfg.jitter_seconds, 3_600);
        assert_eq!(cfg.max_fee_mojos, 200_000);
        assert_eq!(cfg.max_cycle_fee_budget_mojos, 2_000_000);
    }

    /// Defect C1 regression: the ceiling must actually bind a routine Chia fee — the old default
    /// (1_000_000_000, transplanted from `MIRROR_SPEND_FEE_CEILING_MOJOS`) was 4-5 orders of
    /// magnitude looser than the observed 5,000-100,000 mojo range and never rejected a real fee.
    #[test]
    fn the_default_per_claim_ceiling_actually_binds_a_routine_fee() {
        let cfg = RewardsClaimConfig::default();
        assert!(
            cfg.max_fee_mojos < 1_000_000,
            "the default ceiling must be within striking distance of a routine fee, not 1e9"
        );
        assert!(
            cfg.max_fee_mojos >= 100_000,
            "the default ceiling must not reject the top of the routine fee range outright"
        );
    }

    #[test]
    fn save_then_load_round_trips_and_survives_restart() {
        let dir = tempfile::Builder::new()
            .prefix("dig-node-rewards-claim-test-")
            .tempdir()
            .expect("a scratch dir");

        let cfg = RewardsClaimConfig {
            enabled: false,
            cadence_seconds: 43_200,
            jitter_seconds: 1_800,
            max_fee_mojos: 150_000,
            max_cycle_fee_budget_mojos: 900_000,
            rotation_cursor: None,
            fee_window_start_unix: None,
            fee_spent_in_window_mojos: 0,
            last_cycle_completed_at: None,
            corrupt: false,
        };
        cfg.save_to(dir.path()).expect("save");

        let loaded = RewardsClaimConfig::load_from(dir.path());
        assert_eq!(loaded, cfg);
    }

    /// Defect B2: a rotation cursor left in memory only resets on every restart, which starves a
    /// legitimately-tied honest tail forever on any node that restarts daily. It must round-trip
    /// through save/load exactly like every other field.
    #[test]
    fn the_rotation_cursor_survives_a_save_load_round_trip() {
        let dir = tempfile::Builder::new()
            .prefix("dig-node-rewards-claim-cursor-test-")
            .tempdir()
            .expect("a scratch dir");

        let cursor = Bytes32::from([7u8; 32]);
        let cfg = RewardsClaimConfig {
            rotation_cursor: Some(cursor),
            ..RewardsClaimConfig::default()
        };
        cfg.save_to(dir.path()).expect("save");

        let loaded = RewardsClaimConfig::load_from(dir.path());
        assert_eq!(loaded.rotation_cursor, Some(cursor));
        assert_eq!(loaded, cfg);
    }

    /// F7: the persisted fee-window fields must round-trip through save/load exactly like every
    /// other field -- this is the state a restart reads back to avoid re-granting a fresh budget.
    #[test]
    fn the_fee_window_fields_survive_a_save_load_round_trip() {
        let dir = tempfile::Builder::new()
            .prefix("dig-node-rewards-claim-fee-window-test-")
            .tempdir()
            .expect("a scratch dir");

        let cfg = RewardsClaimConfig {
            fee_window_start_unix: Some(1_000),
            fee_spent_in_window_mojos: 1_500_000,
            last_cycle_completed_at: Some(1_000),
            ..RewardsClaimConfig::default()
        };
        cfg.save_to(dir.path()).expect("save");

        let loaded = RewardsClaimConfig::load_from(dir.path());
        assert_eq!(loaded, cfg);
    }

    #[test]
    fn a_config_written_before_a_field_existed_loads_that_fields_default() {
        let dir = tempfile::Builder::new()
            .prefix("dig-node-rewards-claim-legacy-test-")
            .tempdir()
            .expect("a scratch dir");
        std::fs::write(dir.path().join(REWARDS_CLAIM_CONFIG_FILE), b"{}").expect("write");

        let loaded = RewardsClaimConfig::load_from(dir.path());
        assert_eq!(loaded, RewardsClaimConfig::default());
    }

    #[test]
    fn a_missing_file_yields_the_default() {
        let dir = tempfile::Builder::new()
            .prefix("dig-node-rewards-claim-missing-test-")
            .tempdir()
            .expect("a scratch dir");
        assert_eq!(
            RewardsClaimConfig::load_from(dir.path()),
            RewardsClaimConfig::default()
        );
    }

    /// F8 regression: a present-but-unparsable file must NOT load as [`RewardsClaimConfig::default`]
    /// — that is exactly the fail-OPEN bug (a torn write reads as a clean first run and re-grants a
    /// full spend budget). Must go red with only the `Err(e) => ... Self::poisoned()` branch of
    /// [`RewardsClaimConfig::load_from`]'s parse-failure arm reverted to `Self::default()`.
    #[test]
    fn a_corrupt_file_fails_closed_not_default() {
        let dir = tempfile::Builder::new()
            .prefix("dig-node-rewards-claim-corrupt-test-")
            .tempdir()
            .expect("a scratch dir");
        std::fs::write(
            dir.path().join(REWARDS_CLAIM_CONFIG_FILE),
            b"{ this is not json, or a torn write mid-object",
        )
        .expect("write garbage");

        let loaded = RewardsClaimConfig::load_from(dir.path());
        assert!(
            loaded.corrupt,
            "a present-but-unparsable file must be reported as corrupt, never silently defaulted"
        );
        assert_ne!(
            loaded,
            RewardsClaimConfig::default(),
            "corrupt state must be distinguishable from a clean first run"
        );
    }

    /// F8: a MISSING file is the opposite fact from a corrupt one -- still a clean first run.
    #[test]
    fn a_missing_file_is_not_corrupt() {
        let dir = tempfile::Builder::new()
            .prefix("dig-node-rewards-claim-missing-not-corrupt-")
            .tempdir()
            .expect("a scratch dir");
        assert!(!RewardsClaimConfig::load_from(dir.path()).corrupt);
    }

    /// F10 (§8.6 floor) regression: an operator (or corrupt/hostile) config with `cadence_seconds:
    /// 0` must not be honoured verbatim -- it would hot-loop `run_cycle` with no cadence
    /// protection at all. Must go red with only the floor-clamp removed from `load_from`.
    #[test]
    fn a_cadence_below_the_floor_is_clamped_up_on_load() {
        let dir = tempfile::Builder::new()
            .prefix("dig-node-rewards-claim-cadence-floor-")
            .tempdir()
            .expect("a scratch dir");
        std::fs::write(
            dir.path().join(REWARDS_CLAIM_CONFIG_FILE),
            br#"{"cadence_seconds": 0}"#,
        )
        .expect("write");

        let loaded = RewardsClaimConfig::load_from(dir.path());
        assert_eq!(loaded.cadence_seconds, CLAIM_CADENCE_FLOOR_SECONDS);
        assert!(!loaded.corrupt, "a low cadence is clamped, not corrupt");
    }

    /// F14 regression: a persisted spend larger than its own budget is corrupt state, not a large
    /// number to clamp down -- clamping down would hand back exactly the budget the corruption was
    /// hiding. Must go red with only that branch removed (i.e. the field loaded verbatim).
    #[test]
    fn a_spend_exceeding_its_own_budget_fails_closed() {
        let dir = tempfile::Builder::new()
            .prefix("dig-node-rewards-claim-spend-overflow-")
            .tempdir()
            .expect("a scratch dir");
        std::fs::write(
            dir.path().join(REWARDS_CLAIM_CONFIG_FILE),
            br#"{"fee_spent_in_window_mojos": 999999999999, "max_cycle_fee_budget_mojos": 2000000}"#,
        )
        .expect("write");

        let loaded = RewardsClaimConfig::load_from(dir.path());
        assert!(
            loaded.corrupt,
            "a spend exceeding its own budget must fail closed, never be clamped down"
        );
    }
}
