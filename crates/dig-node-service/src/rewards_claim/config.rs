//! This node's peer-side claim-loop preferences (requirement 5) — persisted the same way
//! `crate::collateral::CollateralConfig` is: a dedicated JSON file in the node's state dir, every
//! field `#[serde(default = "...")]` so a config written before a field existed loads that field's
//! DEFAULT, never a fabricated deliberate choice.

use std::path::Path;

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

const REWARDS_CLAIM_CONFIG_FILE: &str = "rewards-claim.json";

/// This node's peer-side claim-loop preferences.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewardsClaimConfig {
    /// Whether the claim loop runs at all. Default-on: a peer earning rewards and never claiming
    /// them is the silent-failure case this ticket exists to prevent, so opting IN by default is
    /// the honest posture — see [`crate::rewards_claim`]'s module doc.
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

    /// Load from an explicit directory. A missing or unparsable file yields the default — the same
    /// survivable-degradation posture as `CollateralConfig::load_from` — visibly logged, never
    /// silent, and never fatal to node start over one preferences file.
    pub fn load_from(dir: &Path) -> Self {
        let path = dir.join(REWARDS_CLAIM_CONFIG_FILE);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Self::default(),
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "the rewards-claim preference file could not be read; using defaults"
                );
                return Self::default();
            }
        };
        match serde_json::from_str(&text) {
            Ok(cfg) => cfg,
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "the rewards-claim preference file could not be parsed; using defaults"
                );
                Self::default()
            }
        }
    }

    /// Persist to `dir`, creating the state directory with restricted permissions if needed.
    pub fn save_to(&self, dir: &Path) -> std::io::Result<()> {
        crate::state::ensure_dir_restricted(dir)?;
        let path = dir.join(REWARDS_CLAIM_CONFIG_FILE);
        let body = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        std::fs::write(&path, body)?;
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
}
