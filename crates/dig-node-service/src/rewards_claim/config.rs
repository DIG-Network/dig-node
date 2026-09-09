//! This node's peer-side claim-loop preferences (requirement 5) — persisted the same way
//! `crate::collateral::CollateralConfig` is: a dedicated JSON file in the node's state dir, every
//! field `#[serde(default = "...")]` so a config written before a field existed loads that field's
//! DEFAULT, never a fabricated deliberate choice.

use std::path::Path;

use serde::{Deserialize, Serialize};

use super::cadence::CLAIM_JITTER_SECONDS_DEFAULT;

/// SPEC §8.6: the peer-side claim cadence default.
pub const CLAIM_CADENCE_SECONDS_DEFAULT: u64 = 86_400;

/// The max fee ceiling this node will spend on one claim (requirement 2), reusing
/// `crate::mirror::signer::MIRROR_SPEND_FEE_CEILING_MOJOS` as the source for the same class of
/// peer-side spend. Not a floor: a true "net > 0" floor is not computable here — the fee is XCH
/// mojos, the reward is $DIG base units, and the node holds no exchange rate between them. SPEC
/// §8.3 clause 2 already asserts `payout_threshold` (1 $DIG) is "above any plausible fee", so the
/// threshold IS the economic floor by construction; this constant only caps what the node will pay
/// to collect it. See the module doc's "fee ceiling" reasoning for the full argument.
pub const CLAIM_FEE_CEILING_MOJOS_DEFAULT: u64 =
    crate::mirror::signer::MIRROR_SPEND_FEE_CEILING_MOJOS;

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

    /// The fee ceiling (requirement 2) — see [`CLAIM_FEE_CEILING_MOJOS_DEFAULT`]'s doc for why this
    /// is a ceiling, not a floor.
    #[serde(default = "default_max_fee_mojos")]
    pub max_fee_mojos: u64,
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

impl Default for RewardsClaimConfig {
    fn default() -> Self {
        RewardsClaimConfig {
            enabled: default_enabled(),
            cadence_seconds: default_cadence_seconds(),
            jitter_seconds: default_jitter_seconds(),
            max_fee_mojos: default_max_fee_mojos(),
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
        assert_eq!(cfg.max_fee_mojos, 1_000_000_000);
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
            max_fee_mojos: 500_000_000,
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
