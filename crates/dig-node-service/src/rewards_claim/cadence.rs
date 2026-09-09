//! Claim cadence + jitter (SPEC §8.6): the peer's own setting, never curried on the distributor,
//! and jittered so a network of peers on the default does not converge on one minute of the day.
//!
//! The jitter SOURCE is injected — never a global RNG or clock read directly — so the schedule is
//! deterministic under test.

/// SPEC §8.6: the minimum jitter spread every peer MUST apply.
pub const CLAIM_JITTER_SECONDS_DEFAULT: u64 = 3_600;

/// Supplies the jitter offset for one scheduling decision. A production implementation draws from
/// the OS CSPRNG; tests inject a fixed or sequenced value.
pub trait JitterSource: Send + Sync {
    /// An offset in `0..=bound` seconds.
    fn jitter_seconds(&self, bound: u64) -> u64;
}

/// A jitter source that always returns the same value — for deterministic tests.
pub struct FixedJitter(pub u64);

impl JitterSource for FixedJitter {
    fn jitter_seconds(&self, bound: u64) -> u64 {
        self.0.min(bound)
    }
}

/// The next cadence interval, in seconds: `cadence_seconds + jitter`, where `jitter` is drawn from
/// `[0, jitter_seconds]` via the injected source (SPEC §8.6). `jitter_seconds` is a lower bound on
/// the SPREAD available to the source, not a fixed addition — a source that always returns `0`
/// still produces a schedule within the required bound, just at its floor.
#[must_use]
pub fn next_interval_seconds(
    cadence_seconds: u64,
    jitter_seconds: u64,
    source: &dyn JitterSource,
) -> u64 {
    let offset = source.jitter_seconds(jitter_seconds);
    cadence_seconds.saturating_add(offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interval_is_cadence_plus_a_bounded_jitter() {
        let cadence = 86_400;
        let jitter_bound = 3_600;

        let at_floor = next_interval_seconds(cadence, jitter_bound, &FixedJitter(0));
        assert_eq!(at_floor, cadence);

        let at_ceiling = next_interval_seconds(cadence, jitter_bound, &FixedJitter(jitter_bound));
        assert_eq!(at_ceiling, cadence + jitter_bound);

        // A source that tries to exceed the bound is clamped by the source contract itself
        // (FixedJitter here), and the composed interval never exceeds cadence + jitter_seconds.
        let over = next_interval_seconds(cadence, jitter_bound, &FixedJitter(jitter_bound * 10));
        assert!(over <= cadence + jitter_bound);
        assert!(over >= cadence);
    }

    /// ACCEPTANCE 8 (part) — a config setting a cadence OTHER than the default is honoured by the
    /// scheduling function, not silently overridden back to `CLAIM_CADENCE_SECONDS_DEFAULT`.
    #[test]
    fn a_non_default_configured_cadence_is_honoured() {
        let cfg = super::super::config::RewardsClaimConfig {
            enabled: true,
            cadence_seconds: 12_000,
            jitter_seconds: 500,
            max_fee_mojos: 1,
        };
        let interval =
            next_interval_seconds(cfg.cadence_seconds, cfg.jitter_seconds, &FixedJitter(0));
        assert_eq!(
            interval, 12_000,
            "configured cadence, not the 86_400 default"
        );
        let interval_at_ceiling =
            next_interval_seconds(cfg.cadence_seconds, cfg.jitter_seconds, &FixedJitter(500));
        assert_eq!(interval_at_ceiling, 12_500);
    }
}
