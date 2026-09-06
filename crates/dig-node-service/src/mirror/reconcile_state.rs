//! Persisted state for the daily mirror-URL reconcile detector (`SPEC.md` §25.13.9, dig-node#570).
//!
//! # Losing this file costs a day, never a spend — and it is the ONLY direction that is safe
//!
//! `mirror-reconcile.json` is a THROTTLE record, not a source of truth: [`super::plan`] and
//! `dig_mirror_coin::list` are the only steady-state truths about what is bonded (`SPEC.md` §25.1),
//! exactly as the ordinary lifecycle already holds. A missing, unreadable or malformed file reads
//! as **"never observed"** — every field `None` or empty — and is overwritten by the next check.
//! That delays any automatic spend by at least two personal days (hysteresis needs two agreeing
//! observations) and cannot cause one. Contrast a hypothetical design that persisted a COIN ID here
//! as evidence of a completed reclaim: dig-node#574 records why a persisted id must always be
//! re-verified against chain before being believed, and the cheapest way to honour that here is to
//! never persist one at all.

use serde::{Deserialize, Serialize};

use super::schedule::Observation;

/// The file name, beside `collateral.json` in the node's state directory (`SPEC.md` §25.13.9).
const RECONCILE_STATE_FILE: &str = "mirror-reconcile.json";

fn default_version() -> u32 {
    1
}

/// The most recent INCONCLUSIVE daily check — recorded so an operator can see WHY the last drift
/// report, if any, did not turn into a plan (`SPEC.md` §C's posture object renders this).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InconclusiveObservation {
    /// The personal day the check ran on.
    pub personal_day: i64,
    /// The `SPEC.md` §25.10 advertise-state label that made the gather inconclusive
    /// (`off` / `no_public_address` / `uncorroborated_address` / `no_relay`).
    pub state: String,
}

/// What one daily check concluded — the two outcomes [`ReconcileState::record_check`] accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckOutcome {
    /// The fresh gather established an address (`SPEC.md` §25.13.7.3): `Override` or `Derived`.
    Conclusive {
        /// The URL set this node would advertise, had it reconciled right then.
        urls: Vec<String>,
    },
    /// The fresh gather did not establish an address: `Off`, `NoPublicAddress`, `Uncorroborated`
    /// or `NoRelay`. The PUBLISHED readings are left exactly as they were — fail closed toward the
    /// old address rather than adopting an uncorroborated new one.
    Inconclusive {
        /// The `SPEC.md` §25.10 label naming which of the four it was.
        state: &'static str,
    },
}

/// Persisted detector state — `mirror-reconcile.json`, `SPEC.md` §25.13.9.
///
/// Every field `#[serde(default)]` so a file written by an earlier version of this struct still
/// parses: a field that did not exist yet reads as "never observed" for that field alone, which is
/// the same safe direction the whole file falls back to when it is missing entirely.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconcileState {
    /// Format version, for a future migration to detect. `1` today.
    #[serde(default = "default_version")]
    pub version: u32,
    /// The personal-day index of the last COMPLETED check (`SPEC.md` §25.13.7.2) — conclusive or
    /// not, completing the day either way so a single STUN blip cannot turn into an hourly retry.
    #[serde(default)]
    pub last_completed_day: Option<i64>,
    /// The two most recent CONCLUSIVE observations, oldest first, at most two
    /// (`SPEC.md` §25.13.7.4's hysteresis reads exactly this pair).
    #[serde(default)]
    pub observations: Vec<Observation>,
    /// The most recent INCONCLUSIVE check, if the last completed check was one.
    #[serde(default)]
    pub last_inconclusive: Option<InconclusiveObservation>,
    /// The epoch of the last automatic reconcile with at least one ACCEPTED reclaim
    /// (`SPEC.md` §25.13.7.5's cap).
    #[serde(default)]
    pub last_auto_reconcile_epoch: Option<i64>,
}

impl Default for ReconcileState {
    fn default() -> Self {
        ReconcileState {
            version: default_version(),
            last_completed_day: None,
            observations: Vec::new(),
            last_inconclusive: None,
            last_auto_reconcile_epoch: None,
        }
    }
}

impl ReconcileState {
    /// Load from the node's own machine-wide state directory.
    pub fn load() -> Self {
        Self::load_from(&crate::state::state_dir())
    }

    /// Persist to the node's own machine-wide state directory.
    pub fn save(&self) -> std::io::Result<()> {
        self.save_to(&crate::state::state_dir())
    }

    /// Load from an explicit directory. For tests and callers that already own one.
    ///
    /// A missing file, an unreadable one and a malformed one all fall back to
    /// [`ReconcileState::default`] — "never observed" — which is the one direction that cannot
    /// itself cause a spend (see the module doc). Unlike [`super::collateral`]'s preference file,
    /// nothing here reaches a spend path without ALSO passing the hysteresis and epoch-cap checks
    /// that read this state, so the fallback is silent by design: there is no decision an operator
    /// made that this loss could silently revert.
    pub fn load_from(dir: &std::path::Path) -> Self {
        let path = dir.join(RECONCILE_STATE_FILE);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(_) => return Self::default(),
        };
        serde_json::from_str(&text).unwrap_or_default()
    }

    /// Persist to `dir`, atomically: written beside the real path and renamed over it, so a torn
    /// write (a crash mid-save) cannot leave a half-written file that fails to parse. A parse
    /// failure would fall back to [`Self::default`] anyway (see [`Self::load_from`]), but the
    /// rename is what makes that fallback rare rather than routine on every unclean shutdown.
    pub fn save_to(&self, dir: &std::path::Path) -> std::io::Result<()> {
        crate::state::ensure_dir_restricted(dir)?;
        let path = dir.join(RECONCILE_STATE_FILE);
        let temp = path.with_extension("json.tmp");
        let body = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        std::fs::write(&temp, &body)?;
        crate::control::restrict_permissions(&temp);
        std::fs::rename(&temp, &path)?;
        crate::control::restrict_permissions(&path);
        Ok(())
    }

    /// Record that a check completed on `day`, one way or the other. The ONLY writer of
    /// [`Self::last_completed_day`], [`Self::observations`] and [`Self::last_inconclusive`] — a
    /// single entry point so "record the outcome" and "mark the day completed" can never be done
    /// as two separate steps, one of which a caller forgets.
    pub fn record_check(&mut self, day: i64, outcome: CheckOutcome) {
        match outcome {
            CheckOutcome::Conclusive { urls } => {
                self.observations.push(Observation {
                    personal_day: day,
                    urls,
                });
                // Keep only the two most recent -- `SPEC.md` §25.13.7.4 reads exactly this pair.
                // A `Vec` rather than a fixed `[Observation; 2]` because a fresh node's first
                // observation is a ONE-element state that is not yet stable, and that is a real,
                // representable state rather than an error.
                while self.observations.len() > 2 {
                    self.observations.remove(0);
                }
                self.last_inconclusive = None;
            }
            CheckOutcome::Inconclusive { state } => {
                self.last_inconclusive = Some(InconclusiveObservation {
                    personal_day: day,
                    state: state.to_string(),
                });
            }
        }
        self.last_completed_day = Some(day);
    }

    /// Record that an automatic reconcile ran in `epoch` with at least one accepted reclaim.
    pub fn mark_auto_reconciled(&mut self, epoch: i64) {
        self.last_auto_reconcile_epoch = Some(epoch);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_file_reads_as_never_observed() {
        let dir = tempfile::tempdir().unwrap();
        let state = ReconcileState::load_from(dir.path());
        assert_eq!(state, ReconcileState::default());
    }

    #[test]
    fn a_malformed_file_reads_as_never_observed_rather_than_panicking() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(RECONCILE_STATE_FILE), b"{ not json ").unwrap();
        let state = ReconcileState::load_from(dir.path());
        assert_eq!(state, ReconcileState::default());
    }

    #[test]
    fn round_trips_through_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = ReconcileState::default();
        state.record_check(
            5,
            CheckOutcome::Conclusive {
                urls: vec!["https://a.example:9444".to_string()],
            },
        );
        state.mark_auto_reconciled(3);
        state.save_to(dir.path()).unwrap();

        let reloaded = ReconcileState::load_from(dir.path());
        assert_eq!(reloaded, state);
    }

    /// **An OLDER file missing a field the struct now has** must still parse, reading the missing
    /// field as its safe default — the whole point of `#[serde(default)]` on every field.
    #[test]
    fn an_older_file_missing_a_field_still_parses() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(RECONCILE_STATE_FILE),
            br#"{"version": 1, "last_completed_day": 7}"#,
        )
        .unwrap();
        let state = ReconcileState::load_from(dir.path());
        assert_eq!(state.last_completed_day, Some(7));
        assert_eq!(state.observations, Vec::new());
        assert_eq!(state.last_auto_reconcile_epoch, None);
    }

    #[test]
    fn only_the_two_most_recent_conclusive_observations_are_kept() {
        let mut state = ReconcileState::default();
        state.record_check(1, CheckOutcome::Conclusive { urls: vec!["a".into()] });
        state.record_check(2, CheckOutcome::Conclusive { urls: vec!["b".into()] });
        state.record_check(3, CheckOutcome::Conclusive { urls: vec!["c".into()] });

        assert_eq!(state.observations.len(), 2, "a third observation must evict the oldest");
        assert_eq!(state.observations[0].personal_day, 2);
        assert_eq!(state.observations[1].personal_day, 3);
    }

    /// **An inconclusive check clears the LAST-inconclusive marker's staleness but must NOT erase
    /// the conclusive observation history** — a single STUN blip must not reset hysteresis back to
    /// zero, which is exactly the flap-tolerance property `SPEC.md` §25.13.7.3's "A, inconclusive,
    /// A" example depends on.
    #[test]
    fn an_inconclusive_check_does_not_erase_prior_conclusive_observations() {
        let mut state = ReconcileState::default();
        state.record_check(1, CheckOutcome::Conclusive { urls: vec!["a".into()] });
        state.record_check(2, CheckOutcome::Inconclusive { state: "no_relay" });

        assert_eq!(state.observations.len(), 1, "the day-1 observation must survive");
        assert_eq!(state.last_completed_day, Some(2));
        assert!(state.last_inconclusive.is_some());
    }

    /// **A subsequent CONCLUSIVE check clears the inconclusive marker** — it is "the most recent
    /// inconclusive check", and once a conclusive one has run, there no longer is one to report.
    #[test]
    fn a_conclusive_check_after_an_inconclusive_one_clears_the_marker() {
        let mut state = ReconcileState::default();
        state.record_check(1, CheckOutcome::Inconclusive { state: "off" });
        assert!(state.last_inconclusive.is_some());

        state.record_check(2, CheckOutcome::Conclusive { urls: vec!["a".into()] });
        assert!(state.last_inconclusive.is_none());
    }
}
