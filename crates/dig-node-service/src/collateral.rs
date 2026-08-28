//! The node's side of the deterministic mirror-coin collateral model.
//!
//! Three things live here, and the split matters because two of them are consensus values and one
//! is an operator preference:
//!
//! * the **per-epoch record store** — what this node has censused, keyed by epoch;
//! * the **safety margin** — a LOCAL preference, persisted, that never reaches a consensus input;
//! * the **funding advice** — how much $DIG this operator should hold, and whether they are short.
//!
//! # Every figure comes out of `dig-mirror-collateral`
//!
//! Not one formula is restated here. `required_per_store` is the WHOLE answer: writing
//! `equilibrium x multiplier - handicap` at a call site silently omits the floor clamp, which
//! understates what an advertisement must post, and under-posting costs the operator that epoch's
//! rewards. The same applies to [`apply_safety_margin`] — it rounds UP, and a re-derivation that
//! rounded down would post a base unit short. Call the crate; never repeat its arithmetic.
//!
//! # Units
//!
//! Every amount here is **DIG base units**: `1 DIG = 1_000`, so the smallest expressible amount is
//! `0.001 DIG`. They are never mojos. A mojo is XCH's base unit, `1e-12 XCH`, nine orders of
//! magnitude away, and the two names must not meet in this module.

use std::path::{Path, PathBuf};

use dig_mirror_collateral::{
    apply_safety_margin, EpochRecord, MULT_SCALE, SAFETY_MARGIN_BP_DEFAULT,
};
use dig_node_control_interface::results::{
    CollateralBufferResult, CollateralBufferUnknownReason, CollateralFundingState,
    CollateralRequirementResult, CollateralUnknownReason,
};
use serde::{Deserialize, Serialize};

/// The file holding this node's local collateral preferences.
const COLLATERAL_CONFIG_FILE: &str = "collateral.json";

/// The file holding the per-epoch records this node has censused, one JSON record per line.
const EPOCH_RECORD_FILE: &str = "collateral-epochs.jsonl";

/// This node's local collateral preferences.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollateralConfig {
    /// The safety margin in basis points over the requirement (`100` is `+1%`).
    ///
    /// `default` rather than required, and the default is
    /// [`SAFETY_MARGIN_BP_DEFAULT`] rather than `0`. A config written before this field existed
    /// must not load as a zero margin: zero is a deliberate choice to post the requirement exactly,
    /// and reporting it for a config that never expressed one tells the operator they declined a
    /// cushion they were never offered.
    #[serde(default = "default_margin_bp")]
    pub margin_bp: u64,
}

fn default_margin_bp() -> u64 {
    SAFETY_MARGIN_BP_DEFAULT
}

impl Default for CollateralConfig {
    fn default() -> Self {
        CollateralConfig {
            margin_bp: SAFETY_MARGIN_BP_DEFAULT,
        }
    }
}

impl CollateralConfig {
    /// Load from `dir`, falling back to the default for a missing OR unreadable file.
    ///
    /// An unreadable file yields the default rather than an error because the margin is a cushion:
    /// refusing to start over a corrupt preference file would take the node down over the one
    /// setting whose absence is survivable. The fallback is the `+1%` default, never `0`, so the
    /// degraded path still errs toward over-posting.
    /// Load from the node's own machine-wide state directory.
    ///
    /// The production entry point. It resolves the directory ITSELF via [`crate::state::state_dir`]
    /// rather than accepting one, so there is exactly one answer to "where does this node keep its
    /// state" — the same shape [`crate::spend_audit::SpendLog::in_state_dir`] uses. Handing the
    /// directory in from a caller made the path depend on a value that entered the process from the
    /// environment, which is both a second resolver for one fact and a taint flow CodeQL flags.
    pub fn load() -> Self {
        CollateralConfig::load_from(&crate::state::state_dir())
    }

    /// Persist to the node's own machine-wide state directory.
    pub fn save(&self) -> std::io::Result<()> {
        self.save_to(&crate::state::state_dir())
    }

    /// Load from an explicit directory.
    ///
    /// For tests and for callers that already own a directory. Production uses [`Self::load`].
    pub fn load_from(dir: &Path) -> Self {
        std::fs::read_to_string(dir.join(COLLATERAL_CONFIG_FILE))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    /// Persist to `dir`, creating the state directory with restricted permissions if needed.
    pub fn save_to(&self, dir: &Path) -> std::io::Result<()> {
        crate::state::ensure_dir_restricted(dir)?;
        let path = dir.join(COLLATERAL_CONFIG_FILE);
        let body = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        std::fs::write(&path, body)?;
        crate::control::restrict_permissions(&path);
        Ok(())
    }
}

/// The per-epoch collateral records this node has censused.
///
/// Append-only JSONL, highest revision of an epoch winning, mirroring the spend-audit record's
/// shape for the same reason: a census that rewrote history in place could not be audited.
#[derive(Debug, Clone)]
pub struct EpochRecordStore {
    path: PathBuf,
}

/// What the store holds for the epoch that was asked about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredEpoch {
    /// A record was found and parsed.
    Found(Box<EpochRecord>),
    /// No record for this epoch.
    Absent,
    /// A record for this epoch exists and could not be read.
    ///
    /// Distinct from [`Absent`](Self::Absent) on purpose: "I have not censused this epoch" and "I
    /// censused it and lost the answer" have different remedies, and collapsing them would hand the
    /// operator the same unactionable sentence for both.
    Unreadable,
}

impl EpochRecordStore {
    /// A store at an explicit path.
    pub fn at(path: impl Into<PathBuf>) -> Self {
        EpochRecordStore { path: path.into() }
    }

    /// The node's own store, in the machine-wide state directory.
    ///
    /// The production entry point, for the same reason as [`CollateralConfig::load`]: one resolver
    /// for one fact.
    pub fn in_state_dir() -> Self {
        EpochRecordStore::at(crate::state::state_dir().join(EPOCH_RECORD_FILE))
    }

    /// The file backing this store.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one censused record.
    pub fn put(&self, record: &EpochRecord) -> std::io::Result<()> {
        if let Some(dir) = self.path.parent() {
            crate::state::ensure_dir_restricted(dir)?;
        }
        let mut line = serde_json::to_vec(record).map_err(std::io::Error::other)?;
        line.push(b'\n');
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        f.write_all(&line)?;
        f.flush()?;
        crate::control::restrict_permissions(&self.path);
        Ok(())
    }

    /// What this store holds for `epoch`.
    ///
    /// A line that names the epoch but does not parse yields [`StoredEpoch::Unreadable`] rather
    /// than [`StoredEpoch::Absent`]. That distinction is why the scan reads the raw `epoch` field
    /// separately from the full record: a record that fails to deserialise still usually carries a
    /// readable epoch number, and attributing it is the difference between the node saying "I lost
    /// this" and the node saying "this never happened".
    pub fn get(&self, epoch: u64) -> StoredEpoch {
        let Ok(text) = std::fs::read_to_string(&self.path) else {
            return StoredEpoch::Absent;
        };
        let mut best: Option<EpochRecord> = None;
        let mut saw_unreadable = false;
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            match serde_json::from_str::<EpochRecord>(line) {
                Ok(rec) if rec.epoch == epoch => {
                    best = Some(rec);
                }
                Ok(_) => {}
                Err(_) => {
                    if line_names_epoch(line, epoch) {
                        saw_unreadable = true;
                    }
                }
            }
        }
        match best {
            Some(rec) => StoredEpoch::Found(Box::new(rec)),
            None if saw_unreadable => StoredEpoch::Unreadable,
            None => StoredEpoch::Absent,
        }
    }
}

/// Does an unparseable line claim to be about `epoch`?
///
/// A deliberately shallow probe: it reads only the `epoch` field, because the line already failed
/// to deserialise as a whole and any deeper interpretation of it would be guessing.
fn line_names_epoch(line: &str, epoch: u64) -> bool {
    serde_json::from_str::<serde_json::Value>(line)
        .ok()
        .and_then(|v| v.get("epoch").and_then(serde_json::Value::as_u64))
        == Some(epoch)
}

/// What the node knows about which epoch is currently in force.
///
/// The node does not derive the epoch from the clock. The collateral epoch schedule is a consensus
/// fact anchored on chain, and a node that guessed it would post against the wrong epoch — so the
/// census names the epoch it is working on, and this type carries that answer or the reason there
/// is not one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurrentEpoch {
    /// The census settled on this epoch and its inputs are final.
    Final(u64),
    /// The census reached this epoch but its inputs are still inside the finality depth.
    ///
    /// The figure would still move, so it is not answerable — but the remedy is only to WAIT,
    /// which is a different sentence from "run the census".
    BehindFinalityDepth,
    /// The node has not censused an epoch.
    NotCensused,
    /// The node cannot see the chain, so it cannot know whether a record should exist.
    NoChainSource,
}

/// The mirror-coin epoch containing `now_unix_ms`.
///
/// Delegated to `dig_constants::mirror_epoch_at_unix_ms`, never re-derived. The epoch number is an
/// INPUT TO COIN IDENTITY — `dig_mirror_coin::mirror_hint` takes it — so a node computing a
/// different epoch than its peers does not display a wrong label, it derives a different coin and
/// orphans the epoch's collateral. There must be exactly one implementation of this arithmetic in
/// the ecosystem, and it is not this one.
///
/// Two properties worth naming because a plausible reimplementation loses both: the epoch is
/// **one-based** (the genesis instant is epoch 1, not 0), and it uses `div_euclid`, so an instant
/// one millisecond BEFORE genesis is epoch 0 rather than colliding with epoch 1 as a truncating
/// `/` would.
///
/// A clock before genesis yields a non-positive epoch, which is not an epoch. It is reported as
/// [`CurrentEpoch::NotCensused`] rather than clamped to 1: a machine whose clock is wrong should
/// not be handed epoch 1's requirement as though it were current.
pub fn current_epoch_at(now_unix_ms: i64) -> CurrentEpoch {
    match dig_constants::mirror_epoch_at_unix_ms(now_unix_ms) {
        epoch if epoch >= 1 => CurrentEpoch::Final(epoch as u64),
        _ => CurrentEpoch::NotCensused,
    }
}

/// The mirror-coin epoch in force right now, by the system clock.
pub fn current_epoch_now() -> CurrentEpoch {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    current_epoch_at(now)
}

/// This epoch's per-store requirement, or the named reason the node cannot state it.
///
/// The margin is deliberately not consulted. `required_per_store_dig_base_units` is the PRE-margin,
/// consensus-derived figure every node derives identically; folding a local preference into it here
/// would make this operator's cushion look like the network's price.
pub fn requirement(store: &EpochRecordStore, current: CurrentEpoch) -> CollateralRequirementResult {
    let unknown = |reason| CollateralRequirementResult::Unknown { reason };
    let epoch = match current {
        CurrentEpoch::Final(e) => e,
        CurrentEpoch::BehindFinalityDepth => {
            return unknown(CollateralUnknownReason::BehindFinalityDepth)
        }
        CurrentEpoch::NotCensused => return unknown(CollateralUnknownReason::NotCensused),
        CurrentEpoch::NoChainSource => return unknown(CollateralUnknownReason::NoChainSource),
    };
    match store.get(epoch) {
        StoredEpoch::Found(rec) => CollateralRequirementResult::Known {
            epoch: rec.epoch,
            // The version that COMPUTED the epoch, read off the record, never the newest version
            // this build implements. The two differ exactly when a node has upgraded mid-schedule,
            // which is the one case where the client needs to know the difference.
            protocol_version: rec.protocol_version.0,
            required_per_store_dig_base_units: rec.required_per_store_dig_base_units,
            stores: rec.census.stores,
            owners: rec.census.owners,
            multiplier_micros: rec.multiplier_micros,
            handicap_dig_base_units: rec.handicap_dig_base_units,
        },
        StoredEpoch::Absent => unknown(CollateralUnknownReason::NotCensused),
        StoredEpoch::Unreadable => unknown(CollateralUnknownReason::RecordUnreadable),
    }
}

/// Why a node cannot state the buffer, and what would resolve it.
///
/// The variants are the CONTRACT's ([`CollateralBufferUnknownReason`]); only the operator-facing
/// remedy sentence lives here. **None has a counterpart in [`CollateralUnknownReason`]**, which is
/// the structural reason the buffer is a separate method rather than a widening of the requirement:
/// collapsing "I do not know what I serve" into "I have not censused the epoch" would report a
/// missing LOCAL fact as a missing NETWORK one, and send the operator to fix the wrong thing.
pub fn buffer_remedy(reason: CollateralBufferUnknownReason) -> &'static str {
    match reason {
        CollateralBufferUnknownReason::RequirementUnknown => {
            "this node cannot state this epoch's per-store requirement"
        }
        CollateralBufferUnknownReason::ServedSetUnknown => {
            "this node cannot list the store roots it serves"
        }
        CollateralBufferUnknownReason::ReclaimStateUnknown => {
            "this node cannot tell which of last epoch's collateral has been reclaimed"
        }
        CollateralBufferUnknownReason::BalanceUnknown => {
            "this node does not know your spendable $DIG"
        }
    }
}

/// The multiplier after `epochs` of uninterrupted escalation, starting from `from_micros`.
///
/// Obtained by stepping `dig_mirror_collateral::step_multiplier` in its own HIGH band, never by
/// evaluating a hand-rolled closed form. Re-deriving the recurrence would be a rival implementation
/// of the controller, and it would silently drop two behaviours the real one has: the step is a
/// fraction of the PREVIOUS multiplier and TRUNCATES each epoch (0.8x over four epochs reaches
/// 1.281444, where the closed form gives 1.281445), and the result is clamped at
/// `MULT_CEILING_MICROS`, so a long horizon cannot manufacture headroom the controller could never
/// produce.
///
/// A **worst case, not a forecast.** The high band is the escalating one; inside the dead band the
/// multiplier does not move at all, and most epochs do not escalate.
fn escalated_multiplier_micros(from_micros: u64, epochs: u32) -> u64 {
    // Any saturation above the dead band's high edge is in `Band::High`. Taking the signal cap is
    // the unambiguous choice: it cannot drift into the dead band if the band edges are ever
    // retuned, which a hand-picked "high edge plus one" could.
    let escalating = dig_mirror_collateral::SIGNAL_CAP_MICROS;
    debug_assert_eq!(
        dig_mirror_collateral::Band::of_saturation(escalating),
        dig_mirror_collateral::Band::High,
        "the escalation ceiling must be computed in the controller's escalating band"
    );
    (0..epochs).fold(from_micros, |m, _| {
        dig_mirror_collateral::step_multiplier(m, escalating)
    })
}

/// Scale `amount` by a millionths factor, saturating rather than wrapping.
fn scale_micros(amount: u64, micros: u64) -> u64 {
    u64::try_from(u128::from(amount) * u128::from(micros) / u128::from(MULT_SCALE))
        .unwrap_or(u64::MAX)
}

/// What one epoch's posting costs: the served pairs at the margined per-store requirement.
///
/// Deliberately NOT carried on the wire — a client derives it from `pairs_served_by_this_node`,
/// `required_per_store_dig_base_units` and `margin_bp`, all of which the contract does carry. It is
/// a named function rather than an inline product because three callers need it and they must not
/// drift.
pub fn one_epoch_lock(pairs: u64, required_per_store: u64, margin_bp: u64) -> u64 {
    // `apply_safety_margin` rounds UP; a re-derivation that rounded down would post a base unit
    // short of what qualifies.
    let per_store = apply_safety_margin(required_per_store, margin_bp);
    u64::try_from(u128::from(pairs) * u128::from(per_store)).unwrap_or(u64::MAX)
}

/// Compute the funding advice, in the contract's own shape.
///
/// # Why the recommendation is not "requirement times epochs of runway"
///
/// **Collateral is RECLAIMED, not spent.** Each pass creates the coins for `(store, root, epoch n)`
/// and reclaims epoch `n-1`, and the reclaims run FIRST and are never gated on funds — so the
/// returned collateral funds the creates behind it. Steady state is therefore roughly ONE epoch's
/// lock, not one per epoch. Multiplying by a runway would overstate the answer by the epoch count
/// and tell an operator to buy many times what they need.
///
/// So the total is three terms, which sum without double-counting: the current epoch's posting, the
/// collateral still held in the epoch being reclaimed (the real peak, and the term nobody budgets
/// for), and what the next `horizon_epochs` could add if the multiplier rises at its ceiling.
///
/// `pairs_served_by_this_node` MUST be this node's OWN served set. It is never the requirement's
/// `stores`, which is a network census figure the contract says in as many words is not a node
/// count — multiplying that by the requirement bills one operator for the whole network.
pub fn buffer_advice(
    pairs_served_by_this_node: Option<u64>,
    requirement: &CollateralRequirementResult,
    margin_bp: u64,
    spendable_dig_base_units: Option<u64>,
    horizon_epochs: u32,
) -> CollateralBufferResult {
    let unknown = |reason| CollateralBufferResult::Unknown { reason };

    // Each missing fact gets its OWN reason. Folding the requirement into the served set — which an
    // earlier version of this function did — reports a NETWORK gap as a LOCAL one.
    let CollateralRequirementResult::Known {
        epoch,
        protocol_version,
        required_per_store_dig_base_units,
        multiplier_micros,
        ..
    } = *requirement
    else {
        return unknown(CollateralBufferUnknownReason::RequirementUnknown);
    };
    let Some(pairs) = pairs_served_by_this_node else {
        return unknown(CollateralBufferUnknownReason::ServedSetUnknown);
    };
    let Some(spendable) = spendable_dig_base_units else {
        return unknown(CollateralBufferUnknownReason::BalanceUnknown);
    };

    let lock = one_epoch_lock(pairs, required_per_store_dig_base_units, margin_bp);

    // The overlap is a second epoch's worth at TODAY's price: the coins of epoch n-1, still locked
    // while epoch n's are created.
    let overlap = lock;

    // The ceiling is expressed RELATIVE to today's multiplier, so a client can check the headroom
    // against the multiplier `control.collateral.requirement` already reported.
    let relative_ceiling = |epochs| {
        u64::try_from(
            u128::from(escalated_multiplier_micros(multiplier_micros, epochs))
                * u128::from(MULT_SCALE)
                / u128::from(multiplier_micros.max(1)),
        )
        .unwrap_or(u64::MAX)
    };
    let escalation_ceiling_micros = relative_ceiling(horizon_epochs);
    let headroom = scale_micros(lock, escalation_ceiling_micros).saturating_sub(lock);
    let recommended = lock.saturating_add(overlap).saturating_add(headroom);

    // "Could not cover the NEXT epoch" is ONE epoch of escalation, not the whole horizon: the
    // horizon sizes the cushion, while this threshold is about the epoch immediately ahead.
    let next_epoch_ceiling = scale_micros(lock, relative_ceiling(1));

    let funding_state = if spendable < lock {
        CollateralFundingState::ShortNow
    } else if spendable < next_epoch_ceiling {
        CollateralFundingState::DangerouslyLow
    } else if spendable < recommended {
        CollateralFundingState::BelowRecommendedBuffer
    } else {
        CollateralFundingState::Funded
    };

    CollateralBufferResult::Known {
        epoch,
        protocol_version,
        funding_state,
        recommended_buffer_dig_base_units: recommended,
        spendable_dig_base_units: spendable,
        pairs_served_by_this_node: pairs,
        required_per_store_dig_base_units,
        margin_bp,
        overlap_dig_base_units: overlap,
        escalation_headroom_dig_base_units: headroom,
        horizon_epochs,
        escalation_ceiling_micros,
    }
}

/// Render a DIG base-unit amount as decimal DIG, e.g. `1_047` -> `"1.047"`.
///
/// Formatted from the integer rather than through a float: `1e-3` steps are exactly the resolution
/// an `f64` starts rounding at scale, and a rounded figure about somebody's money is the class of
/// lie this module exists to avoid.
pub fn format_dig(base_units: u64) -> String {
    format!("{}.{:03}", base_units / 1_000, base_units % 1_000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_mirror_collateral::{
        base_per_store, handicap_for_owners, required_per_store, EpochCensus,
    };
    use dig_node_control_interface::params::DEFAULT_BUFFER_HORIZON_EPOCHS;

    /// A record with independently-chosen fields.
    ///
    /// Every parameter is varied by at least one test. A helper that pinned any of them would make
    /// that field untestable through this module, which is exactly how three defects hid in this
    /// crate family in a single day.
    fn record(epoch: u64, multiplier_micros: u64, owners: u64, stores: u64) -> EpochRecord {
        let mut rec = EpochRecord::bootstrap();
        rec.epoch = epoch;
        rec.multiplier_micros = multiplier_micros;
        rec.census = EpochCensus {
            stores,
            owners,
            ..rec.census
        };
        // Every derived field is recomputed, not just the headline one. A helper that left the
        // handicap at the bootstrap value would build a record no census could produce, and a test
        // reading that field would then pin a fixture artefact rather than the model.
        rec.handicap_dig_base_units = handicap_for_owners(owners);
        rec.base_price_dig_base_units = base_per_store(multiplier_micros);
        rec.required_per_store_dig_base_units = required_per_store(multiplier_micros, owners);
        rec
    }

    fn store_at(dir: &Path) -> EpochRecordStore {
        EpochRecordStore::at(dir.join(EPOCH_RECORD_FILE))
    }

    #[test]
    fn a_config_predating_the_margin_field_loads_as_the_default_not_zero() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(COLLATERAL_CONFIG_FILE), b"{}").expect("write");
        // Zero is a deliberate choice to post exactly; a config that never expressed one must not
        // be reported as having declined the cushion.
        assert_eq!(
            CollateralConfig::load_from(dir.path()).margin_bp,
            SAFETY_MARGIN_BP_DEFAULT
        );
        assert_ne!(SAFETY_MARGIN_BP_DEFAULT, 0, "the default must not be zero");
    }

    #[test]
    fn a_stored_margin_survives_a_round_trip_at_a_value_that_is_not_the_default() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Deliberately not the default: a save/load that silently discarded the value would still
        // pass if the fixture used the default.
        CollateralConfig { margin_bp: 250 }
            .save_to(dir.path())
            .expect("save");
        assert_eq!(CollateralConfig::load_from(dir.path()).margin_bp, 250);
    }

    #[test]
    fn requirement_reports_the_stored_epochs_figures_not_a_recomputation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store_at(dir.path());
        // Two epochs present, with DIFFERENT multipliers and owner counts, so answering with the
        // wrong one is observable. A single-record fixture could not see that.
        store.put(&record(7, 1_000_000, 1_000, 40)).expect("put");
        store.put(&record(8, 500_000, 600, 25)).expect("put");

        let answer = requirement(&store, CurrentEpoch::Final(8));
        let CollateralRequirementResult::Known {
            epoch,
            required_per_store_dig_base_units,
            stores,
            owners,
            multiplier_micros,
            ..
        } = answer
        else {
            panic!("expected a known requirement, got {answer:?}");
        };
        assert_eq!(epoch, 8);
        assert_eq!(multiplier_micros, 500_000);
        assert_eq!(owners, 600);
        assert_eq!(stores, 25);
        // Pinned against the crate AND against a concrete value: a symbolic assertion alone would
        // move with a mutation that changed both sides.
        assert_eq!(
            required_per_store_dig_base_units,
            required_per_store(500_000, 600)
        );
        assert_eq!(required_per_store_dig_base_units, 900);
    }

    #[test]
    fn each_missing_fact_gets_its_own_reason() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store_at(dir.path());
        store.put(&record(3, 1_000_000, 1_000, 10)).expect("put");

        let reason = |c| match requirement(&store, c) {
            CollateralRequirementResult::Unknown { reason } => reason,
            other => panic!("expected unknown, got {other:?}"),
        };
        // An epoch the node holds no record for is NOT the same as having no chain to look at,
        // and neither is the same as waiting for finality. The remedies differ, so the tokens must.
        assert_eq!(
            reason(CurrentEpoch::Final(4)),
            CollateralUnknownReason::NotCensused
        );
        assert_eq!(
            reason(CurrentEpoch::NotCensused),
            CollateralUnknownReason::NotCensused
        );
        assert_eq!(
            reason(CurrentEpoch::BehindFinalityDepth),
            CollateralUnknownReason::BehindFinalityDepth
        );
        assert_eq!(
            reason(CurrentEpoch::NoChainSource),
            CollateralUnknownReason::NoChainSource
        );
    }

    #[test]
    fn a_corrupt_record_for_the_asked_epoch_is_unreadable_not_absent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store_at(dir.path());
        // A healthy neighbouring record, so the fixture keeps an honest control: a store that was
        // entirely corrupt could not show that the corruption was ATTRIBUTED to epoch 5.
        store.put(&record(4, 1_000_000, 1_000, 10)).expect("put");
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(store.path())
            .expect("open");
        writeln!(f, r#"{{"epoch":5,"multiplier_micros":"corrupt"}}"#).expect("write");
        drop(f);

        assert_eq!(store.get(5), StoredEpoch::Unreadable);
        assert!(matches!(
            requirement(&store, CurrentEpoch::Final(5)),
            CollateralRequirementResult::Unknown {
                reason: CollateralUnknownReason::RecordUnreadable
            }
        ));
        // The neighbour is still answerable — the corruption did not swallow the store.
        assert!(matches!(
            requirement(&store, CurrentEpoch::Final(4)),
            CollateralRequirementResult::Known { .. }
        ));
        // And an epoch nobody wrote anything about is still ABSENT, not unreadable.
        assert_eq!(store.get(6), StoredEpoch::Absent);
    }

    #[test]
    fn the_epoch_comes_from_the_canonical_clock_and_is_one_based() {
        use dig_constants::{
            MIRROR_EPOCH_GENESIS_UNIX_MS as GENESIS, MIRROR_EPOCH_LENGTH_MS as WEEK,
        };

        // The genesis instant is epoch ONE, not zero. An off-by-one here derives a different coin
        // for every store on the network, so it is pinned explicitly rather than inferred.
        assert_eq!(current_epoch_at(GENESIS), CurrentEpoch::Final(1));
        assert_eq!(current_epoch_at(GENESIS + WEEK - 1), CurrentEpoch::Final(1));
        assert_eq!(current_epoch_at(GENESIS + WEEK), CurrentEpoch::Final(2));
        assert_eq!(
            current_epoch_at(GENESIS + 51 * WEEK),
            CurrentEpoch::Final(52)
        );

        // One millisecond BEFORE genesis. A truncating `/` puts this in epoch 1 alongside genesis
        // itself; `div_euclid` does not, and the boundary is the only input that can tell them
        // apart -- which is why the fixture is this instant and not an arbitrary earlier one.
        assert_eq!(current_epoch_at(GENESIS - 1), CurrentEpoch::NotCensused);
        assert_eq!(current_epoch_at(0), CurrentEpoch::NotCensused);

        // And the live clock agrees with the constant it is supposed to be reading.
        assert_eq!(
            current_epoch_now(),
            current_epoch_at(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("after 1970")
                    .as_millis() as i64
            )
        );
    }

    /// The exact JSON `control.collateral.requirement` puts on the wire.
    ///
    /// Pinned as literal keys and values rather than by round-tripping the Rust type, because a
    /// round-trip proves only that the type agrees with itself. dig-app reads these names, and a
    /// rename that both sides performed together would be invisible to a symmetric test.
    #[test]
    fn the_known_answer_carries_the_census_inputs_a_client_needs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store_at(dir.path());
        store.put(&record(12, 800_000, 750, 31)).expect("put");

        let wire =
            serde_json::to_value(requirement(&store, CurrentEpoch::Final(12))).expect("serialise");
        assert_eq!(wire["state"], "known");
        assert_eq!(wire["epoch"], 12);
        assert_eq!(wire["protocol_version"], 1);
        assert_eq!(wire["multiplier_micros"], 800_000);
        assert_eq!(wire["stores"], 31);
        assert_eq!(wire["owners"], 750);
        // 5.000 DIG equilibrium x 0.8 = 4.000, less the 750-owner handicap. Pinned as a concrete
        // number as well as against the crate, so a mutation moving both sides is still caught.
        assert_eq!(
            wire["required_per_store_dig_base_units"],
            required_per_store(800_000, 750)
        );
        assert_eq!(wire["required_per_store_dig_base_units"], 3_000);
        assert_eq!(wire["handicap_dig_base_units"], 1_000);
        // The margin MUST NOT appear here. It is a local preference, and a client reading it from
        // this method would render one operator's cushion as the network's price.
        assert!(wire.get("margin_bp").is_none());
    }

    /// The unknown branch is a first-class ANSWER on the wire, not an error and not a zero.
    #[test]
    fn the_unknown_answer_names_its_reason_and_carries_no_figure() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store_at(dir.path());

        let wire = serde_json::to_value(requirement(&store, CurrentEpoch::NoChainSource))
            .expect("serialise");
        assert_eq!(wire["state"], "unknown");
        assert_eq!(wire["reason"], "no_chain_source");
        // The field a client would render as a cost is ABSENT, not zero. A zero here reads as
        // "no collateral required", and under-posting costs the operator that epoch's rewards.
        assert!(wire.get("required_per_store_dig_base_units").is_none());
    }

    /// A `Known` requirement with an explicitly-chosen figure, so the buffer tests never depend on
    /// the record store.
    /// `stores` and `owners` are deliberately set to values that are NOT the `pairs` any caller
    /// passes. They are NETWORK census figures, and a buffer that multiplied one of them by the
    /// requirement would bill one operator for the whole network's collateral -- so the fixture is
    /// built so that mistake changes the answer instead of hiding inside it.
    fn known(required: u64) -> CollateralRequirementResult {
        CollateralRequirementResult::Known {
            epoch: 9,
            protocol_version: 1,
            required_per_store_dig_base_units: required,
            stores: 12,
            owners: 300,
            multiplier_micros: 800_000,
            handicap_dig_base_units: 0,
        }
    }

    /// The `Known` fields of a buffer answer, or a loud failure naming what came back instead.
    #[allow(clippy::type_complexity)]
    fn known_buffer(
        a: CollateralBufferResult,
    ) -> (CollateralFundingState, u64, u64, u64, u64, u32, u64, u64) {
        match a {
            CollateralBufferResult::Known {
                funding_state,
                recommended_buffer_dig_base_units,
                spendable_dig_base_units,
                pairs_served_by_this_node,
                overlap_dig_base_units,
                horizon_epochs,
                escalation_headroom_dig_base_units,
                escalation_ceiling_micros,
                ..
            } => (
                funding_state,
                recommended_buffer_dig_base_units,
                spendable_dig_base_units,
                pairs_served_by_this_node,
                overlap_dig_base_units,
                horizon_epochs,
                escalation_headroom_dig_base_units,
                escalation_ceiling_micros,
            ),
            other => panic!("expected a known buffer, got {other:?}"),
        }
    }

    /// The buffer for `pairs` served roots at `required` per store, at the default horizon.
    fn buf(pairs: u64, required: u64, margin_bp: u64, spendable: u64) -> CollateralBufferResult {
        buffer_advice(
            Some(pairs),
            &known(required),
            margin_bp,
            Some(spendable),
            DEFAULT_BUFFER_HORIZON_EPOCHS,
        )
    }

    #[test]
    fn the_total_is_lock_plus_overlap_plus_headroom_and_the_terms_do_not_double_count() {
        // 10 served roots x 1.000 DIG, no margin, so the lock is exactly 10.000 DIG.
        let (_, recommended, _, pairs, overlap, horizon, headroom, _) =
            known_buffer(buf(10, 1_000, 0, 0));
        let lock = one_epoch_lock(pairs, 1_000, 0);
        assert_eq!(lock, 10_000);
        // The overlap is a second epoch's worth at TODAY's price -- the coins of n-1 still locked.
        assert_eq!(overlap, 10_000);
        // The three terms sum to the authoritative total, exactly. A decomposition that
        // double-counted would still produce a plausible-looking total; this is what catches it.
        assert_eq!(recommended, lock + overlap + headroom);
        // And it is NOT a runway: four epochs of runway would be at least 4x the lock.
        assert!(
            recommended < lock * 3,
            "a runway-shaped recommendation would be at least 4x the lock, got {recommended}"
        );
        assert_eq!(horizon, DEFAULT_BUFFER_HORIZON_EPOCHS);
    }

    #[test]
    fn the_escalation_ceiling_comes_from_the_controller_and_is_reported_with_the_horizon() {
        let (_, _, _, pairs, _, _, headroom, ceiling) = known_buffer(buf(10, 1_000, 0, 0));
        // The controller steps by prev/8 per epoch in its high band, TRUNCATING each step: four
        // epochs from 0.8x go 0.9 -> 1.0125 -> 1.139062 -> 1.281444, a ceiling of x1.601805
        // relative to today. Note this is NOT 0.8 x (9/8)^4 = 1.281445 -- the per-step truncation
        // is the difference, and it is exactly what a hand-rolled closed form would get wrong.
        assert_eq!(escalated_multiplier_micros(800_000, 4), 1_281_444);
        assert_eq!(ceiling, 1_601_805);
        // The headroom is what that ceiling adds ON TOP of the lock, not the scaled lock itself.
        let lock = one_epoch_lock(pairs, 1_000, 0);
        assert_eq!(headroom, scale_micros(lock, ceiling) - lock);
        assert!(ceiling > MULT_SCALE);
    }

    #[test]
    fn escalation_compounds_and_is_clamped_by_the_controller_rather_than_growing_forever() {
        // A linear bound would give 1 + 4 x 0.125 = 1.5x of the start; the compounding one does
        // not. Checked across several horizons because a fixture at one horizon cannot tell a
        // compounding rule from a linear one that happens to agree there.
        assert_eq!(escalated_multiplier_micros(1_000_000, 0), 1_000_000);
        assert_eq!(escalated_multiplier_micros(1_000_000, 1), 1_125_000);
        assert_eq!(escalated_multiplier_micros(1_000_000, 2), 1_265_625);
        assert_eq!(escalated_multiplier_micros(1_000_000, 4), 1_601_806);

        // And it stops at the controller's own ceiling instead of running away. A hand-rolled
        // closed form has no such clamp, so a long horizon would manufacture headroom the
        // controller could never produce -- the whole reason this delegates rather than re-derives.
        assert_eq!(
            escalated_multiplier_micros(1_000_000, 500),
            dig_mirror_collateral::MULT_CEILING_MICROS
        );
    }

    #[test]
    fn the_margin_raises_the_lock_and_is_reported_in_basis_points() {
        // The margin is the ONLY thing varied, so the effect is attributable to it.
        assert_eq!(one_epoch_lock(10, 1_000, 0), 10_000);
        // +5% on 1.000 DIG is 1.050, ten of them 10.500.
        assert_eq!(one_epoch_lock(10, 1_000, 500), 10_500);
        // A 1 bp margin is a legal choice and must survive: the crate rounds UP, so it adds a base
        // unit rather than vanishing. A conversion to whole percent anywhere would erase it.
        assert_eq!(one_epoch_lock(1, 1_000, 1), 1_001);
        // And it reaches the answer: the margined lock is what the recommendation is built on.
        let (_, plain, ..) = known_buffer(buf(10, 1_000, 0, 0));
        let (_, margined, ..) = known_buffer(buf(10, 1_000, 500, 0));
        assert!(margined > plain);
    }

    #[test]
    fn the_states_sit_at_the_boundaries_they_name() {
        // lock 10.000 · next-epoch ceiling 11.250 · recommended from the implementation.
        let at = |spendable| known_buffer(buf(10, 1_000, 0, spendable)).0;
        let (_, recommended, ..) = known_buffer(buf(10, 1_000, 0, 0));

        // Each bound pinned from BOTH sides: one under must move the state, at-bound must not.
        assert_eq!(at(9_999), CollateralFundingState::ShortNow);
        assert_eq!(at(10_000), CollateralFundingState::DangerouslyLow);
        assert_eq!(at(11_249), CollateralFundingState::DangerouslyLow);
        assert_eq!(at(11_250), CollateralFundingState::BelowRecommendedBuffer);
        assert_eq!(
            at(recommended - 1),
            CollateralFundingState::BelowRecommendedBuffer
        );
        assert_eq!(at(recommended), CollateralFundingState::Funded);
    }

    #[test]
    fn only_the_two_states_that_leave_an_epoch_uncovered_are_shortfalls() {
        assert!(CollateralFundingState::ShortNow.is_shortfall());
        assert!(CollateralFundingState::DangerouslyLow.is_shortfall());
        // The one that must stay quiet. Every epoch it covers IS covered; it lacks only a cushion,
        // and a normal node sits here much of the time. An alert an operator learns to dismiss
        // teaches them to dismiss the two above it.
        assert!(!CollateralFundingState::BelowRecommendedBuffer.is_shortfall());
        assert!(!CollateralFundingState::Funded.is_shortfall());
    }

    #[test]
    fn each_missing_fact_gets_its_own_buffer_reason_and_no_figure_at_all() {
        let cases = [
            // No requirement: a NETWORK gap. Reporting it as served_set_unknown -- which an earlier
            // version of this function did -- sends the operator to fix the wrong thing.
            (
                buffer_advice(
                    Some(10),
                    &CollateralRequirementResult::Unknown {
                        reason: CollateralUnknownReason::NotCensused,
                    },
                    100,
                    Some(0),
                    4,
                ),
                CollateralBufferUnknownReason::RequirementUnknown,
            ),
            // No served set: a spendable balance of zero would otherwise look exactly like
            // ShortNow to any implementation that read an unknown count as zero.
            (
                buffer_advice(None, &known(1_000), 100, Some(0), 4),
                CollateralBufferUnknownReason::ServedSetUnknown,
            ),
            // No balance: the costs ARE computable, but where the operator stands is not -- and
            // that is the half that could raise an alarm.
            (
                buffer_advice(Some(10), &known(1_000), 100, None, 4),
                CollateralBufferUnknownReason::BalanceUnknown,
            ),
        ];
        for (answer, expected) in cases {
            let CollateralBufferResult::Unknown { reason } = answer else {
                panic!("expected unknown, got {answer:?}");
            };
            assert_eq!(reason, expected);
            // The tagged shape is what makes a zero unemittable: the serialised form carries the
            // state and the reason and NOTHING numeric. A struct with optional fields could hold a
            // 0 here, and a 0 reads as "no buffer needed".
            let wire = serde_json::to_value(answer).expect("serialise");
            assert_eq!(wire["state"], "unknown");
            for absent in [
                "recommended_buffer_dig_base_units",
                "spendable_dig_base_units",
                "pairs_served_by_this_node",
                "overlap_dig_base_units",
            ] {
                assert!(
                    wire.get(absent).is_none(),
                    "{absent} is representable: {wire}"
                );
            }
            assert!(!buffer_remedy(reason).is_empty());
        }
    }

    #[test]
    fn no_buffer_reason_collides_with_a_census_reason_and_each_has_its_own_remedy() {
        // The structural argument for a separate method rather than a widened requirement: the
        // buffer's missing facts are LOCAL and the census's are NETWORK, so one taxonomy cannot
        // carry both without sending an operator to fix the wrong thing.
        let census: std::collections::BTreeSet<&str> = CollateralUnknownReason::ALL
            .iter()
            .map(|r| r.as_wire())
            .collect();
        let remedies: std::collections::BTreeSet<&str> = CollateralBufferUnknownReason::ALL
            .iter()
            .map(|&r| {
                assert!(
                    !census.contains(r.as_wire()),
                    "{} collides with a census reason",
                    r.as_wire()
                );
                buffer_remedy(r)
            })
            .collect();
        // Four distinct remedies, not one sentence reused four times.
        assert_eq!(remedies.len(), CollateralBufferUnknownReason::ALL.len());
    }

    #[test]
    fn the_served_root_count_scales_the_lock_and_is_never_the_census_figure() {
        // `pairs` is the field a fixture is most likely to pin at 1; vary it.
        assert_eq!(one_epoch_lock(1, 2_500, 0), 2_500);
        let (_, _, _, pairs, ..) = known_buffer(buf(40, 2_500, 0, 0));
        assert_eq!(pairs, 40);
        assert_eq!(one_epoch_lock(pairs, 2_500, 0), 100_000);
        // `known()` reports a NETWORK census of 12 stores. Substituting it for the served set would
        // give 30_000 here rather than 100_000 -- the whole network's bill on one operator.
        let CollateralRequirementResult::Known { stores, .. } = known(2_500) else {
            unreachable!()
        };
        assert_ne!(
            stores, 40,
            "the fixture must make the substitution observable"
        );
        assert_ne!(one_epoch_lock(pairs, 2_500, 0), stores * 2_500);
    }

    #[test]
    fn the_buffer_carries_the_epoch_the_requirement_named() {
        // The epoch and protocol version travel with the buffer so a client never has to pair it
        // with a separately-fetched requirement and hope the two describe the same epoch.
        let CollateralBufferResult::Known {
            epoch,
            protocol_version,
            ..
        } = buf(10, 1_000, 0, 0)
        else {
            panic!("expected known")
        };
        assert_eq!(epoch, 9, "known() names epoch 9");
        assert_eq!(protocol_version, 1);
    }

    #[test]
    fn format_dig_keeps_three_decimals() {
        // The base unit is 0.001 DIG; dropping a trailing zero would misstate an amount by 100x.
        assert_eq!(format_dig(1), "0.001");
        assert_eq!(format_dig(1_000), "1.000");
        assert_eq!(format_dig(1_047), "1.047");
        assert_eq!(format_dig(10_500), "10.500");
    }
}
