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
use dig_node_control_interface::results::{CollateralRequirementResult, CollateralUnknownReason};
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

/// How many epochs of multiplier escalation the recommended buffer covers.
///
/// **4 epochs — 28 days, about a x1.60 headroom.** This is the contract lane's judgement
/// (`dig-node-control-interface` PR#36, `DEFAULT_BUFFER_HORIZON_EPOCHS`), NOT a constant published
/// by `dig-mirror-collateral`, and it is restated here only because the contract crate is not yet
/// depended on for it. It moves if the contract moves.
///
/// A horizon is a CHOICE and not a constant because escalation COMPOUNDS: at the per-epoch ceiling
/// the factors run 1 epoch x1.12, 2 x1.27, 4 x1.60, 8 x2.57, 13 x4.62. Telling an operator to hold
/// 4.6x their current lock against a quarter of uninterrupted worst-case escalation is advice
/// nobody follows. It is reported with the figure ([`BufferAdvice::horizon_epochs`]) because a
/// buffer whose assumption is invisible cannot be argued with.
pub const DEFAULT_BUFFER_HORIZON_EPOCHS: u32 = 4;

/// Why a node cannot state the buffer.
///
/// **None of these has a counterpart in [`CollateralUnknownReason`]**, which is the structural
/// reason the buffer is a separate method rather than a widening of the requirement: collapsing
/// "I do not know what I serve" into "I have not censused the epoch" would report a missing LOCAL
/// fact as a missing NETWORK one, and send the operator to fix the wrong thing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BufferUnknownReason {
    /// The node cannot enumerate the `(owner, store, root)` triples it serves.
    ///
    /// The buffer's first term is a count of those triples, so without it there is no figure at
    /// all — not a zero. Zero served pairs and an unknown served set produce identical arithmetic,
    /// and the zero reads as "you owe nothing".
    ServedSetUnknown,
    /// The node cannot tell which of the previous epoch's coins have been reclaimed.
    ///
    /// The overlap term is precisely the collateral still locked in the epoch being reclaimed, so
    /// it is unknowable without this, and it is the term that decides the PEAK.
    ReclaimStateUnknown,
    /// The operator's spendable $DIG is not known to this node.
    ///
    /// The costs are still computable and are still reported; what is not computable is where the
    /// operator STANDS against them, which is the part that could raise an alarm.
    BalanceUnknown,
}

impl BufferUnknownReason {
    /// The stable snake_case wire token.
    pub const fn as_wire(self) -> &'static str {
        match self {
            BufferUnknownReason::ServedSetUnknown => "served_set_unknown",
            BufferUnknownReason::ReclaimStateUnknown => "reclaim_state_unknown",
            BufferUnknownReason::BalanceUnknown => "balance_unknown",
        }
    }

    /// One line telling the operator what would resolve it.
    pub const fn remedy(self) -> &'static str {
        match self {
            BufferUnknownReason::ServedSetUnknown => {
                "this node cannot list the store roots it serves"
            }
            BufferUnknownReason::ReclaimStateUnknown => {
                "this node cannot tell which of last epoch's collateral has been reclaimed"
            }
            BufferUnknownReason::BalanceUnknown => "this node does not know your spendable $DIG",
        }
    }
}

/// How much $DIG an operator should hold, and whether they are currently short.
///
/// Modelled as a TAGGED enum rather than a struct with optional numbers, so that the unknown case
/// has **no representable numeric field**. A zero cannot be emitted here even by accident, which
/// matters because a zero buffer reads as "no buffer needed" — the reassuring rendering of a
/// missing fact, on a money surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum BufferAdvice {
    /// The node can state the buffer.
    Known(BufferFigures),
    /// The node cannot, and names which fact is missing.
    Unknown {
        /// Which fact the node is missing.
        reason: BufferUnknownReason,
    },
}

/// The figures behind a [`BufferAdvice::Known`] answer.
///
/// Every amount is in **DIG base units** (`1 DIG = 1_000`), never mojos.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BufferFigures {
    /// The `(owner, store, root)` triples THIS NODE serves and must collateralise.
    ///
    /// Deliberately not named `stores`, and deliberately not sourced from
    /// [`CollateralRequirementResult::Known::stores`], which is a NETWORK census figure the
    /// contract says in as many words is not a node count. Multiplying that by the requirement
    /// bills one operator for the whole network.
    pub pairs_served_by_this_node: u64,
    /// The pre-margin per-store requirement this advice was computed from.
    pub required_per_store_dig_base_units: u64,
    /// The margin applied, in BASIS POINTS. Never converted to a percentage.
    pub margin_bp: u64,
    /// What one epoch's posting costs, margin included: `pairs x margined requirement`.
    pub one_epoch_lock_dig_base_units: u64,
    /// The collateral still locked in the epoch being reclaimed.
    ///
    /// The real peak, and the term nobody budgets for. Reclaims run FIRST in every pass and are
    /// never gated on funds, so in the ordinary case the returned collateral funds the creates
    /// behind it — but epoch `n` exists before `n-1` is reclaimed, and a reclaim can be delayed or
    /// fail.
    pub overlap_dig_base_units: u64,
    /// What the next epochs could cost ON TOP of today's lock if the multiplier rises at its
    /// ceiling for [`Self::horizon_epochs`].
    pub escalation_headroom_dig_base_units: u64,
    /// The authoritative total: lock + overlap + headroom.
    pub recommended_buffer_dig_base_units: u64,
    /// The escalation horizon assumed, in epochs. Required on the wire — a buffer without its
    /// horizon is a magic number nobody can check.
    pub horizon_epochs: u32,
    /// The multiplier ceiling after `horizon_epochs`, in millionths, relative to today's.
    ///
    /// Required on the wire beside the horizon so a client can reproduce the headroom rather than
    /// trust it. A **worst case, not a forecast**: inside the controller's dead band the multiplier
    /// does not move at all.
    pub escalation_ceiling_micros: u64,
    /// The operator's spendable $DIG, in base units.
    pub spendable_dig_base_units: u64,
    /// Where the operator stands.
    pub funding_state: FundingState,
    /// How much more $DIG to hold to reach [`Self::recommended_buffer_dig_base_units`].
    ///
    /// The number a person acts on. "Balance low" is not actionable; "add 3.250 DIG" is.
    pub shortfall_to_recommended_dig_base_units: u64,
}

/// Where an operator's $DIG stands against their collateral obligations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FundingState {
    /// Cannot cover the CURRENT epoch: stores are already going uncollateralised.
    ShortNow,
    /// Covers the current epoch but could not cover the next one at the escalation ceiling.
    DangerouslyLow,
    /// Fine for several epochs, with no cushion for a delayed reclaim or sustained escalation.
    ///
    /// **A READOUT, never a notification** — see [`FundingState::is_shortfall`].
    BelowRecommendedBuffer,
    /// At or above the recommended buffer.
    Adequate,
}

impl FundingState {
    /// Does this state leave an epoch UNCOVERED?
    ///
    /// True for exactly the two states that do. Named as a predicate on the type rather than left
    /// to each surface, because two surfaces deciding independently is how the readout state
    /// acquires an alert.
    ///
    /// [`BelowRecommendedBuffer`](Self::BelowRecommendedBuffer) is deliberately EXCLUDED. Every
    /// epoch it covers is covered; it lacks only a cushion, and a healthy node sits there much of
    /// the time. A recurring alert an operator learns to dismiss teaches them to dismiss the two
    /// above it, which are the ones that cost money.
    pub fn is_shortfall(self) -> bool {
        matches!(self, FundingState::ShortNow | FundingState::DangerouslyLow)
    }

    /// The stable snake_case wire token.
    pub const fn token(self) -> &'static str {
        match self {
            FundingState::ShortNow => "short_now",
            FundingState::DangerouslyLow => "dangerously_low",
            FundingState::BelowRecommendedBuffer => "below_recommended_buffer",
            FundingState::Adequate => "adequate",
        }
    }
}

/// The multiplier after `epochs` of uninterrupted escalation, starting from `from_micros`.
///
/// Obtained by stepping `dig_mirror_collateral::step_multiplier` in its own HIGH band, never by
/// evaluating a hand-rolled `(9/8)^n`. Re-deriving the recurrence would be a rival implementation
/// of the controller, and it would silently drop two behaviours the real one has: the step is a
/// fraction of the PREVIOUS multiplier (so it compounds, and an implementation using a fixed
/// increment diverges immediately), and the result is clamped at `MULT_CEILING_MICROS` (so a long
/// horizon cannot manufacture a headroom the controller could never produce).
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

/// Compute the funding advice.
///
/// # Why the recommendation is not "requirement x epochs of runway"
///
/// **Collateral is RECLAIMED, not spent.** Each pass creates the coins for `(store, root, epoch n)`
/// and reclaims epoch `n-1`, and the reclaims run FIRST and are never gated on funds — so the
/// returned collateral funds the creates behind it. Steady state is therefore roughly ONE epoch's
/// lock, not one per epoch. Multiplying by a runway would overstate the answer by the epoch count
/// and tell an operator to buy many times what they need, which is advice they would rightly
/// ignore.
///
/// So the total is three named terms, which sum without double-counting:
///
/// ```text
/// recommended = lock + overlap + escalation_headroom
/// ```
///
/// the current epoch's posting, the collateral still held in the epoch being reclaimed, and what
/// the next `horizon_epochs` could add if the multiplier rises at its ceiling throughout.
///
/// `pairs_served_by_this_node` MUST be this node's own served set. Passing the census `stores`
/// figure produces the whole network's collateral bill presented to one operator.
pub fn buffer_advice(
    pairs_served_by_this_node: Option<u64>,
    requirement: &CollateralRequirementResult,
    margin_bp: u64,
    spendable_dig_base_units: Option<u64>,
    horizon_epochs: u32,
) -> BufferAdvice {
    let unknown = |reason| BufferAdvice::Unknown { reason };

    // A requirement the node does not have is a SERVED-SET-independent gap, but it surfaces here as
    // the same practical fact: there is no per-store price to multiply by. It is reported through
    // `control.collateral.requirement`'s own reason, which is why the caller is expected to have
    // read that first; here it can only be reported as "no figure".
    let CollateralRequirementResult::Known {
        required_per_store_dig_base_units,
        multiplier_micros,
        ..
    } = *requirement
    else {
        return unknown(BufferUnknownReason::ServedSetUnknown);
    };
    let Some(pairs) = pairs_served_by_this_node else {
        return unknown(BufferUnknownReason::ServedSetUnknown);
    };
    let Some(spendable) = spendable_dig_base_units else {
        return unknown(BufferUnknownReason::BalanceUnknown);
    };

    // The margined per-store posting, from the crate — it rounds UP, and a re-derivation that
    // rounded down would post a base unit short of what qualifies.
    let per_store = apply_safety_margin(required_per_store_dig_base_units, margin_bp);
    let lock = u64::try_from(u128::from(pairs) * u128::from(per_store)).unwrap_or(u64::MAX);

    // The overlap is a second epoch's worth at TODAY's price: the coins of epoch n-1, still locked
    // while epoch n's are created.
    let overlap = lock;

    // The ceiling is expressed relative to today's multiplier so a client can check the headroom
    // against the multiplier the requirement already reported.
    let escalated = escalated_multiplier_micros(multiplier_micros, horizon_epochs);
    let ceiling_micros = u64::try_from(
        u128::from(escalated) * u128::from(MULT_SCALE) / u128::from(multiplier_micros.max(1)),
    )
    .unwrap_or(u64::MAX);
    let headroom = scale_micros(lock, ceiling_micros).saturating_sub(lock);

    let recommended = lock.saturating_add(overlap).saturating_add(headroom);
    let next_epoch_ceiling = scale_micros(
        lock,
        u64::try_from(
            u128::from(escalated_multiplier_micros(multiplier_micros, 1)) * u128::from(MULT_SCALE)
                / u128::from(multiplier_micros.max(1)),
        )
        .unwrap_or(MULT_SCALE),
    );

    let funding_state = if spendable < lock {
        FundingState::ShortNow
    } else if spendable < next_epoch_ceiling {
        FundingState::DangerouslyLow
    } else if spendable < recommended {
        FundingState::BelowRecommendedBuffer
    } else {
        FundingState::Adequate
    };

    BufferAdvice::Known(BufferFigures {
        pairs_served_by_this_node: pairs,
        required_per_store_dig_base_units,
        margin_bp,
        one_epoch_lock_dig_base_units: lock,
        overlap_dig_base_units: overlap,
        escalation_headroom_dig_base_units: headroom,
        recommended_buffer_dig_base_units: recommended,
        horizon_epochs,
        escalation_ceiling_micros: ceiling_micros,
        spendable_dig_base_units: spendable,
        funding_state,
        shortfall_to_recommended_dig_base_units: recommended.saturating_sub(spendable),
    })
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

    /// Unwrap a `Known` answer, or fail loudly naming what came back instead.
    fn figures(a: BufferAdvice) -> BufferFigures {
        match a {
            BufferAdvice::Known(f) => f,
            other => panic!("expected a known buffer, got {other:?}"),
        }
    }

    /// The buffer for `pairs` served triples at `required` per store, default horizon.
    fn advice(pairs: u64, required: u64, margin_bp: u64, spendable: u64) -> BufferFigures {
        figures(buffer_advice(
            Some(pairs),
            &known(required),
            margin_bp,
            Some(spendable),
            DEFAULT_BUFFER_HORIZON_EPOCHS,
        ))
    }

    #[test]
    fn the_total_is_lock_plus_overlap_plus_headroom_and_the_terms_do_not_double_count() {
        // 10 served triples x 1.000 DIG, no margin, so the lock is exactly 10.000 DIG.
        let a = advice(10, 1_000, 0, 0);
        assert_eq!(a.one_epoch_lock_dig_base_units, 10_000);
        // The overlap is a second epoch's worth at TODAY's price -- the coins of n-1 still locked.
        assert_eq!(a.overlap_dig_base_units, 10_000);
        // The three terms sum to the authoritative total, exactly. A decomposition that
        // double-counted would still produce a plausible-looking total; this is what catches it.
        assert_eq!(
            a.recommended_buffer_dig_base_units,
            a.one_epoch_lock_dig_base_units
                + a.overlap_dig_base_units
                + a.escalation_headroom_dig_base_units
        );
        // And it is NOT a runway: 4 epochs of runway would be at least 4x the lock.
        assert!(
            a.recommended_buffer_dig_base_units < a.one_epoch_lock_dig_base_units * 3,
            "a runway-shaped recommendation would be at least 4x the lock, got {}",
            a.recommended_buffer_dig_base_units
        );
        assert_eq!(a.horizon_epochs, DEFAULT_BUFFER_HORIZON_EPOCHS);
    }

    #[test]
    fn the_escalation_ceiling_comes_from_the_controller_and_is_reported_with_the_horizon() {
        let a = advice(10, 1_000, 0, 0);
        // The controller steps by prev/8 per epoch in its high band, TRUNCATING each step: four
        // epochs from 0.8x go 0.9 -> 1.0125 -> 1.139062 -> 1.281444, a ceiling of x1.601805
        // relative to today. Note this is NOT exactly 0.8 x (9/8)^4 = 1.281445 -- the per-step
        // truncation is the difference, and it is precisely what a hand-rolled closed form would
        // get wrong. Pinned as concrete numbers as well as against the crate, so a mutation moving
        // both sides is still caught.
        let stepped = escalated_multiplier_micros(800_000, 4);
        assert_eq!(stepped, 1_281_444);
        assert_eq!(a.escalation_ceiling_micros, 1_601_805);
        // The headroom is what that ceiling adds ON TOP of the lock, not the scaled lock itself.
        assert_eq!(
            a.escalation_headroom_dig_base_units,
            scale_micros(a.one_epoch_lock_dig_base_units, a.escalation_ceiling_micros)
                - a.one_epoch_lock_dig_base_units
        );
        // Both fields travel together: a horizon without its ceiling, or a ceiling without its
        // horizon, is a number a client cannot reproduce.
        assert!(a.escalation_ceiling_micros > MULT_SCALE);
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
        // (9/8)^n has no such clamp, so a long horizon would manufacture headroom the controller
        // could never produce -- which is the whole reason this delegates rather than re-derives.
        let far = escalated_multiplier_micros(1_000_000, 500);
        assert_eq!(far, dig_mirror_collateral::MULT_CEILING_MICROS);
    }

    #[test]
    fn the_margin_raises_the_lock_and_is_reported_in_basis_points() {
        // Same pairs and requirement; the margin is the ONLY thing varied, so the effect is
        // attributable to it.
        let none = advice(10, 1_000, 0, 0);
        let generous = advice(10, 1_000, 500, 0);
        assert_eq!(generous.margin_bp, 500);
        // +5% on 1.000 DIG is 1.050, ten of them 10.500.
        assert_eq!(generous.one_epoch_lock_dig_base_units, 10_500);
        assert!(generous.one_epoch_lock_dig_base_units > none.one_epoch_lock_dig_base_units);
        // A 1 bp margin is a legal choice and must survive: the crate rounds UP, so it adds a base
        // unit rather than vanishing. A percentage conversion anywhere would erase it.
        assert_eq!(advice(1, 1_000, 1, 0).one_epoch_lock_dig_base_units, 1_001);
    }

    #[test]
    fn the_states_sit_at_the_boundaries_they_name() {
        // lock 10.000 · next-epoch ceiling 11.250 · recommended 26.016.
        let at = |spendable| advice(10, 1_000, 0, spendable).funding_state;

        // Each bound pinned from BOTH sides: one under must move the state, at-bound must not.
        assert_eq!(at(9_999), FundingState::ShortNow);
        assert_eq!(at(10_000), FundingState::DangerouslyLow);
        assert_eq!(at(11_249), FundingState::DangerouslyLow);
        assert_eq!(at(11_250), FundingState::BelowRecommendedBuffer);
        // Read from the implementation rather than restated, because the exact total depends on
        // the controller's truncation; what this test pins is the BOUNDARY behaviour either side.
        let recommended = advice(10, 1_000, 0, 0).recommended_buffer_dig_base_units;
        assert_eq!(at(recommended - 1), FundingState::BelowRecommendedBuffer);
        assert_eq!(at(recommended), FundingState::Adequate);
    }

    #[test]
    fn only_the_two_states_that_leave_an_epoch_uncovered_are_shortfalls() {
        assert!(FundingState::ShortNow.is_shortfall());
        assert!(FundingState::DangerouslyLow.is_shortfall());
        // The one that must stay quiet. Every epoch it covers IS covered; it lacks only a cushion,
        // and a normal node sits here much of the time. An alert an operator learns to dismiss
        // teaches them to dismiss the two above it.
        assert!(!FundingState::BelowRecommendedBuffer.is_shortfall());
        assert!(!FundingState::Adequate.is_shortfall());
    }

    #[test]
    fn an_unknown_answer_has_no_representable_figure_at_all() {
        let cases = [
            // No served set: a spendable balance of zero would otherwise look exactly like
            // ShortNow to any implementation that read an unknown pair count as zero.
            (
                buffer_advice(None, &known(1_000), 100, Some(0), 4),
                BufferUnknownReason::ServedSetUnknown,
            ),
            // No balance: the costs ARE computable, but where the operator stands is not, and
            // that is the half that could raise an alarm.
            (
                buffer_advice(Some(10), &known(1_000), 100, None, 4),
                BufferUnknownReason::BalanceUnknown,
            ),
            // No requirement: there is no per-store price to multiply by.
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
                BufferUnknownReason::ServedSetUnknown,
            ),
        ];
        for (answer, expected) in cases {
            let BufferAdvice::Unknown { reason } = answer else {
                panic!("expected unknown, got {answer:?}");
            };
            assert_eq!(reason, expected);
            // The tagged shape is what makes a zero unemittable: the serialised form carries the
            // state and the reason and NOTHING numeric. A struct with optional fields could hold a
            // 0 here, and a 0 reads as "no buffer needed".
            let wire = serde_json::to_value(answer).expect("serialise");
            assert_eq!(wire["state"], "unknown");
            assert_eq!(wire["reason"], reason.as_wire());
            for absent in [
                "recommended_buffer_dig_base_units",
                "one_epoch_lock_dig_base_units",
                "shortfall_to_recommended_dig_base_units",
                "spendable_dig_base_units",
            ] {
                assert!(
                    wire.get(absent).is_none(),
                    "{absent} is representable: {wire}"
                );
            }
        }
    }

    #[test]
    fn each_buffer_reason_is_distinct_from_every_census_reason() {
        // The structural argument for a separate method rather than a widened requirement: none of
        // the buffer's missing facts can be expressed in the census taxonomy, so collapsing them
        // would report a missing LOCAL fact as a missing NETWORK one and send the operator to fix
        // the wrong thing.
        let census: std::collections::BTreeSet<&str> = CollateralUnknownReason::ALL
            .iter()
            .map(|r| r.as_wire())
            .collect();
        let buffer = [
            BufferUnknownReason::ServedSetUnknown,
            BufferUnknownReason::ReclaimStateUnknown,
            BufferUnknownReason::BalanceUnknown,
        ];
        for reason in buffer {
            assert!(
                !census.contains(reason.as_wire()),
                "{} collides with a census reason",
                reason.as_wire()
            );
            assert!(!reason.remedy().is_empty());
        }
        // And the three remedies are distinct, not one sentence reused.
        let remedies: std::collections::BTreeSet<&str> =
            buffer.iter().map(|r| r.remedy()).collect();
        assert_eq!(remedies.len(), 3);
    }

    #[test]
    fn the_shortfall_is_the_number_to_add_and_never_underflows() {
        let a = advice(10, 1_000, 0, 20_000);
        let expected = a.recommended_buffer_dig_base_units - 20_000;
        assert_eq!(a.shortfall_to_recommended_dig_base_units, expected);
        assert_eq!(format_dig(expected), "6.018");
        // Above the recommendation there is nothing to add, and it must not wrap.
        let rich = advice(10, 1_000, 0, 90_000);
        assert_eq!(rich.shortfall_to_recommended_dig_base_units, 0);
        assert_eq!(rich.funding_state, FundingState::Adequate);
    }

    #[test]
    fn the_served_pair_count_scales_the_lock_and_is_never_the_census_figure() {
        // `pairs` is the field a fixture is most likely to pin at 1; vary it.
        assert_eq!(advice(1, 2_500, 0, 0).one_epoch_lock_dig_base_units, 2_500);
        let forty = advice(40, 2_500, 0, 0);
        assert_eq!(forty.one_epoch_lock_dig_base_units, 100_000);
        assert_eq!(forty.pairs_served_by_this_node, 40);
        // `known()` reports a NETWORK census of 12 stores. Substituting it for the served set would
        // give 30_000 here rather than 100_000 -- the whole network's bill on one operator.
        let CollateralRequirementResult::Known { stores, .. } = known(2_500) else {
            unreachable!()
        };
        assert_ne!(
            stores, 40,
            "the fixture must make the substitution observable"
        );
        assert_ne!(forty.one_epoch_lock_dig_base_units, stores * 2_500);
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
