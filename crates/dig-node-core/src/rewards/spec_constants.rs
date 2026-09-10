//! Constants transcribed from `dig-rewards-coin/SPEC.md` v0.1.1 (DIG-Network/dig_ecosystem#3250).
//!
//! # Byte-identical contract
//!
//! Every value below is copied verbatim from the normative spec, each tagged with the clause it
//! comes from. They live here — not scattered across the engine — because `dig-rewards-coin` is
//! still SPEC-only (`pub mod distributor {}`, DIG-Network/dig_ecosystem#3249): the moment #3249
//! lands and publishes these as its own constants, this file MUST be deleted and every reference
//! MUST move to `dig_rewards_coin::*`. That migration is the parent's call, not this lane's — do
//! not relitigate it here and do not let a second copy of any of these numbers exist anywhere else
//! in this crate.
//!
//! `epoch_seconds`, `first_epoch_start` and `payout_threshold` are deliberately ABSENT: they are
//! per-distributor chain values (SPEC §8), never constants.

/// SPEC §2.5: a prover MUST begin a new cycle per distributor once per period.
pub const PROVER_CYCLE_PERIOD_SECONDS: u64 = 3_600;

/// SPEC §2.5 clause 1: `observed_at` MUST be refreshed at least this often, including while `Idle`.
pub const PROVER_HEARTBEAT_SECONDS: u64 = 60;

/// SPEC §2.5 clause 2: a cycle exceeding this MUST be abandoned and counted as a prover-fault
/// failure — never a peer strike (clause 3 / §3.6.4).
pub const PROVER_CYCLE_DEADLINE_SECONDS: u64 = 900;

/// SPEC §3.2: windows selected per candidate peer per cycle.
pub const CHALLENGE_WINDOWS_PER_CYCLE: u32 = 4;

/// SPEC §3.2 clause 3: bytes per challenge window (64 KiB), clamped to `total_length` for a smaller
/// resource.
pub const CHALLENGE_WINDOW_BYTES: u64 = 65_536;

/// SPEC §3.2 clause 5: a window MUST NOT repeat for the same `(peer_id, launcher_id)` within this
/// many cycles.
pub const CHALLENGE_NO_REPEAT_CYCLES: u32 = 8;

/// SPEC §3.6 clause 3: consecutive challenge-cycle failures before a `RemoveEntry` is scheduled.
pub const CHALLENGE_STRIKES_TO_EVICT: u32 = 3;

/// SPEC §3.7 clause 1: per-window deadline.
pub const CHALLENGE_DEADLINE_SECONDS: u64 = 30;

/// SPEC §3.7 clause 1: deadline for a peer's four windows.
pub const CHALLENGE_PEER_DEADLINE_SECONDS: u64 = 120;

/// SPEC §3.7 clause 2: minimum interval between challenges of the same peer, summed across every
/// distributor this node funds.
pub const CHALLENGE_MIN_INTERVAL_SECONDS: u64 = 900;

/// SPEC §3.7 clause 3: peers challenged per cycle per distributor, at most.
pub const CHALLENGE_MAX_PEERS_PER_CYCLE: u32 = 64;

/// SPEC §6.3 clause 1: add/remove actions per bundle, at most.
pub const MAX_ENTRY_WRITES_PER_BUNDLE: u32 = 8;

/// SPEC §6.3 clause 2: minimum interval between entry-set write bundles for one distributor.
pub const ENTRY_WRITE_MIN_INTERVAL_SECONDS: u64 = 3_600;

/// SPEC §6.3 clause 4: a removed entry MUST NOT be re-added within this window, keyed on
/// `(payout_puzzle_hash, launcher_id)` — never on `peer_id`.
pub const REENTRY_COOLDOWN_SECONDS: u64 = 21_600;

/// SPEC §4.6 clause 3: grace window after a mirror-collateral epoch rollover during which the
/// PREVIOUS epoch ordinal is still accepted, and a rollover mismatch MUST NOT strike.
pub const MIRROR_EPOCH_GRACE_SECONDS: u64 = 21_600;

/// SPEC §12.4: an entry set that has not changed in this long, with a non-zero reserve, MUST be
/// reported as stale (`entry_set_stale` on `dig.getRewardDistributor` only — never on the prover
/// status record, §2.4).
pub const STALE_ENTRY_SET_SECONDS: u64 = 172_800;

/// SPEC §6.5: the entry set is capped at this many entries per distributor.
pub const MAX_ENTRIES_PER_DISTRIBUTOR: u32 = 250;

/// SPEC §4.4 clause 1: at most this many free-memo URL terms are considered per candidate.
pub const MAX_MIRROR_URL_TERMS: u32 = 8;
