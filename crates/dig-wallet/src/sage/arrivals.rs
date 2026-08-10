//! Incoming-funds ARRIVALS (dig_ecosystem#2548) — the wallet's record of money that showed up.
//!
//! An arrival is a claim about the user's money, so this module is written around the four ways
//! such a claim can be false, and each is answered by making the false claim *unexpressible*
//! rather than by a guard a later refactor can walk around:
//!
//! 1. **A first sync is not a stream of arrivals.** The catch-up replays the whole address
//!    history, so every historical coin passes the write point. [`classify`] refuses without an
//!    [`ArrivalBaseline`], and the baseline can be armed ONLY by
//!    [`WalletDb::complete_catch_up`](super::db::WalletDb::complete_catch_up), which takes a
//!    [`CatchUpReplay`](super::db::CatchUpReplay) — a value only the terminal answer of a full
//!    address-history replay produces. A wallet that has never completed one has no baseline, and a
//!    wallet that has one has it at or above everything that replay wrote. The arming used to hang
//!    off the authoritative-replica FLAG instead, which the coinset-oracle point read also sets: on
//!    a fresh install that armed the baseline at zero, permanently, and the first live update after
//!    the real catch-up would have announced the wallet's entire receive history.
//! 2. **A restart is not a second arrival.** The baseline is a persisted HEIGHT watermark and the
//!    ledger is keyed `UNIQUE` on the coin id, so a replay is excluded twice over, from disk.
//! 3. **A mempool sighting is not money.** A coin with no `created_height` is
//!    [`Verdict::Unconfirmed`]; the stored column is `NOT NULL`, so an unconfirmed arrival cannot
//!    be written even by a caller that wanted to.
//! 4. **Change is not an arrival.** A coin created by spending a coin the wallet already holds is
//!    the user's own change coming back to their own address. That is the likeliest false
//!    positive, and it is answered by the one signal the write point actually has: the parent coin
//!    id.
//!
//! # What this module deliberately does NOT claim
//!
//! The wallet has no record of its own outbound spends (`get_pending_transactions` is empty by
//! construction and history is derived after the fact from coin heights), so `parent_is_ours` is
//! the ONLY available discriminator for change. It is sound in the direction that matters — a
//! coin whose parent the wallet holds could only have been created by spending that coin — and
//! its residual hole is a self-spend whose INPUT sat at a puzzle hash the wallet does not watch,
//! which the wallet could not have spent in the first place.
//!
//! Asset naming is held to the same bar. A coin whose `asset_id` is still unattributed and which
//! does NOT sit at one of the wallet's own p2 puzzle hashes could be an unattributed CAT, so it is
//! [`Verdict::Deferred`] rather than announced as XCH: the conservative failure is silence, never
//! a wrong asset. A coin AT a watched p2 hash is a standard-transaction coin — a CAT lives at
//! `CatArgs::curry_tree_hash(asset_id, p2)`, never at the bare p2 hash — so naming it XCH is a
//! structural fact, not a guess.

use std::collections::HashSet;

use super::db::CoinRow;

/// The height at or below which a confirmed coin is BACKFILL rather than an arrival.
///
/// `None` means no baseline has been established yet — the wallet has never completed a catch-up,
/// so it cannot tell history from news and records nothing at all.
pub type ArrivalBaseline = Option<u32>;

/// One recorded arrival, as read back by a client polling the cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arrival {
    /// The monotonic cursor position. Strictly increasing and never reused, so a client resumes
    /// with `after_seq = <the last one it saw>`.
    pub seq: i64,
    /// The coin that arrived (hex).
    pub coin_id: String,
    /// The puzzle hash it arrived at (hex) — one of the wallet's own watched addresses.
    pub puzzle_hash: String,
    /// The amount, decimal string (full `u64` range; heights and amounts never narrow here).
    pub amount: String,
    /// The CAT asset id (hex TAIL), or `None` for native XCH.
    pub asset_id: Option<String>,
    /// The height at which the coin was CONFIRMED. Never optional: an arrival with no confirmed
    /// height is not an arrival.
    pub confirmed_height: u32,
}

/// What a candidate coin IS, from the arrival recorder's point of view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Money arrived. Carries the asset id (`None` = native XCH).
    Arrival(Option<String>),
    /// The wallet created this coin by spending its own — change, not an arrival.
    OwnChange,
    /// The coin is confirmed and above the baseline, but its ASSET is not yet determinable.
    /// Held for a later pass; never announced while indeterminate.
    Deferred,
    /// Not confirmed on chain **yet**. Held, and re-examined once it confirms — see
    /// [`Verdict::holds`] for why holding rather than dropping is load-bearing.
    Unconfirmed,
    /// No baseline exists yet: the wallet cannot tell history from news, so nothing is an arrival.
    NoBaseline,
    /// Confirmed at or below the baseline — history the user has already been told about (or was
    /// never going to be told about, because it predates this wallet's first catch-up).
    Backfill,
}

impl Verdict {
    /// The asset to record, if this verdict is an arrival at all.
    pub fn arrival_asset(&self) -> Option<Option<&str>> {
        match self {
            Verdict::Arrival(asset) => Some(asset.as_deref()),
            _ => None,
        }
    }

    /// Whether this coin must be HELD for a later pass rather than settled now.
    ///
    /// Both held verdicts describe a coin the recorder has SEEN and deliberately not judged, and
    /// forgetting either loses real money silently. A coin sighted in the mempool at the current
    /// peak and confirmed at that same height would fall below the advanced watermark on the very
    /// next pass; an unattributed CAT would do the same as soon as the watermark passed it. Both
    /// are answered by holding the coin and exempting it from the height window
    /// (`already_deferred` in [`classify`]) until it is settled one way or the other.
    pub fn holds(&self) -> bool {
        matches!(self, Verdict::Deferred | Verdict::Unconfirmed)
    }
}

/// Decide what a single candidate coin is. PURE — the whole judgement, in one place, so a
/// recorder cannot be correct in SQL and wrong in Rust.
///
/// `parent_is_ours` is whether `coin.parent_coin_info` names a coin THIS wallet holds; the caller
/// answers it from the same transaction that wrote the batch, so a parent and its child arriving
/// together cannot race.
///
/// `watched_p2_hashes` are the wallet's own bare p2 puzzle hashes, lowercase hex — exactly the set
/// the chain subscription was taken over.
///
/// `already_deferred` is whether a previous pass HELD this coin ([`Verdict::holds`]). A held coin
/// is exempt from the baseline height window, because the window means "already examined and
/// settled" and a held coin is neither. Without the exemption the watermark would swallow exactly
/// the coins that were waiting on it — see [`Verdict::holds`].
pub fn classify(
    coin: &CoinRow,
    baseline: ArrivalBaseline,
    already_deferred: bool,
    parent_is_ours: bool,
    watched_p2_hashes: &HashSet<String>,
) -> Verdict {
    // Trap 1. Without a baseline there is no line between history and news.
    let Some(baseline) = baseline else {
        return Verdict::NoBaseline;
    };
    // Trap 3. `created_height` is the confirmation; nothing else is.
    let Some(height) = coin.created_height else {
        return Verdict::Unconfirmed;
    };
    let Ok(height) = u32::try_from(height) else {
        // A negative or out-of-range height is not a confirmation anyone can bound a claim with.
        return Verdict::Unconfirmed;
    };
    // Trap 1, again — the part a replay walks straight through.
    if !already_deferred && height <= baseline {
        return Verdict::Backfill;
    }
    // Trap 4. Our own coin spent into a coin at our own address is change coming home.
    if parent_is_ours {
        return Verdict::OwnChange;
    }
    match &coin.asset_id {
        // An attributed CAT names its own asset.
        Some(asset_id) => Verdict::Arrival(Some(asset_id.clone())),
        // A coin sitting at a bare p2 puzzle hash we watch is a standard-transaction (XCH) coin:
        // a CAT is curried, so it can never land here.
        None if watched_p2_hashes.contains(&coin.puzzle_hash.to_ascii_lowercase()) => {
            Verdict::Arrival(None)
        }
        // Somewhere else, unattributed — possibly a CAT hinted to us whose attribution pass has
        // not run or did not succeed. Announcing it as XCH would be a wrong claim about which
        // money arrived, so it waits.
        None => Verdict::Deferred,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn watched() -> HashSet<String> {
        ["aa".to_string(), "bb".to_string()].into_iter().collect()
    }

    fn coin(created: Option<i64>, puzzle_hash: &str, parent: &str) -> CoinRow {
        CoinRow {
            coin_id: "c0".into(),
            parent_coin_info: parent.into(),
            puzzle_hash: puzzle_hash.into(),
            amount: "42".into(),
            created_height: created,
            spent_height: None,
            asset_id: None,
            hint: None,
            created_timestamp: None,
            spent_timestamp: None,
        }
    }

    /// TRAP 1 — with no baseline, nothing is an arrival, however confirmed and however foreign.
    #[test]
    fn without_a_baseline_a_confirmed_foreign_coin_is_still_not_an_arrival() {
        let c = coin(Some(500), "aa", "foreign");
        assert_eq!(
            classify(&c, None, false, false, &watched()),
            Verdict::NoBaseline
        );
    }

    /// TRAP 1 — a coin at or below the baseline is history, not news. The boundary is EXCLUSIVE
    /// at the baseline: a coin confirmed AT the baseline height was inside the catch-up.
    #[test]
    fn a_coin_at_or_below_the_baseline_is_backfill() {
        let w = watched();
        assert_eq!(
            classify(
                &coin(Some(99), "aa", "foreign"),
                Some(100),
                false,
                false,
                &w
            ),
            Verdict::Backfill
        );
        assert_eq!(
            classify(
                &coin(Some(100), "aa", "foreign"),
                Some(100),
                false,
                false,
                &w
            ),
            Verdict::Backfill
        );
        assert_eq!(
            classify(
                &coin(Some(101), "aa", "foreign"),
                Some(100),
                false,
                false,
                &w
            ),
            Verdict::Arrival(None)
        );
    }

    /// TRAP 3 — an unconfirmed coin is never an arrival, even above the baseline.
    #[test]
    fn an_unconfirmed_coin_is_never_an_arrival() {
        let c = coin(None, "aa", "foreign");
        assert_eq!(
            classify(&c, Some(1), false, false, &watched()),
            Verdict::Unconfirmed
        );
    }

    /// TRAP 3 — a nonsense height is treated as no confirmation, not as height zero.
    #[test]
    fn a_negative_height_is_not_a_confirmation() {
        let c = coin(Some(-5), "aa", "foreign");
        assert_eq!(
            classify(&c, Some(1), false, false, &watched()),
            Verdict::Unconfirmed
        );
    }

    /// TRAP 4 — the user's own change lands at the user's own address and must not be announced.
    #[test]
    fn our_own_change_is_not_an_arrival() {
        let c = coin(Some(200), "aa", "our_own_coin");
        assert_eq!(
            classify(&c, Some(100), false, true, &watched()),
            Verdict::OwnChange
        );
    }

    /// The positive control for TRAP 4: identical coin, foreign parent, IS an arrival. Without
    /// this the change test would pass against a classifier that refuses everything.
    #[test]
    fn the_same_coin_with_a_foreign_parent_is_an_arrival() {
        let c = coin(Some(200), "aa", "somebody_elses_coin");
        assert_eq!(
            classify(&c, Some(100), false, false, &watched()),
            Verdict::Arrival(None)
        );
    }

    #[test]
    fn an_attributed_cat_arrival_carries_its_asset_id() {
        let mut c = coin(Some(200), "cat_puzzle_hash_not_ours", "foreign");
        c.asset_id = Some("a406d3".into());
        assert_eq!(
            classify(&c, Some(100), false, false, &watched()),
            Verdict::Arrival(Some("a406d3".into()))
        );
    }

    /// The conservative choice, stated as a test: an unattributed coin somewhere other than one of
    /// our p2 hashes is NOT announced as XCH. Silence beats naming the wrong asset.
    #[test]
    fn an_unattributed_coin_at_a_foreign_puzzle_hash_is_deferred_not_called_xch() {
        let c = coin(Some(200), "some_curried_hash", "foreign");
        assert_eq!(
            classify(&c, Some(100), false, false, &watched()),
            Verdict::Deferred
        );
    }

    #[test]
    fn puzzle_hash_matching_is_case_insensitive() {
        let c = coin(Some(200), "AA", "foreign");
        assert_eq!(
            classify(&c, Some(100), false, false, &watched()),
            Verdict::Arrival(None)
        );
    }

    /// A coin a previous pass HELD is exempt from the height window. Without this the watermark
    /// swallows exactly the coins that were waiting on it: the same coin reads `Backfill` once the
    /// baseline has advanced past it, and the money is never announced.
    #[test]
    fn a_held_coin_is_exempt_from_the_baseline_window() {
        let mut c = coin(Some(101), "aa", "foreign");
        c.asset_id = Some("a406d3".into());
        // Baseline has since advanced past the coin's height.
        assert_eq!(
            classify(&c, Some(200), false, false, &watched()),
            Verdict::Backfill
        );
        assert_eq!(
            classify(&c, Some(200), true, false, &watched()),
            Verdict::Arrival(Some("a406d3".into()))
        );
    }

    /// Holding is what makes a mempool sighting recoverable rather than lost: the unconfirmed
    /// verdict must be a HOLD, not a drop, or a coin confirmed at the height it was sighted at
    /// falls under the advanced watermark forever.
    #[test]
    fn both_indeterminate_verdicts_hold_and_no_settled_verdict_does() {
        assert!(Verdict::Unconfirmed.holds());
        assert!(Verdict::Deferred.holds());
        assert!(!Verdict::Arrival(None).holds());
        assert!(!Verdict::OwnChange.holds());
        assert!(!Verdict::Backfill.holds());
        assert!(!Verdict::NoBaseline.holds());
    }

    /// The precedence that matters: change is refused BEFORE the asset is looked at, so a CAT
    /// change coin is not announced merely because it names its asset.
    #[test]
    fn a_cat_change_coin_is_refused_as_change_not_announced_as_a_cat() {
        let mut c = coin(Some(200), "cat_hash", "our_own_coin");
        c.asset_id = Some("a406d3".into());
        assert_eq!(
            classify(&c, Some(100), false, true, &watched()),
            Verdict::OwnChange
        );
    }
}
