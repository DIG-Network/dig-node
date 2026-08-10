//! Outgoing-funds SENDS (dig_ecosystem#2565) — the wallet's record of money that left.
//!
//! The incoming twin of [`super::arrivals`], and deliberately NOT its mirror image. A receive is a
//! coin; a send is a *difference*. Writing it as a mirror is the money lie this module exists to
//! make unexpressible, so each of the four ways the claim can be false is answered structurally:
//!
//! 1. **A spent coin's amount is not the send.** Spending a 9 XCH coin to send 1 XCH creates ~8 XCH
//!    of change back to the same wallet. Announcing the input would overstate the payment ninefold
//!    — the arrivals defect running backwards. [`settle`] therefore never sees a single coin: its
//!    unit is a whole confirmed height, and the only figure it can produce is
//!    [`Verdict::Send::net_outflow`] — owned inputs MINUS owned outputs.
//! 2. **A send and its change are ONE transaction.** The unit being a height rather than a coin
//!    makes a second notification for the change unexpressible, and makes a multi-input spend
//!    arithmetic rather than a grouping problem: two inputs summing to 9 with 8 returning is still
//!    one row reading 1.
//! 3. **A send need not originate from this app.** Detection is chain observation of the wallet's
//!    own replica, so a spend made from another client on the same seed is seen identically. There
//!    is no local record of an outbound bundle anywhere in this crate, and this module must never
//!    grow one — §908 keeps the user's key out of the node, so the node's only honest source is
//!    what the chain says happened.
//! 4. **A mempool sighting is not a send.** A height is enumerated from `spent_height`, which is
//!    set only from a confirmed `CoinState`. An unconfirmed spend belongs to no height and so
//!    reaches [`settle`] at all. History is answered the same way arrivals answers it: a baseline
//!    armed only by a completed catch-up, so a first sync replays nothing.
//!
//! # The fee is inside the figure, and no observation takes it out
//!
//! This is the load-bearing limitation, and it is structural rather than a gap someone can close
//! by trying harder. The replica holds only coins at puzzle hashes the wallet subscribed
//! (`apply_coin_states` drops the rest), so a send's output to the RECIPIENT is never written. What
//! is exactly computable is the total that left — payment plus fee — and nothing in the replica
//! separates them. So the module reports that total and names it for what it is. It equals the drop
//! in the balance this same node reports, which is the one figure a client can state without
//! inferring anything the node did not observe.
//!
//! Reporting a fabricated `fee: 0` beside a payment figure would be the same lie in a new costume,
//! and is why [`Verdict::Send`] carries exactly one number.
//!
//! # What this module deliberately does NOT claim
//!
//! Two heights' worth of honesty is bought by silence rather than by a guess:
//!
//! - **A height whose spend set is not purely plain XCH at a watched address is
//!   [`Verdict::Unaccountable`]** — recorded as nothing at all. A CAT lives at
//!   `CatArgs::curry_tree_hash(asset_id, p2)`, and the peer sync path drops coins outside the
//!   subscribed bare-p2 set, so a CAT send's CHANGE can be invisible while its input is visible.
//!   Scoring that difference would overstate the send by the entire change. A missed notification
//!   costs the user nothing; a wrong one is the thing being prevented.
//! - **Two independent transactions confirmed in the SAME block become one row.** There is no
//!   transaction id anywhere in the replica — `coins` carries heights and a parent link and nothing
//!   else — so a height is the finest grouping that exists. The residual is deliberate and it errs
//!   toward FEWER notifications carrying a CORRECT sum, never toward a wrong figure.

use std::collections::HashSet;

/// The height at or below which a confirmed spend is BACKFILL rather than a send.
///
/// `None` means no baseline has been established yet — the wallet has never completed a catch-up,
/// so it cannot tell history from news and records nothing at all. Armed only by
/// [`WalletDb::complete_catch_up`](super::db::WalletDb::complete_catch_up), exactly like the
/// arrival baseline and for exactly the same reason.
pub type SendBaseline = Option<u32>;

/// One recorded send, as read back by a client polling the cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Send {
    /// The monotonic cursor position. Strictly increasing and never reused, so a client resumes
    /// with `after_seq = <the last one it saw>`.
    pub seq: i64,
    /// The value that LEFT the wallet, decimal string. Owned inputs minus owned outputs, INCLUSIVE
    /// of any network fee — never a spent coin's amount. A string because the ledger carries the
    /// full `u64` range and a JSON number does not.
    pub net_outflow: String,
    /// The CAT asset id (hex TAIL), or `None` for native XCH. Always `None` today: a height whose
    /// spend set is not plain XCH is [`Verdict::Unaccountable`] and never reaches the ledger.
    pub asset_id: Option<String>,
    /// The height at which the spend was CONFIRMED. Never optional: a send with no confirmed
    /// height is not a send.
    pub confirmed_height: u32,
}

/// A coin of the wallet's that was spent at the height under judgement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpentCoin {
    /// The coin id (hex) — matched against [`CreatedCoin::parent_coin_info`] to find what returned.
    pub coin_id: String,
    /// The puzzle hash it sat at (hex).
    pub puzzle_hash: String,
    /// Its amount, decimal string as stored.
    pub amount: String,
    /// The CAT asset id, if the coin was attributed to one.
    pub asset_id: Option<String>,
}

/// A coin of the wallet's that appeared at the height under judgement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedCoin {
    /// The coin that was spent to create it (hex).
    pub parent_coin_info: String,
    /// The puzzle hash it landed at (hex).
    pub puzzle_hash: String,
    /// Its amount, decimal string as stored.
    pub amount: String,
    /// The CAT asset id, if the coin was attributed to one.
    pub asset_id: Option<String>,
}

/// What one confirmed height IS, from the send recorder's point of view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Money left the wallet at this height.
    Send {
        /// Owned inputs minus owned outputs, in base units. Always `> 0`.
        net_outflow: u128,
    },
    /// No baseline exists yet: the wallet cannot tell history from news, so nothing is a send.
    NoBaseline,
    /// Confirmed at or below the baseline — history that predates this wallet's first catch-up.
    Backfill,
    /// The wallet spent nothing at this height.
    NothingSpent,
    /// Everything the wallet spent came straight back to it: a consolidation or self-transfer with
    /// no fee. Nothing left, so there is nothing to announce.
    NothingLeft,
    /// The height cannot be scored from what the replica holds, so it is recorded as NOTHING.
    ///
    /// Three shapes reach here, all of which would otherwise produce a figure the node did not
    /// observe: a spend set that is not purely plain XCH at a watched address (a CAT's change can
    /// be invisible while its input is visible); a returned coin the wallet cannot fully account
    /// for; and an arithmetic impossibility such as more value returning than was spent, which
    /// means the replica's view of the height is incomplete.
    Unaccountable,
}

/// Decide what one confirmed height IS. PURE — the whole judgement, in one place, so a recorder
/// cannot be correct in SQL and wrong in Rust.
///
/// `spent` is every coin the replica holds with `spent_height == height`; `created` is every coin
/// it holds with `created_height == height`. Both are read from the same transaction that wrote
/// the batch, so a spend and its change arriving together cannot race.
///
/// `watched_p2_hashes` are the wallet's own bare p2 puzzle hashes, lowercase hex — exactly the set
/// the chain subscription was taken over.
pub fn settle(
    height: u32,
    baseline: SendBaseline,
    spent: &[SpentCoin],
    created: &[CreatedCoin],
    watched_p2_hashes: &HashSet<String>,
) -> Verdict {
    // Trap 4. Without a baseline there is no line between history and news.
    let Some(baseline) = baseline else {
        return Verdict::NoBaseline;
    };
    if height <= baseline {
        return Verdict::Backfill;
    }
    if spent.is_empty() {
        return Verdict::NothingSpent;
    }

    // Only a height the wallet can fully account for may produce a figure. A CAT sits at a curried
    // puzzle hash the peer sync path drops, so its change can be absent while its input is present
    // — and the difference between them would be announced as money sent.
    let accountable = |asset_id: &Option<String>, puzzle_hash: &str| {
        asset_id.is_none() && watched_p2_hashes.contains(&puzzle_hash.to_ascii_lowercase())
    };
    if !spent
        .iter()
        .all(|c| accountable(&c.asset_id, &c.puzzle_hash))
    {
        return Verdict::Unaccountable;
    }

    let spent_ids: HashSet<&str> = spent.iter().map(|c| c.coin_id.as_str()).collect();
    // Trap 1 and trap 2 together. A coin created at this height BY one of these spends is the
    // wallet's own change coming home, so its value never left — which is what makes the figure a
    // difference rather than an input, and what makes the change stop being a second notification.
    let returned: Vec<&CreatedCoin> = created
        .iter()
        .filter(|c| spent_ids.contains(c.parent_coin_info.as_str()))
        .collect();
    if !returned
        .iter()
        .all(|c| accountable(&c.asset_id, &c.puzzle_hash))
    {
        return Verdict::Unaccountable;
    }

    let (Some(inputs), Some(outputs)) = (
        sum(spent.iter().map(|c| &c.amount)),
        sum(returned.iter().map(|c| &c.amount)),
    ) else {
        // An amount the ledger cannot read is not a number to subtract with.
        return Verdict::Unaccountable;
    };
    // Conservation says a spend cannot create more than it consumed, so this is not a send that
    // happens to be negative — it is proof the replica's view of the height is incomplete.
    let Some(net_outflow) = inputs.checked_sub(outputs) else {
        return Verdict::Unaccountable;
    };
    if net_outflow == 0 {
        return Verdict::NothingLeft;
    }
    Verdict::Send { net_outflow }
}

/// Total a set of stored decimal amounts, or `None` if any of them is not a number.
///
/// `u128` rather than `u64`: the individual amounts fit a `u64`, but their SUM need not, and a
/// wrapped total is a small believable figure standing in for a large one.
fn sum<'a>(mut amounts: impl Iterator<Item = &'a String>) -> Option<u128> {
    amounts.try_fold(0u128, |total, amount| {
        total.checked_add(amount.parse::<u128>().ok()?)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn watched() -> HashSet<String> {
        ["aa".to_string(), "bb".to_string()].into_iter().collect()
    }

    fn spent(coin_id: &str, amount: &str) -> SpentCoin {
        SpentCoin {
            coin_id: coin_id.into(),
            puzzle_hash: "aa".into(),
            amount: amount.into(),
            asset_id: None,
        }
    }

    fn change(parent: &str, amount: &str) -> CreatedCoin {
        CreatedCoin {
            parent_coin_info: parent.into(),
            puzzle_hash: "bb".into(),
            amount: amount.into(),
            asset_id: None,
        }
    }

    /// **TRAP 1 — the amount is the trap.** A 9 XCH coin spent to send 1 XCH returns ~8 XCH of
    /// change. The figure is the 1 that left, never the 9 the coin held.
    #[test]
    fn a_large_coin_spent_for_a_small_payment_reports_only_what_left() {
        let verdict = settle(
            100,
            Some(50),
            &[spent("c1", "9000000000000")],
            &[change("c1", "7999995000000")],
            &watched(),
        );
        assert_eq!(
            verdict,
            Verdict::Send {
                net_outflow: 1_000_005_000_000
            },
            "the send is inputs minus what came back, never the spent coin's amount"
        );
        assert_ne!(
            verdict,
            Verdict::Send {
                net_outflow: 9_000_000_000_000
            }
        );
    }

    /// **TRAP 2 — a send and its change are ONE notification.** The unit of judgement is a height,
    /// so the change cannot become a second verdict: there is only ever one verdict per height.
    #[test]
    fn a_send_with_change_yields_exactly_one_verdict_and_the_change_is_not_a_second_send() {
        let spends = [spent("c1", "9000000000000")];
        let creations = [change("c1", "7999995000000")];
        let verdict = settle(100, Some(50), &spends, &creations, &watched());
        assert_eq!(
            verdict,
            Verdict::Send {
                net_outflow: 1_000_005_000_000
            }
        );
        // The change coin, offered on its own as if it were its own event, is not a send at all:
        // nothing was spent to reach it, so there is no difference to announce.
        assert_eq!(
            settle(100, Some(50), &[], &creations, &watched()),
            Verdict::NothingSpent,
            "the change coin must never be able to produce a second send"
        );
    }

    /// **TRAP 2b — a multi-input spend is not double-counted.** Two inputs of 5 and 4 with 8
    /// returning is ONE send of 1, not two sends, and not 9.
    ///
    /// This is the case a parent-link grouping gets wrong: the change coin names only ONE of the
    /// inputs as its parent, so grouping per parent would score the other input as a whole second
    /// send of its full amount. Summing over the height makes that shape unreachable.
    #[test]
    fn a_multi_input_spend_is_summed_once_not_counted_per_input() {
        let verdict = settle(
            100,
            Some(50),
            &[spent("c1", "5000000000000"), spent("c2", "4000000000000")],
            // The change names c1 only — c2 is bound to the same bundle by announcements the
            // replica cannot see.
            &[change("c1", "8000000000000")],
            &watched(),
        );
        assert_eq!(
            verdict,
            Verdict::Send {
                net_outflow: 1_000_000_000_000
            },
            "both inputs are consumed by the one transaction; the orphaned input is not a second send"
        );
        assert_ne!(
            verdict,
            Verdict::Send {
                net_outflow: 4_000_000_000_000
            },
            "scoring the parentless input on its own is the multi-input double count"
        );
    }

    /// **Multiple change coins are all credited back.** A spend that returns change to two of the
    /// wallet's own addresses has not sent that money anywhere.
    #[test]
    fn every_returning_coin_is_credited_not_only_the_first() {
        assert_eq!(
            settle(
                100,
                Some(50),
                &[spent("c1", "10")],
                &[change("c1", "4"), change("c1", "5")],
                &watched()
            ),
            Verdict::Send { net_outflow: 1 }
        );
    }

    /// **An incoming payment confirmed in the same block is not netted against the send.** A coin
    /// created at this height by a stranger's spend has a parent the wallet does not hold, so it is
    /// an ARRIVAL and belongs to the other ledger — subtracting it would understate the send.
    #[test]
    fn a_stranger_s_payment_in_the_same_block_does_not_reduce_the_send() {
        let arrival = CreatedCoin {
            parent_coin_info: "someone-elses-coin".into(),
            puzzle_hash: "aa".into(),
            amount: "5000000000000".into(),
            asset_id: None,
        };
        assert_eq!(
            settle(
                100,
                Some(50),
                &[spent("c1", "9000000000000")],
                &[change("c1", "8000000000000"), arrival],
                &watched()
            ),
            Verdict::Send {
                net_outflow: 1_000_000_000_000
            },
            "only coins created BY this wallet's own spends are change"
        );
    }

    /// **TRAP 4a — nothing is a send before the baseline is armed.** However confirmed the spend.
    #[test]
    fn without_a_baseline_a_confirmed_spend_is_still_not_a_send() {
        assert_eq!(
            settle(100, None, &[spent("c1", "9")], &[], &watched()),
            Verdict::NoBaseline
        );
    }

    /// **TRAP 4b — an initial sync replays no sends.** Every historical height sits at or below the
    /// baseline the completed catch-up armed, inclusive of the baseline itself.
    #[test]
    fn history_at_or_below_the_baseline_is_backfill_not_a_send() {
        assert_eq!(
            settle(49, Some(50), &[spent("c1", "9")], &[], &watched()),
            Verdict::Backfill
        );
        assert_eq!(
            settle(50, Some(50), &[spent("c1", "9")], &[], &watched()),
            Verdict::Backfill,
            "the baseline height itself is history: the catch-up already replayed it"
        );
        assert_eq!(
            settle(51, Some(50), &[spent("c1", "9")], &[], &watched()),
            Verdict::Send { net_outflow: 9 },
            "the very next height is news"
        );
    }

    /// **A self-transfer with no fee is not a send.** Everything came back, so nothing left.
    #[test]
    fn a_spend_that_returns_everything_is_not_a_send() {
        assert_eq!(
            settle(
                100,
                Some(50),
                &[spent("c1", "9"), spent("c2", "1")],
                &[change("c1", "10")],
                &watched()
            ),
            Verdict::NothingLeft
        );
    }

    /// **A CAT spend is recorded as NOTHING, never as a figure.** Its change lives at a curried
    /// puzzle hash the peer sync path drops, so the input can be visible while the change is not —
    /// and the difference would be announced as the whole balance leaving.
    #[test]
    fn a_spend_the_replica_cannot_fully_account_for_is_recorded_as_nothing() {
        let cat = SpentCoin {
            coin_id: "c1".into(),
            puzzle_hash: "aa".into(),
            amount: "1000".into(),
            asset_id: Some("a406d3".into()),
        };
        assert_eq!(
            settle(100, Some(50), &[cat], &[], &watched()),
            Verdict::Unaccountable,
            "a CAT send whose change is invisible must produce silence, not the input's amount"
        );

        // The same rule at a foreign puzzle hash: a coin the wallet holds only because it was
        // HINTED to us sits outside the subscribed set, so its siblings may be missing too.
        let hinted = SpentCoin {
            coin_id: "c1".into(),
            puzzle_hash: "curried-somewhere-else".into(),
            amount: "1000".into(),
            asset_id: None,
        };
        assert_eq!(
            settle(100, Some(50), &[hinted], &[], &watched()),
            Verdict::Unaccountable
        );

        // And on the RETURNING side: an XCH input that created a CAT cannot be scored either, since
        // the wallet cannot tell how much of it came home.
        let minted = CreatedCoin {
            parent_coin_info: "c1".into(),
            puzzle_hash: "bb".into(),
            amount: "500".into(),
            asset_id: Some("a406d3".into()),
        };
        assert_eq!(
            settle(100, Some(50), &[spent("c1", "1000")], &[minted], &watched()),
            Verdict::Unaccountable
        );
    }

    /// **More value returning than was spent means the replica's view is incomplete.** Conservation
    /// forbids it on chain, so it is evidence rather than a negative send.
    #[test]
    fn an_impossible_arithmetic_result_is_recorded_as_nothing() {
        assert_eq!(
            settle(
                100,
                Some(50),
                &[spent("c1", "5")],
                &[change("c1", "9")],
                &watched()
            ),
            Verdict::Unaccountable
        );
    }

    /// **An amount the ledger cannot read is not a number to subtract with.**
    #[test]
    fn an_unreadable_amount_is_recorded_as_nothing() {
        assert_eq!(
            settle(
                100,
                Some(50),
                &[spent("c1", "not-a-number")],
                &[],
                &watched()
            ),
            Verdict::Unaccountable
        );
        assert_eq!(
            settle(
                100,
                Some(50),
                &[spent("c1", "10")],
                &[change("c1", "")],
                &watched()
            ),
            Verdict::Unaccountable
        );
    }

    /// **The full `u64` range survives.** Amounts are summed as `u128`, so a wallet holding coins
    /// that total above `u64::MAX` cannot wrap into a small, wrong, believable figure.
    #[test]
    fn summing_large_amounts_cannot_wrap_into_a_small_believable_figure() {
        let max = u64::MAX.to_string();
        assert_eq!(
            settle(
                100,
                Some(50),
                &[spent("c1", &max), spent("c2", &max)],
                &[change("c1", "1")],
                &watched()
            ),
            Verdict::Send {
                net_outflow: u128::from(u64::MAX) * 2 - 1
            }
        );
    }
}
