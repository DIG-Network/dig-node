//! Largest-first coin selection — ONE implementation, for every coin-shaped thing this ecosystem
//! draws spend inputs from.
//!
//! # Why this is a module and not three loops
//!
//! The same fifteen lines had been written three times: over the wallet DB's `CoinRow`s
//! ([`super::rpc`]), over already-resolved `Cat`s ([`super::offers`]), and — the change that
//! prompted the extraction — over chain-read coin records at the operator puzzle hash
//! (dig-node#421). Three copies of a *money* algorithm is the byte-drift shape CLAUDE.md forbids:
//! they were already inconsistent in a way nobody would have chosen deliberately, differing only in
//! the message they print when they refuse.
//!
//! What varies between callers is the coin SET and how to read an amount out of one item. Neither
//! is the algorithm, so both are parameters and the algorithm is written once.
//!
//! # The two properties worth stating
//!
//! **Selection is DETERMINISTIC.** Ordering is descending by amount with an ascending tiebreak on a
//! caller-supplied key, so two nodes — or the same node twice — presented with the same coin set
//! choose the same coins. Without the tiebreak, equal-amount coins order by whatever the source
//! happened to return, and a retry after a restart would select a different funding set for the
//! same spend.
//!
//! **A shortfall REFUSES; it never returns a short set.** The caller is funding a spend, and a
//! partial funding set is not a smaller success — it either fails to build or, worse, builds
//! something that locks the wrong amount. So the outcome is a typed [`Shortfall`] carrying both
//! figures, and each caller phrases it in its own units.

/// A selection that could not reach its target: what was available, and what was needed.
///
/// Both figures are carried rather than a formatted string, because the callers speak different
/// units — XCH mojos, $DIG CAT base units — and a message assembled here would name the wrong one
/// for two of the three. Selection knows the arithmetic; it does not know the asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shortfall {
    /// The total of every candidate that was offered, in the caller's base units.
    pub have: u64,
    /// The total that was required, in the same units.
    pub need: u64,
}

/// Select the fewest largest items whose amounts cover `target`, or refuse with a [`Shortfall`].
///
/// `key` reads one item's `(amount, tiebreak)`. The amount orders descending — largest first, which
/// keeps the number of inputs and therefore the spend size down — and the tiebreak orders ascending
/// so that equal amounts have one stable order rather than the source's incidental one.
///
/// A `target` of zero yields an empty selection, which is correct arithmetic: nothing is needed, so
/// nothing is chosen. A caller for whom an empty funding set is *not* a valid spend must refuse zero
/// in its own right, where the reason can be stated — this function has no way to know that an empty
/// `Vec` will later be handed to a builder that requires inputs.
///
/// Totals accumulate with [`u64::saturating_add`]. The alternative overflows on a coin set summing
/// past `u64::MAX`, which panics in a debug build and wraps to a *small* total in a release one —
/// and a wrapped total reads as a shortfall, so saturating is the direction that cannot manufacture
/// a false success.
pub fn select_largest_first<T, K: Ord>(
    items: Vec<T>,
    target: u64,
    key: impl Fn(&T) -> (u64, K),
) -> Result<Vec<T>, Shortfall> {
    // Decorate-sort-undecorate: `key` is called once per item rather than twice per comparison,
    // which matters because a caller's key may parse a string or hash a coin id.
    let mut decorated: Vec<(u64, K, T)> = items
        .into_iter()
        .map(|item| {
            let (amount, tiebreak) = key(&item);
            (amount, tiebreak, item)
        })
        .collect();
    decorated.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));

    let available = decorated
        .iter()
        .fold(0u64, |sum, item| sum.saturating_add(item.0));

    let mut selected = Vec::new();
    let mut total: u64 = 0;
    for (amount, _, item) in decorated {
        if total >= target {
            break;
        }
        total = total.saturating_add(amount);
        selected.push(item);
    }

    if total < target {
        // `have` is the total of EVERY candidate, not of the ones walked. They are equal here —
        // a shortfall means the walk consumed the whole set — and stating the available total is
        // the figure an operator can act on.
        return Err(Shortfall {
            have: available,
            need: target,
        });
    }
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fixture is deliberately UNSORTED and contains a duplicate amount, because the two
    /// properties under test are the ordering itself and the tiebreak — a pre-sorted fixture with
    /// distinct amounts is satisfied by an implementation that does not sort at all.
    fn coins() -> Vec<(u64, &'static str)> {
        vec![(30, "c"), (70, "a"), (30, "b"), (100, "d")]
    }

    /// Largest first, so a target reachable from one big coin does not consume three small ones.
    #[test]
    fn the_largest_coin_is_taken_first() {
        let selected = select_largest_first(coins(), 90, |c| (c.0, c.1)).expect("covered");
        assert_eq!(
            selected,
            vec![(100, "d")],
            "100 alone covers 90; taking 70+30 instead would build a two-input spend for no reason"
        );
    }

    /// Equal amounts order by the tiebreak, ASCENDING, and the choice is repeatable.
    ///
    /// Asserted on a target that needs exactly ONE of the two thirty-unit coins, so the two
    /// candidates are genuinely interchangeable on amount and only the tiebreak can decide. A test
    /// that took both would pass against an implementation with no tiebreak at all.
    #[test]
    fn equal_amounts_are_broken_by_the_key_not_by_input_order() {
        let selected = select_largest_first(coins(), 190, |c| (c.0, c.1)).expect("covered");
        assert_eq!(
            selected,
            vec![(100, "d"), (70, "a"), (30, "b")],
            "the 30-unit coin chosen is 'b', the lower key — not 'c', which came first in the input"
        );

        let mut reversed = coins();
        reversed.reverse();
        let again = select_largest_first(reversed, 190, |c| (c.0, c.1)).expect("covered");
        assert_eq!(again, selected, "input order must not change the selection");
    }

    /// A shortfall REFUSES, and says what was available rather than handing back what it found.
    #[test]
    fn a_shortfall_refuses_and_reports_both_figures() {
        let err = select_largest_first(coins(), 1_000, |c| (c.0, c.1)).expect_err("not covered");
        assert_eq!(
            err,
            Shortfall {
                have: 230,
                need: 1_000
            },
            "230 is the whole set; a short Vec would be a spend funded at the wrong amount"
        );
    }

    /// Exactly at the target is COVERED — the boundary, from both sides.
    ///
    /// Pinned in both directions because a bound tested only from below can only confirm itself: an
    /// implementation using `>` instead of `>=` refuses the exact-cover case, and one using `<=`
    /// instead of `<` accepts a set one unit short.
    #[test]
    fn the_boundary_holds_from_both_sides() {
        assert!(
            select_largest_first(coins(), 230, |c| (c.0, c.1)).is_ok(),
            "the set totals exactly 230, which covers a target of 230"
        );
        assert!(
            select_largest_first(coins(), 231, |c| (c.0, c.1)).is_err(),
            "one unit over the whole set is a shortfall"
        );
    }

    /// An empty candidate set is a shortfall for any non-zero target, and reports `have: 0`.
    #[test]
    fn an_empty_set_is_a_shortfall_rather_than_an_empty_success() {
        let err =
            select_largest_first(Vec::<(u64, &str)>::new(), 1, |c| (c.0, c.1)).expect_err("empty");
        assert_eq!(err, Shortfall { have: 0, need: 1 });
    }

    /// A total that would overflow saturates rather than wrapping to a small, false shortfall.
    #[test]
    fn an_overflowing_total_saturates_and_still_covers() {
        let huge = vec![(u64::MAX, "a"), (u64::MAX, "b")];
        let selected = select_largest_first(huge, u64::MAX, |c| (c.0, c.1)).expect("covered");
        assert_eq!(
            selected.len(),
            1,
            "the first coin alone covers the target, so the sum never has to be taken"
        );
    }
}
