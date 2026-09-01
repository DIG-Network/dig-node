//! §25.8's read: this node's mirror bonds, as one page of the published contract (dig-node#412).
//!
//! [`super::pass`] decides; this translates that decision into
//! [`MirrorBondStatesResult`](dig_node_control_interface::results::MirrorBondStatesResult) and cuts
//! it into pages. Pure — no clock, no chain, no disk — so every property below is a fixture and a
//! literal rather than a run.
//!
//! # Three things this module exists to get right, each wrong in the reassuring direction
//!
//! **The locked total spans the whole set, never the page.** It is passed in from the one place that
//! saw the entire chain observation ([`super::runner::PassReport::locked_dig_base_units`]) and is
//! copied onto every page unchanged. A client summing a page under-reports locked money on any node
//! with more bonds than fit in one page, and money reported as free while it is on chain is the one
//! direction a money figure must never be wrong in. dig-app#289 renders this field.
//!
//! **Keys are normalized BEFORE they are sorted.** The contract's order is ascending over the
//! LOWERCASE unprefixed hex spelling of `(store_id, root)`, and `MirrorBondKey`'s `Ord` derives over
//! raw `String`s — so a producer that sorted a `0xAB…` spelling and a client that sorted `ab…` would
//! disagree about where the cursor points, and a walk would skip or repeat rows. On a surface a
//! locked-$DIG total is read from, a repeated page is wrong and indistinguishable from correct.
//! Normalizing here is what makes the emitted cursor canonical; the params side refuses a
//! non-canonical one it is handed.
//!
//! **A `FundsUnknown` bond is `deferred{balance_unreadable}`, per row.** Not `unfunded`, which
//! asserts a shortfall this node has no evidence for — the dig-app#300 conflation — and not the
//! call-level `unknown`, which would blank a page of known-good `bonded` rows because one input was
//! unreadable.

use dig_node_control_interface::results::{
    CollateralUnknownReason, MirrorBondEntry, MirrorBondKey, MirrorBondState,
    MirrorBondStatesResult,
};

use super::pass::BondState;
use super::plan::Bond;

/// What one page of §25.8 is cut from: the whole answer, before any paging.
///
/// Carried as one struct rather than four arguments so a caller cannot pair this pass's states with
/// another pass's locked total — the two are only consistent when they came from the same
/// observation, and a mismatched pair is a money figure that describes a set the rows do not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BondObservation {
    /// One state per bond of the SERVED set — held and relayed both, so `withheld` has a producer.
    pub states: Vec<(Bond, BondState)>,
    /// The $DIG locked across the WHOLE owned coin set, including coins being reclaimed.
    pub locked_dig_base_units: u64,
    /// The epoch in force when the observation was taken.
    pub epoch: i64,
}

/// Cut one page of §25.8 out of `observation`.
///
/// `after` resumes STRICTLY after that key in ascending canonical order; `limit` is the page bound
/// the caller asked for, already validated by
/// [`MirrorBondStatesParams`](dig_node_control_interface::params::MirrorBondStatesParams).
///
/// `complete` is computed from what is LEFT, not from the page's length: a set that is an exact
/// multiple of the page size makes the last full page indistinguishable from a truncated one, and a
/// client that inferred completeness from a short page would end a walk early.
pub fn page(
    observation: &BondObservation,
    after: Option<&MirrorBondKey>,
    limit: u32,
) -> MirrorBondStatesResult {
    let mut rows: Vec<(MirrorBondKey, MirrorBondState)> = observation
        .states
        .iter()
        .map(|(bond, state)| (canonical_key(bond), wire_state(state)))
        .collect();
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    rows.dedup_by(|a, b| a.0 == b.0);

    let remaining: Vec<(MirrorBondKey, MirrorBondState)> = match after {
        Some(after) => rows.into_iter().filter(|(key, _)| key > after).collect(),
        None => rows,
    };

    let taken = limit as usize;
    let complete = remaining.len() <= taken;
    let entries: Vec<MirrorBondEntry> = remaining
        .into_iter()
        .take(taken)
        .map(|(key, state)| MirrorBondEntry {
            store_id: key.store_id,
            root: key.root,
            state,
        })
        .collect();

    // The cursor is the key the caller was HANDED — the last row of THIS page — so a caller
    // resuming from it cannot land on a row it never saw. `None` for an empty page, which is
    // meaningful: there is no position to resume from.
    let cursor = entries.last().map(|entry| MirrorBondKey {
        store_id: entry.store_id.clone(),
        root: entry.root.clone(),
    });

    MirrorBondStatesResult::Known {
        entries,
        complete,
        cursor,
        locked_dig_base_units: observation.locked_dig_base_units,
        epoch: observation.epoch.max(0) as u64,
    }
}

/// The key for a bond, in the contract's canonical spelling: lowercase, unprefixed hex.
///
/// Applied before the sort rather than at emit time. The order is over these STRINGS, so
/// normalizing after sorting would emit canonical keys in a non-canonical order — the shape whose
/// symptom is a walk that skips a row while looking correct.
fn canonical_key(bond: &Bond) -> MirrorBondKey {
    MirrorBondKey {
        store_id: canonical_hex(&bond.store_id),
        root: canonical_hex(&bond.root),
    }
}

/// Lowercase and strip one optional `0x`. Anything else is passed through unchanged: this is the
/// node's own bond set, and silently rewriting an id that is not 64-hex would hide the defect that
/// produced it rather than the spelling difference this normalization is for.
fn canonical_hex(value: &str) -> String {
    let lowered = value.to_ascii_lowercase();
    lowered
        .strip_prefix("0x")
        .map(str::to_owned)
        .unwrap_or(lowered)
}

/// One internal [`BondState`] as the contract states it.
///
/// Total rather than a catch-all, so a variant added to `BondState` is a compile error here instead
/// of silently becoming whichever arm a wildcard pointed at — the same guard dig-app keeps over
/// `CollateralUnknownReason`, and for the same reason: every arm below is a money statement.
pub fn wire_state(state: &BondState) -> MirrorBondState {
    match state {
        BondState::Bonded {
            coin_id,
            epoch,
            amount_dig_base_units,
        } => MirrorBondState::Bonded {
            coin_id: coin_id.clone(),
            epoch: (*epoch).max(0) as u64,
            amount_dig_base_units: *amount_dig_base_units,
        },
        BondState::Pending => MirrorBondState::Pending,
        BondState::Unfunded {
            short_dig_base_units,
        } => MirrorBondState::Unfunded {
            short_dig_base_units: *short_dig_base_units,
        },
        // The wallet could not be read. `Deferred` with a reason that names the WALLET — never
        // `Unfunded`, which would assert a shortfall on no evidence, and never a census-shaped
        // reason, which would send an operator to fix a census that is working.
        BondState::FundsUnknown => MirrorBondState::Deferred {
            reason: CollateralUnknownReason::BalanceUnreadable,
        },
        BondState::Deferred { reason } => MirrorBondState::Deferred { reason: *reason },
        // INTERIM (dig-node-control-interface has no `unadvertised` value yet, and adding one is
        // a release-first change in that repo). `Disabled` is the least-wrong existing value: it
        // and `Unadvertised` agree on the only fact a person acts on at once — this node will
        // create no bonds — and differ only in which knob clears it. It is chosen over the two
        // alternatives deliberately: `Unfunded` would name a figure and send the operator to buy
        // $DIG that would bond nothing, and a `Deferred` reason would blame the census or the
        // wallet, both of which are working. Understating the remedy is recoverable; a false money
        // statement is the class this whole enum exists to prevent.
        BondState::Unadvertised => MirrorBondState::Disabled,
        BondState::Disabled => MirrorBondState::Disabled,
        BondState::Withheld => MirrorBondState::Withheld,
        BondState::Reclaiming {
            coin_id,
            epoch,
            amount_dig_base_units,
        } => MirrorBondState::Reclaiming {
            coin_id: coin_id.clone(),
            epoch: (*epoch).max(0) as u64,
            amount_dig_base_units: *amount_dig_base_units,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bond(store: &str, root: &str) -> Bond {
        Bond::new(store, root)
    }

    /// A 64-hex id whose first byte is `n`, so fixtures sort in a stated order.
    fn hex(n: u8) -> String {
        format!("{n:02x}").repeat(32)
    }

    fn observation(states: Vec<(Bond, BondState)>, locked: u64) -> BondObservation {
        BondObservation {
            states,
            locked_dig_base_units: locked,
            epoch: 7,
        }
    }

    fn known(
        result: MirrorBondStatesResult,
    ) -> (Vec<MirrorBondEntry>, bool, Option<MirrorBondKey>, u64) {
        match result {
            MirrorBondStatesResult::Known {
                entries,
                complete,
                cursor,
                locked_dig_base_units,
                ..
            } => (entries, complete, cursor, locked_dig_base_units),
            other => panic!("expected a Known page, got {other:?}"),
        }
    }

    /// A `Relayed` capsule is genuinely reported as `withheld` — the variant the contract calls
    /// VACUOUS until a producer enumerates its served set.
    ///
    /// The fixture keeps an honest `Bonded` control beside it: a page of nothing but relayed rows
    /// would go green for a producer that answered `withheld` to everything, which is the nearest
    /// wrong implementation to this one.
    #[test]
    fn a_relayed_capsule_is_reported_withheld_beside_a_bonded_one() {
        let page = page(
            &observation(
                vec![
                    (
                        bond(&hex(0x11), &hex(0xaa)),
                        BondState::Bonded {
                            coin_id: "c0".into(),
                            epoch: 7,
                            amount_dig_base_units: 1_010,
                        },
                    ),
                    (bond(&hex(0x22), &hex(0xbb)), BondState::Withheld),
                ],
                1_010,
            ),
            None,
            100,
        );
        let (entries, ..) = known(page);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].store_id, hex(0x22));
        assert_eq!(entries[1].state, MirrorBondState::Withheld);
        assert!(
            matches!(entries[0].state, MirrorBondState::Bonded { .. }),
            "the honest control must not be withheld too: {:?}",
            entries[0].state
        );
    }

    /// `locked_dig_base_units` is the WHOLE-SET total, and a truncated page proves it: the figure
    /// stays put while the page it travels on holds a fraction of the bonds.
    ///
    /// Asserted against the page sum rather than only against the literal, because a producer that
    /// summed the page would satisfy an equality with the literal on any fixture where the two
    /// happen to coincide.
    #[test]
    fn the_locked_total_is_the_whole_sets_and_not_the_pages() {
        let states: Vec<(Bond, BondState)> = (1u8..=4)
            .map(|n| {
                (
                    bond(&hex(n), &hex(0xaa)),
                    BondState::Bonded {
                        coin_id: format!("c{n}"),
                        epoch: 7,
                        amount_dig_base_units: 1_000,
                    },
                )
            })
            .collect();
        let (entries, complete, _, locked) = known(page(&observation(states, 4_000), None, 2));

        assert_eq!(entries.len(), 2, "the page is truncated");
        assert!(!complete);
        assert_eq!(locked, 4_000);
        let page_sum: u64 = entries
            .iter()
            .map(|e| match e.state {
                MirrorBondState::Bonded {
                    amount_dig_base_units,
                    ..
                } => amount_dig_base_units,
                _ => 0,
            })
            .sum();
        assert_ne!(
            locked, page_sum,
            "a page sum would under-report locked money"
        );
    }

    /// A full walk visits every bond EXACTLY once — no skip, no repeat — including across a page
    /// boundary that falls inside one store's roots.
    ///
    /// The fixture deliberately gives one store two roots straddling the boundary: resuming by
    /// `store_id` alone would drop the second, and that is the nearest wrong cursor.
    #[test]
    fn a_cursor_walk_visits_every_bond_exactly_once() {
        let mut states = vec![
            (bond(&hex(0x11), &hex(0x01)), BondState::Pending),
            (bond(&hex(0x11), &hex(0x02)), BondState::Pending),
            (bond(&hex(0x22), &hex(0x01)), BondState::Pending),
        ];
        states.push((bond(&hex(0x33), &hex(0x01)), BondState::Withheld));
        let observed = observation(states, 0);

        let mut seen: Vec<(String, String)> = Vec::new();
        let mut after: Option<MirrorBondKey> = None;
        loop {
            let (entries, complete, cursor, _) = known(page(&observed, after.as_ref(), 2));
            seen.extend(entries.iter().map(|e| (e.store_id.clone(), e.root.clone())));
            if complete {
                break;
            }
            after = Some(cursor.expect("a truncated page hands back a cursor"));
        }

        let mut unique = seen.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(seen.len(), 4, "every bond exactly once");
        assert_eq!(unique.len(), seen.len(), "no bond was repeated: {seen:?}");
        assert_eq!(
            seen[1],
            (hex(0x11), hex(0x02)),
            "the second root of the boundary store survives"
        );
    }

    /// An unreadable wallet is `deferred{balance_unreadable}` — never `unfunded`, and never a
    /// census-shaped reason.
    ///
    /// The other rows of the fixture stay definite, which is the property the call-level `unknown`
    /// would destroy.
    #[test]
    fn an_unreadable_balance_defers_that_row_and_blanks_no_other() {
        let (entries, ..) = known(page(
            &observation(
                vec![
                    (bond(&hex(0x11), &hex(0xaa)), BondState::FundsUnknown),
                    (
                        bond(&hex(0x22), &hex(0xbb)),
                        BondState::Bonded {
                            coin_id: "c0".into(),
                            epoch: 7,
                            amount_dig_base_units: 1_010,
                        },
                    ),
                ],
                1_010,
            ),
            None,
            100,
        ));
        assert_eq!(
            entries[0].state,
            MirrorBondState::Deferred {
                reason: CollateralUnknownReason::BalanceUnreadable
            }
        );
        assert!(
            matches!(entries[1].state, MirrorBondState::Bonded { .. }),
            "one unreadable balance must not blank a known-good row"
        );
    }

    /// A genuinely deferred requirement keeps ITS OWN reason — `balance_unreadable` is not applied
    /// to every `Deferred`, which a mapping that ignored the payload would do while passing the
    /// test above.
    #[test]
    fn a_deferred_requirement_keeps_the_reason_the_requirement_gave() {
        assert_eq!(
            wire_state(&BondState::Deferred {
                reason: CollateralUnknownReason::NotCensused
            }),
            MirrorBondState::Deferred {
                reason: CollateralUnknownReason::NotCensused
            }
        );
    }

    /// Keys are canonicalized BEFORE the sort, so the emitted order is the contract's order over
    /// canonical spellings — not over whatever the observation happened to hold.
    ///
    /// `0xFF…`-prefixed sorts FIRST among raw strings (`0` < `1`) and LAST among canonical ones, so
    /// a producer that normalized after sorting emits a different order on this fixture.
    #[test]
    fn keys_are_canonicalized_before_they_are_sorted() {
        let (entries, _, cursor, _) = known(page(
            &observation(
                vec![
                    (
                        bond(&format!("0x{}", hex(0xff).to_uppercase()), &hex(0xaa)),
                        BondState::Pending,
                    ),
                    (bond(&hex(0x11), &hex(0xaa)), BondState::Pending),
                ],
                0,
            ),
            None,
            100,
        ));
        assert_eq!(
            entries
                .iter()
                .map(|e| e.store_id.as_str())
                .collect::<Vec<_>>(),
            vec![hex(0x11), hex(0xff)]
        );
        assert_eq!(cursor.expect("a cursor").store_id, hex(0xff));
    }

    /// An empty served set is a COMPLETE page with no cursor — not a truncated one, and not a
    /// cursor pointing at a row nobody was handed.
    #[test]
    fn an_empty_set_is_a_complete_page_with_no_cursor() {
        let (entries, complete, cursor, locked) = known(page(&observation(vec![], 0), None, 100));
        assert!(entries.is_empty());
        assert!(complete);
        assert_eq!(cursor, None);
        assert_eq!(locked, 0);
    }

    /// A page holding EXACTLY the whole set says `complete`, which a producer inferring
    /// completeness from a short page would get wrong.
    #[test]
    fn a_page_that_holds_the_whole_set_exactly_says_complete() {
        let states = vec![
            (bond(&hex(0x11), &hex(0xaa)), BondState::Pending),
            (bond(&hex(0x22), &hex(0xaa)), BondState::Pending),
        ];
        let (entries, complete, ..) = known(page(&observation(states, 0), None, 2));
        assert_eq!(entries.len(), 2);
        assert!(complete, "an exactly-full page is still the whole set");
    }
}
