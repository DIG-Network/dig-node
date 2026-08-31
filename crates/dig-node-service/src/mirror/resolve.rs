//! Resolving a mirror spend the chain has since confirmed (dig-node#412 step 6).
//!
//! # The gap this closes
//!
//! A mirror spend is broadcast in one pass and confirms during a LATER one. The audit record's
//! confirmation entry point took a [`RecordedSpend`](crate::spend_audit::RecordedSpend), and a pass
//! drops every handle it opened when it ends — so nothing could ever record the outcome, and every
//! successfully broadcast mirror spend settled `unresolved` on drop. `dign spends` therefore showed
//! a node whose money had demonstrably moved as a node that did not know what it had done.
//!
//! This module is the reader that closes it, over
//! [`SpendJournal::resolve_landed`](crate::spend_audit::SpendJournal::resolve_landed) — the id-keyed
//! entry point that exists inside `spend_audit` because the write path is private to that module.
//!
//! # Resolution is POSITIVE, never inferred
//!
//! Two inferences are available here and both are wrong:
//!
//! - **"the broadcast succeeded, so it landed."** Reaching a mempool is not confirmation, and
//!   `Confirmed` carries a height and a coin id INSIDE the variant precisely so that a record
//!   cannot hold a confirmation without one.
//! - **"the coin disappeared from the owned set, so our reclaim landed."** The mirror puzzle hash
//!   is shared by every mirror coin of every node, so a coin leaving the set proves that SOMEONE
//!   spent it. A short or truncated scan is also indistinguishable from a spend. And in any case
//!   there would be nothing to pass as the confirmed coin id.
//!
//! So the only key used is the coin's PRESENCE, read through
//! [`MirrorEffects::coin_confirmation`](super::runner::MirrorEffects::coin_confirmation), whose
//! three answers stay three:
//!
//! | answer | meaning | action |
//! |---|---|---|
//! | `Ok(Some(height))` | the chain has the coin, in a block | resolve to `Confirmed` |
//! | `Ok(None)` | the chain does not have it, or has it with no height yet | resolve NOTHING |
//! | `Err(_)` | the chain could not be asked | resolve NOTHING |
//!
//! **An `Err` must never resolve anything, and must never resolve anything the other way either.**
//! A chain source that is down for an hour is exactly the condition under which a resolver that
//! "concluded" would produce a wrong answer on every open record at once.
//!
//! # The two operations have different keys, and one of them is `None` by design
//!
//! A **reclaim** records `intended_coin_id = Some(reclaimed_coin_id(coin))`, so it already has the
//! key: one [`coin_confirmation`](super::runner::MirrorEffects::coin_confirmation) read.
//!
//! A **create** records `intended_coin_id = None`, because the created coin's parent is whichever
//! funding input the builder drew from and this node does not know which. Its key is therefore the
//! coin's APPEARANCE in the pass's own chain observation, matched on the `(store, root, epoch)` the
//! record bonds — the three terms the record carries structurally. That match yields a coin id,
//! which is then confirmed positively like any other. Nothing is invented: the coin id comes from
//! the chain, never from the record.
//!
//! # An AMBIGUOUS claim resolves nothing
//!
//! Two open records can name one coin. Two reclaim attempts of the same mirror coin derive the same
//! child id, and at most one of those bundles can have landed; §25.4.6's in-flight suppression
//! deliberately does not suppress on `Unresolved`, so two open creates for one `(store, root,
//! epoch)` are reachable too. Resolving both would tell a person that two spends created one coin,
//! which is false about at least one of them — so a coin claimed by more than one open record, or
//! already attributed to a `Confirmed` record, resolves NONE of them. They stay `unresolved`, which
//! is what they honestly are: this node signed twice and cannot tell which signature landed.

use std::collections::{HashMap, HashSet};

use crate::spend_audit::{kinds, Resolution, SpendJournal, SpendStatus, TargetCoinId};

use super::plan::HeldMirror;
use super::runner::MirrorEffects;

/// What one resolution sweep did. Reported rather than only logged, so a test can assert that an
/// unreadable chain resolved nothing rather than merely assert that it did not crash.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct ResolveSummary {
    /// Records promoted to `Confirmed` this sweep.
    pub recorded: usize,
    /// Open records left alone because the chain could not be asked about their coin.
    pub chain_unreadable: usize,
    /// Open records left alone because more than one of them claims the same coin.
    pub ambiguous: usize,
}

/// Promote every open mirror-coin spend whose coin the chain now shows.
///
/// `on_chain` is the pass's OWN observation, passed in rather than re-read, so the sweep and the
/// plan see one chain reading — the same rule the pass follows for the disk and the balance.
pub(super) fn resolve_landed_spends<E: MirrorEffects + ?Sized>(
    journal: &SpendJournal,
    effects: &E,
    on_chain: &[HeldMirror],
) -> ResolveSummary {
    let mut summary = ResolveSummary::default();

    let ledger = match journal.log().ledger() {
        Ok(ledger) => ledger,
        Err(e) => {
            // Resolve nothing, exactly as an unreadable ledger suppresses no create. The records
            // stay open and the next pass tries again; nothing is written on a read this node
            // could not take.
            tracing::warn!(
                target: "mirror",
                error = %e,
                "the spend audit record could not be read; no landed mirror spend is resolved this pass"
            );
            return summary;
        }
    };

    // Coins already attributed to a settled record. A second record must not be confirmed against
    // a coin some other spend is already recorded as having created.
    let attributed: HashSet<&str> = ledger
        .records
        .iter()
        .filter(|r| matches!(r.status, SpendStatus::Confirmed { .. }))
        .filter_map(|r| r.intended_coin_id.as_ref().map(|c| c.0.as_str()))
        .collect();

    // Every open mirror-coin record, paired with the coin id it claims — from its own
    // `intended_coin_id` for a reclaim, or from the chain observation for a create.
    let mut claims: HashMap<String, Vec<&str>> = HashMap::new();
    for record in &ledger.records {
        if record.kind.as_str() != kinds::MIRROR_COIN {
            continue;
        }
        if !matches!(
            record.status,
            SpendStatus::Submitted | SpendStatus::Unresolved { .. }
        ) {
            continue;
        }
        let coin_id = match &record.intended_coin_id {
            Some(target) => target.0.clone(),
            None => {
                let (Some(store_id), Some(bond)) = (&record.store_id, &record.bond) else {
                    continue; // a record written before the bond was carried structurally
                };
                let Some(found) = on_chain.iter().find(|m| {
                    m.store_id == *store_id && m.root == bond.root && m.epoch == bond.epoch
                }) else {
                    continue; // no coin for this bond yet: nothing positive to confirm against
                };
                found.coin_id.clone()
            }
        };
        claims.entry(coin_id).or_default().push(&record.id);
    }

    for (coin_id, claimants) in claims {
        if claimants.len() > 1 || attributed.contains(coin_id.as_str()) {
            summary.ambiguous += claimants.len();
            tracing::warn!(
                target: "mirror",
                coin_id = %coin_id,
                claimants = claimants.len(),
                "more than one automated spend claims this coin; none is resolved, because at most \
                 one of them created it and this node cannot tell which"
            );
            continue;
        }
        let id = claimants[0];

        match effects.coin_confirmation(&coin_id) {
            Ok(Some(height)) => {
                match journal.resolve_landed(id, TargetCoinId(coin_id.clone()), height) {
                    Ok(Resolution::Recorded) => {
                        summary.recorded += 1;
                        tracing::info!(
                            target: "mirror",
                            spend_id = %id,
                            coin_id = %coin_id,
                            height,
                            "an automated mirror spend is confirmed on chain"
                        );
                    }
                    Ok(other) => tracing::debug!(
                        target: "mirror",
                        spend_id = %id,
                        outcome = ?other,
                        "the audit record was not open for resolution"
                    ),
                    Err(e) => tracing::error!(
                        target: "mirror",
                        spend_id = %id,
                        error = %e,
                        "FAILED to append the confirmation of an automated mirror spend"
                    ),
                }
            }
            // Absent, or present with no height yet. Both mean "not confirmed", and both leave the
            // record open for a later pass rather than settling it as anything.
            Ok(None) => {}
            Err(e) => {
                summary.chain_unreadable += 1;
                tracing::warn!(
                    target: "mirror",
                    spend_id = %id,
                    coin_id = %coin_id,
                    error = %e,
                    "the chain could not be asked about this coin; the spend stays unresolved"
                );
            }
        }
    }

    summary
}
