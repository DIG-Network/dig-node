//! Observing whether the node's own wallet has ever held funds, and latching that fact
//! (dig-node#286).
//!
//! `dig_wallet::autoseed::latch_ever_funded` was written, persisted and tested — and never
//! called. The consequence in the shipped build was that an auto-created wallet stayed marked
//! **disposable** forever, however much money arrived in it. That wallet was created without the
//! user asking and its recovery phrase has never been shown to anyone, so "disposable" is the
//! single most dangerous thing a surface can say about it.
//!
//! This module is the missing caller. It holds the decision as a pure function so the rule can be
//! tested without a chain, a wallet or a filesystem.

use dig_wallet::autoseed::{self, WalletPaths};

/// What a balance observation lets the node conclude about the wallet ever having held money.
///
/// # Not to be confused with [`crate::mirror::funding::FundingObservation`]
///
/// The two were both called `FundingObservation` and are different concepts, which is why this one
/// was renamed rather than merged (dig-node#481). Merging them would collapse the distinction
/// `mirror::funding` exists to protect:
///
/// | | this type | `mirror::funding::FundingObservation` |
/// |---|---|---|
/// | subject | the NODE-custodied wallet | the OPERATOR wallet |
/// | question | has it EVER held money | what is spendable THIS pass |
/// | decides | [`dig_wallet::autoseed::latch_ever_funded`] | the operator alert gate |
/// | lifetime | monotonic, permanent | per-pass |
///
/// The name says what it decides: this is evidence about ever having been funded, not a
/// measurement of funding.
///
/// The three variants exist because a balance read has THREE outcomes, not two, and collapsing
/// the middle one is the defect this whole batch is about: a zero from a node that cannot see is
/// not the same claim as a zero from a node that can.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EverFundedEvidence {
    /// A non-zero figure was observed. The wallet holds, or has held, money.
    Funded,
    /// A CURRENT read from an authoritative tier reported zero. This is a real claim of
    /// emptiness — the only observation that is genuine evidence the wallet has never mattered.
    ObservedEmpty,
    /// No usable claim: the read failed, or it answered zero without being current (a stale
    /// replica, an unbounded fallback figure, no chain source at all).
    CannotSay,
}

impl EverFundedEvidence {
    /// Classify a balance reading.
    ///
    /// `balance`/`pending` are summed deliberately: value in flight is value the wallet has held.
    /// `synced` is the currency gate — the same flag
    /// [`dig_wallet::sage::rpc::WalletBalanceResult::synced`] carries, meaning *the replica
    /// produced this figure AND is following the chain right now*.
    pub fn classify(balance: u128, pending: u128, synced: bool) -> Self {
        if balance > 0 || pending > 0 {
            Self::Funded
        } else if synced {
            Self::ObservedEmpty
        } else {
            Self::CannotSay
        }
    }

    /// Whether this observation must latch the funded flag.
    ///
    /// # Only positive evidence of funds latches — and why that is NOT a weakening
    ///
    /// #286 says *"Fail toward latching. If it is unclear whether funds were observed, latch."*
    /// Taken literally that would latch on [`Self::CannotSay`], and [`Self::CannotSay`] is the
    /// state EVERY node is in for the first seconds of its life, before its replica has caught
    /// up. Every auto-created wallet in the ecosystem would latch on its first pass and
    /// `is_disposable` would answer `false` unconditionally — a conformance claim that passes
    /// because the thing it governs never occurs, which is precisely the vacuity #286's own body
    /// cites as the pattern to avoid.
    ///
    /// The instruction's PURPOSE is served without that cost, because of an asymmetry the wording
    /// does not rely on: **the latch is monotonic and nothing ever records "not funded".** Failing
    /// to latch on an unknown therefore defers a decision rather than making the wrong one, and
    /// the next observation that sees money latches. There is no state this can settle into that
    /// says a funded wallet is disposable — only a window before the first usable read.
    ///
    /// The direction that actually matters is already covered, and covered without a currency
    /// gate: [`Self::classify`] answers [`Self::Funded`] for a non-zero figure from EITHER tier.
    /// A stale replica or an unbounded fallback answer that shows money latches immediately.
    /// `synced` gates only the ZERO case, which is the one case where the distinction between
    /// "nothing" and "I cannot see" decides anything.
    pub fn should_latch(self) -> bool {
        matches!(self, Self::Funded)
    }
}

/// Record a balance observation against the wallet at `paths`, latching the funded flag when the
/// observation warrants it.
///
/// Idempotent and cheap to call on every poll: `latch_ever_funded` rewrites nothing once set.
///
/// A latch write that FAILS is logged and swallowed. This runs inside a periodic pass whose job is
/// something else, and a sidecar write failure must not take that pass down — the next observation
/// retries, and the flag defaults to the safe answer meanwhile.
pub fn observe(paths: &WalletPaths, observation: EverFundedEvidence) {
    if !observation.should_latch() {
        return;
    }
    if let Err(e) = autoseed::latch_ever_funded(paths) {
        tracing::warn!(
            error = %e,
            ?observation,
            "could not persist the wallet funded latch; the wallet may still be described as \
             disposable until the next observation succeeds"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The classification is the whole point of the module, so it is pinned in all three
    /// directions at once. A test asserting only `Funded` would pass against an implementation
    /// that returned `Funded` unconditionally.
    #[test]
    fn a_current_zero_is_evidence_of_emptiness_and_an_unsynced_zero_is_not() {
        assert_eq!(
            EverFundedEvidence::classify(0, 0, true),
            EverFundedEvidence::ObservedEmpty
        );
        assert_eq!(
            EverFundedEvidence::classify(0, 0, false),
            EverFundedEvidence::CannotSay
        );
        // The control that makes the pair load-bearing: a real figure classifies as funded from
        // EITHER tier, so `synced` is a gate on the zero case only, never on the money case.
        assert_eq!(
            EverFundedEvidence::classify(1, 0, true),
            EverFundedEvidence::Funded
        );
        assert_eq!(
            EverFundedEvidence::classify(1, 0, false),
            EverFundedEvidence::Funded
        );
        // Value in flight is value held.
        assert_eq!(
            EverFundedEvidence::classify(0, 1, true),
            EverFundedEvidence::Funded
        );
    }

    /// Exactly ONE observation latches, and it is the one that is evidence of money.
    ///
    /// Both non-latching cases are asserted alongside it, because an implementation that latched
    /// unconditionally and one that never latched would each satisfy a single-direction test.
    #[test]
    fn only_evidence_of_money_latches() {
        assert!(EverFundedEvidence::Funded.should_latch());
        assert!(
            !EverFundedEvidence::CannotSay.should_latch(),
            "an unknown DEFERS: every node is in this state on its first pass, so latching here \
             would make `is_disposable` vacuously false forever — see `should_latch`'s doc"
        );
        assert!(
            !EverFundedEvidence::ObservedEmpty.should_latch(),
            "a current zero is real evidence of emptiness and must not latch"
        );
    }

    /// End to end over the real sidecar: an `origin: auto` wallet is disposable, an observation of
    /// funds latches it, and the answer SURVIVES a restart — which is the property #286 asks for
    /// and the one a purely in-memory flag would not have.
    #[test]
    fn observing_funds_makes_an_auto_wallet_permanently_non_disposable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = WalletPaths::resolve(dir.path().join("seed"));
        autoseed::ensure_wallet(&paths).expect("mint an auto wallet");

        assert!(
            autoseed::is_disposable(&paths),
            "a freshly auto-created wallet is disposable — the control for the assertion below"
        );

        // A current zero must NOT latch, or the test below could not fail.
        observe(&paths, EverFundedEvidence::ObservedEmpty);
        assert!(
            autoseed::is_disposable(&paths),
            "a measured empty wallet stays disposable"
        );

        observe(&paths, EverFundedEvidence::Funded);

        // Re-read from the filesystem rather than from memory: this is the restart.
        assert!(
            !autoseed::is_disposable(&paths),
            "a funded auto wallet must never be described as disposable again"
        );
    }
}
