//! The one thing in this process that may sign a mirror-coin spend.
//!
//! # Two guarantees, both structural
//!
//! **What may be signed** is bounded by the argument type. [`MirrorSigner::sign`] takes a
//! [`MirrorSpends`], which has no public constructor and whose only producers wrap
//! `dig_mirror_coin::create` and `::reclaim`. There is no entry point here that accepts a
//! `CoinSpend`, a `Vec<CoinSpend>`, or a `SpendBundle`, so this signer is not a signing oracle with
//! a filter in front of it — it is a function that cannot be handed anything else.
//!
//! **That a spend is recorded, ONCE and TRUTHFULLY**, is bounded the same way. `sign` takes the
//! [`SpendJournal`](crate::spend_audit::SpendJournal) itself and opens the record here, from the
//! spends, returning the [`RecordedSpend`](crate::spend_audit::RecordedSpend) for the caller to
//! resolve. Recording is therefore the SHAPE of the call, not a convention a later producer can
//! forget — and a signer wired without a journal would be strictly worse than neither, since it
//! would produce unattended spends with no record.
//!
//! Taking the journal rather than an already-opened record closes two gaps that an earlier shape
//! left open, both of which an executor written the obvious way would have walked into:
//!
//! * **One record could back N signatures.** A `&RecordedSpend` is a shared borrow and is not
//!   consumed, so a single `begin()` could be handed to `sign` in a loop — N unattended spends
//!   accounted for as one.
//! * **The record could describe a different spend than the one signed.** The intent — amount,
//!   store, fee — was supplied by the caller alongside the spends and never checked against them,
//!   so an entry reading "one spend of X" could sit beside N spends of Y.
//!
//! A record that is confidently wrong is worse than no record at all, because §908's carve-out is
//! bought precisely with the account being true. Both gaps close the same way, and it is the same
//! way the fee ceiling closes below: **read the fact from the artifact, never from a value passed
//! next to it.**
//!
//! # It is not installed anywhere
//!
//! The [`OperatorWallet`] inside is held by this type and is never passed to
//! `WalletBackend::with_signer`. `WalletBackend::current_signer()` therefore answers exactly what it
//! answered before this module existed — asserted in dig-wallet's own
//! `sage::rpc::tests::opening_the_operator_wallet_installs_no_signer_on_the_general_surface`, because
//! that is where a backend can be built and where the mistake would be made. The failure it guards
//! against is silent: installing a signer on the general backend would
//! activate every other node-custodied spend path, including default-on auto-tipping, as a side
//! effect of turning collateralisation on.
//!
//! # Fees cannot shave collateral
//!
//! The crate's builders take XCH fee coins separately from the $DIG being locked, so a fee is never
//! taken out of the amount advertised. [`MIRROR_SPEND_FEE_CEILING_MOJOS`] bounds the fee itself, and
//! [`MirrorSigner::sign`] refuses above it rather than trusting every future caller to check.
//!
//! The ceiling is checked against [`MirrorSpends::fee_mojos`] — the fee the bundle actually pays,
//! recorded by the builder that baked it in — and NOT against a fee the caller passes alongside.
//! Those are not the same bound. A separate argument would make this the one bound of the four that
//! is a promise about a parameter rather than a property of the artifact: a caller holding a reclaim
//! built at 0.9 XCH could offer it with a `0` and be signed, with no edit to this file and nothing
//! for a reviewer of this file to see. Since the fee now travels ON the thing being signed, and
//! `MirrorSpends` has no public constructor, there is no number a caller can substitute.

use chia_protocol::{Bytes32, SpendBundle};
use dig_wallet::operator_wallet::OperatorWallet;

use crate::spend_audit::{FailureStage, RecordedSpend, SpendJournal};

use super::spends::MirrorSpends;

/// The most XCH, in mojos, a single mirror spend may pay in fees: 0.001 XCH.
///
/// Deliberately generous against observed mainnet fees — its job is that the bound EXISTS and is
/// stated, not that it is tight. The shipped default fee is 0 and a zero-fee reclaim is explicitly
/// supported, so this ceiling is reached only by a caller that has chosen to pay.
///
/// It may be lowered. It MUST NOT be raised without saying why in the same change: the whole point of
/// a named ceiling on an unattended money path is that widening it is visible.
pub const MIRROR_SPEND_FEE_CEILING_MOJOS: u64 = 1_000_000_000;

/// Why a mirror spend could not be signed.
///
/// No variant carries key material, a phrase, or a puzzle hash — an error from a signing path is one
/// of the likeliest things to end up in a log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignError {
    /// The fee these spends pay exceeds [`MIRROR_SPEND_FEE_CEILING_MOJOS`].
    FeeAboveCeiling {
        /// What the spends actually pay, in XCH mojos.
        requested_mojos: u64,
        /// The ceiling it exceeded, in XCH mojos.
        ceiling_mojos: u64,
    },
    /// These spends belong to a different wallet than the one this signer holds.
    ///
    /// Carries no puzzle hash: an error from a signing path is one of the likeliest things to end up
    /// in a log, and the two hashes are the only interesting thing in it.
    NotThisWallet,
    /// The signature could not be produced. Carries a one-line cause with no key material in it.
    Signing(String),
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignError::FeeAboveCeiling {
                requested_mojos,
                ceiling_mojos,
            } => write!(
                f,
                "mirror spend fee {requested_mojos} mojos exceeds the ceiling of {ceiling_mojos}"
            ),
            SignError::NotThisWallet => write!(
                f,
                "mirror spends belong to a different wallet than this signer holds"
            ),
            SignError::Signing(cause) => write!(f, "mirror spend could not be signed: {cause}"),
        }
    }
}

impl std::error::Error for SignError {}

/// Signs mirror-coin creates and reclaims with the node's own operating wallet, and nothing else.
///
/// Construct one at bring-up and keep it inside the lifecycle. It is deliberately not `Clone` and
/// exposes no way to get at the wallet or the signer it holds: the only thing a holder can do with
/// one is sign a proven mirror spend that has already been journaled.
pub struct MirrorSigner {
    wallet: OperatorWallet,
}

impl MirrorSigner {
    /// Wrap an already-opened operator wallet.
    ///
    /// Takes the wallet rather than opening it so the decision "is an operator wallet available at
    /// all" belongs to bring-up, where the answer can be reported once as a capability state, instead
    /// of being rediscovered — and possibly reported differently — at every spend.
    pub fn new(wallet: OperatorWallet) -> Self {
        Self { wallet }
    }

    /// This wallet's own puzzle hash: the `owner_puzzle_hash` term of every hint this node creates,
    /// the destination reclaims return to, and the address the user funds.
    pub fn owner_puzzle_hash(&self) -> Bytes32 {
        self.wallet.owner_puzzle_hash()
    }

    /// Open an audit record for `spends` and sign them, returning both.
    ///
    /// The record is opened HERE, from the spends, and exactly one is opened per signature. Its
    /// intent — amount, store, fee — is derived by [`MirrorSpends::intent`] and is not something a
    /// caller can state, so the account of a spend cannot disagree with the spend. The caller
    /// resolves the returned [`RecordedSpend`] as the bundle is submitted and confirms (§23.3).
    ///
    /// Two refusals come BEFORE anything is written or signed, so a refused spend leaves no
    /// `pending` entry for a spend that never happened:
    ///
    /// * spends belonging to any wallet but this one ([`SignError::NotThisWallet`]);
    /// * a fee above [`MIRROR_SPEND_FEE_CEILING_MOJOS`] — read from `spends` themselves, never from
    ///   a parameter. See the module doc for why that distinction is the whole bound.
    pub fn sign(
        &self,
        spends: &MirrorSpends,
        journal: &SpendJournal,
    ) -> Result<(SpendBundle, RecordedSpend), SignError> {
        if spends.owner_puzzle_hash() != self.wallet.owner_puzzle_hash() {
            return Err(SignError::NotThisWallet);
        }

        let fee_mojos = spends.fee_mojos();
        if fee_mojos > MIRROR_SPEND_FEE_CEILING_MOJOS {
            return Err(SignError::FeeAboveCeiling {
                requested_mojos: fee_mojos,
                ceiling_mojos: MIRROR_SPEND_FEE_CEILING_MOJOS,
            });
        }

        let recorded = journal.begin(spends.intent());

        let coin_spends = spends.coin_spends().to_vec();
        let signature = match self.wallet.signer().sign(&coin_spends) {
            Ok(signature) => signature,
            Err(e) => {
                // Resolve the record BEFORE returning. A bare `?` here drops `recorded` inside this
                // frame, and `Drop` writes `Unresolved` -- which this crate defines as "the node
                // signed and does not know what became of it". No signature exists, so that entry
                // would claim money may have moved when nothing left the wallet, and §23.5's
                // reconcile would chase a chain reference that can never exist.
                //
                // `Failed { stage: Signing }` is the truthful status: `money_may_have_moved()` is
                // false for it and only for it, which is the whole reason the stage is on the entry.
                let cause = e.to_string();
                journal.failed(&recorded, FailureStage::Signing, cause.clone());
                return Err(SignError::Signing(cause));
            }
        };

        Ok((SpendBundle::new(coin_spends, signature), recorded))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spend_audit::{kinds, SpendJournal, SpendLog};

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
abandon abandon abandon art";

    fn signer() -> MirrorSigner {
        MirrorSigner::new(
            OperatorWallet::from_phrase(PHRASE, Bytes32::from([7u8; 32])).expect("derives"),
        )
    }

    fn journal(dir: &std::path::Path) -> (SpendJournal, SpendLog) {
        let log = SpendLog::at(dir.join("spend-audit.jsonl"));
        (SpendJournal::new(log.clone()), log)
    }

    /// Spends this signer's own wallet owns, paying `fee_mojos`.
    fn own(signer: &MirrorSigner, fee_mojos: u64) -> super::super::spends::MirrorSpends {
        super::super::spends::empty_for_tests(fee_mojos, signer.owner_puzzle_hash())
    }

    /// The mirror signer holds its wallet and hands nothing back.
    ///
    /// The companion assertion — that the GENERAL `WalletBackend` surface still answers
    /// `current_signer() == None` once an operator wallet has been opened — lives in dig-wallet
    /// (`sage::rpc::tests::opening_the_operator_wallet_installs_no_signer_on_the_general_surface`),
    /// because that is where a backend can be built and where the mistake would be made. It is the
    /// guard against a silent side effect: installing this wallet on the general backend would
    /// activate every other node-custodied spend path, default-on auto-tipping included.
    #[test]
    fn the_mirror_signer_exposes_its_wallet_to_nobody() {
        let mirror = signer();
        assert_ne!(
            mirror.owner_puzzle_hash(),
            Bytes32::default(),
            "a real wallet is open behind it"
        );
    }

    /// A fee above the ceiling is refused, and one at the ceiling is not.
    ///
    /// Both sides, because a bound tested only from above passes for an implementation with no bound
    /// at all, and one tested only at the bound passes for an implementation that refuses everything.
    /// The fee here travels ON the spends; that it cannot be overridden by a caller is proven
    /// against a REAL bundle in `tests/mirror_fee_ceiling.rs`, which an empty spend set cannot show.
    #[test]
    fn the_fee_ceiling_is_exact_in_both_directions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (journal, _log) = journal(dir.path());
        let signer = signer();

        assert_eq!(
            signer
                .sign(&own(&signer, MIRROR_SPEND_FEE_CEILING_MOJOS + 1), &journal)
                .err(),
            Some(SignError::FeeAboveCeiling {
                requested_mojos: MIRROR_SPEND_FEE_CEILING_MOJOS + 1,
                ceiling_mojos: MIRROR_SPEND_FEE_CEILING_MOJOS,
            }),
            "one mojo over the ceiling is refused"
        );

        assert!(
            signer
                .sign(&own(&signer, MIRROR_SPEND_FEE_CEILING_MOJOS), &journal)
                .is_ok(),
            "exactly at the ceiling is permitted, so the refusal above is not unconditional"
        );
    }

    /// Spends belonging to another wallet are refused, and this signer's own are not.
    ///
    /// The failure direction was already safe — a bundle signed by the wrong key does not make it
    /// through the network — but §25.2's destination bound is supposed to hold by construction, and
    /// "the network catches it" is a different guarantee. The control is what makes this a test of
    /// the comparison rather than of a signer that refuses everything.
    #[test]
    fn spends_belonging_to_another_wallet_are_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (journal, log) = journal(dir.path());
        let signer = signer();

        let foreign = super::super::spends::empty_for_tests(0, Bytes32::from([0x99u8; 32]));
        assert_eq!(
            signer.sign(&foreign, &journal).err(),
            Some(SignError::NotThisWallet)
        );
        assert!(
            signer.sign(&own(&signer, 0), &journal).is_ok(),
            "the signer's own spends still sign"
        );

        assert_eq!(
            log.ledger().expect("ledger readable").records.len(),
            1,
            "the refused spend wrote no record: nothing happened, so nothing is accounted for"
        );
    }

    /// Each signature opens exactly ONE audit entry, and it is `pending` before the signature.
    ///
    /// The count is the point. When `sign` took an already-opened `&RecordedSpend` it took it by
    /// shared borrow and never consumed it, so one `begin()` could back a loop of signatures — N
    /// unattended spends accounted for as one, which is the shape an executor written the obvious
    /// way produces. Signing twice here and asserting TWO records is what distinguishes the current
    /// shape from that one; asserting only that a record exists would pass under both.
    #[test]
    fn every_signature_opens_exactly_one_pending_record() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (journal, log) = journal(dir.path());
        let signer = signer();

        let (_bundle, recorded) = signer.sign(&own(&signer, 0), &journal).expect("signs");

        let ledger = log.ledger().expect("ledger readable");
        assert_eq!(ledger.records.len(), 1);
        assert_eq!(
            ledger.records[0].status.token(),
            "pending",
            "the record is open by the time a signature exists, not resolved later by someone else"
        );
        assert_eq!(ledger.records[0].id, recorded.id());

        signer.sign(&own(&signer, 0), &journal).expect("signs");
        assert_eq!(
            log.ledger().expect("ledger readable").records.len(),
            2,
            "a second signature is a second record -- one record can never stand for two spends"
        );
    }

    /// The recorded intent is derived from the spends, so the two cannot disagree.
    ///
    /// The fee is the field a caller used to supply, and it is the one asserted here: the record
    /// reports the fee the bundle pays because it reads it from the bundle. `tests/mirror_fee_ceiling.rs`
    /// carries the amount and store half against a real build, which an empty spend set cannot.
    #[test]
    fn the_recorded_intent_comes_from_the_spends() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (journal, log) = journal(dir.path());
        let signer = signer();

        signer
            .sign(&own(&signer, MIRROR_SPEND_FEE_CEILING_MOJOS), &journal)
            .expect("signs");

        let ledger = log.ledger().expect("ledger readable");
        assert_eq!(
            ledger.records[0].fee_mojos, MIRROR_SPEND_FEE_CEILING_MOJOS,
            "the entry names the fee the spends pay, with no caller in a position to say otherwise"
        );
        assert_eq!(ledger.records[0].kind.as_str(), kinds::MIRROR_COIN);
        assert_eq!(ledger.records[0].authority.grant, "mirror-collateral");
    }

    /// A signature that could not be produced is `failed { stage: signing }` — NOT `unresolved`.
    ///
    /// The distinction is the entry's whole job. `Unresolved` means "the node signed and does not
    /// know what became of it", so `money_may_have_moved()` is true for it and §23.5's reconcile
    /// chases a chain reference. When signing itself failed, no bundle exists and nothing can have
    /// moved; `Failed { stage: Signing }` is the only status whose `money_may_have_moved()` is false.
    ///
    /// This was a real regression: a bare `?` on the signing call dropped the open record inside this
    /// frame, and `Drop` writes `Unresolved`. It failed in the SAFE direction — over-reporting risk —
    /// which is exactly why nothing caught it, and why it is fixed before the first production caller
    /// exists rather than after.
    ///
    /// The two assertions are not redundant. The status is asserted because it is the thing that
    /// changed, and `money_may_have_moved()` because that is the property every consumer actually
    /// branches on — a future third status with the wrong answer would pass the first and fail the
    /// second.
    #[test]
    fn a_signing_failure_is_recorded_as_failed_at_signing_not_unresolved() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (journal, log) = journal(dir.path());
        let signer = signer();

        let unsignable = super::super::spends::unsignable_for_tests(signer.owner_puzzle_hash());

        assert!(
            matches!(
                signer.sign(&unsignable, &journal),
                Err(SignError::Signing(_))
            ),
            "the fixture must actually fail to sign, or this test proves nothing"
        );

        let ledger = log.ledger().expect("ledger readable");
        assert_eq!(ledger.records.len(), 1, "one attempt, one entry");
        match &ledger.records[0].status {
            crate::spend_audit::SpendStatus::Failed { stage, .. } => {
                assert_eq!(*stage, crate::spend_audit::FailureStage::Signing);
                assert!(
                    !stage.money_may_have_moved(),
                    "no bundle was produced, so nothing can have moved"
                );
            }
            other => panic!("expected failed at signing, got {other:?}"),
        }
    }
}
