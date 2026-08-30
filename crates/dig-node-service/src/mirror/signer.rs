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
//! **That a spend is recorded** is bounded the same way. `sign` also takes a
//! [`RecordedSpend`](crate::spend_audit::RecordedSpend), whose sole producer is
//! [`SpendJournal::begin`](crate::spend_audit::SpendJournal::begin). A caller therefore cannot reach
//! a signature without having first written a `pending` audit entry: recording is the SHAPE of the
//! call, not a convention a later producer can forget. That is the whole §908 bargain — the node may
//! spend without asking *because* the account of it is readable afterwards — and it is worth stating
//! that a signer wired without a journal would be strictly worse than neither, since it would produce
//! unattended spends with no record.
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

use crate::spend_audit::RecordedSpend;

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

    /// Sign `spends`, which the record `_recorded` has already been opened for.
    ///
    /// `_recorded` is unused by the signing arithmetic and is required anyway. That is the point: its
    /// only producer is `SpendJournal::begin`, so demanding one makes a `pending` audit entry a
    /// precondition of a signature that the type system enforces. Removing this parameter would
    /// remove the audit guarantee while changing no observable behaviour — which is exactly why it is
    /// spelled out here rather than left to a reviewer to notice.
    ///
    /// Refuses a fee above [`MIRROR_SPEND_FEE_CEILING_MOJOS`] before signing anything. The fee read
    /// is `spends`' own — see the module doc for why it is deliberately not a parameter here.
    pub fn sign(
        &self,
        spends: &MirrorSpends,
        _recorded: &RecordedSpend,
    ) -> Result<SpendBundle, SignError> {
        let fee_mojos = spends.fee_mojos();
        if fee_mojos > MIRROR_SPEND_FEE_CEILING_MOJOS {
            return Err(SignError::FeeAboveCeiling {
                requested_mojos: fee_mojos,
                ceiling_mojos: MIRROR_SPEND_FEE_CEILING_MOJOS,
            });
        }

        let coin_spends = spends.coin_spends().to_vec();
        let signature = self
            .wallet
            .signer()
            .sign(&coin_spends)
            .map_err(|e| SignError::Signing(e.to_string()))?;

        Ok(SpendBundle::new(coin_spends, signature))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spend_audit::{kinds, Asset, Authority, SpendIntent, SpendJournal, SpendLog};

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
abandon abandon abandon art";

    fn signer() -> MirrorSigner {
        MirrorSigner::new(
            OperatorWallet::from_phrase(PHRASE, Bytes32::from([7u8; 32])).expect("derives"),
        )
    }

    fn journal(dir: &std::path::Path) -> SpendJournal {
        SpendJournal::new(SpendLog::at(dir.join("spend-audit.jsonl")))
    }

    fn intent() -> SpendIntent {
        SpendIntent {
            kind: crate::spend_audit::SpendKind::new(kinds::MIRROR_COIN),
            purpose: "collateralise a held capsule".to_string(),
            authority: Authority {
                principal: "node".to_string(),
                grant: "mirror-collateral".to_string(),
            },
            asset: Asset::Dig,
            amount_mojos: 1_000,
            fee_mojos: 0,
            store_id: Some("store".to_string()),
        }
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
    #[test]
    fn the_fee_ceiling_is_exact_in_both_directions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let journal = journal(dir.path());
        let recorded = journal.begin(intent());
        let signer = signer();

        let over = signer.sign(
            &super::super::spends::empty_for_tests(MIRROR_SPEND_FEE_CEILING_MOJOS + 1),
            &recorded,
        );
        assert_eq!(
            over,
            Err(SignError::FeeAboveCeiling {
                requested_mojos: MIRROR_SPEND_FEE_CEILING_MOJOS + 1,
                ceiling_mojos: MIRROR_SPEND_FEE_CEILING_MOJOS,
            }),
            "one mojo over the ceiling is refused"
        );

        assert!(
            signer
                .sign(
                    &super::super::spends::empty_for_tests(MIRROR_SPEND_FEE_CEILING_MOJOS),
                    &recorded
                )
                .is_ok(),
            "exactly at the ceiling is permitted, so the refusal above is not unconditional"
        );
    }

    /// Signing requires a journaled spend, and the journal entry exists BEFORE the signature.
    ///
    /// The type system already makes a `RecordedSpend` unobtainable without `SpendJournal::begin`, so
    /// this test cannot fail while compiling — which is the property being demonstrated. What it does
    /// check is the observable half: that `begin` has actually written a `pending` line by the time a
    /// signature is possible, rather than deferring the write to some later resolution.
    #[test]
    fn a_pending_audit_entry_exists_before_a_signature_can_be_produced() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = SpendLog::at(dir.path().join("spend-audit.jsonl"));
        let journal = SpendJournal::new(log.clone());

        let recorded = journal.begin(intent());
        let ledger = log.ledger().expect("ledger readable");
        assert_eq!(
            ledger.records.len(),
            1,
            "the record is written by `begin`, not by whatever happens next"
        );
        assert_eq!(ledger.records[0].status.token(), "pending");

        signer()
            .sign(&super::super::spends::empty_for_tests(0), &recorded)
            .expect("an empty spend set signs to an empty aggregate");
    }
}
