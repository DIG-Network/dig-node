//! Bring-up for the node's OWN operating wallet — the one wallet this process may sign with.
//!
//! # What this is, and what it is emphatically not
//!
//! `SPEC.md` §16.4 mints a sealed mnemonic on every install, under a device key, with no user in the
//! path. That wallet is **machine custody**: it is the node's own money, the address the dig-app
//! deposit flow funds, and the address collateral returns to. It is NOT the user's account, and
//! §908 is untouched by this module — no user seed reaches this process, and nothing here can be
//! reached by a dapp, an RPC method, or the control plane.
//!
//! This module is the only place that turns that sealed phrase into something that can produce a
//! signature. It exists so there is exactly ONE such place: a second derivation of the same wallet
//! would be a second answer to "which address is ours", and the two would disagree the moment either
//! moved.
//!
//! # Standard Chia HD derivation, deliberately
//!
//! The keys are derived by `digstore_chain::keys::derive_wallet_keys`, the ecosystem's canonical
//! standard-Chia-HD derivation (BIP-39 seed → master → `master_to_wallet_unhardened(0)` →
//! `derive_synthetic()`). Using the standard path is a **recovery property, not a style choice**: the
//! phrase `dign wallet export-seed` hands back must open this wallet in any ordinary Chia wallet,
//! including whatever is locked in unreclaimed mirror coins, with no dig-node code involved. A
//! bespoke derivation would make the exported phrase a phrase that recovers nothing.
//!
//! The first derived key is the wallet: its standard puzzle hash is the receive address, the
//! `owner_puzzle_hash` term of every mirror hint this node creates, the address reclaims return to,
//! and the address create-change returns to. Deposits, bonds and reclaims therefore all move through
//! one address the wallet already tracks.
//!
//! # Nothing here is installed on the general wallet surface
//!
//! [`OperatorWallet`] is a value a caller holds; it is not registered anywhere. In particular it is
//! never passed to `WalletBackend::with_signer`, so `WalletBackend::current_signer()` answers exactly
//! what it answered before — see the guard test
//! `sage::rpc::tests::opening_the_operator_wallet_installs_no_signer_on_the_general_surface`, in
//! `sage/rpc.rs`, which is where a `WalletBackend` can be built and so where the mistake would be
//! made. That matters beyond
//! tidiness: installing a signer on the general backend would silently activate every other
//! node-custodied spend path, including default-on auto-tipping, as a side effect of enabling
//! collateralisation.

use chia_protocol::Bytes32;

use crate::autoseed::{self, WalletPaths};
use crate::sage::spend::WalletSigner;

/// The node's own operating wallet, opened and ready to sign.
///
/// Holding one is not permission to sign anything in particular — the signer inside is reachable
/// only through [`Self::signer`], and the mirror lifecycle wraps it so its own callers can pass
/// nothing but a proven mirror spend.
pub struct OperatorWallet {
    signer: WalletSigner,
    owner_puzzle_hash: Bytes32,
}

impl OperatorWallet {
    /// Open the operator wallet at `paths` for the network `agg_sig_data` selects.
    ///
    /// `None` when no operator wallet is available — the seed is absent, the device key is missing or
    /// malformed (§16.4 `Orphaned`), the sealed seed will not open (`Locked`), or the phrase does not
    /// derive. A caller MUST report the capability as unavailable rather than fall back to any other
    /// key; there is no other key it would be correct to use.
    ///
    /// This function reads. It never mints a seed and never mints a device key: minting a device key
    /// beside an existing seed produces a key that cannot open it, turning a recoverable mistake into
    /// permanent loss. Only the §16.4 bootstrap may create either.
    ///
    /// Nothing here is logged. The phrase lives in a zeroizing wrapper for the length of the
    /// derivation and the failure type is `Option`, so no error path can carry a fragment of it.
    pub fn open(paths: &WalletPaths, agg_sig_data: Bytes32) -> Option<Self> {
        let phrase = autoseed::open_operator_phrase(paths)?;
        Self::from_phrase(&phrase, agg_sig_data)
    }

    /// Derive the wallet from a mnemonic already in hand.
    ///
    /// Separated from [`Self::open`] so the derivation — the half with a checkable property — can be
    /// exercised against a known phrase without a sealed file, a device key, or a temp layout. The
    /// seal is `autoseed`'s contract and is tested there; this is the derivation's.
    pub fn from_phrase(phrase: &str, agg_sig_data: Bytes32) -> Option<Self> {
        let keys = digstore_chain::keys::derive_wallet_keys(phrase).ok()?;
        Some(Self {
            owner_puzzle_hash: keys.owner_puzzle_hash,
            signer: WalletSigner::new(vec![keys.synthetic_sk], agg_sig_data),
        })
    }

    /// The signer for this wallet's keys.
    pub fn signer(&self) -> &WalletSigner {
        &self.signer
    }

    /// This wallet's own standard puzzle hash — the receive address, the reclaim destination, the
    /// change destination, and the `owner_puzzle_hash` term of every mirror hint this node creates.
    ///
    /// One value for all four uses on purpose: a deposit the user makes, a bond the node locks, and
    /// the collateral that comes back all move through an address the wallet already watches.
    pub fn owner_puzzle_hash(&self) -> Bytes32 {
        self.owner_puzzle_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed, well-known BIP-39 phrase. Fixed rather than generated so the derived address is a
    /// value this test can compare against an INDEPENDENT derivation rather than against itself.
    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
abandon abandon abandon art";

    fn agg_sig_data() -> Bytes32 {
        Bytes32::from([7u8; 32])
    }

    /// The wallet derives, and its address is the standard-layer puzzle hash of the first
    /// unhardened synthetic key.
    ///
    /// The assertion re-derives the expected value from `chia_bls` + `chia_puzzle_types` DIRECTLY,
    /// rather than calling the same helper the implementation calls. Comparing the code against
    /// itself would pass for any derivation whatsoever, including one whose exported phrase recovers
    /// nothing — which is the whole property this test exists to hold.
    #[test]
    fn the_operator_address_is_the_standard_chia_hd_address_for_the_phrase() {
        // `derive_keys` is a private module in chia-bls 0.36; its contents are re-exported at the
        // crate root, which is the supported path.
        // Both re-exported at their crate roots; `derive_keys` and `derive_synthetic` are private
        // modules. `DeriveSynthetic` is the trait that carries `derive_synthetic`, and it lives in
        // chia-puzzle-types rather than chia-bls.
        use chia_bls::{master_to_wallet_unhardened, SecretKey};
        use chia_puzzle_types::{standard::StandardArgs, DeriveSynthetic};

        let wallet = OperatorWallet::from_phrase(PHRASE, agg_sig_data())
            .expect("a valid 24-word phrase derives");

        let mnemonic = bip39::Mnemonic::parse(PHRASE).expect("valid phrase");
        let seed = mnemonic.to_seed("");
        let master = SecretKey::from_seed(&seed);
        let expected_sk = master_to_wallet_unhardened(&master, 0).derive_synthetic();
        let expected_ph =
            Bytes32::from(StandardArgs::curry_tree_hash(expected_sk.public_key()).to_bytes());

        assert_eq!(
            wallet.owner_puzzle_hash(),
            expected_ph,
            "the exported phrase must recover this wallet in any standard Chia wallet"
        );
    }

    /// The derived key is the one the signer will actually sign with — not merely an address that
    /// happens to match.
    ///
    /// Asserted through `public_keys()`, which is what `WalletSigner::sign` decides on, rather than
    /// through `puzzle_hashes()`: a coin's puzzle hash equals its owner's p2 hash only for a bare
    /// standard coin, and a mirror coin is a CAT. The required KEY is what is invariant.
    #[test]
    fn the_signer_holds_the_key_the_address_is_derived_from() {
        let wallet = OperatorWallet::from_phrase(PHRASE, agg_sig_data()).expect("derives");
        let keys = digstore_chain::keys::derive_wallet_keys(PHRASE).expect("derives");

        assert!(
            wallet.signer().public_keys().contains(&keys.synthetic_pk),
            "the signer must hold the key that spends the wallet's own address"
        );
        assert_eq!(
            wallet.signer().change_puzzle_hash(),
            Some(wallet.owner_puzzle_hash()),
            "change returns to the same address deposits arrive at"
        );
    }

    /// A phrase that is not a valid mnemonic yields no wallet, rather than a wallet derived from
    /// garbage. The control is the valid phrase above, which must still derive — without it, an
    /// implementation that returned `None` unconditionally would pass.
    #[test]
    fn an_invalid_phrase_yields_no_wallet() {
        assert!(
            OperatorWallet::from_phrase("not a mnemonic", agg_sig_data()).is_none(),
            "an unparsable phrase must not produce a wallet"
        );
        assert!(
            OperatorWallet::from_phrase(PHRASE, agg_sig_data()).is_some(),
            "and the valid phrase must, so the assertion above is not vacuous"
        );
    }

    /// Two networks derive the SAME address and different signing domains.
    ///
    /// `agg_sig_data` changes the message a signature commits to, never the key that produces it, so
    /// an implementation that folded the network into derivation would give a node one address on
    /// mainnet and another on testnet — and money sent to the first would be invisible to the second.
    #[test]
    fn the_address_does_not_depend_on_the_network_domain() {
        let a = OperatorWallet::from_phrase(PHRASE, Bytes32::from([1u8; 32])).expect("derives");
        let b = OperatorWallet::from_phrase(PHRASE, Bytes32::from([2u8; 32])).expect("derives");
        assert_eq!(a.owner_puzzle_hash(), b.owner_puzzle_hash());
    }
}
