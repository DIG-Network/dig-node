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
    synthetic_key: chia_bls::PublicKey,
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
            synthetic_key: keys.synthetic_sk.public_key(),
            signer: WalletSigner::new(vec![keys.synthetic_sk], agg_sig_data),
        })
    }

    /// The PUBLIC synthetic key the spend builders curry into a standard layer.
    ///
    /// Public, and deliberately typed as such: `dig_mirror_coin::create` and `::reclaim` both take a
    /// [`chia_bls::PublicKey`] to derive the owner they build for, and handing them the secret key
    /// would be neither necessary nor expressible. Derived once at construction from the same
    /// secret the signer holds, so the key a spend is BUILT for and the key it is SIGNED with cannot
    /// be two different keys.
    pub fn synthetic_key(&self) -> chia_bls::PublicKey {
        self.synthetic_key
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

/// This node's operator PUZZLE HASH, derived without ever producing a signer.
///
/// `None` for exactly the cases [`OperatorWallet::open`] returns `None` for: no seed, no device key,
/// a seal that will not open, or a phrase that does not derive. A caller MUST report the capability
/// as unavailable rather than substitute any other address — a balance or a coin list read for the
/// wrong puzzle hash is a confident number about somebody else's money.
///
/// # Why this exists beside [`OperatorWallet::open`] rather than being a call to it
///
/// The puzzle hash is a **public** value: this node's receive address, the address the dig-app
/// deposit flow funds, and the address reclaims return to. A [`WalletSigner`] is not. §25.8's bond
/// surface (dig-node#412) is a token-gated READ that needs the first and has no business
/// materialising the second, so this function's return type is a [`Bytes32`] and there is no signer
/// value anywhere on its path.
///
/// That distinction is held by the **type**, not by a convention: a control-plane read built on this
/// cannot reach a signing capability, because no such capability is ever constructed for it to
/// reach. `OperatorWallet::open` remains the only way to obtain one, and the mirror lifecycle
/// remains its only caller.
///
/// The secret key derived along the way is dropped at the end of this function and never leaves it;
/// the phrase lives in a zeroizing wrapper for the length of the derivation, exactly as in
/// [`OperatorWallet::open`], and nothing here is logged.
///
/// §908 is untouched. This is the §16.4 machine-custody wallet — the node's own money — and no user
/// seed reaches this process.
pub fn operator_puzzle_hash(paths: &WalletPaths) -> Option<Bytes32> {
    let phrase = autoseed::open_operator_phrase(paths)?;
    Some(
        digstore_chain::keys::derive_wallet_keys(&phrase)
            .ok()?
            .owner_puzzle_hash,
    )
}

/// Why this node cannot name its own operator wallet.
///
/// Two outcomes rather than one `None`, because they call for different responses and a caller that
/// cannot tell them apart must either alarm on a healthy node or stay quiet on a broken one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorAddressUnavailable {
    /// No seed file exists: this node has never run its autoseed setup, so it has no operator
    /// wallet and no address. Nothing is wrong.
    NotInitialized,
    /// Seed material is present and this node could not turn it into an address -- the seal will
    /// not open, the device key is missing, or the phrase does not derive. A fault: a node in this
    /// state cannot pay mirror collateral either.
    Unreadable,
}

/// This node's operator-wallet RECEIVE ADDRESS, bech32m, under `address_prefix`.
///
/// The public destination for the machine-custody wallet -- where a person sends $DIG to fund the
/// wallet that pays mirror collateral. Built on [`operator_puzzle_hash`], so it inherits that
/// function's central property: **no signing capability is ever constructed on this path**, and the
/// distinction is held by the types rather than by convention.
///
/// # It fails rather than approximating
///
/// An unencodable puzzle hash yields [`OperatorAddressUnavailable::Unreadable`], never the hex
/// spelling of the hash and never an empty string. An address a client renders is an address
/// somebody may send money to, so a value that merely LOOKS like one is worse than no value: hex
/// that fails to be an address is at best a dead end, and at worst pasted somewhere it is accepted.
///
/// # The two failures are distinguished by whether the seed FILE exists
///
/// A node that has never been set up and a node whose seal will not open both fail to derive, and
/// reporting them alike would either alarm on the first or stay silent on the second. The seed path
/// is the only observation that separates them without opening anything.
pub fn operator_address(
    paths: &WalletPaths,
    address_prefix: &str,
) -> Result<String, OperatorAddressUnavailable> {
    if !paths.seed.exists() {
        return Err(OperatorAddressUnavailable::NotInitialized);
    }
    let puzzle_hash = operator_puzzle_hash(paths).ok_or(OperatorAddressUnavailable::Unreadable)?;
    chia_wallet_sdk::utils::Address::new(puzzle_hash, address_prefix.to_string())
        .encode()
        .map_err(|_| OperatorAddressUnavailable::Unreadable)
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

    /// **The address this node PUBLISHES is derived from the same puzzle hash the mirror
    /// lifecycle SPENDS from.**
    ///
    /// `server.rs` picks the owner puzzle hash from the SIGNER when one is open and falls back to
    /// [`operator_puzzle_hash`] when none is; `control.wallet.operatorAddress` reaches it through
    /// the fallback. If those two could ever disagree, dig-app would show a funded address while
    /// collateral failed from an empty one -- today's defect rebuilt one layer up, and harder to
    /// diagnose the second time because the app would now be SHOWING an address and it would be
    /// the wrong one.
    ///
    /// They cannot disagree, and this pins that rather than asserting it in prose: both reduce to
    /// `derive_wallet_keys(open_operator_phrase(paths)).owner_puzzle_hash`. The test opens ONE real
    /// sealed wallet on disk and takes both routes over it, so a future change that gave either
    /// route its own derivation, its own phrase source, or its own key slot fails here.
    ///
    /// `agg_sig_data` is varied across the two signer opens deliberately: it is the one input that
    /// differs between call sites, and a derivation that folded it in would give a node two
    /// addresses for one wallet. That property has its own test above; this one keeps it true
    /// through the seam a client actually reads.
    #[test]
    fn the_published_address_derives_from_the_hash_the_mirror_lifecycle_spends_from() {
        let dir = tempfile::tempdir().unwrap();
        let paths = WalletPaths {
            seed: dir.path().join("seed.bin"),
            device_key: dir.path().join("device.key"),
            meta: dir.path().join("meta.json"),
        };
        autoseed::ensure_wallet(&paths).expect("the bootstrap mints a sealed operator wallet");

        let spent_from = OperatorWallet::open(&paths, Bytes32::from([9u8; 32]))
            .expect("the sealed wallet opens")
            .owner_puzzle_hash();
        let published = operator_puzzle_hash(&paths).expect("the same wallet derives its own hash");
        assert_eq!(
            published, spent_from,
            "the address a client is shown must be the wallet collateral is paid from"
        );

        let other_domain = OperatorWallet::open(&paths, Bytes32::from([4u8; 32]))
            .expect("the sealed wallet opens")
            .owner_puzzle_hash();
        assert_eq!(
            other_domain, spent_from,
            "one wallet must not have two addresses because two call sites signed for two networks"
        );

        // And the rendered address is that hash, not a neighbouring one: decode-free, by
        // constructing the expected encoding from the hash the lifecycle spends from.
        let expected = chia_wallet_sdk::utils::Address::new(spent_from, "xch".to_string())
            .encode()
            .unwrap();
        assert_eq!(operator_address(&paths, "xch").unwrap(), expected);
    }

    /// **An address is produced for the network the caller names, and a node with no seed says so
    /// rather than producing anything.**
    ///
    /// Three cases, and the fixture varies exactly one thing at a time.
    ///
    /// The two networks are the control that makes the first assertion mean something: an
    /// implementation that hardcoded `xch` would still pass a single-prefix test, and would render
    /// a mainnet address on a node reading testnet coins -- one wallet in appearance and two in
    /// fact, which is the confusion this whole surface exists to end.
    ///
    /// The missing-seed case asserts the ERROR VALUE, not merely that it failed. A `NotInitialized`
    /// reported as `Unreadable` alarms an operator about a node that is simply new, and the reverse
    /// stays silent about a node whose machine custody is broken; a test that only checked
    /// `is_err()` could not tell those apart, and they are the two responses a person actually
    /// takes.
    #[test]
    fn the_operator_address_follows_the_network_and_a_seedless_node_says_not_initialized() {
        let dir = tempfile::tempdir().unwrap();
        let paths = WalletPaths {
            seed: dir.path().join("seed.bin"),
            device_key: dir.path().join("device.key"),
            meta: dir.path().join("meta.json"),
        };

        assert_eq!(
            operator_address(&paths, "xch"),
            Err(OperatorAddressUnavailable::NotInitialized),
            "a node that has never been set up is NEW, not broken"
        );

        let wallet = OperatorWallet::from_phrase(PHRASE, agg_sig_data()).unwrap();
        let ph = wallet.owner_puzzle_hash();
        let mainnet = chia_wallet_sdk::utils::Address::new(ph, "xch".to_string())
            .encode()
            .unwrap();
        let testnet = chia_wallet_sdk::utils::Address::new(ph, "txch".to_string())
            .encode()
            .unwrap();
        assert!(mainnet.starts_with("xch1"));
        assert!(testnet.starts_with("txch1"));
        assert_ne!(
            mainnet, testnet,
            "the prefix must reach the encoding, or the network argument is decorative"
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
