//! Golden byte-vectors for the money path, pinned on the chia line this crate
//! currently builds against.
//!
//! WHY these exist: `dig-wallet` derives addresses, curries puzzle hashes and signs
//! spends through `digstore-chain`, whose types come from `chia-protocol` / `chia-bls`.
//! A chia-line uplift moves every one of those serializers at once, and a drift in any
//! of them is silent -- an address that still parses, a puzzle hash that still curries,
//! a signature that still verifies, all while pointing at different money than before.
//! Pinning the literal bytes here turns that silent drift into a named test failure.
//!
//! These are DERIVATION vectors, not custody: the mnemonic is the public BIP-39
//! all-`abandon` test vector, never a real wallet, and nothing here signs on a user's
//! behalf (CLAUDE.md §908 -- the node signs nothing for the user; this is a local
//! test-only derivation).
//!
//! If a value here changes, that is a COMPATIBILITY BREAK, not a migration detail.

use digstore_chain::cat::cat_puzzle_hash;
use digstore_chain::dig::DIG_ASSET_ID;
use digstore_chain::keys::{derive_indexed_keys, derive_wallet_keys, owner_address};

/// Public BIP-39 test vector. NOT a real wallet, holds nothing, never used for custody.
const ABANDON: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

/// The BLS synthetic public key derived from [`ABANDON`] at the wallet's default index.
const SYNTH_PK: &str = "93c7d36e915aa1570087c9adc427c3a9bb532efe964dcc3bb04a07bc64308dbd82598a1f49f6ca86a82b32559e41380e";
/// The p2-standard owner puzzle hash curried from [`SYNTH_PK`].
const OWNER_PH: &str = "d207c1e11fc3b0cd7472e8c7e53c8d2b81709516346c7baa9fbb9070ffccfe89";
/// The bech32m mainnet receive address encoded from [`OWNER_PH`].
const ADDRESS: &str = "xch16grurcglcwcv6arjarr720yd9wqhp9gkx3k8h25lhwg8pl7vl6ysuax0gy";
/// The DIG CAT asset id (TAIL hash) -- the token this wallet's balances are denominated in.
const DIG_ASSET: &str = "a406d3a9de984d03c9591c10d917593b434d5263cabe2b42f6b367df16832f81";
/// The DIG CAT puzzle hash wrapping [`OWNER_PH`] -- where this wallet's $DIG actually lives.
const DIG_CAT_PH: &str = "1a0fb6b58621fb2fa657b1b0b6c75bd34a7655b463889aad17fe9425b1a9b764";
/// Unhardened derivation path `m/12381/8444/2/{0,1,2}` owner puzzle hashes.
const IDX_PH: [&str; 3] = [
    "d207c1e11fc3b0cd7472e8c7e53c8d2b81709516346c7baa9fbb9070ffccfe89",
    "7ba6cfb69d2cbd960dffed610aef280384d0435a4c9d9e8582430f0df5d4052f",
    "6aaf6665bbde852f20f9b8f0f682624a369a09e4f73ef58faa0c67163a0d14a3",
];
/// An AugScheme signature over [`SIG_MESSAGE`] by the synthetic key.
const SIG: &str = "8acb18df14f234192c7b6d973e173c802869d0464af79e468dc0e831311c883928f4f1efff51123957b0eb0a7d7c6fa115dc5a3fda1d942e9fa354a36ef08cb7931fafc17adcb28d0db2e3882264db6cf39fe3d035c6504493dbd5bbdf9829d7";
const SIG_MESSAGE: &[u8] = b"dig-wallet golden vector";

/// HD derivation + synthetic-key offset must produce the same public key bytes.
///
/// This is the root of every other vector below: if the derived key moves, the address,
/// the puzzle hash and the signature all move with it, and the wallet silently starts
/// watching a different set of coins than the user funded.
#[test]
fn synthetic_public_key_is_byte_identical() {
    let k = derive_wallet_keys(ABANDON).unwrap();
    assert_eq!(hex::encode(k.synthetic_pk.to_bytes()), SYNTH_PK);
}

/// `StandardArgs::curry_tree_hash` must curry to the same p2 puzzle hash.
#[test]
fn owner_puzzle_hash_is_byte_identical() {
    let k = derive_wallet_keys(ABANDON).unwrap();
    assert_eq!(hex::encode(k.owner_puzzle_hash), OWNER_PH);
}

/// bech32m encoding of the receive address must not move.
///
/// This is the value a user copies to receive funds; a drift here sends money to an
/// address the wallet does not control.
#[test]
fn receive_address_is_byte_identical() {
    let k = derive_wallet_keys(ABANDON).unwrap();
    assert_eq!(owner_address(&k), ADDRESS);
}

/// The DIG asset id and the CAT puzzle hash wrapping the owner's p2 hash.
///
/// `cat_puzzle_hash` is what the balance reader scans against, so a drift here reports
/// a zero balance for a wallet that in fact holds $DIG.
#[test]
fn dig_cat_puzzle_hash_is_byte_identical() {
    let k = derive_wallet_keys(ABANDON).unwrap();
    assert_eq!(hex::encode(DIG_ASSET_ID), DIG_ASSET);
    assert_eq!(
        hex::encode(cat_puzzle_hash(k.owner_puzzle_hash, DIG_ASSET_ID)),
        DIG_CAT_PH
    );
}

/// Indexed (unhardened) derivation must stay stable across the whole scanned range,
/// not merely at index 0 -- the wallet scans a window of addresses, and a derivation
/// change that happened to fix index 0 would still lose every other coin.
#[test]
fn indexed_derivation_is_byte_identical() {
    let ks = derive_indexed_keys(ABANDON, 0..3).unwrap();
    let got: Vec<String> = ks
        .iter()
        .map(|k| hex::encode(k.owner_puzzle_hash))
        .collect();
    assert_eq!(got, IDX_PH);
}

/// Index 0 must equal the default derivation -- the two code paths are documented to
/// agree, and a wallet whose scan window disagrees with its own receive address would
/// show funds as missing.
#[test]
fn index_zero_agrees_with_default_derivation() {
    let k = derive_wallet_keys(ABANDON).unwrap();
    let ks = derive_indexed_keys(ABANDON, 0..1).unwrap();
    assert_eq!(ks[0].owner_puzzle_hash, k.owner_puzzle_hash);
}

/// The AugScheme signing path must produce identical signature bytes.
///
/// This pins the one serializer whose drift is unrecoverable: a spend signed under a
/// changed scheme is rejected by the network, or worse, authorizes a different message
/// than the one shown to the user.
#[test]
fn signature_is_byte_identical() {
    let k = derive_wallet_keys(ABANDON).unwrap();
    let sig = digstore_chain::chip0002::sign_message_with(&k.synthetic_sk, SIG_MESSAGE).unwrap();
    assert_eq!(sig, SIG);
}

/// A DIFFERENT message must produce a different signature -- the control that keeps
/// `signature_is_byte_identical` from passing against a constant or empty signature.
#[test]
fn signature_varies_with_the_message() {
    let k = derive_wallet_keys(ABANDON).unwrap();
    let other =
        digstore_chain::chip0002::sign_message_with(&k.synthetic_sk, b"a different message")
            .unwrap();
    assert_ne!(other, SIG);
}
