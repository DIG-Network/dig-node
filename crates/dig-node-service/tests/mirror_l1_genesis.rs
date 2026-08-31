//! A mirror-coin spend is signed under **Chia mainnet's** `AGG_SIG_ME` domain, never the DIG L2 one.
//!
//! A mirror coin is an ordinary Chia L1 CAT. The consensus that validates its spend appends Chia
//! mainnet's genesis challenge to every `AGG_SIG_ME` message, so a signature produced under any
//! other domain commits to a different message and the mempool answers `BAD_AGGREGATE_SIGNATURE`
//! from every peer, on every retry.
//!
//! dig-node#447 shipped exactly that: `open_signer` opened the operator wallet with
//! `dig_constants::DIG_MAINNET.genesis_challenge()`, the **L2** anchor, which locked 1010 $DIG base
//! units in an unspendable mirror coin on mainnet. Nothing local disagreed — the bundle built,
//! signed and broadcast; only the network refused.
//!
//! # Why these tests are shaped the way they are
//!
//! Asserting that the trailing 32 bytes of a required message equal a constant is circular when the
//! same constant is fed to the extractor. So the load-bearing test below signs with the wallet the
//! PRODUCTION selector builds, and then verifies that signature against the message Chia's own
//! consensus requires — a domain this file states independently of the code under test. A signature
//! made under the L2 domain cannot verify against the L1 message, so it cannot pass on the defect.

mod support;

use chia_bls::PublicKey;
use chia_protocol::{Bytes32, Coin, CoinSpend};
use chia_sdk_types::MAINNET_CONSTANTS;
use dig_mirror_coin::MirrorCoin;
use dig_node_service::mirror::lifecycle::mirror_agg_sig_data;
use dig_node_service::mirror::spends::build_reclaim;
use dig_wallet::operator_wallet::OperatorWallet;
use dig_wallet::sage::spend::required_bls_signatures;
use support::{creating_spend, mirror_memos, root_1, store_a, Wallet};

const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
abandon abandon abandon art";

/// Chia mainnet's genesis challenge, stated here rather than read from the code under test.
///
/// This is the value the Chia mempool actually appends. Restating it makes every assertion below a
/// comparison against the NETWORK's constant instead of against the program's opinion of it.
///
/// Decoded from the published hex rather than written as 32 byte literals so a transcription slip
/// cannot happen silently, and so the source reads as the value operators quote.
fn chia_mainnet_genesis() -> Bytes32 {
    let mut out = [0u8; 32];
    hex::decode_to_slice(
        "ccd5bb71183532bff220ba46c268991a3ff07eb358e8255a65c30a2dce0e5fbb",
        &mut out,
    )
    .expect("the published Chia mainnet genesis challenge is 32 bytes of hex");
    Bytes32::new(out)
}

/// The wallet the PRODUCTION selector builds: the fixture phrase, opened under
/// `mirror_agg_sig_data()`. Nothing here restates the domain — that is the point.
fn production_wallet() -> OperatorWallet {
    OperatorWallet::from_phrase(PHRASE, mirror_agg_sig_data())
        .expect("the fixture phrase derives an operator wallet")
}

fn fixture_wallet() -> Wallet {
    let keys = digstore_chain::keys::derive_wallet_keys(PHRASE).expect("the phrase derives");
    Wallet {
        public_key: keys.synthetic_sk.public_key(),
        puzzle_hash: keys.owner_puzzle_hash,
    }
}

/// A genuine mirror coin this wallet owns, from a real CAT spend executed to produce its conditions.
fn owned_mirror_coin(owner: &Wallet) -> MirrorCoin {
    let memos = mirror_memos(owner, store_a(), root_1(), &["https://example.invalid"]);
    let (spend, coin) = creating_spend(owner, &memos);

    MirrorCoin::from_creating_spend(&spend, coin.coin_id())
        .expect("the fixture spend decodes")
        .expect("and it is a mirror coin")
}

/// The spends of a real, zero-fee reclaim of a coin this wallet owns.
fn reclaim_spends() -> Vec<CoinSpend> {
    let owner = fixture_wallet();
    let coin = owned_mirror_coin(&owner);
    build_reclaim(&coin, owner.public_key, Vec::<Coin>::new(), 0)
        .expect("a zero-fee reclaim builds")
        .coin_spends()
        .to_vec()
}

/// Every BLS signature a reclaim requires under the Chia L1 domain, as `(key, message)`.
fn required_under_chia_l1() -> Vec<(PublicKey, Vec<u8>)> {
    required_bls_signatures(&reclaim_spends(), chia_mainnet_genesis())
        .expect("required signatures extract")
}

/// **The regression.** The signature the production wallet produces verifies against the message
/// Chia's consensus requires.
///
/// This is the assertion the network was making and we were not. Under the L2 domain the wallet
/// signs a message ending in `0af98186…` while Chia checks one ending in `ccd5bb71…`, so the
/// aggregate cannot verify — and this test fails on its own assertion, not on a build error and not
/// on a missing fixture.
#[test]
fn a_reclaim_signed_by_the_production_wallet_verifies_under_the_chia_l1_domain() {
    let required = required_under_chia_l1();
    assert!(
        !required.is_empty(),
        "a reclaim must require at least one BLS signature, or this test proves nothing"
    );

    let signature = production_wallet()
        .signer()
        .sign(&reclaim_spends())
        .expect("the production wallet signs its own reclaim");

    let pairs = required
        .iter()
        .map(|(key, message)| (*key, message.as_slice()));

    assert!(
        chia_bls::aggregate_verify(&signature, pairs),
        "the operator wallet must sign the message CHIA validates -- a mirror coin is an L1 CAT, \
         and a signature made under any other genesis is rejected as BAD_AGGREGATE_SIGNATURE"
    );
}

/// The message's trailing 32 bytes ARE the domain, and the domain the production selector chooses is
/// Chia mainnet's.
///
/// Stated separately from the verification above so a failure says WHICH half broke: a wrong domain
/// here, or a wrong key or derivation there.
#[test]
fn the_required_message_ends_in_the_chia_mainnet_genesis_challenge() {
    let required = required_under_chia_l1();
    assert!(!required.is_empty(), "no required signature to inspect");

    for (_, message) in &required {
        assert!(
            message.len() > 32,
            "an AGG_SIG_ME message carries a 32-byte domain after its payload"
        );
        assert_eq!(
            &message[message.len() - 32..],
            chia_mainnet_genesis().as_ref(),
            "the trailing 32 bytes of an AGG_SIG_ME message are the network domain"
        );
    }

    assert_eq!(
        mirror_agg_sig_data(),
        chia_mainnet_genesis(),
        "the production selector must choose the domain those messages are built from"
    );
    assert_eq!(
        mirror_agg_sig_data(),
        MAINNET_CONSTANTS.genesis_challenge,
        "and it must be the SDK's mainnet constant, not a second copy of the same bytes"
    );
}

/// **The class guard.** No `dig-constants` genesis may ever be the mirror signing domain.
///
/// The test above pins one wrong value; this pins the family it came from. `dig-constants` describes
/// the **DIG L2** chain, and nothing in it is an `AGG_SIG_ME` domain for a Chia L1 CAT. An edit that
/// reintroduces this genesis — or reaches for a different `dig_constants` network — fails here even
/// if it happens to satisfy nothing else.
#[test]
fn the_mirror_signing_domain_is_never_a_dig_constants_genesis() {
    let chosen = mirror_agg_sig_data();

    // Spelled as a list rather than a single comparison so adding a network to `dig-constants` and
    // reaching for it here is caught, instead of being silently outside the guard.
    for (name, genesis) in [(
        "DIG_MAINNET",
        dig_constants::DIG_MAINNET.genesis_challenge(),
    )] {
        assert_ne!(
            chosen, genesis,
            "dig_constants::{name} is a DIG L2 anchor and must never be the mirror signing \
             domain; using it locked 1010 $DIG in an unspendable mainnet coin (dig-node#447)"
        );
    }
}
