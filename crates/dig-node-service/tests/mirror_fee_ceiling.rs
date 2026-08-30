//! The fee ceiling bounds the ARTIFACT being signed, not a number the caller says about it.
//!
//! `SPEC.md` §25.2 states four bounds on the mirror signing authority and rests the module's whole
//! thesis on their being held by construction. Three of them are structural — the spend shape is a
//! type with no public constructor, the destination is enforced inside `dig-mirror-coin`, the audit
//! record is a required argument. The fee bound is the one that could have been a promise about a
//! parameter, and a promise about a parameter is only as good as the caller.
//!
//! So the test that matters is not "does `sign` refuse a large number" — it is "does `sign` refuse a
//! bundle that PAYS a large fee". Those are the same assertion only when the fee is read from the
//! spends. The fixture below builds a genuine reclaim at 900× the ceiling through the real builder
//! and offers it to the signer, which is exactly the shape a caller reaches for when it wants the
//! spend it already has to be signed.

mod support;

use chia_protocol::{Bytes32, Coin};
use dig_mirror_coin::MirrorCoin;
use dig_node_service::mirror::signer::{MirrorSigner, SignError, MIRROR_SPEND_FEE_CEILING_MOJOS};
use dig_node_service::mirror::spends::build_reclaim;
use dig_node_service::spend_audit::{
    kinds, Asset, Authority, RecordedSpend, SpendIntent, SpendJournal, SpendKind, SpendLog,
};
use support::{creating_spend, mirror_memos, root_1, store_a, wallet, Wallet};

const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
abandon abandon abandon art";

/// 900× the ceiling — chosen from the ceiling itself rather than picked, so the fixture cannot drift
/// under a future retune of `MIRROR_SPEND_FEE_CEILING_MOJOS` into a value that is legal after all.
const RUINOUS_FEE_MOJOS: u64 = MIRROR_SPEND_FEE_CEILING_MOJOS * 900;

/// XCH coins this wallet owns, exactly covering `fee`.
///
/// A non-zero fee needs somewhere to come from: `dig_mirror_coin::reclaim` assembles a fee bundle
/// only when there is a fee to pay, and one built from no coins has nowhere to emit its required
/// concurrency condition. Passing none turned an assertion about the ceiling into a build failure,
/// which is a different test.
fn fee_coins(owner: &Wallet, fee: u64) -> Vec<Coin> {
    if fee == 0 {
        return Vec::new();
    }
    vec![Coin::new(Bytes32::new([0x5E; 32]), owner.puzzle_hash, fee)]
}

fn signer() -> MirrorSigner {
    MirrorSigner::new(
        dig_wallet::operator_wallet::OperatorWallet::from_phrase(PHRASE, Bytes32::from([7u8; 32]))
            .expect("the fixture phrase derives an operator wallet"),
    )
}

fn recorded(journal: &SpendJournal) -> RecordedSpend {
    journal.begin(SpendIntent {
        kind: SpendKind::new(kinds::MIRROR_COIN),
        purpose: "reclaim a mirror coin".to_string(),
        authority: Authority {
            principal: "node".to_string(),
            grant: "mirror-collateral".to_string(),
        },
        asset: Asset::Dig,
        amount_mojos: support::COLLATERAL,
        fee_mojos: 0,
        store_id: Some("store".to_string()),
    })
}

/// A genuine mirror coin this wallet owns, built from a real CAT spend that is executed to produce
/// its conditions.
fn owned_mirror_coin(owner: &Wallet) -> MirrorCoin {
    let memos = mirror_memos(owner, store_a(), root_1(), &["https://example.invalid"]);
    let (spend, coin) = creating_spend(owner, &memos);

    MirrorCoin::from_creating_spend(&spend, coin.coin_id())
        .expect("the fixture spend decodes")
        .expect("and it is a mirror coin")
}

/// A reclaim built at a ruinous fee is refused, however the caller describes it.
///
/// This is the finding, stated as a test. The old signature took the fee as a separate argument, so
/// a caller holding a bundle that pays 0.9 XCH could hand it over alongside a `0` and be signed —
/// the ceiling saw the argument, and the argument was not the thing being signed.
#[test]
fn a_reclaim_built_above_the_ceiling_is_refused_even_though_no_caller_says_so() {
    let owner = wallet(3);
    let coin = owned_mirror_coin(&owner);

    let spends = build_reclaim(
        &coin,
        owner.public_key,
        fee_coins(&owner, RUINOUS_FEE_MOJOS),
        RUINOUS_FEE_MOJOS,
    )
    .expect("a reclaim at any fee builds; refusing it is the signer's job");

    let dir = tempfile::tempdir().expect("tempdir");
    let journal = SpendJournal::new(SpendLog::at(dir.path().join("spend-audit.jsonl")));

    assert_eq!(
        signer().sign(&spends, &recorded(&journal)),
        Err(SignError::FeeAboveCeiling {
            requested_mojos: RUINOUS_FEE_MOJOS,
            ceiling_mojos: MIRROR_SPEND_FEE_CEILING_MOJOS,
        }),
        "the ceiling must read the fee the spends actually pay"
    );
}

/// The control: the same path at a legal fee signs.
///
/// Without this the test above is satisfied by a signer that refuses everything, which would hold
/// the fee bound by making the module useless rather than by making it correct.
#[test]
fn the_same_reclaim_at_a_legal_fee_signs() {
    let owner = wallet(3);
    let coin = owned_mirror_coin(&owner);

    let spends = build_reclaim(
        &coin,
        owner.public_key,
        fee_coins(&owner, MIRROR_SPEND_FEE_CEILING_MOJOS),
        MIRROR_SPEND_FEE_CEILING_MOJOS,
    )
    .expect("builds");

    let dir = tempfile::tempdir().expect("tempdir");
    let journal = SpendJournal::new(SpendLog::at(dir.path().join("spend-audit.jsonl")));

    assert!(
        signer().sign(&spends, &recorded(&journal)).is_ok(),
        "exactly at the ceiling is permitted, so the refusal above is not unconditional"
    );
}

/// A zero-fee reclaim signs — the case §25.4 requires to work when the wallet holds no XCH.
#[test]
fn a_zero_fee_reclaim_signs() {
    let owner = wallet(3);
    let coin = owned_mirror_coin(&owner);
    let spends = build_reclaim(&coin, owner.public_key, fee_coins(&owner, 0), 0).expect("builds");

    let dir = tempfile::tempdir().expect("tempdir");
    let journal = SpendJournal::new(SpendLog::at(dir.path().join("spend-audit.jsonl")));

    assert!(
        signer().sign(&spends, &recorded(&journal)).is_ok(),
        "a wallet with no XCH must still be able to recover what it has locked"
    );
}
