//! Fixtures shared by the behavioural test binaries.
//!
//! Every mirror coin built here comes from a genuine CAT spend whose puzzle is executed to produce
//! its conditions — the same execution `MirrorCoin::from_creating_spend` performs. A hand-written
//! struct cannot exhibit the properties these tests are about, so none is used.
#![allow(dead_code)]

use chia_bls::{PublicKey, SecretKey};
use chia_protocol::{Bytes, Bytes32, Coin, CoinSpend};
use chia_puzzle_types::{cat::CatArgs, LineageProof, Memos};
use chia_sdk_driver::{
    Cat, CatInfo, CatSpend, P2ParentCoin, SpendContext, SpendWithConditions, StandardLayer,
};
use chia_sdk_types::Conditions;
use clvm_utils::{ToTreeHash, TreeHash};
use dig_mirror_coin::{mirror_hint, DIG_ASSET_ID};
use num_bigint::BigInt;

pub const COLLATERAL: u64 = 1_000_000;

pub fn store_a() -> Bytes32 {
    Bytes32::new([0xA1; 32])
}

pub fn store_b() -> Bytes32 {
    Bytes32::new([0xB2; 32])
}

/// Two roots of the SAME store. A mirror bonds one root, so most fixtures here need a second one to
/// be able to show that bonding the first does not bond the second.
pub fn root_1() -> Bytes32 {
    Bytes32::new([0xC3; 32])
}

pub fn root_2() -> Bytes32 {
    Bytes32::new([0xD4; 32])
}

pub fn epoch() -> BigInt {
    BigInt::from(42)
}

/// The hint `owner`'s advertisement of `store` at `root` lands on, in the current epoch.
pub fn hint_of(owner: &Wallet, store: Bytes32, root: Bytes32) -> Bytes32 {
    mirror_hint(store, root, owner.puzzle_hash, &epoch())
}

/// The hint `owner`'s advertisement of `store` at `root` lands on in an ARBITRARY epoch.
///
/// Separate from [`hint_of`] so a test can build a coin that is honestly published for an epoch
/// other than the current one — which is a different fixture from a coin that lies about its epoch.
pub fn mirror_hint_for(owner: &Wallet, store: Bytes32, root: Bytes32, epoch: &BigInt) -> Bytes32 {
    mirror_hint(store, root, owner.puzzle_hash, epoch)
}

/// A wallet: the key that signs, and the puzzle hash that owns.
pub struct Wallet {
    pub public_key: PublicKey,
    pub puzzle_hash: Bytes32,
}

pub fn wallet(seed: u8) -> Wallet {
    let public_key = SecretKey::from_seed(&[seed; 64]).public_key();
    let puzzle_hash: Bytes32 = StandardLayer::new(public_key).tree_hash().into();
    Wallet {
        public_key,
        puzzle_hash,
    }
}

/// Builds the real CAT spend that creates a mirror coin, and the coin it creates.
///
/// The parent is a $DIG CAT whose lineage proof is internally consistent, so the CAT puzzle runs
/// through to its conditions rather than raising — which is what makes these fixtures able to
/// exercise the authentication path at all.
pub fn creating_spend(owner: &Wallet, memo_entries: &[Bytes]) -> (CoinSpend, Coin) {
    creating_spend_of_asset(owner, memo_entries, DIG_ASSET_ID)
}

/// As [`creating_spend`], but locking `amount` rather than the default collateral.
///
/// The amount is the ONLY thing that distinguishes two coins of the same owner here: the fixture
/// derives its parent deterministically from owner, asset and amount, so two spends built with
/// identical arguments produce a coin with an identical id. A test that needs two genuinely
/// different coins from one wallet must vary this, or the second `publish` silently overwrites the
/// first's creating spend and both records resolve to the same coin.
pub fn creating_spend_of_amount(
    owner: &Wallet,
    memo_entries: &[Bytes],
    amount: u64,
) -> (CoinSpend, Coin) {
    let entries = memo_entries.to_vec();
    let (spend, children) = creating_spend_of_children(owner, DIG_ASSET_ID, amount, |ctx| {
        vec![(amount, Memos::Some(ctx.alloc(&entries).unwrap()))]
    });

    (spend, children[0])
}

/// As [`creating_spend`], but for an arbitrary CAT — so a test can present collateral that is not
/// $DIG and watch it be refused.
pub fn creating_spend_of_asset(
    owner: &Wallet,
    memo_entries: &[Bytes],
    asset_id: Bytes32,
) -> (CoinSpend, Coin) {
    let entries = memo_entries.to_vec();
    let (spend, children) = creating_spend_of_children(owner, asset_id, COLLATERAL, |ctx| {
        vec![(COLLATERAL, Memos::Some(ctx.alloc(&entries).unwrap()))]
    });

    (spend, children[0])
}

/// The general fixture: one real CAT spend that creates any number of coins at the mirror puzzle
/// hash, each with memos of the test's choosing.
///
/// `children` returns one `(amount, memos)` per `CREATE_COIN` the parent emits. The amounts MUST
/// sum to `parent_amount` or the CAT puzzle refuses to run, and the memos are allocated inside the
/// spend's own allocator so a test can shape them freely — including into shapes no honest writer
/// produces, which is the only way to exercise what happens when a stranger writes them.
pub fn creating_spend_of_children(
    owner: &Wallet,
    asset_id: Bytes32,
    parent_amount: u64,
    children: impl FnOnce(&mut SpendContext) -> Vec<(u64, Memos)>,
) -> (CoinSpend, Vec<Coin>) {
    let mut ctx = SpendContext::new();

    let cat_puzzle_hash: Bytes32 =
        CatArgs::curry_tree_hash(asset_id, TreeHash::from(owner.puzzle_hash)).into();
    let grandparent_parent = Bytes32::new([0x99; 32]);
    let grandparent = Coin::new(grandparent_parent, cat_puzzle_hash, parent_amount);
    let parent = Coin::new(grandparent.coin_id(), cat_puzzle_hash, parent_amount);

    let lineage_proof = LineageProof {
        parent_parent_coin_info: grandparent_parent,
        parent_inner_puzzle_hash: owner.puzzle_hash,
        parent_amount,
    };
    let cat = Cat::new(
        parent,
        Some(lineage_proof),
        CatInfo::new(asset_id, None, owner.puzzle_hash),
    );

    let inner_puzzle_hash: Bytes32 = P2ParentCoin::inner_puzzle_hash(Some(asset_id)).into();
    let requested = children(&mut ctx);
    let mut conditions = Conditions::new();
    for (amount, memos) in &requested {
        conditions = conditions.create_coin(inner_puzzle_hash, *amount, *memos);
    }

    let inner_spend = StandardLayer::new(owner.public_key)
        .spend_with_conditions(&mut ctx, conditions)
        .unwrap();
    Cat::spend_all(&mut ctx, &[CatSpend::new(cat, inner_spend)]).unwrap();

    let spend = ctx
        .take()
        .into_iter()
        .find(|spend| spend.coin == parent)
        .expect("the parent CAT spend");
    let outer_puzzle_hash: Bytes32 = P2ParentCoin::puzzle_hash(Some(asset_id)).into();
    let coins = requested
        .iter()
        .map(|(amount, _)| Coin::new(parent.coin_id(), outer_puzzle_hash, *amount))
        .collect();

    (spend, coins)
}

/// Memos for `owner`'s mirror advertising `store` at `root` in the current epoch — the honest
/// `[hint, store, root, epoch, url…]` layout a real `create` emits.
pub fn mirror_memos(owner: &Wallet, store: Bytes32, root: Bytes32, urls: &[&str]) -> Vec<Bytes> {
    declared_memos(hint_of(owner, store, root), store, root, &epoch(), urls)
}

/// Memos with every field chosen independently, so a test can build a coin whose declaration and
/// whose hint disagree — which no honest writer produces and every hostile one might.
pub fn declared_memos(
    hint: Bytes32,
    store: Bytes32,
    root: Bytes32,
    epoch: &BigInt,
    urls: &[&str],
) -> Vec<Bytes> {
    let mut entries = vec![
        Bytes::new(hint.to_vec()),
        Bytes::new(store.to_vec()),
        Bytes::new(root.to_vec()),
        Bytes::new(epoch.to_signed_bytes_be()),
    ];
    entries.extend(urls.iter().map(|url| Bytes::new(url.as_bytes().to_vec())));
    entries
}

/// An ordinary **XCH** spend that pays coins to the mirror puzzle hash.
///
/// This is the fixture that distinguishes a puzzle hash from an asset, and no other helper here can
/// build it. `mirror_coin_puzzle_hash()` is a CAT outer hash, but it is still only 32 bytes: any
/// spend at all may name it in a `CREATE_COIN`, and the resulting records sit in the census's
/// candidate list carrying an `amount` denominated in **mojos**. A screen that compares that number
/// against a threshold in DIG CAT base units is comparing a number to a unit it does not have.
///
/// The coins are minted by ONE spend, which is the shape a real attacker uses and the shape that
/// makes the attack cheap: one transaction, `amounts.len()` records.
pub fn xch_spend_paying_the_mirror_hash(
    owner: &Wallet,
    parent_amount: u64,
    amounts: &[u64],
) -> (CoinSpend, Vec<Coin>) {
    let mut ctx = SpendContext::new();
    let parent = Coin::new(Bytes32::new([0x77; 32]), owner.puzzle_hash, parent_amount);

    let mirror_hash: Bytes32 = P2ParentCoin::puzzle_hash(Some(DIG_ASSET_ID)).into();
    let mut conditions = Conditions::new();
    for amount in amounts {
        conditions = conditions.create_coin(mirror_hash, *amount, Memos::None);
    }

    StandardLayer::new(owner.public_key)
        .spend(&mut ctx, parent, conditions)
        .unwrap();

    let spend = ctx
        .take()
        .into_iter()
        .find(|spend| spend.coin == parent)
        .expect("the parent XCH spend");
    let coins = amounts
        .iter()
        .map(|amount| Coin::new(parent.coin_id(), mirror_hash, *amount))
        .collect();

    (spend, coins)
}
