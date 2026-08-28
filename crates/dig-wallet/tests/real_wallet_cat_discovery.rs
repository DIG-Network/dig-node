//! Measurement harness for dig-node#380, run against a COPY of the real wallet replica.
//!
//! Not a unit test and not part of the gate: it is `#[ignore]`d and only runs when
//! `DIG_REAL_WALLET` names a copy of a live `wallet.sqlite`. It exists because #380 states its own
//! acceptance bar as a real wallet reporting its real `$DIG` figure, and a green suite does not
//! answer that question.
//!
//! Run with:
//! `DIG_REAL_WALLET=C:\tmp\w390.sqlite cargo test -p dig-wallet --test real_wallet_cat_discovery -- --ignored --nocapture`

use std::collections::HashSet;

use chia_protocol::{Bytes32, Coin, CoinState};
use dig_wallet::sage::cat_discovery::{promote_staged_cats, stage_from_states, DerivedCats};
use dig_wallet::sage::db::WalletDb;
use dig_wallet::sage::singleton::{LineageSource, ParentSpend};

/// Where the real replica's addresses live, and what a `$DIG` coin of theirs would sit at.
#[tokio::test]
#[ignore = "requires DIG_REAL_WALLET pointing at a copy of a live wallet.sqlite"]
async fn report_the_real_wallets_dig_discovery_surface() {
    let path = std::env::var("DIG_REAL_WALLET").expect("set DIG_REAL_WALLET");
    let db = WalletDb::open(&path).await.expect("open the replica copy");

    let coins = db.all_coins().await.expect("read coins");
    let addresses: HashSet<String> = coins.iter().map(|c| c.puzzle_hash.clone()).collect();
    let attributed = coins.iter().filter(|c| c.asset_id.is_some()).count();
    println!(
        "[REPLICA] coins={} distinct_puzzle_hashes={} attributed={}",
        coins.len(),
        addresses.len(),
        attributed
    );

    let p2: Vec<Bytes32> = addresses
        .iter()
        .map(|h| {
            let b = hex::decode(h).expect("hex");
            let a: [u8; 32] = b.try_into().expect("32 bytes");
            Bytes32::from(a)
        })
        .collect();
    let asset = digstore_chain::dig::DIG_ASSET_ID;
    let derived = DerivedCats::derive(&p2, &[asset]);
    println!("[DERIVED] dig_asset_id={}", hex::encode(asset));
    for h in derived.hashes() {
        println!(
            "[DERIVED] a $DIG coin of this wallet sits at {}",
            hex::encode(h)
        );
    }
    let at_derived = coins
        .iter()
        .filter(|c| derived.owner_of(&hex_to_b32(&c.puzzle_hash)).is_some())
        .count();
    println!("[REPLICA] rows already at a derived CAT hash = {at_derived}");
    assert_eq!(
        at_derived, 0,
        "before this change the replica holds NO row at the derived hash -- that is #380"
    );
}

fn hex_to_b32(h: &str) -> Bytes32 {
    let b = hex::decode(h).expect("hex");
    let a: [u8; 32] = b.try_into().expect("32 bytes");
    Bytes32::from(a)
}

/// The end-to-end pass: real replica, real chain-sourced coins at the derived hash, real parent
/// spends, and the `$DIG` balance the wallet reports afterwards.
///
/// The coins and their parent spends are supplied through `DIG_REAL_COINS` /
/// `DIG_REAL_PARENTS` as JSON captured from the chain, so the harness performs no network I/O of
/// its own and the capture is auditable separately from the code it exercises.
#[tokio::test]
#[ignore = "requires DIG_REAL_WALLET plus a captured chain snapshot"]
async fn the_real_wallet_reports_its_real_dig_balance() {
    let path = std::env::var("DIG_REAL_WALLET").expect("set DIG_REAL_WALLET");
    let coins_json = std::env::var("DIG_REAL_COINS").expect("set DIG_REAL_COINS");
    let parents_json = std::env::var("DIG_REAL_PARENTS").expect("set DIG_REAL_PARENTS");
    let db = WalletDb::open(&path).await.expect("open the replica copy");

    let existing = db.all_coins().await.unwrap();
    let p2: Vec<Bytes32> = existing
        .iter()
        .map(|c| hex_to_b32(&c.puzzle_hash))
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    let asset = digstore_chain::dig::DIG_ASSET_ID;
    let derived = DerivedCats::derive(&p2, &[asset]);
    let asset_hex = hex::encode(asset);

    println!(
        "[BEFORE] dig_balance={}",
        db.balance(Some(&asset_hex)).await.unwrap()
    );

    let states: Vec<CoinState> = serde_json::from_str::<Vec<CapturedCoin>>(
        &std::fs::read_to_string(&coins_json).expect("read coins capture"),
    )
    .expect("parse coins capture")
    .into_iter()
    .map(CapturedCoin::into_state)
    .collect();
    println!(
        "[CHAIN] coins captured at the derived hash = {}",
        states.len()
    );

    let rows = stage_from_states(&states, &derived, |_| false);
    println!("[STAGE] staged = {}", rows.len());
    db.stage_cat_admissions(&rows).await.unwrap();

    let lineage = CapturedLineage::load(&parents_json);
    let stats = promote_staged_cats(&db, &lineage, &std::collections::HashSet::new())
        .await
        .unwrap();
    println!("[PROMOTE] {stats:?}");

    let balance = db.balance(Some(&asset_hex)).await.unwrap();
    println!("[AFTER] dig_balance={balance}");
    println!("[AFTER] xch_balance={}", db.balance(None).await.unwrap());
}

#[derive(serde::Deserialize)]
struct CapturedCoin {
    parent_coin_info: String,
    puzzle_hash: String,
    amount: u64,
    confirmed_block_index: u32,
    spent_block_index: u32,
}

impl CapturedCoin {
    fn into_state(self) -> CoinState {
        CoinState {
            coin: Coin {
                parent_coin_info: hex_to_b32(self.parent_coin_info.trim_start_matches("0x")),
                puzzle_hash: hex_to_b32(self.puzzle_hash.trim_start_matches("0x")),
                amount: self.amount,
            },
            created_height: Some(self.confirmed_block_index),
            spent_height: (self.spent_block_index != 0).then_some(self.spent_block_index),
        }
    }
}

#[derive(serde::Deserialize)]
struct CapturedParent {
    coin_parent: String,
    coin_puzzle_hash: String,
    coin_amount: u64,
    puzzle_reveal: String,
    solution: String,
}

struct CapturedLineage(std::collections::HashMap<String, ParentSpend>);

impl CapturedLineage {
    fn load(path: &str) -> Self {
        let captured: Vec<CapturedParent> =
            serde_json::from_str(&std::fs::read_to_string(path).expect("read parents capture"))
                .expect("parse parents capture");
        let mut map = std::collections::HashMap::new();
        for c in captured {
            let coin = Coin {
                parent_coin_info: hex_to_b32(c.coin_parent.trim_start_matches("0x")),
                puzzle_hash: hex_to_b32(c.coin_puzzle_hash.trim_start_matches("0x")),
                amount: c.coin_amount,
            };
            map.insert(
                hex::encode(coin.coin_id()),
                ParentSpend {
                    coin,
                    puzzle_reveal: hex::decode(c.puzzle_reveal.trim_start_matches("0x"))
                        .expect("puzzle hex"),
                    solution: hex::decode(c.solution.trim_start_matches("0x")).expect("sol hex"),
                },
            );
        }
        Self(map)
    }
}

#[async_trait::async_trait]
impl LineageSource for CapturedLineage {
    async fn parent_spend(
        &self,
        parent_coin_id: &str,
        _spent_height: u32,
    ) -> dig_wallet::sage::Result<Option<ParentSpend>> {
        Ok(self.0.get(parent_coin_id).cloned())
    }
}
