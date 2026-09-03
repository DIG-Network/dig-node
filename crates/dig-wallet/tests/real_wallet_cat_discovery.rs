//! Measurement harness for dig-node#380, run against a COPY of the real wallet replica.
//!
//! Not a unit test and not part of the gate: it is `#[ignore]`d and only runs when
//! `DIG_REAL_WALLET` names a copy of a live `wallet.sqlite`. It exists because #380 states its own
//! acceptance bar as a real wallet reporting its real `$DIG` figure, and a green suite does not
//! answer that question.
//!
//! Run with:
//! `DIG_REAL_WALLET=C:\tmp\w390.sqlite cargo test -p dig-wallet --test real_wallet_cat_discovery -- --ignored --nocapture`
//!
//! # The #380/#382 subscription gap is CLOSED -- do not re-derive the trace
//!
//! This harness was written when the node never subscribed to derived CAT puzzle hashes, so a real
//! sync could not populate `cats`/`nfts` and `nfts=0 dids=0` was a meaningless reading. That is no
//! longer true, and the writer chain is production code rather than `#[cfg(test)]` scaffolding:
//!
//! - `sage/service.rs:248` builds the `Attribution` whenever `cfg.enable_chain_sync`, deliberately
//!   NOT gated on the may-spend flag, so a read-only install can still name the `$DIG` it holds.
//! - `sage/sync_supervisor.rs:1513` computes the derived hashes with `DerivedCats::derive(..)`.
//! - `sage/sync.rs:1113` SUBSCRIBES them -- widening the request only; `sync.rs:1094-1105` keeps
//!   them out of the admission set, so an arrival there is staged, never believed.
//! - `sync.rs:792` stages arrivals, `sync.rs:835`/`:853` promotes them once a parent spend proves
//!   lineage, and `singleton.rs:557` / `db.rs:3365` write the attributed row.
//!
//! So `[REPLICA] nfts=0 dids=0` is now a MEANINGFUL measurement, which is what dig-node#396 was
//! filed to make true.

use std::collections::HashSet;

use chia_protocol::{Bytes32, Coin, CoinState};
use dig_wallet::sage::cat_discovery::{promote_staged_cats, stage_from_states, DerivedCats};
use dig_wallet::sage::db::WalletDb;
use dig_wallet::sage::singleton::{LineageAnswer, LineageSource, ParentSpend};

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
    // THE PROPERTY: no coin reaches `coins` at a derived CAT hash without lineage attribution.
    //
    // `at_derived` is REPORTED, never asserted: post-#380/#382 a promoted derived-hash coin is
    // believed by `sync::apply_coin_states` (`sync.rs:774-791`), so both zero and non-zero are
    // legitimate readings depending on what this wallet holds. What is never legitimate is a row
    // sitting there UNATTRIBUTED -- that would mean promotion admitted a coin without a parent
    // spend proving its asset id, which is the guarantee `cat_discovery::promote_staged_cats` and
    // `singleton::attribute_cat_coin` exist to hold. Asserting the count instead of the property
    // is what made the previous version of this test encode the pre-fix world.
    let at_derived: Vec<_> = coins
        .iter()
        .filter_map(|c| {
            derived
                .owner_of(&hex_to_b32(&c.puzzle_hash))
                .map(|owner| (c, owner))
        })
        .collect();
    println!(
        "[REPLICA] rows already at a derived CAT hash = {}",
        at_derived.len()
    );
    for (coin, owner) in &at_derived {
        let expected = hex::encode(owner.asset_id);
        match &coin.asset_id {
            None => panic!(
                "coin {} sits at derived hash {} with NO asset id: promotion admitted an \
                 unattributed coin, so `coins` now asserts an unproven holding",
                coin.coin_id, coin.puzzle_hash
            ),
            Some(actual) => assert_eq!(
                actual.trim_start_matches("0x"),
                expected,
                "coin {} at derived hash {} carries asset id {actual}, but that hash is only \
                 reachable for asset {expected} -- attribution and derivation disagree",
                coin.coin_id,
                coin.puzzle_hash
            ),
        }
    }

    // THE OBSERVABLE THIS ROUND PREDICTS (dig-node#394). The point-read tier stages every row that
    // is not at one of the wallet's OWN p2 hashes, and until this round a staged row that proved to
    // be an NFT or DID singleton was refused terminally. So the figures that matter to a real
    // wallet are: how many of its rows the tier stages at all, and whether its NFT/DID tables
    // survive a pass. `refused > 0` on a wallet holding singletons is the defect, visible here.
    let nfts = db.all_nfts().await.expect("read nfts").len();
    let dids = db.all_dids().await.expect("read dids").len();
    println!("[REPLICA] nfts={nfts} dids={dids}");
    println!(
        "[REPLICA] dig_balance={} xch_balance={}",
        db.balance(Some(&hex::encode(asset))).await.unwrap(),
        db.balance(None).await.unwrap()
    );

    let owned: HashSet<String> = addresses.iter().cloned().collect();
    let (believed, staged) =
        dig_wallet::sage::cat_discovery::route_point_read_rows(&coins, &owned, &derived, |_| false);
    println!(
        "[ROUTE] point-read tier: believed={} staged={}",
        believed.len(),
        staged.len()
    );
    println!(
        "[ROUTE] staged rows are the ones a promotion pass reads a parent spend for; before this \
         round any of them that proved to be an NFT or DID was deleted"
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
    ) -> dig_wallet::sage::Result<LineageAnswer> {
        // A miss is `Unavailable`, NOT `Absent`. This capture holds the parents that were
        // recorded, so a parent missing from it means "this fixture did not capture that spend" --
        // a gap in what could be learned, never a chain fact that no such spend exists. Folding it
        // to `Absent` would let the fixture assert a settled absence it has no evidence for, which
        // is the exact double-side lie `LineageAnswer::from_lookup` exists to make impossible.
        Ok(LineageAnswer::from_lookup(
            self.0.get(parent_coin_id).cloned(),
            LineageAnswer::Unavailable,
        ))
    }
}
