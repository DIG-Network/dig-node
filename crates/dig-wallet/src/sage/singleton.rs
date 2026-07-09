//! NFT / DID / CAT singleton reconstruction from synced coin state (design **B.6**, #216).
//!
//! The direct-peer sync ([`crate::sage::sync`]) records every coin at the wallet's puzzle
//! hashes, but a raw [`chia::protocol::CoinState`] does not say whether a coin is an NFT, a
//! DID, or a CAT — that lives in the coin's *puzzle*, which is only revealed when its parent
//! is spent. This module reconstructs those assets by **uncurrying the parent coin's spend**
//! via the canonical `chia-wallet-sdk` driver parsers ([`Nft::parse_child`],
//! [`Did::parse_child`], [`Cat::parse_children`]) — never hand-rolling CLVM (SYSTEM.md §4.1).
//!
//! Split into a **pure core** ([`reconstruct_parsed`] / [`reconstruct`]) that is exercised
//! mainnet-safely against `chia-sdk-test::Simulator`-built spends, and an **async
//! orchestrator** ([`reconstruct_coins`]) that fetches parent spends through a
//! [`LineageSource`] and writes the resolved rows into the wallet DB. Reconstruction reads
//! only; it never signs or broadcasts.

use std::collections::HashSet;

use async_trait::async_trait;
use chia::puzzles::nft::NftMetadata;
use chia_protocol::{Bytes32, Coin, Program};
use chia_wallet_sdk::driver::{Cat, Did, Nft, Puzzle, SpendContext};
use chia_wallet_sdk::utils::Address;
use clvmr::NodePtr;

use super::db::{CoinRow, DidDbRow, NftDbRow, WalletDb};
use super::types::{Amount, DidRecord, NftRecord};
use super::{Error, Result};

/// A parent coin's spend — the raw material singleton/CAT reconstruction needs. Puzzle and
/// solution are the **serialized CLVM** bytes (as `chia-query`/`request_puzzle_and_solution`
/// return them, hex-decoded).
#[derive(Debug, Clone)]
pub struct ParentSpend {
    /// The parent coin (parent id + puzzle hash + amount).
    pub coin: Coin,
    /// The serialized CLVM puzzle reveal of the parent's spend.
    pub puzzle_reveal: Vec<u8>,
    /// The serialized CLVM solution of the parent's spend.
    pub solution: Vec<u8>,
}

/// The outcome of reconstructing one coin from its parent spend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reconstructed {
    /// The coin is an NFT singleton.
    Nft(Box<NftDbRow>),
    /// The coin is a DID singleton.
    Did(Box<DidDbRow>),
    /// The coin is a CAT — attribute it to this asset id (+ inner p2 hint).
    Cat {
        /// The child coin id (hex).
        coin_id: String,
        /// The CAT asset id / TAIL hash (hex).
        asset_id: String,
        /// The inner p2 puzzle hash (hex) the CAT is hinted to.
        hint: String,
    },
    /// The coin is not a recognized NFT/DID/CAT (e.g. a plain XCH coin) — leave as-is.
    Unknown,
}

/// How many of each asset kind a reconstruction pass resolved.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReconstructStats {
    /// NFTs written.
    pub nfts: u32,
    /// DIDs written.
    pub dids: u32,
    /// CAT coins attributed.
    pub cats: u32,
}

/// Fetches the parent coin's spend for a coin being reconstructed. The production path reads
/// through the `chia-query`/coinset fallback (an out-of-DB lineage read, design B.5); the
/// direct-peer `request_puzzle_and_solution` is an equivalent implementation.
#[async_trait]
pub trait LineageSource: Send + Sync {
    /// The spend of `parent_coin_id`, which was spent at `spent_height` (= the child's
    /// created height). `None` if the parent spend is not available.
    async fn parent_spend(
        &self,
        parent_coin_id: &str,
        spent_height: u32,
    ) -> Result<Option<ParentSpend>>;
}

fn hexb(b: Bytes32) -> String {
    hex::encode(b)
}

fn encode_addr(puzzle_hash: Bytes32, prefix: &str) -> String {
    Address::new(puzzle_hash, prefix.to_string())
        .encode()
        .unwrap_or_else(|_| hexb(puzzle_hash))
}

fn bytes32_from_hex(s: &str) -> Result<Bytes32> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let v = hex::decode(s).map_err(|e| Error::internal(format!("bad hex: {e}")))?;
    let arr: [u8; 32] = v
        .try_into()
        .map_err(|_| Error::internal("expected 32-byte hex"))?;
    Ok(arr.into())
}

/// Build a `chia_protocol::Coin` from a stored wallet [`CoinRow`].
fn coin_from_row(c: &CoinRow) -> Result<Coin> {
    Ok(Coin {
        parent_coin_info: bytes32_from_hex(&c.parent_coin_info)?,
        puzzle_hash: bytes32_from_hex(&c.puzzle_hash)?,
        amount: c.amount.parse::<u64>().unwrap_or(0),
    })
}

/// Reconstruct a coin from an already-allocated parent puzzle + solution (the pure core).
///
/// Tries the NFT, DID, then CAT driver parsers in turn; the first whose child matches
/// `child` wins. A parser that does not recognize the parent returns `None` (not an error),
/// and any driver parse *error* is treated as "not this kind" so one odd coin never aborts a
/// whole sync pass.
pub fn reconstruct_parsed(
    ctx: &mut SpendContext,
    prefix: &str,
    created_height: Option<u32>,
    parent_coin: Coin,
    parent_puzzle: Puzzle,
    parent_solution: NodePtr,
    child: Coin,
) -> Reconstructed {
    let child_id = child.coin_id();

    // NFT: parse_child computes the single child singleton coin itself.
    if let Ok(Some(nft)) = Nft::parse_child(ctx, parent_coin, parent_puzzle, parent_solution) {
        if nft.coin.coin_id() == child_id {
            return Reconstructed::Nft(Box::new(nft_row(ctx, prefix, created_height, &nft)));
        }
    }

    // DID: parse_child validates the given child coin.
    if let Ok(Some(did)) =
        Did::parse_child(ctx, parent_coin, parent_puzzle, parent_solution, child)
    {
        return Reconstructed::Did(Box::new(did_row(prefix, created_height, &did)));
    }

    // CAT: parse_children returns every child; match ours by coin id.
    if let Ok(Some(children)) =
        Cat::parse_children(ctx, parent_coin, parent_puzzle, parent_solution)
    {
        if let Some(cat) = children.iter().find(|c| c.coin.coin_id() == child_id) {
            return Reconstructed::Cat {
                coin_id: hexb(child_id),
                asset_id: hexb(cat.info.asset_id),
                hint: hexb(cat.info.p2_puzzle_hash),
            };
        }
    }

    Reconstructed::Unknown
}

/// Reconstruct a coin from a [`ParentSpend`] (allocates the serialized puzzle/solution, then
/// delegates to [`reconstruct_parsed`]).
pub fn reconstruct(
    prefix: &str,
    created_height: Option<u32>,
    parent: &ParentSpend,
    child: Coin,
) -> Result<Reconstructed> {
    let mut ctx = SpendContext::new();
    let puzzle_ptr = ctx
        .alloc(&Program::from(parent.puzzle_reveal.clone()))
        .map_err(|e| Error::internal(format!("alloc parent puzzle: {e}")))?;
    let parent_puzzle = Puzzle::parse(&ctx, puzzle_ptr);
    let solution_ptr = ctx
        .alloc(&Program::from(parent.solution.clone()))
        .map_err(|e| Error::internal(format!("alloc parent solution: {e}")))?;
    Ok(reconstruct_parsed(
        &mut ctx,
        prefix,
        created_height,
        parent.coin,
        parent_puzzle,
        solution_ptr,
        child,
    ))
}

fn nft_row(
    ctx: &mut SpendContext,
    prefix: &str,
    created_height: Option<u32>,
    nft: &Nft,
) -> NftDbRow {
    let info = &nft.info;
    let meta = ctx.extract::<NftMetadata>(info.metadata.ptr()).ok();
    let (
        data_uris,
        data_hash,
        metadata_uris,
        metadata_hash,
        license_uris,
        license_hash,
        edition_number,
        edition_total,
    ) = match &meta {
        Some(m) => (
            m.data_uris.clone(),
            m.data_hash.map(hexb),
            m.metadata_uris.clone(),
            m.metadata_hash.map(hexb),
            m.license_uris.clone(),
            m.license_hash.map(hexb),
            Some(m.edition_number as u32),
            Some(m.edition_total as u32),
        ),
        None => (
            Vec::new(),
            None,
            Vec::new(),
            None,
            Vec::new(),
            None,
            None,
            None,
        ),
    };

    let record = NftRecord {
        launcher_id: hexb(info.launcher_id),
        collection_id: None,
        collection_name: None,
        // The minting DID requires tracing the launcher's eve spend; the current owner is
        // available directly. Minter resolution is a follow-on (off-chain metadata).
        minter_did: None,
        owner_did: info.current_owner.map(hexb),
        visible: true,
        sensitive_content: false,
        name: None,
        created_height,
        coin_id: hexb(nft.coin.coin_id()),
        address: encode_addr(info.p2_puzzle_hash, prefix),
        royalty_address: encode_addr(info.royalty_puzzle_hash, prefix),
        // basis points (300 = 3%) are already in ten-thousandths.
        royalty_ten_thousandths: info.royalty_basis_points,
        data_uris,
        data_hash,
        metadata_uris,
        metadata_hash,
        license_uris,
        license_hash,
        edition_number,
        edition_total,
        icon_url: None,
        created_timestamp: None,
        special_use_type: None,
    };

    NftDbRow {
        launcher_id: record.launcher_id.clone(),
        coin_id: record.coin_id.clone(),
        collection_id: record.collection_id.clone(),
        minter_did: record.minter_did.clone(),
        owner_did: record.owner_did.clone(),
        name: record.name.clone(),
        visible: record.visible,
        created_height: created_height.map(i64::from),
        record_json: serde_json::to_string(&record).unwrap_or_default(),
    }
}

fn did_row(prefix: &str, created_height: Option<u32>, did: &Did) -> DidDbRow {
    let info = &did.info;
    let record = DidRecord {
        launcher_id: hexb(info.launcher_id),
        name: None,
        visible: true,
        coin_id: hexb(did.coin.coin_id()),
        address: encode_addr(info.p2_puzzle_hash, prefix),
        amount: Amount::u64(did.coin.amount),
        recovery_hash: info.recovery_list_hash.map(hexb),
        created_height,
    };
    DidDbRow {
        launcher_id: record.launcher_id.clone(),
        coin_id: record.coin_id.clone(),
        name: None,
        visible: true,
        created_height: created_height.map(i64::from),
        record_json: serde_json::to_string(&record).unwrap_or_default(),
    }
}

/// Whether a synced coin is a reconstruction candidate: a singleton has an **odd** amount,
/// and a CAT coin sits at a puzzle hash that is NOT one of the wallet's plain p2 hashes (it
/// is hinted to us instead). Plain XCH coins are skipped so a sync pass does not fetch a
/// parent spend for every ordinary coin.
fn is_candidate(c: &CoinRow, plain_puzzle_hashes: &HashSet<String>) -> bool {
    let amount: u64 = c.amount.parse().unwrap_or(0);
    amount % 2 == 1 || !plain_puzzle_hashes.contains(&c.puzzle_hash.to_ascii_lowercase())
}

/// Reconstruct + persist the NFT/DID/CAT assets among `coins` (the async orchestrator).
///
/// For each **unspent** candidate coin, fetch its parent spend through `lineage`, reconstruct
/// it, and write the result: NFT/DID rows are upserted; a CAT coin is attributed to its asset
/// id in the `coins` table (so `get_cats`/`get_token` become complete). Coins whose parent
/// spend is unavailable, or that are not NFT/DID/CAT, are skipped.
pub async fn reconstruct_coins(
    db: &WalletDb,
    lineage: &dyn LineageSource,
    prefix: &str,
    plain_puzzle_hashes: &HashSet<String>,
    coins: &[CoinRow],
) -> Result<ReconstructStats> {
    let mut stats = ReconstructStats::default();
    for c in coins {
        let Some(created) = c.created_height else {
            continue;
        };
        if c.spent_height.is_some() || c.asset_id.is_some() {
            continue; // already spent, or already attributed
        }
        if !is_candidate(c, plain_puzzle_hashes) {
            continue;
        }
        let Some(parent) = lineage.parent_spend(&c.parent_coin_info, created as u32).await? else {
            continue;
        };
        let child = coin_from_row(c)?;
        match reconstruct(prefix, Some(created as u32), &parent, child)? {
            Reconstructed::Nft(row) => {
                db.upsert_nft(&row).await?;
                stats.nfts += 1;
            }
            Reconstructed::Did(row) => {
                db.upsert_did(&row).await?;
                stats.dids += 1;
            }
            Reconstructed::Cat {
                coin_id,
                asset_id,
                hint,
            } => {
                db.attribute_cat_coin(&coin_id, &asset_id, Some(&hint)).await?;
                stats.cats += 1;
            }
            Reconstructed::Unknown => {}
        }
    }
    Ok(stats)
}

/// Convenience: reconstruct every coin currently in the wallet DB.
pub async fn reconstruct_all(
    db: &WalletDb,
    lineage: &dyn LineageSource,
    prefix: &str,
    plain_puzzle_hashes: &HashSet<String>,
) -> Result<ReconstructStats> {
    let coins = db.all_coins().await?;
    reconstruct_coins(db, lineage, prefix, plain_puzzle_hashes, &coins).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia::traits::Streamable;
    use chia_wallet_sdk::driver::{
        Cat as SdkCat, CatSpend, IntermediateLauncher, Launcher, NftMint, SingletonInfo,
        SpendWithConditions, StandardLayer,
    };
    use chia_wallet_sdk::types::conditions::TransferNft;
    use chia_wallet_sdk::types::Conditions;
    use chia_sdk_test::Simulator;
    use std::collections::HashMap;

    /// A [`LineageSource`] backed by an in-memory map of `parent_coin_id -> ParentSpend`,
    /// populated from a `Simulator` in tests.
    #[derive(Default)]
    struct MockLineage {
        by_parent: HashMap<String, ParentSpend>,
    }

    #[async_trait]
    impl LineageSource for MockLineage {
        async fn parent_spend(
            &self,
            parent_coin_id: &str,
            _spent_height: u32,
        ) -> Result<Option<ParentSpend>> {
            Ok(self.by_parent.get(parent_coin_id).cloned())
        }
    }

    /// Extract a `ParentSpend` (raw serialized puzzle + solution) for `parent_coin` from the
    /// simulator after its spend has been committed.
    fn parent_spend_from_sim(sim: &Simulator, parent_coin: Coin) -> ParentSpend {
        let puzzle = sim
            .puzzle_reveal(parent_coin.coin_id())
            .expect("parent puzzle reveal");
        let solution = sim
            .solution(parent_coin.coin_id())
            .expect("parent solution");
        ParentSpend {
            coin: parent_coin,
            puzzle_reveal: puzzle.to_bytes().unwrap(),
            solution: solution.to_bytes().unwrap(),
        }
    }

    fn coin_row(c: Coin, height: i64) -> CoinRow {
        CoinRow {
            coin_id: hex::encode(c.coin_id()),
            parent_coin_info: hex::encode(c.parent_coin_info),
            puzzle_hash: hex::encode(c.puzzle_hash),
            amount: c.amount.to_string(),
            created_height: Some(height),
            spent_height: None,
            asset_id: None,
            hint: None,
            created_timestamp: None,
            spent_timestamp: None,
        }
    }

    /// Mint a DID + an NFT on the simulator, transfer both to self, and return the parent
    /// spends + the child coins a syncing wallet would observe.
    #[allow(clippy::type_complexity)]
    fn mint_did_and_nft() -> (Simulator, ParentSpend, Coin, ParentSpend, Coin, Bytes32, Bytes32)
    {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();
        let alice = sim.bls(2);
        let alice_p2 = StandardLayer::new(alice.pk);

        // Create a DID.
        let (create_did, did) = Launcher::new(alice.coin.coin_id(), 1)
            .create_simple_did(ctx, &alice_p2)
            .unwrap();
        alice_p2.spend(ctx, alice.coin, create_did).unwrap();

        // Mint an NFT owned by the DID.
        let mut metadata = NftMetadata::default();
        metadata.data_uris.push("https://example.com/a.png".to_string());
        metadata.data_hash = Some(Bytes32::new([7; 32]));
        let metadata = ctx.alloc_hashed(&metadata).unwrap();
        let (mint_nft, nft) = IntermediateLauncher::new(did.coin.coin_id(), 0, 1)
            .create(ctx)
            .unwrap()
            .mint_nft(
                ctx,
                &NftMint::new(
                    metadata,
                    alice.puzzle_hash,
                    300,
                    Some(TransferNft::new(
                        Some(did.info.launcher_id),
                        Vec::new(),
                        Some(did.info.inner_puzzle_hash().into()),
                    )),
                ),
            )
            .unwrap();
        let did = did.update(ctx, &alice_p2, mint_nft).unwrap();
        sim.spend_coins(ctx.take(), &[alice.sk.clone()]).unwrap();

        // Transfer both singletons to self, producing the children a wallet syncs.
        let child_did = did.transfer(ctx, &alice_p2, alice.puzzle_hash, Conditions::new()).unwrap();
        let child_nft = nft
            .transfer(ctx, &alice_p2, alice.puzzle_hash, Conditions::new())
            .unwrap();
        sim.spend_coins(ctx.take(), &[alice.sk]).unwrap();

        let did_parent = parent_spend_from_sim(&sim, did.coin);
        let nft_parent = parent_spend_from_sim(&sim, nft.coin);
        (
            sim,
            did_parent,
            child_did.coin,
            nft_parent,
            child_nft.coin,
            did.info.launcher_id,
            nft.info.launcher_id,
        )
    }

    #[test]
    fn reconstruct_parses_nft_and_did_from_parent_spends() {
        let (_sim, did_parent, did_child, nft_parent, nft_child, did_launcher, nft_launcher) =
            mint_did_and_nft();

        match reconstruct("xch", Some(42), &nft_parent, nft_child).unwrap() {
            Reconstructed::Nft(row) => {
                assert_eq!(row.launcher_id, hex::encode(nft_launcher));
                let rec: NftRecord = serde_json::from_str(&row.record_json).unwrap();
                assert_eq!(rec.royalty_ten_thousandths, 300);
                assert_eq!(rec.data_uris, vec!["https://example.com/a.png".to_string()]);
                assert_eq!(rec.data_hash.as_deref(), Some(&hex::encode([7u8; 32])[..]));
                assert!(rec.address.starts_with("xch1"));
            }
            other => panic!("expected NFT, got {other:?}"),
        }

        match reconstruct("xch", Some(7), &did_parent, did_child).unwrap() {
            Reconstructed::Did(row) => {
                assert_eq!(row.launcher_id, hex::encode(did_launcher));
                let rec: DidRecord = serde_json::from_str(&row.record_json).unwrap();
                assert!(rec.address.starts_with("xch1"));
            }
            other => panic!("expected DID, got {other:?}"),
        }
    }

    #[test]
    fn reconstruct_attributes_cat_asset_id() {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();
        // Fund alice with 1000 mojos so she can issue a 1000-unit CAT.
        let alice = sim.bls(1000);
        let alice_p2 = StandardLayer::new(alice.pk);

        // Issue a CAT to alice, then spend it to produce a child CAT (its parent is now a
        // CAT coin, which is what parse_children reconstructs from).
        let memos = ctx.hint(alice.puzzle_hash).unwrap();
        let (issue_cat, cats) = SdkCat::issue_with_coin(
            ctx,
            alice.coin.coin_id(),
            1000,
            Conditions::new().create_coin(alice.puzzle_hash, 1000, memos),
        )
        .unwrap();
        alice_p2.spend(ctx, alice.coin, issue_cat).unwrap();
        sim.spend_coins(ctx.take(), &[alice.sk.clone()]).unwrap();
        let cat0 = cats[0];

        let inner = alice_p2
            .spend_with_conditions(
                ctx,
                Conditions::new().create_coin(alice.puzzle_hash, 1000, memos),
            )
            .unwrap();
        SdkCat::spend_all(ctx, &[CatSpend::new(cat0, inner)]).unwrap();
        sim.spend_coins(ctx.take(), &[alice.sk]).unwrap();

        let child_cat = cat0.child(alice.puzzle_hash, 1000);
        let parent = parent_spend_from_sim(&sim, cat0.coin);

        match reconstruct("xch", Some(5), &parent, child_cat.coin).unwrap() {
            Reconstructed::Cat { asset_id, .. } => {
                assert_eq!(asset_id, hex::encode(cat0.info.asset_id));
            }
            other => panic!("expected CAT, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn reconstruct_coins_populates_db_and_get_reads() {
        let (_sim, did_parent, did_child, nft_parent, nft_child, _dl, _nl) = mint_did_and_nft();

        let db = WalletDb::open_in_memory().await.unwrap();
        // The wallet has synced the two child singleton coins (odd amount = 1).
        db.upsert_coin(&coin_row(nft_child, 100)).await.unwrap();
        db.upsert_coin(&coin_row(did_child, 100)).await.unwrap();

        let mut lineage = MockLineage::default();
        lineage
            .by_parent
            .insert(hex::encode(nft_child.parent_coin_info), nft_parent);
        lineage
            .by_parent
            .insert(hex::encode(did_child.parent_coin_info), did_parent);

        let stats =
            reconstruct_coins(&db, &lineage, "xch", &HashSet::new(), &db.all_coins().await.unwrap())
                .await
                .unwrap();
        assert_eq!(stats.nfts, 1, "one NFT reconstructed");
        assert_eq!(stats.dids, 1, "one DID reconstructed");
        assert_eq!(db.all_nfts().await.unwrap().len(), 1);
        assert_eq!(db.all_dids().await.unwrap().len(), 1);
    }

    #[test]
    fn plain_xch_coin_is_not_a_candidate() {
        let mut phs = HashSet::new();
        phs.insert("aa".repeat(32));
        let c = CoinRow {
            coin_id: "c".into(),
            parent_coin_info: "pp".into(),
            puzzle_hash: "aa".repeat(32),
            amount: "1000000".into(), // even, at a known plain p2 hash
            created_height: Some(1),
            spent_height: None,
            asset_id: None,
            hint: None,
            created_timestamp: None,
            spent_timestamp: None,
        };
        assert!(!is_candidate(&c, &phs));
        // An odd amount flips it to a singleton candidate.
        let mut odd = c.clone();
        odd.amount = "1".into();
        assert!(is_candidate(&odd, &phs));
    }
}
