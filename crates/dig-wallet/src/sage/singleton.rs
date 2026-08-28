//! NFT / DID / CAT singleton reconstruction from synced coin state (design **B.6**, #216).
//!
//! The direct-peer sync ([`crate::sage::sync`]) records every coin at the wallet's puzzle
//! hashes, but a raw [`chia_protocol::CoinState`] does not say whether a coin is an NFT, a
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
use chia_protocol::{Bytes32, Coin, Program};
use chia_puzzle_types::nft::NftMetadata;
use chia_wallet_sdk::driver::{Cat, Did, Nft, Puzzle, SingletonInfo, SpendContext};
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
    ///
    /// `owner_p2` is the inner p2 puzzle hash the singleton is currently owned by, carried
    /// alongside the row for the same reason [`Reconstructed::Cat`] carries `hint`: the row alone
    /// says WHAT the coin is, and an admission decision additionally needs to know WHOSE it is.
    Nft {
        /// The NFT as it will be stored.
        row: Box<NftDbRow>,
        /// The inner p2 puzzle hash (hex) that owns the singleton.
        owner_p2: String,
    },
    /// The coin is a DID singleton (the DID twin of [`Reconstructed::Nft`]).
    Did {
        /// The DID as it will be stored.
        row: Box<DidDbRow>,
        /// The inner p2 puzzle hash (hex) that owns the singleton.
        owner_p2: String,
    },
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
    /// Rows this pass RESOLVED and will never read again, whatever they turned out to be.
    pub settled: u32,
    /// Rows whose parent could not be read at all, so nothing was learned and nothing marked.
    pub unresolved: u32,
}

/// What a lineage source has to say about a parent coin's spend.
///
/// The two negative answers are deliberately NOT one variant. They differ in the only way that
/// matters to a caller deciding what to do next:
///
/// * [`LineageAnswer::Absent`] is a FACT about the chain — it was asked and the spend is not
///   there. Remembering it is sound, because asking again immediately gets the same answer.
/// * [`LineageAnswer::Unavailable`] is a fact about THIS NODE — no source could be reached.
///   Nothing was learned about the chain at all.
///
/// Collapsing them is how an outage becomes a money-lie: a wallet that caches "we could not reach
/// anyone" as "it does not exist" spends the cache's lifetime confidently refusing to name coins
/// it owns. Every consumer here therefore treats `Unavailable` as *unknown* — never as a negative
/// result, and never as grounds to declare a replica complete.
#[derive(Debug, Clone)]
pub enum LineageAnswer {
    /// The parent spend, as read.
    Found(Box<ParentSpend>),
    /// A source answered, and there is no such spend at that height.
    Absent,
    /// No source could answer. Nothing is known either way.
    Unavailable,
}

impl LineageAnswer {
    /// The spend if one was found. Discards the [`Absent`](LineageAnswer::Absent) /
    /// [`Unavailable`](LineageAnswer::Unavailable) distinction, so it belongs only in callers
    /// that genuinely treat the two alike.
    pub fn found(self) -> Option<ParentSpend> {
        match self {
            Self::Found(spend) => Some(*spend),
            _ => None,
        }
    }

    /// The answer for a spend that was found, or `on_miss` when it was not.
    ///
    /// # Why the miss answer must be passed in
    ///
    /// This replaces a `from_answered(Option<ParentSpend>)` helper that folded every miss to
    /// [`Self::Absent`]. Nothing in production ever called it — but it was the constructor every
    /// test double reached for, so **every** double in this crate modelled an unresolvable parent
    /// as a settled absence while the production source modelled it as unreadable. The suite was
    /// therefore structurally unable to reach production's unreadable-parent path by the ordinary
    /// route, which is how dig-node#383 survived a review round hunting exactly that class.
    ///
    /// A fixture map cannot know which of the two a miss represents, so it has to say. Making the
    /// caller name it is the whole point: a double that cannot express production's failure mode
    /// makes every test over it a partial green.
    pub fn from_lookup(spend: Option<ParentSpend>, on_miss: Self) -> Self {
        spend.map_or(on_miss, |s| Self::Found(Box::new(s)))
    }
}

/// Fetches the parent coin's spend for a coin being reconstructed. The production path reads
/// through the `chia-query`/coinset fallback (an out-of-DB lineage read, design B.5); the
/// direct-peer `request_puzzle_and_solution` is an equivalent implementation.
#[async_trait]
pub trait LineageSource: Send + Sync {
    /// The spend of `parent_coin_id`, which was spent at `spent_height` (= the child's
    /// created height).
    ///
    /// `Err` is reserved for a caller-fatal fault. An unreadable parent is
    /// [`LineageAnswer::Unavailable`], not an error: an error here escapes
    /// [`reconstruct_coins`] and ends the peer session, handing a denial of service to whoever
    /// made the read fail.
    async fn parent_spend(&self, parent_coin_id: &str, spent_height: u32) -> Result<LineageAnswer>;
}

fn hexb(b: Bytes32) -> String {
    hex::encode(b)
}

fn encode_addr(puzzle_hash: Bytes32, prefix: &str) -> String {
    Address::new(puzzle_hash, prefix.to_string())
        .encode()
        .unwrap_or_else(|_| hexb(puzzle_hash))
}

pub(crate) fn bytes32_from_hex(s: &str) -> Result<Bytes32> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let v = hex::decode(s).map_err(|e| Error::internal(format!("bad hex: {e}")))?;
    let arr: [u8; 32] = v
        .try_into()
        .map_err(|_| Error::internal("expected 32-byte hex"))?;
    Ok(arr.into())
}

/// Build a `chia_protocol::Coin` from a stored wallet [`CoinRow`].
pub(crate) fn coin_from_row(c: &CoinRow) -> Result<Coin> {
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
            return Reconstructed::Nft {
                owner_p2: hexb(nft.info.p2_puzzle_hash),
                row: Box::new(nft_row(ctx, prefix, created_height, &nft)),
            };
        }
    }

    // DID: `parse_child` takes the child coin but does NOT bind it to what it parsed. It reads the
    // owner out of the parent spend's CREATE_COIN memo *hint* and stores it verbatim
    // (`DidInfo::p2_puzzle_hash = hint`), which anybody who can spend any DID may write to name any
    // p2 hash they like. So the parse alone proves nothing about ownership, and the check the SDK's
    // own construction path makes — `inner_puzzle_hash() == create_coin.puzzle_hash` — has no
    // counterpart on the read path.
    //
    // Recomputing the singleton puzzle hash FROM the parsed info and requiring it to equal the real
    // child coin's is what turns the hint back into a proof: `puzzle_hash()` is curried over
    // `p2_puzzle_hash`, so a lie about the owner cannot reproduce the on-chain coin. An honest DID
    // pays nothing — its child is built from that same hash, so the two are equal by construction.
    // (The NFT arm above needs no equivalent: `nft.coin` is derived from `nft.info`, and the coin-id
    // equality at that arm already commits to it.)
    if let Ok(Some(did)) = Did::parse_child(ctx, parent_coin, parent_puzzle, parent_solution, child)
    {
        let reconstructed_puzzle_hash: Bytes32 = did.info.puzzle_hash().into();
        if reconstructed_puzzle_hash == child.puzzle_hash {
            return Reconstructed::Did {
                owner_p2: hexb(did.info.p2_puzzle_hash),
                row: Box::new(did_row(prefix, created_height, &did)),
            };
        }
        tracing::warn!(
            coin_id = %hexb(child_id),
            "DID reconstruction: the parent spend's owner hint does not reproduce the coin's puzzle hash; refusing"
        );
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

/// Resolve a spendable [`Cat`] (with its lineage proof) for `child` from its parent spend —
/// the input a CAT spend builder needs. `None` if the parent is not a CAT or no child matches.
pub fn resolve_cat(parent: &ParentSpend, child: Coin) -> Result<Option<Cat>> {
    let mut ctx = SpendContext::new();
    let puzzle_ptr = ctx
        .alloc(&Program::from(parent.puzzle_reveal.clone()))
        .map_err(|e| Error::internal(format!("alloc parent puzzle: {e}")))?;
    let parent_puzzle = Puzzle::parse(&ctx, puzzle_ptr);
    let solution_ptr = ctx
        .alloc(&Program::from(parent.solution.clone()))
        .map_err(|e| Error::internal(format!("alloc parent solution: {e}")))?;
    let child_id = child.coin_id();
    if let Ok(Some(children)) =
        Cat::parse_children(&mut ctx, parent.coin, parent_puzzle, solution_ptr)
    {
        return Ok(children.into_iter().find(|c| c.coin.coin_id() == child_id));
    }
    Ok(None)
}

/// Parse the spendable [`Nft`] for `child` from its `parent` spend INTO `ctx`, so its
/// allocator-relative metadata pointer is valid for a transfer spend built in the same
/// `ctx`. `None` if the parent is not an NFT or no child matches (used by `transfer_nfts`).
pub fn parse_nft_in(
    ctx: &mut SpendContext,
    parent: &ParentSpend,
    child: Coin,
) -> Result<Option<Nft>> {
    let puzzle_ptr = ctx
        .alloc(&Program::from(parent.puzzle_reveal.clone()))
        .map_err(|e| Error::internal(format!("alloc parent puzzle: {e}")))?;
    let parent_puzzle = Puzzle::parse(ctx, puzzle_ptr);
    let solution_ptr = ctx
        .alloc(&Program::from(parent.solution.clone()))
        .map_err(|e| Error::internal(format!("alloc parent solution: {e}")))?;
    let child_id = child.coin_id();
    match Nft::parse_child(ctx, parent.coin, parent_puzzle, solution_ptr) {
        Ok(Some(nft)) if nft.coin.coin_id() == child_id => Ok(Some(nft)),
        _ => Ok(None),
    }
}

/// Parse the spendable [`Did`] for `child` from its `parent` spend INTO `ctx` (the DID twin
/// of [`parse_nft_in`]). `None` if the parent is not a DID or the child does not match
/// (used by `transfer_dids` and DID-attributed mints).
pub fn parse_did_in(
    ctx: &mut SpendContext,
    parent: &ParentSpend,
    child: Coin,
) -> Result<Option<Did>> {
    let puzzle_ptr = ctx
        .alloc(&Program::from(parent.puzzle_reveal.clone()))
        .map_err(|e| Error::internal(format!("alloc parent puzzle: {e}")))?;
    let parent_puzzle = Puzzle::parse(ctx, puzzle_ptr);
    let solution_ptr = ctx
        .alloc(&Program::from(parent.solution.clone()))
        .map_err(|e| Error::internal(format!("alloc parent solution: {e}")))?;
    match Did::parse_child(ctx, parent.coin, parent_puzzle, solution_ptr, child) {
        Ok(did) => Ok(did),
        Err(_) => Ok(None),
    }
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
/// id in the `coins` table, which is what makes it visible to `get_cats`/`get_token` at all.
///
/// Neither reader becomes COMPLETE by this: a CAT coin the replica never ingested cannot be
/// attributed by a pass over rows it does not hold, and a row whose parent could not be read is
/// deliberately left for a later pass. The honest claim is that an attributed row is nameable,
/// never that every coin the wallet owns has been attributed.
///
/// # A row is examined ONCE, and the outcome is what gets remembered
///
/// A coin's parent spend is immutable chain history, and so is what that spend says the coin is.
/// So a row this pass RESOLVED and could not attribute — an NFT, a DID, an odd-amount plain XCH
/// coin that uncurries to [`Reconstructed::Unknown`] — will answer identically on every future
/// pass, forever, at the cost of one outbound chain read each time.
///
/// That is not hypothetical: `upsert_nft`/`upsert_did` write the `nfts`/`dids` tables and never
/// touch `coins.asset_id`, so **every NFT and DID the wallet holds** stays a candidate for the
/// life of the replica. A negative cache over the *lookup* cannot help, because these lookups
/// SUCCEED. What has to be remembered is the *attribution outcome*.
///
/// [`WalletDb::mark_attribution_examined`] records it, so the pass costs one indexed read plus
/// work proportional to **newly-arrived** rows rather than to every row ever synced.
///
/// A row whose parent could not be READ ([`LineageAnswer::Unavailable`]) is deliberately NOT
/// marked: nothing was learned about it, and marking it would convert a chain-source outage into
/// a permanent refusal to name the wallet's own money.
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
        let parent = match lineage
            .parent_spend(&c.parent_coin_info, created as u32)
            .await
        {
            Ok(LineageAnswer::Found(parent)) => *parent,
            // The chain says there is no such spend, and says it with corroboration. That answer
            // is stable, so the row is settled and never costs another read.
            Ok(LineageAnswer::Absent) => {
                db.mark_attribution_examined(&c.coin_id).await?;
                stats.settled += 1;
                continue;
            }
            // No source answered, so nothing was learned. The row is left UNMARKED so a later
            // pass retries it -- marking it would turn a momentary outage into a permanently
            // wrong balance.
            Ok(LineageAnswer::Unavailable) => {
                stats.unresolved += 1;
                continue;
            }
            // PER-COIN RESILIENCE, kept from dig-node#394 and load-bearing here.
            //
            // With `LineageAnswer` in place a read failure is `Unavailable` rather than `Err`, so
            // this arm is narrower than #394's was -- it now catches a source that answered with
            // something unusable (a malformed puzzle reveal, an undecodable hex field) rather than
            // an outage. The handling must still not be `?`. Propagating would let ONE malformed
            // reply from ONE peer abandon attribution for every remaining coin in the pass, which
            // is the same failure #394 removed, re-entered through a narrower door. The row is
            // left unmarked, so it is retried like any other thing not yet learned.
            Err(e) => {
                tracing::debug!(
                    coin_id = %c.coin_id,
                    error = %e,
                    "attribution: parent spend unusable; leaving the coin unattributed"
                );
                stats.unresolved += 1;
                continue;
            }
        };
        let child = coin_from_row(c)?;
        match reconstruct(prefix, Some(created as u32), &parent, child)? {
            Reconstructed::Nft { row, .. } => {
                db.upsert_nft(&row).await?;
                stats.nfts += 1;
            }
            Reconstructed::Did { row, .. } => {
                db.upsert_did(&row).await?;
                stats.dids += 1;
            }
            Reconstructed::Cat {
                coin_id,
                asset_id,
                hint,
            } => {
                db.attribute_cat_coin(&coin_id, &asset_id, Some(&hint))
                    .await?;
                stats.cats += 1;
            }
            Reconstructed::Unknown => {}
        }
        // Marked for EVERY resolved outcome, including the CAT one. `asset_id` alone would do
        // for a CAT, but making the mark unconditional on "we read the spend and acted on it"
        // means no future reconstruction kind can be added that silently re-reads forever.
        db.mark_attribution_examined(&c.coin_id).await?;
        stats.settled += 1;
    }
    Ok(stats)
}

/// Reconstruct every coin in the wallet DB that a pass could still learn something from.
///
/// The candidate set is narrowed in SQL — unspent, unattributed, confirmed, and not already
/// examined — rather than by scanning the whole `coins` table in Rust. The scan this replaces
/// was the standing per-frame cost that made a seeded replica an amplifier: one `SELECT *` plus
/// one outbound chain read per stable row, on every push frame, for the life of the process.
pub async fn reconstruct_all(
    db: &WalletDb,
    lineage: &dyn LineageSource,
    prefix: &str,
    plain_puzzle_hashes: &HashSet<String>,
) -> Result<ReconstructStats> {
    let coins = db.unexamined_attribution_candidates().await?;
    reconstruct_coins(db, lineage, prefix, plain_puzzle_hashes, &coins).await
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use chia_sdk_test::Simulator;
    use chia_traits::Streamable;
    use chia_wallet_sdk::driver::{
        Cat as SdkCat, CatSpend, IntermediateLauncher, Launcher, NftMint, SingletonInfo,
        SpendWithConditions, StandardLayer,
    };
    use chia_wallet_sdk::types::conditions::TransferNft;
    use chia_wallet_sdk::types::Conditions;
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
        ) -> Result<LineageAnswer> {
            // A parent this map does not hold is one the node could not READ — production's
            // answer for an unresolvable parent, not a settled absence.
            Ok(LineageAnswer::from_lookup(
                self.by_parent.get(parent_coin_id).cloned(),
                LineageAnswer::Unavailable,
            ))
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
    ///
    /// Shared with `cat_discovery`'s tests rather than re-minted there: a second copy of this
    /// fixture would be a second definition of what an owned singleton looks like, and the two
    /// would drift.
    pub(crate) fn mint_did_and_nft() -> MintedSingletons {
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
        metadata
            .data_uris
            .push("https://example.com/a.png".to_string());
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
        sim.spend_coins(ctx.take(), std::slice::from_ref(&alice.sk))
            .unwrap();

        // Transfer both singletons to self, producing the children a wallet syncs.
        let child_did = did
            .transfer(ctx, &alice_p2, alice.puzzle_hash, Conditions::new())
            .unwrap();
        let child_nft = nft
            .transfer(ctx, &alice_p2, alice.puzzle_hash, Conditions::new())
            .unwrap();
        sim.spend_coins(ctx.take(), &[alice.sk]).unwrap();

        let did_parent = parent_spend_from_sim(&sim, did.coin);
        let nft_parent = parent_spend_from_sim(&sim, nft.coin);
        MintedSingletons {
            _sim: sim,
            did_parent,
            did_child: child_did.coin,
            nft_parent,
            nft_child: child_nft.coin,
            did_launcher: did.info.launcher_id,
            nft_launcher: nft.info.launcher_id,
            owner_p2: alice.puzzle_hash,
        }
    }

    /// What [`mint_did_and_nft`] hands back: the two child singleton coins a wallet observes,
    /// the parent spends that prove them, and the p2 hash that owns both.
    pub(crate) struct MintedSingletons {
        /// Held so the simulator's spend store outlives the parent spends taken from it.
        pub(crate) _sim: Simulator,
        pub(crate) did_parent: ParentSpend,
        pub(crate) did_child: Coin,
        pub(crate) nft_parent: ParentSpend,
        pub(crate) nft_child: Coin,
        pub(crate) did_launcher: Bytes32,
        pub(crate) nft_launcher: Bytes32,
        /// The p2 puzzle hash both singletons are owned by — the wallet's own hash in these tests.
        pub(crate) owner_p2: Bytes32,
    }

    /// Mint a DID that MALLORY owns, then spend it so the child singleton keeps MALLORY's inner
    /// puzzle while the `CREATE_COIN` memo **hint** names the VICTIM.
    ///
    /// FIXTURE DESIGN — the hint is varied INDEPENDENTLY of the true owner, which is the one thing
    /// no previous fixture did. [`mint_did_and_nft`] transfers with `Did::transfer`, which derives
    /// the hint FROM the destination p2 hash, so hint and owner agree in every row it produces —
    /// and a fixture in which two fields can never disagree cannot see a guard that reads the wrong
    /// one. Every value here is chain-valid: the simulator accepts the spend, because a memo is
    /// free-form data the consensus does not constrain.
    pub(crate) fn mint_did_hinted_to_a_stranger() -> ForgedDid {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();
        let mallory = sim.bls(2);
        let mallory_layer = StandardLayer::new(mallory.pk);
        // The p2 hash the forgery names as owner. Arbitrary: a victim's wallet recognises its own
        // hashes by value, and Mallory needs only to know one of them (a hint is public).
        let victim_p2 = Bytes32::new([0x5a; 32]);

        let (create_did, did) = Launcher::new(mallory.coin.coin_id(), 1)
            .create_simple_did(ctx, &mallory_layer)
            .unwrap();
        mallory_layer.spend(ctx, mallory.coin, create_did).unwrap();
        sim.spend_coins(ctx.take(), std::slice::from_ref(&mallory.sk))
            .unwrap();

        // THE FORGERY. The created coin is the singleton Mallory still controls — its inner puzzle
        // hash is curried over HER p2 hash — but the memo hint, which is the only place
        // `Did::parse_child` reads an owner from, names the victim instead.
        let child = did.child(did.info.p2_puzzle_hash, did.info.metadata, did.coin.amount);
        let memos = ctx.hint(victim_p2).unwrap();
        did.spend_with(
            ctx,
            &mallory_layer,
            Conditions::new().create_coin(
                child.info.inner_puzzle_hash().into(),
                did.coin.amount,
                memos,
            ),
        )
        .unwrap();
        sim.spend_coins(ctx.take(), &[mallory.sk]).unwrap();

        ForgedDid {
            parent: parent_spend_from_sim(&sim, did.coin),
            _sim: sim,
            child: child.coin,
            victim_p2,
            mallory_p2: did.info.p2_puzzle_hash,
            launcher: did.info.launcher_id,
        }
    }

    /// What [`mint_did_hinted_to_a_stranger`] hands back: a chain-valid DID spend whose memo hint
    /// and whose actual owner are DIFFERENT p2 hashes.
    pub(crate) struct ForgedDid {
        /// Held so the simulator's spend store outlives the parent spend taken from it.
        pub(crate) _sim: Simulator,
        pub(crate) parent: ParentSpend,
        pub(crate) child: Coin,
        /// The p2 hash the memo hint names — the one the victim's wallet controls.
        pub(crate) victim_p2: Bytes32,
        /// The p2 hash the coin's puzzle is actually curried over — Mallory's.
        pub(crate) mallory_p2: Bytes32,
        pub(crate) launcher: Bytes32,
    }

    /// A DID whose memo hint disagrees with the puzzle the coin is actually locked to is NOT
    /// reconstructed — the hint is attacker-written and proves nothing about ownership.
    ///
    /// The pure-core half of the end-to-end proof in `cat_discovery::tests`. Both are kept: this
    /// one pins WHERE the binding lives (in the reconstruction, so `reconstruct_coins` is covered
    /// by it too), and the other pins that production routing reaches it.
    #[test]
    fn a_did_whose_hint_disagrees_with_its_puzzle_is_not_reconstructed() {
        let f = mint_did_hinted_to_a_stranger();
        assert_ne!(
            f.victim_p2, f.mallory_p2,
            "the fixture is only meaningful if the hint and the real owner differ"
        );

        assert_eq!(
            reconstruct("xch", Some(7), &f.parent, f.child).unwrap(),
            Reconstructed::Unknown,
            "a DID whose owner hint does not reproduce the coin's puzzle hash is not a DID this \
             wallet may attribute to anybody"
        );

        // THE CONTROL. The same code path, the same driver call, and the one varied thing is
        // whether the hint tells the truth: an honest DID still reconstructs.
        let honest = mint_did_and_nft();
        assert!(
            matches!(
                reconstruct("xch", Some(7), &honest.did_parent, honest.did_child).unwrap(),
                Reconstructed::Did { .. }
            ),
            "an honest DID pays nothing for the binding"
        );
    }

    /// The wider path the binding also closes: [`reconstruct_coins`] writes `dids` rows with no
    /// ownership test of its own, so before the binding a forged hint minted a `dids` row there
    /// too — a path the promotion-site guard never sees.
    #[tokio::test]
    async fn reconstruct_coins_writes_no_did_row_for_a_forged_hint() {
        let f = mint_did_hinted_to_a_stranger();
        let mut lineage = MockLineage::default();
        lineage
            .by_parent
            .insert(hex::encode(f.child.parent_coin_info), f.parent.clone());

        let db = WalletDb::open_in_memory().await.unwrap();
        let rows = vec![coin_row(f.child, 100)];
        let stats = reconstruct_coins(&db, &lineage, "xch", &HashSet::new(), &rows)
            .await
            .unwrap();

        assert_eq!(stats.dids, 0, "the forged DID is not reconstructed");
        assert!(
            db.all_dids().await.unwrap().is_empty(),
            "and no row naming the victim as owner of Mallory's launcher {} reaches `dids`",
            hex::encode(f.launcher)
        );
    }

    #[test]
    fn reconstruct_parses_nft_and_did_from_parent_spends() {
        let m = mint_did_and_nft();
        let (did_parent, did_child, nft_parent, nft_child, did_launcher, nft_launcher) = (
            m.did_parent,
            m.did_child,
            m.nft_parent,
            m.nft_child,
            m.did_launcher,
            m.nft_launcher,
        );

        match reconstruct("xch", Some(42), &nft_parent, nft_child).unwrap() {
            Reconstructed::Nft { row, owner_p2 } => {
                assert_eq!(row.launcher_id, hex::encode(nft_launcher));
                assert_eq!(
                    owner_p2,
                    hex::encode(m.owner_p2),
                    "the reconstruction names the p2 hash that owns the NFT"
                );
                let rec: NftRecord = serde_json::from_str(&row.record_json).unwrap();
                assert_eq!(rec.royalty_ten_thousandths, 300);
                assert_eq!(rec.data_uris, vec!["https://example.com/a.png".to_string()]);
                assert_eq!(rec.data_hash.as_deref(), Some(&hex::encode([7u8; 32])[..]));
                assert!(rec.address.starts_with("xch1"));
            }
            other => panic!("expected NFT, got {other:?}"),
        }

        match reconstruct("xch", Some(7), &did_parent, did_child).unwrap() {
            Reconstructed::Did { row, owner_p2 } => {
                assert_eq!(row.launcher_id, hex::encode(did_launcher));
                assert_eq!(
                    owner_p2,
                    hex::encode(m.owner_p2),
                    "the reconstruction names the p2 hash that owns the DID"
                );
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
        let (issue_cat, cats) = SdkCat::single_issuance(
            ctx,
            alice.coin.coin_id(),
            // `hidden_puzzle_hash`: the slot chia-sdk-driver 0.36 exposes where 0.30's
            // `issue_with_coin` hard-coded `None`. `None` keeps the eve coin's puzzle hash — and so
            // this fixture's CAT — byte-identical; `Some(..)` would issue a different coin.
            None,
            1000,
            Conditions::new().create_coin(alice.puzzle_hash, 1000, memos),
        )
        .unwrap();
        alice_p2.spend(ctx, alice.coin, issue_cat).unwrap();
        sim.spend_coins(ctx.take(), std::slice::from_ref(&alice.sk))
            .unwrap();
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
        let m = mint_did_and_nft();
        let (did_parent, did_child, nft_parent, nft_child) =
            (m.did_parent, m.did_child, m.nft_parent, m.nft_child);

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

        let stats = reconstruct_coins(
            &db,
            &lineage,
            "xch",
            &HashSet::new(),
            &db.all_coins().await.unwrap(),
        )
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

    /// A [`LineageSource`] that counts its reads and answers however it was told to.
    struct CountingLineage {
        answer: LineageAnswerKind,
        hits: std::sync::atomic::AtomicUsize,
    }

    /// Which answer [`CountingLineage`] gives. Named rather than boolean because the three cases
    /// have three different consequences for whether a row may be written off.
    #[derive(Clone, Copy)]
    enum LineageAnswerKind {
        /// A real spend that reconstructs to nothing — the shape of an odd-amount plain XCH coin
        /// at the wallet's own p2 hash, and of every NFT/DID coin row after its own table is
        /// written. These RESOLVE, which is precisely why a cache over the lookup cannot help.
        ResolvesToNothing,
        /// The chain answered: no such spend.
        Absent,
        /// Nothing could be reached.
        Unavailable,
    }

    #[async_trait]
    impl LineageSource for CountingLineage {
        async fn parent_spend(&self, _parent: &str, _height: u32) -> Result<LineageAnswer> {
            self.hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(match self.answer {
                LineageAnswerKind::ResolvesToNothing => {
                    LineageAnswer::Found(Box::new(ParentSpend {
                        // A spend of a coin that creates nothing the drivers recognise, so
                        // `reconstruct_parsed` falls through to `Unknown`.
                        coin: Coin {
                            parent_coin_info: Bytes32::from([1u8; 32]),
                            puzzle_hash: Bytes32::from([2u8; 32]),
                            amount: 1,
                        },
                        puzzle_reveal: vec![0x01],
                        solution: vec![0x80],
                    }))
                }
                LineageAnswerKind::Absent => LineageAnswer::Absent,
                LineageAnswerKind::Unavailable => LineageAnswer::Unavailable,
            })
        }
    }

    fn counting(answer: LineageAnswerKind) -> CountingLineage {
        CountingLineage {
            answer,
            hits: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// An unattributed, unspent, confirmed coin at an UNSUBSCRIBED puzzle hash — a candidate on
    /// every pass until something settles it.
    fn candidate_row(n: u8) -> CoinRow {
        CoinRow {
            coin_id: hex::encode([n; 32]),
            parent_coin_info: hex::encode([n.wrapping_add(100); 32]),
            puzzle_hash: hex::encode([n.wrapping_add(200); 32]),
            amount: "1".into(),
            created_height: Some(5),
            spent_height: None,
            asset_id: None,
            hint: None,
            created_timestamp: None,
            spent_timestamp: None,
        }
    }

    /// **Proves (dig-node#383):** a row whose parent RESOLVES but which cannot be attributed is
    /// read exactly once, however many passes run.
    ///
    /// # Why this fixture and not an unresolvable parent
    ///
    /// The nearest wrong implementation is the one that shipped: a negative cache over the LOOKUP.
    /// It makes an *unresolvable* parent free and is structurally unable to help here, because
    /// this lookup succeeds. Every NFT and DID the wallet holds has this shape — the reconstructed
    /// row is written to its own table and `coins.asset_id` stays NULL — so choosing a resolving
    /// parent is what distinguishes remembering the OUTCOME from remembering the lookup.
    ///
    /// Ten passes rather than two, so a fix that merely halves the work fails as loudly as one
    /// that does nothing.
    #[tokio::test]
    async fn a_resolving_but_unattributable_row_is_read_once_not_once_per_pass() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_coins(&[candidate_row(1)]).await.unwrap();
        let lineage = counting(LineageAnswerKind::ResolvesToNothing);
        let plain = HashSet::new();

        for _ in 0..10 {
            reconstruct_all(&db, &lineage, "xch", &plain).await.unwrap();
        }

        assert_eq!(
            lineage.hits.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "ten passes over one settled row must cost one read; anything more is a per-frame \
             outbound chain read for the life of the replica"
        );
    }

    /// **Proves (dig-node#383):** a reported ABSENCE settles the row too — asking again gets the
    /// same answer, so paying for it again buys nothing.
    #[tokio::test]
    async fn a_reported_absence_settles_the_row() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_coins(&[candidate_row(2)]).await.unwrap();
        let lineage = counting(LineageAnswerKind::Absent);
        let plain = HashSet::new();

        for _ in 0..10 {
            reconstruct_all(&db, &lineage, "xch", &plain).await.unwrap();
        }

        assert_eq!(
            lineage.hits.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a spend the chain says does not exist is settled chain history, not a retry"
        );
    }

    /// **Proves (dig-node#383, D3):** an UNREADABLE parent is NOT settled, so a chain-source
    /// outage cannot write a coin off.
    ///
    /// The control that makes this test load-bearing is its sibling above: identical traffic,
    /// identical row, and the only difference is whether the source answered. If the mark were
    /// applied on every pass rather than on a resolved one, this would report 1 like the others —
    /// and the wallet would spend the rest of the replica's life refusing to look at a coin it
    /// failed to read once.
    #[tokio::test]
    async fn an_unreadable_parent_is_retried_rather_than_written_off() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_coins(&[candidate_row(3)]).await.unwrap();
        let lineage = counting(LineageAnswerKind::Unavailable);
        let plain = HashSet::new();

        for _ in 0..10 {
            reconstruct_all(&db, &lineage, "xch", &plain).await.unwrap();
        }

        assert_eq!(
            lineage.hits.load(std::sync::atomic::Ordering::SeqCst),
            10,
            "nothing was learned about this parent, so every pass must ask again; marking it \
             would turn a transient outage into a permanent wrong balance"
        );
    }

    /// **Proves (dig-node#383):** the pass's cost tracks NEWLY-ARRIVED rows, not the size of the
    /// replica.
    ///
    /// This is the property the deferral of the per-frame scan was wrongly assumed to already
    /// have. Twenty settled rows plus one new one costs one read, not twenty-one — the difference
    /// between a scan a peer can re-trigger for the price of an empty frame and one it cannot.
    #[tokio::test]
    async fn a_later_pass_pays_only_for_what_newly_arrived() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let seeded: Vec<CoinRow> = (10..30).map(candidate_row).collect();
        db.upsert_coins(&seeded).await.unwrap();
        let lineage = counting(LineageAnswerKind::ResolvesToNothing);
        let plain = HashSet::new();

        reconstruct_all(&db, &lineage, "xch", &plain).await.unwrap();
        assert_eq!(
            lineage.hits.load(std::sync::atomic::Ordering::SeqCst),
            20,
            "the first pass must genuinely examine all twenty, or the second pass proves nothing"
        );

        db.upsert_coins(&[candidate_row(40)]).await.unwrap();
        reconstruct_all(&db, &lineage, "xch", &plain).await.unwrap();

        assert_eq!(
            lineage.hits.load(std::sync::atomic::Ordering::SeqCst),
            21,
            "the second pass must pay for the one new row only"
        );
    }
}
