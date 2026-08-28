//! CAT discovery by derived puzzle hash, and the lineage proof that promotes a discovery into a
//! believed coin (dig-node#380).
//!
//! # The distinction this module exists to hold
//!
//! A `CoinState` on the wire carries three fields — parent, puzzle hash, amount — and **no hint**.
//! A wallet therefore cannot recognise a CAT coin from the frame that delivers it; the only thing
//! it can do locally is derive, in advance, the outer hash a CAT of a known asset would sit at if
//! this wallet owned it, and subscribe to that hash. That derivation,
//! `cat_puzzle_hash(owner_p2, asset_id)`, is injective: it commits to the CAT2 module, the asset
//! id and the inner p2 together.
//!
//! What it proves is *"if this coin is ever spent, only this wallet can spend it, and only as this
//! asset"*. What it does **not** prove is *"this coin is a unit of that asset"* — because
//! `CREATE_COIN` is unconstrained in its destination, so anybody may place a coin at any puzzle
//! hash. A stranger holding nothing but the victim's public address can therefore manufacture a
//! coin at the derived hash for **one mojo per displayed base unit**.
//!
//! Believing the derivation costs three things at once: a fabricated balance, a **permanent send
//! kill-switch** (coin selection is largest-first, and the fabricated coin is unspendable by
//! anyone, so it is chosen forever and never leaves the set), and a false *"you were paid"*
//! notification.
//!
//! So discovery and belief are separated by a **table**, not a flag:
//!
//! | stage | where the coin lives | what is known |
//! |---|---|---|
//! | discovered | [`crate::sage::db::StagedCatRow`] in `cat_admission_pending` | it sits at a hash we derived |
//! | believed | `CoinRow` in `coins`, fully attributed | its parent spend reconstructs it as that asset |
//!
//! Every production reader of `coins` — the balance, the spend-input selector, the arrivals
//! notifier, `get_cats` — is clean because a staged coin is **absent from the table they read**,
//! not because each of them remembers a predicate. That difference is load-bearing: the
//! enumeration of those readers has already been found incomplete twice in this ticket family.
//!
//! # Where the work happens
//!
//! - **On the peer frame path**: [`DerivedCats::owner_of`] is a hash-map lookup. Zero chain reads,
//!   structurally — [`stage_from_states`] takes no [`LineageSource`] and so cannot perform one.
//! - **Off the frame path**: [`promote_staged_cats`] performs roughly **one** parent-spend read per
//!   newly staged coin, **terminal** on both success and definitive refusal, and capped per pass.

use std::collections::HashMap;

use chia_protocol::{Bytes32, Coin, CoinState};

use super::db::{StagedCatRow, WalletDb};
use super::singleton::{coin_from_row, LineageSource, Reconstructed};
use super::{singleton, Result};

/// How many staged coins one promotion pass will read parent spends for.
///
/// This is the amplification bound. An attacker who stages `N` coins buys at most this many chain
/// reads per pass, and because promotion is **terminal** — a coin is promoted or refused once and
/// never re-read — the total reads they can buy is `N`, not `N` per pass forever. Against a coin
/// each of which cost them a `CREATE_COIN` and at least one mojo, that is roughly 1x.
///
/// Small enough that a pass stays short (each read is a network round trip), large enough that an
/// honest wallet's whole backlog clears in a handful of passes.
pub const MAX_CAT_PROMOTIONS_PER_PASS: i64 = 64;

/// The outer CAT puzzle hashes this wallet would own, and what each one was derived FROM.
///
/// A map rather than a set because the provenance is the point: when a coin arrives at one of
/// these hashes, promotion has to check the parent spend against the *specific* (asset id, owner
/// p2) pair that predicted it. A bare set would only be able to say "one of ours predicted this",
/// which is not a claim promotion can test.
#[derive(Debug, Clone, Default)]
pub struct DerivedCats {
    by_hash: HashMap<Bytes32, DerivedOwner>,
}

/// What a derived CAT puzzle hash was built from — a CLAIM about an arriving coin, never a fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerivedOwner {
    /// The CAT asset id (TAIL hash) curried into the outer puzzle.
    pub asset_id: Bytes32,
    /// The inner p2 puzzle hash the wallet controls.
    pub owner_p2: Bytes32,
}

impl DerivedCats {
    /// Derive the outer hash for every `(owner p2, asset id)` pair.
    ///
    /// Built through `digstore_chain::cat::cat_puzzle_hash` — the one construction the wallet's CAT
    /// balance, coin reconstruction and send paths already share. A second spelling of this curry
    /// would be a byte-drift bug in the code that decides whether money is counted (SYSTEM.md §4.1).
    pub fn derive(owner_p2_hashes: &[Bytes32], asset_ids: &[Bytes32]) -> Self {
        let mut by_hash = HashMap::new();
        for &owner_p2 in owner_p2_hashes {
            for &asset_id in asset_ids {
                let outer = digstore_chain::cat::cat_puzzle_hash(owner_p2, asset_id);
                by_hash.insert(
                    outer,
                    DerivedOwner {
                        asset_id,
                        owner_p2,
                    },
                );
            }
        }
        Self { by_hash }
    }

    /// What predicted `puzzle_hash`, if anything did.
    pub fn owner_of(&self, puzzle_hash: &Bytes32) -> Option<DerivedOwner> {
        self.by_hash.get(puzzle_hash).copied()
    }

    /// Every derived hash, for the subscription request.
    pub fn hashes(&self) -> Vec<Bytes32> {
        let mut hashes: Vec<Bytes32> = self.by_hash.keys().copied().collect();
        // A HashMap's iteration order is arbitrary; sorting makes a subscription — and a test
        // asserting one — reproducible.
        hashes.sort();
        hashes
    }

    /// Whether anything was derived at all.
    pub fn is_empty(&self) -> bool {
        self.by_hash.is_empty()
    }
}

/// Turn the derived-hash coins in `states` into staged rows.
///
/// `already_promoted` are coin ids that already have a row in `coins`. A coin that has cleared
/// promotion is NOT re-staged: its later states — a spend, above all — must update `coins` exactly
/// as `origin/main` updates any other coin, or a promoted coin would stay unspent in the replica
/// forever and be selected again after it was already spent.
///
/// Takes no [`LineageSource`], which is how the zero-chain-reads-on-the-frame-path property is
/// guaranteed: it is not a discipline the body observes, it is a fact about the signature.
pub fn stage_from_states<'a, F>(
    states: &'a [CoinState],
    derived: &DerivedCats,
    mut already_promoted: F,
) -> Vec<StagedCatRow>
where
    F: FnMut(&str) -> bool,
{
    let mut rows = Vec::new();
    for s in states {
        let Some(owner) = derived.owner_of(&s.coin.puzzle_hash) else {
            continue;
        };
        let coin_id = hex::encode(s.coin.coin_id());
        if already_promoted(&coin_id) {
            continue;
        }
        rows.push(StagedCatRow {
            coin_id,
            parent_coin_info: hex::encode(s.coin.parent_coin_info),
            puzzle_hash: hex::encode(s.coin.puzzle_hash),
            amount: s.coin.amount.to_string(),
            created_height: s.created_height.map(i64::from),
            spent_height: s.spent_height.map(i64::from),
            created_timestamp: None,
            spent_timestamp: None,
            derived_asset_id: hex::encode(owner.asset_id),
            derived_owner_p2: hex::encode(owner.owner_p2),
        });
    }
    rows
}

/// What one promotion pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PromoteStats {
    /// Coins whose parent spend proved them units of the derived asset, and which are now in `coins`.
    pub promoted: u32,
    /// Coins a SUCCESSFUL parent read proved are not units of the derived asset — deleted.
    pub refused: u32,
    /// Coins left staged because their parent spend could not be read this pass.
    pub deferred: u32,
}

/// Promote every staged coin a parent spend proves, and refuse every one it disproves.
///
/// # The three outcomes, and why the third is not the second
///
/// - **Proven** — the parent spend reconstructs the coin as a CAT, and both the asset id and the
///   inner p2 hash it reconstructs to equal the ones the derivation predicted. The coin moves into
///   `coins` attributed from the RECONSTRUCTION, never from the derivation.
/// - **Disproven** — the parent spend was read successfully and does not reconstruct this coin as a
///   CAT of that asset. The staged row is deleted, terminally: this is what makes an attacker's
///   read amplification ~1x rather than perpetual.
/// - **Unavailable** — the parent spend could not be read. The row stays staged, unmarked, and is
///   retried. Deleting here would let a peer that simply withholds parent spends erase real money;
///   leaving the row staged means the coin is *absent*, which is the acceptable direction.
///
/// # Errors are returned, and the caller must swallow them
///
/// A promotion failure is a chain-read failure. It must never propagate into the peer update loop,
/// where it would end a live session — that is exactly how earlier rounds of this work turned a
/// read failure into a denial primitive. The function returns `Result` so a caller can LOG the
/// cause; every production caller logs and continues.
pub async fn promote_staged_cats(
    db: &WalletDb,
    lineage: &dyn LineageSource,
) -> Result<PromoteStats> {
    let mut stats = PromoteStats::default();
    for row in db.staged_cat_admissions(MAX_CAT_PROMOTIONS_PER_PASS).await? {
        // A coin already spent on chain can never contribute to a balance or be selected as a
        // spend input, so proving it would buy nothing and cost a round trip. Dropped without a
        // read, which also stops a spent coin sitting in staging forever waiting for a promotion
        // that could not matter. The cost is that such a coin never appears in HISTORY — absence,
        // the stated failure direction, and never a wrong figure.
        if row.spent_height.is_some() {
            db.discard_cat_admission(&row.coin_id).await?;
            stats.refused += 1;
            continue;
        }
        let Some(created) = row.created_height else {
            // Unconfirmed: there is no height to read a parent spend at yet. Left staged.
            stats.deferred += 1;
            continue;
        };
        let parent = match lineage
            .parent_spend(&row.parent_coin_info, created as u32)
            .await
        {
            Ok(Some(parent)) => parent,
            // `Ok(None)` is "the parent spend is not available", NOT "the parent is not a CAT".
            // Treating it as a disproof would delete real coins whenever a source is behind.
            Ok(None) => {
                stats.deferred += 1;
                continue;
            }
            Err(e) => {
                tracing::debug!(
                    coin_id = %row.coin_id,
                    error = %e,
                    "cat promotion: parent spend unreadable; leaving the coin staged"
                );
                stats.deferred += 1;
                continue;
            }
        };
        if promote_one(db, lineage_prefix(), &row, &parent).await? {
            stats.promoted += 1;
        } else {
            db.discard_cat_admission(&row.coin_id).await?;
            stats.refused += 1;
        }
    }
    Ok(stats)
}

/// The address prefix reconstruction wants. CAT attribution never produces an address — only NFT
/// and DID rows do — so the value is irrelevant here and is named rather than threaded.
fn lineage_prefix() -> &'static str {
    "xch"
}

/// Decide and apply one coin's promotion. `Ok(true)` promoted, `Ok(false)` disproven.
async fn promote_one(
    db: &WalletDb,
    prefix: &str,
    row: &StagedCatRow,
    parent: &super::singleton::ParentSpend,
) -> Result<bool> {
    let coin_row = staged_as_coin(row);
    let child: Coin = coin_from_row(&coin_row)?;
    // THE BINDING CHECK. The staged row's coin id is re-derived from the fields the row itself
    // carries rather than trusted as stored, so a row whose id does not bind its own
    // (parent, puzzle hash, amount) can never be promoted. Without this, a transcription mistake
    // anywhere upstream would let a proof about one coin admit a different one.
    if hex::encode(child.coin_id()) != row.coin_id.to_ascii_lowercase() {
        tracing::warn!(
            coin_id = %row.coin_id,
            "cat promotion: staged row's coin id does not bind its own fields; refusing"
        );
        return Ok(false);
    }
    let reconstructed = singleton::reconstruct(prefix, row.created_height.map(|h| h as u32), parent, child)?;
    let Reconstructed::Cat {
        coin_id,
        asset_id,
        hint,
    } = reconstructed
    else {
        // The parent read succeeded and this coin is not a CAT child of it at all. Disproven.
        return Ok(false);
    };
    // The reconstruction must agree with the derivation on BOTH halves. Checking only the asset id
    // would admit a real CAT of the right asset owned by somebody else; checking only the owner
    // would admit a CAT of a different asset counted as this one. Both are money-visible.
    let agrees = coin_id.eq_ignore_ascii_case(&row.coin_id)
        && asset_id.eq_ignore_ascii_case(&row.derived_asset_id)
        && hint.eq_ignore_ascii_case(&row.derived_owner_p2);
    if !agrees {
        tracing::warn!(
            coin_id = %row.coin_id,
            reconstructed_asset = %asset_id,
            derived_asset = %row.derived_asset_id,
            "cat promotion: the parent spend disagrees with the derivation; refusing"
        );
        return Ok(false);
    }
    // Attributed from the RECONSTRUCTION's own values, which is the whole content of the proof.
    db.promote_cat_admission(row, &asset_id, &hint).await?;
    Ok(true)
}

/// A staged row viewed as a coin, for reconstruction only. Never written to `coins` from here —
/// [`WalletDb::promote_cat_admission`] owns that write, and only after the proof.
fn staged_as_coin(row: &StagedCatRow) -> super::db::CoinRow {
    super::db::CoinRow {
        coin_id: row.coin_id.clone(),
        parent_coin_info: row.parent_coin_info.clone(),
        puzzle_hash: row.puzzle_hash.clone(),
        amount: row.amount.clone(),
        created_height: row.created_height,
        spent_height: row.spent_height,
        asset_id: None,
        hint: None,
        created_timestamp: row.created_timestamp,
        spent_timestamp: row.spent_timestamp,
    }
}
