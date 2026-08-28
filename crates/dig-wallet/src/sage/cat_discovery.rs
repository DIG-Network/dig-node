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

use std::collections::{HashMap, HashSet};

use chia_protocol::{Bytes32, Coin, CoinState};

use super::db::{CoinRow, PromotedSingleton, StagedCatRow, WalletDb};
use super::singleton::{coin_from_row, LineageAnswer, LineageSource, Reconstructed};
use super::{singleton, Result};

/// How many staged coins one promotion pass will read parent spends for.
///
/// The per-pass bound. A pass stays short — each read is a network round trip — while an honest
/// wallet's whole backlog still clears in a handful of passes.
///
/// This is NOT on its own the amplification bound, and an earlier version of this comment claimed
/// it was: it asserted that promotion is terminal, so an attacker who stages `N` coins buys `N`
/// reads in total. That is true of a coin whose promotion CONCLUDES, and false of one whose
/// parent cannot be read — which is the case an attacker chooses. Such a row stays staged by
/// design, so it was re-read on every pass, for ever. The real bound is one read per staged row
/// per [`PROMOTION_RETRY_COOLDOWN`], enforced in [`crate::sage::db::WalletDb::staged_cat_admissions`].
pub const MAX_CAT_PROMOTIONS_PER_PASS: i64 = 64;

/// The least time between two parent-spend reads for the SAME staged coin (dig-node#394).
///
/// # What this bounds, and why a classification does not replace it
///
/// A parent spend that cannot be read has two causes with opposite correct handling: the parent
/// never existed (an invented ancestry, and the row will never resolve), or the source has not
/// got there yet (pruned, behind, offline — and the row will resolve later). Distinguishing them
/// would let the first be refused terminally.
///
/// The distinction is not soundly available. A coinset source answers a null `coin_solution` for
/// BOTH — a spend it has never heard of and a spend it is simply behind on — so a terminal
/// refusal built on that answer converts a source that is briefly behind into permanent erasure of
/// a real coin. That is the one failure direction this whole design refuses to take: absence is
/// acceptable, a wrong figure is not, and erasing money is worse than either.
///
/// So the cost is bounded instead of the cause classified. With attempts-ordered fetch, a row that
/// never resolves cannot starve one that would, and this cooldown holds each row to one read per
/// hour. An attacker who spends 64 mojos buys 64 reads an hour rather than 64 reads a pass, and
/// an honest coin behind a source outage still promotes the moment the source recovers.
pub const PROMOTION_RETRY_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(3_600);

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
                by_hash.insert(outer, DerivedOwner { asset_id, owner_p2 });
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
pub fn stage_from_states<F>(
    states: &[CoinState],
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

/// Split already-materialised [`CoinRow`]s into the ones that may be BELIEVED and the ones that
/// must be STAGED — the point-read tier's half of the same routing `stage_from_states` performs on
/// the peer frame path (dig-node#394).
///
/// # Why this exists rather than a second guard
///
/// `refresh_tracked_coins` reads coins two ways: by PUZZLE HASH, which finds coins sitting at the
/// wallet's own p2 hashes, and by HINT, which finds coins that merely *claim* to be for this
/// wallet. It upserted both straight into `coins`, where a row with no `asset_id` means XCH — so a
/// hint is attacker-controlled input that minted a balance. Anyone may `CREATE_COIN` with any
/// hint, so this was the same fabricated-balance and send-kill-switch primitive as the catch-up
/// path, at a third tier and reachable without a peer at all.
///
/// The fix is not a third guard. Three guards that must agree is what produced this defect twice
/// already; this routes the third tier through the SAME staging table, so there is one admission
/// point and it is the one that demands a lineage proof.
///
/// A hinted coin that is not at a derived hash for a known asset is STAGED with the empty
/// sentinel, not believed and not discarded: nothing was predicted about it, so there is nothing to
/// match against, and its parent spend alone decides what it is. What the narrowing removes is
/// BELIEF before the proof — such a coin used to enter `coins` with no asset id, where it read as
/// XCH and produced a wrong figure. Absence until proven is this design's accepted failure
/// direction; a wrong figure is not.
pub fn route_point_read_rows<F>(
    rows: &[CoinRow],
    owned_puzzle_hashes: &HashSet<String>,
    derived: &DerivedCats,
    mut already_promoted: F,
) -> (Vec<CoinRow>, Vec<StagedCatRow>)
where
    F: FnMut(&str) -> bool,
{
    let mut believed = Vec::new();
    let mut staged = Vec::new();
    for row in rows {
        // A coin at one of the wallet's OWN p2 hashes is an ordinary XCH coin: the wallet can
        // spend it and its amount is XCH. Unchanged, and the only thing that stays unchanged.
        if owned_puzzle_hashes.contains(&row.puzzle_hash) {
            believed.push(row.clone());
            continue;
        }
        // Everything else was found by HINT and is a CLAIM. A derived hash additionally tells us
        // which asset to expect; anything else is staged with the empty sentinel and proven purely
        // from its parent spend. Nothing is dropped, so no CAT this path used to surface is lost —
        // what changes is that none of it is BELIEVED before the proof.
        let predicted = hex_to_bytes32(&row.puzzle_hash).and_then(|h| derived.owner_of(&h));
        if already_promoted(&row.coin_id) {
            // Already proven once; its later states update `coins` normally, exactly as on the
            // frame path, or a promoted coin would stay unspent in the replica for ever.
            believed.push(row.clone());
            continue;
        }
        staged.push(StagedCatRow {
            coin_id: row.coin_id.clone(),
            parent_coin_info: row.parent_coin_info.clone(),
            puzzle_hash: row.puzzle_hash.clone(),
            amount: row.amount.clone(),
            created_height: row.created_height,
            spent_height: row.spent_height,
            // Preserved here, unlike the frame path: a point read carries them and throwing them
            // away would make a promoted coin's history poorer than the row it came from.
            created_timestamp: row.created_timestamp,
            spent_timestamp: row.spent_timestamp,
            derived_asset_id: predicted
                .map(|o| hex::encode(o.asset_id))
                .unwrap_or_default(),
            derived_owner_p2: predicted
                .map(|o| hex::encode(o.owner_p2))
                .unwrap_or_default(),
        });
    }
    (believed, staged)
}

/// Parse a 32-byte hex puzzle hash, tolerating a `0x` prefix and either case.
fn hex_to_bytes32(s: &str) -> Option<Bytes32> {
    let bytes = hex::decode(s.strip_prefix("0x").unwrap_or(s)).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Some(Bytes32::new(arr))
}

/// What one promotion pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PromoteStats {
    /// Coins whose parent spend proved them units of the derived asset, and which are now in `coins`.
    pub promoted: u32,
    /// Coins whose parent spend proved them owned NFT/DID singletons, now in `nfts`/`dids`.
    pub resolved: u32,
    /// Coins a SUCCESSFUL parent read proved are not units of the derived asset — deleted.
    pub refused: u32,
    /// Coins left staged because their parent spend could not be read this pass.
    pub deferred: u32,
}

/// Promote every staged coin a parent spend proves, and refuse every one it disproves.
///
/// # The four outcomes, and why they are four
///
/// - **Proven** — the parent spend reconstructs the coin as a CAT, and both the asset id and the
///   inner p2 hash it reconstructs to equal the ones the derivation predicted. The coin moves into
///   `coins` attributed from the RECONSTRUCTION, never from the derivation.
/// - **Resolved** — the parent spend reconstructs the coin as an NFT or DID singleton this wallet's
///   p2 hash owns. Equally proven, by the same machinery, so it is admitted — to `nfts`/`dids`,
///   because a singleton in `coins` would read as XCH. Kept apart from *Disproven* deliberately:
///   one says the derivation was a lie, the other says it was true about something this function
///   does not itself handle, and collapsing them deletes real assets (dig-node#394).
/// - **Disproven** — the parent spend was read successfully and refutes the claim: the coin is not
///   a CAT of that asset, or is a singleton belonging to another p2 hash, or reconstructs to
///   nothing at all. The staged row is deleted, terminally: this is what makes an attacker's read
///   amplification ~1x rather than perpetual. It is also the outcome for a row already spent on
///   chain, which is dropped without a read at all, and for a row whose coin id does not bind its
///   own fields.
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
    owned_p2: &HashSet<String>,
) -> Result<PromoteStats> {
    let mut stats = PromoteStats::default();
    // Read from the wall clock ONCE, so every row in this pass is metered against the same
    // instant and a long pass cannot let its own duration widen the cooldown.
    let now = unix_now();
    let retry_cutoff = now - i64::try_from(PROMOTION_RETRY_COOLDOWN.as_secs()).unwrap_or(3_600);
    for row in db
        .staged_cat_admissions(MAX_CAT_PROMOTIONS_PER_PASS, retry_cutoff)
        .await?
    {
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
            // Unconfirmed: there is no height to read a parent spend at yet. Left staged, and
            // metered — a coin that is never confirmed is exactly as unresolvable as one whose
            // parent is never readable, and it must not hold the queue head either.
            db.record_promotion_attempt(&row.coin_id, now).await?;
            stats.deferred += 1;
            continue;
        };
        let parent = match lineage
            .parent_spend(&row.parent_coin_info, created as u32)
            .await
        {
            Ok(LineageAnswer::Found(parent)) => *parent,
            // A source ANSWERED, and has no spend for this parent.
            //
            // #393 reasoned about this as `Ok(None)` and DEFERRED it, and that stays exactly
            // right even though the answer is strictly stronger now: with `LineageAnswer` this
            // arm is a CORROBORATED absence (chia-query settles an uncorroborated one as an
            // `Err`), so one hostile peer can no longer produce it. Corroboration is agreement,
            // NOT currency -- every source can agree and every source can be behind the chain,
            // which is the ordinary case for a coin created seconds ago. So a corroborated
            // absence still does not disprove ancestry, and promoting it to `Disproven` would
            // delete real coins whenever the sources lag. Deferred, with the cooldown bounding
            // the cost of retrying for ever.
            Ok(LineageAnswer::Absent) => {
                db.record_promotion_attempt(&row.coin_id, now).await?;
                stats.deferred += 1;
                continue;
            }
            // No source answered at all -- transport, timeout, an uncorroborated claim, or two
            // sources that contradict each other. Strictly less informative than an absence, and
            // handled the same way.
            Ok(LineageAnswer::Unavailable) => {
                db.record_promotion_attempt(&row.coin_id, now).await?;
                stats.deferred += 1;
                continue;
            }
            // A source answered with something unusable (a malformed reveal, undecodable hex).
            // Narrower than #393's `Err` arm, which also caught outages; those are `Unavailable`
            // above. Handled identically, so no promotion decision changes.
            Err(e) => {
                tracing::debug!(
                    coin_id = %row.coin_id,
                    error = %e,
                    "cat promotion: parent spend unreadable; leaving the coin staged"
                );
                db.record_promotion_attempt(&row.coin_id, now).await?;
                stats.deferred += 1;
                continue;
            }
        };
        match promote_one(db, lineage_prefix(), &row, &parent, owned_p2).await? {
            Promotion::Promoted => stats.promoted += 1,
            // The staging row was consumed inside `promote_singleton_admission`, in the same
            // transaction that wrote the singleton. Nothing left to discard.
            Promotion::Resolved => stats.resolved += 1,
            Promotion::Disproven => {
                db.discard_cat_admission(&row.coin_id).await?;
                stats.refused += 1;
            }
            // The staged row was rolled back while its parent spend was being read. Nothing was
            // written and there is nothing to discard; the coin re-stages if it reappears above
            // the fork. Counted as deferred because that is what it is — no verdict was reached.
            Promotion::Vanished => stats.deferred += 1,
        }
    }
    Ok(stats)
}

/// Seconds since the Unix epoch, saturating at zero on a clock set before it.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// The address prefix reconstruction wants. CAT attribution never produces an address — only NFT
/// and DID rows do — so the value is irrelevant here and is named rather than threaded.
fn lineage_prefix() -> &'static str {
    "xch"
}

/// What deciding one coin's promotion concluded.
///
/// Four outcomes rather than a bool, because "not promoted into `coins`" covers three situations
/// that must not be treated alike: a coin the parent spend DISPROVES is finished with and its
/// staging row is deleted; a coin the parent spend PROVES to be a singleton is equally finished
/// with but was written to `nfts`/`dids` instead; and a coin whose row a reorg removed mid-read
/// reached no verdict at all and must not be recorded as either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Promotion {
    /// The parent spend proves the coin, and it is now in `coins`.
    Promoted,
    /// The parent spend proves the coin is an owned NFT or DID, now in `nfts`/`dids`. Terminal,
    /// and a SUCCESS — distinct from `Disproven`, which is a refutation.
    Resolved,
    /// The parent spend was read and does not support the claim. Terminal.
    Disproven,
    /// The staged row was gone by the time the write ran — a reorg rollback inside the read.
    Vanished,
}

/// Admit a proven NFT/DID singleton to its own table, if this wallet owns it.
///
/// The ownership test is the SAME one an unpredicted CAT gets: the reconstruction's own inner p2
/// hash must be one the wallet controls. Without it a hint would be enough to make the wallet
/// display a stranger's NFT as its own — the hint is attacker-controlled, and the reconstruction is
/// the only thing that says who the singleton actually belongs to.
///
/// A singleton owned by somebody else is `Disproven`: the claim that staged it was "this coin is
/// for me", and the parent spend refutes exactly that claim.
async fn promote_singleton(
    db: &WalletDb,
    row: &StagedCatRow,
    reconstructed_owner_p2: &str,
    owned_p2: &HashSet<String>,
    singleton: PromotedSingleton<'_>,
) -> Result<Promotion> {
    if !owned_p2.contains(&reconstructed_owner_p2.to_ascii_lowercase()) {
        tracing::warn!(
            coin_id = %row.coin_id,
            "singleton promotion: the parent spend proves the coin is owned by another p2 hash; refusing"
        );
        return Ok(Promotion::Disproven);
    }
    Ok(
        if db
            .promote_singleton_admission(&row.coin_id, &singleton)
            .await?
        {
            Promotion::Resolved
        } else {
            Promotion::Vanished
        },
    )
}

/// Decide and apply one coin's promotion.
async fn promote_one(
    db: &WalletDb,
    prefix: &str,
    row: &StagedCatRow,
    parent: &super::singleton::ParentSpend,
    owned_p2: &HashSet<String>,
) -> Result<Promotion> {
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
        return Ok(Promotion::Disproven);
    }
    let reconstructed =
        singleton::reconstruct(prefix, row.created_height.map(|h| h as u32), parent, child)?;
    let (coin_id, asset_id, hint) = match reconstructed {
        Reconstructed::Cat {
            coin_id,
            asset_id,
            hint,
        } => (coin_id, asset_id, hint),
        // PROVEN, BUT NOT A CAT (dig-node#394). An NFT or DID singleton reached the same proof by
        // the same machinery — the parent spend reconstructs THIS coin id as that singleton — so it
        // is admissible by the same standard; it simply belongs in a different table.
        //
        // Refusing it here would conflate two verdicts that must never share an outcome: "the
        // derivation was a lie" is a security finding, while "the derivation was true and about
        // something this function does not handle" is a routing gap. Treating the second as the
        // first deleted the row terminally, and since the point-read tier is the only production
        // path that reaches `reconstruct_all`, it silently emptied the wallet's NFTs and DIDs and
        // re-paid the chain read for each of them on every refresh.
        Reconstructed::Nft { row: nft, owner_p2 } => {
            return promote_singleton(db, row, &owner_p2, owned_p2, PromotedSingleton::Nft(&nft))
                .await;
        }
        Reconstructed::Did { row: did, owner_p2 } => {
            return promote_singleton(db, row, &owner_p2, owned_p2, PromotedSingleton::Did(&did))
                .await;
        }
        // A plain XCH coin, or a shape no driver recognises. The read succeeded and produced no
        // claim this coin is anything the wallet may hold, so the hint that staged it is refuted.
        Reconstructed::Unknown => return Ok(Promotion::Disproven),
    };
    // The reconstruction must agree on BOTH halves — which coin, and whose. Checking only the
    // asset id would admit a real CAT of the right asset owned by somebody else; checking only the
    // owner would admit a CAT of a different asset counted as this one. Both are money-visible.
    //
    // WHAT "AGREE" MEANS DEPENDS ON WHETHER ANYTHING WAS PREDICTED (dig-node#394). A coin found at
    // a DERIVED hash arrives with a predicted (asset, owner) pair, and the reconstruction must
    // match that pair exactly — the derivation said where to look, and a coin that turns out to be
    // something else is disproven. A coin found by HINT arrives with no prediction: nothing was
    // derived, so there is nothing to match against, and the row carries the empty sentinel.
    //
    // The proof is equally strong in both cases, because it is the same proof: the parent spend
    // reconstructs this coin id as a CAT of asset A hinted to p2 H. When H is one of the wallet's
    // own p2 hashes, that IS "this coin is a unit of asset A and only this wallet can spend it" —
    // which is the entire claim being made. The predicted case additionally checks that the
    // derivation was not lying about which asset it expected.
    let asset_agrees =
        row.derived_asset_id.is_empty() || asset_id.eq_ignore_ascii_case(&row.derived_asset_id);
    let owner_agrees = if row.derived_owner_p2.is_empty() {
        // Unpredicted: the reconstruction's own hint must name an address this wallet controls.
        // Without this the hint would be attacker-controlled all the way to `coins`, which is the
        // defect being fixed rather than a smaller version of it.
        owned_p2.contains(&hint.to_ascii_lowercase())
    } else {
        hint.eq_ignore_ascii_case(&row.derived_owner_p2)
    };
    let agrees = coin_id.eq_ignore_ascii_case(&row.coin_id) && asset_agrees && owner_agrees;
    if !agrees {
        tracing::warn!(
            coin_id = %row.coin_id,
            reconstructed_asset = %asset_id,
            derived_asset = %row.derived_asset_id,
            "cat promotion: the parent spend disagrees with the derivation; refusing"
        );
        return Ok(Promotion::Disproven);
    }
    // Attributed from the RECONSTRUCTION's own values, which is the whole content of the proof.
    Ok(if db.promote_cat_admission(row, &asset_id, &hint).await? {
        Promotion::Promoted
    } else {
        Promotion::Vanished
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sage::db::{CoinRow, CAT_ADMISSION_PENDING_MAX_ROWS};
    use crate::sage::singleton::ParentSpend;
    use chia_sdk_test::Simulator;
    use chia_wallet_sdk::driver::{
        Cat as SdkCat, CatSpend, SpendContext, SpendWithConditions, StandardLayer,
    };
    use chia_wallet_sdk::types::Conditions;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A real CAT coin owned by a real key, with the parent spend that proves it.
    struct CatFixture {
        asset_id: Bytes32,
        owner_p2: Bytes32,
        child: Coin,
        parent: ParentSpend,
        amount: u64,
    }

    /// Issue a CAT, spend it once, and hand back the child coin plus its parent's spend.
    ///
    /// The child is what a wallet actually receives: a CAT whose PARENT is itself a CAT, which is
    /// the only shape `Cat::parse_children` can reconstruct. Its amount is deliberately not round
    /// so an assertion cannot pass against a hard-coded default.
    fn real_cat() -> CatFixture {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();
        let alice = sim.bls(1000);
        let alice_p2 = StandardLayer::new(alice.pk);
        let memos = ctx.hint(alice.puzzle_hash).unwrap();
        let (issue, cats) = SdkCat::single_issuance(
            ctx,
            alice.coin.coin_id(),
            None,
            1000,
            Conditions::new().create_coin(alice.puzzle_hash, 1000, memos),
        )
        .unwrap();
        alice_p2.spend(ctx, alice.coin, issue).unwrap();
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
        let child = cat0.child(alice.puzzle_hash, 1000);
        let parent = ParentSpend {
            coin: cat0.coin,
            puzzle_reveal: sim
                .puzzle_reveal(cat0.coin.coin_id())
                .expect("parent puzzle reveal")
                .to_vec(),
            solution: sim
                .solution(cat0.coin.coin_id())
                .expect("parent solution")
                .to_vec(),
        };
        CatFixture {
            asset_id: cat0.info.asset_id,
            owner_p2: alice.puzzle_hash,
            child: child.coin,
            parent,
            amount: 1000,
        }
    }

    /// The wallet's own p2 hashes, for the tests whose staged rows all carry a PREDICTED owner.
    ///
    /// Empty on purpose, and only sound because of that precondition: `owned_p2` is consulted
    /// solely on the unpredicted branch, so an empty set here cannot make a predicted-row test
    /// pass for the wrong reason. The unpredicted branch has its own fixture with a real set --
    /// see `an_unpredicted_hinted_coin_promotes_only_to_an_address_we_control`, without which this
    /// helper would be exactly the uniform-fixture collapse this family keeps paying for.
    fn owned() -> HashSet<String> {
        HashSet::new()
    }

    /// What a MISS from [`CountingLineage`] means. Named rather than left implicit because the
    /// two are different chain facts that `Option<ParentSpend>` could not tell apart: `Absent` is
    /// "the sources agree there is no such spend", `Unavailable` is "nothing could be learned".
    ///
    /// The field exists so a double is not forced to pick one and pretend it is both. A fixture
    /// map cannot know which a missing key represents, so it has to say -- and a double that can
    /// only express one of production's two miss modes makes every test over it a partial green
    /// (see [`LineageAnswer::from_lookup`]).
    #[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
    enum Miss {
        /// Nothing could be learned. The default, because it is the WEAKER claim: a double that
        /// silently asserted a settled absence would let a test read a deferral as a disproof.
        #[default]
        Unavailable,
        /// The sources agree there is no such spend.
        Absent,
    }

    /// A [`LineageSource`] over a fixed parent map, which COUNTS its reads and can be told to fail
    /// for one specific parent.
    ///
    /// The failure is scoped to a single parent on purpose. A source that fails for EVERYTHING is
    /// the blindest possible fixture for a denial test: with no honest answer left anywhere, a
    /// pass that skipped the whole table and a pass that handled the error correctly are
    /// indistinguishable. One hostile actor beside a truthful control is what makes them differ.
    #[derive(Default)]
    struct CountingLineage {
        by_parent: HashMap<String, ParentSpend>,
        reads: AtomicUsize,
        fail_for: Option<String>,
        /// What a parent absent from `by_parent` reports. See [`Miss`].
        miss: Miss,
    }

    impl CountingLineage {
        fn reads(&self) -> usize {
            self.reads.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl LineageSource for CountingLineage {
        async fn parent_spend(
            &self,
            parent_coin_id: &str,
            _spent_height: u32,
        ) -> Result<LineageAnswer> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            if self.fail_for.as_deref() == Some(parent_coin_id) {
                return Err(crate::sage::Error::internal("parent unreadable"));
            }
            Ok(LineageAnswer::from_lookup(
                self.by_parent.get(parent_coin_id).cloned(),
                match self.miss {
                    Miss::Unavailable => LineageAnswer::Unavailable,
                    Miss::Absent => LineageAnswer::Absent,
                },
            ))
        }
    }

    fn state(coin: Coin, created: Option<u32>, spent: Option<u32>) -> CoinState {
        CoinState {
            coin,
            created_height: created,
            spent_height: spent,
        }
    }

    /// A coin ANYONE can make: it sits at the derived hash and its parent is a nobody.
    ///
    /// The whole attack, in one value. Nothing about constructing it needs a key, a peer, or any
    /// relationship to the victim beyond their public address.
    fn fabricated_at(derived_hash: Bytes32, amount: u64, parent: u8) -> Coin {
        Coin {
            parent_coin_info: Bytes32::new([parent; 32]),
            puzzle_hash: derived_hash,
            amount,
        }
    }

    /// THE DISCOVERY CLAIM, asserted rather than assumed: a genuine CAT coin owned by this wallet
    /// really does sit at the hash the derivation predicts.
    ///
    /// If this were false, discovery would subscribe hashes no coin ever arrives at and every
    /// other test here would pass vacuously while the feature did nothing.
    #[test]
    fn the_derivation_predicts_where_a_real_cat_coin_sits() {
        let f = real_cat();
        let derived = DerivedCats::derive(&[f.owner_p2], &[f.asset_id]);
        assert_eq!(
            derived.owner_of(&f.child.puzzle_hash),
            Some(DerivedOwner {
                asset_id: f.asset_id,
                owner_p2: f.owner_p2,
            }),
            "a real CAT coin must sit at the hash the wallet derives for it"
        );
    }

    /// **TEST 1 — fixes #380.** A CAT coin arriving from a peer reaches the wallet and the balance
    /// is right.
    ///
    /// Load-bearing against `origin/main`: there, the coin's puzzle hash is not in `subscribed`, so
    /// `apply_coin_states` drops it and the balance stays 0. This is the whole starvation.
    #[tokio::test]
    async fn a_real_cat_coin_arrives_is_promoted_and_is_counted() {
        let f = real_cat();
        let db = WalletDb::open_in_memory().await.unwrap();
        let derived = DerivedCats::derive(&[f.owner_p2], &[f.asset_id]);
        let asset_hex = hex::encode(f.asset_id);

        let rows = stage_from_states(&[state(f.child, Some(10), None)], &derived, |_| false);
        db.stage_cat_admissions(&rows).await.unwrap();
        assert_eq!(db.staged_cat_admission_count().await.unwrap(), 1);
        // Not yet believed: discovery alone buys nothing.
        assert_eq!(db.balance(Some(&asset_hex)).await.unwrap(), 0);

        let mut lineage = CountingLineage::default();
        lineage
            .by_parent
            .insert(hex::encode(f.child.parent_coin_info), f.parent.clone());
        let stats = promote_staged_cats(&db, &lineage, &owned()).await.unwrap();

        assert_eq!(stats.promoted, 1, "{stats:?}");
        assert_eq!(db.staged_cat_admission_count().await.unwrap(), 0);
        assert_eq!(
            db.balance(Some(&asset_hex)).await.unwrap(),
            u128::from(f.amount),
            "the promoted coin must be counted as its own asset"
        );
    }

    /// **TEST 5 — a fabricated coin never enters `coins`.**
    ///
    /// Two actors, and that is the point. The fabricated coin alone would let a filter placed at
    /// the WRONG layer — one that drops every derived-hash coin outright — satisfy "coins is
    /// empty" identically, pinning a coincidence rather than the property. The real CAT beside it
    /// is the truthful control: any implementation that keeps the attacker out by refusing
    /// everyone fails here, visibly.
    #[tokio::test]
    async fn a_fabricated_coin_is_refused_while_a_real_one_is_promoted() {
        let f = real_cat();
        let db = WalletDb::open_in_memory().await.unwrap();
        let derived = DerivedCats::derive(&[f.owner_p2], &[f.asset_id]);
        let asset_hex = hex::encode(f.asset_id);
        // Larger than the real coin, so a largest-first coin selector would prefer it -- the
        // send kill-switch this test exists to make unreachable.
        let fake = fabricated_at(f.child.puzzle_hash, 999_999_999, 0xAB);

        let rows = stage_from_states(
            &[state(f.child, Some(10), None), state(fake, Some(11), None)],
            &derived,
            |_| false,
        );
        assert_eq!(
            rows.len(),
            2,
            "both coins are DISCOVERED; neither is believed"
        );
        db.stage_cat_admissions(&rows).await.unwrap();

        let mut lineage = CountingLineage::default();
        lineage
            .by_parent
            .insert(hex::encode(f.child.parent_coin_info), f.parent.clone());
        // The fabricated coin's parent is readable and is simply not a CAT spend: `Ok(None)` from
        // the map would mean UNAVAILABLE, so give it a real, honest, non-CAT parent answer by
        // pointing it at the same map -- absent means unavailable, which would leave it staged
        // rather than refused. Use the real parent spend, which reconstructs no child matching it.
        lineage
            .by_parent
            .insert(hex::encode(fake.parent_coin_info), f.parent.clone());

        let stats = promote_staged_cats(&db, &lineage, &owned()).await.unwrap();
        assert_eq!(stats.promoted, 1, "{stats:?}");
        assert_eq!(stats.refused, 1, "{stats:?}");

        // The believed set contains the real coin and ONLY the real coin.
        let believed: Vec<CoinRow> = db.all_coins().await.unwrap();
        assert_eq!(believed.len(), 1);
        assert_eq!(believed[0].coin_id, hex::encode(f.child.coin_id()));
        assert_eq!(
            db.balance(Some(&asset_hex)).await.unwrap(),
            u128::from(f.amount),
            "the fabricated amount must not appear in the balance"
        );
        // And it is gone, not merely hidden: nothing will ever promote it later.
        assert_eq!(db.staged_cat_admission_count().await.unwrap(), 0);
    }

    /// **TEST 4 — the failure mode is incompleteness, never a wrong figure.**
    ///
    /// A staged coin must be ABSENT: not counted as its asset, and — the round-5 defect — not
    /// counted as XCH either, because `asset_id IS NULL` MEANS XCH and feeds the spend-input
    /// selector. Both directions are asserted separately; asserting only the CAT balance would
    /// pass against an implementation that admitted the coin untyped.
    #[tokio::test]
    async fn an_unpromoted_coin_is_absent_from_both_balances_and_from_selection() {
        let f = real_cat();
        let db = WalletDb::open_in_memory().await.unwrap();
        let derived = DerivedCats::derive(&[f.owner_p2], &[f.asset_id]);

        let rows = stage_from_states(&[state(f.child, Some(10), None)], &derived, |_| false);
        db.stage_cat_admissions(&rows).await.unwrap();
        // A source that can read nothing at all: every coin stays staged.
        let stats = promote_staged_cats(&db, &CountingLineage::default(), &owned())
            .await
            .unwrap();
        assert_eq!(stats.deferred, 1, "{stats:?}");
        assert_eq!(db.staged_cat_admission_count().await.unwrap(), 1);

        assert_eq!(
            db.balance(Some(&hex::encode(f.asset_id))).await.unwrap(),
            0,
            "an unproven coin must be absent from its asset's balance"
        );
        assert_eq!(
            db.balance(None).await.unwrap(),
            0,
            "an unproven coin must NOT be counted as XCH"
        );
        assert!(
            db.unspent_coins(None).await.unwrap().is_empty(),
            "an unproven coin must never reach the spend-input selector"
        );
    }

    /// **TEST 3 — no denial.** A parent read that FAILS must not fail the pass.
    ///
    /// One hostile actor, one truthful control: the real coin's parent reads fine and is promoted
    /// in the same pass whose other coin errors. A fixture where every read failed could not tell
    /// "handled the error" from "did no work at all".
    #[tokio::test]
    async fn a_failing_parent_read_neither_ends_the_pass_nor_deletes_the_coin() {
        let f = real_cat();
        let db = WalletDb::open_in_memory().await.unwrap();
        let derived = DerivedCats::derive(&[f.owner_p2], &[f.asset_id]);
        let hostile = fabricated_at(f.child.puzzle_hash, 7, 0xCD);

        let rows = stage_from_states(
            &[
                state(hostile, Some(9), None),
                state(f.child, Some(10), None),
            ],
            &derived,
            |_| false,
        );
        db.stage_cat_admissions(&rows).await.unwrap();

        let mut lineage = CountingLineage {
            fail_for: Some(hex::encode(hostile.parent_coin_info)),
            ..Default::default()
        };
        lineage
            .by_parent
            .insert(hex::encode(f.child.parent_coin_info), f.parent.clone());

        let stats = promote_staged_cats(&db, &lineage, &owned())
            .await
            .expect("a failing parent read must not fail the whole pass");
        assert_eq!(
            stats.promoted, 1,
            "the honest coin is still promoted: {stats:?}"
        );
        assert_eq!(stats.deferred, 1, "{stats:?}");
        // Left staged, NOT deleted: an unreadable answer is not a disproof, and deleting on one
        // would let a peer that withholds parent spends erase real money.
        assert_eq!(db.staged_cat_admission_count().await.unwrap(), 1);
    }

    /// **TEST 2 — the read is bounded, terminal, and non-zero.**
    ///
    /// The calibration comes FIRST and is not decoration: a counter that was never attached to the
    /// code under test reports zero reads just as convincingly as a correct implementation, and
    /// that exact mistake was made three times on this PR family. So the counter is proven able to
    /// move before any zero it produces is believed.
    #[tokio::test]
    async fn promotion_reads_are_bounded_and_never_repeated() {
        let f = real_cat();
        let db = WalletDb::open_in_memory().await.unwrap();
        let derived = DerivedCats::derive(&[f.owner_p2], &[f.asset_id]);

        // CALIBRATION: the counter can go non-zero through exactly this path.
        let mut lineage = CountingLineage::default();
        lineage
            .by_parent
            .insert(hex::encode(f.child.parent_coin_info), f.parent.clone());
        let real = stage_from_states(&[state(f.child, Some(10), None)], &derived, |_| false);
        db.stage_cat_admissions(&real).await.unwrap();
        promote_staged_cats(&db, &lineage, &owned()).await.unwrap();
        assert_eq!(
            lineage.reads(),
            1,
            "the counter must be able to move at all"
        );

        // One over the per-pass cap, so the bound is pinned from BOTH sides in one run: the pass
        // must read exactly the cap, and must NOT read the extra coin.
        let over = usize::try_from(MAX_CAT_PROMOTIONS_PER_PASS).unwrap() + 1;
        let extra: Vec<CoinState> = (0..over)
            .map(|i| {
                state(
                    fabricated_at(f.child.puzzle_hash, 1_000 + i as u64, 0x40),
                    Some(20 + i as u32),
                    None,
                )
            })
            .collect();
        let rows = stage_from_states(&extra, &derived, |_| false);
        assert_eq!(rows.len(), over);
        db.stage_cat_admissions(&rows).await.unwrap();

        let before = lineage.reads();
        let stats = promote_staged_cats(&db, &lineage, &owned()).await.unwrap();
        let first_pass = lineage.reads() - before;
        assert_eq!(
            first_pass,
            usize::try_from(MAX_CAT_PROMOTIONS_PER_PASS).unwrap(),
            "one pass must read exactly the cap, never the whole backlog"
        );
        // None of them promotes: their parents are unknown to the map, which answers "unavailable"
        // rather than "not a CAT", so they stay staged rather than being refused.
        assert_eq!(stats.promoted, 0, "{stats:?}");

        // NOT REPEATED — the property this test is named for, and which it did not previously
        // assert. An earlier version settled for `second <= cap`, which is satisfied by the
        // defect: every one of those rows WAS re-read on every pass, for ever, because a deferred
        // row was eligible again immediately. With the retry cooldown the correct number is zero,
        // and zero is what distinguishes a bounded queue from an unbounded one.
        let before = lineage.reads();
        promote_staged_cats(&db, &lineage, &owned()).await.unwrap();
        let second = lineage.reads() - before;
        // EXACTLY ONE, and the number is the assertion. `over` is one past the per-pass cap, so
        // after pass one there is precisely one row that has never been read; the other 64 are
        // inside their retry cooldown. So the second pass reads the new row and RE-reads nothing.
        // Zero would be wrong -- it would mean a row that had never been tried was skipped -- and
        // any number above one means the defect is back.
        assert_eq!(
            second, 1,
            "a second pass may read only the row that has never been read, and must re-read none              of the rows it already tried"
        );
        assert!(
            !db.all_coins()
                .await
                .unwrap()
                .iter()
                .any(|c| c.coin_id != hex::encode(f.child.coin_id())),
            "no unproven coin may have entered `coins` at any point"
        );
    }

    /// **Proves (dig-node#394, gate finding 2):** a wall of unresolvable staged coins cannot starve
    /// an honest one out of the promotion queue.
    ///
    /// THE BUG THIS PINS. A promotion that cannot read its parent leaves the row staged, on
    /// purpose — deleting it would let a source that is merely behind erase real money. The queue
    /// was served `ORDER BY seq ASC LIMIT 64`, so exactly 64 coins with invented parents occupied
    /// the head permanently: every pass re-read the same 64, the read count climbed 64, 128, 192
    /// without bound, and the honest coin sitting behind them was never reached. The gate
    /// reproduced it at ten passes with the victim's $DIG balance still zero. The whole primitive
    /// costs 64 mojos and needs only the victim's public address.
    ///
    /// FIXTURE DESIGN — the honest coin is the point. A fixture in which EVERY staged coin is
    /// unresolvable is the blindest possible one for this defect: with nothing left that could
    /// promote, a starved queue and a healthy one produce identical output. So the wall is exactly
    /// `MAX_CAT_PROMOTIONS_PER_PASS` coins, staged FIRST so they own the head under the old
    /// ordering, and one real simulator-built CAT is staged behind them as the truthful control.
    /// The assertion is that the control promotes — which is false under the old ordering for any
    /// number of passes, and true here on the second.
    #[tokio::test]
    async fn a_wall_of_unresolvable_coins_cannot_starve_an_honest_one() {
        let f = real_cat();
        let db = WalletDb::open_in_memory().await.unwrap();
        let derived = DerivedCats::derive(&[f.owner_p2], &[f.asset_id]);
        let mut lineage = CountingLineage::default();
        lineage
            .by_parent
            .insert(hex::encode(f.child.parent_coin_info), f.parent.clone());

        // The wall: exactly one pass's worth, so it fills the head and nothing more. Their parents
        // are absent from the map, which is the "unresolvable" answer.
        let wall = usize::try_from(MAX_CAT_PROMOTIONS_PER_PASS).unwrap();
        let poisoned: Vec<CoinState> = (0..wall)
            .map(|i| {
                state(
                    fabricated_at(f.child.puzzle_hash, 1_000 + i as u64, 0x40),
                    Some(20 + i as u32),
                    None,
                )
            })
            .collect();
        let rows = stage_from_states(&poisoned, &derived, |_| false);
        assert_eq!(rows.len(), wall, "the wall must actually stage");
        db.stage_cat_admissions(&rows).await.unwrap();

        // The honest coin, staged BEHIND the wall — the position that made it unreachable.
        let honest = stage_from_states(&[state(f.child, Some(10), None)], &derived, |_| false);
        assert_eq!(honest.len(), 1);
        db.stage_cat_admissions(&honest).await.unwrap();

        // Pass one spends its whole budget on the wall, exactly as before the fix.
        let first = promote_staged_cats(&db, &lineage, &owned()).await.unwrap();
        assert_eq!(first.promoted, 0, "the wall owns the head on pass one");
        assert_eq!(
            usize::try_from(first.deferred).unwrap(),
            wall,
            "and consumes the whole budget: {first:?}"
        );

        // Pass two is the one the old ordering could never reach. The wall has been read once and
        // is inside its cooldown; the honest coin has never been read, so it is served.
        let before = lineage.reads();
        let second = promote_staged_cats(&db, &lineage, &owned()).await.unwrap();
        assert_eq!(
            second.promoted, 1,
            "an honest coin behind a wall of unresolvable ones must still promote: {second:?}"
        );
        assert_eq!(
            lineage.reads() - before,
            1,
            "and the wall must not be re-read while it is inside its cooldown"
        );

        // The money answer, concretely: the honest coin's own amount, and nothing the wall claimed.
        assert_eq!(
            db.balance(Some(&hex::encode(f.asset_id))).await.unwrap(),
            u128::from(f.amount),
            "the promoted CAT must be counted, and only it"
        );
        assert_eq!(
            db.balance(None).await.unwrap(),
            0u128,
            "and nothing staged may ever be counted as XCH"
        );
    }

    /// **Proves (dig-node#394):** the promotion queue is ordered by ATTEMPTS before arrival, and a
    /// row inside its retry cooldown is not served at all.
    ///
    /// The mechanism under the test above, asserted directly so a regression names itself. Time is
    /// PINNED to an explicit `NOW` rather than taken from the clock: `staged_cat_admissions` takes
    /// its cutoff as a parameter precisely so a test can choose one, and a fixture that passed a
    /// small number through a wall-clock comparison would place every row roughly 1.8 billion
    /// seconds in the past and assert the expired path while claiming to test the fresh one.
    #[tokio::test]
    async fn the_queue_serves_fewest_attempts_first_and_honours_the_cooldown() {
        const NOW: i64 = 1_800_000_000;
        const COOLDOWN: i64 = 3_600;
        let cutoff = NOW - COOLDOWN;

        let f = real_cat();
        let db = WalletDb::open_in_memory().await.unwrap();
        let derived = DerivedCats::derive(&[f.owner_p2], &[f.asset_id]);
        let states: Vec<CoinState> = (0..3)
            .map(|i| {
                state(
                    fabricated_at(f.child.puzzle_hash, 500 + i as u64, 0x50),
                    Some(30 + i as u32),
                    None,
                )
            })
            .collect();
        let rows = stage_from_states(&states, &derived, |_| false);
        assert_eq!(rows.len(), 3);
        db.stage_cat_admissions(&rows).await.unwrap();
        let first_id = rows[0].coin_id.clone();
        let last_id = rows[2].coin_id.clone();

        // Arrival order, with nothing attempted yet.
        let queue = db.staged_cat_admissions(3, cutoff).await.unwrap();
        assert_eq!(
            queue[0].coin_id, first_id,
            "an untried queue is served in arrival order"
        );

        // The head is read, LONG ago — outside the cooldown, so it stays eligible.
        db.record_promotion_attempt(&first_id, cutoff - 1)
            .await
            .unwrap();
        let queue = db.staged_cat_admissions(3, cutoff).await.unwrap();
        assert_eq!(queue.len(), 3, "a row outside its cooldown is still served");
        assert_ne!(
            queue[0].coin_id, first_id,
            "but it must have SUNK: a row that has been tried never precedes one that has not"
        );
        assert_eq!(
            queue[2].coin_id, first_id,
            "specifically, to the back of the queue"
        );

        // Read again, this time RECENTLY. Now the cooldown excludes it outright.
        db.record_promotion_attempt(&first_id, NOW).await.unwrap();
        let queue = db.staged_cat_admissions(3, cutoff).await.unwrap();
        assert_eq!(
            queue.len(),
            2,
            "a row read inside its cooldown must not be served at all"
        );
        assert!(
            queue.iter().all(|r| r.coin_id != first_id),
            "and it is that row that is missing"
        );

        // AT the boundary, the row is eligible again: pinned from both sides, so a cutoff
        // comparison that drifted by one would fail here rather than pass quietly.
        db.record_promotion_attempt(&last_id, cutoff).await.unwrap();
        let queue = db.staged_cat_admissions(3, cutoff).await.unwrap();
        assert!(
            queue.iter().any(|r| r.coin_id == last_id),
            "a row last read exactly AT the cutoff is eligible"
        );
    }

    /// **Proves (dig-node#394):** an UNPREDICTED staged coin — one found by hint, with no derived
    /// pair to check against — promotes only when the parent spend hints it to an address this
    /// wallet actually controls.
    ///
    /// THE RISK THIS PINS. A coin found by hint carries no prediction, so the asset-id and owner
    /// comparisons the derived path relies on have nothing to compare with. If that branch simply
    /// skipped the owner check, the hint would reach `coins` attacker-controlled — the whole of
    /// #394, moved one layer inwards rather than fixed.
    ///
    /// FIXTURE DESIGN — the same coin, twice, with ONE thing varied. The lineage source, the
    /// staged row, the reconstruction and the asset are identical across both halves; only the
    /// set of addresses the wallet claims to control differs. So a pass cannot be explained by
    /// anything except the owner check, and an implementation that ignored `owned_p2` fails the
    /// second half while still passing the first.
    #[tokio::test]
    async fn an_unpredicted_hinted_coin_promotes_only_to_an_address_we_control() {
        let f = real_cat();
        let mut lineage = CountingLineage::default();
        lineage
            .by_parent
            .insert(hex::encode(f.child.parent_coin_info), f.parent.clone());

        // The staged row as the HINT path builds it: both derived fields empty, because nothing
        // was predicted. Everything else is the real coin.
        let unpredicted = StagedCatRow {
            coin_id: hex::encode(f.child.coin_id()),
            parent_coin_info: hex::encode(f.child.parent_coin_info),
            puzzle_hash: hex::encode(f.child.puzzle_hash),
            amount: f.child.amount.to_string(),
            created_height: Some(10),
            spent_height: None,
            created_timestamp: None,
            spent_timestamp: None,
            derived_asset_id: String::new(),
            derived_owner_p2: String::new(),
        };

        // HALF ONE — the wallet controls the address the parent spend hints to.
        let db = WalletDb::open_in_memory().await.unwrap();
        db.stage_cat_admissions(std::slice::from_ref(&unpredicted))
            .await
            .unwrap();
        let ours: HashSet<String> = [hex::encode(f.owner_p2)].into_iter().collect();
        let stats = promote_staged_cats(&db, &lineage, &ours).await.unwrap();
        assert_eq!(
            stats.promoted, 1,
            "a hinted coin whose parent proves it ours must promote: {stats:?}"
        );
        assert_eq!(
            db.balance(Some(&hex::encode(f.asset_id))).await.unwrap(),
            u128::from(f.amount),
            "and be counted under the asset the PARENT SPEND named, not one anybody claimed"
        );

        // HALF TWO — the identical coin, the identical proof, and the one varied thing: this
        // wallet does not control the address it is hinted to.
        let db = WalletDb::open_in_memory().await.unwrap();
        db.stage_cat_admissions(std::slice::from_ref(&unpredicted))
            .await
            .unwrap();
        let stranger: HashSet<String> = [hex::encode(Bytes32::new([0x77; 32]))]
            .into_iter()
            .collect();
        let stats = promote_staged_cats(&db, &lineage, &stranger).await.unwrap();
        assert_eq!(
            stats.refused, 1,
            "a hinted coin belonging to somebody else must be REFUSED: {stats:?}"
        );
        assert_eq!(stats.promoted, 0);
        assert_eq!(
            db.all_coins().await.unwrap().len(),
            0,
            "and must not reach `coins` by any route"
        );
    }

    /// A coin that has already cleared promotion is NOT re-staged: its later states, a spend above
    /// all, must update `coins` normally.
    ///
    /// Without this a promoted coin stays unspent in the replica for ever and is selected again
    /// after it was spent — a double-spend attempt built out of the wallet's own bookkeeping.
    #[test]
    fn an_already_promoted_coin_is_routed_to_coins_not_back_into_staging() {
        let f = real_cat();
        let derived = DerivedCats::derive(&[f.owner_p2], &[f.asset_id]);
        let promoted = hex::encode(f.child.coin_id());
        let rows = stage_from_states(&[state(f.child, Some(10), Some(11))], &derived, |id| {
            id == promoted
        });
        assert!(
            rows.is_empty(),
            "a believed coin must never be pushed back into the staging table"
        );
    }

    /// The staging bound DELAYS; it never errors — pinned from both sides.
    ///
    /// A staging insert sits on the peer frame path, so a bound that could refuse would hand a
    /// peer able to fill the table a way to fail a frame, and a peer that can fail a frame can
    /// deny a catch-up. Eviction is oldest-first, which is also recoverable: a re-pushed coin
    /// re-stages.
    #[tokio::test]
    async fn the_staging_bound_evicts_the_oldest_and_never_errors() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let f = real_cat();
        let derived = DerivedCats::derive(&[f.owner_p2], &[f.asset_id]);
        let cap = usize::try_from(CAT_ADMISSION_PENDING_MAX_ROWS).unwrap();

        // AT the bound: everything is kept.
        let at: Vec<CoinState> = (0..cap)
            .map(|i| {
                state(
                    fabricated_at(f.child.puzzle_hash, 1 + i as u64, 0x11),
                    Some(1),
                    None,
                )
            })
            .collect();
        let rows = stage_from_states(&at, &derived, |_| false);
        db.stage_cat_admissions(&rows).await.unwrap();
        assert_eq!(
            db.staged_cat_admission_count().await.unwrap(),
            CAT_ADMISSION_PENDING_MAX_ROWS
        );
        let oldest = rows[0].coin_id.clone();

        // ONE OVER: still `Ok`, still exactly the bound, and the OLDEST is the one that went.
        let over = stage_from_states(
            &[state(
                fabricated_at(f.child.puzzle_hash, 9_999_999, 0x22),
                Some(2),
                None,
            )],
            &derived,
            |_| false,
        );
        db.stage_cat_admissions(&over)
            .await
            .expect("the bound must delay, never error");
        assert_eq!(
            db.staged_cat_admission_count().await.unwrap(),
            CAT_ADMISSION_PENDING_MAX_ROWS
        );
        let held = db
            .staged_cat_admissions(CAT_ADMISSION_PENDING_MAX_ROWS, i64::MAX)
            .await
            .unwrap();
        assert!(
            !held.iter().any(|r| r.coin_id == oldest),
            "eviction must take the OLDEST row, not the newest"
        );
    }

    /// A reorg unmakes a staged observation with the coin it describes — and only above the fork.
    ///
    /// Both sides asserted: a row above the fork goes, a row at or below it stays. Asserting only
    /// the deletion would pass against an implementation that emptied the whole table.
    #[tokio::test]
    async fn a_reorg_deletes_staged_rows_above_the_fork_and_keeps_the_rest() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let f = real_cat();
        let derived = DerivedCats::derive(&[f.owner_p2], &[f.asset_id]);
        let below = fabricated_at(f.child.puzzle_hash, 1, 0x31);
        let above = fabricated_at(f.child.puzzle_hash, 2, 0x32);
        let rows = stage_from_states(
            &[state(below, Some(100), None), state(above, Some(200), None)],
            &derived,
            |_| false,
        );
        db.stage_cat_admissions(&rows).await.unwrap();

        db.rollback_above(150).await.unwrap();

        let held = db.staged_cat_admissions(100, i64::MAX).await.unwrap();
        assert_eq!(held.len(), 1, "only the row above the fork is unmade");
        assert_eq!(held[0].coin_id, hex::encode(below.coin_id()));
    }

    /// A `CoinRow` as the point-read tier materialises one from a coin record.
    fn coin_row_of(c: Coin, height: i64) -> CoinRow {
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

    /// The staged row the HINT path builds for a real CAT: both derived fields empty, because
    /// nothing was predicted about it.
    fn staged_row_of(f: &CatFixture) -> StagedCatRow {
        StagedCatRow {
            coin_id: hex::encode(f.child.coin_id()),
            parent_coin_info: hex::encode(f.child.parent_coin_info),
            puzzle_hash: hex::encode(f.child.puzzle_hash),
            amount: f.child.amount.to_string(),
            created_height: Some(10),
            spent_height: None,
            created_timestamp: None,
            spent_timestamp: None,
            derived_asset_id: String::new(),
            derived_owner_p2: String::new(),
        }
    }

    /// THE POINT-READ TIER MUST NOT DELETE THE WALLET'S NFTs AND DIDs (dig-node#394).
    ///
    /// An NFT or DID coin sits at a SINGLETON puzzle hash — never one of the wallet's own p2
    /// hashes — and is hinted to the owner, so the point-read tier stages it exactly as it stages
    /// an unpredicted CAT. Promotion then reconstructs it correctly as a singleton, which is not a
    /// CAT; an outcome set with no place for that verdict refused it, and the refusal is TERMINAL.
    /// Since this tier is the only production path that reaches `reconstruct_all`, that silently
    /// emptied `nfts`/`dids` and re-paid the chain read for every singleton on every refresh.
    ///
    /// FIXTURE DESIGN — production routing, and nothing beneath it. The rows go through
    /// [`route_point_read_rows`] and [`promote_staged_cats`], the two functions the point-read tier
    /// actually calls, because the defect lives in the seam BETWEEN them: a test that injected with
    /// `db.upsert_coin` (as `singleton::tests` does) sits one layer below the narrowing and stays
    /// green whether or not the narrowing eats the coin — which is precisely why nothing caught
    /// this. Both singleton kinds are present rather than one, because NFT and DID reconstruct
    /// through different driver calls and a fix handling only one would still pass with either
    /// alone.
    #[tokio::test]
    async fn an_owned_nft_and_did_survive_the_point_read_tier() {
        let m = crate::sage::singleton::tests::mint_did_and_nft();
        let mut lineage = CountingLineage::default();
        lineage
            .by_parent
            .insert(hex::encode(m.nft_child.parent_coin_info), m.nft_parent);
        lineage
            .by_parent
            .insert(hex::encode(m.did_child.parent_coin_info), m.did_parent);

        let rows = vec![coin_row_of(m.nft_child, 100), coin_row_of(m.did_child, 100)];
        // The wallet's own p2 hashes. The singletons are NOT at them — that is the whole reason
        // routing stages these rows rather than believing them.
        let ours: HashSet<String> = [hex::encode(m.owner_p2)].into_iter().collect();
        let (believed, staged) =
            route_point_read_rows(&rows, &ours, &DerivedCats::default(), |_| false);
        assert!(
            believed.is_empty(),
            "a singleton coin is never at an owned p2 hash, so nothing may be believed outright"
        );
        assert_eq!(staged.len(), 2, "both singletons are staged for a proof");

        let db = WalletDb::open_in_memory().await.unwrap();
        db.stage_cat_admissions(&staged).await.unwrap();
        let stats = promote_staged_cats(&db, &lineage, &ours).await.unwrap();

        assert_eq!(
            (stats.resolved, stats.refused, stats.deferred),
            (2, 0, 0),
            "both singletons are PROVEN, not refused: {stats:?}"
        );
        let nfts = db.all_nfts().await.unwrap();
        let dids = db.all_dids().await.unwrap();
        assert_eq!(
            nfts.len(),
            1,
            "the NFT reaches the table the wallet reads NFTs from"
        );
        assert_eq!(dids.len(), 1, "and the DID reaches the DID table");
        assert_eq!(
            nfts[0].launcher_id,
            hex::encode(m.nft_launcher),
            "and it is the NFT that was minted, identified by its launcher"
        );
        assert_eq!(dids[0].launcher_id, hex::encode(m.did_launcher));
        // THE PLACEMENT HALF. A singleton carries no asset id, so a row for it in `coins` would
        // read as XCH and inflate the spendable balance. Admitting it to the right table is the
        // fix; admitting it to `coins` would also satisfy "not deleted", and would reintroduce
        // the fabricated-balance defect this whole PR closes.
        assert!(
            db.all_coins().await.unwrap().is_empty(),
            "a singleton must never enter `coins`, where a missing asset id means XCH"
        );
        assert_eq!(
            db.staged_cat_admission_count().await.unwrap(),
            0,
            "and staging is cleared, so the chain read is not re-paid on every refresh"
        );
    }

    /// The ownership half: the SAME NFT, the SAME proof, and the one varied thing is whether this
    /// wallet controls the p2 hash the parent spend proves owns it.
    ///
    /// Without this check a hint — which anybody may write — would be enough to make the wallet
    /// display a stranger's NFT as its own. The reconstruction is the only thing that says whose
    /// the singleton is, and it is the same standard an unpredicted CAT is held to.
    #[tokio::test]
    async fn a_singleton_owned_by_a_stranger_is_refused() {
        let m = crate::sage::singleton::tests::mint_did_and_nft();
        let mut lineage = CountingLineage::default();
        lineage
            .by_parent
            .insert(hex::encode(m.nft_child.parent_coin_info), m.nft_parent);

        let rows = vec![coin_row_of(m.nft_child, 100)];
        let stranger: HashSet<String> = [hex::encode(Bytes32::new([0x77; 32]))]
            .into_iter()
            .collect();
        let (_believed, staged) =
            route_point_read_rows(&rows, &stranger, &DerivedCats::default(), |_| false);

        let db = WalletDb::open_in_memory().await.unwrap();
        db.stage_cat_admissions(&staged).await.unwrap();
        let stats = promote_staged_cats(&db, &lineage, &stranger).await.unwrap();

        assert_eq!(
            (stats.resolved, stats.refused),
            (0, 1),
            "a singleton the parent spend proves belongs to somebody else is REFUSED: {stats:?}"
        );
        assert!(
            db.all_nfts().await.unwrap().is_empty(),
            "and never reaches the NFT table"
        );
    }

    /// A DID hinted to this wallet but LOCKED TO SOMEBODY ELSE is refused, end to end.
    ///
    /// `Did::parse_child` reads the owner out of the parent spend's `CREATE_COIN` memo hint and
    /// stores it verbatim, so before the binding in [`crate::sage::singleton::reconstruct_parsed`]
    /// the ownership guard tested an attacker-written value: Mallory spends her own DID keeping her
    /// p2 hash, hints the victim, and the victim's wallet writes the row to `dids` as `Resolved` —
    /// the SUCCESS outcome — rendering the victim's own address as owner of Mallory's launcher.
    ///
    /// FIXTURE DESIGN — an honest DID rides alongside the forged one, and both p2 hashes are in
    /// `ours`. A guard that refuses every DID would close the hole and break the wallet, and with
    /// only the forged row present that regression is indistinguishable from the fix. The entry
    /// point is [`route_point_read_rows`] -> [`promote_staged_cats`], ABOVE the narrowing, because
    /// a probe entering at `db.upsert_coin` would stay green whether or not routing reaches the
    /// binding at all.
    #[tokio::test]
    async fn a_did_hinted_to_us_but_owned_by_a_stranger_is_refused() {
        let forged = crate::sage::singleton::tests::mint_did_hinted_to_a_stranger();
        let honest = crate::sage::singleton::tests::mint_did_and_nft();
        let mut lineage = CountingLineage::default();
        lineage
            .by_parent
            .insert(hex::encode(forged.child.parent_coin_info), forged.parent);
        lineage.by_parent.insert(
            hex::encode(honest.did_child.parent_coin_info),
            honest.did_parent,
        );

        // Both p2 hashes are the wallet's. The forged coin is hinted to `victim_p2`, which is why
        // `coin_records_by_hints` returned it in the first place.
        let ours: HashSet<String> = [hex::encode(forged.victim_p2), hex::encode(honest.owner_p2)]
            .into_iter()
            .collect();
        let rows = vec![
            coin_row_of(forged.child, 100),
            coin_row_of(honest.did_child, 100),
        ];
        let (believed, staged) =
            route_point_read_rows(&rows, &ours, &DerivedCats::default(), |_| false);
        assert!(
            believed.is_empty(),
            "singletons are never believed outright"
        );
        assert_eq!(staged.len(), 2);

        let db = WalletDb::open_in_memory().await.unwrap();
        db.stage_cat_admissions(&staged).await.unwrap();
        let stats = promote_staged_cats(&db, &lineage, &ours).await.unwrap();

        assert_eq!(
            (stats.resolved, stats.refused, stats.promoted),
            (1, 1, 0),
            "the honest DID resolves and the forged one is refused: {stats:?}"
        );
        let dids = db.all_dids().await.unwrap();
        assert_eq!(
            dids.len(),
            1,
            "exactly one DID row — the forged launcher must not be among them"
        );
        assert_eq!(
            dids[0].launcher_id,
            hex::encode(honest.did_launcher),
            "and it is the honest one, not Mallory's {}",
            hex::encode(forged.launcher)
        );
        assert!(
            db.all_coins().await.unwrap().is_empty(),
            "no forged balance either"
        );
    }

    /// A staged row already SPENT on chain is dropped without a parent read at all.
    ///
    /// One of two early exits in [`promote_staged_cats`] that had no coverage: neutering either
    /// left the whole suite green, so nothing pinned the behaviour that bounds the read cost of a
    /// spent coin (and stops it sitting in staging for ever awaiting a promotion that could not
    /// matter).
    #[tokio::test]
    async fn a_spent_staged_row_is_dropped_without_a_parent_read() {
        let f = real_cat();
        let lineage = CountingLineage::default(); // deliberately EMPTY: no read may occur
        let mut spent = staged_row_of(&f);
        spent.spent_height = Some(11);

        let db = WalletDb::open_in_memory().await.unwrap();
        db.stage_cat_admissions(std::slice::from_ref(&spent))
            .await
            .unwrap();
        let stats = promote_staged_cats(&db, &lineage, &owned()).await.unwrap();

        assert_eq!(
            (stats.refused, stats.promoted, stats.deferred),
            (1, 0, 0),
            "a spent coin is dropped, not promoted and not left staged: {stats:?}"
        );
        assert_eq!(lineage.reads(), 0, "and costs no chain read at all");
        assert_eq!(db.staged_cat_admission_count().await.unwrap(), 0);
    }

    /// A staged row with no created height is UNCONFIRMED: there is no height to read a parent
    /// spend at, so it is deferred and METERED — it must not hold the queue head for ever.
    ///
    /// The second uncovered early exit. The metering is the load-bearing half: without
    /// `record_promotion_attempt` an unconfirmable row is re-read every pass, which is exactly the
    /// amplification the cooldown exists to bound.
    #[tokio::test]
    async fn an_unconfirmed_staged_row_is_deferred_and_metered() {
        let f = real_cat();
        let lineage = CountingLineage::default();
        let mut unconfirmed = staged_row_of(&f);
        unconfirmed.created_height = None;

        let db = WalletDb::open_in_memory().await.unwrap();
        db.stage_cat_admissions(std::slice::from_ref(&unconfirmed))
            .await
            .unwrap();
        let first = promote_staged_cats(&db, &lineage, &owned()).await.unwrap();
        assert_eq!(
            (first.deferred, first.refused, first.promoted),
            (1, 0, 0),
            "unconfirmed is deferred, never refused: {first:?}"
        );
        assert_eq!(
            db.staged_cat_admission_count().await.unwrap(),
            1,
            "and the row stays staged, because it may confirm later"
        );

        // METERED: the attempt was recorded, so the cooldown now holds the row back.
        let second = promote_staged_cats(&db, &lineage, &owned()).await.unwrap();
        assert_eq!(
            (second.deferred, second.refused, second.promoted),
            (0, 0, 0),
            "a second pass inside the cooldown must not touch it again: {second:?}"
        );
    }

    /// **Proves:** a CORROBORATED absence defers exactly like an unreadable parent -- it never
    /// disproves the coin, and never discards the staged row.
    ///
    /// # Why this test exists
    ///
    /// `LineageAnswer` split what used to be one `Ok(None)` into `Absent` ("the sources AGREE
    /// there is no such spend") and `Unavailable` ("nothing could be learned"). `Absent` is the
    /// stronger claim, and the tempting next step is to treat it as a disproof and discard the
    /// row. That would be wrong, and wrong in the money-losing direction: corroboration is
    /// agreement, NOT currency. Every source can agree and every source can be behind the chain,
    /// which is the ordinary case for a coin created seconds ago -- so discarding on `Absent`
    /// deletes real coins whenever the sources lag. This test goes red on that change.
    ///
    /// # The fixture varies ONE actor
    ///
    /// The honest CAT is present in both runs with its parent resolvable, so it must promote in
    /// both. Only the SECOND coin's miss answer varies. A fixture where every parent missed would
    /// be the blindest possible one here: with no promotion left to observe, a pass that deferred
    /// correctly and a pass that abandoned the whole table on the first miss look identical.
    #[tokio::test]
    async fn a_corroborated_absence_defers_the_row_exactly_as_an_unreadable_parent_does() {
        /// Run one promotion pass in which the honest CAT resolves and a second staged coin
        /// MISSES, with the miss reported as `miss`. Returns
        /// `(stats, rows still staged, rows believed)`.
        async fn pass_with(miss: Miss) -> (PromoteStats, i64, usize) {
            let f = real_cat();
            let db = WalletDb::open_in_memory().await.unwrap();
            let derived = DerivedCats::derive(&[f.owner_p2], &[f.asset_id]);
            // A second coin at the SAME derived hash, so it is staged for the same reason the
            // honest one is; only its parent differs, and that parent is deliberately absent from
            // the lineage map.
            let missing = fabricated_at(f.child.puzzle_hash, 1_234, 0xCD);

            let rows = stage_from_states(
                &[
                    state(f.child, Some(10), None),
                    state(missing, Some(11), None),
                ],
                &derived,
                |_| false,
            );
            assert_eq!(rows.len(), 2, "both coins are staged, neither believed");
            db.stage_cat_admissions(&rows).await.unwrap();

            let mut lineage = CountingLineage {
                miss,
                ..Default::default()
            };
            // ONLY the honest coin's parent is resolvable. The other falls through to `miss`.
            lineage
                .by_parent
                .insert(hex::encode(f.child.parent_coin_info), f.parent.clone());

            let stats = promote_staged_cats(&db, &lineage, &owned()).await.unwrap();
            let staged_left = db.staged_cat_admission_count().await.unwrap();
            let believed = db.all_coins().await.unwrap().len();
            (stats, staged_left, believed)
        }

        let (absent, absent_staged, absent_believed) = pass_with(Miss::Absent).await;
        let (unavail, unavail_staged, unavail_believed) = pass_with(Miss::Unavailable).await;

        // The truthful control: the honest CAT promotes under BOTH miss answers. Without this, a
        // pass that abandoned the table on the first miss would satisfy every assertion below.
        assert_eq!(
            (absent.promoted, unavail.promoted),
            (1, 1),
            "the honest CAT must promote regardless of what the OTHER coin's parent reported -- \
             one unresolvable row must never abandon the pass: absent={absent:?} \
             unavailable={unavail:?}"
        );

        // The missing coin is DEFERRED under both, never refused.
        assert_eq!(
            (absent.deferred, absent.refused),
            (1, 0),
            "a corroborated absence must DEFER the row, not disprove it: sources can agree and \
             still be behind the chain, so refusing here deletes real coins whenever they lag. \
             {absent:?}"
        );
        assert_eq!(
            (absent.deferred, absent.refused),
            (unavail.deferred, unavail.refused),
            "and it must be handled identically to an unreadable parent -- the promotion path \
             deliberately does not act on the Absent/Unavailable distinction. absent={absent:?} \
             unavailable={unavail:?}"
        );

        // The row SURVIVES, so a later pass can promote it once the sources catch up. This is the
        // assertion a discard-on-Absent implementation fails.
        assert_eq!(
            (absent_staged, unavail_staged),
            (1, 1),
            "the unresolved row must stay STAGED under both answers, or a source that is merely \
             behind permanently deletes a real coin"
        );
        assert_eq!(
            (absent_believed, unavail_believed),
            (1, 1),
            "and exactly one coin is believed -- the proven one. An unresolved coin must never \
             enter `coins`, where a NULL asset id would read as XCH"
        );
    }
}
