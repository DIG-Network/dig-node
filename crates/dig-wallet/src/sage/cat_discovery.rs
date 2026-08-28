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
            Ok(Some(parent)) => parent,
            // `Ok(None)` is "the source ANSWERED, and has no spend for this parent" — which is
            // consistent with an invented ancestry AND with a source that is merely behind.
            // Treating it as a disproof would delete real coins whenever a source is behind, so it
            // is a deferral; the cost of retrying it for ever is bounded by the cooldown instead.
            Ok(None) => {
                db.record_promotion_attempt(&row.coin_id, now).await?;
                stats.deferred += 1;
                continue;
            }
            // The source did not answer at all — transport, timeout, a malformed reply. Strictly
            // less informative than `Ok(None)`, and handled the same way.
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
        if promote_one(db, lineage_prefix(), &row, &parent).await? {
            stats.promoted += 1;
        } else {
            db.discard_cat_admission(&row.coin_id).await?;
            stats.refused += 1;
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
    let reconstructed =
        singleton::reconstruct(prefix, row.created_height.map(|h| h as u32), parent, child)?;
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
        ) -> Result<Option<ParentSpend>> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            if self.fail_for.as_deref() == Some(parent_coin_id) {
                return Err(crate::sage::Error::internal("parent unreadable"));
            }
            Ok(self.by_parent.get(parent_coin_id).cloned())
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
        let stats = promote_staged_cats(&db, &lineage).await.unwrap();

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

        let stats = promote_staged_cats(&db, &lineage).await.unwrap();
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
        let stats = promote_staged_cats(&db, &CountingLineage::default())
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

        let stats = promote_staged_cats(&db, &lineage)
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
        promote_staged_cats(&db, &lineage).await.unwrap();
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
        let stats = promote_staged_cats(&db, &lineage).await.unwrap();
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
        promote_staged_cats(&db, &lineage).await.unwrap();
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
        let first = promote_staged_cats(&db, &lineage).await.unwrap();
        assert_eq!(first.promoted, 0, "the wall owns the head on pass one");
        assert_eq!(
            usize::try_from(first.deferred).unwrap(),
            wall,
            "and consumes the whole budget: {first:?}"
        );

        // Pass two is the one the old ordering could never reach. The wall has been read once and
        // is inside its cooldown; the honest coin has never been read, so it is served.
        let before = lineage.reads();
        let second = promote_staged_cats(&db, &lineage).await.unwrap();
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
}
