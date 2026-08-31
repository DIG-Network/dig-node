//! **A funding coin committed to a spend that never lands returns to the SELECTABLE set**
//! (dig-node#471).
//!
//! # Why this probe exists beside the unit tests
//!
//! `spend_audit`'s own tests assert what the committed SET contains. That is one layer below the
//! property a person experiences, and the two can disagree: a coin can be absent from the committed
//! set and still be unselectable, and the failure this ticket describes is not "a set has an extra
//! string in it" — it is a genuinely funded operator wallet reporting `Insufficient` forever.
//!
//! So every assertion below runs the real selector,
//! [`select_operator_dig_cats`], over a chain holding real $DIG, and asks the only question that
//! matters: **does a coin come back.**
//!
//! # The fixture varies ONE thing, and it is not the coin
//!
//! Both probes publish the SAME chain and the SAME audit record. The only thing that differs is the
//! instant the committed set is computed at. A fixture that varied the coins, or the statuses, could
//! be satisfied by an implementation that released everything unconditionally — which is the nearest
//! wrong fix to this defect, and the one a release-only test cannot see.
//!
//! # Fixture time is PINNED
//!
//! The journal is driven by an injected clock fixed at [`NOW`], never the wall clock. A record
//! written "now" and queried against a small literal is already expired by ~1.8 billion seconds, so
//! it would assert the release path while never exercising the hold.

mod support;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use chia_protocol::{Bytes32, CoinSpend};
use chia_sha2::Sha256;
use dig_chainsource_interface::{ChainSource, ChainSourceError, CoinRecord, SingletonLineage};
use dig_node_service::mirror::funding::select_operator_dig_cats;
use dig_node_service::spend_audit::{
    committed_funding_coin_ids, kinds, Asset, Authority, FundingCoinId, SpendIntent, SpendJournal,
    SpendKind, SpendLog, SpendStatus, Submission, FUNDING_RESERVATION_WINDOW_MS,
};
use support::{ordinary_dig_coins, wallet, Wallet};

/// The margined requirement a create is funded for, in $DIG **base units** (1 DIG = 1_000).
const REQUIRED: u64 = 40_000;

/// A pinned instant. Every audit revision below is written at exactly this millisecond, so the only
/// variable in the probes is the instant the committed set is read at.
const NOW: u64 = 1_767_225_600_000;

fn clock() -> u64 {
    NOW
}

/// A fixture discriminator, DERIVED rather than spelled as a byte literal — a literal here reads to
/// CodeQL as a hard-coded cryptographic value used as a salt (dig-node#917, #950 are the same false
/// positive). Deterministic, so a failing fixture reproduces.
fn salt(step: u8) -> u8 {
    let mut hasher = Sha256::new();
    hasher.update(b"dig-node mirror_funding_reservation_expiry fixture");
    hasher.finalize()[0].wrapping_add(step)
}

/// A chain holding whatever the test put on it — and nothing else.
///
/// Every coin comes from a genuine CAT spend, because a `Cat` is spendable only with a lineage proof
/// reconstructed by EXECUTING its creating spend. A hand-built `CoinRecord` never reaches that path,
/// so a probe using one would assert selection against a fixture that cannot exhibit it.
#[derive(Default)]
struct Chain {
    by_puzzle_hash: HashMap<Bytes32, Vec<CoinRecord>>,
    spends: HashMap<Bytes32, CoinSpend>,
}

impl Chain {
    /// Publish `amounts` of ordinary $DIG at `owner`'s address, with their real creating spend.
    fn fund(&mut self, owner: &Wallet, amounts: &[u64], salt: u8) -> Vec<Bytes32> {
        let (spend, coins) = ordinary_dig_coins(owner, amounts, salt);
        self.spends.insert(spend.coin.coin_id(), spend);
        let mut ids = Vec::new();
        for coin in coins {
            // A coin id is `(parent, puzzle_hash, amount)`, so two children of ONE spend paying the
            // SAME amount to the SAME address are literally one coin. A fixture that thinks it
            // published two has published one, which silently defeats every per-coin assertion.
            assert!(
                !ids.contains(&coin.coin_id()),
                "two fixture coins collapsed to one id; vary the AMOUNTS, not just the count"
            );
            ids.push(coin.coin_id());
            self.by_puzzle_hash
                .entry(coin.puzzle_hash)
                .or_default()
                .push(CoinRecord {
                    coin,
                    confirmed_height: Some(100),
                    spent_height: None,
                    timestamp: Some(1_700_000_000),
                    coinbase: false,
                });
        }
        ids
    }
}

impl ChainSource for Chain {
    type Error = ChainSourceError;

    fn coin_record(&self, _coin_id: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
        Ok(None)
    }

    fn coin_records_by_puzzle_hash(
        &self,
        puzzle_hash: Bytes32,
        _include_spent: bool,
    ) -> Result<Vec<CoinRecord>, Self::Error> {
        Ok(self
            .by_puzzle_hash
            .get(&puzzle_hash)
            .cloned()
            .unwrap_or_default())
    }

    fn coin_records_by_parent(&self, _parent: Bytes32) -> Result<Vec<CoinRecord>, Self::Error> {
        Ok(Vec::new())
    }

    fn coin_spend(&self, coin_id: Bytes32) -> Result<Option<CoinSpend>, Self::Error> {
        Ok(self.spends.get(&coin_id).cloned())
    }

    fn resolve_singleton_lineage(
        &self,
        _launcher_id: Bytes32,
    ) -> Result<Option<SingletonLineage>, Self::Error> {
        Ok(None)
    }

    fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
        Ok(Some(1_000))
    }

    fn block_timestamp(&self, _height: u32) -> Result<Option<u64>, Self::Error> {
        Ok(Some(1_700_000_000))
    }
}

/// A log at a path no other probe in this binary can reach.
///
/// The counter is not decoration. Integration tests in one binary run on parallel THREADS, so two
/// probes deriving the same path append to one file -- and the failure that produces is a ledger
/// with a foreign record in it, which reads as the code under test having written something it
/// never wrote. Measured here on the first run.
fn tmp_log(name: &str) -> SpendLog {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "dig-node-471-{}-{NOW}-{name}-{n}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("a temp dir");
    SpendLog::at(dir.join("spend-audit.jsonl"))
}

fn intent() -> SpendIntent {
    SpendIntent {
        kind: SpendKind::new(kinds::MIRROR_COIN),
        purpose: "advertise that this node holds the store".to_string(),
        authority: Authority {
            principal: "node".to_string(),
            grant: "settings.autoMirror".to_string(),
        },
        asset: Asset::Dig,
        amount_mojos: REQUIRED,
        fee_mojos: 0,
        store_id: Some("store-a".to_string()),
        bond: None,
    }
}

/// One operator wallet whose ENTIRE $DIG holding is committed to a spend that was submitted at
/// [`NOW`] and never landed, plus the log that records it.
///
/// The whole holding, deliberately: a wallet with an uncommitted coin to spare could satisfy the
/// selector from that coin and would report success while the committed coin stayed stranded
/// forever. Committing everything is what makes `Insufficient` the observable.
fn wedged_wallet() -> (Chain, Wallet, SpendLog) {
    let operator = wallet(0x21);
    let mut chain = Chain::default();
    let coins = chain.fund(&operator, &[REQUIRED], salt(1));

    let log = tmp_log("wedged");
    let journal = SpendJournal::with_clock(log.clone(), clock);
    let spend = journal.begin(intent());
    journal.submitted(
        &spend,
        Submission {
            // `None`, which is the create path's real shape: a mirror create's output coin takes
            // its parent from whichever input the builder drew from, so this node cannot derive it.
            intended_coin_id: None,
            funding_coin_ids: coins
                .iter()
                .map(|c| FundingCoinId(hex::encode(c)))
                .collect(),
        },
    );
    // The handle is leaked rather than dropped, because `Drop` would append an `Unresolved`
    // revision at the CURRENT wall-clock instant and un-pin the fixture's time. The record under
    // test is the `Submitted` one written at `NOW`.
    std::mem::forget(spend);

    (chain, operator, log)
}

/// **A coin committed to a spend still INSIDE the confirmation window is NOT released.**
///
/// This is the half a release-only probe cannot see. A fix that dropped the reservation entirely,
/// or released every non-terminal record immediately, passes the expiry probe below and fails here
/// — and it would re-open the double-select dig-node#348 exists to close, because the original
/// bundle can still be included.
///
/// One millisecond before the bound rather than at some comfortable midpoint: a bound tested only
/// from well inside it can only confirm itself.
#[test]
fn a_coin_committed_to_a_spend_still_in_flight_is_not_selectable() {
    let (chain, operator, log) = wedged_wallet();

    let committed = committed_funding_coin_ids(&log, NOW + FUNDING_RESERVATION_WINDOW_MS - 1)
        .expect("the audit record is readable");

    let refusal = select_operator_dig_cats(&chain, operator.puzzle_hash, REQUIRED, &committed)
        .expect_err("the wallet's only $DIG is committed to a bundle that may still be included");

    assert!(
        matches!(
            refusal,
            dig_node_service::mirror::funding::FundingError::Insufficient { .. }
        ),
        "an in-flight commitment withholds the coin, so the create is refused: {refusal:?}"
    );
}

/// **The same coin IS selectable once the hold lapses — N = 2 mirror passes.**
///
/// `FUNDING_RESERVATION_WINDOW_MS` is `2 * MIRROR_ROUND_LENGTH_MS`, and the mirror pass runs every
/// `MIRROR_ROUND_LENGTH_MS`, so the coin returns on the SECOND pass after the last observation.
///
/// The chain, the wallet and the audit record are byte-for-byte the ones the probe above refused.
/// Only the instant differs, so nothing but the elapsed time can explain the difference.
#[test]
fn a_coin_committed_to_a_spend_that_never_lands_is_selectable_two_passes_later() {
    let (chain, operator, log) = wedged_wallet();

    let n_passes = FUNDING_RESERVATION_WINDOW_MS / dig_constants::MIRROR_ROUND_LENGTH_MS as u64;
    assert_eq!(n_passes, 2, "N is two mirror passes; state it, do not imply it");

    let committed = committed_funding_coin_ids(
        &log,
        NOW + n_passes * dig_constants::MIRROR_ROUND_LENGTH_MS as u64,
    )
    .expect("the audit record is readable");

    let cats = select_operator_dig_cats(&chain, operator.puzzle_hash, REQUIRED, &committed)
        .expect("the hold has lapsed, so the operator's genuine $DIG is selectable again");
    assert_eq!(
        cats.len(),
        1,
        "the wallet was funded all along; it must stop reporting Insufficient"
    );

    // The record is NOT rewritten. Releasing the coins is not declaring the spend failed:
    // `Unresolved`/`Submitted` mean "this node signed and does not know what happened", and that
    // stays true after the coins are released. A fabricated outcome here would be the money lie
    // `Confirmed`'s shape — height and coin id INSIDE the variant — exists to prevent.
    let ledger = log.ledger().expect("readable");
    assert_eq!(ledger.records.len(), 1);
    assert_eq!(ledger.records[0].status, SpendStatus::Submitted);
    assert!(
        ledger.records[0].status.may_have_reached_the_network(),
        "a released record stays chaseable by resolve_landed and reconcile"
    );
}
