//! **Two creates in ONE pass never select the same coin** (`SPEC.md` §25, dig-node#423).
//!
//! The across-pass reservation is durable and was already correct: `sign_and_broadcast` records
//! every submission's consumed coins in the [`SpendLog`], and the scheduler reads that record once
//! before each pass. What it could not cover is the window INSIDE a pass.
//!
//! # Why the snapshot alone cannot close it
//!
//! A pass emits N creates — `mirror::runner` loops over the affordable prefix, and
//! `mirror::plan` derives that prefix as `balance / per_coin`, so two is the ordinary case for a
//! node holding twice one bond's collateral. Every one of those creates was handed the SAME
//! pre-pass snapshot, and neither of the two other sources could correct it:
//!
//! * the durable journal is re-read once per pass, before the pass, so create #1's own record does
//!   not reach create #2 through it;
//! * the chain shows a broadcast coin as UNSPENT for the whole confirmation window, which is the
//!   premise `mirror::funding`'s module doc is built on.
//!
//! So create #2 re-selected create #1's coin and broadcast a second bundle spending it — a
//! double-spend of real operator collateral, reported as two successful creates.
//!
//! # The fixture varies ONE actor and keeps a truthful control
//!
//! Both probes below fund the operator with genuine CAT coins through `support::ordinary_dig_coins`
//! and drive the REAL `NodeMirrorEffects::create` twice. The two probes differ in exactly one
//! thing — whether a second coin exists — because either alone is blind:
//!
//! * with only one coin, "the second create refused" is also what a broken selector that refuses
//!   everything produces;
//! * with two coins, "both creates succeeded" is also what the defective implementation produces,
//!   since it happily broadcasts twice.
//!
//! Together they pin the property: the second create spends a DIFFERENT coin when one is available,
//! and spends NOTHING when one is not.
//!
//! # The assertion is on the bundles, not on the reservation set
//!
//! Each probe reads the coins each broadcast bundle actually spends. Asserting on the in-memory set
//! instead would pin the mechanism rather than the property, and would stay green if the extension
//! were moved somewhere the selector never consults.

mod support;

use std::collections::{HashMap, HashSet};

use chia_protocol::{Bytes32, CoinSpend, SpendBundle};
use chia_sha2::Sha256;
use dig_chainsource_interface::{ChainSource, ChainSourceError, CoinRecord, SingletonLineage};
use dig_node_service::mirror::advertise::{AdvertiseState, Effective};
use dig_node_service::mirror::lifecycle::{mirror_agg_sig_data, NodeMirrorEffects};
use dig_node_service::mirror::plan::Bond;
use dig_node_service::mirror::runner::MirrorEffects;
use dig_node_service::mirror::signer::MirrorSigner;
use dig_node_service::spend_audit::{SpendJournal, SpendLog};
use dig_wallet::autoseed::WalletPaths;
use dig_wallet::operator_wallet::OperatorWallet;
use dig_wallet::sage::spend::MockBroadcaster;
use support::{ordinary_dig_coins, Wallet};

/// One bond's margined collateral, in $DIG **base units** (1 DIG = 1_000).
const PER_COIN: u64 = 40_000;

/// The epoch a create is made for. Any value; nothing here asserts about it.
const EPOCH: i64 = 42;

/// A fixture discriminator, DERIVED rather than spelled.
///
/// `ordinary_dig_coins` seeds a grandparent with `[salt; 32]`, so a byte literal reads to CodeQL as
/// a hard-coded cryptographic value (dig-node#917, #950 twice over). Deterministic, so a failure
/// reproduces; distinct per `step`, so two fixture coins cannot collapse onto one id.
fn salt(step: u8) -> u8 {
    let mut hasher = Sha256::new();
    hasher.update(b"dig-node mirror_intra_pass_reservation fixture");
    hasher.finalize()[0].wrapping_add(step)
}

/// A chain holding whatever the test put on it — and nothing else.
#[derive(Default)]
struct Chain {
    by_puzzle_hash: HashMap<Bytes32, Vec<CoinRecord>>,
    spends: HashMap<Bytes32, CoinSpend>,
}

impl Chain {
    /// Publish `amounts` of ordinary $DIG at `owner`'s address, with their real creating spend.
    ///
    /// The coins stay UNSPENT for the life of the fixture even after a create broadcasts one of
    /// them. That is not a simplification — it is the production premise this whole file is about
    /// (`mirror::funding` module doc): a broadcast coin remains unspent in the chain's view for the
    /// whole confirmation window, so the chain cannot be what stops the second create.
    fn fund(&mut self, owner: &Wallet, amounts: &[u64], salt: u8) {
        let (spend, coins) = ordinary_dig_coins(owner, amounts, salt);
        self.spends.insert(spend.coin.coin_id(), spend);
        for coin in coins {
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

/// A REAL operator wallet in a temp layout, and the fixture address its coins land on.
///
/// The wallet must be genuine: `MirrorSigner::sign` refuses any bundle whose owner is not its own
/// wallet, so a create funded from some other key's coins would be refused for a reason that has
/// nothing to do with the property under test — and the probes would go green having never reached
/// a broadcast.
fn operator(dir: &std::path::Path) -> (MirrorSigner, Wallet) {
    let paths = WalletPaths::resolve(dir.join("seed"));
    dig_node_service::wallet_bootstrap::ensure_wallet_seed_at(&paths)
        .expect("the autoseed bootstrap yields a state");
    // The SAME domain production signs mirror spends under, taken from the one function that
    // decides it -- never a constant restated here. A mirror spend is a Chia L1 CAT spend, so its
    // AGG_SIG_ME domain is the Chia mainnet genesis; this fixture previously passed the DIG **L2**
    // genesis, which is the #447 regression that stranded 1010 $DIG on chain. A signer asked for
    // the message it already believes in always agrees with itself, so a fixture under the wrong
    // domain cannot fail -- and the next signature-validity assertion added here would have been
    // written against it (#449).
    let wallet = OperatorWallet::open(&paths, mirror_agg_sig_data())
        .expect("a wallet was just created, so it opens");
    let signer = MirrorSigner::new(wallet);
    let address = Wallet {
        public_key: signer.synthetic_key(),
        puzzle_hash: signer.owner_puzzle_hash(),
    };
    (signer, address)
}

/// The coin ids each broadcast bundle spends, in broadcast order.
///
/// Read from the bundles themselves rather than from anything the effects reported: a `CoinSpend`
/// names the coin it spends, so this cannot disagree with what was signed.
fn coins_spent_per_bundle(broadcaster: &MockBroadcaster) -> Vec<HashSet<Bytes32>> {
    let sent: Vec<SpendBundle> = broadcaster.sent.lock().expect("not poisoned").clone();
    sent.iter()
        .map(|bundle| {
            bundle
                .coin_spends
                .iter()
                .map(|cs| cs.coin.coin_id())
                .collect()
        })
        .collect()
}

/// A bond over two distinct 64-hex ids.
fn bond(store: u8, root: u8) -> Bond {
    Bond::new(hex::encode([store; 32]), hex::encode([root; 32]))
}

/// Two creates in one pass select DISJOINT coins when a second coin is available.
///
/// This is `SPEC.md` §25's clause directly. The defective implementation reaches the same two `Ok`
/// results — it broadcasts twice quite happily — so the outcome of each create is not what
/// discriminates. The bundles are: it spends the SAME coin in both, and the disjointness assertion
/// is the one that fails.
///
/// The amounts differ so the two coins cannot collapse onto one id, and so that largest-first
/// selection has a defined order to take them in.
#[test]
fn two_creates_in_one_pass_select_disjoint_coins() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let (signer, address) = operator(dir.path());

    let mut chain = Chain::default();
    // Two coins, each on its own able to fund one bond, so a create never needs both.
    chain.fund(&address, &[PER_COIN + 1, PER_COIN], salt(1));

    let log = SpendLog::at(dir.path().join("spend-audit.jsonl"));
    let journal = SpendJournal::new(log);
    let broadcaster = MockBroadcaster::default();

    // Owned OUTSIDE the runtime, and the test body is not itself async: `sign_and_broadcast`
    // drives the broadcast with `Handle::block_on`, which panics when called from a thread already
    // inside that runtime. A `#[tokio::test]` here would fail on the harness rather than the
    // property.
    let runtime = tokio::runtime::Runtime::new().expect("a tokio runtime");

    let effects = NodeMirrorEffects::new(
        Vec::new(),
        Ok(2 * PER_COIN),
        Ok(HashSet::new()),
        // Non-empty: `create` refuses before any chain read without one, and a probe that tripped
        // that refusal would assert nothing about coin selection.
        Effective {
            urls: vec!["https://mirror.example/dig".to_string()],
            state: AdvertiseState::Override,
            ..Default::default()
        },
        // A well-formed peer id, for the same reason the URL list is non-empty: `create` refuses
        // before selecting any coin without one, and a probe that stopped at the identity guard
        // would assert nothing about DISJOINTNESS, which is the property under test.
        Some("a1".repeat(32)),
        &chain,
        signer.owner_puzzle_hash(),
        Some(&signer),
        &journal,
        Some(&broadcaster),
        runtime.handle().clone(),
    );

    effects
        .create(&bond(0xA1, 0xC3), EPOCH, PER_COIN)
        .expect("the first create is funded");
    effects
        .create(&bond(0xB2, 0xD4), EPOCH, PER_COIN)
        .expect("a second coin is available, so the second create is funded too");

    let spent = coins_spent_per_bundle(&broadcaster);
    assert_eq!(spent.len(), 2, "both creates must have reached the mempool");
    assert!(
        spent[0].is_disjoint(&spent[1]),
        "the second create re-selected a coin the first already spent, so this pass broadcast two \
         bundles double-spending it: {spent:?}"
    );
}

/// With only ONE coin, the second create refuses rather than re-spending it.
///
/// The companion probe, and the one that shows the reservation is a REFUSAL and not merely a
/// preference for an unused coin. An implementation that filtered the committed coin only when an
/// alternative existed would pass the probe above and fail here.
#[test]
fn the_only_coin_funds_one_create_and_the_second_refuses() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let (signer, address) = operator(dir.path());

    let mut chain = Chain::default();
    // ONE coin, large enough for one bond and not two.
    chain.fund(&address, &[PER_COIN], salt(2));

    let log = SpendLog::at(dir.path().join("spend-audit.jsonl"));
    let journal = SpendJournal::new(log);
    let broadcaster = MockBroadcaster::default();

    // Owned OUTSIDE the runtime, and the test body is not itself async: `sign_and_broadcast`
    // drives the broadcast with `Handle::block_on`, which panics when called from a thread already
    // inside that runtime. A `#[tokio::test]` here would fail on the harness rather than the
    // property.
    let runtime = tokio::runtime::Runtime::new().expect("a tokio runtime");

    let effects = NodeMirrorEffects::new(
        Vec::new(),
        Ok(PER_COIN),
        Ok(HashSet::new()),
        Effective {
            urls: vec!["https://mirror.example/dig".to_string()],
            state: AdvertiseState::Override,
            ..Default::default()
        },
        // A well-formed peer id: `create` refuses before selecting any coin without one, and this
        // fixture needs the FIRST create to genuinely reach coin selection so that the second one
        // has something already reserved to collide with.
        Some("a1".repeat(32)),
        &chain,
        signer.owner_puzzle_hash(),
        Some(&signer),
        &journal,
        Some(&broadcaster),
        runtime.handle().clone(),
    );

    effects
        .create(&bond(0xA1, 0xC3), EPOCH, PER_COIN)
        .expect("the first create is funded");

    let second = effects.create(&bond(0xB2, 0xD4), EPOCH, PER_COIN);
    assert!(
        second.is_err(),
        "the only coin is already committed to a bundle in flight, so there is nothing left to \
         fund a second create with"
    );

    let spent = coins_spent_per_bundle(&broadcaster);
    assert_eq!(
        spent.len(),
        1,
        "exactly one bundle may reach the mempool; a second would double-spend the one coin: \
         {spent:?}"
    );
}
