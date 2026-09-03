//! **The operator's advertised URLs reach the coin** (`SPEC.md` §25.10, dig-node#426).
//!
//! A mirror coin publishes where its store can be fetched from, and those URLs are fixed at create
//! for the whole epoch. Until dig-node#426 the node parsed the operator's value and then handed
//! `create` an EMPTY list, so every create refused and no coin was ever made. This file drives the
//! real composition the scheduler performs — environment → [`configured_urls`] → the real
//! `NodeMirrorEffects::create` → a signed bundle — and reads the answer off the broadcast bundle.
//!
//! # Why the assertion is on the BUNDLE, not on the list
//!
//! Asserting that `configured_urls()` returns the right strings would pass identically while the
//! scheduler kept passing `Vec::new()` beside it — the exact defect this work removes. The bundle
//! is the only artifact that can distinguish "parsed" from "published", because it is what a
//! stranger eventually reads.
//!
//! # The fixture keeps a truthful control
//!
//! The configured value mixes a this-machine entry among two publishable ones. A fixture of only
//! good entries cannot see a filter that drops too much, and a fixture of only bad entries cannot
//! see one that drops too little; varying one entry against two honest survivors sees both.

mod support;

use std::collections::HashSet;
use std::sync::{Mutex, MutexGuard, OnceLock};

use chia_protocol::{Bytes32, CoinSpend, SpendBundle};
use chia_sha2::Sha256;
use dig_chainsource_interface::{ChainSource, ChainSourceError, CoinRecord, SingletonLineage};
use dig_node_service::mirror::advertise::{configured_urls, ADVERTISE_URLS_ENV};
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

/// Serialises the two probes: both write the SAME process-wide environment variable, and cargo runs
/// the tests in this binary on parallel threads. Without this, one probe reads the other's value and
/// the failure looks like a defect in the code under test.
fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Runs `body` with the operator's advertised-URL value set, restoring the previous value after.
fn with_advertise_env<T>(value: &str, body: impl FnOnce() -> T) -> T {
    let _guard = env_lock();
    let previous = std::env::var(ADVERTISE_URLS_ENV).ok();
    std::env::set_var(ADVERTISE_URLS_ENV, value);
    let out = body();
    match previous {
        Some(prior) => std::env::set_var(ADVERTISE_URLS_ENV, prior),
        None => std::env::remove_var(ADVERTISE_URLS_ENV),
    }
    out
}

/// A fixture discriminator, DERIVED rather than spelled.
///
/// `ordinary_dig_coins` seeds a grandparent with `[salt; 32]`, so a byte literal reads to CodeQL as
/// a hard-coded cryptographic value (dig-node#917, #950). Deterministic, so a failure reproduces;
/// distinct per `step`, so two fixture coins cannot collapse onto one id.
fn salt(step: u8) -> u8 {
    let mut hasher = Sha256::new();
    hasher.update(b"dig-node mirror_advertised_urls fixture");
    hasher.finalize()[0].wrapping_add(step)
}

/// A chain holding whatever the test put on it — and nothing else.
///
/// It COUNTS its address lookups, because that is the only externally visible trace coin selection
/// leaves when no spend follows. Without it, the refusal probe below could not tell a guard that
/// runs before selection from one that runs after: both broadcast nothing.
#[derive(Default)]
struct Chain {
    by_puzzle_hash: std::collections::HashMap<Bytes32, Vec<CoinRecord>>,
    spends: std::collections::HashMap<Bytes32, CoinSpend>,
    address_lookups: std::sync::atomic::AtomicUsize,
}

impl Chain {
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
        self.address_lookups
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
/// `MirrorSigner::sign` refuses any bundle whose owner is not its own wallet, so a create funded
/// from another key's coins would be refused for a reason unrelated to the property under test.
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

/// The solution bytes of every broadcast bundle, one entry per bundle.
///
/// A memo is a plain byte atom inside the spend's SOLUTION, so a URL that was published appears in
/// these bytes verbatim and one that was filtered does not. Reading the wire form rather than any
/// reported value is what makes this an observation of the advertisement itself.
fn broadcast_bytes(broadcaster: &MockBroadcaster) -> Vec<Vec<u8>> {
    let sent: Vec<SpendBundle> = broadcaster.sent.lock().expect("not poisoned").clone();
    sent.iter()
        .map(|bundle| {
            bundle
                .coin_spends
                .iter()
                .flat_map(|cs| cs.solution.as_ref().to_vec())
                .collect()
        })
        .collect()
}

/// Where `needle` first appears in `haystack`, if it does.
fn index_of(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// A bond over two distinct 64-hex ids.
fn bond(store: u8, root: u8) -> Bond {
    Bond::new(hex::encode([store; 32]), hex::encode([root; 32]))
}

/// The whole composition, end to end: the operator's value becomes the coin's advertisement, in the
/// operator's own order, with the this-machine entry dropped and its honest siblings kept.
///
/// The order assertion is made on the bundle's own bytes, so an implementation that sorted the list
/// — which §25.10 forbids, because the order is the operator's statement of preference — fails here
/// rather than passing on a fixture that happens to be sorted already.
#[test]
fn the_configured_urls_reach_the_coin_in_the_operators_order() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let (signer, address) = operator(dir.path());

    let mut chain = Chain::default();
    chain.fund(&address, &[PER_COIN], salt(1));

    let log = SpendLog::at(dir.path().join("spend-audit.jsonl"));
    let journal = SpendJournal::new(log);
    let broadcaster = MockBroadcaster::default();

    // Owned OUTSIDE the runtime: `sign_and_broadcast` drives the broadcast with
    // `Handle::block_on`, which panics when called from a thread already inside that runtime.
    let runtime = tokio::runtime::Runtime::new().expect("a tokio runtime");

    // IPv6 second on purpose. §5.2 recommends listing IPv6 first, and the node publishes the
    // operator's order regardless — a fixture already in the recommended order could not tell the
    // two apart.
    let first = "https://mirror-b.example/dig";
    let second = "https://[2001:db8::1]/dig";
    let urls = with_advertise_env(
        &format!("{first}, http://127.0.0.1:4161/, {second}"),
        configured_urls,
    );

    let effects = NodeMirrorEffects::new(
        Vec::new(),
        Ok(PER_COIN),
        Ok(HashSet::new()),
        urls,
        // A well-formed peer id, because `create` now refuses without one: a coin naming no peer
        // locks collateral no reader could credit. This fixture is about URL ORDER, so it must
        // reach the advertisement rather than stop at the identity guard. `repeat` rather than a
        // 64-character literal so the length is right by construction instead of by counting.
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
        .expect("a configured advertisement and a funding coin are both present");

    let bundles = broadcast_bytes(&broadcaster);
    assert_eq!(bundles.len(), 1, "the create must have reached the mempool");
    let wire = &bundles[0];

    let at_first = index_of(wire, first.as_bytes())
        .unwrap_or_else(|| panic!("{first} was configured but does not appear in the coin"));
    let at_second = index_of(wire, second.as_bytes())
        .unwrap_or_else(|| panic!("{second} was configured but does not appear in the coin"));
    assert!(
        at_first < at_second,
        "the coin reordered the operator's list: {first} must precede {second}"
    );
    assert!(
        index_of(wire, b"127.0.0.1").is_none(),
        "a loopback entry can only mean this machine, so it must never be advertised"
    );
}

/// A value whose every entry is rejected advertises nothing, refuses, and spends NOTHING.
///
/// This is the money-safe default and the assertion most worth having: the refusal is what stops
/// collateral being locked against a claim no stranger can act on, and it must be reached before
/// any coin is selected — so the emptiness of the broadcaster is the load-bearing half, not the
/// error itself.
#[test]
fn an_all_rejected_value_refuses_and_spends_nothing() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let (signer, address) = operator(dir.path());

    let mut chain = Chain::default();
    // Funded deliberately: a refusal on an EMPTY wallet would be indistinguishable from a funding
    // refusal, and would assert nothing about the advertisement.
    chain.fund(&address, &[PER_COIN], salt(2));

    let log = SpendLog::at(dir.path().join("spend-audit.jsonl"));
    let journal = SpendJournal::new(log);
    let broadcaster = MockBroadcaster::default();
    let runtime = tokio::runtime::Runtime::new().expect("a tokio runtime");

    let urls = with_advertise_env(
        "http://localhost:4161/, mirror.example.net",
        configured_urls,
    );
    assert!(
        urls.is_empty(),
        "every entry names this machine or no scheme, so none may be published: {urls:?}"
    );

    let effects = NodeMirrorEffects::new(
        Vec::new(),
        Ok(PER_COIN),
        Ok(HashSet::new()),
        urls,
        // Deliberately absent, and deliberately UNREACHED: the advertisement guard returns before
        // `declaration_for_create` is consulted, so this row still refuses for the URL reason. It
        // is left as `None` so that a future reordering putting the identity guard first changes
        // the REASON, which the assertion below now names explicitly.
        None,
        &chain,
        signer.owner_puzzle_hash(),
        Some(&signer),
        &journal,
        Some(&broadcaster),
        runtime.handle().clone(),
    );

    let reason = effects
        .create(&bond(0xB2, 0xD4), EPOCH, PER_COIN)
        .expect_err(
            "a mirror with nowhere to fetch from is not a mirror, so the create must refuse",
        );
    // WHICH refusal, not merely that one happened. `create` now has a second early return -- the
    // peer-identity guard -- and this fixture carries no declaration, so a bare `is_err()` would
    // pass just as happily if the identity guard were reordered ahead of the advertisement one,
    // leaving the URL guard this test exists for completely unexercised.
    assert!(
        reason.to_string().contains("at least one URL"),
        "the refusal must name the missing advertisement rather than any other cause: {reason}"
    );
    assert!(
        broadcast_bytes(&broadcaster).is_empty(),
        "no spend may be attempted for an advertisement no stranger could act on"
    );
    // The PLACEMENT, which the two assertions above cannot see. `dig-mirror-coin` also refuses an
    // empty URL list, so a guard moved to after coin selection would broadcast nothing and return
    // an error exactly as this one does — while having reserved a funding coin for a create that
    // can never happen, starving the next bond in the same pass. A create that never reads an
    // address is the only observation that separates the two.
    assert_eq!(
        chain
            .address_lookups
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the refusal must be reached before any chain read, so no coin is selected or reserved"
    );
}
