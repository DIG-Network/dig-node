//! The send/spend method group (design A.5, #216): coin selection, spend building, signing,
//! pre-broadcast validation, and broadcast — for `send_xch`/`bulk_send_xch`/`combine`/
//! `split`/`multi_send`/`send_cat`/`bulk_send_cat`/`sign_coin_spends`/`view_coin_spends`/
//! `submit_transaction`.
//!
//! Every spend is built with the canonical `chia-wallet-sdk` driver constructors
//! ([`StandardLayer`]/[`SpendContext`]/[`Conditions`]/[`Cat::spend_all`]) — never hand-rolled
//! CLVM (SYSTEM.md §4.1) — following the proven `dig-l1-wallet` builder pattern. Bundles are
//! validated with [`dig_clvm::validate_spend_bundle`] before broadcast (C.6 fail-closed).
//!
//! ## Signature validation split
//!
//! `dig-clvm` is the DIG **L2** consensus engine; its BLS check uses the DIG-L2 aggregate-sig
//! domain, which is NOT the Chia **L1** domain a wallet spend is signed for. So we validate
//! CLVM execution + conservation + structure here with `DONT_VALIDATE_SIGNATURE`, and let the
//! **L1 broadcast target** (the Chia peer's `send_transaction`, or the simulator in tests)
//! verify the aggregate signature against the correct L1 constants. This is fail-closed: a
//! malformed/over-spending bundle is rejected before it ever reaches the network.
//!
//! ## Never auto-broadcast in tests/CI
//!
//! Broadcasting goes through the [`Broadcaster`] trait. Tests use the in-memory
//! [`MockBroadcaster`] or drive the `chia-sdk-test` simulator directly — a real mainnet
//! broadcast is a separate, explicitly-gated live pass, never reached from a unit test.

use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use chia::bls::{sign, PublicKey, SecretKey, Signature};
use chia::puzzles::{standard::StandardArgs, Memos};
use chia::traits::Streamable;
use chia_protocol::{Bytes32, Coin, CoinSpend, Program, SpendBundle};
use chia_wallet_sdk::driver::{Cat, CatSpend, SpendContext, SpendWithConditions, StandardLayer};
use chia_wallet_sdk::signer::{AggSigConstants, RequiredSignature};
use chia_wallet_sdk::types::Conditions;
use clvmr::Allocator;
use dig_clvm::chia_consensus::flags::DONT_VALIDATE_SIGNATURE;
use dig_clvm::{
    validate_spend_bundle, SpendResult, ValidationConfig, ValidationContext, DIG_MAINNET,
};

use super::types::{
    Amount, CoinJson, CoinSpendJson, SpendBundleJson, TransactionInput, TransactionOutput,
    TransactionSummary,
};
use super::{Error, Result};

/// The wallet's signing keys + the network aggregate-signature domain. Each key is the
/// **p2 signing key used directly in the standard puzzle** — for a real HD wallet the node
/// derives the synthetic child key (`child_sk.derive_synthetic()`) BEFORE constructing the
/// signer, so `sk.public_key()` is the on-chain standard-layer key and its standard puzzle
/// hash is the wallet address. A coin is matched to the key by that puzzle hash.
///
/// Custody note (C.6): a `WalletSigner` is only ever constructed node-side from the node's
/// custodied seed for node-class / DIG-Browser callers. The MV3 extension self-custodies and
/// never uses the node's signing path.
pub struct WalletSigner {
    keys: Vec<KeyEntry>,
    agg_sig_data: Bytes32,
}

struct KeyEntry {
    sk: SecretKey,
    p2_pk: PublicKey,
    puzzle_hash: Bytes32,
}

impl WalletSigner {
    /// Build a signer from the wallet's p2 signing keys (already synthetic-derived for a real
    /// HD wallet) and the network agg-sig additional data (mainnet vs testnet11).
    pub fn new(secret_keys: Vec<SecretKey>, agg_sig_data: Bytes32) -> Self {
        let keys = secret_keys
            .into_iter()
            .map(|sk| {
                let p2_pk = sk.public_key();
                let puzzle_hash = Bytes32::from(StandardArgs::curry_tree_hash(p2_pk).to_bytes());
                KeyEntry {
                    sk,
                    p2_pk,
                    puzzle_hash,
                }
            })
            .collect();
        Self { keys, agg_sig_data }
    }

    /// The standard-layer public key that spends a coin at `puzzle_hash`, if this wallet
    /// holds it (the key a [`StandardLayer`] is built from).
    pub fn synthetic_for(&self, puzzle_hash: Bytes32) -> Option<PublicKey> {
        self.keys
            .iter()
            .find(|k| k.puzzle_hash == puzzle_hash)
            .map(|k| k.p2_pk)
    }

    /// The wallet's standard p2 puzzle hashes (for the summary "receiving" flag).
    pub fn puzzle_hashes(&self) -> HashSet<Bytes32> {
        self.keys.iter().map(|k| k.puzzle_hash).collect()
    }

    /// The ordered `owner puzzle hash -> standard-layer public key` map the chia-wallet-sdk
    /// action system's `Spends::finish_with_keys` needs (offer building, [`super::offers`]).
    pub fn key_map(&self) -> indexmap::IndexMap<Bytes32, PublicKey> {
        self.keys.iter().map(|k| (k.puzzle_hash, k.p2_pk)).collect()
    }

    /// The wallet's first receive puzzle hash (used as the change address).
    pub fn change_puzzle_hash(&self) -> Option<Bytes32> {
        self.keys.first().map(|k| k.puzzle_hash)
    }

    /// Map each p2 public key to its secret key, for signing.
    fn key_pairs(&self) -> HashMap<PublicKey, SecretKey> {
        self.keys.iter().map(|k| (k.p2_pk, k.sk.clone())).collect()
    }

    /// Produce the aggregated BLS signature for `coin_spends` (the `dig-l1-wallet` pattern:
    /// each required BLS signature is matched to the original or synthetic key).
    pub fn sign(&self, coin_spends: &[CoinSpend]) -> Result<Signature> {
        let mut allocator = Allocator::new();
        let agg = AggSigConstants::new(self.agg_sig_data);
        let required = RequiredSignature::from_coin_spends(&mut allocator, coin_spends, &agg)
            .map_err(|e| Error::internal(format!("required-signature extraction: {e:?}")))?;
        let pairs = self.key_pairs();
        let mut sig = Signature::default();
        for req in required {
            let RequiredSignature::Bls(bls) = req else {
                continue;
            };
            if let Some(sk) = pairs.get(&bls.public_key) {
                sig += &sign(sk, bls.message());
            }
        }
        Ok(sig)
    }
}

/// Broadcast a signed spend bundle to the network. Node-class production broadcasts via the
/// Chia peer's `send_transaction`; tests use [`MockBroadcaster`] (records, never sends).
#[async_trait]
pub trait Broadcaster: Send + Sync {
    /// Broadcast a signed bundle. `Ok` once the network has accepted it for the mempool.
    async fn broadcast(&self, bundle: &SpendBundle) -> Result<()>;
}

/// A broadcaster that records bundles instead of sending them (tests, mainnet-safe).
#[derive(Default)]
pub struct MockBroadcaster {
    /// The bundles handed to [`Broadcaster::broadcast`].
    pub sent: std::sync::Mutex<Vec<SpendBundle>>,
}

#[async_trait]
impl Broadcaster for MockBroadcaster {
    async fn broadcast(&self, bundle: &SpendBundle) -> Result<()> {
        self.sent.lock().unwrap().push(bundle.clone());
        Ok(())
    }
}

/// The PRODUCTION broadcaster (§18.21): pushes a signed bundle to mainnet via
/// `chia_query::push_tx` — decentralized Chia peers with a coinset.org fallback (IPv6-first per
/// §5.2), mirroring Sage's peer `send_transaction`. This is the REAL [`Broadcaster`] the node
/// attaches on the authorized sign+broadcast path; tests use [`MockBroadcaster`] or the simulator,
/// NEVER this (there is no auto-broadcast in CI).
pub struct ChiaQueryBroadcaster {
    query: std::sync::Arc<chia_query::ChiaQuery>,
}

impl ChiaQueryBroadcaster {
    /// Wrap a shared [`chia_query::ChiaQuery`] — the SAME substrate the fallback tier uses
    /// ([`super::fallback::CoinsetFallback`]), so the serving layer shares one client.
    pub fn new(query: std::sync::Arc<chia_query::ChiaQuery>) -> Self {
        Self { query }
    }
}

/// Convert a `chia_protocol::SpendBundle` into the `chia_query` wire bundle `push_tx` accepts
/// (hex-encoded coin spends + aggregate signature; `chia_query` parses these 0x-tolerantly). PURE
/// — unit-tested against a known bundle so the field encoding can't silently drift.
fn to_query_bundle(bundle: &SpendBundle) -> Result<chia_query::SpendBundle> {
    let coin_spends = bundle
        .coin_spends
        .iter()
        .map(|cs| {
            Ok(chia_query::CoinSpend {
                coin: chia_query::Coin {
                    parent_coin_info: hex::encode(cs.coin.parent_coin_info),
                    puzzle_hash: hex::encode(cs.coin.puzzle_hash),
                    amount: cs.coin.amount,
                },
                puzzle_reveal: hex::encode(
                    cs.puzzle_reveal
                        .to_bytes()
                        .map_err(|e| Error::internal(format!("serialize puzzle: {e}")))?,
                ),
                solution: hex::encode(
                    cs.solution
                        .to_bytes()
                        .map_err(|e| Error::internal(format!("serialize solution: {e}")))?,
                ),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(chia_query::SpendBundle {
        coin_spends,
        aggregated_signature: hex::encode(bundle.aggregated_signature.to_bytes()),
    })
}

#[async_trait]
impl Broadcaster for ChiaQueryBroadcaster {
    async fn broadcast(&self, bundle: &SpendBundle) -> Result<()> {
        let wire = to_query_bundle(bundle)?;
        let status = self
            .query
            .push_tx(&wire)
            .await
            .map_err(|e| Error::internal(format!("broadcast (push_tx) failed: {e}")))?;
        // Fail closed: a non-success mempool status is an error, not a silent no-op.
        if !status.success {
            return Err(Error::api(format!(
                "the network rejected the transaction: {}",
                status.status
            )));
        }
        Ok(())
    }
}

/// Confirms that a broadcast spend reached the chain by polling for one of its CREATED output
/// coins to appear on-chain (§18.12): a created coin with a non-zero confirmed height proves the
/// spend was included in a block. Injected as a seam so the confirm logic is testable without a
/// live chain (tests use a mock; production uses [`ChiaQueryConfirmer`]).
#[async_trait]
pub trait Confirmer: Send + Sync {
    /// Poll until any of `created_coin_ids` is confirmed on-chain, or the confirmer's timeout
    /// elapses.
    ///
    /// - `Ok(true)` — confirmed on-chain (a block included the spend).
    /// - `Ok(false)` — NOT confirmed within the window. The spend was already accepted into the
    ///   mempool (money moved — that boundary is [`Broadcaster::broadcast`]); on-chain inclusion
    ///   is asynchronous, so a miss is NOT a spend failure — it is "pending confirmation".
    ///
    /// A confirmation READ error (network/parse) is folded into `Ok(false)` by the production
    /// implementation: a failed READ must never be reported as a spend failure (the money already
    /// moved). The `Result` is kept for a future confirmer that needs to distinguish read faults.
    async fn confirm(&self, created_coin_ids: &[Bytes32]) -> Result<bool>;
}

/// The PRODUCTION confirmer (§18.12): polls `chia_query::wait_for_confirmation` for a created
/// output coin. Shares the SAME [`chia_query::ChiaQuery`] the broadcaster + fallback use.
pub struct ChiaQueryConfirmer {
    query: std::sync::Arc<chia_query::ChiaQuery>,
    poll_interval: std::time::Duration,
    timeout: std::time::Duration,
}

impl ChiaQueryConfirmer {
    /// A confirmer with the default cadence (poll every 5s, give up after 3 minutes) — long enough
    /// to span a mainnet block, short enough not to wedge the unattended tip engine.
    pub fn new(query: std::sync::Arc<chia_query::ChiaQuery>) -> Self {
        Self::with_timings(
            query,
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(180),
        )
    }

    /// A confirmer with explicit poll/timeout durations (tests pin tiny values).
    pub fn with_timings(
        query: std::sync::Arc<chia_query::ChiaQuery>,
        poll_interval: std::time::Duration,
        timeout: std::time::Duration,
    ) -> Self {
        Self {
            query,
            poll_interval,
            timeout,
        }
    }
}

#[async_trait]
impl Confirmer for ChiaQueryConfirmer {
    async fn confirm(&self, created_coin_ids: &[Bytes32]) -> Result<bool> {
        let Some(first) = created_coin_ids.first() else {
            // Nothing to confirm against (should not happen for a real spend) — treat as pending.
            return Ok(false);
        };
        // Confirm on the first created coin: every addition of one spend is included in the SAME
        // block, so the first is representative. `wait_for_confirmation` polls until the coin has a
        // non-zero confirmed height or the timeout elapses (a timeout ⇒ pending, not a failure).
        let coin_id = format!("0x{}", hex::encode(first));
        match self
            .query
            .wait_for_confirmation(&coin_id, self.poll_interval, self.timeout)
            .await
        {
            Ok(_record) => Ok(true),
            // Timed out (or the read repeatedly failed) — the broadcast still succeeded; report
            // pending, never a failure.
            Err(_) => Ok(false),
        }
    }
}

/// A [`Broadcaster`] decorator (§18.12) that broadcasts via `inner` (mempool accept = the
/// money-moving boundary) and then BEST-EFFORT confirms on-chain via `confirmer`. A confirmation
/// miss/timeout is LOGGED but NOT an error: the spend was accepted; on-chain inclusion is
/// asynchronous. ONLY a mempool-push (`inner`) error propagates. This is the broadcaster attached
/// to the GENERAL wallet surface (send/offer/mint) whose Sage responses carry no confirmation
/// field; the tip path surfaces confirmation EXPLICITLY in its ledger via its own
/// [`Confirmer`] (see `WalletBackend::build_and_broadcast_dig_tip`).
pub struct ConfirmingBroadcaster {
    inner: std::sync::Arc<dyn Broadcaster>,
    confirmer: std::sync::Arc<dyn Confirmer>,
}

impl ConfirmingBroadcaster {
    /// Wrap `inner`, confirming each broadcast via `confirmer`.
    pub fn new(
        inner: std::sync::Arc<dyn Broadcaster>,
        confirmer: std::sync::Arc<dyn Confirmer>,
    ) -> Self {
        Self { inner, confirmer }
    }
}

#[async_trait]
impl Broadcaster for ConfirmingBroadcaster {
    async fn broadcast(&self, bundle: &SpendBundle) -> Result<()> {
        // The money boundary: propagate a mempool-push failure (ambiguous), never swallow it.
        self.inner.broadcast(bundle).await?;
        // Best-effort on-chain confirmation (observability only — the send already happened).
        let created = bundle_addition_coin_ids(bundle).unwrap_or_default();
        match self.confirmer.confirm(&created).await {
            Ok(true) => {}
            Ok(false) => eprintln!(
                "dig-node: WARN broadcast accepted into the mempool but not confirmed on-chain \
                 within the window (txid {}); confirmation is asynchronous",
                hex::encode(bundle.name())
            ),
            Err(e) => eprintln!(
                "dig-node: WARN confirmation read failed after a successful broadcast (txid {}): \
                 {e}",
                hex::encode(bundle.name())
            ),
        }
        Ok(())
    }
}

/// The coin ids of the output coins a signed `bundle` CREATES — the confirmation targets (a created
/// coin appearing on-chain proves the spend was included). Computed by running the bundle through
/// `dig-clvm` (pure — no network) and taking the additions. PURE + fail-closed: a bundle that does
/// not validate yields no ids (the caller then confirms nothing rather than confirming a phantom).
pub fn bundle_addition_coin_ids(bundle: &SpendBundle) -> Result<Vec<Bytes32>> {
    let result = run_and_validate(&bundle.coin_spends)?;
    Ok(result.additions.iter().map(|a| a.coin_id()).collect())
}

/// A one-shot broadcast-consent handle (§18.21). The served layer ARMS it when the paired caller
/// confirms a SPECIFIC spend; [`ConsentBroadcaster`] then forwards exactly ONE broadcast and
/// disarms. Cheap to `clone` (shared flag) so the arming site and the broadcaster observe the same
/// state. The default is DISARMED — nothing broadcasts until explicit per-op consent.
#[derive(Clone, Default)]
pub struct BroadcastConsent {
    armed: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl BroadcastConsent {
    /// A fresh, DISARMED consent handle.
    pub fn new() -> Self {
        Self::default()
    }
    /// Arm consent for the NEXT single broadcast (the caller confirmed the op).
    pub fn arm(&self) {
        self.armed.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    /// Whether consent is currently armed (does not consume it).
    pub fn is_armed(&self) -> bool {
        self.armed.load(std::sync::atomic::Ordering::SeqCst)
    }
    /// Consume the armed consent (one-shot): returns whether it WAS armed, disarming it.
    fn take(&self) -> bool {
        self.armed.swap(false, std::sync::atomic::Ordering::SeqCst)
    }
}

/// A [`Broadcaster`] decorator enforcing per-op consent (§18.21). It forwards to `inner` ONLY when
/// a one-shot [`BroadcastConsent`] is armed, then disarms; an unarmed (unconsented) broadcast FAILS
/// CLOSED and the inner broadcaster is never called — nothing is spent. This adapts the §16.2
/// broadcast gate to the authorized-extension path (each spend needs a fresh, explicit confirm).
pub struct ConsentBroadcaster {
    inner: std::sync::Arc<dyn Broadcaster>,
    consent: BroadcastConsent,
}

impl ConsentBroadcaster {
    /// Wrap `inner`, gating each broadcast on `consent`.
    pub fn new(inner: std::sync::Arc<dyn Broadcaster>, consent: BroadcastConsent) -> Self {
        Self { inner, consent }
    }
}

#[async_trait]
impl Broadcaster for ConsentBroadcaster {
    async fn broadcast(&self, bundle: &SpendBundle) -> Result<()> {
        if !self.consent.take() {
            return Err(Error::unauthorized(
                "broadcast requires explicit per-op consent; nothing was spent",
            ));
        }
        self.inner.broadcast(bundle).await
    }
}

// ---- coin selection -------------------------------------------------------

/// Greedily select coins (largest first) covering `target`. Errors if the coins cannot cover
/// it. Deterministic (sorts by amount desc, then coin id) so tests are stable.
pub fn select_coins(mut coins: Vec<Coin>, target: u64) -> Result<Vec<Coin>> {
    coins.sort_by(|a, b| b.amount.cmp(&a.amount).then(a.coin_id().cmp(&b.coin_id())));
    let mut selected = Vec::new();
    let mut total: u64 = 0;
    for c in coins {
        if total >= target {
            break;
        }
        total += c.amount;
        selected.push(c);
    }
    if total < target {
        return Err(Error::api(format!(
            "insufficient funds: have {total}, need {target}"
        )));
    }
    Ok(selected)
}

// ---- XCH spend builders (per-coin synthetic key) --------------------------

/// Spend one coin at `coin.puzzle_hash` with `conditions`, using the key that owns it.
/// `pub(crate)` so the mint/offer builders reuse the exact per-coin standard-layer spend.
pub(crate) fn spend_std(
    ctx: &mut SpendContext,
    signer: &WalletSigner,
    coin: Coin,
    conditions: Conditions,
) -> Result<()> {
    let syn_pk = signer
        .synthetic_for(coin.puzzle_hash)
        .ok_or_else(|| Error::internal("no signing key for coin's puzzle hash"))?;
    StandardLayer::new(syn_pk)
        .spend(ctx, coin, conditions)
        .map_err(|e| Error::internal(format!("standard spend: {e:?}")))?;
    Ok(())
}

/// Link the remaining input coins to the first via `assert_concurrent_spend`.
pub(crate) fn link_rest(
    ctx: &mut SpendContext,
    signer: &WalletSigner,
    inputs: &[Coin],
) -> Result<()> {
    if let Some(first) = inputs.first() {
        let first_id = first.coin_id();
        for coin in &inputs[1..] {
            spend_std(
                ctx,
                signer,
                *coin,
                Conditions::new().assert_concurrent_spend(first_id),
            )?;
        }
    }
    Ok(())
}

/// Build an XCH send: `amount` to `dest`, `fee` reserved, change back to `change`.
pub fn build_xch_send(
    signer: &WalletSigner,
    inputs: &[Coin],
    dest: Bytes32,
    amount: u64,
    fee: u64,
    change: Bytes32,
) -> Result<Vec<CoinSpend>> {
    if inputs.is_empty() {
        return Err(Error::api("no input coins"));
    }
    let total: u64 = inputs.iter().map(|c| c.amount).sum();
    let need = amount
        .checked_add(fee)
        .ok_or_else(|| Error::api("amount overflow"))?;
    if total < need {
        return Err(Error::api(format!(
            "insufficient funds: have {total}, need {need}"
        )));
    }
    let mut ctx = SpendContext::new();
    let hint = ctx
        .hint(dest)
        .map_err(|e| Error::internal(format!("hint: {e:?}")))?;
    let mut conditions = Conditions::new().create_coin(dest, amount, hint);
    let change_amount = total - amount - fee;
    if change_amount > 0 {
        conditions = conditions.create_coin(change, change_amount, Memos::None);
    }
    if fee > 0 {
        conditions = conditions.reserve_fee(fee);
    }
    spend_std(&mut ctx, signer, inputs[0], conditions)?;
    link_rest(&mut ctx, signer, inputs)?;
    Ok(ctx.take())
}

/// Build a bulk XCH send: `amount` to EACH of `dests`, one `fee`, change back to `change`.
pub fn build_bulk_xch_send(
    signer: &WalletSigner,
    inputs: &[Coin],
    dests: &[Bytes32],
    amount: u64,
    fee: u64,
    change: Bytes32,
) -> Result<Vec<CoinSpend>> {
    if inputs.is_empty() {
        return Err(Error::api("no input coins"));
    }
    if dests.is_empty() {
        return Err(Error::api("no destinations"));
    }
    let total: u64 = inputs.iter().map(|c| c.amount).sum();
    let payout = amount
        .checked_mul(dests.len() as u64)
        .and_then(|p| p.checked_add(fee))
        .ok_or_else(|| Error::api("amount overflow"))?;
    if total < payout {
        return Err(Error::api(format!(
            "insufficient funds: have {total}, need {payout}"
        )));
    }
    let mut ctx = SpendContext::new();
    let mut conditions = Conditions::new();
    for dest in dests {
        let hint = ctx
            .hint(*dest)
            .map_err(|e| Error::internal(format!("hint: {e:?}")))?;
        conditions = conditions.create_coin(*dest, amount, hint);
    }
    let change_amount = total - amount * dests.len() as u64 - fee;
    if change_amount > 0 {
        conditions = conditions.create_coin(change, change_amount, Memos::None);
    }
    if fee > 0 {
        conditions = conditions.reserve_fee(fee);
    }
    spend_std(&mut ctx, signer, inputs[0], conditions)?;
    link_rest(&mut ctx, signer, inputs)?;
    Ok(ctx.take())
}

/// Build a combine: merge all `inputs` into a single coin at `own`, minus `fee`.
pub fn build_combine(
    signer: &WalletSigner,
    inputs: &[Coin],
    own: Bytes32,
    fee: u64,
) -> Result<Vec<CoinSpend>> {
    if inputs.len() < 2 {
        return Err(Error::api("need at least 2 coins to combine"));
    }
    let total: u64 = inputs.iter().map(|c| c.amount).sum();
    if total <= fee {
        return Err(Error::api("fee exceeds combined amount"));
    }
    let mut ctx = SpendContext::new();
    let mut conditions = Conditions::new().create_coin(own, total - fee, Memos::None);
    if fee > 0 {
        conditions = conditions.reserve_fee(fee);
    }
    spend_std(&mut ctx, signer, inputs[0], conditions)?;
    link_rest(&mut ctx, signer, inputs)?;
    Ok(ctx.take())
}

/// Build a split: divide `inputs` into `output_count` roughly-equal coins at `own`, minus
/// `fee`. The first output carries the remainder.
pub fn build_split(
    signer: &WalletSigner,
    inputs: &[Coin],
    output_count: u32,
    own: Bytes32,
    fee: u64,
) -> Result<Vec<CoinSpend>> {
    if inputs.is_empty() {
        return Err(Error::api("no input coins"));
    }
    if output_count < 2 {
        return Err(Error::api("output_count must be at least 2"));
    }
    let total: u64 = inputs.iter().map(|c| c.amount).sum();
    if total <= fee {
        return Err(Error::api("fee exceeds total"));
    }
    let spendable = total - fee;
    let each = spendable / output_count as u64;
    let remainder = spendable % output_count as u64;
    if each == 0 {
        return Err(Error::api("coins too small to split into that many"));
    }
    let mut ctx = SpendContext::new();
    let mut conditions = Conditions::new().create_coin(own, each + remainder, Memos::None);
    for _ in 1..output_count {
        conditions = conditions.create_coin(own, each, Memos::None);
    }
    if fee > 0 {
        conditions = conditions.reserve_fee(fee);
    }
    spend_std(&mut ctx, signer, inputs[0], conditions)?;
    link_rest(&mut ctx, signer, inputs)?;
    Ok(ctx.take())
}

/// A resolved multi-send output: a destination puzzle hash + amount (XCH only in this PR).
pub struct MultiPayment {
    /// The destination puzzle hash.
    pub dest: Bytes32,
    /// The amount to send.
    pub amount: u64,
}

/// Build a multi-send of XCH: each payment creates a hinted coin; one `fee`; change to
/// `change`. (CAT payments in `multi_send` are a follow-on — see the RPC dispatch.)
pub fn build_multi_send(
    signer: &WalletSigner,
    inputs: &[Coin],
    payments: &[MultiPayment],
    fee: u64,
    change: Bytes32,
) -> Result<Vec<CoinSpend>> {
    if inputs.is_empty() {
        return Err(Error::api("no input coins"));
    }
    if payments.is_empty() {
        return Err(Error::api("no payments"));
    }
    let total: u64 = inputs.iter().map(|c| c.amount).sum();
    let out: u64 = payments.iter().map(|p| p.amount).sum();
    let need = out
        .checked_add(fee)
        .ok_or_else(|| Error::api("amount overflow"))?;
    if total < need {
        return Err(Error::api(format!(
            "insufficient funds: have {total}, need {need}"
        )));
    }
    let mut ctx = SpendContext::new();
    let mut conditions = Conditions::new();
    for p in payments {
        let hint = ctx
            .hint(p.dest)
            .map_err(|e| Error::internal(format!("hint: {e:?}")))?;
        conditions = conditions.create_coin(p.dest, p.amount, hint);
    }
    let change_amount = total - out - fee;
    if change_amount > 0 {
        conditions = conditions.create_coin(change, change_amount, Memos::None);
    }
    if fee > 0 {
        conditions = conditions.reserve_fee(fee);
    }
    spend_std(&mut ctx, signer, inputs[0], conditions)?;
    link_rest(&mut ctx, signer, inputs)?;
    Ok(ctx.take())
}

// ---- CAT spend builder ----------------------------------------------------

/// Build a CAT send of `amount` to a single `dest` (see [`build_cat_send_multi`]).
#[allow(clippy::too_many_arguments)]
pub fn build_cat_send(
    signer: &WalletSigner,
    cats: &[Cat],
    dest: Bytes32,
    amount: u64,
    change: Bytes32,
    include_hint: bool,
    fee: u64,
    xch_fee_coins: &[Coin],
) -> Result<Vec<CoinSpend>> {
    build_cat_send_multi(
        signer,
        cats,
        &[(dest, amount)],
        change,
        include_hint,
        fee,
        xch_fee_coins,
    )
}

/// Build a CAT send with one or more `outputs` (`(dest, amount)`), change back to `change`;
/// `fee` (XCH) is paid from `xch_fee_coins` linked via `assert_concurrent_spend`. `cats` are
/// the spendable input CAT coins (resolved with lineage via [`super::singleton::resolve_cat`]).
pub fn build_cat_send_multi(
    signer: &WalletSigner,
    cats: &[Cat],
    outputs: &[(Bytes32, u64)],
    change: Bytes32,
    include_hint: bool,
    fee: u64,
    xch_fee_coins: &[Coin],
) -> Result<Vec<CoinSpend>> {
    if cats.is_empty() {
        return Err(Error::api("no CAT coins"));
    }
    if outputs.is_empty() {
        return Err(Error::api("no CAT outputs"));
    }
    let total: u64 = cats.iter().map(|c| c.coin.amount).sum();
    let out_total: u64 = outputs.iter().map(|(_, a)| *a).sum();
    if total < out_total {
        return Err(Error::api(format!(
            "insufficient CAT balance: have {total}, need {out_total}"
        )));
    }
    let mut ctx = SpendContext::new();
    let cat_change = total - out_total;
    let mut cat_spends = Vec::with_capacity(cats.len());
    for (i, cat) in cats.iter().enumerate() {
        let syn_pk = signer
            .synthetic_for(cat.info.p2_puzzle_hash)
            .ok_or_else(|| Error::internal("no signing key for CAT inner puzzle"))?;
        let p2 = StandardLayer::new(syn_pk);
        let inner_conditions = if i == 0 {
            let mut conds = Conditions::new();
            for (dest, amount) in outputs {
                let dest_memos = if include_hint {
                    ctx.hint(*dest)
                        .map_err(|e| Error::internal(format!("hint: {e:?}")))?
                } else {
                    Memos::None
                };
                conds = conds.create_coin(*dest, *amount, dest_memos);
            }
            if cat_change > 0 {
                conds = conds.create_coin(change, cat_change, Memos::None);
            }
            conds
        } else {
            Conditions::new()
        };
        let inner_spend = p2
            .spend_with_conditions(&mut ctx, inner_conditions)
            .map_err(|e| Error::internal(format!("cat inner spend: {e:?}")))?;
        cat_spends.push(CatSpend::new(*cat, inner_spend));
    }
    Cat::spend_all(&mut ctx, &cat_spends)
        .map_err(|e| Error::internal(format!("cat spend_all: {e:?}")))?;

    if fee > 0 {
        if xch_fee_coins.is_empty() {
            return Err(Error::api("a CAT-send fee requires XCH fee coins"));
        }
        let xch_total: u64 = xch_fee_coins.iter().map(|c| c.amount).sum();
        if xch_total < fee {
            return Err(Error::api("insufficient XCH for the CAT-send fee"));
        }
        let mut fee_conditions = Conditions::new()
            .reserve_fee(fee)
            .assert_concurrent_spend(cats[0].coin.coin_id());
        let xch_change = xch_total - fee;
        if xch_change > 0 {
            fee_conditions = fee_conditions.create_coin(change, xch_change, Memos::None);
        }
        spend_std(&mut ctx, signer, xch_fee_coins[0], fee_conditions)?;
        link_rest(&mut ctx, signer, xch_fee_coins)?;
    }
    Ok(ctx.take())
}

// ---- validation + summary (dig-clvm) --------------------------------------

/// Run the coin spends through `dig-clvm` (CLVM execution + conservation + structural checks,
/// signature deferred to the L1 broadcast target — see the module docs). Returns the parsed
/// [`SpendResult`] (additions/removals/fee). Fail-closed: an invalid spend errors here.
pub fn run_and_validate(coin_spends: &[CoinSpend]) -> Result<SpendResult> {
    let bundle = SpendBundle::new(coin_spends.to_vec(), Signature::default());
    let context = ValidationContext {
        height: 0,
        timestamp: 0,
        constants: DIG_MAINNET,
        coin_records: HashMap::new(),
        // Treat every spent coin as available so the structural check passes without a UTXO
        // set (the node has already confirmed these coins exist in its wallet DB).
        ephemeral_coins: bundle
            .coin_spends
            .iter()
            .map(|cs| cs.coin.coin_id())
            .collect(),
    };
    let mut config = ValidationConfig::default();
    config.flags |= DONT_VALIDATE_SIGNATURE;
    validate_spend_bundle(&bundle, &context, &config, None)
        .map_err(|e| Error::api(format!("spend failed dig-clvm validation: {e}")))
}

/// Build a [`TransactionSummary`] from the CLVM execution of `coin_spends`: each input coin
/// and the outputs it creates, with `receiving` set for outputs back to the wallet.
pub fn summarize(
    coin_spends: &[CoinSpend],
    prefix: &str,
    wallet_puzzle_hashes: &HashSet<Bytes32>,
) -> Result<TransactionSummary> {
    let result = run_and_validate(coin_spends)?;
    let burn = Bytes32::from([0u8; 32]);
    let mut inputs = Vec::with_capacity(coin_spends.len());
    for cs in coin_spends {
        let coin_id = cs.coin.coin_id();
        let outputs = result
            .additions
            .iter()
            .filter(|a| a.parent_coin_info == coin_id)
            .map(|a| TransactionOutput {
                coin_id: hex::encode(a.coin_id()),
                amount: Amount::u64(a.amount),
                address: encode_addr(a.puzzle_hash, prefix),
                receiving: wallet_puzzle_hashes.contains(&a.puzzle_hash),
                burning: a.puzzle_hash == burn,
            })
            .collect();
        inputs.push(TransactionInput {
            coin_id: hex::encode(coin_id),
            amount: Amount::u64(cs.coin.amount),
            address: encode_addr(cs.coin.puzzle_hash, prefix),
            asset: None,
            outputs,
        });
    }
    Ok(TransactionSummary {
        fee: Amount::u64(result.fee),
        inputs,
    })
}

// ---- JSON <-> chia conversions --------------------------------------------

fn encode_addr(puzzle_hash: Bytes32, prefix: &str) -> String {
    chia_wallet_sdk::utils::Address::new(puzzle_hash, prefix.to_string())
        .encode()
        .unwrap_or_else(|_| hex::encode(puzzle_hash))
}

/// A `CoinSpend` as its Sage wire [`CoinSpendJson`].
pub fn coin_spend_to_json(cs: &CoinSpend) -> Result<CoinSpendJson> {
    Ok(CoinSpendJson {
        coin: CoinJson {
            parent_coin_info: hex::encode(cs.coin.parent_coin_info),
            puzzle_hash: hex::encode(cs.coin.puzzle_hash),
            amount: Amount::u64(cs.coin.amount),
        },
        puzzle_reveal: hex::encode(
            cs.puzzle_reveal
                .to_bytes()
                .map_err(|e| Error::internal(format!("serialize puzzle: {e}")))?,
        ),
        solution: hex::encode(
            cs.solution
                .to_bytes()
                .map_err(|e| Error::internal(format!("serialize solution: {e}")))?,
        ),
    })
}

fn hex_to_bytes(s: &str) -> Result<Vec<u8>> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(|e| Error::api(format!("bad hex: {e}")))
}

/// Parse a Sage wire [`CoinSpendJson`] into a `CoinSpend`.
pub fn coin_spend_from_json(j: &CoinSpendJson) -> Result<CoinSpend> {
    let coin = Coin {
        parent_coin_info: super::singleton::bytes32_from_hex(&j.coin.parent_coin_info)?,
        puzzle_hash: super::singleton::bytes32_from_hex(&j.coin.puzzle_hash)?,
        amount: j.coin.amount.to_u64().unwrap_or(0),
    };
    Ok(CoinSpend {
        coin,
        puzzle_reveal: Program::from(hex_to_bytes(&j.puzzle_reveal)?),
        solution: Program::from(hex_to_bytes(&j.solution)?),
    })
}

/// A `SpendBundle` as its Sage wire [`SpendBundleJson`].
pub fn spend_bundle_to_json(bundle: &SpendBundle) -> Result<SpendBundleJson> {
    Ok(SpendBundleJson {
        coin_spends: bundle
            .coin_spends
            .iter()
            .map(coin_spend_to_json)
            .collect::<Result<Vec<_>>>()?,
        aggregated_signature: hex::encode(bundle.aggregated_signature.to_bytes()),
    })
}

/// Parse a Sage wire [`SpendBundleJson`] into a `SpendBundle`.
pub fn spend_bundle_from_json(j: &SpendBundleJson) -> Result<SpendBundle> {
    let coin_spends = j
        .coin_spends
        .iter()
        .map(coin_spend_from_json)
        .collect::<Result<Vec<_>>>()?;
    let sig_bytes: [u8; 96] = hex_to_bytes(&j.aggregated_signature)?
        .try_into()
        .map_err(|_| Error::api("aggregated_signature must be 96 bytes"))?;
    let signature = Signature::from_bytes(&sig_bytes)
        .map_err(|e| Error::api(format!("bad signature: {e:?}")))?;
    Ok(SpendBundle::new(coin_spends, signature))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia_sdk_test::Simulator;
    use chia_wallet_sdk::types::TESTNET11_CONSTANTS;

    /// A signer whose single key owns `alice`'s simulator coin, using the testnet11 agg-sig
    /// domain (the domain the simulator validates against).
    fn signer_for(sk: SecretKey) -> WalletSigner {
        WalletSigner::new(vec![sk], TESTNET11_CONSTANTS.agg_sig_me_additional_data)
    }

    #[test]
    fn select_coins_greedy_covers_target_or_errors() {
        let mk = |amt: u64| Coin::new(Bytes32::new([1; 32]), Bytes32::new([2; 32]), amt);
        let sel = select_coins(vec![mk(100), mk(50), mk(25)], 120).unwrap();
        assert_eq!(sel.iter().map(|c| c.amount).sum::<u64>(), 150); // 100 + 50
        assert_eq!(sel.len(), 2);
        assert!(select_coins(vec![mk(10)], 100).is_err());
    }

    #[test]
    fn json_round_trips_coin_spend_and_bundle() {
        let cs = CoinSpend {
            coin: Coin::new(Bytes32::new([1; 32]), Bytes32::new([2; 32]), 42),
            puzzle_reveal: Program::from(vec![0x80]),
            solution: Program::from(vec![0x80]),
        };
        let bundle = SpendBundle::new(vec![cs.clone()], Signature::default());
        let json = spend_bundle_to_json(&bundle).unwrap();
        let back = spend_bundle_from_json(&json).unwrap();
        assert_eq!(back.coin_spends.len(), 1);
        assert_eq!(back.coin_spends[0].coin, cs.coin);
        assert_eq!(back.aggregated_signature, bundle.aggregated_signature);
    }

    /// End-to-end (mainnet-safe): build an XCH send, sign it, validate via dig-clvm, and
    /// broadcast it to the simulator (which verifies the signature against L1 constants).
    #[test]
    fn xch_send_builds_signs_validates_and_broadcasts_on_simulator() {
        let mut sim = Simulator::new();
        let alice = sim.bls(1_000);
        let signer = signer_for(alice.sk.clone());

        // Sanity: the signer derives the same p2 puzzle hash the simulator funded.
        assert_eq!(
            signer.synthetic_for(alice.puzzle_hash),
            Some(alice.pk),
            "signer must recognize alice's coin"
        );

        let dest = Bytes32::new([9; 32]);
        let coin_spends =
            build_xch_send(&signer, &[alice.coin], dest, 600, 10, alice.puzzle_hash).unwrap();

        // dig-clvm validates CLVM execution + conservation (fee = 10).
        let result = run_and_validate(&coin_spends).unwrap();
        assert_eq!(result.fee, 10);
        assert!(result
            .additions
            .iter()
            .any(|a| a.puzzle_hash == dest && a.amount == 600));

        // Sign, then broadcast the SIGNED bundle to the simulator (real consensus, incl. BLS).
        let signature = signer.sign(&coin_spends).unwrap();
        let bundle = SpendBundle::new(coin_spends, signature);
        let states = sim
            .new_transaction(bundle)
            .expect("simulator must accept the signed XCH send");
        assert!(!states.is_empty(), "the send produced coin-state changes");
    }

    #[test]
    fn summarize_reports_inputs_outputs_and_fee() {
        let mut sim = Simulator::new();
        let alice = sim.bls(1_000);
        let signer = signer_for(alice.sk.clone());
        let dest = Bytes32::new([9; 32]);
        let coin_spends =
            build_xch_send(&signer, &[alice.coin], dest, 600, 10, alice.puzzle_hash).unwrap();

        let summary = summarize(&coin_spends, "xch", &signer.puzzle_hashes()).unwrap();
        assert_eq!(summary.fee.to_u64(), Some(10));
        assert_eq!(summary.inputs.len(), 1);
        let outputs = &summary.inputs[0].outputs;
        // dest (600, not ours) + change (390, ours).
        assert!(outputs
            .iter()
            .any(|o| o.amount.to_u64() == Some(600) && !o.receiving));
        assert!(outputs
            .iter()
            .any(|o| o.amount.to_u64() == Some(390) && o.receiving));
    }

    #[test]
    fn sign_coin_spends_produces_a_bundle_the_simulator_accepts() {
        let mut sim = Simulator::new();
        let alice = sim.bls(500);
        let signer = signer_for(alice.sk.clone());
        let dest = Bytes32::new([5; 32]);
        let coin_spends =
            build_xch_send(&signer, &[alice.coin], dest, 400, 0, alice.puzzle_hash).unwrap();

        // Round-trip through the wire JSON (what sign_coin_spends receives), sign, broadcast.
        let json: Vec<_> = coin_spends
            .iter()
            .map(|cs| coin_spend_to_json(cs).unwrap())
            .collect();
        let parsed: Vec<_> = json
            .iter()
            .map(|j| coin_spend_from_json(j).unwrap())
            .collect();
        let signature = signer.sign(&parsed).unwrap();
        let bundle = SpendBundle::new(parsed, signature);
        assert!(sim.new_transaction(bundle).is_ok());
    }

    /// Per-op consent gate (#371, §18.21): an unconsented broadcast fails closed and the inner
    /// broadcaster is never called; an armed consent forwards EXACTLY one broadcast, then disarms.
    #[tokio::test]
    async fn consent_broadcaster_refuses_without_consent_and_forwards_once_when_armed() {
        let inner = std::sync::Arc::new(MockBroadcaster::default());
        let consent = BroadcastConsent::new();
        let bc = ConsentBroadcaster::new(inner.clone(), consent.clone());
        let bundle = SpendBundle::new(vec![], Signature::default());

        // Unconsented: fails closed, inner never called (nothing spent).
        assert!(bc.broadcast(&bundle).await.is_err());
        assert_eq!(inner.sent.lock().unwrap().len(), 0);
        assert!(!consent.is_armed());

        // Armed: forwards exactly once, then disarms.
        consent.arm();
        assert!(consent.is_armed());
        assert!(bc.broadcast(&bundle).await.is_ok());
        assert_eq!(inner.sent.lock().unwrap().len(), 1);

        // One-shot: a second broadcast without re-arming fails closed again.
        assert!(bc.broadcast(&bundle).await.is_err());
        assert_eq!(inner.sent.lock().unwrap().len(), 1);
    }

    /// `to_query_bundle` hex-encodes each field into the `chia_query` wire shape (the production
    /// broadcaster's conversion — proven deterministically so it can't silently drift).
    #[test]
    fn to_query_bundle_hex_encodes_every_field() {
        let cs = CoinSpend {
            coin: Coin::new(Bytes32::new([1; 32]), Bytes32::new([2; 32]), 42),
            puzzle_reveal: Program::from(vec![0x80]),
            solution: Program::from(vec![0x81]),
        };
        let bundle = SpendBundle::new(vec![cs], Signature::default());
        let wire = to_query_bundle(&bundle).unwrap();
        assert_eq!(wire.coin_spends.len(), 1);
        assert_eq!(wire.coin_spends[0].coin.parent_coin_info, "01".repeat(32));
        assert_eq!(wire.coin_spends[0].coin.puzzle_hash, "02".repeat(32));
        assert_eq!(wire.coin_spends[0].coin.amount, 42);
        assert_eq!(wire.coin_spends[0].puzzle_reveal, "80");
        assert_eq!(wire.coin_spends[0].solution, "81");
        assert_eq!(
            wire.aggregated_signature,
            hex::encode(Signature::default().to_bytes())
        );
    }

    /// Fail-closed pre-broadcast validation (#371): a tampered bundle (an over-spend — inputs less
    /// than outputs) is rejected by `dig-clvm` before any broadcast.
    #[test]
    fn tampered_bundle_fails_dig_clvm_validation() {
        let mut sim = Simulator::new();
        let alice = sim.bls(1_000);
        let signer = signer_for(alice.sk.clone());
        let dest = Bytes32::new([9; 32]);
        let mut coin_spends =
            build_xch_send(&signer, &[alice.coin], dest, 600, 10, alice.puzzle_hash).unwrap();

        // The honest bundle validates.
        assert!(run_and_validate(&coin_spends).is_ok());

        // Tamper: claim the spent coin holds far less than its outputs create (over-spend).
        coin_spends[0].coin.amount = 1;
        assert!(
            run_and_validate(&coin_spends).is_err(),
            "a tampered/over-spending bundle must fail dig-clvm validation (fail-closed)"
        );
    }

    #[test]
    fn cat_send_builds_validates_and_broadcasts_on_simulator() {
        use chia_wallet_sdk::driver::Cat as SdkCat;

        let mut sim = Simulator::new();
        let alice = sim.bls(1_000);
        let signer = signer_for(alice.sk.clone());
        let alice_p2 = StandardLayer::new(alice.pk);
        let ctx = &mut SpendContext::new();

        // Issue + settle a CAT so we hold a spendable child CAT (parent is a CAT coin).
        let memos = ctx.hint(alice.puzzle_hash).unwrap();
        let (issue, cats) = SdkCat::issue_with_coin(
            ctx,
            alice.coin.coin_id(),
            1_000,
            Conditions::new().create_coin(alice.puzzle_hash, 1_000, memos),
        )
        .unwrap();
        alice_p2.spend(ctx, alice.coin, issue).unwrap();
        sim.spend_coins(ctx.take(), std::slice::from_ref(&alice.sk))
            .unwrap();
        let cat0 = cats[0];

        // Build a CAT send of 400 to a destination, 600 change, no fee.
        let dest = Bytes32::new([3; 32]);
        let coin_spends =
            build_cat_send(&signer, &[cat0], dest, 400, alice.puzzle_hash, true, 0, &[]).unwrap();
        run_and_validate(&coin_spends).unwrap();
        let signature = signer.sign(&coin_spends).unwrap();
        assert!(
            sim.new_transaction(SpendBundle::new(coin_spends, signature))
                .is_ok(),
            "simulator must accept the signed CAT send"
        );
    }

    /// The TIP spend path (#378), mainnet-safe: build a $DIG-style CAT tip to a store OWNER puzzle
    /// hash, validate (dig-clvm), sign, and route through the [`Broadcaster`] seam using a
    /// [`MockBroadcaster`] — which RECORDS the bundle and NEVER sends it. Also asserts the real
    /// simulator accepts the SAME signed bundle (so the recorded tip is a valid on-chain spend),
    /// and that it pays the owner the tip amount. This is the "spend build + mocked broadcaster"
    /// proof: no live mainnet broadcast is ever reached from a test.
    #[tokio::test]
    async fn dig_tip_cat_send_records_via_mock_broadcaster_never_sends() {
        use chia_wallet_sdk::driver::Cat as SdkCat;

        let mut sim = Simulator::new();
        let alice = sim.bls(1_000);
        let signer = signer_for(alice.sk.clone());
        let alice_p2 = StandardLayer::new(alice.pk);
        let ctx = &mut SpendContext::new();

        let memos = ctx.hint(alice.puzzle_hash).unwrap();
        let (issue, cats) = SdkCat::issue_with_coin(
            ctx,
            alice.coin.coin_id(),
            1_000,
            Conditions::new().create_coin(alice.puzzle_hash, 1_000, memos),
        )
        .unwrap();
        alice_p2.spend(ctx, alice.coin, issue).unwrap();
        sim.spend_coins(ctx.take(), std::slice::from_ref(&alice.sk))
            .unwrap();
        let cat0 = cats[0];

        // A tip of 100 base units to the store OWNER puzzle hash (hinted so the owner's wallet sees it).
        let owner_ph = Bytes32::new([7; 32]);
        let tip: u64 = 100;
        let coin_spends = build_cat_send(
            &signer,
            &[cat0],
            owner_ph,
            tip,
            alice.puzzle_hash,
            true,
            0,
            &[],
        )
        .unwrap();

        // dig-clvm validates the tip (fail-closed). The created CAT coin's puzzle hash is the
        // CAT-layer-wrapped hash of the owner p2 (not the bare owner ph), so assert the tip-AMOUNT
        // output coin exists (the recipient is `owner_ph` by construction — `dest` above — and it
        // is hinted so the owner's wallet attributes it).
        let result = run_and_validate(&coin_spends).unwrap();
        assert!(
            result.additions.iter().any(|a| a.amount == tip),
            "the tip must create an output coin of the tip amount"
        );

        let signature = signer.sign(&coin_spends).unwrap();
        let bundle = SpendBundle::new(coin_spends, signature);

        // Route through the Broadcaster seam with a MockBroadcaster: it RECORDS, never sends.
        let mock = MockBroadcaster::default();
        mock.broadcast(&bundle).await.unwrap();
        assert_eq!(
            mock.sent.lock().unwrap().len(),
            1,
            "the tip bundle is recorded by the mock, not sent to any network"
        );

        // The recorded bundle is a valid on-chain spend (real simulator consensus, incl. BLS).
        assert!(
            sim.new_transaction(bundle).is_ok(),
            "the tip spend must be a valid, broadcastable bundle"
        );
    }

    /// A [`Confirmer`] test double: returns a fixed verdict and records how many times it was asked
    /// (so tests assert confirmation was — or was not — attempted). Never touches a chain.
    struct MockConfirmer {
        verdict: bool,
        calls: std::sync::Mutex<usize>,
    }
    impl MockConfirmer {
        fn confirming() -> Self {
            Self {
                verdict: true,
                calls: std::sync::Mutex::new(0),
            }
        }
        fn pending() -> Self {
            Self {
                verdict: false,
                calls: std::sync::Mutex::new(0),
            }
        }
        fn calls(&self) -> usize {
            *self.calls.lock().unwrap()
        }
    }
    #[async_trait]
    impl Confirmer for MockConfirmer {
        async fn confirm(&self, _created_coin_ids: &[Bytes32]) -> Result<bool> {
            *self.calls.lock().unwrap() += 1;
            Ok(self.verdict)
        }
    }

    /// A broadcaster that always fails at the mempool boundary (money never moves).
    struct FailingBroadcaster;
    #[async_trait]
    impl Broadcaster for FailingBroadcaster {
        async fn broadcast(&self, _bundle: &SpendBundle) -> Result<()> {
            Err(Error::api("mempool rejected"))
        }
    }

    /// `bundle_addition_coin_ids` returns the CREATED output coin ids of a valid bundle (the
    /// confirmation targets) — proven against a real built XCH send (dest coin + change coin).
    #[test]
    fn bundle_addition_coin_ids_lists_the_created_output_coins() {
        let mut sim = Simulator::new();
        let alice = sim.bls(1_000);
        let signer = signer_for(alice.sk.clone());
        let dest = Bytes32::new([9; 32]);
        let coin_spends =
            build_xch_send(&signer, &[alice.coin], dest, 600, 10, alice.puzzle_hash).unwrap();
        let bundle = SpendBundle::new(coin_spends, Signature::default());

        let ids = bundle_addition_coin_ids(&bundle).unwrap();
        // Two additions: the 600 to `dest` and the 390 change back to alice.
        assert_eq!(ids.len(), 2, "the send creates two output coins");
        // Each id is the canonical coin id of an addition (matches run_and_validate).
        let expected: HashSet<Bytes32> = run_and_validate(&bundle.coin_spends)
            .unwrap()
            .additions
            .iter()
            .map(|a| a.coin_id())
            .collect();
        assert_eq!(ids.into_iter().collect::<HashSet<_>>(), expected);
    }

    /// `ConfirmingBroadcaster` (§18.12): broadcasts via the inner broadcaster (money boundary),
    /// THEN confirms on-chain. Inner is called exactly once; the confirmer is consulted once.
    #[tokio::test]
    async fn confirming_broadcaster_broadcasts_then_confirms() {
        let inner = std::sync::Arc::new(MockBroadcaster::default());
        let confirmer = std::sync::Arc::new(MockConfirmer::confirming());
        let bc = ConfirmingBroadcaster::new(inner.clone(), confirmer.clone());

        // A real, validatable bundle so `bundle_addition_coin_ids` yields confirmation targets.
        let mut sim = Simulator::new();
        let alice = sim.bls(1_000);
        let signer = signer_for(alice.sk.clone());
        let coin_spends = build_xch_send(
            &signer,
            &[alice.coin],
            Bytes32::new([9; 32]),
            600,
            10,
            alice.puzzle_hash,
        )
        .unwrap();
        let sig = signer.sign(&coin_spends).unwrap();
        let bundle = SpendBundle::new(coin_spends, sig);

        bc.broadcast(&bundle).await.unwrap();
        assert_eq!(inner.sent.lock().unwrap().len(), 1, "inner broadcast once");
        assert_eq!(confirmer.calls(), 1, "confirmation attempted once");
    }

    /// A pending (unconfirmed) result is NOT an error: the money moved at the mempool boundary, so
    /// `ConfirmingBroadcaster::broadcast` still returns `Ok` (confirmation is asynchronous).
    #[tokio::test]
    async fn confirming_broadcaster_pending_confirmation_is_not_an_error() {
        let inner = std::sync::Arc::new(MockBroadcaster::default());
        let confirmer = std::sync::Arc::new(MockConfirmer::pending());
        let bc = ConfirmingBroadcaster::new(inner.clone(), confirmer.clone());
        let bundle = SpendBundle::new(vec![], Signature::default());

        assert!(
            bc.broadcast(&bundle).await.is_ok(),
            "pending is not a failure"
        );
        assert_eq!(
            inner.sent.lock().unwrap().len(),
            1,
            "the send still happened"
        );
    }

    /// A mempool-push failure PROPAGATES and the confirmer is never consulted (nothing to confirm —
    /// no money moved). Fail-closed at the money boundary.
    #[tokio::test]
    async fn confirming_broadcaster_propagates_mempool_failure_and_skips_confirm() {
        let inner = std::sync::Arc::new(FailingBroadcaster);
        let confirmer = std::sync::Arc::new(MockConfirmer::confirming());
        let bc = ConfirmingBroadcaster::new(inner, confirmer.clone());
        let bundle = SpendBundle::new(vec![], Signature::default());

        assert!(
            bc.broadcast(&bundle).await.is_err(),
            "mempool failure propagates"
        );
        assert_eq!(
            confirmer.calls(),
            0,
            "no confirmation when nothing was broadcast"
        );
    }
}
